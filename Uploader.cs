using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;

namespace PacketCapture;

internal sealed class Uploader(string endpoint)
{
    private readonly HttpClient _http = new() { BaseAddress = new Uri(endpoint.TrimEnd('/') + "/"), Timeout = TimeSpan.FromMinutes(5) };
    public string Endpoint { get; } = endpoint;

    public sealed record LinkInfo(string Code, string Token);

    public sealed class ResumeState
    {
        public string Endpoint { get; set; } = "";
        public string Token { get; set; } = "";
        public string? Id { get; set; }
        public string Mode { get; set; } = "general";
        public string Title { get; set; } = "";
        public string Description { get; set; } = "";

        public string ToJson() => Json.Write(new Json.Obj
            { { "Endpoint", Endpoint }, { "Token", Token }, { "Id", Id }, { "Mode", Mode }, { "Title", Title }, { "Description", Description } });

        public static ResumeState FromJson(string text)
        {
            var o = Json.AsObject(Json.Parse(text));
            return new ResumeState
            {
                Endpoint = o.Str("Endpoint") ?? "", Token = o.Str("Token") ?? "", Id = o.Str("Id"), Mode = o.Str("Mode") ?? "general",
                Title = o.Str("Title") ?? "", Description = o.Str("Description") ?? "",
            };
        }
    }

    public sealed class UploadRefused(string message) : Exception(message);

    public async Task<bool> HealthAsync()
    {
        try
        {
            using var r = await _http.GetAsync("api/health");
            return r.IsSuccessStatusCode;
        }
        catch (Exception e) when (e is HttpRequestException or TaskCanceledException) { return false; }
    }

    public async Task<string?> ProfileAsync()
    {
        try
        {
            using var r = await _http.GetAsync("api/capture-profile");
            return r.IsSuccessStatusCode ? await r.Content.ReadAsStringAsync() : null;
        }
        catch (Exception e) when (e is HttpRequestException or TaskCanceledException) { return null; }
    }

    public async Task<string?> LatestVersionAsync()
    {
        try
        {
            using var r = await _http.GetAsync("api/tool");
            return r.IsSuccessStatusCode ? (await ReadObject(r)).Str("latest") : null;
        }
        catch (Exception e) when (e is HttpRequestException or TaskCanceledException or FormatException) { return null; }
    }

    public async Task<LinkInfo> NewLinkAsync()
    {
        using var r = await _http.PostAsync("api/links", null);
        r.EnsureSuccessStatusCode();
        var j = await ReadObject(r);
        return new LinkInfo(j.Str("code")!, j.Str("token")!);
    }

    public async Task<bool> TokenValidAsync(string token)
    {
        try
        {
            using var req = Authorized(HttpMethod.Get, "api/links", token);
            using var r = await _http.SendAsync(req);
            return r.IsSuccessStatusCode;
        }
        catch (Exception e) when (e is HttpRequestException or TaskCanceledException) { return true; }
    }

    public async Task<string?> WaitForLinkAsync(string token, CancellationToken giveUp)
    {
        while (!giveUp.IsCancellationRequested)
        {
            try
            {
                using var req = Authorized(HttpMethod.Get, "api/links", token);
                using var r = await _http.SendAsync(req, giveUp);
                if (r.IsSuccessStatusCode && await ReadObject(r) is var j && j.Bool("linked")) return j.Str("discord_name") ?? "you";
            }
            catch (Exception e) when (e is HttpRequestException or FormatException) { }
            try { await Task.Delay(2000, giveUp); } catch (TaskCanceledException) { break; }
        }
        return null;
    }

    public async Task<(string Status, string Reason)> StatusAsync(string id, string token)
    {
        using var req = Authorized(HttpMethod.Get, $"api/submissions/{id}", token);
        using var r = await _http.SendAsync(req);
        if (!r.IsSuccessStatusCode) throw new UploadRefused(await Detail(r));
        var j = await ReadObject(r);
        return (j.Str("status")!, j.Str("reason") ?? "");
    }

    public async Task<(string Status, string Reason)> UploadAsync(string zip, ResumeState state, Action<long, long> progress)
    {
        long size = new FileInfo(zip).Length;
        int chunkSize, chunks;
        var have = new HashSet<int>();
        if (state.Id == null)
        {
            using var req = Authorized(HttpMethod.Post, "api/submissions", state.Token);
            req.Content = new StringContent(Json.Write(new Json.Obj
            {
                { "mode", state.Mode }, { "title", state.Title }, { "description", state.Description }, { "size", size },
                { "sha256", await Task.Run(() => Sha256(zip)) }, { "tool_version", Program.Version },
            }), Encoding.UTF8, "application/json");
            using var r = await _http.SendAsync(req);
            if (!r.IsSuccessStatusCode) throw new UploadRefused(await Detail(r));
            var j = await ReadObject(r);
            (state.Id, chunkSize, chunks) = (j.Str("id"), j.Int("chunk_size"), j.Int("chunks"));
            File.WriteAllText(zip + ".upload.json", state.ToJson());
        }
        else
        {
            using var req = Authorized(HttpMethod.Get, $"api/submissions/{state.Id}", state.Token);
            using var r = await _http.SendAsync(req);
            if (!r.IsSuccessStatusCode) throw new UploadRefused(await Detail(r));
            var j = await ReadObject(r);
            string status = j.Str("status")!;
            if (status != "uploading") return (status, j.Str("reason") ?? "");
            (chunkSize, chunks) = (j.Int("chunk_size"), j.Int("chunks"));
            foreach (var n in j.List("received").OfType<double>()) have.Add((int)n);
        }

        var buffer = new byte[chunkSize];
        using (var f = File.OpenRead(zip))
            for (int n = 0; n < chunks; n++)
            {
                long offset = (long)n * chunkSize;
                int len = (int)Math.Min(chunkSize, size - offset);
                if (have.Contains(n)) { progress(offset + len, size); continue; }
                f.Seek(offset, SeekOrigin.Begin);
                for (int got = 0; got < len;)
                {
                    int read = await f.ReadAsync(buffer, got, len - got);
                    if (read == 0) throw new IOException("the capture file got shorter while uploading");
                    got += read;
                }
                await SendChunkAsync(state, n, buffer, len, sent => progress(offset + sent, size));
                progress(offset + len, size);
            }

        using (var req = Authorized(HttpMethod.Post, $"api/submissions/{state.Id}/finish", state.Token))
        {
            using var r = await _http.SendAsync(req);
            if (!r.IsSuccessStatusCode) throw new UploadRefused(await Detail(r));
            var j = await ReadObject(r);
            return (j.Str("status")!, j.Str("reason") ?? "");
        }
    }

    private async Task SendChunkAsync(ResumeState state, int n, byte[] buffer, int len, Action<long> sent)
    {
        string hash;
        using (var sha = SHA256.Create()) hash = Hex(sha.ComputeHash(buffer, 0, len));
        for (int attempt = 1; ; attempt++)
        {
            using var req = Authorized(HttpMethod.Put, $"api/submissions/{state.Id}/chunks/{n}", state.Token);
            req.Content = new ProgressContent(buffer, len, sent);
            req.Headers.Add("X-Chunk-SHA256", hash);
            try
            {
                using var r = await _http.SendAsync(req);
                if (r.IsSuccessStatusCode) return;
                if ((int)r.StatusCode is 401 or 404 or 409 or 413 or 416) throw new UploadRefused(await Detail(r));
                if (attempt >= 5) throw new HttpRequestException($"chunk {n}: {await Detail(r)}");
            }
            catch (Exception e) when (e is HttpRequestException or TaskCanceledException && attempt < 5) { }
            await Task.Delay(TimeSpan.FromSeconds(2 * attempt));
        }
    }

    private static HttpRequestMessage Authorized(HttpMethod method, string path, string token)
    {
        var req = new HttpRequestMessage(method, path);
        req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        return req;
    }

    private static async Task<Dictionary<string, object?>> ReadObject(HttpResponseMessage r) => Json.AsObject(Json.Parse(await r.Content.ReadAsStringAsync()));

    private static async Task<string> Detail(HttpResponseMessage r)
    {
        string text = $"server error {(int)r.StatusCode}";
        try { if ((await ReadObject(r)).Str("detail") is { Length: > 0 } s) text = s; }
        catch (FormatException) { }
        return char.ToUpperInvariant(text[0]) + text.Substring(1) + (text.EndsWith(".") ? "" : ".");
    }

    private static string Sha256(string path)
    {
        using var f = File.OpenRead(path);
        using var sha = SHA256.Create();
        return Hex(sha.ComputeHash(f));
    }

    private static string Hex(byte[] hash) => BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant();

    private sealed class ProgressContent(byte[] buffer, int length, Action<long> sent) : HttpContent
    {
        protected override async Task SerializeToStreamAsync(Stream stream, System.Net.TransportContext? context)
        {
            for (int at = 0; at < length;)
            {
                int n = Math.Min(64 * 1024, length - at);
                await stream.WriteAsync(buffer, at, n);
                at += n;
                sent(at);
            }
        }

        protected override bool TryComputeLength(out long size)
        {
            size = length;
            return true;
        }
    }
}
