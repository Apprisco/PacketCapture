using System.IO.Compression;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text.RegularExpressions;

namespace PacketCapture;

public static class Program
{
    public const string DefaultEndpoint = "https://trove.apprisco.me";
    public static string Version => Assembly.GetExecutingAssembly().GetName().Version?.ToString(3) ?? "0.0.0";
    internal static CaptureProfile Profile = null!;
    private static string _host = new Uri(DefaultEndpoint).Host;
    private static readonly string ExeName = Path.GetFileName(Assembly.GetEntryAssembly()!.Location);

    public static int Main(string[] args)
    {
        Console.Title = "PacketCapture";
        if (!new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator))
        {
            Warn($"Recording needs admin rights. Right-click {ExeName} and choose Run as administrator.");
            Pause();
            return 1;
        }
        _onClose = _ => { PacketMonitor.Stop(); return false; };
        SetConsoleCtrlHandler(_onClose, true);
        try
        {
            var uploader = new Uploader(Arg(args, "--endpoint") ?? DefaultEndpoint);
            _host = new Uri(uploader.Endpoint).Host;
            if (CaptureProfile.Load(uploader) is not { } profile)
            {
                Warn("Can't reach the server, and it's needed once before the first recording. Check your connection and try again.");
                Pause();
                return 1;
            }
            Profile = profile;
            Console.Title = Profile.T("title");
            Console.WriteLine(Profile.T("header", Version));
            Console.WriteLine();
            CheckVersion(uploader);
            string? zip = Arg(args, "--upload") ?? (args.Length == 1 && args[0].EndsWith(".zip", StringComparison.OrdinalIgnoreCase) ? args[0] : null);
            return zip != null ? UploadExisting(uploader, zip) : Record(uploader, Arg(args, "--mode"));
        }
        catch (Exception e)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"Something went wrong: {Hide(e.Message)}");
            Console.ResetColor();
            PacketMonitor.Stop();
            Pause();
            return 1;
        }
    }

    private static int Record(Uploader uploader, string? mode)
    {
        var lists = Profile.Checklists;
        mode ??= Choose("What do you want to record?", [.. lists.Values.Select(c => c.Title)], [.. lists.Keys]);
        if (!lists.TryGetValue(mode, out var list)) throw new ArgumentException($"unknown mode '{mode}'");
        var resume = new Uploader.ResumeState { Endpoint = uploader.Endpoint, Mode = mode };
        if (mode == "general") AskTitle(resume);
        if (!uploader.HealthAsync().GetAwaiter().GetResult())
        {
            Warn(Profile.T("serverDown"));
            Console.WriteLine("You can still record. Your capture is saved so you can upload it later.");
            Console.WriteLine("Press Enter to record anyway, or close this window.");
            Console.ReadLine();
        }
        else if (!LinkDiscord(uploader, resume)) Console.WriteLine("Not linked. Your capture is saved so you can upload it later.");
        if (GameRunning())
        {
            Console.WriteLine(Profile.T("gameRunning"));
            while (GameRunning()) Thread.Sleep(1000);
        }

        string stamp = DateTime.Now.ToString("yyyyMMdd-HHmmss");
        string dir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments), "PacketCapture", $"{stamp}-{mode}");
        Directory.CreateDirectory(dir);
        string etl = Path.Combine(dir, "capture.etl"), pcap = Path.Combine(dir, "capture.pcapng");
        var ranges = Profile.Ranges.Concat(CaptureProfile.LearnedRanges()).Distinct().ToList();
        var started = DateTime.UtcNow;
        PacketMonitor.Start(etl, ranges);
        var watcher = new EndpointWatcher(ranges, Profile);
        watcher.Start();

        Console.WriteLine();
        Console.ForegroundColor = ConsoleColor.Green;
        Console.WriteLine($"Recording: {(mode == "general" ? resume.Title : list.Title)}");
        Console.ResetColor();
        Console.WriteLine(Profile.T("launch"));
        var steps = list.Items ?? [];
        if (mode == "general") Console.WriteLine("Then play what you described.");
        else
        {
            Console.WriteLine(list.Intro);
            for (int i = 0; i < steps.Count; i++) Console.WriteLine($"  {i + 1}. {steps[i]}");
        }
        Console.WriteLine();
        Console.WriteLine(Profile.T("whenDone"));
        Console.ReadLine();

        watcher.Stop();
        PacketMonitor.Stop();
        Console.WriteLine("Recording stopped.");
        Console.WriteLine("Saving the recording...");
        PacketMonitor.Convert(etl, pcap);
        try { if (LoginStripper.Strip(pcap, Profile) is var n and > 0) Console.WriteLine($"Removed your login ticket from {n} connection{(n == 1 ? "" : "s")}."); }
        catch (IOException e) { Console.WriteLine($"Couldn't remove the login ticket here ({e.Message}). The server removes it when the upload arrives."); }
        LinkStripper.Strip(pcap);

        var done = new List<string>();
        if (steps.Count > 0)
        {
            Console.WriteLine("Which steps did you do? Type their numbers, like 1 2 3, or press Enter to skip:");
            done = [.. (Console.ReadLine() ?? "").Split([' ', ','], StringSplitOptions.RemoveEmptyEntries)
                .Select(t => int.TryParse(t, out int n) ? n - 1 : -1).Where(n => n >= 0 && n < steps.Count).Distinct().Select(n => steps[n])];
        }
        Console.WriteLine(Profile.T("notes"));
        string notes = Console.ReadLine() ?? "";

        var meta = new Json.Obj
        {
            { "tool", "PacketCapture" }, { "version", Version }, { "mode", mode }, { "title", resume.Title }, { "description", resume.Description },
            { "filter", ranges },
            { "endpoints", watcher.Seen.OrderBy(e => e.Value).Select(e => new Json.Obj { { "endpoint", e.Key }, { "firstSeenUtc", e.Value } }).ToList() },
            { "uncovered", watcher.Uncovered.ToList() },
            { "startedUtc", started }, { "stoppedUtc", DateTime.UtcNow }, { "stepsDone", done }, { "notes", notes },
            { "captureBytes", new FileInfo(pcap).Length },
        };
        string zip = Path.Combine(Path.GetDirectoryName(dir)!, $"PacketCapture-{mode}-{stamp}.zip");
        using (var archive = ZipFile.Open(zip, ZipArchiveMode.Create))
        {
            archive.CreateEntryFromFile(pcap, "capture.pcapng", CompressionLevel.Optimal);
            using var w = new StreamWriter(archive.CreateEntry("metadata.json").Open());
            w.Write(Json.Write(meta, indented: true));
        }
        File.Delete(pcap);
        Directory.Delete(dir);

        Console.WriteLine();
        File.WriteAllText(zip + ".upload.json", resume.ToJson());
        int result = resume.Token.Length > 0 ? Upload(uploader, zip, resume) : Kept(zip);
        Pause();
        return result;
    }

    private static int UploadExisting(Uploader uploader, string zip)
    {
        zip = Path.GetFullPath(zip);
        if (!File.Exists(zip)) throw new FileNotFoundException($"There's no file at {zip}");
        string statePath = zip + ".upload.json";
        var resume = File.Exists(statePath) ? Uploader.ResumeState.FromJson(File.ReadAllText(statePath)) : new Uploader.ResumeState { Endpoint = uploader.Endpoint };
        if (resume.Endpoint != uploader.Endpoint) (resume.Endpoint, resume.Token, resume.Id) = (uploader.Endpoint, "", null);
        if (!uploader.HealthAsync().GetAwaiter().GetResult())
        {
            Warn(Profile.T("serverDownLater"));
            Pause();
            return 1;
        }
        if (resume.Token.Length > 0 && !uploader.TokenValidAsync(resume.Token).GetAwaiter().GetResult()) (resume.Token, resume.Id) = ("", null);
        if (resume.Token.Length == 0 && !LinkDiscord(uploader, resume)) return Kept(zip);
        if (resume.Mode == "general" && resume.Title.Length < 3) AskTitle(resume);
        File.WriteAllText(statePath, resume.ToJson());
        int result = Upload(uploader, zip, resume);
        Pause();
        return result;
    }

    private static bool LinkDiscord(Uploader uploader, Uploader.ResumeState resume)
    {
        var link = uploader.NewLinkAsync().GetAwaiter().GetResult();
        Console.WriteLine();
        Console.Write(Profile.T("linkPrompt"));
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine($"/capture {link.Code}");
        Console.ResetColor();
        Console.WriteLine("Waiting for you to do that. Press Enter to skip and link later.");
        using var skip = new CancellationTokenSource();
        var keys = Task.Run(() =>
        {
            while (!skip.IsCancellationRequested && !Console.IsInputRedirected)
            {
                if (Console.KeyAvailable && Console.ReadKey(intercept: true).Key == ConsoleKey.Enter) { skip.Cancel(); return; }
                Thread.Sleep(100);
            }
        });
        string? name = uploader.WaitForLinkAsync(link.Token, skip.Token).GetAwaiter().GetResult();
        skip.Cancel();
        keys.Wait(500);
        if (name == null) return false;
        resume.Token = link.Token;
        Console.ForegroundColor = ConsoleColor.Green;
        Console.WriteLine($"Linked to {name}.");
        Console.ResetColor();
        return true;
    }

    private static void AskTitle(Uploader.ResumeState resume)
    {
        Console.WriteLine();
        while (true)
        {
            Console.WriteLine("What are you recording? Give it a short title. It shows on your public Discord ticket.");
            Console.WriteLine(Profile.T("titleExample"));
            Console.Write("> ");
            resume.Title = (Console.ReadLine() ?? "").Trim();
            if (resume.Title.Length is >= 3 and <= 80) break;
            Console.WriteLine("Use 3 to 80 characters.");
        }
        Console.WriteLine("Add details if you like, such as where and which class. These are public too. Type them, or press Enter to skip:");
        Console.Write("> ");
        resume.Description = (Console.ReadLine() ?? "").Trim();
    }

    private static int Upload(Uploader uploader, string zip, Uploader.ResumeState resume)
    {
        Console.WriteLine();
        Console.WriteLine($"Uploading {new FileInfo(zip).Length / 1048576.0:0.0} MB...");
        for (int attempt = 1; ; attempt++)
        {
            try
            {
                var (status, reason) = uploader.UploadAsync(zip, resume, (done, total) =>
                    Console.Write($"\r  {done / 1048576.0,8:0.0} / {total / 1048576.0:0.0} MB  ({100.0 * done / Math.Max(1, total):0}%)   ")).GetAwaiter().GetResult();
                Console.WriteLine();
                if (status == "checking") (status, reason) = WaitWhileChecking(uploader, resume);
                if (status is "received" or "checking")
                {
                    File.Delete(zip + ".upload.json");
                    File.Delete(zip);
                    Console.ForegroundColor = ConsoleColor.Green;
                    Console.WriteLine(Profile.T(status == "received" ? "uploadDone" : "uploadChecking"));
                    Console.ResetColor();
                    return 0;
                }
                Warn($"The upload wasn't accepted: {reason}");
                return Kept(zip);
            }
            catch (Uploader.UploadRefused e) when (e.Message.Contains("title") || e.Message.Contains("description"))
            {
                Console.WriteLine();
                Warn(e.Message);
                AskTitle(resume);
                File.WriteAllText(zip + ".upload.json", resume.ToJson());
            }
            catch (Uploader.UploadRefused e)
            {
                Console.WriteLine();
                Warn(e.Message);
                return Kept(zip);
            }
            catch (Exception e) when (e is HttpRequestException or TaskCanceledException or IOException && attempt < 3)
            {
                Console.WriteLine();
                Warn("The upload was interrupted. Trying again...");
                Thread.Sleep(5000);
            }
            catch (Exception e) when (e is HttpRequestException or TaskCanceledException or IOException)
            {
                Console.WriteLine();
                Warn("The upload failed. Check your connection and try again later.");
                return Kept(zip);
            }
        }
    }

    private static (string Status, string Reason) WaitWhileChecking(Uploader uploader, Uploader.ResumeState resume)
    {
        var started = DateTime.UtcNow;
        string status = "checking", reason = "";
        while (status == "checking" && DateTime.UtcNow - started < TimeSpan.FromMinutes(3))
        {
            Console.Write($"\r  Checking the upload... {(DateTime.UtcNow - started).TotalSeconds:0} s   ");
            Thread.Sleep(2000);
            try { (status, reason) = uploader.StatusAsync(resume.Id!, resume.Token).GetAwaiter().GetResult(); }
            catch (Exception e) when (e is HttpRequestException or TaskCanceledException) { }
        }
        Console.WriteLine();
        return (status, reason);
    }

    private static void CheckVersion(Uploader uploader)
    {
        if (uploader.LatestVersionAsync().GetAwaiter().GetResult() is not { } latest) return;
        if (System.Version.TryParse(latest, out var newest) && System.Version.TryParse(Version, out var mine) && newest > mine)
        {
            Warn(Profile.T("newVersion", latest, Version));
            Console.WriteLine();
        }
    }

    internal static bool GameRunning() => Profile.Processes.Any(n => System.Diagnostics.Process.GetProcessesByName(n).Length > 0);

    private static int Kept(string zip)
    {
        Console.WriteLine($"Your capture is saved here: {zip}");
        Console.WriteLine($"To upload it later, drag the file onto {ExeName}.");
        return 2;
    }

    private static string Hide(string text) => Regex.Replace(text.Replace($" ({_host}:443)", ""), Regex.Escape(_host), "the server", RegexOptions.IgnoreCase);

    private static void Warn(string text)
    {
        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.WriteLine(Hide(text));
        Console.ResetColor();
    }

    private static string Choose(string question, string[] labels, string[] values)
    {
        Console.WriteLine(question);
        for (int i = 0; i < labels.Length; i++) Console.WriteLine($"  {i + 1}. {labels[i]}");
        while (true)
        {
            Console.Write("> ");
            if (int.TryParse(Console.ReadLine(), out int n) && n >= 1 && n <= labels.Length) { Console.WriteLine(); return values[n - 1]; }
        }
    }

    private static string? Arg(string[] args, string name)
    {
        int i = Array.IndexOf(args, name);
        return i >= 0 && i + 1 < args.Length ? args[i + 1] : null;
    }

    private static void Pause()
    {
        Console.WriteLine("Press Enter to close.");
        Console.ReadLine();
    }

    private delegate bool ConsoleCtrlHandler(int ctrlType);
    private static ConsoleCtrlHandler? _onClose;
    [DllImport("kernel32.dll")] private static extern bool SetConsoleCtrlHandler(ConsoleCtrlHandler handler, bool add);
}
