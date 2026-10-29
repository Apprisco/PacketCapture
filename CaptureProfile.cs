using System.Text.RegularExpressions;

namespace PacketCapture;

internal sealed class CaptureProfile
{
    public sealed record Checklist(string Title, string Intro, List<string>? Items);

    public List<string> Processes { get; private set; } = [];
    public List<string> Ranges { get; private set; } = [];
    public Dictionary<string, Checklist> Checklists { get; } = [];
    private readonly Dictionary<string, string> _text = [];
    private int _loginPort, _worldLow, _worldHigh;

    private static readonly string Folder = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "PacketCapture");
    private static string CacheFile => Path.Combine(Folder, "profile.json");
    private static string RangesFile => Path.Combine(Folder, "ranges.json");

    private static readonly Regex Cidr = new(@"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})/(\d{1,2})$");
    private static readonly Regex Name = new(@"^[A-Za-z0-9_]{1,64}$");
    private static readonly Regex Key = new(@"^[a-z][a-z0-9_]{0,31}$", RegexOptions.IgnoreCase);

    public string T(string key, params object[] args)
    {
        if (!_text.TryGetValue(key, out var t)) return key;
        try { return string.Format(t, args); }
        catch (FormatException) { return t; }
    }

    public bool IsGamePort(int port) => port == _loginPort || (port >= _worldLow && port <= _worldHigh);
    public bool IsLoginPort(int port) => port == _loginPort;

    public static CaptureProfile? Load(Uploader uploader)
    {
        string? fresh = uploader.ProfileAsync().GetAwaiter().GetResult();
        if (fresh != null && Parse(fresh) is { } p)
        {
            try { Directory.CreateDirectory(Folder); File.WriteAllText(CacheFile, fresh); }
            catch (IOException) { }
            return p;
        }
        try { return File.Exists(CacheFile) ? Parse(File.ReadAllText(CacheFile)) : null; }
        catch (IOException) { return null; }
    }

    public static CaptureProfile? Parse(string json)
    {
        try
        {
            var o = Json.AsObject(Json.Parse(json));
            var p = new CaptureProfile
            {
                Processes = [.. o.List("processes").OfType<string>()],
                Ranges = [.. o.List("ranges").OfType<string>()],
                _loginPort = o.Int("authPort"),
            };
            var world = o.List("worldPorts").OfType<double>().Select(d => (int)d).ToList();
            if (world.Count != 2) return null;
            (p._worldLow, p._worldHigh) = (world[0], world[1]);
            if (p.Processes.Count is 0 or > 8 || !p.Processes.All(Name.IsMatch)) return null;
            if (p.Ranges.Count is 0 or > 32 || !p.Ranges.All(ValidRange)) return null;
            if (!ValidPort(p._loginPort) || !ValidPort(p._worldLow) || !ValidPort(p._worldHigh) || p._worldLow > p._worldHigh) return null;
            foreach (var (key, value) in o.TryGetValue("checklists", out var cl) && cl is Dictionary<string, object?> lists ? lists : [])
            {
                if (!Key.IsMatch(key) || value is not Dictionary<string, object?> c) return null;
                var items = c.TryGetValue("items", out var it) && it is List<object?> l ? l.OfType<string>().Select(Clean).ToList() : null;
                p.Checklists[key] = new Checklist(Clean(c.Str("title") ?? key), Clean(c.Str("intro") ?? ""), items);
            }
            if (!p.Checklists.ContainsKey("general")) return null;
            foreach (var (key, value) in o.TryGetValue("text", out var tx) && tx is Dictionary<string, object?> text ? text : [])
                if (Key.IsMatch(key) && value is string s) p._text[key] = Clean(s);
            return p;
        }
        catch (FormatException) { return null; }
    }

    public static List<string> LearnedRanges()
    {
        try { return File.Exists(RangesFile) && Json.Parse(File.ReadAllText(RangesFile)) is List<object?> l ? [.. l.OfType<string>().Where(ValidRange)] : []; }
        catch (Exception e) when (e is IOException or FormatException) { return []; }
    }

    public static void Learn(string range)
    {
        var all = LearnedRanges();
        if (all.Contains(range)) return;
        all.Add(range);
        Directory.CreateDirectory(Folder);
        File.WriteAllText(RangesFile, Json.Write(all));
    }

    private static bool ValidPort(int port) => port is > 0 and < 65536;

    private static bool ValidRange(string cidr)
    {
        var m = Cidr.Match(cidr);
        return m.Success && Enumerable.Range(1, 4).All(i => int.Parse(m.Groups[i].Value) <= 255) && int.Parse(m.Groups[5].Value) is >= 8 and <= 32;
    }

    private static string Clean(string s) => new([.. s.Where(c => c == '\n' || !char.IsControl(c))]);
}
