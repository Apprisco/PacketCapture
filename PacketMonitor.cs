using System.Diagnostics;

namespace PacketCapture;

internal static class PacketMonitor
{
    private static readonly string Exe = Path.Combine(Environment.SystemDirectory, "PktMon.exe");

    public static void Start(string etl, IReadOnlyList<string> ranges)
    {
        Stop();
        for (int i = 0; i < ranges.Count; i++) Run($"filter add TC{i} -t TCP -i {ranges[i]}");
        Run($"start --capture --pkt-size 0 --file-name \"{etl}\" --file-size 4096");
    }

    public static void Stop()
    {
        Run("stop", check: false);
        Run("filter remove", check: false);
    }

    public static void Convert(string etl, string pcap)
    {
        Run($"etl2pcap \"{etl}\" --out \"{pcap}\"");
        if (!File.Exists(pcap)) throw new IOException("pktmon did not write the converted capture");
        File.Delete(etl);
    }

    private static void Run(string args, bool check = true)
    {
        var p = Process.Start(new ProcessStartInfo(Exe, args) { RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false })
            ?? throw new IOException("pktmon did not start");
        string output = p.StandardOutput.ReadToEnd() + p.StandardError.ReadToEnd();
        p.WaitForExit();
        if (check && p.ExitCode != 0) throw new IOException($"pktmon {args.Split(' ')[0]} failed ({p.ExitCode}): {output.Trim()}");
    }
}
