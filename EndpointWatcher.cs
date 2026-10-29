using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Runtime.InteropServices;

namespace PacketCapture;

internal sealed class EndpointWatcher(IReadOnlyList<string> ranges, CaptureProfile profile)
{
    public ConcurrentDictionary<string, DateTime> Seen { get; } = new();
    public ConcurrentBag<string> Uncovered { get; } = [];

    private readonly CancellationTokenSource _stop = new();
    private Thread? _thread;
    private HashSet<uint> _running = [];
    private bool _hooked;

    public void Start()
    {
        _thread = new Thread(Run) { IsBackground = true, Name = "endpoint watcher" };
        _thread.Start();
    }

    public void Stop()
    {
        _stop.Cancel();
        _thread?.Join(2000);
    }

    private void Run()
    {
        while (!_stop.IsCancellationRequested)
        {
            try
            {
                var pids = profile.Processes.SelectMany(Process.GetProcessesByName).Select(p => (uint)p.Id).ToHashSet();
                if (pids.Count > 0 && _running.Count == 0) Say(ConsoleColor.Cyan, profile.T("gameStarted"));
                if (pids.Count == 0 && _running.Count > 0)
                {
                    Say(ConsoleColor.Cyan, profile.T("gameClosed"));
                    _hooked = false;
                }
                _running = pids;
                if (pids.Count > 0)
                    foreach (var (pid, address, port) in TcpConnections())
                        if (pids.Contains(pid) && !IPAddress.IsLoopback(address) && !address.Equals(IPAddress.Any)) Observe(address, port);
            }
            catch (Exception e) when (e is InvalidOperationException or System.ComponentModel.Win32Exception) { }
            _stop.Token.WaitHandle.WaitOne(1000);
        }
    }

    private void Observe(IPAddress address, int port)
    {
        string key = $"{address}:{port}";
        if (!Seen.TryAdd(key, DateTime.UtcNow) || !profile.IsGamePort(port)) return;
        if (ranges.Any(r => InRange(address, r)))
        {
            if (!_hooked) Say(ConsoleColor.Green, "Hooked. Your game is being recorded.");
            else if (!profile.IsLoginPort(port)) Say(ConsoleColor.DarkGray, "  World changed.");
            _hooked = true;
            return;
        }
        Uncovered.Add(key);
        CaptureProfile.Learn($"{string.Join(".", address.ToString().Split('.').Take(3))}.0/24");
        Say(ConsoleColor.Yellow, profile.T("uncovered"));
    }

    private static void Say(ConsoleColor color, string text)
    {
        Console.ForegroundColor = color;
        Console.WriteLine(text);
        Console.ResetColor();
    }

    private static bool InRange(IPAddress address, string cidr)
    {
        var parts = cidr.Split('/');
        if (parts.Length != 2 || !IPAddress.TryParse(parts[0], out var net) || !int.TryParse(parts[1], out int bits)) return false;
        uint mask = bits == 0 ? 0 : uint.MaxValue << (32 - bits);
        return (ToUInt(address) & mask) == (ToUInt(net) & mask);
    }

    private static uint ToUInt(IPAddress ip)
    {
        var b = ip.MapToIPv4().GetAddressBytes();
        return (uint)(b[0] << 24 | b[1] << 16 | b[2] << 8 | b[3]);
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct TcpRow { public uint State, LocalAddr, LocalPort, RemoteAddr, RemotePort, OwningPid; }

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetExtendedTcpTable(IntPtr table, ref int size, bool sort, int ipVersion, int tableClass, uint reserved);

    private const int AfInet = 2, TcpTableOwnerPidAll = 5;

    private static List<(uint Pid, IPAddress Address, int Port)> TcpConnections()
    {
        var result = new List<(uint, IPAddress, int)>();
        int size = 0;
        GetExtendedTcpTable(IntPtr.Zero, ref size, false, AfInet, TcpTableOwnerPidAll, 0);
        IntPtr buffer = Marshal.AllocHGlobal(size);
        try
        {
            if (GetExtendedTcpTable(buffer, ref size, false, AfInet, TcpTableOwnerPidAll, 0) != 0) return result;
            int count = Marshal.ReadInt32(buffer), rowSize = Marshal.SizeOf<TcpRow>();
            for (int i = 0; i < count; i++)
            {
                var row = Marshal.PtrToStructure<TcpRow>(buffer + 4 + i * rowSize);
                int port = (int)(((row.RemotePort & 0xFF) << 8) | ((row.RemotePort >> 8) & 0xFF));
                result.Add((row.OwningPid, new IPAddress(row.RemoteAddr), port));
            }
        }
        finally { Marshal.FreeHGlobal(buffer); }
        return result;
    }
}
