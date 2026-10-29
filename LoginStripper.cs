namespace PacketCapture;

internal static class LoginStripper
{
    private readonly record struct Packet(long Payload, int Length, uint Seq, bool Syn, byte[]? Data);

    private const int HeadPackets = 64, HeadBytes = 16384, Segments = 8;

    public static int Strip(string pcap, CaptureProfile profile)
    {
        var flows = Read(pcap, profile);
        var writes = new List<(long At, int Count)>();
        int stripped = 0;
        foreach (var list in flows.Values)
        {
            if (Login(list) is not (uint isn, int from, int to)) continue;
            stripped++;
            foreach (var p in list.Where(p => p.Length > 0))
            {
                int rel = unchecked((int)(p.Seq - isn)), a = Math.Max(from, rel), b = Math.Min(to, rel + p.Length);
                if (a < b) writes.Add((p.Payload + a - rel, b - a));
            }
        }
        if (writes.Count > 0) Write(pcap, writes);
        return stripped;
    }

    private static Dictionary<(uint, int, uint, int), List<Packet>> Read(string pcap, CaptureProfile profile)
    {
        var flows = new Dictionary<(uint, int, uint, int), List<Packet>>();
        var links = new List<int>();
        using var file = new FileStream(pcap, FileMode.Open, FileAccess.Read, FileShare.Read, 1 << 20);
        var b = new byte[65536];
        for (long at = 0; Fill(file, b, 0, 8); )
        {
            uint type = BitConverter.ToUInt32(b, 0);
            int length = (int)BitConverter.ToUInt32(b, 4);
            if (length < 12 || length % 4 != 0 || at + length > file.Length) break;
            if (b.Length < length) Array.Resize(ref b, length);
            if (!Fill(file, b, 8, length - 8)) break;
            if (type == 0x0A0D0D0A)
            {
                if (BitConverter.ToUInt32(b, 8) != 0x1A2B3C4D) return [];
                links.Clear();
            }
            else if (type == 1) links.Add(BitConverter.ToUInt16(b, 8));
            else if (type == 6 && length >= 32) Parse(b, length, at, links, profile, flows);
            at += length;
        }
        return flows;
    }

    private static void Parse(byte[] b, int length, long at, List<int> links, CaptureProfile profile, Dictionary<(uint, int, uint, int), List<Packet>> flows)
    {
        int iface = (int)BitConverter.ToUInt32(b, 8), cap = (int)BitConverter.ToUInt32(b, 20);
        if (iface >= links.Count || cap < 0 || 28 + cap > length - 4) return;
        int end = 28 + cap, ip;
        if (links[iface] == 1)
        {
            int et = 28 + 12;
            while (et + 2 <= end && Be16(b, et) == 0x8100) et += 4;
            if (et + 2 > end || Be16(b, et) != 0x0800) return;
            ip = et + 2;
        }
        else if (links[iface] is 101 or 228) ip = 28;
        else return;
        if (end < ip + 20 || b[ip] >> 4 != 4 || b[ip + 9] != 6) return;
        end = Math.Min(end, ip + Be16(b, ip + 2));
        int tcp = ip + (b[ip] & 15) * 4;
        if (end < tcp + 20) return;
        int sport = Be16(b, tcp), dport = Be16(b, tcp + 2), payload = tcp + (b[tcp + 12] >> 4) * 4;
        if (!profile.IsGamePort(dport) || profile.IsGamePort(sport) || payload > end) return;
        bool syn = (b[tcp + 13] & 2) != 0;
        int n = end - payload;
        if (n == 0 && !syn) return;
        var key = (Be32(b, ip + 12), sport, Be32(b, ip + 16), dport);
        if (!flows.TryGetValue(key, out var list)) flows[key] = list = [];
        byte[]? data = null;
        if (n > 0 && list.Count < HeadPackets)
        {
            data = new byte[n];
            Array.Copy(b, payload, data, 0, n);
        }
        list.Add(new Packet(at + payload, n, Be32(b, tcp + 4), syn, data));
    }

    private static (uint Isn, int From, int To)? Login(List<Packet> list)
    {
        var data = list.Where(p => p.Data != null).ToList();
        if (data.Count == 0) return null;
        uint isn = list.Any(p => p.Syn) ? list.First(p => p.Syn).Seq + 1 : data.Min(p => p.Seq);
        var s = new byte[HeadBytes];
        int have = 0;
        foreach (var (rel, p) in data.Select(p => (unchecked((int)(p.Seq - isn)), p)).Where(x => x.Item1 >= 0).OrderBy(x => x.Item1))
        {
            if (rel > have) break;
            int upto = Math.Min(rel + p.Length, HeadBytes);
            if (upto > have) Array.Copy(p.Data!, have - rel, s, have, upto - have);
            have = Math.Max(have, upto);
        }
        for (int off = 0, i = 0; i < Segments && off + 5 <= have; i++)
        {
            int len = (int)BitConverter.ToUInt32(s, off);
            byte flag = s[off + 4];
            if (len < 0 || len % 16 != 0 || len > 1 << 20 || flag > 1) return null;
            if (flag == 1 && len > 16) return off + 5 + len <= have ? (isn, off + 5, off + 5 + len - 16) : null;
            off += 5 + len;
        }
        return null;
    }

    private static void Write(string pcap, List<(long At, int Count)> writes)
    {
        using var file = new FileStream(pcap, FileMode.Open, FileAccess.Write, FileShare.None);
        foreach (var (at, count) in writes)
        {
            file.Position = at;
            file.Write(new byte[count], 0, count);
        }
    }

    private static bool Fill(Stream s, byte[] b, int off, int count)
    {
        for (int n; count > 0; off += n, count -= n)
            if ((n = s.Read(b, off, count)) <= 0) return false;
        return true;
    }

    private static int Be16(byte[] b, int i) => (b[i] << 8) | b[i + 1];
    private static uint Be32(byte[] b, int i) => (uint)((b[i] << 24) | (b[i + 1] << 16) | (b[i + 2] << 8) | b[i + 3]);
}
