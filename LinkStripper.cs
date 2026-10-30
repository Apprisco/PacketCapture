namespace PacketCapture;

internal static class LinkStripper
{
    private const int Raw = 101;

    public static void Strip(string pcap)
    {
        string tmp = pcap + ".tmp";
        using (var src = new FileStream(pcap, FileMode.Open, FileAccess.Read, FileShare.Read, 1 << 20))
        using (var dst = new FileStream(tmp, FileMode.Create, FileAccess.Write, FileShare.None, 1 << 20))
        {
            var links = new List<int>();
            var b = new byte[65536];
            while (Fill(src, b, 0, 8))
            {
                uint type = BitConverter.ToUInt32(b, 0);
                int length = (int)BitConverter.ToUInt32(b, 4);
                if (length < 12 || length % 4 != 0) throw new IOException("the recording is unreadable");
                if (b.Length < length) Array.Resize(ref b, length);
                if (!Fill(src, b, 8, length - 8)) throw new IOException("the recording is cut short");
                if (type == 0x0A0D0D0A)
                {
                    links.Clear();
                    var head = new byte[16];
                    Array.Copy(b, 8, head, 0, 8);
                    for (int i = 8; i < 16; i++) head[i] = 0xFF;
                    Block(dst, type, head, head.Length);
                }
                else if (type == 1)
                {
                    links.Add(BitConverter.ToUInt16(b, 8));
                    Interface(dst, b, length);
                }
                else if (type == 6 && length >= 32) Packet(dst, b, length, links);
            }
        }
        File.Delete(pcap);
        File.Move(tmp, pcap);
    }

    private static void Interface(Stream dst, byte[] b, int length)
    {
        var body = new List<byte>(24);
        body.AddRange(BitConverter.GetBytes((ushort)Raw));
        body.AddRange(new byte[2]);
        body.AddRange(BitConverter.GetBytes(BitConverter.ToUInt32(b, 12)));
        for (int o = 16; o + 4 <= length - 4; )
        {
            int code = BitConverter.ToUInt16(b, o), n = BitConverter.ToUInt16(b, o + 2);
            if (code == 0) break;
            if (code == 9 && n == 1) body.AddRange([9, 0, 1, 0, b[o + 4], 0, 0, 0]);
            o += 4 + ((n + 3) & ~3);
        }
        if (body.Count > 8) body.AddRange(new byte[4]);
        Block(dst, 1, [.. body], body.Count);
    }

    private static void Packet(Stream dst, byte[] b, int length, List<int> links)
    {
        int iface = (int)BitConverter.ToUInt32(b, 8), cap = (int)BitConverter.ToUInt32(b, 20), orig = (int)BitConverter.ToUInt32(b, 24);
        if (iface >= links.Count || cap < 0 || 28 + cap > length - 4) return;
        int ip = 0;
        if (links[iface] == 1)
        {
            int et = 12;
            while (et + 2 <= cap && Be16(b, 28 + et) == 0x8100) et += 4;
            if (et + 2 > cap || Be16(b, 28 + et) != 0x0800) return;
            ip = et + 2;
        }
        else if (links[iface] is not (101 or 228)) return;
        int at = 28 + ip, n = cap - ip;
        if (n < 20 || b[at] >> 4 != 4 || b[at + 9] != 6 || (Be16(b, at + 6) & 0x3FFF) != 0) return;
        int total = Be16(b, at + 2);
        if (total < 20 || total > n) return;
        n = total;
        var body = new byte[20 + ((n + 3) & ~3)];
        Array.Copy(b, 8, body, 0, 12);
        Array.Copy(BitConverter.GetBytes(n), 0, body, 12, 4);
        Array.Copy(BitConverter.GetBytes(Math.Max(orig - ip, n)), 0, body, 16, 4);
        Array.Copy(b, 28 + ip, body, 20, n);
        Block(dst, 6, body, body.Length);
    }

    private static void Block(Stream dst, uint type, byte[] body, int count)
    {
        int total = 12 + ((count + 3) & ~3);
        dst.Write(BitConverter.GetBytes(type), 0, 4);
        dst.Write(BitConverter.GetBytes(total), 0, 4);
        dst.Write(body, 0, count);
        dst.Write(new byte[total - 12 - count], 0, total - 12 - count);
        dst.Write(BitConverter.GetBytes(total), 0, 4);
    }

    private static bool Fill(Stream s, byte[] b, int off, int count)
    {
        for (int n; count > 0; off += n, count -= n)
            if ((n = s.Read(b, off, count)) <= 0) return false;
        return true;
    }

    private static int Be16(byte[] b, int i) => (b[i] << 8) | b[i + 1];
}
