using System.Globalization;
using System.Text;

namespace PacketCapture;

internal static class Json
{
    internal sealed class Obj : List<KeyValuePair<string, object?>>
    {
        public void Add(string key, object? value) => Add(new KeyValuePair<string, object?>(key, value));
    }

    public static string Write(object? value, bool indented = false)
    {
        var sb = new StringBuilder();
        Write(sb, value, indented, 0);
        return sb.ToString();
    }

    private static void Write(StringBuilder sb, object? v, bool indented, int depth)
    {
        switch (v)
        {
            case null: sb.Append("null"); break;
            case string s: WriteString(sb, s); break;
            case bool b: sb.Append(b ? "true" : "false"); break;
            case DateTime t: WriteString(sb, t.ToUniversalTime().ToString("o", CultureInfo.InvariantCulture)); break;
            case int or long or uint or short: sb.Append(Convert.ToInt64(v, CultureInfo.InvariantCulture).ToString(CultureInfo.InvariantCulture)); break;
            case double d: sb.Append(d.ToString("R", CultureInfo.InvariantCulture)); break;
            case Obj o: Container(sb, '{', '}', o.Count, i => { WriteString(sb, o[i].Key); sb.Append(indented ? ": " : ":"); Write(sb, o[i].Value, indented, depth + 1); }, indented, depth); break;
            case System.Collections.IEnumerable e:
                var items = e.Cast<object?>().ToList();
                Container(sb, '[', ']', items.Count, i => Write(sb, items[i], indented, depth + 1), indented, depth);
                break;
            default: throw new ArgumentException($"can't write {v.GetType().Name} as JSON");
        }
    }

    private static void Container(StringBuilder sb, char open, char close, int count, Action<int> item, bool indented, int depth)
    {
        sb.Append(open);
        for (int i = 0; i < count; i++)
        {
            if (i > 0) sb.Append(',');
            if (indented) sb.Append('\n').Append(' ', 2 * (depth + 1));
            item(i);
        }
        if (indented && count > 0) sb.Append('\n').Append(' ', 2 * depth);
        sb.Append(close);
    }

    private static void WriteString(StringBuilder sb, string s)
    {
        sb.Append('"');
        foreach (char c in s)
            switch (c)
            {
                case '"': sb.Append("\\\""); break;
                case '\\': sb.Append("\\\\"); break;
                case '\n': sb.Append("\\n"); break;
                case '\r': sb.Append("\\r"); break;
                case '\t': sb.Append("\\t"); break;
                default:
                    if (c < 0x20) sb.Append("\\u").Append(((int)c).ToString("x4", CultureInfo.InvariantCulture));
                    else sb.Append(c);
                    break;
            }
        sb.Append('"');
    }

    public static object? Parse(string text)
    {
        int i = 0;
        var v = Value(text, ref i);
        Space(text, ref i);
        if (i != text.Length) throw new FormatException($"JSON: unexpected text at {i}");
        return v;
    }

    private static object? Value(string s, ref int i)
    {
        Space(s, ref i);
        if (i >= s.Length) throw new FormatException("JSON: unexpected end");
        switch (s[i])
        {
            case '{':
                var obj = new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase);
                i++;
                Space(s, ref i);
                if (Peek(s, i) == '}') { i++; return obj; }
                while (true)
                {
                    Space(s, ref i);
                    if (Peek(s, i) != '"') throw new FormatException($"JSON: expected a key at {i}");
                    string key = Str(s, ref i);
                    Space(s, ref i);
                    Expect(s, ref i, ':');
                    obj[key] = Value(s, ref i);
                    Space(s, ref i);
                    if (Peek(s, i) == ',') { i++; continue; }
                    Expect(s, ref i, '}');
                    return obj;
                }
            case '[':
                var list = new List<object?>();
                i++;
                Space(s, ref i);
                if (Peek(s, i) == ']') { i++; return list; }
                while (true)
                {
                    list.Add(Value(s, ref i));
                    Space(s, ref i);
                    if (Peek(s, i) == ',') { i++; continue; }
                    Expect(s, ref i, ']');
                    return list;
                }
            case '"': return Str(s, ref i);
            case 't': Word(s, ref i, "true"); return true;
            case 'f': Word(s, ref i, "false"); return false;
            case 'n': Word(s, ref i, "null"); return null;
            default:
                int start = i;
                while (i < s.Length && "+-0123456789.eE".IndexOf(s[i]) >= 0) i++;
                if (!double.TryParse(s.Substring(start, i - start), NumberStyles.Float, CultureInfo.InvariantCulture, out double d))
                    throw new FormatException($"JSON: bad value at {start}");
                return d;
        }
    }

    private static string Str(string s, ref int i)
    {
        var sb = new StringBuilder();
        i++;
        while (true)
        {
            if (i >= s.Length) throw new FormatException("JSON: unterminated string");
            char c = s[i++];
            if (c == '"') return sb.ToString();
            if (c != '\\') { sb.Append(c); continue; }
            if (i >= s.Length) throw new FormatException("JSON: unterminated string");
            char e = s[i++];
            switch (e)
            {
                case 'n': sb.Append('\n'); break;
                case 'r': sb.Append('\r'); break;
                case 't': sb.Append('\t'); break;
                case 'b': sb.Append('\b'); break;
                case 'f': sb.Append('\f'); break;
                case 'u':
                    if (i + 4 > s.Length || !int.TryParse(s.Substring(i, 4), NumberStyles.HexNumber, CultureInfo.InvariantCulture, out int u))
                        throw new FormatException($"JSON: bad escape at {i}");
                    sb.Append((char)u);
                    i += 4;
                    break;
                default: sb.Append(e); break;
            }
        }
    }

    private static char Peek(string s, int i) => i < s.Length ? s[i] : '\0';

    private static void Space(string s, ref int i)
    {
        while (i < s.Length && char.IsWhiteSpace(s[i])) i++;
    }

    private static void Expect(string s, ref int i, char c)
    {
        if (Peek(s, i) != c) throw new FormatException($"JSON: expected '{c}' at {i}");
        i++;
    }

    private static void Word(string s, ref int i, string word)
    {
        if (string.CompareOrdinal(s, i, word, 0, word.Length) != 0) throw new FormatException($"JSON: bad value at {i}");
        i += word.Length;
    }

    public static Dictionary<string, object?> AsObject(object? v) =>
        v as Dictionary<string, object?> ?? throw new FormatException("JSON: expected an object");

    public static string? Str(this Dictionary<string, object?> o, string key) => o.TryGetValue(key, out var v) ? v as string : null;

    public static bool Bool(this Dictionary<string, object?> o, string key) => o.TryGetValue(key, out var v) && v is true;

    public static int Int(this Dictionary<string, object?> o, string key) =>
        o.TryGetValue(key, out var v) && v is double d ? (int)d : throw new FormatException($"JSON: no number '{key}'");

    public static List<object?> List(this Dictionary<string, object?> o, string key) =>
        o.TryGetValue(key, out var v) && v is List<object?> l ? l : [];
}
