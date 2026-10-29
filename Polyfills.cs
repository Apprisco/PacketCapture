namespace System.Runtime.CompilerServices
{
    internal static class IsExternalInit { }
}

namespace PacketCapture
{
    internal static class Polyfills
    {
        public static void Deconstruct<TKey, TValue>(this KeyValuePair<TKey, TValue> pair, out TKey key, out TValue value) =>
            (key, value) = (pair.Key, pair.Value);
    }
}
