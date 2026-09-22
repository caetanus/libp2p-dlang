/// A D port of Holepunch's `compact-encoding` (holepunchto/compact-encoding,
/// pinned d579287). This is the serialization codec the whole hyperswarm stack
/// speaks, so every byte here must match the reference exactly — the tests
/// assert against vectors generated from the real JS.
///
/// The reference models each codec as an object with three methods and threads
/// a mutable `state` through them:
///
///   preencode(state, m)  grows `state.end` by the size m will occupy
///   encode(state, m)     writes m at `state.start`, advancing it
///   decode(state)        reads one value at `state.start`, advancing it
///
/// Encoding is two-pass: preencode sizes the whole message, the buffer is
/// allocated once, then encode fills it. We keep that shape. Each codec is a
/// struct with static methods (a zero-size value type), and the combinators
/// (`ArrayOf`, `Frame`) are templates that take another codec as a parameter,
/// mirroring `c.array(enc)` / `c.frame(enc)`.
///
/// All integers are little-endian on the wire. The reference caps `uint`/`int`
/// at JavaScript's safe-integer range (a real peer never encodes past it), and
/// we replicate those bounds so we neither emit nor accept bytes the reference
/// would reject.
module libp2p.wire.cenc;

import std.traits : ReturnType;

/// JavaScript's Number.MAX_SAFE_INTEGER — the ceiling `uint` accepts.
enum ulong MAX_SAFE_INTEGER = (1UL << 53) - 1;
/// Zig-zag doubles a value's magnitude before writing it as a uint, so a
/// signed int only reaches half as far as a uint of the same width.
enum long MAX_SAFE_INT = (1L << 52) - 1;
enum long MIN_SAFE_INT = -(1L << 52);

/// The cursor threaded through preencode/encode/decode. During preencode the
/// buffer is null and only `end` moves; encode/decode advance `start`.
struct State
{
    size_t start;
    size_t end;
    ubyte[] buffer;
}

/// `c.state()` — a fresh cursor.
State state(size_t start = 0, size_t end = 0, ubyte[] buffer = null)
{
    return State(start, end, buffer);
}

private void outOfBounds()
{
    throw new Exception("Out of bounds");
}

private void requireBytes(ref State s, size_t n)
{
    if (s.end - s.start < n)
        outOfBounds();
}

// ── little-endian / big-endian fixed-width helpers ───────────────────────────

private void writeLE(ref State s, ulong n, size_t bytes)
{
    foreach (i; 0 .. bytes)
    {
        s.buffer[s.start++] = cast(ubyte)(n & 0xff);
        n >>= 8;
    }
}

private ulong readLE(ref State s, size_t bytes)
{
    requireBytes(s, bytes);
    ulong n = 0;
    foreach (i; 0 .. bytes)
        n |= cast(ulong)s.buffer[s.start++] << (8 * i);
    return n;
}

private void writeBE(ref State s, ulong n, size_t bytes)
{
    foreach_reverse (i; 0 .. bytes)
        s.buffer[s.start++] = cast(ubyte)((n >> (8 * i)) & 0xff);
}

private ulong readBE(ref State s, size_t bytes)
{
    requireBytes(s, bytes);
    ulong n = 0;
    foreach (i; 0 .. bytes)
        n = (n << 8) | s.buffer[s.start++];
    return n;
}

private void validateUint(ulong n)
{
    if (n > MAX_SAFE_INTEGER)
        throw new Exception("uint must be between 0 and 9007199254740991, use biguint");
}

// ── unsigned integers ────────────────────────────────────────────────────────

/// The variable-length uint: 1 byte for values ≤ 0xfc, otherwise a tag byte
/// (0xfd/0xfe/0xff) followed by a 2/4/8-byte little-endian value.
struct Uint
{
    static void preencode(ref State s, ulong n)
    {
        s.end += n <= 0xfc ? 1 : n <= 0xffff ? 3 : n <= 0xffffffff ? 5 : 9;
    }

    static void encode(ref State s, ulong n)
    {
        validateUint(n);
        if (n <= 0xfc)
            s.buffer[s.start++] = cast(ubyte)n;
        else if (n <= 0xffff)
        {
            s.buffer[s.start++] = 0xfd;
            writeLE(s, n, 2);
        }
        else if (n <= 0xffffffff)
        {
            s.buffer[s.start++] = 0xfe;
            writeLE(s, n, 4);
        }
        else
        {
            s.buffer[s.start++] = 0xff;
            writeLE(s, n, 8);
        }
    }

    static ulong decode(ref State s)
    {
        immutable a = Uint8.decode(s);
        if (a <= 0xfc)
            return a;
        if (a == 0xfd)
            return readLE(s, 2);
        if (a == 0xfe)
            return readLE(s, 4);
        immutable n = readLE(s, 8);
        if (n > MAX_SAFE_INTEGER)
            outOfBounds();
        return n;
    }
}

private mixin template FixedUint(size_t BYTES)
{
    static void preencode(ref State s, ulong n)
    {
        s.end += BYTES;
    }

    static void encode(ref State s, ulong n)
    {
        validateUint(n);
        writeLE(s, n, BYTES);
    }

    static ulong decode(ref State s)
    {
        immutable n = readLE(s, BYTES);
        static if (BYTES >= 7)
            if (n > MAX_SAFE_INTEGER)
                outOfBounds();
        return n;
    }
}

struct Uint8 { mixin FixedUint!1; }
struct Uint16 { mixin FixedUint!2; }
struct Uint24 { mixin FixedUint!3; }
struct Uint32 { mixin FixedUint!4; }
struct Uint40 { mixin FixedUint!5; }
struct Uint48 { mixin FixedUint!6; }
struct Uint56 { mixin FixedUint!7; }
struct Uint64 { mixin FixedUint!8; }

/// Big-endian 32-bit — used by a few length prefixes in the stack.
struct Uint32be
{
    static void preencode(ref State s, ulong n) { s.end += 4; }
    static void encode(ref State s, ulong n) { validateUint(n); writeBE(s, n, 4); }
    static ulong decode(ref State s) { return readBE(s, 4); }
}

struct Uint64be
{
    static void preencode(ref State s, ulong n) { s.end += 8; }
    static void encode(ref State s, ulong n)
    {
        validateUint(n);
        writeBE(s, n, 8);
    }
    static ulong decode(ref State s)
    {
        immutable n = readBE(s, 8);
        if (n > MAX_SAFE_INTEGER)
            outOfBounds();
        return n;
    }
}

// ── signed integers (zig-zag over a uint codec) ──────────────────────────────

private ulong zigZagEncode(long n)
{
    if (n < MIN_SAFE_INT || n > MAX_SAFE_INT)
        throw new Exception("int out of safe range, use bigint");
    // 0, -1, 1, -2, 2, ...
    return n < 0 ? cast(ulong)(2 * -n - 1) : cast(ulong)(2 * n);
}

private long zigZagDecode(ulong u)
{
    immutable n = cast(long)u;
    if (n == 0)
        return 0;
    return (n & 1) == 0 ? n / 2 : -(n + 1) / 2;
}

/// Wraps an unsigned codec `U` in zig-zag so it carries a signed value.
template ZigZag(U)
{
    struct ZigZag
    {
        static void preencode(ref State s, long n) { U.preencode(s, zigZagEncode(n)); }
        static void encode(ref State s, long n) { U.encode(s, zigZagEncode(n)); }
        static long decode(ref State s) { return zigZagDecode(U.decode(s)); }
    }
}

alias Int = ZigZag!Uint;
alias Int8 = ZigZag!Uint8;
alias Int16 = ZigZag!Uint16;
alias Int24 = ZigZag!Uint24;
alias Int32 = ZigZag!Uint32;
alias Int40 = ZigZag!Uint40;
alias Int48 = ZigZag!Uint48;
alias Int56 = ZigZag!Uint56;
alias Int64 = ZigZag!Uint64;

// ── floats ───────────────────────────────────────────────────────────────────

struct Float32
{
    static void preencode(ref State s, float n) { s.end += 4; }
    static void encode(ref State s, float n)
    {
        import std.bitmanip : nativeToLittleEndian;
        s.buffer[s.start .. s.start + 4] = nativeToLittleEndian(n)[];
        s.start += 4;
    }
    static float decode(ref State s)
    {
        import std.bitmanip : littleEndianToNative;
        requireBytes(s, 4);
        ubyte[4] b = s.buffer[s.start .. s.start + 4];
        s.start += 4;
        return littleEndianToNative!float(b);
    }
}

struct Float64
{
    static void preencode(ref State s, double n) { s.end += 8; }
    static void encode(ref State s, double n)
    {
        import std.bitmanip : nativeToLittleEndian;
        s.buffer[s.start .. s.start + 8] = nativeToLittleEndian(n)[];
        s.start += 8;
    }
    static double decode(ref State s)
    {
        import std.bitmanip : littleEndianToNative;
        requireBytes(s, 8);
        ubyte[8] b = s.buffer[s.start .. s.start + 8];
        s.start += 8;
        return littleEndianToNative!double(b);
    }
}

// ── bool ─────────────────────────────────────────────────────────────────────

struct Bool
{
    static void preencode(ref State s, bool b) { s.end += 1; }
    static void encode(ref State s, bool b) { s.buffer[s.start++] = b ? 1 : 0; }
    static bool decode(ref State s)
    {
        if (s.start >= s.end)
            outOfBounds();
        return s.buffer[s.start++] == 1;
    }
}

// ── length-prefixed byte buffers ─────────────────────────────────────────────

/// `c.buffer` / `c.uint8array`: a uint length prefix followed by the raw bytes.
/// Decode returns a slice that views into the input buffer (like JS subarray).
struct Buffer
{
    static void preencode(ref State s, const(ubyte)[] b)
    {
        Uint.preencode(s, b.length);
        s.end += b.length;
    }
    static void encode(ref State s, const(ubyte)[] b)
    {
        Uint.encode(s, b.length);
        s.buffer[s.start .. s.start + b.length] = b[];
        s.start += b.length;
    }
    static ubyte[] decode(ref State s)
    {
        immutable len = cast(size_t)Uint.decode(s);
        requireBytes(s, len);
        auto b = s.buffer[s.start .. s.start + len];
        s.start += len;
        return b;
    }
}

/// A fixed-width byte field of exactly N bytes (no length prefix). `c.fixed(n)`.
template Fixed(size_t N)
{
    struct Fixed
    {
        static void preencode(ref State s, const(ubyte)[] b)
        {
            if (b.length != N)
                throw new Exception("Incorrect buffer size");
            s.end += N;
        }
        static void encode(ref State s, const(ubyte)[] b)
        {
            s.buffer[s.start .. s.start + N] = b[0 .. N];
            s.start += N;
        }
        static ubyte[] decode(ref State s)
        {
            requireBytes(s, N);
            auto b = s.buffer[s.start .. s.start + N];
            s.start += N;
            return b;
        }
    }
}

alias Fixed32 = Fixed!32;
alias Fixed64 = Fixed!64;

// ── strings ──────────────────────────────────────────────────────────────────

/// `c.string` / `c.utf8`: a uint byte-length prefix followed by UTF-8 bytes.
struct Utf8
{
    static void preencode(ref State s, const(char)[] str)
    {
        Uint.preencode(s, str.length);
        s.end += str.length;
    }
    static void encode(ref State s, const(char)[] str)
    {
        Uint.encode(s, str.length);
        s.buffer[s.start .. s.start + str.length] = cast(const(ubyte)[])str;
        s.start += str.length;
    }
    static string decode(ref State s)
    {
        immutable len = cast(size_t)Uint.decode(s);
        requireBytes(s, len);
        auto str = cast(string)(s.buffer[s.start .. s.start + len].idup);
        s.start += len;
        return str;
    }
}

alias Str = Utf8;

// ── combinators ──────────────────────────────────────────────────────────────

/// `c.array(enc)`: a uint count followed by that many `Elem`-encoded items.
template ArrayOf(Elem)
{
    private alias T = ReturnType!(Elem.decode);

    struct ArrayOf
    {
        static void preencode(ref State s, const(T)[] list)
        {
            Uint.preencode(s, list.length);
            foreach (ref item; list)
                Elem.preencode(s, item);
        }
        static void encode(ref State s, const(T)[] list)
        {
            Uint.encode(s, list.length);
            foreach (ref item; list)
                Elem.encode(s, item);
        }
        static T[] decode(ref State s)
        {
            immutable len = cast(size_t)Uint.decode(s);
            if (len > 0x100000)
                throw new Exception("Array is too big");
            // Don't preallocate `len`: a tiny datagram can claim ~1M elements. Append
            // as we decode, so a bogus count fails fast on the first missing element
            // (Elem.decode throws out-of-bounds) instead of allocating megabytes.
            T[] arr;
            arr.reserve(len < 4096 ? len : 4096);
            foreach (i; 0 .. len)
                arr ~= Elem.decode(s);
            return arr;
        }
    }
}

/// `c.frame(enc)`: prefixes an `Inner`-encoded message with its uint byte length,
/// so a decoder can bound the inner message exactly.
template Frame(Inner)
{
    private alias T = ReturnType!(Inner.decode);

    struct Frame
    {
        static void preencode(ref State s, const(T) m)
        {
            immutable before = s.end;
            Inner.preencode(s, m);
            Uint.preencode(s, s.end - before);
        }
        static void encode(ref State s, const(T) m)
        {
            State dummy;
            Inner.preencode(dummy, m);
            Uint.encode(s, dummy.end);
            Inner.encode(s, m);
        }
        static T decode(ref State s)
        {
            immutable savedEnd = s.end;
            immutable len = cast(size_t)Uint.decode(s);
            s.end = s.start + len;
            auto m = Inner.decode(s);
            s.start = s.end;
            s.end = savedEnd;
            return m;
        }
    }
}

// ── network addresses ────────────────────────────────────────────────────────

struct Address
{
    string host;
    int family;
    ushort port;
}

/// `c.port` is a bare uint16.
alias Port = Uint16;

/// `c.ipv4`: four raw bytes, encoded from / decoded to a dotted-quad string.
struct Ipv4
{
    static void preencode(ref State s, const(char)[] str) { s.end += 4; }
    static void encode(ref State s, const(char)[] str)
    {
        size_t i = 0;
        foreach (_; 0 .. 4)
        {
            uint n = 0;
            while (i < str.length && str[i] != '.')
                n = n * 10 + (str[i++] - '0');
            if (i < str.length)
                i++; // skip '.'
            s.buffer[s.start++] = cast(ubyte)n;
        }
    }
    static string decode(ref State s)
    {
        import std.conv : to;
        requireBytes(s, 4);
        auto a = s.buffer[s.start++];
        auto b = s.buffer[s.start++];
        auto c = s.buffer[s.start++];
        auto d = s.buffer[s.start++];
        return a.to!string ~ "." ~ b.to!string ~ "." ~ c.to!string ~ "." ~ d.to!string;
    }
}

/// `c.ipv6`: sixteen bytes, with "::" expansion on encode. Decode returns the
/// eight hex groups joined by ':' (uncompressed), matching the reference.
struct Ipv6
{
    static void preencode(ref State s, const(char)[] str) { s.end += 16; }
    static void encode(ref State s, const(char)[] str)
    {
        immutable start = s.start;
        immutable end = start + 16;
        size_t i = 0;
        bool haveSplit = false;
        size_t split = 0;

        while (i < str.length)
        {
            uint n = 0;
            while (i < str.length && str[i] != ':')
            {
                immutable c = str[i++];
                if (c >= '0' && c <= '9')
                    n = n * 0x10 + (c - '0');
                else if (c >= 'A' && c <= 'F')
                    n = n * 0x10 + (c - 'A' + 10);
                else if (c >= 'a' && c <= 'f')
                    n = n * 0x10 + (c - 'a' + 10);
            }
            s.buffer[s.start++] = cast(ubyte)(n >> 8);
            s.buffer[s.start++] = cast(ubyte)n;

            if (i < str.length && str[i] == ':')
            {
                i++;
                haveSplit = true;
                split = s.start;
            }
        }

        if (haveSplit)
        {
            // A "::" was seen at `split`. The groups written after it sit
            // directly behind the ones before it; shift them to the tail and
            // zero-fill the gap the compression stands for.
            immutable offset = end - s.start;
            auto tail = s.buffer[split .. s.start].dup;
            s.buffer[split .. split + offset] = 0;
            s.buffer[end - tail.length .. end] = tail[];
        }

        s.start = end;
    }
    static string decode(ref State s)
    {
        import std.conv : to;
        import std.format : format;
        requireBytes(s, 16);
        string outStr;
        foreach (g; 0 .. 8)
        {
            immutable hi = s.buffer[s.start++];
            immutable lo = s.buffer[s.start++];
            immutable group = hi * 256 + lo;
            if (g)
                outStr ~= ":";
            outStr ~= format("%x", group);
        }
        return outStr;
    }
}

private template AddressCodec(Host, int family)
{
    struct AddressCodec
    {
        static void preencode(ref State s, const Address m)
        {
            Host.preencode(s, m.host);
            Port.preencode(s, m.port);
        }
        static void encode(ref State s, const Address m)
        {
            Host.encode(s, m.host);
            Port.encode(s, m.port);
        }
        static Address decode(ref State s)
        {
            Address a;
            a.host = Host.decode(s);
            a.family = family;
            a.port = cast(ushort)Port.decode(s);
            return a;
        }
    }
}

alias Ipv4Address = AddressCodec!(Ipv4, 4);
alias Ipv6Address = AddressCodec!(Ipv6, 6);

/// `c.ip`: a family byte (4 or 6) then the address. Family is chosen by whether
/// the host string contains a ':'.
struct Ip
{
    private static int familyOf(const(char)[] str)
    {
        foreach (c; str)
            if (c == ':')
                return 6;
        return 4;
    }
    static void preencode(ref State s, const(char)[] str)
    {
        Uint8.preencode(s, familyOf(str));
        s.end += familyOf(str) == 4 ? 4 : 16;
    }
    static void encode(ref State s, const(char)[] str)
    {
        immutable family = familyOf(str);
        Uint8.encode(s, family);
        if (family == 4)
            Ipv4.encode(s, str);
        else
            Ipv6.encode(s, str);
    }
    static string decode(ref State s)
    {
        immutable family = Uint8.decode(s);
        return family == 4 ? Ipv4.decode(s) : Ipv6.decode(s);
    }
}

/// `c.ipAddress`: an `ip` host followed by a uint16 port.
struct IpAddress
{
    static void preencode(ref State s, const Address m)
    {
        Ip.preencode(s, m.host);
        Port.preencode(s, m.port);
    }
    static void encode(ref State s, const Address m)
    {
        Ip.encode(s, m.host);
        Port.encode(s, m.port);
    }
    static Address decode(ref State s)
    {
        immutable family = cast(int)Uint8.decode(s);
        Address a;
        a.host = family == 4 ? Ipv4.decode(s) : Ipv6.decode(s);
        a.family = family;
        a.port = cast(ushort)Port.decode(s);
        return a;
    }
}

// ── top-level encode/decode ──────────────────────────────────────────────────

/// `c.encode(enc, m)`: two-pass — size, allocate once, fill.
ubyte[] encode(C, T)(auto ref T m)
{
    State s;
    C.preencode(s, m);
    s.buffer = new ubyte[](s.end);
    C.encode(s, m);
    return s.buffer;
}

/// `c.decode(enc, buffer)`.
auto decode(C)(ubyte[] buffer)
{
    auto s = State(0, buffer.length, buffer);
    return C.decode(s);
}
