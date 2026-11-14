namespace Vulpes.Plugins.SecretSharing.Services;

/// <summary>
/// X25519 from TweetNaCl, the same scalar multiplication the browser uses for a send.
/// .NET 10 has no <c>X25519DiffieHellman</c> type. That class starts in .NET 11.
/// </summary>
internal static class X25519
{
    private static readonly long[] Ladder = [0xdb41, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

    internal static byte[] ScalarMultBase(ReadOnlySpan<byte> secret)
    {
        Span<byte> basePoint = stackalloc byte[32];
        basePoint[0] = 9;
        return ScalarMult(secret, basePoint);
    }

    internal static byte[] ScalarMult(ReadOnlySpan<byte> secret, ReadOnlySpan<byte> point)
    {
        if (secret.Length != 32 || point.Length != 32)
        {
            throw new ArgumentException("X25519 keys are 32 bytes.");
        }

        var z = new byte[32];
        secret.CopyTo(z);
        z[31] = (byte)((secret[31] & 127) | 64);
        z[0] &= 248;

        var x = new long[80];
        Unpack(x, point);
        var a = new long[16];
        var b = new long[16];
        var c = new long[16];
        var d = new long[16];
        var e = new long[16];
        var f = new long[16];
        for (var i = 0; i < 16; i++)
        {
            b[i] = x[i];
        }

        a[0] = 1;
        d[0] = 1;
        for (var i = 254; i >= 0; i--)
        {
            var r = (z[i >> 3] >> (i & 7)) & 1;
            Select(a, b, r);
            Select(c, d, r);
            Add(e, a, c);
            Sub(a, a, c);
            Add(c, b, d);
            Sub(b, b, d);
            Square(d, e);
            Square(f, a);
            Multiply(a, c, a);
            Multiply(c, b, e);
            Add(e, a, c);
            Sub(a, a, c);
            Square(b, a);
            Sub(c, d, f);
            Multiply(a, c, Ladder);
            Add(a, a, d);
            Multiply(c, c, a);
            Multiply(a, d, f);
            Multiply(d, b, x);
            Square(b, e);
            Select(a, b, r);
            Select(c, d, r);
        }

        Array.Copy(a, 0, x, 16, 16);
        Array.Copy(c, 0, x, 32, 16);
        Array.Copy(b, 0, x, 48, 16);
        Array.Copy(d, 0, x, 64, 16);
        var inverse = new long[16];
        Array.Copy(x, 32, inverse, 0, 16);
        Invert(inverse);
        var product = new long[16];
        Array.Copy(x, 16, product, 0, 16);
        Multiply(product, product, inverse);
        var output = new byte[32];
        Pack(output, product);
        return output;
    }

    private static void Unpack(long[] field, ReadOnlySpan<byte> bytes)
    {
        for (var i = 0; i < 16; i++)
        {
            field[i] = bytes[2 * i] + (bytes[(2 * i) + 1] << 8);
        }

        field[15] &= 0x7fff;
    }

    private static void Pack(Span<byte> output, long[] field)
    {
        var t = (long[])field.Clone();
        Carry(t);
        Carry(t);
        Carry(t);
        for (var j = 0; j < 2; j++)
        {
            var m = new long[16];
            m[0] = t[0] - 0xffed;
            for (var i = 1; i < 15; i++)
            {
                m[i] = t[i] - 0xffff - ((ToInt32(m[i - 1]) >> 16) & 1);
                m[i - 1] &= 0xffff;
            }

            m[15] = t[15] - 0x7fff - ((ToInt32(m[14]) >> 16) & 1);
            var borrow = (ToInt32(m[15]) >> 16) & 1;
            m[14] &= 0xffff;
            Select(t, m, 1 - borrow);
        }

        for (var i = 0; i < 16; i++)
        {
            var limb = ToInt32(t[i]);
            output[2 * i] = (byte)(limb & 0xff);
            output[(2 * i) + 1] = (byte)(limb >> 8);
        }
    }

    private static void Add(long[] output, long[] left, long[] right)
    {
        for (var i = 0; i < 16; i++)
        {
            output[i] = left[i] + right[i];
        }
    }

    private static void Sub(long[] output, long[] left, long[] right)
    {
        for (var i = 0; i < 16; i++)
        {
            output[i] = left[i] - right[i];
        }
    }

    private static void Square(long[] output, long[] value) => Multiply(output, value, value);

    private static void Multiply(long[] output, long[] left, long[] right)
    {
        Span<long> t = stackalloc long[31];
        for (var i = 0; i < 16; i++)
        {
            for (var j = 0; j < 16; j++)
            {
                t[i + j] += left[i] * right[j];
            }
        }

        for (var i = 0; i < 15; i++)
        {
            t[i] += 38 * t[i + 16];
        }

        for (var pass = 0; pass < 2; pass++)
        {
            long carry = 1;
            for (var i = 0; i < 16; i++)
            {
                var wide = t[i] + carry + 65535;
                carry = Floor(wide, 65536);
                t[i] = wide - (carry * 65536);
            }

            t[0] += carry - 1 + (37 * (carry - 1));
        }

        for (var i = 0; i < 16; i++)
        {
            output[i] = t[i];
        }
    }

    private static void Carry(long[] field)
    {
        long carry = 1;
        for (var i = 0; i < 16; i++)
        {
            var wide = field[i] + carry + 65535;
            carry = Floor(wide, 65536);
            field[i] = wide - (carry * 65536);
        }

        field[0] += carry - 1 + (37 * (carry - 1));
    }

    private static void Invert(long[] value)
    {
        var c = (long[])value.Clone();
        for (var a = 253; a >= 0; a--)
        {
            Square(c, c);
            if (a is not 2 and not 4)
            {
                Multiply(c, c, value);
            }
        }

        Array.Copy(c, value, 16);
    }

    private static void Select(long[] left, long[] right, int bit)
    {
        var mask = ~(bit - 1);
        for (var i = 0; i < 16; i++)
        {
            var swap = mask & (ToInt32(left[i]) ^ ToInt32(right[i]));
            left[i] = ToInt32(left[i]) ^ swap;
            right[i] = ToInt32(right[i]) ^ swap;
        }
    }

    private static int ToInt32(long value) => unchecked((int)value);

    private static long Floor(long value, long divisor)
    {
        var quotient = value / divisor;
        if (value < 0 && value % divisor != 0)
        {
            quotient--;
        }

        return quotient;
    }
}
