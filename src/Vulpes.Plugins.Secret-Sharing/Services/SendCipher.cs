using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace Vulpes.Plugins.SecretSharing.Services;

/// <summary>The browser send: AES-256-GCM payload, X25519 wrap, owner fields under the user data key.</summary>
internal static class SendCipher
{
    private static readonly byte[] WrapInfo = Encoding.ASCII.GetBytes("sendit-v1-wrap");

    internal static SendWire Encrypt(ReadOnlySpan<byte> plaintext, out byte[] recipientSecret)
    {
        recipientSecret = RandomNumberGenerator.GetBytes(32);
        var recipientPublic = X25519.ScalarMultBase(recipientSecret);
        return EncryptFor(plaintext, recipientPublic);
    }

    internal static SendWire EncryptFor(ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> recipientPublic)
    {
        var aesKey = RandomNumberGenerator.GetBytes(32);
        var iv = RandomNumberGenerator.GetBytes(12);
        try
        {
            var payload = Aes(aesKey, iv, plaintext, encrypt: true);
            var wrapped = Wrap(aesKey, recipientPublic);
            return new SendWire(Base64Url.Encode(payload), Base64Url.Encode(iv), Base64Url.Encode(wrapped.Packed), Base64Url.Encode(wrapped.EphemeralPublic));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(aesKey);
        }
    }

    internal static byte[] Decrypt(SendWire wire, ReadOnlySpan<byte> recipientSecret)
    {
        var iv = Base64Url.Decode(wire.Iv);
        var payload = Base64Url.Decode(wire.Ciphertext);
        var wrapped = Base64Url.Decode(wire.WrappedKey);
        var ephemeral = Base64Url.Decode(wire.EphemeralPublicKey);
        var aesKey = Unwrap(wrapped, ephemeral, recipientSecret);
        try
        {
            return Aes(aesKey, iv, payload, encrypt: false);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(aesKey);
        }
    }

    internal static string SealOwnerField(string text, ReadOnlySpan<byte> userDataKey)
    {
        var plain = Encoding.UTF8.GetBytes(text);
        var iv = RandomNumberGenerator.GetBytes(12);
        try
        {
            var packed = new byte[12 + plain.Length + 16];
            iv.CopyTo(packed);
            Aes(userDataKey, iv, plain, encrypt: true).CopyTo(packed.AsSpan(12));
            return Base64Url.Encode(packed);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plain);
        }
    }

    internal static string? OpenOwnerField(string? packed, ReadOnlySpan<byte> userDataKey)
    {
        if (string.IsNullOrEmpty(packed))
        {
            return null;
        }

        try
        {
            var bytes = Base64Url.Decode(packed);
            if (bytes.Length < 12 + 16)
            {
                return null;
            }

            var plain = Aes(userDataKey, bytes.AsSpan(0, 12), bytes.AsSpan(12), encrypt: false);
            var text = Encoding.UTF8.GetString(plain);
            CryptographicOperations.ZeroMemory(plain);
            return text;
        }
        catch (CryptographicException)
        {
            return null;
        }
        catch (FormatException)
        {
            return null;
        }
    }

    internal const int PasswordIterations = 893241;

    internal static string WrapSecretKey(ReadOnlySpan<byte> secretKey, string password)
    {
        var salt = RandomNumberGenerator.GetBytes(16);
        var iv = RandomNumberGenerator.GetBytes(12);
        var key = Rfc2898DeriveBytes.Pbkdf2(password, salt, PasswordIterations, HashAlgorithmName.SHA512, 32);
        try
        {
            var ct = Aes(key, iv, secretKey, encrypt: true);
            return "{\"i\":" + PasswordIterations.ToString(CultureInfo.InvariantCulture)
                + ",\"s\":\"" + Base64Url.Encode(salt)
                + "\",\"iv\":\"" + Base64Url.Encode(iv)
                + "\",\"ct\":\"" + Base64Url.Encode(ct) + "\"}";
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
        }
    }

    internal static byte[] UnwrapSecretKey(string packageJson, string password)
    {
        using var document = JsonDocument.Parse(packageJson);
        var root = document.RootElement;
        if (root.GetProperty("i").GetInt32() != PasswordIterations)
        {
            throw new CryptographicException("Unsupported wrap parameters.");
        }

        var salt = Base64Url.Decode(root.GetProperty("s").GetString()!);
        var iv = Base64Url.Decode(root.GetProperty("iv").GetString()!);
        var ct = Base64Url.Decode(root.GetProperty("ct").GetString()!);
        var key = Rfc2898DeriveBytes.Pbkdf2(password, salt, PasswordIterations, HashAlgorithmName.SHA512, 32);
        try
        {
            var plain = Aes(key, iv, ct, encrypt: false);
            if (plain.Length != 32)
            {
                throw new CryptographicException("Unwrapped key has unexpected length.");
            }

            return plain;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
        }
    }

    internal static string RecipientLabel(ReadOnlySpan<byte> label, ReadOnlySpan<byte> recipientPublic)
    {
        var wire = EncryptFor(label, recipientPublic);
        return new JsonObject
        {
            ["v"] = 1,
            ["ciphertext"] = wire.Ciphertext,
            ["iv"] = wire.Iv,
            ["wrappedKey"] = wire.WrappedKey,
            ["ephemeralPublicKey"] = wire.EphemeralPublicKey,
        }.ToJsonString();
    }

    internal static bool ContributoryPublicKey(ReadOnlySpan<byte> publicKey)
    {
        if (publicKey.Length != 32)
        {
            return false;
        }

        Span<byte> scalar = stackalloc byte[32];
        scalar[0] = 9;
        return Contributes(X25519.ScalarMult(scalar, publicKey));
    }

    private static bool Contributes(ReadOnlySpan<byte> shared)
    {
        foreach (var b in shared)
        {
            if (b != 0)
            {
                return true;
            }
        }

        return false;
    }

    private static (byte[] Packed, byte[] EphemeralPublic) Wrap(ReadOnlySpan<byte> aesKey, ReadOnlySpan<byte> recipientPublic)
    {
        var ephemeralSecret = RandomNumberGenerator.GetBytes(32);
        try
        {
            var ephemeralPublic = X25519.ScalarMultBase(ephemeralSecret);
            var shared = X25519.ScalarMult(ephemeralSecret, recipientPublic);
            if (!Contributes(shared))
            {
                CryptographicOperations.ZeroMemory(shared);
                throw new CryptographicException("Recipient public key is not usable.");
            }

            var wrapKey = HKDF.DeriveKey(HashAlgorithmName.SHA256, shared, 32, new byte[32], WrapInfo);
            CryptographicOperations.ZeroMemory(shared);
            try
            {
                var iv = RandomNumberGenerator.GetBytes(12);
                var sealedKey = Aes(wrapKey, iv, aesKey, encrypt: true);
                var packed = new byte[12 + sealedKey.Length];
                iv.CopyTo(packed);
                sealedKey.CopyTo(packed.AsSpan(12));
                return (packed, ephemeralPublic);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(wrapKey);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(ephemeralSecret);
        }
    }

    private static byte[] Unwrap(ReadOnlySpan<byte> packed, ReadOnlySpan<byte> ephemeralPublic, ReadOnlySpan<byte> recipientSecret)
    {
        var shared = X25519.ScalarMult(recipientSecret, ephemeralPublic);
        var wrapKey = HKDF.DeriveKey(HashAlgorithmName.SHA256, shared, 32, new byte[32], WrapInfo);
        CryptographicOperations.ZeroMemory(shared);
        try
        {
            return Aes(wrapKey, packed[..12], packed[12..], encrypt: false);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(wrapKey);
        }
    }

    private static byte[] Aes(ReadOnlySpan<byte> key, ReadOnlySpan<byte> iv, ReadOnlySpan<byte> input, bool encrypt)
    {
        using var aes = new AesGcm(key, 16);
        if (encrypt)
        {
            var cipher = new byte[input.Length];
            var tag = new byte[16];
            aes.Encrypt(iv, input, cipher, tag);
            var output = new byte[cipher.Length + tag.Length];
            cipher.CopyTo(output);
            tag.CopyTo(output.AsSpan(cipher.Length));
            return output;
        }

        var body = input[..^16];
        var found = input[^16..];
        var plain = new byte[body.Length];
        aes.Decrypt(iv, body, found, plain);
        return plain;
    }
}

internal readonly record struct SendWire(string Ciphertext, string Iv, string WrappedKey, string EphemeralPublicKey);
