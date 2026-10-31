using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Http;
using Microsoft.Data.Sqlite;
using Vulpes.Plugins.SecretSharing.Data;
using Vulpes.Sdk;

namespace Vulpes.Plugins.SecretSharing.Services;

/// <summary>
/// HMAC-SHA256 proof of work. Same check as Sendit: leading zero bits, ASCII decimal nonce, one-time delete.
/// Difficulty and lifetimes come from the host <see cref="IPowPolicy"/> (Manage → Settings). Difficulty is at least 1.
/// </summary>
public sealed class PowService(ShareDatabase database, IPowPolicy? policy = null)
{
    private readonly IPowPolicy _policy = policy ?? DefaultPowPolicy.Instance;
    public const int DefaultDifficultyBits = PowPolicyLimits.DefaultDifficultyBits;
    public const int DefaultCollectTtlSeconds = PowPolicyLimits.DefaultCollectChallengeTtlSeconds;
    public const string HeaderChallenge = "X-Sendit-Pow-Challenge";
    public const string HeaderNonce = "X-Sendit-Pow-Nonce";
    public const string HeaderHash = "X-Sendit-Pow-Hash";
    public const string HttpContextPowConsumed = "vulpes.secret.pow.consumed";
    /// <summary>Anonymous uploads stay at this size until the header proof is burned.</summary>
    public const long SmallBodyBytes = 275_251;
    public const long LargeBodyBytes = 100L * 1024 * 1024;

    public sealed record Challenge(string ChallengeId, string HmacKey, int DifficultyBits, string ExpiresAt);

    public static void ReadFromHeaders(IHeaderDictionary headers, out string? challengeId, out string? nonce, out string? hash)
    {
        challengeId = Blank(headers[HeaderChallenge].ToString());
        nonce = Blank(headers[HeaderNonce].ToString());
        hash = Blank(headers[HeaderHash].ToString());
    }

    public Challenge Issue(string resourceKind, string resourceId, DateTimeOffset? secretExpiresAt = null)
    {
        var now = DateTimeOffset.UtcNow;
        if (secretExpiresAt is DateTimeOffset secretExp && secretExp <= now)
        {
            throw new InvalidOperationException("Cannot issue PoW for an already-expired secret.");
        }

        var id = NewId();
        var key = RandomNumberGenerator.GetBytes(32);
        var bits = _policy.DifficultyBits;
        var ttl = string.Equals(resourceKind, "collect", StringComparison.OrdinalIgnoreCase)
            ? _policy.CollectChallengeTtlSeconds
            : _policy.ChallengeTtlSeconds;
        var exp = now.AddSeconds(ttl);
        if (secretExpiresAt is DateTimeOffset cap && cap < exp) exp = cap;
        using var conn = database.Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = """
            INSERT INTO pow_challenges (Id, ResourceKind, ResourceId, HmacKey, DifficultyBits, ExpiresAt)
            VALUES (@id, @kind, @rid, @key, @bits, @exp)
            """;
        cmd.Parameters.AddWithValue("@id", id);
        cmd.Parameters.AddWithValue("@kind", resourceKind);
        cmd.Parameters.AddWithValue("@rid", resourceId);
        cmd.Parameters.AddWithValue("@key", key);
        cmd.Parameters.AddWithValue("@bits", bits);
        cmd.Parameters.AddWithValue("@exp", exp.ToString("O"));
        cmd.ExecuteNonQuery();
        return new Challenge(id, Base64Url.Encode(key), bits, exp.ToString("O"));
    }

    /// <summary>
    /// Validate without consuming. nginx <c>auth_request</c> uses this so the following POST can still <see cref="TryConsume"/>.
    /// A valid collect challenge is stretched to the current collect lifetime from now.
    /// </summary>
    public string? TryValidate(string resourceKind, string resourceId, string? challengeId, string? nonce, string? hashB64)
    {
        var error = TryConsume(resourceKind, resourceId, challengeId, nonce, hashB64, consume: false);
        if (error is not null || string.IsNullOrWhiteSpace(challengeId)) return error;
        if (!string.Equals(resourceKind, "collect", StringComparison.OrdinalIgnoreCase)) return null;
        using var conn = database.Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "UPDATE pow_challenges SET ExpiresAt = @exp WHERE Id = @id AND ResourceKind = 'collect'";
        cmd.Parameters.AddWithValue("@exp", DateTimeOffset.UtcNow.AddSeconds(_policy.CollectChallengeTtlSeconds).ToString("O"));
        cmd.Parameters.AddWithValue("@id", challengeId);
        cmd.ExecuteNonQuery();
        return null;
    }

    /// <summary>Returns null when the proof is valid and the challenge has been consumed.</summary>
    public string? TryConsume(string resourceKind, string resourceId, string? challengeId, string? nonce, string? hashB64)
        => TryConsume(resourceKind, resourceId, challengeId, nonce, hashB64, consume: true);

    private string? TryConsume(string resourceKind, string resourceId, string? challengeId, string? nonce, string? hashB64, bool consume)
    {
        if (string.IsNullOrWhiteSpace(challengeId) || string.IsNullOrWhiteSpace(nonce))
        {
            return "Proof of work is required (challengeId and nonce).";
        }

        using var conn = database.Open();
        using var tx = conn.BeginTransaction();
        using var sel = conn.CreateCommand();
        sel.Transaction = tx;
        sel.CommandText = "SELECT ResourceKind, ResourceId, HmacKey, DifficultyBits, ExpiresAt FROM pow_challenges WHERE Id = @id LIMIT 1";
        sel.Parameters.AddWithValue("@id", challengeId);
        using var reader = sel.ExecuteReader();
        if (!reader.Read())
        {
            tx.Rollback();
            return "Unknown or expired proof-of-work challenge.";
        }

        var kind = reader.GetString(0);
        var rid = reader.GetString(1);
        var key = (byte[])reader[2];
        var bits = reader.GetInt32(3);
        var exp = DateTimeOffset.Parse(reader.GetString(4), System.Globalization.CultureInfo.InvariantCulture);
        reader.Close();

        if (exp < DateTimeOffset.UtcNow)
        {
            Delete(conn, tx, challengeId);
            tx.Commit();
            return "Proof-of-work challenge expired.";
        }

        if (!string.Equals(kind, resourceKind, StringComparison.Ordinal) || !string.Equals(rid, resourceId, StringComparison.Ordinal))
        {
            tx.Rollback();
            return "Proof-of-work challenge does not match this secret.";
        }

        if (nonce.Length is 0 or > 24 || !nonce.All(char.IsAsciiDigit) || (nonce.Length > 1 && nonce[0] == '0'))
        {
            tx.Rollback();
            return "Invalid proof-of-work nonce.";
        }

        var mac = HMACSHA256.HashData(key, Encoding.ASCII.GetBytes(nonce));
        if (!HasLeadingZeroBits(mac, bits))
        {
            tx.Rollback();
            return "Proof of work does not meet difficulty.";
        }

        if (!string.IsNullOrWhiteSpace(hashB64))
        {
            try
            {
                var presented = Base64Url.Decode(hashB64);
                if (!CryptographicOperations.FixedTimeEquals(mac, presented))
                {
                    tx.Rollback();
                    return "Proof-of-work hash does not match.";
                }
            }
            catch (FormatException)
            {
                tx.Rollback();
                return "Invalid proof-of-work hash encoding.";
            }
        }

        if (consume && Delete(conn, tx, challengeId) != 1)
        {
            tx.Rollback();
            return "Proof-of-work challenge already used.";
        }

        tx.Commit();
        return null;
    }

    public static bool HasLeadingZeroBits(ReadOnlySpan<byte> hash, int bits)
    {
        if (bits <= 0)
        {
            return true;
        }

        if (bits > hash.Length * 8)
        {
            return false;
        }

        var fullBytes = bits / 8;
        var rem = bits % 8;
        for (var i = 0; i < fullBytes; i++)
        {
            if (hash[i] != 0)
            {
                return false;
            }
        }

        if (rem == 0)
        {
            return true;
        }

        var mask = (byte)(0xFF << (8 - rem));
        return (hash[fullBytes] & mask) == 0;
    }

    private static int Delete(SqliteConnection conn, SqliteTransaction tx, string id)
    {
        using var del = conn.CreateCommand();
        del.Transaction = tx;
        del.CommandText = "DELETE FROM pow_challenges WHERE Id = @id";
        del.Parameters.AddWithValue("@id", id);
        return del.ExecuteNonQuery();
    }

    private static string? Blank(string? value) => string.IsNullOrWhiteSpace(value) ? null : value.Trim();

    private static string NewId() => Base64Url.Encode(RandomNumberGenerator.GetBytes(16));

    private sealed class DefaultPowPolicy : IPowPolicy
    {
        public static readonly DefaultPowPolicy Instance = new();
        public int DifficultyBits => PowPolicyLimits.DefaultDifficultyBits;
        public int ChallengeTtlSeconds => PowPolicyLimits.DefaultChallengeTtlSeconds;
        public int CollectChallengeTtlSeconds => PowPolicyLimits.DefaultCollectChallengeTtlSeconds;
    }
}

public static class Base64Url
{
    public static string Encode(ReadOnlySpan<byte> data)
    {
        var s = Convert.ToBase64String(data);
        return s.TrimEnd('=').Replace('+', '-').Replace('/', '_');
    }

    public static byte[] Decode(string input)
    {
        var s = input.Replace('-', '+').Replace('_', '/');
        switch (s.Length % 4)
        {
            case 2: s += "=="; break;
            case 3: s += "="; break;
        }

        return Convert.FromBase64String(s);
    }

    public static bool IsToken(string? value, int max)
    {
        if (string.IsNullOrEmpty(value) || value.Length > max)
        {
            return false;
        }

        foreach (var c in value)
        {
            if (c is (>= 'A' and <= 'Z') or (>= 'a' and <= 'z') or (>= '0' and <= '9') or '-' or '_')
            {
                continue;
            }

            return false;
        }

        return true;
    }

    /// <summary>True when <paramref name="value"/> is canonical base64url for exactly <paramref name="bytes"/> decoded bytes.</summary>
    public static bool IsExact(string? value, int bytes)
    {
        if (!IsToken(value, ((bytes + 2) / 3 * 4) + 2))
        {
            return false;
        }

        try
        {
            return Decode(value!).Length == bytes;
        }
        catch (FormatException)
        {
            return false;
        }
    }
}
