using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using Vulpes.Plugins.SecretSharing.Data;
using Vulpes.Plugins.SecretSharing.Services;
using Vulpes.Sdk;
using Xunit;

namespace Vulpes.Plugins.SecretSharing.Tests;

public sealed class ProofOfWorkTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "ss-pow-" + Guid.NewGuid().ToString("N"));
    private readonly ShareDatabase _db;
    private readonly PowService _pow;

    public ProofOfWorkTests()
    {
        Directory.CreateDirectory(_dir);
        _db = new ShareDatabase(Path.Combine(_dir, "secret-sharing.db"));
        _pow = new PowService(_db);
    }

    [Fact]
    public void Validate_leaves_the_challenge_for_the_upload()
    {
        var challenge = _pow.Issue("collect", "collect-1");
        var (nonce, hash) = Solve(challenge);
        var issued = DateTimeOffset.Parse(challenge.ExpiresAt, System.Globalization.CultureInfo.InvariantCulture);
        Assert.Null(_pow.TryValidate("collect", "collect-1", challenge.ChallengeId, nonce, hash));
        Assert.Null(_pow.TryValidate("collect", "collect-1", challenge.ChallengeId, nonce, hash));
        using (var conn = _db.Open())
        using (var cmd = conn.CreateCommand())
        {
            cmd.CommandText = "SELECT ExpiresAt FROM pow_challenges WHERE Id = @id";
            cmd.Parameters.AddWithValue("@id", challenge.ChallengeId);
            var stored = DateTimeOffset.Parse((string)cmd.ExecuteScalar()!, System.Globalization.CultureInfo.InvariantCulture);
            Assert.Equal(issued, stored);
        }

        Assert.Null(_pow.TryConsume("collect", "collect-1", challenge.ChallengeId, nonce, hash));
        Assert.NotNull(_pow.TryConsume("collect", "collect-1", challenge.ChallengeId, nonce, hash));
    }

    [Fact]
    public void Issued_difficulty_follows_the_host_policy()
    {
        var policy = new MutablePowPolicy { DifficultyBits = 5, ChallengeTtlSeconds = 45, CollectChallengeTtlSeconds = 900 };
        var pow = new PowService(_db, policy);
        var first = pow.Issue("send", "a");
        Assert.Equal(5, first.DifficultyBits);
        var sendLife = DateTimeOffset.Parse(first.ExpiresAt, System.Globalization.CultureInfo.InvariantCulture) - DateTimeOffset.UtcNow;
        Assert.InRange(sendLife.TotalSeconds, 30, 50);

        policy.DifficultyBits = 7;
        policy.CollectChallengeTtlSeconds = 1200;
        var second = pow.Issue("collect", "b");
        Assert.Equal(7, second.DifficultyBits);
        var collectLife = DateTimeOffset.Parse(second.ExpiresAt, System.Globalization.CultureInfo.InvariantCulture) - DateTimeOffset.UtcNow;
        Assert.InRange(collectLife.TotalSeconds, 1100, 1210);
    }

    [Fact]
    public void A_challenge_can_be_issued_without_a_stored_secret()
    {
        var challenge = _pow.Issue("send", "not-a-real-secret");
        Assert.False(string.IsNullOrWhiteSpace(challenge.ChallengeId));
        Assert.False(string.IsNullOrWhiteSpace(challenge.HmacKey));
    }

    [Fact]
    public void Issue_refuses_an_already_expired_secret()
    {
        Assert.Throws<InvalidOperationException>(() => _pow.Issue("send", "secret-1", DateTimeOffset.UtcNow.AddMinutes(-1)));
    }

    [Fact]
    public void Ten_failed_lookups_from_one_address_are_rate_limited()
    {
        var guard = new ShareScanGuard(_db);
        for (var i = 0; i < 9; i++) guard.RecordFailure("203.0.113.10");
        Assert.False(guard.IsFailureBudgetExceeded("203.0.113.10", out _));
        guard.RecordFailure("203.0.113.10");
        Assert.True(guard.IsFailureBudgetExceeded("203.0.113.10", out var retry));
        Assert.True(retry > 0);
        Assert.False(guard.IsFailureBudgetExceeded("203.0.113.11", out _));
    }

    [Fact]
    public void Leading_zero_bits_match_the_high_bits_only()
    {
        Assert.True(PowService.HasLeadingZeroBits([0x00, 0xFF], 8));
        Assert.False(PowService.HasLeadingZeroBits([0x00, 0x80], 9));
        Assert.True(PowService.HasLeadingZeroBits([0x7F], 1));
        Assert.False(PowService.HasLeadingZeroBits([0x80], 1));
        Assert.True(PowService.HasLeadingZeroBits([0xFF], 0));
        Assert.False(PowService.HasLeadingZeroBits([0x00], 9));
    }

    [Fact]
    public void A_solved_challenge_is_accepted_once_and_only_for_its_resource()
    {
        var challenge = _pow.Issue("send", "secret-1");
        var (nonce, hash) = Solve(challenge);
        Assert.Null(_pow.TryConsume("send", "secret-1", challenge.ChallengeId, nonce, hash));
        Assert.Equal("Unknown or expired proof-of-work challenge.", _pow.TryConsume("send", "secret-1", challenge.ChallengeId, nonce, hash));

        var other = _pow.Issue("send", "secret-1");
        var solved = Solve(other);
        Assert.Equal("Proof-of-work challenge does not match this secret.", _pow.TryConsume("collect", "secret-1", other.ChallengeId, solved.Nonce, solved.Hash));
        var bound = _pow.Issue("send", "secret-1", clientId: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        var boundSolved = Solve(bound);
        Assert.Equal("Proof-of-work challenge does not match this browser.", _pow.TryConsume("send", "secret-1", bound.ChallengeId, boundSolved.Nonce, boundSolved.Hash, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"));
        Assert.Null(_pow.TryConsume("send", "secret-1", bound.ChallengeId, boundSolved.Nonce, boundSolved.Hash, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"));
        Assert.Equal("Invalid proof-of-work nonce.", _pow.TryConsume("send", "secret-1", other.ChallengeId, "01", solved.Hash));
        Assert.Equal("Proof-of-work hash does not match.", _pow.TryConsume("send", "secret-1", other.ChallengeId, solved.Nonce, Base64Url.Encode([1, 2, 3, 4])));
        Assert.Null(_pow.TryConsume("send", "secret-1", other.ChallengeId, solved.Nonce, solved.Hash));
    }

    [Fact]
    public void An_expired_challenge_is_rejected()
    {
        var challenge = _pow.Issue("send", "secret-1");
        using var conn = _db.Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "UPDATE pow_challenges SET ExpiresAt = @exp WHERE Id = @id";
        cmd.Parameters.AddWithValue("@exp", DateTimeOffset.UnixEpoch.ToString("O"));
        cmd.Parameters.AddWithValue("@id", challenge.ChallengeId);
        cmd.ExecuteNonQuery();
        var solved = Solve(challenge);
        Assert.Equal("Proof-of-work challenge expired.", _pow.TryConsume("send", "secret-1", challenge.ChallengeId, solved.Nonce, solved.Hash));
    }

    private static (string Nonce, string Hash) Solve(PowService.Challenge challenge)
    {
        var key = Base64Url.Decode(challenge.HmacKey);
        for (var n = 0; n < 2_000_000; n++)
        {
            var nonce = n.ToString(System.Globalization.CultureInfo.InvariantCulture);
            var mac = HMACSHA256.HashData(key, Encoding.ASCII.GetBytes(nonce));
            if (PowService.HasLeadingZeroBits(mac, challenge.DifficultyBits))
            {
                return (nonce, Base64Url.Encode(mac));
            }
        }

        throw new InvalidOperationException("No proof found.");
    }

    [Fact]
    public void Thirty_issues_is_the_cap_and_an_expired_challenge_is_purged()
    {
        const string client = "203.0.113.50";
        string? expiredId = null;
        for (var i = 0; i < ShareScanGuard.MaxChallengeIssuesInWindow; i++)
        {
            Assert.True(_pow.TryIssue("send", "s" + i, client, null, out var issued, out _));
            expiredId ??= issued!.ChallengeId;
        }

        Assert.False(_pow.TryIssue("send", "over", client, null, out _, out var retry));
        Assert.True(retry > 0);
        Assert.True(_pow.TryIssue("send", "other", "203.0.113.51", null, out _, out _));

        using (var conn = _db.Open())
        using (var cmd = conn.CreateCommand())
        {
            cmd.CommandText = "UPDATE pow_challenges SET ExpiresAt = @exp WHERE Id = @id";
            cmd.Parameters.AddWithValue("@exp", DateTimeOffset.UnixEpoch.ToString("O"));
            cmd.Parameters.AddWithValue("@id", expiredId);
            cmd.ExecuteNonQuery();
        }

        Assert.True(_pow.TryIssue("send", "fresh", "203.0.113.52", null, out _, out _));
        using (var conn = _db.Open())
        using (var cmd = conn.CreateCommand())
        {
            cmd.CommandText = "SELECT COUNT(*) FROM pow_challenges WHERE Id = @id";
            cmd.Parameters.AddWithValue("@id", expiredId);
            Assert.Equal(0L, (long)cmd.ExecuteScalar()!);
        }
    }

    [Fact]
    public void A_burst_cannot_issue_more_than_the_cap()
    {
        const string client = "203.0.113.60";
        var wins = 0;
        Parallel.For(0, 40, index =>
        {
            if (_pow.TryIssue("send", "burst", client, null, out PowService.Challenge? issued, out double retry))
            {
                Interlocked.Increment(ref wins);
            }
        });
        Assert.Equal(ShareScanGuard.MaxChallengeIssuesInWindow, wins);
    }

    public void Dispose() => Directory.Delete(_dir, recursive: true);
}

public sealed class IpRestrictionTests
{
    [Fact]
    public void Normalizes_and_matches_addresses_and_cidrs()
    {
        Assert.True(IpRestriction.TryNormalize(" 203.0.113.10, 192.168.1.20/24 ", out var canonical, out var error));
        Assert.Null(error);
        Assert.Equal("203.0.113.10,192.168.1.0/24", canonical);
        Assert.True(IpRestriction.IsClientAllowed(canonical, System.Net.IPAddress.Parse("203.0.113.10")));
        Assert.True(IpRestriction.IsClientAllowed(canonical, System.Net.IPAddress.Parse("192.168.1.9")));
        Assert.False(IpRestriction.IsClientAllowed(canonical, System.Net.IPAddress.Parse("198.51.100.1")));
        Assert.False(IpRestriction.TryNormalize("10.0.0.1/99", out _, out error));
        Assert.Contains("prefix", error, StringComparison.OrdinalIgnoreCase);
        Assert.False(IpRestriction.TryNormalize("192.168.001.1", out _, out error));
        Assert.Contains("dotted decimal", error, StringComparison.OrdinalIgnoreCase);
        Assert.False(IpRestriction.TryNormalize("::ffff:192.0.2.1", out _, out error));
        Assert.Contains("IPv4", error, StringComparison.OrdinalIgnoreCase);
        Assert.False(IpRestriction.TryNormalize("fe80::1%eth0", out _, out error));
        Assert.Contains("zone", error, StringComparison.OrdinalIgnoreCase);
        Assert.True(IpRestriction.TryNormalize("2001:db8::1", out canonical, out error));
        Assert.Null(error);
        Assert.Equal("2001:db8::1", canonical);
        Assert.True(IpRestriction.TryNormalize("2001:db8::/32", out canonical, out error));
        Assert.Equal("2001:db8::/32", canonical);
        Assert.True(IpRestriction.IsClientAllowed(canonical, System.Net.IPAddress.Parse("2001:db8::1")));
        Assert.False(IpRestriction.IsClientAllowed(canonical, System.Net.IPAddress.Parse("2001:db9::1")));
        Assert.True(IpRestriction.TryNormalize("*, 10.0.0.1", out canonical, out error));
        Assert.Equal("*", canonical);
        Assert.True(IpRestriction.IsClientAllowed(canonical, System.Net.IPAddress.Parse("198.51.100.9")));
    }
}

public sealed class WrapPackageTests
{
    [Fact]
    public void Password_and_passkey_wraps_must_use_the_fixed_layout()
    {
        Assert.True(WrapPackage.IsValid("password", Package("PBKDF2-SHA512-AES-256-GCM", WrapPackage.PasswordIterations, salt: 16)));
        Assert.True(WrapPackage.IsValid("passkey", Package("PRF-AES-256-GCM", iterations: null, salt: 0)));
        Assert.False(WrapPackage.IsValid("password", Package("PBKDF2-SHA512-AES-256-GCM", 1, salt: 16)));
        Assert.False(WrapPackage.IsValid("password", Package("PBKDF2-SHA512-AES-256-GCM", WrapPackage.PasswordIterations, salt: 8)));
        Assert.False(WrapPackage.IsValid("passkey", Package("PBKDF2-SHA512-AES-256-GCM", WrapPackage.PasswordIterations, salt: 16)));
        Assert.False(WrapPackage.IsValid("password", Package("PBKDF2-SHA512-AES-256-GCM", WrapPackage.PasswordIterations, salt: 16, ct: 16)));
    }

    [Fact]
    public void Aes_gcm_of_a_32_byte_key_is_48_bytes_including_the_tag()
    {
        var key = new byte[32];
        var iv = new byte[12];
        var plain = new byte[32];
        var ct = new byte[32];
        var tag = new byte[16];
        using var aes = new AesGcm(key, tag.Length);
        aes.Encrypt(iv, plain, ct, tag);
        Assert.Equal(48, ct.Length + tag.Length);
        aes.Decrypt(iv, ct, tag, plain);
    }

    [Fact]
    public void Payload_fields_must_be_exact_sizes()
    {
        Assert.True(Base64Url.IsExact(Base64Url.Encode(new byte[12]), 12));
        Assert.True(Base64Url.IsExact(Base64Url.Encode(new byte[32]), 32));
        Assert.True(Base64Url.IsExact(Base64Url.Encode(new byte[60]), 60));
        Assert.False(Base64Url.IsExact(Base64Url.Encode(new byte[11]), 12));
        Assert.False(Base64Url.IsExact(Base64Url.Encode(new byte[31]), 32));
        Assert.False(Base64Url.IsExact("not base64!!", 12));
    }

    private static string Package(string alg, int? iterations, int salt, int ct = 48)
    {
        var body = new Dictionary<string, object?>
        {
            ["v"] = 1,
            ["alg"] = alg,
            ["iv"] = Base64Url.Encode(new byte[12]),
            ["ct"] = Base64Url.Encode(new byte[ct]),
        };
        if (iterations is not null)
        {
            body["iterations"] = iterations;
            body["salt"] = Base64Url.Encode(new byte[salt]);
        }

        return JsonSerializer.Serialize(body);
    }
}

file sealed class MutablePowPolicy : IPowPolicy
{
    public int DifficultyBits { get; set; } = PowPolicyLimits.DefaultDifficultyBits;
    public int ChallengeTtlSeconds { get; set; } = PowPolicyLimits.DefaultChallengeTtlSeconds;
    public int CollectChallengeTtlSeconds { get; set; } = PowPolicyLimits.DefaultCollectChallengeTtlSeconds;
    public int ScanBudgetWindowSeconds { get; set; } = PowPolicyLimits.DefaultScanBudgetWindowSeconds;
}

public sealed class ShareBurnTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "ss-burn-" + Guid.NewGuid().ToString("N"));
    private readonly ShareStore _store;

    public ShareBurnTests()
    {
        Directory.CreateDirectory(_dir);
        _store = new ShareStore(new ShareDatabase(Path.Combine(_dir, "secret-sharing.db")));
    }

    [Fact]
    public void One_time_send_returns_the_payload_once_and_deletes_it()
    {
        var id = _store.CreateSend("owner", Sample(oneTime: true, max: null));
        var first = _store.TakeSend(id);
        Assert.Equal("ciphertext", first!.Ciphertext);
        var again = _store.TakeSend(id);
        Assert.Equal("consumed", again!.Status);
        Assert.Equal("", again.Ciphertext);
        Assert.Equal("", SendCiphertext(id));
    }

    [Fact]
    public void Capped_send_burns_on_the_last_allowed_open()
    {
        var id = _store.CreateSend("owner", Sample(oneTime: false, max: 2));
        Assert.Equal("ciphertext", _store.TakeSend(id)!.Ciphertext);
        Assert.Equal("ciphertext", _store.TakeSend(id)!.Ciphertext);
        Assert.Equal("consumed", _store.TakeSend(id)!.Status);
        Assert.Equal("", SendCiphertext(id));
    }

    [Fact]
    public void One_time_collect_can_be_retrieved_without_the_owner_and_then_burns()
    {
        var id = _store.CreateCollect("owner", new CollectInput(Base64Url.Encode(new byte[32]), null, null, null, true, 60, null, false, false, null));
        Assert.Null(_store.SaveUpload(id, new UploadInput("ciphertext", "iv", "wk", "eph", "text/plain", null)));
        Assert.Equal("ciphertext", _store.TakeCollect(id)!.Ciphertext);
        Assert.Null(_store.TakeCollect(id));
        Assert.Null(CollectCiphertext(id));
    }

    [Fact]
    public void Capped_collect_burns_on_the_last_allowed_open()
    {
        var id = _store.CreateCollect("owner", new CollectInput(Base64Url.Encode(new byte[32]), null, null, null, false, 60, 2, false, false, null));
        Assert.Null(_store.SaveUpload(id, new UploadInput("ciphertext", "iv", "wk", "eph", "text/plain", null)));
        Assert.Equal("ciphertext", _store.TakeCollect(id)!.Ciphertext);
        Assert.Equal("ciphertext", _store.TakeCollect(id)!.Ciphertext);
        Assert.Null(_store.TakeCollect(id));
        Assert.Null(CollectCiphertext(id));
    }

    [Fact]
    public void Reset_removes_wraps_sends_and_collects()
    {
        _store.CreateSend("owner", Sample(false, null));
        _store.CreateCollect("owner", new CollectInput(Base64Url.Encode(new byte[32]), null, null, null, true, 60, null, false, false, null));
        _store.UpsertWrap("owner", "password", "", "{\"v\":1}");
        var (sends, collects) = _store.ResetUser("owner");
        Assert.Equal(1, sends);
        Assert.Equal(1, collects);
        Assert.Empty(_store.List("owner"));
        Assert.Empty(_store.ListWraps("owner"));
    }

    [Fact]
    public void Expired_and_consumed_shares_leave_the_dashboard()
    {
        var live = _store.CreateSend("owner", new SendInput("ciphertext", "iv", "wk", "eph", "text/plain", null, true, 60, null, null, null, false, false));
        var expired = _store.CreateSend("owner", new SendInput("ciphertext", "iv", "wk", "eph", "text/plain", null, true, -5, null, null, null, false, false));
        var burned = _store.CreateSend("owner", new SendInput("ciphertext", "iv", "wk", "eph", "text/plain", null, true, 60, null, null, null, false, false));
        Assert.NotNull(_store.TakeSend(burned));

        var items = _store.List("owner");
        var only = Assert.Single(items);
        Assert.Equal(live, only.Id);
        Assert.DoesNotContain(items, i => i.Id == expired || i.Id == burned);
    }

    [Fact]
    public void Cipher_limit_fits_a_40_mebibyte_file()
    {
        var chars = ((40 * 1024 * 1024 + 16 + 2) / 3) * 4;
        Assert.True(ShareStore.MaxCipherChars >= chars);
    }

    [Fact]
    public void Home_list_includes_the_name_note_and_ip_flag()
    {
        _store.CreateSend("owner", new SendInput("ciphertext", "iv", "wk", "eph", "text/plain", null, true, 60, "send-name", "send-note", null, true, false, "10.0.0.0/8"));
        _store.CreateSend("owner", new SendInput("ciphertext", "iv", "wk", "eph", "text/plain", null, false, 60, null, null, null, false, false, "*"));
        _store.CreateCollect("owner", new CollectInput(Base64Url.Encode(new byte[32]), "owner-key", "collect-name", "collect-note", true, 60, null, false, false, null));

        var items = _store.List("owner");
        var restricted = Assert.Single(items, i => i.Kind == "send" && i.IpRestricted);
        Assert.Equal("send-name", restricted.EncryptedLabel);
        Assert.Equal("send-note", restricted.PrivateNoteCiphertext);
        Assert.True(restricted.PasswordProtected);
        Assert.Equal("active", restricted.Status);
        var open = Assert.Single(items, i => i.Kind == "send" && !i.IpRestricted);
        Assert.False(open.PasswordProtected);
        var collect = Assert.Single(items, i => i.Kind == "collect");
        Assert.Equal("waiting", collect.Status);
        Assert.Equal("collect-note", collect.PrivateNoteCiphertext);
        Assert.True(collect.HasOwnerKey);
        Assert.False(collect.IpRestricted);
    }

    private string? SendCiphertext(string id)
    {
        using var conn = new SqliteConnection("Data Source=" + Path.Combine(_dir, "secret-sharing.db"));
        conn.Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT Ciphertext FROM secrets WHERE Id = @id";
        cmd.Parameters.AddWithValue("@id", id);
        return cmd.ExecuteScalar() as string;
    }

    private string? CollectCiphertext(string id)
    {
        using var conn = new SqliteConnection("Data Source=" + Path.Combine(_dir, "secret-sharing.db"));
        conn.Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT Ciphertext FROM collects WHERE Id = @id";
        cmd.Parameters.AddWithValue("@id", id);
        return cmd.ExecuteScalar() as string;
    }

    private static SendInput Sample(bool oneTime, int? max) => new(
        "ciphertext", "iv", "wk", "eph", "text/plain", null, oneTime, 24, null, null, max, false, false);

    public void Dispose() => Directory.Delete(_dir, recursive: true);
}
