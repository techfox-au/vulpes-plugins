using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.DependencyInjection;
using Vulpes.Host.Security;
using Xunit;

namespace Vulpes.Plugins.SecretSharing.Tests;

public sealed class ShareFlowFixture : IDisposable
{
    public const string Password = "correct horse battery staple 42";
    public ShareHostFactory Factory { get; } = new();
    private readonly SemaphoreSlim _gate = new(1, 1);
    private bool _ready;

    public Task<FlowClient> AdminAsync() => LoginAsync("admin", Password);

    public async Task<FlowClient> LoginAsync(string username, string password)
    {
        await EnsureReadyAsync();
        var client = NewClient();
        var proof = await client.JsonAsync(HttpMethod.Get, "/auth/login/pow");
        var (nonce, hash) = FlowClient.Solve(proof.GetProperty("hmacKey").GetString()!, proof.GetProperty("difficultyBits").GetInt32());
        var login = await client.SendAsync(HttpMethod.Post, "/auth/login/password", new { username, password, powChallengeId = proof.GetProperty("challengeId").GetString(), powNonce = nonce, powHash = hash, powClientTime = proof.GetProperty("serverTime").GetString() });
        Assert.Equal(HttpStatusCode.OK, login.StatusCode);
        client.Reset();
        return client;
    }

    public async Task<FlowClient> AnonymousAsync()
    {
        await EnsureReadyAsync();
        return new FlowClient(Factory.CreateClient(new Microsoft.AspNetCore.Mvc.Testing.WebApplicationFactoryClientOptions { AllowAutoRedirect = false, BaseAddress = new Uri("http://localhost") }));
    }

    public async Task EnableIpRestrictionsAsync()
    {
        await EnsureReadyAsync();
        var capability = Factory.Services.GetRequiredService<ClientIpCapability>();
        var deadline = DateTime.UtcNow.AddSeconds(20);
        while (!capability.ProbeFinished && DateTime.UtcNow < deadline)
        {
            await Task.Delay(100);
        }

        Assert.True(capability.ProbeFinished);
        capability.MarkVerified();
        Assert.True(capability.IpRestrictionsEnabled);
    }

    public string? SecretCipher(string id) => One("SELECT Ciphertext FROM secrets WHERE Id = @id", id);

    public string? SecretPasswordFlag(string id) => One("SELECT PasswordProtected FROM secrets WHERE Id = @id", id);

    public string? CollectCipher(string id) => One("SELECT Ciphertext FROM collects WHERE Id = @id", id);

    public string? CollectOwnerKey(string id) => One("SELECT OwnerPrivateKeyProtected FROM collects WHERE Id = @id", id);

    public void Expire(string id)
    {
        using var conn = Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "UPDATE secrets SET ExpiresAt = @exp WHERE Id = @id";
        cmd.Parameters.AddWithValue("@exp", DateTimeOffset.UnixEpoch.ToString("O"));
        cmd.Parameters.AddWithValue("@id", id);
        Assert.Equal(1, cmd.ExecuteNonQuery());
    }

    private string? One(string sql, string id)
    {
        using var conn = Open();
        using var cmd = conn.CreateCommand();
#pragma warning disable CA2100 // SQL text is a literal chosen by this fixture, and the id is a parameter.
        cmd.CommandText = sql;
#pragma warning restore CA2100
        cmd.Parameters.AddWithValue("@id", id);
        var value = cmd.ExecuteScalar();
        return value is DBNull or null ? null : value.ToString();
    }

    private SqliteConnection Open()
    {
        var conn = new SqliteConnection("Data Source=" + Path.Combine(Factory.DataDirectory, "plugins", "secret-sharing", "secret-sharing.db"));
        conn.Open();
        return conn;
    }

    public void Dispose()
    {
        Factory.Dispose();
        _gate.Dispose();
    }

    private async Task EnsureReadyAsync()
    {
        await _gate.WaitAsync();
        try
        {
            if (_ready)
            {
                return;
            }

            using var client = NewClient();
            var setup = await client.SendAsync(HttpMethod.Post, "/auth/setup", new { token = ShareHostFactory.SetupToken, username = "admin", displayName = "Admin", email = "admin@example.com", password = Password });
            Assert.Equal(HttpStatusCode.OK, setup.StatusCode);
            client.Reset();
            var saved = await client.SendAsync(HttpMethod.Put, "/api/admin/settings/pow", new { difficultyBits = 4, challengeTtlSeconds = 120, scanBudgetWindowSeconds = 60 });
            Assert.True(saved.IsSuccessStatusCode, await saved.Content.ReadAsStringAsync());
            _ready = true;
        }
        finally
        {
            _gate.Release();
        }
    }

    private FlowClient NewClient() => new(Factory.CreateClient(new Microsoft.AspNetCore.Mvc.Testing.WebApplicationFactoryClientOptions { AllowAutoRedirect = false, BaseAddress = new Uri("http://localhost") }));
}

public sealed class ShareFlowTests(ShareFlowFixture fixture) : IClassFixture<ShareFlowFixture>
{
    private const string Cipher = "CIPHERTEXTONLY";

    [Fact]
    public async Task Anonymous_create_is_rejected_and_a_bad_payload_is_not_stored()
    {
        using var anon = await fixture.AnonymousAsync();
        var denied = await anon.SendAsync(HttpMethod.Post, "/api/plugins/secret-sharing/sends", Payload());
        Assert.Equal(HttpStatusCode.Unauthorized, denied.StatusCode);

        using var admin = await fixture.AdminAsync();
        var invalid = await admin.SendAsync(HttpMethod.Post, "/api/plugins/secret-sharing/sends", Payload(ciphertext: "not valid!!"));
        Assert.Equal(HttpStatusCode.BadRequest, invalid.StatusCode);
        Assert.DoesNotContain("not valid!!", await invalid.Content.ReadAsStringAsync(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task One_time_send_is_released_once_and_then_matches_a_missing_secret()
    {
        using var admin = await fixture.AdminAsync();
        var created = await admin.JsonAsync(HttpMethod.Post, "/api/plugins/secret-sharing/sends", Payload());
        var id = created.GetProperty("id").GetString()!;
        Assert.False(created.TryGetProperty("ciphertext", out _));
        Assert.Equal(Cipher, fixture.SecretCipher(id));

        using var anon = await fixture.AnonymousAsync();
        var meta = await ProveAsync(anon, "/api/plugins/secret-sharing/public/sends/" + id + "/meta");
        Assert.False(meta.TryGetProperty("ciphertext", out _));
        Assert.False(meta.GetProperty("passwordProtected").GetBoolean());
        Assert.Equal(Cipher, fixture.SecretCipher(id));

        var payload = await ProveAsync(anon, "/api/plugins/secret-sharing/public/sends/" + id);
        Assert.Equal(Cipher, payload.GetProperty("ciphertext").GetString());
        Assert.Equal("", fixture.SecretCipher(id));

        var burned = await GoneAsync(anon, "/api/plugins/secret-sharing/public/sends/" + id);
        var missing = await GoneAsync(anon, "/api/plugins/secret-sharing/public/sends/missing-send-id");
        Assert.Equal(missing, burned);
        Assert.Contains("no longer available", burned, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task A_link_password_is_only_a_flag_and_the_dashboard_omits_the_payload()
    {
        using var admin = await fixture.AdminAsync();
        var created = await admin.JsonAsync(HttpMethod.Post, "/api/plugins/secret-sharing/sends", Payload(oneTime: false, passwordProtected: true, extra: new Dictionary<string, object?> { ["linkPassword"] = "hunter2-not-stored" }));
        var id = created.GetProperty("id").GetString()!;
        Assert.Equal("1", fixture.SecretPasswordFlag(id));
        Assert.DoesNotContain("hunter2-not-stored", ReadRow(id), StringComparison.Ordinal);

        var home = await admin.JsonAsync(HttpMethod.Get, "/api/plugins/secret-sharing/home");
        var item = home.GetProperty("items").EnumerateArray().Single(row => row.GetProperty("id").GetString() == id);
        Assert.True(item.GetProperty("passwordProtected").GetBoolean());
        Assert.False(item.TryGetProperty("ciphertext", out _));
        Assert.DoesNotContain(Cipher, home.GetRawText(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task Another_user_cannot_see_or_delete_the_send()
    {
        using var admin = await fixture.AdminAsync();
        var created = await admin.JsonAsync(HttpMethod.Post, "/api/plugins/secret-sharing/sends", Payload(oneTime: false));
        var id = created.GetProperty("id").GetString()!;
        var username = "viewer" + Guid.NewGuid().ToString("N")[..8];
        var user = await admin.JsonAsync(HttpMethod.Post, "/api/admin/users", new { username, role = "Viewer", email = username + "@example.com" });
        var userId = user.GetProperty("user").GetProperty("id").GetString()!;
        var password = (await admin.JsonAsync(HttpMethod.Post, $"/api/admin/users/{userId}/temporary-password")).GetProperty("temporaryPassword").GetString()!;

        using var viewer = await fixture.LoginAsync(username, password);
        var home = await viewer.JsonAsync(HttpMethod.Get, "/api/plugins/secret-sharing/home");
        Assert.DoesNotContain(home.GetProperty("items").EnumerateArray(), item => item.GetProperty("id").GetString() == id);
        Assert.Equal(HttpStatusCode.NotFound, (await viewer.SendAsync(HttpMethod.Delete, "/api/plugins/secret-sharing/sends/" + id)).StatusCode);
        Assert.Equal(Cipher, fixture.SecretCipher(id));
    }

    [Fact]
    public async Task An_expired_send_uses_the_same_response_as_a_missing_one()
    {
        using var admin = await fixture.AdminAsync();
        var id = (await admin.JsonAsync(HttpMethod.Post, "/api/plugins/secret-sharing/sends", Payload())).GetProperty("id").GetString()!;
        fixture.Expire(id);
        using var anon = await fixture.AnonymousAsync();
        var expired = await GoneAsync(anon, "/api/plugins/secret-sharing/public/sends/" + id);
        var missing = await GoneAsync(anon, "/api/plugins/secret-sharing/public/sends/also-missing");
        Assert.Equal(missing, expired);
        Assert.Equal(Cipher, fixture.SecretCipher(id));
    }

    [Fact]
    public async Task A_quoted_id_does_not_change_stored_secrets()
    {
        using var admin = await fixture.AdminAsync();
        var id = (await admin.JsonAsync(HttpMethod.Post, "/api/plugins/secret-sharing/sends", Payload(oneTime: false))).GetProperty("id").GetString()!;
        using var anon = await fixture.AnonymousAsync();
        var evil = Uri.EscapeDataString("x'; DROP TABLE secrets;--");
        var issued = await anon.SendAsync(HttpMethod.Get, "/api/plugins/secret-sharing/public/sends/" + evil + "/pow");
        Assert.Equal(HttpStatusCode.OK, issued.StatusCode);
        Assert.Equal(Cipher, fixture.SecretCipher(id));
    }

    [Fact]
    public async Task Ip_denial_does_not_burn_the_payload()
    {
        await fixture.EnableIpRestrictionsAsync();
        using var admin = await fixture.AdminAsync();
        var id = (await admin.JsonAsync(HttpMethod.Post, "/api/plugins/secret-sharing/sends", Payload(oneTime: true, cidr: "203.0.113.10"))).GetProperty("id").GetString()!;
        using var anon = await fixture.AnonymousAsync();
        var firstProof = await ProofAsync(anon, "/api/plugins/secret-sharing/public/sends/" + id);
        var first = await anon.SendAsync(HttpMethod.Post, "/api/plugins/secret-sharing/public/sends/" + id + "/meta", firstProof.Body);
        var firstText = await first.Content.ReadAsStringAsync();
        Assert.Equal(HttpStatusCode.Forbidden, first.StatusCode);
        Assert.Contains("not available from your IP address", firstText, StringComparison.Ordinal);
        Assert.Equal(Cipher, fixture.SecretCipher(id));

        var secondProof = await ProofAsync(anon, "/api/plugins/secret-sharing/public/sends/" + id);
        var second = await anon.SendAsync(HttpMethod.Post, "/api/plugins/secret-sharing/public/sends/" + id + "/meta", secondProof.Body);
        Assert.Equal(HttpStatusCode.Forbidden, second.StatusCode);
        Assert.Equal(Cipher, fixture.SecretCipher(id));
    }

    [Fact]
    public async Task Existing_allow_lists_stay_closed_when_the_public_address_is_not_visible()
    {
        await fixture.EnableIpRestrictionsAsync();
        using var admin = await fixture.AdminAsync();
        var restricted = (await admin.JsonAsync(HttpMethod.Post, "/api/plugins/secret-sharing/sends", Payload(oneTime: true, cidr: "203.0.113.10"))).GetProperty("id").GetString()!;
        var open = (await admin.JsonAsync(HttpMethod.Post, "/api/plugins/secret-sharing/sends", Payload(oneTime: false))).GetProperty("id").GetString()!;
        var collectId = (await admin.JsonAsync(HttpMethod.Post, "/api/plugins/secret-sharing/collects", new { publicKey = FlowClient.B64(32), expiresInMinutes = 60, oneTime = true })).GetProperty("id").GetString()!;
        using var anon = await fixture.AnonymousAsync();
        var proof = await ProofAsync(anon, "/api/plugins/secret-sharing/public/collects/" + collectId);
        Assert.Equal(HttpStatusCode.NoContent, (await anon.SendAsync(HttpMethod.Post, "/api/plugins/secret-sharing/public/collects/" + collectId, proof.Body, proof.Headers)).StatusCode);
        Assert.True((await admin.SendAsync(HttpMethod.Put, "/api/plugins/secret-sharing/collect-retrieve-ips", new { allowedIps = "203.0.113.10" })).IsSuccessStatusCode);

        var capability = fixture.Factory.Services.GetRequiredService<ClientIpCapability>();
        capability.MarkUnverified();
        try
        {
            var sendDenied = await anon.SendAsync(HttpMethod.Post, "/api/plugins/secret-sharing/public/sends/" + restricted + "/meta", (await ProofAsync(anon, "/api/plugins/secret-sharing/public/sends/" + restricted)).Body);
            Assert.Equal(HttpStatusCode.Forbidden, sendDenied.StatusCode);
            Assert.Contains("not available from your IP address", await sendDenied.Content.ReadAsStringAsync(), StringComparison.Ordinal);
            Assert.Equal(Cipher, fixture.SecretCipher(restricted));

            var sendOpen = await ProveAsync(anon, "/api/plugins/secret-sharing/public/sends/" + open + "/meta");
            Assert.Equal("active", sendOpen.GetProperty("status").GetString());

            var collectDenied = await anon.SendAsync(HttpMethod.Post, "/api/plugins/secret-sharing/public/collects/" + collectId + "/open", (await ProofAsync(anon, "/api/plugins/secret-sharing/public/collects/" + collectId)).Body);
            Assert.Equal(HttpStatusCode.Forbidden, collectDenied.StatusCode);
            Assert.Equal(Cipher, fixture.CollectCipher(collectId));
        }
        finally
        {
            await admin.SendAsync(HttpMethod.Put, "/api/plugins/secret-sharing/collect-retrieve-ips", new { allowedIps = "" });
            capability.MarkUnverified();
        }
    }

    [Fact]
    public async Task Collect_upload_checks_the_proof_before_replacing_it_and_retrieval_burns_once()
    {
        using var admin = await fixture.AdminAsync();
        await admin.SendAsync(HttpMethod.Put, "/api/plugins/secret-sharing/collect-retrieve-ips", new { allowedIps = "" });
        var created = await admin.JsonAsync(HttpMethod.Post, "/api/plugins/secret-sharing/collects", new { publicKey = FlowClient.B64(32), expiresInMinutes = 60, oneTime = true });
        var id = created.GetProperty("id").GetString()!;
        using var anon = await fixture.AnonymousAsync();
        var proof = await ProofAsync(anon, "/api/plugins/secret-sharing/public/collects/" + id);
        var permit = await anon.SendAsync(HttpMethod.Get, "/api/plugins/secret-sharing/public/collects/" + id + "/upload-permit", headers: proof.Headers);
        Assert.Equal(HttpStatusCode.NoContent, permit.StatusCode);
        var permitAgain = await anon.SendAsync(HttpMethod.Get, "/api/plugins/secret-sharing/public/collects/" + id + "/upload-permit", headers: proof.Headers);
        Assert.Equal(HttpStatusCode.NoContent, permitAgain.StatusCode);

        var upload = await anon.SendAsync(HttpMethod.Post, "/api/plugins/secret-sharing/public/collects/" + id, proof.Body, proof.Headers);
        Assert.Equal(HttpStatusCode.NoContent, upload.StatusCode);
        Assert.Equal(Cipher, fixture.CollectCipher(id));

        var again = await ProofAsync(anon, "/api/plugins/secret-sharing/public/collects/" + id);
        var conflict = await anon.SendAsync(HttpMethod.Post, "/api/plugins/secret-sharing/public/collects/" + id, again.Body, again.Headers);
        Assert.Equal(HttpStatusCode.Conflict, conflict.StatusCode);
        Assert.Equal(Cipher, fixture.CollectCipher(id));

        var opened = await ProveAsync(anon, "/api/plugins/secret-sharing/public/collects/" + id + "/open");
        Assert.Equal(Cipher, opened.GetProperty("ciphertext").GetString());
        Assert.Null(fixture.CollectCipher(id));
        var burned = await GoneAsync(anon, "/api/plugins/secret-sharing/public/collects/" + id + "/open");
        Assert.Contains("no longer available", burned, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Blocked_collect_retrieval_does_not_burn_the_upload()
    {
        await fixture.EnableIpRestrictionsAsync();
        using var admin = await fixture.AdminAsync();
        try
        {
            var id = (await admin.JsonAsync(HttpMethod.Post, "/api/plugins/secret-sharing/collects", new { publicKey = FlowClient.B64(32), expiresInMinutes = 60, oneTime = true })).GetProperty("id").GetString()!;
            using var anon = await fixture.AnonymousAsync();
            var proof = await ProofAsync(anon, "/api/plugins/secret-sharing/public/collects/" + id);
            Assert.Equal(HttpStatusCode.NoContent, (await anon.SendAsync(HttpMethod.Post, "/api/plugins/secret-sharing/public/collects/" + id, proof.Body, proof.Headers)).StatusCode);
            var saved = await admin.SendAsync(HttpMethod.Put, "/api/plugins/secret-sharing/collect-retrieve-ips", new { allowedIps = "203.0.113.10" });
            Assert.True(saved.IsSuccessStatusCode, await saved.Content.ReadAsStringAsync());

            var metaDenied = await anon.SendAsync(HttpMethod.Post, "/api/plugins/secret-sharing/public/collects/" + id + "/meta", (await ProofAsync(anon, "/api/plugins/secret-sharing/public/collects/" + id)).Body);
            var metaText = await metaDenied.Content.ReadAsStringAsync();
            Assert.Equal(HttpStatusCode.Forbidden, metaDenied.StatusCode);
            Assert.Contains("not available from your IP address", metaText, StringComparison.Ordinal);
            Assert.DoesNotContain("publicKey", metaText, StringComparison.Ordinal);
            Assert.DoesNotContain("expiresAt", metaText, StringComparison.Ordinal);

            var openProof = await ProofAsync(anon, "/api/plugins/secret-sharing/public/collects/" + id);
            var denied = await anon.SendAsync(HttpMethod.Post, "/api/plugins/secret-sharing/public/collects/" + id + "/open", openProof.Body);
            var deniedText = await denied.Content.ReadAsStringAsync();
            Assert.Equal(HttpStatusCode.Forbidden, denied.StatusCode);
            Assert.Contains("not available from your IP address", deniedText, StringComparison.Ordinal);
            Assert.Equal(Cipher, fixture.CollectCipher(id));
        }
        finally
        {
            await admin.SendAsync(HttpMethod.Put, "/api/plugins/secret-sharing/collect-retrieve-ips", new { allowedIps = "" });
        }
    }

    [Fact]
    public async Task A_collect_owner_key_is_sealed_in_the_database_and_returned_opened()
    {
        using var admin = await fixture.AdminAsync();
        const string ownerKey = "owner-key-material-0123456789abcd";
        var created = await admin.JsonAsync(HttpMethod.Post, "/api/plugins/secret-sharing/collects", new { publicKey = FlowClient.B64(32), ownerPrivateKeyProtected = ownerKey, expiresInMinutes = 60, oneTime = true });
        var id = created.GetProperty("id").GetString()!;
        var stored = fixture.CollectOwnerKey(id);
        Assert.StartsWith("vd1.", stored, StringComparison.Ordinal);
        Assert.DoesNotContain(ownerKey, stored, StringComparison.Ordinal);
        var opened = await admin.JsonAsync(HttpMethod.Get, "/api/plugins/secret-sharing/collects/" + id + "/owner-key");
        Assert.Equal(ownerKey, opened.GetProperty("ownerPrivateKeyProtected").GetString());
    }

    [Fact]
    public async Task Difficulty_cannot_be_turned_off_and_the_ticket_field_keeps_its_name()
    {
        using var admin = await fixture.AdminAsync();
        var difficulty = await admin.SendAsync(HttpMethod.Put, "/api/admin/settings/pow", new { difficultyBits = 0, challengeTtlSeconds = 120, scanBudgetWindowSeconds = 60 });
        Assert.Equal(HttpStatusCode.BadRequest, difficulty.StatusCode);
        Assert.Contains("Difficulty must be from 1", await difficulty.Content.ReadAsStringAsync(), StringComparison.Ordinal);

        var duration = await admin.SendAsync(HttpMethod.Put, "/api/admin/settings/pow", new { difficultyBits = 4, challengeTtlSeconds = 10, scanBudgetWindowSeconds = 60 });
        var text = await duration.Content.ReadAsStringAsync();
        Assert.Equal(HttpStatusCode.BadRequest, duration.StatusCode);
        Assert.Contains("Ticket duration must be from", text, StringComparison.Ordinal);
        Assert.DoesNotContain("PoW ticket duration", text, StringComparison.Ordinal);
    }

    private string ReadRow(string id)
    {
        using var conn = new SqliteConnection("Data Source=" + Path.Combine(fixture.Factory.DataDirectory, "plugins", "secret-sharing", "secret-sharing.db"));
        conn.Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT * FROM secrets WHERE Id = @id";
        cmd.Parameters.AddWithValue("@id", id);
        using var reader = cmd.ExecuteReader();
        Assert.True(reader.Read());
        var parts = new string[reader.FieldCount];
        for (var i = 0; i < reader.FieldCount; i++)
        {
            parts[i] = reader.IsDBNull(i) ? "" : reader.GetValue(i)?.ToString() ?? "";
        }

        return string.Join('\n', parts);
    }

    private static async Task<JsonElement> ProveAsync(FlowClient client, string path)
    {
        var proof = await ProofAsync(client, path.EndsWith("/meta", StringComparison.Ordinal) || path.EndsWith("/open", StringComparison.Ordinal) ? path[..path.LastIndexOf('/')] : path);
        return await client.JsonAsync(HttpMethod.Post, path, proof.Body);
    }

    private static async Task<string> GoneAsync(FlowClient client, string path)
    {
        var proof = await ProofAsync(client, path.EndsWith("/open", StringComparison.Ordinal) ? path[..path.LastIndexOf('/')] : path);
        var response = await client.SendAsync(HttpMethod.Post, path, proof.Body);
        var text = await response.Content.ReadAsStringAsync();
        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
        return text;
    }

    private static async Task<Proof> ProofAsync(FlowClient client, string resourcePath)
    {
        var challenge = await client.JsonAsync(HttpMethod.Get, resourcePath + "/pow");
        var (nonce, hash) = FlowClient.Solve(challenge.GetProperty("hmacKey").GetString()!, challenge.GetProperty("difficultyBits").GetInt32());
        var challengeId = challenge.GetProperty("challengeId").GetString()!;
        return new Proof(challengeId, nonce, hash, challenge.GetProperty("serverTime").GetString()!);
    }

    private static Dictionary<string, object?> Payload(string ciphertext = Cipher, bool oneTime = true, bool passwordProtected = false, string? cidr = null, Dictionary<string, object?>? extra = null)
    {
        var body = new Dictionary<string, object?>
        {
            ["ciphertext"] = ciphertext,
            ["iv"] = FlowClient.B64(12),
            ["wrappedKey"] = FlowClient.B64(60),
            ["ephemeralPublicKey"] = FlowClient.B64(32),
            ["contentType"] = "text/plain",
            ["oneTime"] = oneTime,
            ["expiresInMinutes"] = 60,
            ["passwordProtected"] = passwordProtected,
            ["allowedCidr"] = cidr,
        };
        if (extra is not null)
        {
            foreach (var pair in extra)
            {
                body[pair.Key] = pair.Value;
            }
        }

        return body;
    }

    private sealed record Proof(string ChallengeId, string Nonce, string Hash, string ClientTime)
    {
        public object Body => new
        {
            challengeId = ChallengeId,
            nonce = Nonce,
            hash = Hash,
            clientTime = ClientTime,
            ciphertext = Cipher,
            iv = FlowClient.B64(12),
            wrappedKey = FlowClient.B64(60),
            ephemeralPublicKey = FlowClient.B64(32),
            contentType = "text/plain",
        };

        public Dictionary<string, string> Headers => new()
        {
            ["X-Sendit-Pow-Challenge"] = ChallengeId,
            ["X-Sendit-Pow-Nonce"] = Nonce,
            ["X-Sendit-Pow-Hash"] = Hash,
            ["X-Sendit-Pow-Time"] = ClientTime,
        };
    }
}

public sealed class FlowClient(HttpClient http) : IDisposable
{
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);
    private string? _csrf;

    public async Task<HttpResponseMessage> SendAsync(HttpMethod method, string path, object? body = null, IReadOnlyDictionary<string, string>? headers = null)
    {
        var request = new HttpRequestMessage(method, path);
        if (body is not null)
        {
            request.Content = JsonContent.Create(body, options: Json);
        }

        if (method != HttpMethod.Get)
        {
            request.Headers.TryAddWithoutValidation("X-CSRF-TOKEN", await CsrfAsync());
        }

        if (headers is not null)
        {
            foreach (var header in headers)
            {
                request.Headers.TryAddWithoutValidation(header.Key, header.Value);
            }
        }

        return await http.SendAsync(request);
    }

    public async Task<JsonElement> JsonAsync(HttpMethod method, string path, object? body = null)
    {
        var response = await SendAsync(method, path, body);
        var text = await response.Content.ReadAsStringAsync();
        Assert.True(response.IsSuccessStatusCode, $"{method} {path} -> {(int)response.StatusCode}: {text}");
        return text.Length == 0 ? default : JsonSerializer.Deserialize<JsonElement>(text, Json);
    }

    public void Reset() => _csrf = null;

    public void Dispose() => http.Dispose();

    public static (string Nonce, string Hash) Solve(string hmacKey, int difficultyBits)
    {
        var key = Base64UrlDecode(hmacKey);
        for (var nonce = 0; nonce < 5_000_000; nonce++)
        {
            var text = nonce.ToString(System.Globalization.CultureInfo.InvariantCulture);
            var mac = HMACSHA256.HashData(key, Encoding.ASCII.GetBytes(text));
            if (!HasLeadingZeroBits(mac, Math.Max(1, difficultyBits)))
            {
                continue;
            }

            return (text, Convert.ToBase64String(mac).TrimEnd('=').Replace('+', '-').Replace('/', '_'));
        }

        throw new InvalidOperationException("Could not solve the proof of work.");
    }

    public static string B64(int bytes) => Convert.ToBase64String(new byte[bytes]).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private async Task<string> CsrfAsync()
    {
        if (_csrf is null)
        {
            var session = await http.GetFromJsonAsync<JsonElement>("/api/session", Json);
            _csrf = session.GetProperty("csrfToken").GetString();
        }

        return _csrf!;
    }

    private static bool HasLeadingZeroBits(ReadOnlySpan<byte> hash, int bits)
    {
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

    private static byte[] Base64UrlDecode(string input)
    {
        var text = input.Replace('-', '+').Replace('_', '/');
        switch (text.Length % 4)
        {
            case 2: text += "=="; break;
            case 3: text += "="; break;
        }

        return Convert.FromBase64String(text);
    }
}
