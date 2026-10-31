using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Vulpes.PluginPacker;
using Xunit;

namespace Vulpes.Plugins.SecretSharing.Tests;

public sealed class RoleAccessTests : IDisposable
{
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);
    private readonly ShareHostFactory _factory = new();

    [Fact]
    public async Task Viewer_can_send_and_configure_send_mail_but_cannot_collect()
    {
        var admin = await AdminAsync();
        var adminNav = await NavIdsAsync(admin);
        Assert.Contains("secret-sharing:collect", adminNav);
        Assert.Contains("secret-sharing:settings", adminNav);

        var (analyst, userId, password) = await UserWithRoleAsync(admin, "Analyst", "analyst");
        var analystNav = await NavIdsAsync(analyst);
        Assert.Contains("secret-sharing:send", analystNav);
        Assert.Contains("secret-sharing:collect", analystNav);
        Assert.Contains("secret-sharing:settings", analystNav);

        var turnedOn = await analyst.JsonAsync(HttpMethod.Put, "/api/plugins/secret-sharing/notifications", new { notifyCollectReady = true, notifySendOpened = true });
        Assert.True(turnedOn.GetProperty("canCollect").GetBoolean());
        Assert.True(turnedOn.GetProperty("notifyCollectReady").GetBoolean());
        var created = await analyst.JsonAsync(HttpMethod.Post, "/api/plugins/secret-sharing/collects", new { publicKey = PublicKey(), expiresInMinutes = 60, oneTime = true });
        Assert.False(string.IsNullOrEmpty(created.GetProperty("id").GetString()));

        Assert.Equal(HttpStatusCode.OK, (await admin.SendAsync(HttpMethod.Patch, $"/api/admin/users/{userId}", new { role = "Viewer" })).StatusCode);

        var viewer = await LoginAsync("analyst", password);
        var nav = await NavIdsAsync(viewer);
        Assert.Contains("secret-sharing:send", nav);
        Assert.Contains("secret-sharing:settings", nav);
        Assert.DoesNotContain("secret-sharing:collect", nav);

        var prefs = await viewer.JsonAsync(HttpMethod.Get, "/api/plugins/secret-sharing/notifications");
        Assert.False(prefs.GetProperty("canCollect").GetBoolean());
        Assert.False(prefs.GetProperty("notifyCollectReady").GetBoolean());
        Assert.True(prefs.GetProperty("notifySendOpened").GetBoolean());

        var saved = await viewer.JsonAsync(HttpMethod.Put, "/api/plugins/secret-sharing/notifications", new { notifyCollectReady = true, notifySendOpened = true });
        Assert.False(saved.GetProperty("notifyCollectReady").GetBoolean());
        Assert.True(saved.GetProperty("notifySendOpened").GetBoolean());

        Assert.Equal(HttpStatusCode.Forbidden, (await viewer.SendAsync(HttpMethod.Post, "/api/plugins/secret-sharing/collects", new { publicKey = PublicKey(), expiresInMinutes = 60, oneTime = true })).StatusCode);
        var send = await viewer.SendAsync(HttpMethod.Post, "/api/plugins/secret-sharing/sends", new { });
        Assert.NotEqual(HttpStatusCode.Forbidden, send.StatusCode);
        var home = await viewer.JsonAsync(HttpMethod.Get, "/api/plugins/secret-sharing/home");
        Assert.DoesNotContain(home.GetProperty("items").EnumerateArray(), item => item.GetProperty("kind").GetString() == "collect");
    }

    public void Dispose() => _factory.Dispose();

    private static string PublicKey() => Convert.ToBase64String(new byte[32]).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private async Task<Client> AdminAsync()
    {
        var client = NewClient();
        var setup = await client.SendAsync(HttpMethod.Post, "/auth/setup", new { token = ShareHostFactory.SetupToken, username = "admin", displayName = "Admin", email = "admin@example.com", password = "correct horse battery staple 42" });
        Assert.Equal(HttpStatusCode.OK, setup.StatusCode);
        client.Reset();
        return client;
    }

    private async Task<(Client Client, string UserId, string Password)> UserWithRoleAsync(Client admin, string role, string username)
    {
        var created = await admin.JsonAsync(HttpMethod.Post, "/api/admin/users", new { username, role, email = username + "@example.com" });
        var id = created.GetProperty("user").GetProperty("id").GetString()!;
        var password = (await admin.JsonAsync(HttpMethod.Post, $"/api/admin/users/{id}/temporary-password")).GetProperty("temporaryPassword").GetString()!;
        return (await LoginAsync(username, password), id, password);
    }

    private async Task<Client> LoginAsync(string username, string password)
    {
        var client = NewClient();
        var proof = await client.JsonAsync(HttpMethod.Get, "/auth/login/pow");
        var (nonce, hash) = Solve(proof.GetProperty("hmacKey").GetString()!, proof.GetProperty("difficultyBits").GetInt32());
        var login = await client.SendAsync(HttpMethod.Post, "/auth/login/password", new { username, password, powChallengeId = proof.GetProperty("challengeId").GetString(), powNonce = nonce, powHash = hash });
        Assert.Equal(HttpStatusCode.OK, login.StatusCode);
        client.Reset();
        return client;
    }

    private static async Task<List<string?>> NavIdsAsync(Client client)
    {
        var nav = await client.JsonAsync(HttpMethod.Get, "/api/nav");
        return nav.GetProperty("sections").EnumerateArray().SelectMany(section => section.GetProperty("items").EnumerateArray()).Select(item => item.GetProperty("id").GetString()).ToList();
    }

    private Client NewClient() => new(_factory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false, BaseAddress = new Uri("http://localhost") }));

    private static (string Nonce, string Hash) Solve(string hmacKey, int difficultyBits)
    {
        var key = Base64UrlDecode(hmacKey);
        for (var nonce = 0; nonce < 5_000_000; nonce++)
        {
            var text = nonce.ToString(System.Globalization.CultureInfo.InvariantCulture);
            var mac = HMACSHA256.HashData(key, Encoding.ASCII.GetBytes(text));
            if (!HasLeadingZeroBits(mac, Math.Max(1, difficultyBits))) continue;
            return (text, Convert.ToBase64String(mac).TrimEnd('=').Replace('+', '-').Replace('/', '_'));
        }

        throw new InvalidOperationException("Could not solve the login proof of work.");
    }

    private static bool HasLeadingZeroBits(ReadOnlySpan<byte> hash, int bits)
    {
        var fullBytes = bits / 8;
        var rem = bits % 8;
        for (var i = 0; i < fullBytes; i++)
        {
            if (hash[i] != 0) return false;
        }

        if (rem == 0) return true;
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

    private sealed class Client(HttpClient http)
    {
        private string? _csrf;

        public async Task<HttpResponseMessage> SendAsync(HttpMethod method, string path, object? body = null)
        {
            var request = new HttpRequestMessage(method, path);
            if (body is not null) request.Content = JsonContent.Create(body, options: Json);
            if (method != HttpMethod.Get) request.Headers.Add("X-CSRF-TOKEN", await CsrfAsync());
            return await http.SendAsync(request);
        }

        public async Task<JsonElement> JsonAsync(HttpMethod method, string path, object? body = null)
        {
            var response = await SendAsync(method, path, body);
            var text = await response.Content.ReadAsStringAsync();
            Assert.True(response.IsSuccessStatusCode, $"{method} {path} -> {(int)response.StatusCode}: {text}");
            return JsonSerializer.Deserialize<JsonElement>(text, Json);
        }

        public void Reset() => _csrf = null;

        private async Task<string> CsrfAsync()
        {
            if (_csrf is null)
            {
                var session = await http.GetFromJsonAsync<JsonElement>("/api/session", Json);
                _csrf = session.GetProperty("csrfToken").GetString();
            }

            return _csrf!;
        }
    }
}

public sealed class ShareHostFactory : WebApplicationFactory<Vulpes.Host.Data.AppDbContext>
{
    public const string SetupToken = "share-role-test-token-0123456789";
    private readonly string _root = Path.Combine(Path.GetTempPath(), "vc-share-role", Guid.NewGuid().ToString("N"));

    public ShareHostFactory()
    {
        var data = Path.Combine(_root, "data");
        var incoming = Path.Combine(data, "plugins", "incoming");
        Directory.CreateDirectory(incoming);
        var testBin = AppContext.BaseDirectory.TrimEnd(Path.DirectorySeparatorChar);
        var tfm = Path.GetFileName(testBin);
        var configuration = Path.GetFileName(Path.GetDirectoryName(testBin)!);
        var repoRoot = Path.GetFullPath(Path.Combine(testBin, "..", "..", "..", "..", ".."));
        var result = PluginPackager.Pack(new PackOptions
        {
            PluginDirectory = Path.Combine(repoRoot, "src", "Vulpes.Plugins.Secret-Sharing", "bin", configuration, tfm),
            HostDirectory = Path.Combine(repoRoot, "..", "vulpes", "src", "Vulpes.Host", "bin", configuration, tfm),
            OutputPath = Path.Combine(_root, "secret-sharing.7z"),
        });
        var package = Path.Combine(incoming, "secret-sharing.7z");
        File.Copy(result.OutputPath, package);
        var catalog = Path.Combine(_root, "catalog");
        Directory.CreateDirectory(catalog);
        File.WriteAllText(Path.Combine(catalog, "manifest"), ReleaseLine(package, result.Version));
        CatalogDirectory = catalog;
        DataDirectory = data;
    }

    public string CatalogDirectory { get; }

    public string DataDirectory { get; }

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.UseEnvironment("Development");
        builder.UseSetting("Host:DataDirectory", DataDirectory);
        builder.UseSetting("Host:PublicOrigin", "http://localhost");
        builder.UseSetting("Host:SetupToken", SetupToken);
        builder.UseSetting("Host:MasterKey", Convert.ToBase64String(new byte[32]));
        builder.UseSetting("Plugins:InstallBundled", "false");
        builder.UseSetting("Plugins:PluginLocalDirectory", CatalogDirectory);
        builder.UseSetting("LocalAuth:PasswordHashIterations", "100000");
        builder.UseSetting("LocalAuth:AuthRateLimitPerMinute", "1000");
        builder.UseSetting("Logging:LogLevel:Default", "Warning");
    }

    protected override void Dispose(bool disposing)
    {
        base.Dispose(disposing);
        if (!disposing) return;
        try
        {
            Directory.Delete(_root, recursive: true);
        }
        catch (IOException)
        {
        }
    }

    private static string ReleaseLine(string packagePath, string version)
    {
        using var algorithm = new HMACSHA512(new byte[32]);
        using var stream = File.OpenRead(packagePath);
        var hmac = Convert.ToHexStringLower(algorithm.ComputeHash(stream));
        return "hmac_key:" + Convert.ToHexString(new byte[32]).ToLowerInvariant() + "\n" + Path.GetFileName(packagePath) + ":" + hmac + ":" + version + "\n";
    }
}
