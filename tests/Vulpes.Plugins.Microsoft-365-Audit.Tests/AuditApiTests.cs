using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Vulpes.PluginPacker;
using Xunit;

namespace Vulpes.Plugins.Microsoft365Audit.Tests;

/// <summary>Boots the real host with the packed audit module installed (no Elasticsearch, no Graph network access).</summary>
public sealed class AuditHostFactory : WebApplicationFactory<Vulpes.Host.Data.AppDbContext>
{
    public const string SetupToken = "audit-api-test-token-0123456789";
    private readonly string _root = Path.Combine(Path.GetTempPath(), "vc-audit-api", Guid.NewGuid().ToString("N"));

    public AuditHostFactory()
    {
        var data = Path.Combine(_root, "data");
        var incoming = Path.Combine(data, "modules", "incoming");
        Directory.CreateDirectory(incoming);
        var testBin = AppContext.BaseDirectory.TrimEnd(Path.DirectorySeparatorChar);
        var tfm = Path.GetFileName(testBin);
        var configuration = Path.GetFileName(Path.GetDirectoryName(testBin)!);
        var repoRoot = Path.GetFullPath(Path.Combine(testBin, "..", "..", "..", "..", ".."));
        var result = PluginPackager.Pack(new PackOptions
        {
            ModuleDirectory = Path.Combine(repoRoot, "src", "Vulpes.Plugins.Microsoft-365-Audit", "bin", configuration, tfm),
            HostDirectory = Path.Combine(repoRoot, "..", "vulpes", "src", "Vulpes.Host", "bin", configuration, tfm),
            OutputPath = Path.Combine(_root, "audit.7z"),
        });
        File.Copy(result.OutputPath, Path.Combine(incoming, "audit.7z"));
        DataDirectory = data;
    }

    public string DataDirectory { get; }

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.UseEnvironment("Development");
        builder.UseSetting("Host:DataDirectory", DataDirectory);
        builder.UseSetting("Host:PublicOrigin", "http://localhost");
        builder.UseSetting("Host:SetupToken", SetupToken);
        builder.UseSetting("Host:MasterKey", Convert.ToBase64String(new byte[32]));
        builder.UseSetting("Modules:InstallBundled", "false");
        builder.UseSetting("Modules:Settings:microsoft-365-audit:SchedulerIntervalSeconds", "600");
        builder.UseSetting("LocalAuth:PasswordHashIterations", "100000");
        builder.UseSetting("LocalAuth:AuthRateLimitPerMinute", "1000");
        builder.UseSetting("Logging:LogLevel:Default", "Warning");
    }

    protected override void Dispose(bool disposing)
    {
        base.Dispose(disposing);
        if (disposing)
        {
            try
            {
                Directory.Delete(_root, recursive: true);
            }
            catch (IOException)
            {
            }
        }
    }
}

public sealed class AuditApiTests : IDisposable
{
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);
    private readonly AuditHostFactory _factory = new();

    private sealed class Client(HttpClient http)
    {
        private string? _csrf;

        public HttpClient Http { get; } = http;

        public async Task<string> CsrfAsync()
        {
            if (_csrf is null)
            {
                var session = await Http.GetFromJsonAsync<JsonElement>("/api/session", Json);
                _csrf = session.GetProperty("csrfToken").GetString();
            }

            return _csrf!;
        }

        public void Reset() => _csrf = null;

        public async Task<HttpResponseMessage> SendAsync(HttpMethod method, string path, object? body = null)
        {
            var request = new HttpRequestMessage(method, path);
            if (body is not null)
            {
                request.Content = JsonContent.Create(body, options: Json);
            }

            if (method != HttpMethod.Get)
            {
                request.Headers.Add("X-CSRF-TOKEN", await CsrfAsync());
            }

            return await Http.SendAsync(request);
        }

        public async Task<JsonElement> JsonAsync(HttpMethod method, string path, object? body = null)
        {
            var response = await SendAsync(method, path, body);
            var text = await response.Content.ReadAsStringAsync();
            Assert.True(response.IsSuccessStatusCode, $"{method} {path} -> {(int)response.StatusCode}: {text}");
            return JsonSerializer.Deserialize<JsonElement>(text, Json);
        }
    }

    private Client NewClient() => new(_factory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false, BaseAddress = new Uri("http://localhost") }));

    private async Task<Client> AdminAsync()
    {
        var client = NewClient();
        var setup = await client.SendAsync(HttpMethod.Post, "/auth/setup", new { token = AuditHostFactory.SetupToken, username = "admin", password = "correct horse battery staple 42" });
        Assert.Equal(HttpStatusCode.OK, setup.StatusCode);
        client.Reset();
        return client;
    }

    private async Task<Client> UserWithRoleAsync(Client admin, string role, string username)
    {
        var created = await admin.JsonAsync(HttpMethod.Post, "/api/admin/users", new { username, role });
        var id = created.GetProperty("user").GetProperty("id").GetString();
        var password = (await admin.JsonAsync(HttpMethod.Post, $"/api/admin/users/{id}/temporary-password")).GetProperty("temporaryPassword").GetString();
        var client = NewClient();
        var login = await client.SendAsync(HttpMethod.Post, "/auth/login/password", new { username, password, remember = false });
        Assert.Equal(HttpStatusCode.OK, login.StatusCode);
        client.Reset();
        return client;
    }

    private static object TenantBody(string name = "Contoso", bool enabled = false) => new
    {
        displayName = name,
        tenantId = Guid.NewGuid().ToString(),
        clientId = Guid.NewGuid().ToString(),
        credentialType = "secret",
        clientSecret = "client-secret-value",
        cloud = "Global",
        enabled,
        lookbackDays = 3,
        settings = new { sources = new Dictionary<string, object> { ["signins"] = new { enabled = true, includeNonInteractive = false } } },
    };

    [Fact]
    public async Task Module_is_loaded_and_exposes_sources_and_navigation()
    {
        var admin = await AdminAsync();
        var nav = await admin.JsonAsync(HttpMethod.Get, "/api/nav");
        var ids = nav.GetProperty("sections").EnumerateArray().SelectMany(s => s.GetProperty("items").EnumerateArray()).Select(i => i.GetProperty("id").GetString()).ToList();
        Assert.Contains("microsoft-365-audit:overview", ids);
        Assert.Contains("microsoft-365-audit:permissions", ids);
        Assert.Contains("admin-tenants", ids);
        Assert.DoesNotContain("microsoft-365-audit:tenants", ids);

        var sources = await admin.JsonAsync(HttpMethod.Get, "/api/plugins/microsoft-365-audit/sources");
        Assert.Equal(9, sources.GetArrayLength());
        var signins = sources.EnumerateArray().Single(s => s.GetProperty("source").GetString() == "signins");
        Assert.Contains("AuditLog.Read.All", signins.GetProperty("collector").GetProperty("permissions").EnumerateArray().Select(p => p.GetString()));
        Assert.Contains(signins.GetProperty("fields").EnumerateArray(), f => f.GetProperty("path").GetString() == "labels.riskLevel");

        Assert.Equal(HttpStatusCode.OK, (await admin.Http.GetAsync("/modules/microsoft-365-audit/pages/overview.html")).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await admin.Http.GetAsync("/modules/microsoft-365-audit/js/common.js")).StatusCode);
    }

    [Fact]
    public async Task Tenant_lifecycle_through_the_api_with_role_enforcement()
    {
        var admin = await AdminAsync();
        var analyst = await UserWithRoleAsync(admin, "Analyst", "analyst");
        var viewer = await UserWithRoleAsync(admin, "Viewer", "viewer");

        Assert.Equal(HttpStatusCode.Forbidden, (await analyst.SendAsync(HttpMethod.Post, "/api/plugins/microsoft-365-audit/tenants", TenantBody())).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await viewer.SendAsync(HttpMethod.Get, "/api/plugins/microsoft-365-audit/tenants")).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await admin.SendAsync(HttpMethod.Post, "/api/plugins/microsoft-365-audit/tenants", new { displayName = "x", tenantId = "nope", clientId = Guid.NewGuid().ToString(), credentialType = "secret", clientSecret = "s" })).StatusCode);

        var created = await admin.JsonAsync(HttpMethod.Post, "/api/plugins/microsoft-365-audit/tenants", TenantBody());
        var id = created.GetProperty("id").GetString();
        Assert.True(created.GetProperty("hasSecret").GetBoolean());
        Assert.False(created.TryGetProperty("protectedSecret", out _));
        Assert.DoesNotContain("client-secret-value", created.GetRawText(), StringComparison.Ordinal);
        Assert.False(created.GetProperty("settings").GetProperty("sources").GetProperty("signins").GetProperty("includeNonInteractive").GetBoolean());

        var list = await analyst.JsonAsync(HttpMethod.Get, "/api/plugins/microsoft-365-audit/tenants");
        Assert.Single(list.EnumerateArray());
        var names = await viewer.JsonAsync(HttpMethod.Get, "/api/plugins/microsoft-365-audit/tenants/names");
        Assert.Equal("Contoso", names.EnumerateArray().Single().GetProperty("displayName").GetString());

        var updated = await admin.JsonAsync(HttpMethod.Put, $"/api/plugins/microsoft-365-audit/tenants/{id}", new { displayName = "Contoso Renamed", tenantId = created.GetProperty("tenantId").GetString(), clientId = created.GetProperty("clientId").GetString(), credentialType = "secret", clientSecret = (string?)null, cloud = "Global", enabled = false, lookbackDays = 10 });
        Assert.Equal("Contoso Renamed", updated.GetProperty("displayName").GetString());
        Assert.True(updated.GetProperty("hasSecret").GetBoolean());
        Assert.Equal(10, updated.GetProperty("lookbackDays").GetInt32());

        // Run-now schedules every source (tenant disabled, so nothing actually runs) and reset clears the checkpoints.
        var run = await analyst.JsonAsync(HttpMethod.Post, $"/api/plugins/microsoft-365-audit/tenants/{id}/run", new { });
        Assert.Equal(8, run.GetProperty("scheduled").GetArrayLength());
        Assert.Equal(HttpStatusCode.BadRequest, (await analyst.SendAsync(HttpMethod.Post, $"/api/plugins/microsoft-365-audit/tenants/{id}/run", new { source = "nope" })).StatusCode);
        var detail = await analyst.JsonAsync(HttpMethod.Get, $"/api/plugins/microsoft-365-audit/tenants/{id}");
        Assert.Equal(8, detail.GetProperty("checkpoints").GetArrayLength());
        var status = await analyst.JsonAsync(HttpMethod.Get, "/api/plugins/microsoft-365-audit/status");
        Assert.Single(status.GetProperty("tenants").EnumerateArray());
        Assert.Equal(HttpStatusCode.Forbidden, (await analyst.SendAsync(HttpMethod.Post, $"/api/plugins/microsoft-365-audit/tenants/{id}/reset", new { })).StatusCode);
        var reset = await admin.JsonAsync(HttpMethod.Post, $"/api/plugins/microsoft-365-audit/tenants/{id}/reset", new { source = "signins" });
        Assert.Equal(1, reset.GetProperty("removed").GetInt32());

        var audit = await admin.JsonAsync(HttpMethod.Get, "/api/admin/audit?action=audit.tenant");
        Assert.Contains(audit.GetProperty("items").EnumerateArray(), i => i.GetProperty("action").GetString() == "audit.tenant.created");

        Assert.Equal(HttpStatusCode.Forbidden, (await analyst.SendAsync(HttpMethod.Delete, $"/api/plugins/microsoft-365-audit/tenants/{id}")).StatusCode);
        Assert.Equal(HttpStatusCode.NoContent, (await admin.SendAsync(HttpMethod.Delete, $"/api/plugins/microsoft-365-audit/tenants/{id}")).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await admin.SendAsync(HttpMethod.Get, $"/api/plugins/microsoft-365-audit/tenants/{id}")).StatusCode);
    }

    [Fact]
    public async Task Search_endpoints_validate_input_and_degrade_gracefully_without_elasticsearch()
    {
        var admin = await AdminAsync();
        var viewer = await UserWithRoleAsync(admin, "Viewer", "viewer2");

        var search = await viewer.JsonAsync(HttpMethod.Post, "/api/plugins/microsoft-365-audit/search", new { source = "signins", size = 10, filters = new[] { new { field = "user.name", @operator = "equals", values = new[] { "bob" } } } });
        Assert.Equal(0, search.GetProperty("total").GetInt64());
        Assert.Empty(search.GetProperty("hits").EnumerateArray());

        Assert.Equal(HttpStatusCode.BadRequest, (await viewer.SendAsync(HttpMethod.Post, "/api/plugins/microsoft-365-audit/search", new { source = "" })).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await viewer.SendAsync(HttpMethod.Post, "/api/plugins/microsoft-365-audit/search", new { source = "nope" })).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await viewer.SendAsync(HttpMethod.Post, "/api/plugins/microsoft-365-audit/search", new { source = "signins", filters = new[] { new { field = "user.name", @operator = "like", values = new[] { "x" } } } })).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await viewer.SendAsync(HttpMethod.Post, "/api/plugins/microsoft-365-audit/search", new { source = "signins", filters = new[] { new { field = "secret.field", @operator = "equals", values = new[] { "x" } } } })).StatusCode);

        var aggregate = await viewer.JsonAsync(HttpMethod.Post, "/api/plugins/microsoft-365-audit/aggregate", new { source = "activity", aggregations = new[] { new { name = "byUser", kind = "terms", field = "user.name", size = 5 } } });
        Assert.Equal(0, aggregate.GetProperty("total").GetInt64());
        Assert.Equal(HttpStatusCode.BadRequest, (await viewer.SendAsync(HttpMethod.Post, "/api/plugins/microsoft-365-audit/aggregate", new { source = "activity", aggregations = new[] { new { name = "x", kind = "avg", field = "user.name" } } })).StatusCode);

        var overview = await viewer.JsonAsync(HttpMethod.Get, "/api/plugins/microsoft-365-audit/overview?hours=24");
        Assert.False(overview.GetProperty("available").GetBoolean());
        Assert.Equal(0, overview.GetProperty("signIns").GetProperty("total").GetInt64());

        Assert.Equal(HttpStatusCode.NotFound, (await viewer.SendAsync(HttpMethod.Get, "/api/plugins/microsoft-365-audit/events/signins/t:signins:missing")).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await viewer.SendAsync(HttpMethod.Get, "/api/plugins/microsoft-365-audit/status")).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await NewClient().SendAsync(HttpMethod.Get, "/api/plugins/microsoft-365-audit/sources")).StatusCode);
    }

    public void Dispose() => _factory.Dispose();
}
