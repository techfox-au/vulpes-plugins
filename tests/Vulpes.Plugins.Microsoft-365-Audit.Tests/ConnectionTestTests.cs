using System.Net;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Time.Testing;
using Vulpes.Plugins.Microsoft365Audit.Collectors;
using Vulpes.Plugins.Microsoft365Audit.Data;
using Vulpes.Plugins.Microsoft365Audit.Graph;
using Vulpes.Plugins.Microsoft365Audit.Tenants;
using Xunit;

namespace Vulpes.Plugins.Microsoft365Audit.Tests;

public sealed class ConnectionTestTests : IDisposable
{
    private readonly SqliteConnection _connection = new("Data Source=:memory:");
    private readonly AuditDbContext _db;
    private readonly FakeTimeProvider _time = new(new DateTimeOffset(2026, 10, 30, 12, 0, 0, TimeSpan.Zero));

    public ConnectionTestTests()
    {
        _connection.Open();
        _db = new AuditDbContext(new DbContextOptionsBuilder<AuditDbContext>().UseSqlite(_connection).Options);
        _db.Database.EnsureCreated();
        _db.Tenants.Add(new Tenant { Id = TestContext.Tenant.Id, DisplayName = "Contoso", TenantId = TestContext.Tenant.TenantId, ClientId = TestContext.Tenant.ClientId, ProtectedSecret = "v1.x" });
        _db.SaveChanges();
    }

    private TenantService Service(HttpMessageHandler handler, params ICollector[] collectors) =>
        new(_db, new FakeProtector(), new ScriptedGraphFactory(handler, _time), collectors, _time, new AuditOptions(), NullLogger<TenantService>.Instance);

    [Fact]
    public async Task Probes_each_collector_and_records_the_organisation_name()
    {
        var handler = new RoutedGraphHandler()
            .Get(p => p.Contains("organization", StringComparison.Ordinal), _ => FakeGraphHandler.Json(new { value = new[] { new { id = "x", displayName = "Contoso Ltd" } } }))
            .Get(p => p.Contains("auditLogs/signIns", StringComparison.Ordinal), _ => RoutedGraphHandler.Page([]))
            .Get(p => p.Contains("security/alerts_v2", StringComparison.Ordinal), _ => FakeGraphHandler.Json(new { error = new { code = "Authorization_RequestDenied", message = "denied" } }, HttpStatusCode.Forbidden))
            .Get(p => p.Contains("security/secureScores", StringComparison.Ordinal), _ => FakeGraphHandler.Json(new { error = new { code = "InternalServerError", message = "boom" } }, HttpStatusCode.InternalServerError));
        var service = Service(handler, new SignInsCollector(), new SecurityAlertsCollector(), new SecureScoreCollector());

        var result = await service.TestConnectionAsync(_db.Tenants.Single(), CancellationToken.None);

        Assert.True(result.TokenAcquired);
        Assert.Equal("Contoso Ltd", result.OrganizationName);
        Assert.Equal(3, result.Probes.Count);
        Assert.Equal("ok", result.Probes.Single(p => p.Source == "signins").Status);
        var forbidden = result.Probes.Single(p => p.Source == "security-alerts");
        Assert.Equal("forbidden", forbidden.Status);
        Assert.Contains("SecurityAlert.Read.All", forbidden.Detail, StringComparison.Ordinal);
        Assert.Equal("error", result.Probes.Single(p => p.Source == "securescore").Status);

        var stored = _db.Tenants.Single();
        Assert.Equal("Contoso Ltd", stored.DiscoveredName);
        Assert.Equal(_time.GetUtcNow(), stored.LastTestAt);
        Assert.Contains("\"tokenAcquired\":true", stored.LastTestResultJson, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Token_or_organisation_failures_are_reported_without_probing()
    {
        var handler = new RoutedGraphHandler().Get(p => p.Contains("organization", StringComparison.Ordinal), _ => FakeGraphHandler.Json(new { error = new { code = "InvalidAuthenticationToken", message = "Access token has expired" } }, HttpStatusCode.Unauthorized));
        var service = Service(handler, new SignInsCollector());

        var result = await service.TestConnectionAsync(_db.Tenants.Single(), CancellationToken.None);

        Assert.False(result.TokenAcquired);
        Assert.Contains("401", result.Error, StringComparison.Ordinal);
        Assert.Empty(result.Probes);
        Assert.Null(_db.Tenants.Single().DiscoveredName);
        Assert.NotNull(_db.Tenants.Single().LastTestResultJson);
    }

    public void Dispose()
    {
        _db.Dispose();
        _connection.Dispose();
    }

    private sealed class ScriptedGraphFactory : GraphClientFactory
    {
        private readonly HttpMessageHandler _handler;
        private readonly TimeProvider _time;

        public ScriptedGraphFactory(HttpMessageHandler handler, TimeProvider time)
            : base(new NoHttp(), new GraphCredentialFactory(new FakeProtector()), NullLoggerFactory.Instance, time)
        {
            _handler = handler;
            _time = time;
        }

        public override GraphClient Create(Tenant tenant) => TestContext.Client(_handler, _time);
    }

    private sealed class NoHttp : IHttpClientFactory
    {
        public HttpClient CreateClient(string name) => new(new RoutedGraphHandler());
    }
}
