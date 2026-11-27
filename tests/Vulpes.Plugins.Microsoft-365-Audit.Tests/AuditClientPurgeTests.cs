using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Vulpes.Plugins.Microsoft365Audit.Data;
using Vulpes.Plugins.Microsoft365Audit.Graph;
using Vulpes.Plugins.Microsoft365Audit.Scheduling;
using Vulpes.Plugins.Microsoft365Audit.Tenants;
using Vulpes.Sdk;
using Xunit;

namespace Vulpes.Plugins.Microsoft365Audit.Tests;

public sealed class AuditClientPurgeTests
{
    [Fact]
    public async Task Stored_logs_are_deleted_only_after_the_checkpoints_are_gone()
    {
        await using var connection = new SqliteConnection("Data Source=:memory:");
        await connection.OpenAsync();
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddDbContext<AuditDbContext>(o => o.UseSqlite(connection));
        await using var provider = services.BuildServiceProvider();
        using var scope = provider.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AuditDbContext>();
        db.Database.EnsureCreated();
        var tenant = new Tenant { Id = Guid.NewGuid(), DisplayName = "Contoso", TenantId = "tenant", ClientId = "client", ProtectedSecret = "secret" };
        db.Tenants.Add(tenant);
        db.Checkpoints.Add(new Checkpoint { TenantId = tenant.Id, Source = "signins" });
        db.RunLog.Add(new RunLogEntry { TenantId = tenant.Id, Source = "signins", StartedAt = DateTimeOffset.UnixEpoch });
        db.SaveChanges();

        var seenCheckpoints = -1;
        var store = new CountingStore(provider, count => seenCheckpoints = count);
        var scheduler = new CollectionScheduler(
            provider.GetRequiredService<IServiceScopeFactory>(),
            [],
            new GraphClientFactory(new NoHttp(), new GraphCredentialFactory(new FakeProtector()), NullLoggerFactory.Instance, TimeProvider.System),
            new FakePipeline(),
            new Ready(),
            new AuditOptions(),
            TimeProvider.System,
            NullLogger<CollectionScheduler>.Instance);

        await AuditClientPurge.RunAsync(tenant, scheduler, store, new Ready(), db, CancellationToken.None);
        Assert.Equal(0, seenCheckpoints);
    }

    private sealed class CountingStore(IServiceProvider provider, Action<int> seen) : IEventStoreMaintenance
    {
        public async Task<long?> DeleteTenantAsync(string pluginId, string tenantId, CancellationToken cancellationToken)
        {
            await using var scope = provider.CreateAsyncScope();
            var db = scope.ServiceProvider.GetRequiredService<AuditDbContext>();
            seen(await db.Checkpoints.CountAsync(cancellationToken));
            return 1;
        }
    }

    private sealed class Ready : IEventStoreReadiness
    {
        public bool IsReady => true;
    }

    private sealed class NoHttp : IHttpClientFactory
    {
        public HttpClient CreateClient(string name) => new();
    }
}
