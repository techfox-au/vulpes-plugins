using Microsoft.EntityFrameworkCore;
using Vulpes.Plugins.Microsoft365Audit.Data;
using Vulpes.Plugins.Microsoft365Audit.Scheduling;
using Vulpes.Sdk;

namespace Vulpes.Plugins.Microsoft365Audit.Tenants;

/// <summary>Stops Audit collection for a disabled client and deletes their stored logs.</summary>
public sealed class AuditDisabledClient(IServiceScopeFactory scopes) : IDisabledClient
{
    public async Task OnDisabledAsync(Guid clientId, CancellationToken cancellationToken)
    {
        await using var scope = scopes.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<AuditDbContext>();
        var tenants = scope.ServiceProvider.GetRequiredService<TenantService>();
        var directory = scope.ServiceProvider.GetRequiredService<ITenantDirectory>();
        var application = scope.ServiceProvider.GetRequiredService<IEntraApplication>();
        var remote = await directory.ListAsync(cancellationToken);
        var shared = await application.GetAsync(cancellationToken);
        if (remote.Count > 0 || shared is not null)
        {
            await tenants.SyncFromDirectoryAsync(remote, shared, cancellationToken);
        }

        var tenant = await db.Tenants.FirstOrDefaultAsync(t => t.Id == clientId, cancellationToken);
        if (tenant is null)
        {
            return;
        }

        tenant.Enabled = false;
        await db.SaveChangesAsync(cancellationToken);
        await AuditClientPurge.RunAsync(
            tenant,
            scope.ServiceProvider.GetRequiredService<CollectionScheduler>(),
            scope.ServiceProvider.GetRequiredService<IEventStoreMaintenance>(),
            scope.ServiceProvider.GetRequiredService<IEventStoreReadiness>(),
            db,
            cancellationToken);
    }

    public async Task OnEnabledAsync(Guid clientId, CancellationToken cancellationToken)
    {
        await using var scope = scopes.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<AuditDbContext>();
        var tenant = await db.Tenants.FirstOrDefaultAsync(t => t.Id == clientId, cancellationToken);
        if (tenant is null)
        {
            return;
        }

        tenant.Enabled = true;
        await db.SaveChangesAsync(cancellationToken);
    }
}
