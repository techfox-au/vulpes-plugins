using Microsoft.EntityFrameworkCore;
using Vulpes.Plugins.Microsoft365Audit.Data;
using Vulpes.Plugins.Microsoft365Audit.Normalization;
using Vulpes.Plugins.Microsoft365Audit.Scheduling;
using Vulpes.Sdk;

namespace Vulpes.Plugins.Microsoft365Audit.Tenants;

/// <summary>Deletes one client's stored audit logs, checkpoints, and run history.</summary>
public static class AuditClientPurge
{
    public static async Task<long> RunAsync(Tenant tenant, CollectionScheduler scheduler, IEventStoreMaintenance store, IEventStoreReadiness readiness, AuditDbContext db, CancellationToken cancellationToken)
    {
        if (!readiness.IsReady)
        {
            throw new ClientUnavailableException("search_unavailable", "Elasticsearch is not ready.");
        }

        if (!scheduler.TryBeginPurge(tenant.Id))
        {
            throw new ClientUnavailableException("busy", "A collector is still running for this client. Try again when it finishes.");
        }

        try
        {
            long deleted;
            try
            {
                deleted = await store.DeleteTenantAsync(Normalizers.PluginId, tenant.TenantId, cancellationToken) ?? 0;
            }
            catch (ArgumentException ex)
            {
                throw new ClientUnavailableException("validation", ex.Message);
            }
            catch (Exception ex) when (ex.GetType().Name == "SearchUnavailableException")
            {
                throw new ClientUnavailableException("search_unavailable", "Elasticsearch could not delete the stored logs.");
            }

            var checkpoints = await db.Checkpoints.Where(c => c.TenantId == tenant.Id).ToListAsync(cancellationToken);
            db.Checkpoints.RemoveRange(checkpoints);
            var runs = await db.RunLog.Where(r => r.TenantId == tenant.Id).ToListAsync(cancellationToken);
            db.RunLog.RemoveRange(runs);
            await db.SaveChangesAsync(cancellationToken);
            return deleted;
        }
        finally
        {
            scheduler.EndPurge(tenant.Id);
        }
    }
}
