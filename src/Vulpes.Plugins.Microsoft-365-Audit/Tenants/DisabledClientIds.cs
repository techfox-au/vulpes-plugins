using Vulpes.Sdk;

namespace Vulpes.Plugins.Microsoft365Audit.Tenants;

internal static class DisabledClientIds
{
    public static async Task<HashSet<Guid>> LoadAsync(ISharedClientDirectory directory, CancellationToken cancellationToken)
    {
        var ids = new HashSet<Guid>();
        foreach (var tenant in await directory.ListAllAsync(cancellationToken))
        {
            if (tenant.Disabled)
            {
                ids.Add(tenant.Id);
            }
        }

        return ids;
    }
}
