using Vulpes.Sdk;

namespace Vulpes.Plugins.SecretSharing.Services;

/// <summary>Drops the user data key and every send and collect encrypted under it.</summary>
public sealed class SecretReset(ShareStore store, IHostAuditLog audit) : IUserSecretReset
{
    public async Task ResetAsync(string userId, CancellationToken cancellationToken)
    {
        var (sends, collects) = store.ResetUser(userId);
        await audit.RecordAsync("secret.reset", userId, $"sends={sends} collects={collects}", actor: "system:secret-sharing", cancellationToken: cancellationToken);
    }
}
