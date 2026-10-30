using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Vulpes.Plugins.SecretSharing.Services;

/// <summary>Deletes expired and consumed sends and collects every minute, same as Sendit.</summary>
public sealed class ShareExpiryService(ShareStore store, ILogger<ShareExpiryService> log) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        try
        {
            await Task.Delay(TimeSpan.FromSeconds(5), stoppingToken);
        }
        catch (OperationCanceledException)
        {
            return;
        }

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                var removed = store.PurgeExpired();
                if (removed > 0) log.LogInformation("Purged expired or consumed secrets and collects: {Count}", removed);
            }
            catch (Exception ex)
            {
                log.LogError(ex, "Secret sharing expiry purge failed");
            }

            try
            {
                await Task.Delay(TimeSpan.FromMinutes(1), stoppingToken);
            }
            catch (OperationCanceledException)
            {
                break;
            }
        }
    }
}
