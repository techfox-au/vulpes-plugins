using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Vulpes.Plugins.Mcp.Data;
using Vulpes.Sdk;

namespace Vulpes.Plugins.Mcp.Endpoints;

internal sealed class TokenExpiryNotice(IServiceScopeFactory scopes, ILogger<TokenExpiryNotice> log) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (!await Wait(TimeSpan.FromMinutes(1), stoppingToken))
        {
            return;
        }

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await using var scope = scopes.CreateAsyncScope();
                var services = scope.ServiceProvider;
                await TokenExpiryMail.SendDueAsync(
                    services.GetRequiredService<McpDbContext>(),
                    services.GetRequiredService<IHostEmail>(),
                    services.GetRequiredService<IDefaultMailRecipients>(),
                    services.GetRequiredService<IHostAuditLog>(),
                    services.GetRequiredService<TimeProvider>(),
                    stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception ex)
            {
                log.LogError(ex, "MCP token expiry notice failed");
            }

            if (!await Wait(TimeSpan.FromHours(1), stoppingToken))
            {
                break;
            }
        }
    }

    private static async Task<bool> Wait(TimeSpan delay, CancellationToken cancellationToken)
    {
        try
        {
            await Task.Delay(delay, cancellationToken);
            return true;
        }
        catch (OperationCanceledException)
        {
            return false;
        }
    }
}
