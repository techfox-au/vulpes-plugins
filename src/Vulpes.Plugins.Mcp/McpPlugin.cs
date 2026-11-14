using Microsoft.AspNetCore.Routing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Vulpes.Plugins.Mcp.Data;
using Vulpes.Plugins.Mcp.Endpoints;
using Vulpes.Sdk;

namespace Vulpes.Plugins.Mcp;

public sealed class McpPlugin : IPlugin
{
    public string Id => "mcp";

    public void ConfigureServices(IServiceCollection services, IPluginContext context)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(context);
        services.AddDbContext<McpDbContext>(o => o.UseSqlite($"Data Source={context.DatabasePath};Default Timeout=30;Pooling=True"));
        services.AddHostedService<TokenExpiryNotice>();
    }

    public void MapEndpoints(IEndpointRouteBuilder endpoints, IPluginContext context)
    {
        ArgumentNullException.ThrowIfNull(endpoints);
        McpEndpoints.Map(endpoints);
    }

    public async Task InitializeAsync(IServiceProvider services, IPluginContext context, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(context);
        Directory.CreateDirectory(context.DataDirectory);
        await using var scope = services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<McpDbContext>();
        await db.Database.MigrateAsync(cancellationToken);
        await db.Database.ExecuteSqlRawAsync("PRAGMA journal_mode=WAL;", cancellationToken);
        var copied = await AuditTokenImport.CopyIfEmptyAsync(db, context.DataDirectory, cancellationToken);
        var logger = services.GetRequiredService<ILoggerFactory>().CreateLogger<McpPlugin>();
        if (copied > 0)
        {
            logger.LogInformation("Copied {Count} Grok Bot tokens from Microsoft 365 Audit", copied);
        }

        logger.LogInformation("MCP plugin database ready at {Path}", context.DatabasePath);
    }
}
