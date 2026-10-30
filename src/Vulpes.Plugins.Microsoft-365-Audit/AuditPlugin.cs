using Microsoft.AspNetCore.Routing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Vulpes.Plugins.Microsoft365Audit.Collectors;
using Vulpes.Plugins.Microsoft365Audit.Data;
using Vulpes.Plugins.Microsoft365Audit.Endpoints;
using Vulpes.Plugins.Microsoft365Audit.Graph;
using Vulpes.Plugins.Microsoft365Audit.Scheduling;
using Vulpes.Plugins.Microsoft365Audit.Normalization;
using Vulpes.Plugins.Microsoft365Audit.Tenants;
using Vulpes.Sdk;

namespace Vulpes.Plugins.Microsoft365Audit;

/// <summary>Identity Protection risk is the source Business Premium mode turns off.</summary>
public sealed class AuditSourceAvailability(AuditOptions options) : ISourceAvailability
{
    public string ModuleId => Normalizers.ModuleId;

    public bool IsAvailable(string source) => options.Collects(source);
}

/// <summary>Microsoft 365 / Entra audit log ingestion module.</summary>
public sealed class AuditGraphPermissions : IGraphPermissionSource
{
    public string ModuleId => Normalizers.ModuleId;

    public IReadOnlyList<GraphAccess> Permissions { get; } =
    [
        new("AuditLog.Read.All", "Sign-ins, directory audit, provisioning"),
        new("Directory.Read.All", "Organisation name and sign-in enrichment"),
        new("AuditLogsQuery.Read.All", "Microsoft 365 unified audit log"),
        new("SecurityAlert.Read.All", "Defender alerts"),
        new("SecurityIncident.Read.All", "Defender incidents"),
        new("IdentityRiskEvent.Read.All", "Identity Protection risk detections", "risk"),
        new("IdentityRiskyUser.Read.All", "Risky users", "risk"),
        new("IdentityRiskyServicePrincipal.Read.All", "Risky service principals", "risk"),
        new("SecurityEvents.Read.All", "Secure Score"),
    ];
}

public sealed class AuditConnectionTester(TenantService tenants, ITenantDirectory directory, IEntraApplication application) : ITenantConnectionTester
{
    public string ModuleId => Normalizers.ModuleId;

    public async Task<TenantConnectionReport> TestAsync(Guid tenantId, CancellationToken cancellationToken)
    {
        await tenants.SyncFromDirectoryAsync(await directory.ListAsync(cancellationToken), await application.GetAsync(cancellationToken), cancellationToken);
        var tenant = await tenants.FindAsync(tenantId, cancellationToken);
        if (tenant is null)
        {
            return new TenantConnectionReport(ModuleId, false, null, "Tenant not found.", []);
        }

        var result = await tenants.TestConnectionAsync(tenant, cancellationToken);
        if (!string.IsNullOrWhiteSpace(result.OrganizationName))
        {
            await directory.SetDiscoveredNameAsync(tenantId, result.OrganizationName, cancellationToken);
        }

        return new TenantConnectionReport(
            ModuleId,
            result.TokenAcquired,
            result.OrganizationName,
            result.Error,
            result.Probes.Select(p => new TenantProbe(p.Source, p.Title, p.Status, p.Detail)).ToList());
    }
}

public sealed class AuditPlugin : IPlugin
{
    public string Id => Normalizers.ModuleId;

    public void ConfigureServices(IServiceCollection services, IPluginContext context)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(context);

        var options = context.Configuration.Get<AuditOptions>() ?? new AuditOptions();
        services.AddSingleton(options);
        services.AddSingleton<ISourceAvailability>(new AuditSourceAvailability(options));
        services.AddSingleton<IGraphPermissionSource, AuditGraphPermissions>();
        services.AddSingleton<IEntraTokenSource, EntraTokenSource>();
        services.AddScoped<ITenantConnectionTester, AuditConnectionTester>();
        services.AddSingleton(new AuditSettingsStore(Path.Combine(context.DataDirectory, "settings.json"), options));
        services.AddSingleton<IIndexSchemaContributor, AuditSchema>();

        services.AddDbContext<AuditDbContext>(o => o.UseSqlite($"Data Source={context.DatabasePath};Default Timeout=30;Pooling=True"));

        services.AddHttpClient(GraphClientFactory.HttpClientName)
            .ConfigurePrimaryHttpMessageHandler(() => new SocketsHttpHandler
            {
                PooledConnectionLifetime = TimeSpan.FromMinutes(10),
                AutomaticDecompression = System.Net.DecompressionMethods.All,
            });

        services.AddSingleton<GraphCredentialFactory>();
        services.AddSingleton<GraphClientFactory>();

        services.AddSingleton<ICollector, SignInsCollector>();
        services.AddSingleton<ICollector, DirectoryAuditsCollector>();
        services.AddSingleton<ICollector, ProvisioningCollector>();
        services.AddSingleton<ICollector, PurviewAuditCollector>();
        services.AddSingleton<ICollector, SecurityAlertsCollector>();
        services.AddSingleton<ICollector, IncidentsCollector>();
        services.AddSingleton<ICollector, RiskCollector>();
        services.AddSingleton<ICollector, SecureScoreCollector>();

        services.AddScoped<TenantService>();
        services.AddSingleton<CollectionScheduler>();
        services.AddHostedService(sp => sp.GetRequiredService<CollectionScheduler>());
    }

    public void MapEndpoints(IEndpointRouteBuilder endpoints, IPluginContext context) => AuditEndpoints.Map(endpoints);

    public async Task InitializeAsync(IServiceProvider services, IPluginContext context, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(context);
        Directory.CreateDirectory(context.DataDirectory);
        await using var scope = services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<AuditDbContext>();
        await db.Database.MigrateAsync(cancellationToken);
        await db.Database.ExecuteSqlRawAsync("PRAGMA journal_mode=WAL;", cancellationToken);
        services.GetRequiredService<AuditSettingsStore>().Load();
        await ImportHostTenantsAsync(scope.ServiceProvider, cancellationToken);
        scope.ServiceProvider.GetRequiredService<ILoggerFactory>().CreateLogger<AuditPlugin>().LogInformation("Audit plugin database ready at {Path}", context.DatabasePath);
    }

    /// <summary>Moves plugin-local tenant credentials onto the shared host application the first time the host list is empty.</summary>
    private static async Task ImportHostTenantsAsync(IServiceProvider services, CancellationToken cancellationToken)
    {
        var directory = services.GetService<ITenantDirectory>();
        var application = services.GetService<IEntraApplication>();
        if (directory is null || application is null || (await directory.ListAsync(cancellationToken)).Count > 0)
        {
            return;
        }

        var db = services.GetRequiredService<AuditDbContext>();
        var protector = services.GetRequiredService<ISecretProtector>();
        var existing = await db.Tenants.AsNoTracking().OrderBy(t => t.CreatedAt).ToListAsync(cancellationToken);
        var credentialSource = existing.FirstOrDefault(t => t.ProtectedSecret is not null || t.ProtectedCertificate is not null);
        if (credentialSource is not null)
        {
            await application.SaveIfEmptyAsync(new EntraApplicationCredential(
                credentialSource.ClientId,
                credentialSource.CredentialType,
                credentialSource.Cloud,
                credentialSource.ProtectedSecret is null ? null : protector.Unprotect(credentialSource.ProtectedSecret),
                credentialSource.ProtectedCertificate is null ? null : protector.Unprotect(credentialSource.ProtectedCertificate),
                credentialSource.ProtectedCertificatePassword is null ? null : protector.Unprotect(credentialSource.ProtectedCertificatePassword)), cancellationToken);
        }

        foreach (var tenant in existing)
        {
            await directory.AddIfMissingAsync(new ManagedTenant(tenant.Id, tenant.DisplayName, tenant.TenantId, tenant.Enabled, tenant.DiscoveredName), cancellationToken);
        }
    }
}
