using Microsoft.AspNetCore.Builder;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Time.Testing;
using Vulpes.Host.Plugins;
using Vulpes.PluginPacker;
using Vulpes.Plugins.Microsoft365Audit.Collectors;
using Vulpes.Plugins.Microsoft365Audit.Data;
using Vulpes.Plugins.Microsoft365Audit.Graph;
using Vulpes.Plugins.Microsoft365Audit.Tenants;
using Vulpes.Sdk;
using Xunit;

namespace Vulpes.Plugins.Microsoft365Audit.Tests;

public sealed class TenantServiceTests : IDisposable
{
    private readonly SqliteConnection _connection = new("Data Source=:memory:");
    private readonly AuditDbContext _db;
    private readonly FakeProtector _protector = new();

    public TenantServiceTests()
    {
        _connection.Open();
        _db = new AuditDbContext(new DbContextOptionsBuilder<AuditDbContext>().UseSqlite(_connection).Options);
        _db.Database.EnsureCreated();
    }

    private TenantService Service() => new(_db, _protector, new GraphClientFactory(new NoHttpClientFactory(), new GraphCredentialFactory(_protector), NullLoggerFactory.Instance, TimeProvider.System), [new SignInsCollector()], new FakeTimeProvider(), new AuditOptions(), NullLogger<TenantService>.Instance);

    [Fact]
    public async Task Secrets_are_encrypted_at_rest_and_blank_updates_keep_them()
    {
        var service = Service();
        var (tenant, error) = await service.CreateAsync(new TenantInput("Contoso", Guid.NewGuid().ToString(), Guid.NewGuid().ToString(), "secret", "super-secret-value", null, null, "Global", true, 14, null), "admin", CancellationToken.None);
        Assert.Null(error);
        Assert.NotNull(tenant);
        Assert.StartsWith("v1.", tenant.ProtectedSecret, StringComparison.Ordinal);
        Assert.DoesNotContain("super-secret-value", tenant.ProtectedSecret, StringComparison.Ordinal);
        Assert.Equal(14, tenant.LookbackDays);

        var (updated, updateError) = await service.UpdateAsync(tenant.Id, new TenantInput("Contoso 2", tenant.TenantId, tenant.ClientId, "secret", null, null, null, "Global", false, null, null), CancellationToken.None);
        Assert.Null(updateError);
        Assert.Equal(tenant.ProtectedSecret, updated!.ProtectedSecret);
        Assert.False(updated.Enabled);
        Assert.Equal("Contoso 2", updated.DisplayName);

        var dto = System.Text.Json.JsonSerializer.Serialize(TenantService.ToDto(updated));
        Assert.DoesNotContain("super-secret-value", dto, StringComparison.Ordinal);
        Assert.DoesNotContain("ProtectedSecret", dto, StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData("", "tenant", "client", "Display name")]
    [InlineData("Contoso", "not-a-guid", "client", "Tenant id")]
    [InlineData("Contoso", "tenant", "not-a-guid", "Client id")]
    public async Task Validation_errors_are_reported(string name, string tenantId, string clientId, string expectedFragment)
    {
        var service = Service();
        var tid = tenantId == "tenant" ? Guid.NewGuid().ToString() : tenantId;
        var cid = clientId == "client" ? Guid.NewGuid().ToString() : clientId;
        var (tenant, error) = await service.CreateAsync(new TenantInput(name, tid, cid, "secret", "s", null, null, "Global", true, 7, null), null, CancellationToken.None);
        Assert.Null(tenant);
        Assert.Contains(expectedFragment, error, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Missing_secret_and_unknown_source_settings_are_rejected()
    {
        var service = Service();
        var (_, noSecret) = await service.CreateAsync(new TenantInput("Contoso", Guid.NewGuid().ToString(), Guid.NewGuid().ToString(), "secret", null, null, null, "Global", true, 7, null), null, CancellationToken.None);
        Assert.Contains("client secret", noSecret, StringComparison.Ordinal);

        var settings = new TenantSettings { Sources = { ["nope"] = new SourceSettings() } };
        var (_, badSource) = await service.CreateAsync(new TenantInput("Contoso", Guid.NewGuid().ToString(), Guid.NewGuid().ToString(), "secret", "s", null, null, "Global", true, 7, settings), null, CancellationToken.None);
        Assert.Contains("Unknown source", badSource, StringComparison.Ordinal);
    }

    public void Dispose()
    {
        _db.Dispose();
        _connection.Dispose();
    }

    private sealed class NoHttpClientFactory : IHttpClientFactory
    {
        public HttpClient CreateClient(string name) => new(new RoutedGraphHandler());
    }
}

/// <summary>Packs the real audit module from its build output, installs it through the host installer and loads it in an isolated context.</summary>
public sealed class AuditPackagingTests : IDisposable
{
    private readonly string _temp = Path.Combine(Path.GetTempPath(), "vc-audit-pack", Guid.NewGuid().ToString("N"));

    private static (string ModuleDir, string HostDir) OutputDirectories()
    {
        var testBin = AppContext.BaseDirectory.TrimEnd(Path.DirectorySeparatorChar);
        var tfm = Path.GetFileName(testBin);
        var configuration = Path.GetFileName(Path.GetDirectoryName(testBin)!);
        var repoRoot = Path.GetFullPath(Path.Combine(testBin, "..", "..", "..", "..", ".."));
        var moduleDir = Path.Combine(repoRoot, "src", "Vulpes.Plugins.Microsoft-365-Audit", "bin", configuration, tfm);
        var hostDir = Path.Combine(repoRoot, "..", "vulpes", "src", "Vulpes.Host", "bin", configuration, tfm);
        Assert.True(File.Exists(Path.Combine(moduleDir, "plugin.json")), $"module output not found at {moduleDir}");
        Assert.True(File.Exists(Path.Combine(hostDir, "Vulpes.Host.dll")), $"host output not found at {hostDir}");
        return (moduleDir, hostDir);
    }

    [Fact]
    public async Task Audit_module_round_trips_through_packer_installer_and_loader()
    {
        Directory.CreateDirectory(_temp);
        var (moduleDir, hostDir) = OutputDirectories();
        var result = PluginPackager.Pack(new PackOptions
        {
            ModuleDirectory = moduleDir,
            OutputPath = Path.Combine(_temp, "dist", "audit.7z"),
            HostDirectory = hostDir, // everything the real host ships is stripped; module-private deps (Azure.Identity) stay
        });

        Assert.Equal("microsoft-365-audit", result.ModuleId);
        Assert.Contains("Vulpes.Sdk.dll", result.Stripped);
        Assert.Contains("Microsoft.EntityFrameworkCore.dll", result.Stripped);
        Assert.DoesNotContain("Vulpes.Plugins.Microsoft-365-Audit.dll", result.Stripped);
        Assert.DoesNotContain("Azure.Identity.dll", result.Stripped);
        Assert.True(new FileInfo(result.OutputPath).Length < 20 * 1024 * 1024, "package should stay small once host-shared assemblies are stripped");

        var options = new PluginOptions { Directory = Path.Combine(_temp, "modules") };
        var installer = new PluginPackageInstaller(options, options.Directory!, NullLogger<PluginPackageInstaller>.Instance);
        var record = await installer.InstallAsync(result.OutputPath, "test", "tester", CancellationToken.None);
        Assert.Equal("microsoft-365-audit", record.Id);

        var catalog = PluginLoader.LoadAll(options.Directory!, new ConfigurationBuilder().Build(), installer, NullLogger.Instance);
        Assert.Empty(catalog.Failures);
        var module = Assert.Single(catalog.Modules);
        Assert.Equal(8, module.Manifest.Nav.Count);
        Assert.True(File.Exists(Path.Combine(module.Context.WebRoot, "pages", "overview.html")));
        Assert.True(File.Exists(Path.Combine(module.Context.WebRoot, "js", "common.js")));

        // Host-provided services the module depends on.
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddHttpClient();
        services.AddSingleton(TimeProvider.System);
        services.AddSingleton<ISecretProtector>(new FakeProtector());
        services.AddSingleton<IEventPipeline>(new FakePipeline());
        module.Instance.ConfigureServices(services, module.Context);
        await using var provider = services.BuildServiceProvider();
        await module.Instance.InitializeAsync(provider, module.Context, CancellationToken.None);
        Assert.True(File.Exists(module.Context.DatabasePath));

        // The module's schema contributor and collectors are resolvable through the shared SDK types.
        var schema = Assert.Single(provider.GetServices<IIndexSchemaContributor>());
        Assert.Equal("microsoft-365-audit", schema.ModuleId);
        Assert.Contains(schema.Sources, s => s.Source == "signins");
        // Module-private types live in the module's own load context, so compare by name rather than by Type identity.
        Assert.Equal(8, services.Count(d => d.ServiceType.Name == nameof(ICollector)));

        // Endpoints map without throwing on a real route builder.
        var app = WebApplication.CreateBuilder().Build();
        module.Instance.MapEndpoints(app.MapGroup("/api/plugins/microsoft-365-audit"), module.Context);
    }

    public void Dispose()
    {
        try
        {
            Directory.Delete(_temp, recursive: true);
        }
        catch (IOException)
        {
        }
    }
}
