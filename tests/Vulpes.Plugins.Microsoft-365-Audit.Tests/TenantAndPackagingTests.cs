using System.Security.Cryptography;
using System.Text;
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
    public async Task Shared_application_secret_is_encrypted_on_the_plugin_row()
    {
        var service = Service();
        var id = Guid.NewGuid();
        await service.SyncFromDirectoryAsync(
            [new ManagedTenant(id, "Contoso", Guid.NewGuid().ToString(), true, null)],
            new EntraApplicationCredential(Guid.NewGuid().ToString(), "secret", "Global", "super-secret-value", null, null),
            CancellationToken.None);

        var tenant = Assert.Single(_db.Tenants);
        Assert.Equal(id, tenant.Id);
        Assert.StartsWith("v1.", tenant.ProtectedSecret, StringComparison.Ordinal);
        Assert.DoesNotContain("super-secret-value", tenant.ProtectedSecret, StringComparison.Ordinal);

        var dto = System.Text.Json.JsonSerializer.Serialize(TenantService.ToDto(tenant));
        Assert.DoesNotContain("super-secret-value", dto, StringComparison.Ordinal);
        Assert.DoesNotContain("ProtectedSecret", dto, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Collection_settings_reject_an_unknown_source_and_a_bad_lookback()
    {
        var service = Service();
        var id = Guid.NewGuid();
        await service.SyncFromDirectoryAsync(
            [new ManagedTenant(id, "Contoso", Guid.NewGuid().ToString(), true, null)],
            new EntraApplicationCredential(Guid.NewGuid().ToString(), "secret", "Global", "secret", null, null),
            CancellationToken.None);

        var settings = new TenantSettings { Sources = { ["nope"] = new SourceSettings() } };
        Assert.Contains("Unknown source", await service.UpdateCollectionAsync(id, 7, settings, CancellationToken.None), StringComparison.Ordinal);
        Assert.Contains("Lookback", await service.UpdateCollectionAsync(id, 999, null, CancellationToken.None), StringComparison.Ordinal);
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

/// <summary>Packs the real audit plugin from its build output, installs it through the host installer and loads it in an isolated context.</summary>
public sealed class AuditPackagingTests : IDisposable
{
    private readonly string _temp = Path.Combine(Path.GetTempPath(), "vc-audit-pack", Guid.NewGuid().ToString("N"));

    private static (string PluginDir, string HostDir) OutputDirectories()
    {
        var testBin = AppContext.BaseDirectory.TrimEnd(Path.DirectorySeparatorChar);
        var tfm = Path.GetFileName(testBin);
        var configuration = Path.GetFileName(Path.GetDirectoryName(testBin)!);
        var repoRoot = Path.GetFullPath(Path.Combine(testBin, "..", "..", "..", "..", ".."));
        var pluginDir = Path.Combine(repoRoot, "src", "Vulpes.Plugins.Microsoft-365-Audit", "bin", configuration, tfm);
        var hostDir = Path.Combine(repoRoot, "..", "vulpes", "src", "Vulpes.Host", "bin", configuration, tfm);
        Assert.True(File.Exists(Path.Combine(pluginDir, "plugin.json")), $"plugin output not found at {pluginDir}");
        Assert.True(File.Exists(Path.Combine(hostDir, "Vulpes.Host.dll")), $"host output not found at {hostDir}");
        return (pluginDir, hostDir);
    }

    [Fact]
    public async Task Audit_plugin_round_trips_through_packer_installer_and_loader()
    {
        Directory.CreateDirectory(_temp);
        var (pluginDir, hostDir) = OutputDirectories();
        var result = PluginPackager.Pack(new PackOptions
        {
            PluginDirectory = pluginDir,
            OutputPath = Path.Combine(_temp, "dist", "audit.7z"),
            HostDirectory = hostDir, // everything the real host ships is stripped; plugin-private deps (Azure.Identity) stay
        });

        Assert.Equal("microsoft-365-audit", result.PluginId);
        Assert.Contains("Vulpes.Sdk.dll", result.Stripped);
        Assert.Contains("Microsoft.EntityFrameworkCore.dll", result.Stripped);
        Assert.DoesNotContain("Vulpes.Plugins.Microsoft-365-Audit.dll", result.Stripped);
        Assert.DoesNotContain("Azure.Identity.dll", result.Stripped);
        Assert.True(new FileInfo(result.OutputPath).Length < 20 * 1024 * 1024, "package should stay small once host-shared assemblies are stripped");

        var options = new PluginOptions { Directory = Path.Combine(_temp, "plugins") };
        var pins = new PluginAssemblyPinStore(Path.Combine(_temp, "pins.db"));
        pins.EnsureSchema();
        var installer = new PluginPackageInstaller(options, options.Directory!, NullLogger<PluginPackageInstaller>.Instance, pins);
        var record = await installer.InstallAsync(result.OutputPath, "test", "tester", ManifestFor(result.OutputPath, result.Version), CancellationToken.None);
        Assert.Equal("microsoft-365-audit", record.Id);

        var catalog = PluginLoader.LoadAll(options.Directory!, new ConfigurationBuilder().Build(), installer, pins, NullLogger.Instance);
        Assert.Empty(catalog.Failures);
        var plugin = Assert.Single(catalog.Plugins);
        Assert.Equal(9, plugin.Manifest.Nav.Count);
        Assert.True(File.Exists(Path.Combine(plugin.Context.WebRoot, "pages", "overview.html")));
        Assert.True(File.Exists(Path.Combine(plugin.Context.WebRoot, "js", "common.js")));

        // Host-provided services the plugin depends on.
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddHttpClient();
        services.AddSingleton(TimeProvider.System);
        services.AddSingleton<ISecretProtector>(new FakeProtector());
        services.AddSingleton<IEventPipeline>(new FakePipeline());
        plugin.Instance.ConfigureServices(services, plugin.Context);
        await using var provider = services.BuildServiceProvider();
        await plugin.Instance.InitializeAsync(provider, plugin.Context, CancellationToken.None);
        Assert.True(File.Exists(plugin.Context.DatabasePath));

        // The plugin's schema contributor and collectors are resolvable through the shared SDK types.
        var schema = Assert.Single(provider.GetServices<IIndexSchemaContributor>());
        Assert.Equal("microsoft-365-audit", schema.PluginId);
        Assert.Contains(schema.Sources, s => s.Source == "signins");
        // Plugin-private types live in the plugin's own load context, so compare by name rather than by Type identity.
        Assert.Equal(8, services.Count(d => d.ServiceType.Name == nameof(ICollector)));

        // Endpoints map without throwing on a real route builder.
        var app = WebApplication.CreateBuilder().Build();
        plugin.Instance.MapEndpoints(app.MapGroup("/api/plugins/microsoft-365-audit"), plugin.Context);
    }

    private static ReleaseManifest ManifestFor(string packagePath, string version)
    {
        var key = new byte[32];
        using var algorithm = new HMACSHA512(key);
        using var stream = File.OpenRead(packagePath);
        var hmac = Convert.ToHexStringLower(algorithm.ComputeHash(stream));
        var body = new StringBuilder()
            .Append("hmac_key:").Append(Convert.ToHexString(key).ToLowerInvariant()).Append('\n')
            .Append(Path.GetFileName(packagePath)).Append(':').Append(hmac).Append(':').Append(version).Append('\n');
        return ReleaseManifest.Parse(body.ToString());
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
