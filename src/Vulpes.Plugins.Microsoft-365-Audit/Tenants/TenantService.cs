using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Vulpes.Plugins.Microsoft365Audit.Collectors;
using Vulpes.Plugins.Microsoft365Audit.Data;
using Vulpes.Plugins.Microsoft365Audit.Graph;
using Vulpes.Sdk;

namespace Vulpes.Plugins.Microsoft365Audit.Tenants;

public sealed record TenantInput(
    string? DisplayName,
    string? TenantId,
    string? ClientId,
    string? CredentialType,
    string? ClientSecret,
    string? CertificatePfxBase64,
    string? CertificatePassword,
    string? Cloud,
    bool? Enabled,
    int? LookbackDays,
    TenantSettings? Settings);

public sealed record ProbeResult(string Source, string Title, string Status, string? Detail);

public sealed record ConnectionTestResult(bool TokenAcquired, string? OrganizationName, string? Error, IReadOnlyList<ProbeResult> Probes, DateTimeOffset TestedAt);

/// <summary>Tenant CRUD with encrypted credentials and connection/permission probing.</summary>
public sealed class TenantService(AuditDbContext db, ISecretProtector protector, GraphClientFactory graphFactory, IEnumerable<ICollector> collectors, TimeProvider timeProvider, AuditOptions options, ILogger<TenantService> logger)
{
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);

    public Task<List<Tenant>> ListAsync(CancellationToken ct) => db.Tenants.AsNoTracking().OrderBy(t => t.DisplayName).ToListAsync(ct);

    public Task<Tenant?> FindAsync(Guid id, CancellationToken ct) => db.Tenants.FirstOrDefaultAsync(t => t.Id == id, ct);

    public async Task<(Tenant? Tenant, string? Error)> CreateAsync(TenantInput input, string? createdBy, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(input);
        var tenant = new Tenant { Id = Guid.NewGuid(), DisplayName = string.Empty, TenantId = string.Empty, ClientId = string.Empty, CreatedBy = createdBy, CreatedAt = timeProvider.GetUtcNow(), LookbackDays = Math.Clamp(options.DefaultLookbackDays, 1, 180) };
        var error = Apply(tenant, input, isNew: true);
        if (error is not null)
        {
            return (null, error);
        }

        db.Tenants.Add(tenant);
        await db.SaveChangesAsync(ct);
        return (tenant, null);
    }

    public async Task<(Tenant? Tenant, string? Error)> UpdateAsync(Guid id, TenantInput input, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(input);
        var tenant = await FindAsync(id, ct);
        if (tenant is null)
        {
            return (null, "Tenant not found.");
        }

        var error = Apply(tenant, input, isNew: false);
        if (error is not null)
        {
            return (null, error);
        }

        tenant.UpdatedAt = timeProvider.GetUtcNow();
        await db.SaveChangesAsync(ct);
        return (tenant, null);
    }

    /// <summary>Mirrors the host tenant directory onto local rows so collectors and checkpoints keep their ids. Credentials come from the shared application.</summary>
    public async Task SyncFromDirectoryAsync(IReadOnlyList<ManagedTenant> tenants, EntraApplicationCredential? application, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(tenants);
        var wanted = tenants.Select(t => t.Id).ToHashSet();
        var local = await db.Tenants.ToListAsync(ct);
        foreach (var gone in local.Where(t => !wanted.Contains(t.Id)).ToList())
        {
            db.Tenants.Remove(gone);
        }

        foreach (var remote in tenants)
        {
            var row = local.FirstOrDefault(t => t.Id == remote.Id);
            if (row is null)
            {
                row = new Tenant
                {
                    Id = remote.Id,
                    DisplayName = remote.DisplayName,
                    TenantId = remote.DirectoryId,
                    ClientId = application?.ClientId ?? remote.DirectoryId,
                    CreatedAt = timeProvider.GetUtcNow(),
                    LookbackDays = Math.Clamp(options.DefaultLookbackDays, 1, 180),
                };
                db.Tenants.Add(row);
            }

            row.DisplayName = remote.DisplayName;
            row.TenantId = remote.DirectoryId;
            row.Enabled = remote.Enabled;
            if (!string.IsNullOrWhiteSpace(remote.DiscoveredName))
            {
                row.DiscoveredName = remote.DiscoveredName;
            }

            if (application is not null)
            {
                row.ClientId = application.ClientId;
                row.CredentialType = application.CredentialType;
                row.Cloud = application.Cloud;
                if (!string.IsNullOrEmpty(application.Secret))
                {
                    row.ProtectedSecret = protector.Protect(application.Secret);
                }

                if (!string.IsNullOrEmpty(application.CertificatePfxBase64))
                {
                    row.ProtectedCertificate = protector.Protect(application.CertificatePfxBase64);
                    row.ProtectedCertificatePassword = string.IsNullOrEmpty(application.CertificatePassword) ? null : protector.Protect(application.CertificatePassword);
                }
            }

            row.UpdatedAt = timeProvider.GetUtcNow();
        }

        await db.SaveChangesAsync(ct);
    }

    public async Task<string?> UpdateCollectionAsync(Guid id, int? lookbackDays, TenantSettings? settings, CancellationToken ct)
    {
        var tenant = await FindAsync(id, ct);
        if (tenant is null)
        {
            return "Tenant not found.";
        }

        if (lookbackDays is { } lookback && lookback is < 1 or > 180)
        {
            return "Lookback must be between 1 and 180 days.";
        }

        if (lookbackDays is { } days)
        {
            tenant.LookbackDays = days;
        }

        if (settings is not null)
        {
            var error = ValidateSettings(settings);
            if (error is not null)
            {
                return error;
            }

            tenant.SettingsJson = settings.Serialize();
        }

        tenant.UpdatedAt = timeProvider.GetUtcNow();
        await db.SaveChangesAsync(ct);
        return null;
    }

    public async Task<bool> DeleteAsync(Guid id, CancellationToken ct)
    {
        var tenant = await FindAsync(id, ct);
        if (tenant is null)
        {
            return false;
        }

        db.Tenants.Remove(tenant);
        await db.SaveChangesAsync(ct);
        return true;
    }

    private string? ValidateSettings(TenantSettings settings)
    {
        foreach (var (source, s) in settings.Sources)
        {
            if (!collectors.Any(c => c.Source == source))
            {
                return $"Unknown source '{source}' in settings.";
            }

            if (s.IntervalMinutes is { } m && m is < 1 or > 10080)
            {
                return "Intervals must be between 1 minute and 7 days.";
            }

            if (s.RecordTypes is { Count: > 100 } || s.RecordTypes?.Any(r => r.Length > 64 || !r.All(char.IsAsciiLetterOrDigit)) == true)
            {
                return "Record types must be alphanumeric names (max 100).";
            }
        }

        return null;
    }

    /// <summary>Validates and copies the input onto the entity, encrypting secrets. Blank secrets keep the stored value.</summary>
    private string? Apply(Tenant tenant, TenantInput input, bool isNew)
    {
        if (string.IsNullOrWhiteSpace(input.DisplayName) || input.DisplayName.Trim().Length > 120)
        {
            return "Display name is required (max 120 characters).";
        }

        if (!Guid.TryParse(input.TenantId, out var tenantGuid))
        {
            return "Tenant id must be the directory (tenant) GUID.";
        }

        if (!Guid.TryParse(input.ClientId, out var clientGuid))
        {
            return "Client id must be the application (client) GUID.";
        }

        var cloud = input.Cloud ?? Clouds.Global;
        if (!Clouds.All.Contains(cloud, StringComparer.Ordinal))
        {
            return "Cloud must be Global or USGov.";
        }

        var credentialType = input.CredentialType ?? tenant.CredentialType;
        if (credentialType is not (CredentialTypes.Secret or CredentialTypes.Certificate))
        {
            return "Credential type must be 'secret' or 'certificate'.";
        }

        if (credentialType == CredentialTypes.Secret)
        {
            if (!string.IsNullOrEmpty(input.ClientSecret))
            {
                if (input.ClientSecret.Length > 1024)
                {
                    return "Client secret is too long.";
                }

                tenant.ProtectedSecret = protector.Protect(input.ClientSecret);
            }
            else if (isNew || tenant.ProtectedSecret is null)
            {
                return "A client secret is required.";
            }
        }
        else
        {
            if (!string.IsNullOrEmpty(input.CertificatePfxBase64))
            {
                byte[] pfx;
                try
                {
                    pfx = Convert.FromBase64String(input.CertificatePfxBase64);
                    if (pfx.Length > 64 * 1024)
                    {
                        return "Certificate file is too large.";
                    }

                    using var certificate = X509CertificateLoader.LoadPkcs12(pfx, input.CertificatePassword, X509KeyStorageFlags.DefaultKeySet);
                    if (!certificate.HasPrivateKey)
                    {
                        return "The PFX does not contain a private key.";
                    }
                }
                catch (FormatException)
                {
                    return "Certificate must be a base64-encoded PFX.";
                }
                catch (System.Security.Cryptography.CryptographicException ex)
                {
                    return "Certificate could not be loaded: " + ex.Message;
                }

                tenant.ProtectedCertificate = protector.Protect(Convert.ToBase64String(pfx));
                tenant.ProtectedCertificatePassword = string.IsNullOrEmpty(input.CertificatePassword) ? null : protector.Protect(input.CertificatePassword);
            }
            else if (isNew || tenant.ProtectedCertificate is null)
            {
                return "A certificate (PFX) is required.";
            }
        }

        if (input.LookbackDays is { } lookback && lookback is < 1 or > 180)
        {
            return "Lookback must be between 1 and 180 days.";
        }

        if (input.Settings is { } settings)
        {
            var settingsError = ValidateSettings(settings);
            if (settingsError is not null)
            {
                return settingsError;
            }

            tenant.SettingsJson = settings.Serialize();
        }

        tenant.DisplayName = input.DisplayName.Trim();
        tenant.TenantId = tenantGuid.ToString("D");
        tenant.ClientId = clientGuid.ToString("D");
        tenant.CredentialType = credentialType;
        tenant.Cloud = cloud;
        tenant.Enabled = input.Enabled ?? tenant.Enabled;
        tenant.LookbackDays = input.LookbackDays ?? tenant.LookbackDays;
        if (credentialType == CredentialTypes.Secret)
        {
            tenant.ProtectedCertificate = null;
            tenant.ProtectedCertificatePassword = null;
        }
        else
        {
            tenant.ProtectedSecret = null;
        }

        return null;
    }

    /// <summary>Acquires a token, reads the organisation name and probes each collector's endpoint for permissions.</summary>
    public async Task<ConnectionTestResult> TestConnectionAsync(Tenant tenant, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(tenant);
        var probes = new List<ProbeResult>();
        var testedAt = timeProvider.GetUtcNow();
        GraphClient graph;
        string? organization = null;
        try
        {
            graph = graphFactory.Create(tenant);
            using var org = await graph.GetAsync("organization?$select=id,displayName", ct);
            if (org.RootElement.TryGetProperty("value", out var value) && value.ValueKind == JsonValueKind.Array && value.GetArrayLength() > 0)
            {
                organization = value[0].Str("displayName");
            }
        }
        catch (Exception ex) when (ex is GraphException or Azure.Identity.AuthenticationFailedException or Azure.RequestFailedException or InvalidOperationException or HttpRequestException or System.Security.Cryptography.CryptographicException or FormatException)
        {
            logger.LogWarning(ex, "Connection test failed for tenant {Tenant}", tenant.DisplayName);
            var failed = new ConnectionTestResult(false, null, Sanitize(ex.Message), probes, testedAt);
            await StoreTestResultAsync(tenant, failed, ct);
            return failed;
        }

        foreach (var collector in collectors.OrderBy(c => c.Source, StringComparer.Ordinal))
        {
            if (string.IsNullOrEmpty(collector.ProbePath))
            {
                continue;
            }

            if (!options.Collects(collector.Source))
            {
                probes.Add(new ProbeResult(collector.Source, collector.Title, "skipped", "Not included with Microsoft 365 Business Premium."));
                continue;
            }

            try
            {
                using var _ = await graph.GetAsync(collector.ProbePath, ct);
                probes.Add(new ProbeResult(collector.Source, collector.Title, "ok", null));
            }
            catch (GraphException ex) when (ex.IsForbidden)
            {
                probes.Add(new ProbeResult(collector.Source, collector.Title, "forbidden", $"Missing permission ({string.Join(", ", collector.RequiredPermissions)})"));
            }
            catch (GraphException ex)
            {
                probes.Add(new ProbeResult(collector.Source, collector.Title, "error", Sanitize(ex.Message)));
            }
            catch (HttpRequestException ex)
            {
                probes.Add(new ProbeResult(collector.Source, collector.Title, "error", Sanitize(ex.Message)));
            }
        }

        var result = new ConnectionTestResult(true, organization, null, probes, testedAt);
        await StoreTestResultAsync(tenant, result, ct);
        return result;
    }

    private async Task StoreTestResultAsync(Tenant tenant, ConnectionTestResult result, CancellationToken ct)
    {
        var tracked = await db.Tenants.FirstOrDefaultAsync(t => t.Id == tenant.Id, ct);
        if (tracked is null)
        {
            return;
        }

        tracked.LastTestAt = result.TestedAt;
        tracked.LastTestResultJson = JsonSerializer.Serialize(result, Json);
        if (result.OrganizationName is not null)
        {
            tracked.DiscoveredName = result.OrganizationName.Length <= 256 ? result.OrganizationName : result.OrganizationName[..256];
        }

        await db.SaveChangesAsync(ct);
    }

    private static string Sanitize(string message) => message.Length <= 500 ? message : message[..500];

    public static object ToDto(Tenant t, IReadOnlyList<Checkpoint>? checkpoints = null) => new
    {
        id = t.Id,
        displayName = t.DisplayName,
        tenantId = t.TenantId,
        clientId = t.ClientId,
        credentialType = t.CredentialType,
        hasSecret = t.ProtectedSecret is not null,
        hasCertificate = t.ProtectedCertificate is not null,
        cloud = t.Cloud,
        enabled = t.Enabled,
        lookbackDays = t.LookbackDays,
        settings = TenantSettings.Parse(t.SettingsJson),
        createdAt = t.CreatedAt,
        updatedAt = t.UpdatedAt,
        createdBy = t.CreatedBy,
        lastTestAt = t.LastTestAt,
        lastTest = t.LastTestResultJson is null ? null : JsonSerializer.Deserialize<ConnectionTestResult>(t.LastTestResultJson, Json),
        discoveredName = t.DiscoveredName,
        checkpoints = checkpoints?.Select(c => new { c.Source, c.Watermark, c.LastRunAt, c.LastSuccessAt, c.LastStatus, c.LastError, c.LastCount, c.TotalCount, c.NextRunAt, c.ConsecutiveFailures }).ToList(),
    };
}
