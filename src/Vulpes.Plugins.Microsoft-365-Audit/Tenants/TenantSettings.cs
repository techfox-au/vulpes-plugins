using System.Text.Json;
using System.Text.Json.Serialization;

namespace Vulpes.Plugins.Microsoft365Audit.Tenants;

/// <summary>Per-source overrides stored in <see cref="Data.Tenant.SettingsJson"/>.</summary>
public sealed class SourceSettings
{
    public bool Enabled { get; set; } = true;

    /// <summary>Overrides the module default interval.</summary>
    public int? IntervalMinutes { get; set; }

    /// <summary>Sign-ins only: also pull non-interactive, service-principal and managed-identity sign-ins (beta endpoint).</summary>
    public bool IncludeNonInteractive { get; set; } = true;

    /// <summary>Purview only: record types to query; null uses the module default.</summary>
    public List<string>? RecordTypes { get; set; }
}

public sealed class TenantSettings
{
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web) { DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull };

    public Dictionary<string, SourceSettings> Sources { get; set; } = new(StringComparer.Ordinal);

    public SourceSettings For(string source) => Sources.TryGetValue(source, out var s) ? s : new SourceSettings();

    public static TenantSettings Parse(string? json)
    {
        if (string.IsNullOrWhiteSpace(json))
        {
            return new TenantSettings();
        }

        try
        {
            return JsonSerializer.Deserialize<TenantSettings>(json, Json) ?? new TenantSettings();
        }
        catch (JsonException)
        {
            return new TenantSettings();
        }
    }

    public string Serialize() => JsonSerializer.Serialize(this, Json);
}
