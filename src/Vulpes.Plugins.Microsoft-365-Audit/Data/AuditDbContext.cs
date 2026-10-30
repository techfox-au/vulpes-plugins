using System.ComponentModel.DataAnnotations;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;
using Microsoft.EntityFrameworkCore.Storage.ValueConversion;

namespace Vulpes.Plugins.Microsoft365Audit.Data;

public static class Clouds
{
    public const string Global = "Global";
    public const string UsGov = "USGov";
    public static readonly IReadOnlyList<string> All = [Global, UsGov];
}

public static class CredentialTypes
{
    public const string Secret = "secret";
    public const string Certificate = "certificate";
}

public sealed class Tenant
{
    public Guid Id { get; set; }

    [MaxLength(120)]
    public required string DisplayName { get; set; }

    /// <summary>Entra tenant (directory) id.</summary>
    [MaxLength(64)]
    public required string TenantId { get; set; }

    [MaxLength(64)]
    public required string ClientId { get; set; }

    [MaxLength(16)]
    public string CredentialType { get; set; } = CredentialTypes.Secret;

    /// <summary>Client secret, encrypted with the host master key.</summary>
    public string? ProtectedSecret { get; set; }

    /// <summary>PFX (base64) encrypted with the host master key.</summary>
    public string? ProtectedCertificate { get; set; }

    public string? ProtectedCertificatePassword { get; set; }

    [MaxLength(16)]
    public string Cloud { get; set; } = Clouds.Global;

    public bool Enabled { get; set; } = true;

    public int LookbackDays { get; set; } = 7;

    /// <summary>JSON: per-source settings (enabled, interval, record types, non-interactive sign-ins).</summary>
    public string SettingsJson { get; set; } = "{}";

    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;

    public DateTimeOffset UpdatedAt { get; set; } = DateTimeOffset.UtcNow;

    [MaxLength(256)]
    public string? CreatedBy { get; set; }

    public DateTimeOffset? LastTestAt { get; set; }

    public string? LastTestResultJson { get; set; }

    /// <summary>Organisation display name discovered during the last successful connection test.</summary>
    [MaxLength(256)]
    public string? DiscoveredName { get; set; }
}

public static class RunStatuses
{
    public const string Idle = "idle";
    public const string Running = "running";
    public const string Succeeded = "succeeded";
    public const string Failed = "failed";
    public const string Pending = "pending";
}

public sealed class Checkpoint
{
    public Guid TenantId { get; set; }

    [MaxLength(32)]
    public required string Source { get; set; }

    public DateTimeOffset? Watermark { get; set; }

    /// <summary>Collector-specific state (e.g. an in-flight Purview query id).</summary>
    public string? StateJson { get; set; }

    public DateTimeOffset? LastRunAt { get; set; }

    public DateTimeOffset? LastSuccessAt { get; set; }

    [MaxLength(16)]
    public string LastStatus { get; set; } = RunStatuses.Idle;

    [MaxLength(2000)]
    public string? LastError { get; set; }

    public int LastCount { get; set; }

    public long TotalCount { get; set; }

    public DateTimeOffset? NextRunAt { get; set; }

    public int ConsecutiveFailures { get; set; }
}

public sealed class RunLogEntry
{
    public long Id { get; set; }
    public Guid TenantId { get; set; }

    [MaxLength(32)]
    public required string Source { get; set; }

    public DateTimeOffset StartedAt { get; set; }
    public DateTimeOffset? FinishedAt { get; set; }

    [MaxLength(16)]
    public string Status { get; set; } = RunStatuses.Running;

    public int Count { get; set; }
    public int Duplicates { get; set; }
    public int Failed { get; set; }
    public int Alerts { get; set; }

    [MaxLength(2000)]
    public string? Error { get; set; }
}

public sealed class AuditDbContext(DbContextOptions<AuditDbContext> options) : DbContext(options)
{
    public DbSet<Tenant> Tenants => Set<Tenant>();
    public DbSet<Checkpoint> Checkpoints => Set<Checkpoint>();
    public DbSet<RunLogEntry> RunLog => Set<RunLogEntry>();

    protected override void ConfigureConventions(ModelConfigurationBuilder configurationBuilder)
    {
        configurationBuilder.Properties<DateTimeOffset>().HaveConversion<UtcTicksConverter>();
    }

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<Tenant>(e =>
        {
            e.HasKey(t => t.Id);
            e.HasIndex(t => t.TenantId);
        });
        modelBuilder.Entity<Checkpoint>(e =>
        {
            e.HasKey(c => new { c.TenantId, c.Source });
            e.HasOne<Tenant>().WithMany().HasForeignKey(c => c.TenantId).OnDelete(DeleteBehavior.Cascade);
        });
        modelBuilder.Entity<RunLogEntry>(e =>
        {
            e.HasKey(r => r.Id);
            e.HasIndex(r => r.StartedAt);
            e.HasOne<Tenant>().WithMany().HasForeignKey(r => r.TenantId).OnDelete(DeleteBehavior.Cascade);
        });
    }
}

public sealed class UtcTicksConverter() : ValueConverter<DateTimeOffset, long>(v => v.UtcTicks, v => new DateTimeOffset(v, TimeSpan.Zero));

public sealed class AuditDbContextDesignTimeFactory : IDesignTimeDbContextFactory<AuditDbContext>
{
    public AuditDbContext CreateDbContext(string[] args) =>
        new(new DbContextOptionsBuilder<AuditDbContext>().UseSqlite("Data Source=design-time-audit.db").Options);
}
