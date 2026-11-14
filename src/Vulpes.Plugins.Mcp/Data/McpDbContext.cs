using System.ComponentModel.DataAnnotations;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;
using Microsoft.EntityFrameworkCore.Storage.ValueConversion;

namespace Vulpes.Plugins.Mcp.Data;

/// <summary>A bearer token for a machine client such as Grok Bot. Only the hash is stored.</summary>
public sealed class BotToken
{
    public Guid Id { get; set; }

    [MaxLength(80)]
    public required string Name { get; set; }

    [MaxLength(64)]
    public required string TokenHash { get; set; }

    [MaxLength(16)]
    public required string Prefix { get; set; }

    public DateTimeOffset CreatedAt { get; set; }

    public DateTimeOffset? ExpiresAt { get; set; }

    public DateTimeOffset? LastUsedAt { get; set; }

    public DateTimeOffset? RevokedAt { get; set; }

    /// <summary>When the 10-day expiry notice was sent. Null until that mail succeeds.</summary>
    public DateTimeOffset? ExpiryNoticeSentAt { get; set; }

    /// <summary>Random salt mixed into this token's user data key. The key itself is not stored.</summary>
    public byte[]? UserDataKeySalt { get; set; }
}

public sealed class McpDbContext(DbContextOptions<McpDbContext> options) : DbContext(options)
{
    public DbSet<BotToken> BotTokens => Set<BotToken>();

    protected override void ConfigureConventions(ModelConfigurationBuilder configurationBuilder)
    {
        configurationBuilder.Properties<DateTimeOffset>().HaveConversion<UtcTicksConverter>();
    }

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<BotToken>(e =>
        {
            e.HasKey(t => t.Id);
            e.HasIndex(t => t.TokenHash).IsUnique();
        });
    }
}

public sealed class UtcTicksConverter() : ValueConverter<DateTimeOffset, long>(v => v.UtcTicks, v => new DateTimeOffset(v, TimeSpan.Zero));

public sealed class McpDbContextDesignTimeFactory : IDesignTimeDbContextFactory<McpDbContext>
{
    public McpDbContext CreateDbContext(string[] args) =>
        new(new DbContextOptionsBuilder<McpDbContext>().UseSqlite("Data Source=design-time-mcp.db").Options);
}
