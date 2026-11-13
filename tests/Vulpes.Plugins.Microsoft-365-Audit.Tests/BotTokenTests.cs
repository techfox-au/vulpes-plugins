using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;
using Vulpes.Plugins.Microsoft365Audit.Data;
using Vulpes.Plugins.Microsoft365Audit.Endpoints;
using Vulpes.Sdk;
using Xunit;

namespace Vulpes.Plugins.Microsoft365Audit.Tests;

public sealed class BotTokenTests
{
    [Fact]
    public async Task A_bot_token_is_stored_as_a_hash()
    {
        var path = Path.Combine(Path.GetTempPath(), "vulpes-audit-bot-" + Guid.NewGuid().ToString("N") + ".db");
        var options = new DbContextOptionsBuilder<AuditDbContext>().UseSqlite($"Data Source={path}").Options;
        try
        {
            await using var db = new AuditDbContext(options);
            await db.Database.MigrateAsync();
            var secret = AuditMcp.CreateSecret();
            Assert.StartsWith("vba_", secret, StringComparison.Ordinal);
            Assert.NotEqual(secret, AuditMcp.Hash(secret));
            db.BotTokens.Add(new BotToken
            {
                Id = Guid.NewGuid(),
                Name = "Grok Bot",
                Prefix = secret[..12],
                TokenHash = AuditMcp.Hash(secret),
                CreatedAt = DateTimeOffset.UtcNow,
            });
            await db.SaveChangesAsync();
            var found = await db.BotTokens.SingleAsync(t => t.TokenHash == AuditMcp.Hash(secret));
            Assert.Equal("Grok Bot", found.Name);
            Assert.Equal(secret[..12], found.Prefix);
        }
        finally
        {
            try { File.Delete(path); } catch (IOException) { }
        }
    }

    [Fact]
    public async Task Deleting_a_bot_removes_the_row_and_the_key()
    {
        var path = Path.Combine(Path.GetTempPath(), "vulpes-audit-bot-" + Guid.NewGuid().ToString("N") + ".db");
        var options = new DbContextOptionsBuilder<AuditDbContext>().UseSqlite($"Data Source={path}").Options;
        try
        {
            await using var db = new AuditDbContext(options);
            await db.Database.MigrateAsync();
            var secret = AuditMcp.CreateSecret();
            var id = Guid.NewGuid();
            db.BotTokens.Add(new BotToken
            {
                Id = id,
                Name = "Grok Bot",
                Prefix = secret[..12],
                TokenHash = AuditMcp.Hash(secret),
                CreatedAt = DateTimeOffset.UtcNow,
                RevokedAt = DateTimeOffset.UtcNow,
            });
            await db.SaveChangesAsync();
            var audit = new MemoryAudit();

            var missing = await AuditEndpoints.DeleteBotTokenAsync(Guid.NewGuid(), db, audit, CancellationToken.None);
            Assert.Equal(404, (missing as IStatusCodeHttpResult)?.StatusCode);

            var deleted = await AuditEndpoints.DeleteBotTokenAsync(id, db, audit, CancellationToken.None);
            Assert.Equal(204, (deleted as IStatusCodeHttpResult)?.StatusCode);
            Assert.Empty(await db.BotTokens.ToListAsync());
            Assert.Equal("audit.bot_token.deleted", audit.Entries[0].Action);
            Assert.Contains(secret[..12], audit.Entries[0].Details, StringComparison.Ordinal);
        }
        finally
        {
            try { File.Delete(path); } catch (IOException) { }
        }
    }

    private sealed class MemoryAudit : IHostAuditLog
    {
        public List<(string Action, string? Target, string? Details)> Entries { get; } = [];

        public Task RecordAsync(string action, string? target, string? details, string? actor = null, CancellationToken cancellationToken = default)
        {
            Entries.Add((action, target, details));
            return Task.CompletedTask;
        }
    }
}
