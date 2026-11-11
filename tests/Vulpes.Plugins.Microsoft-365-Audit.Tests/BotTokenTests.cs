using Microsoft.EntityFrameworkCore;
using Vulpes.Plugins.Microsoft365Audit.Data;
using Vulpes.Plugins.Microsoft365Audit.Endpoints;
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
}
