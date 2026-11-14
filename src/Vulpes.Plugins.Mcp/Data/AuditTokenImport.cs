using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;

namespace Vulpes.Plugins.Mcp.Data;

/// <summary>
/// Copies bearer tokens out of the Microsoft 365 Audit database the first time this plugin's table is empty.
/// The audit plugin no longer issues tokens. The rows there are left in place.
/// </summary>
internal static class AuditTokenImport
{
    internal static async Task<int> CopyIfEmptyAsync(McpDbContext db, string dataDirectory, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(db);
        if (await db.BotTokens.AnyAsync(cancellationToken))
        {
            return 0;
        }

        var root = Directory.GetParent(dataDirectory)?.FullName;
        if (string.IsNullOrEmpty(root))
        {
            return 0;
        }

        var path = Path.Combine(root, "microsoft-365-audit", "microsoft-365-audit.db");
        if (!File.Exists(path))
        {
            return 0;
        }

        List<BotToken> rows;
        try
        {
            rows = Read(path);
        }
        catch (SqliteException)
        {
            return 0;
        }

        if (rows.Count == 0)
        {
            return 0;
        }

        db.BotTokens.AddRange(rows);
        await db.SaveChangesAsync(cancellationToken);
        return rows.Count;
    }

    private static List<BotToken> Read(string path)
    {
        var rows = new List<BotToken>();
        using var connection = new SqliteConnection($"Data Source={path};Mode=ReadOnly");
        connection.Open();
        using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT Id, Name, TokenHash, Prefix, CreatedAt, ExpiresAt, LastUsedAt, RevokedAt
            FROM BotTokens
            """;
        using var reader = command.ExecuteReader();
        while (reader.Read())
        {
            var name = reader.GetString(1);
            var hash = reader.GetString(2);
            var prefix = reader.GetString(3);
            if (name.Length is < 1 or > 80 || hash.Length is < 1 or > 64 || prefix.Length is < 1 or > 16)
            {
                continue;
            }

            if (!Guid.TryParse(reader.GetString(0), out var id))
            {
                continue;
            }

            rows.Add(new BotToken
            {
                Id = id,
                Name = name,
                TokenHash = hash,
                Prefix = prefix,
                CreatedAt = Tick(reader, 4) ?? DateTimeOffset.UnixEpoch,
                ExpiresAt = Tick(reader, 5),
                LastUsedAt = Tick(reader, 6),
                RevokedAt = Tick(reader, 7),
            });
        }

        return rows;
    }

    private static DateTimeOffset? Tick(SqliteDataReader reader, int ordinal)
    {
        if (reader.IsDBNull(ordinal))
        {
            return null;
        }

        return new DateTimeOffset(reader.GetInt64(ordinal), TimeSpan.Zero);
    }
}
