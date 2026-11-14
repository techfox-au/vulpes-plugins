using System.Security.Cryptography;
using System.Text;
using Microsoft.EntityFrameworkCore;
using Vulpes.Plugins.Mcp.Data;

namespace Vulpes.Plugins.Mcp.Endpoints;

internal static class BotUdk
{
    private static readonly byte[] Info = Encoding.ASCII.GetBytes("vulpes-mcp-bot-udk-v1");

    internal static async Task<byte[]> ForAsync(McpDbContext db, BotToken row, string token, CancellationToken cancellationToken)
    {
        if (row.UserDataKeySalt is not { Length: 32 })
        {
            row.UserDataKeySalt = RandomNumberGenerator.GetBytes(32);
            await db.SaveChangesAsync(cancellationToken);
            await db.Entry(row).ReloadAsync(cancellationToken);
        }

        var salt = row.UserDataKeySalt!;
        var ikm = Encoding.UTF8.GetBytes(token);
        try
        {
            return HKDF.DeriveKey(HashAlgorithmName.SHA256, ikm, 32, salt, Info);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(ikm);
        }
    }
}
