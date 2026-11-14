using System.Security.Cryptography;
using System.Text;

namespace Vulpes.Plugins.Mcp.Endpoints;

internal static class McpTokens
{
    internal static readonly TimeSpan Lifetime = TimeSpan.FromDays(90);

    internal const int ActiveLimit = 10;

    internal static string CreateSecret() => "vba_" + Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(24));

    internal static string Hash(string token) => Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(token)));
}
