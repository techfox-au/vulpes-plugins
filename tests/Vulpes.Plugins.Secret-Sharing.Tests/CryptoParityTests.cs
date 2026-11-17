using Xunit;

namespace Vulpes.Plugins.SecretSharing.Tests;

public sealed class CryptoParityTests
{
    [Fact]
    public void The_plugin_uses_the_host_crypto_and_does_not_ship_a_copy()
    {
        Assert.False(Exists("vulpes-plugins/src/Vulpes.Plugins.Secret-Sharing/wwwroot/public/crypto.js"));
        Assert.False(Exists("vulpes-plugins/src/Vulpes.Plugins.Secret-Sharing/wwwroot/public/nacl-fast.js"));
        Assert.Equal(
            File.ReadAllBytes(Find("vulpes/src/Vulpes.Host/wwwroot/assets/js/udk.js")),
            File.ReadAllBytes(Find("vulpes-plugins/src/Vulpes.Plugins.Secret-Sharing/wwwroot/public/udk.js")));
        Assert.True(Exists("vulpes/src/Vulpes.Host/wwwroot/assets/js/crypto/crypto.js"));
        Assert.True(Exists("vulpes/src/Vulpes.Host/wwwroot/assets/js/crypto/nacl-fast.js"));
    }

    [Fact]
    public void The_host_proof_of_work_search_is_still_HMAC_SHA256()
    {
        var engine = File.ReadAllText(Find("vulpes/src/Vulpes.Host/wwwroot/assets/js/pow-engine.js"));
        Assert.Contains("HMAC-SHA256(key, ASCII decimal nonce)", engine, StringComparison.Ordinal);
        Assert.DoesNotContain("SHA-1", engine, StringComparison.Ordinal);
    }

    private static string Find(string relative)
    {
        var slash = relative.IndexOf('/', StringComparison.Ordinal);
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null)
        {
            var direct = Path.Combine(dir.FullName, relative);
            if (File.Exists(direct))
            {
                return direct;
            }

            if (slash > 0 && dir.Name.Equals(relative[..slash], StringComparison.Ordinal))
            {
                var nested = Path.Combine(dir.FullName, relative[(slash + 1)..]);
                if (File.Exists(nested))
                {
                    return nested;
                }
            }

            dir = dir.Parent;
        }

        throw new FileNotFoundException("Could not find " + relative + " by walking up from the test output.");
    }

    private static bool Exists(string relative) 
    {
        try
        {
            Find(relative);
            return true;
        }
        catch (FileNotFoundException)
        {
            return false;
        }
    }
}
