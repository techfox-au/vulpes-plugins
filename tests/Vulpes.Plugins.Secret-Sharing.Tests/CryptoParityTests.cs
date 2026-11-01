using Xunit;

namespace Vulpes.Plugins.SecretSharing.Tests;

public sealed class CryptoParityTests
{
    [Fact]
    public void Payload_crypto_matches_sendit_except_the_params_url_and_iteration_lock()
    {
        var pluginPath = Find("vulpes-plugins/src/Vulpes.Plugins.Secret-Sharing/wwwroot/public/crypto.js");
        var senditPath = Find("sendit/src/frontend/js/crypto.js");
        var plugin = File.ReadAllText(pluginPath);
        Assert.Contains("/api/plugins/secret-sharing/crypto/params", plugin, StringComparison.Ordinal);
        Assert.Contains("if (iterations !== 893241) throw new Error(\"Unsupported wrap parameters.\");", plugin, StringComparison.Ordinal);

        var reverted = plugin
            .Replace("/api/plugins/secret-sharing/crypto/params", "/api/v1/crypto/params", StringComparison.Ordinal)
            .Replace(
                "    const iterations = typeof pkg.i === \"number\" && pkg.i > 0 ? pkg.i : PW_WRAP_ITERATIONS;\n    if (iterations !== 893241) throw new Error(\"Unsupported wrap parameters.\");",
                "    const iterations =\n      typeof pkg.i === \"number\" && pkg.i > 0 ? pkg.i : PW_WRAP_ITERATIONS;",
                StringComparison.Ordinal);
        Assert.Equal(File.ReadAllText(senditPath), reverted);
    }

    [Fact]
    public void TweetNaCl_and_the_user_data_key_script_are_shared_bytes()
    {
        Assert.Equal(
            File.ReadAllBytes(Find("sendit/src/frontend/vendor/nacl-fast.js")),
            File.ReadAllBytes(Find("vulpes-plugins/src/Vulpes.Plugins.Secret-Sharing/wwwroot/public/nacl-fast.js")));
        Assert.Equal(
            File.ReadAllBytes(Find("vulpes/src/Vulpes.Host/wwwroot/assets/js/udk.js")),
            File.ReadAllBytes(Find("vulpes-plugins/src/Vulpes.Plugins.Secret-Sharing/wwwroot/public/udk.js")));
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
}
