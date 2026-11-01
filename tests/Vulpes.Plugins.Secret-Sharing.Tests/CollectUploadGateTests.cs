using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.Extensions.DependencyInjection;
using Vulpes.Plugins.SecretSharing.Data;
using Vulpes.Plugins.SecretSharing.Services;
using Vulpes.Sdk;
using Xunit;

namespace Vulpes.Plugins.SecretSharing.Tests;

public sealed class CollectUploadGateTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "ss-gate-" + Guid.NewGuid().ToString("N"));

    [Fact]
    public async Task An_unproven_upload_keeps_the_small_body_cap_and_a_proof_burns_before_the_body()
    {
        var database = new ShareDatabase(Path.Combine(_dir, "share.db"));
        var pow = new PowService(database, new GatePowPolicy());
        var store = new ShareStore(database);
        var id = store.CreateCollect("owner", new CollectInput(Base64Url.Encode(new byte[32]), null, null, null, true, 60, null, false, false, null));
        var browser = Convert.ToHexString(RandomNumberGenerator.GetBytes(16)).ToLowerInvariant();
        var challenge = pow.Issue("collect", id, clientId: browser);
        var (nonce, hash) = Solve(challenge);

        var unproven = await RunAsync(database, pow, store, id, browser, null, null, null);
        Assert.Equal(PowService.SmallBodyBytes, unproven.MaxRequestBodySize);
        Assert.False(unproven.Consumed);

        var permit = pow.TryValidate("collect", id, challenge.ChallengeId, nonce, hash, browser);
        Assert.Null(permit);
        Assert.Null(pow.TryValidate("collect", id, challenge.ChallengeId, nonce, hash, browser));

        var proven = await RunAsync(database, pow, store, id, browser, challenge.ChallengeId, nonce, hash);
        Assert.Equal(PowService.LargeBodyBytes, proven.MaxRequestBodySize);
        Assert.True(proven.Consumed);
        Assert.NotNull(pow.TryConsume("collect", id, challenge.ChallengeId, nonce, hash, browser));
    }

    public void Dispose() => Directory.Delete(_dir, recursive: true);

    private static async Task<GateResult> RunAsync(ShareDatabase database, PowService pow, ShareStore store, string id, string browser, string? challenge, string? nonce, string? hash)
    {
        var services = new ServiceCollection();
        services.AddSingleton(database);
        services.AddSingleton(pow);
        services.AddSingleton(store);
        var provider = services.BuildServiceProvider();
        var context = new DefaultHttpContext { RequestServices = provider };
        context.Request.Method = HttpMethods.Post;
        context.Request.Path = "/api/plugins/secret-sharing/public/collects/" + id;
        context.Request.Headers.Cookie = PowBrowser.CookieName + "=" + browser;
        if (challenge is not null)
        {
            context.Request.Headers[PowService.HeaderChallenge] = challenge;
            context.Request.Headers[PowService.HeaderNonce] = nonce;
            context.Request.Headers[PowService.HeaderHash] = hash;
        }

        var cap = new BodyCap();
        context.Features.Set<IHttpMaxRequestBodySizeFeature>(cap);
        var builder = new ApplicationBuilder(provider);
        new CollectUploadGate().Configure(_ => { })(builder);
        await builder.Build()(context);
        return new GateResult(cap.MaxRequestBodySize, context.Items.ContainsKey(PowService.HttpContextPowConsumed));
    }

    private static (string Nonce, string Hash) Solve(PowService.Challenge challenge)
    {
        var key = Base64Url.Decode(challenge.HmacKey);
        for (var n = 0; n < 2_000_000; n++)
        {
            var nonce = n.ToString(System.Globalization.CultureInfo.InvariantCulture);
            var mac = HMACSHA256.HashData(key, Encoding.ASCII.GetBytes(nonce));
            if (!PowService.HasLeadingZeroBits(mac, challenge.DifficultyBits))
            {
                continue;
            }

            return (nonce, Base64Url.Encode(mac));
        }

        throw new InvalidOperationException("No proof found.");
    }

    private sealed record GateResult(long? MaxRequestBodySize, bool Consumed);

    private sealed class BodyCap : IHttpMaxRequestBodySizeFeature
    {
        public bool IsReadOnly => false;

        public long? MaxRequestBodySize { get; set; }
    }

    private sealed class GatePowPolicy : IPowPolicy
    {
        public int DifficultyBits => 4;
        public int ChallengeTtlSeconds => 120;
        public int CollectChallengeTtlSeconds => 120;
        public int ScanBudgetWindowSeconds => 60;
    }
}
