using System.Net;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.HttpOverrides;
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
        var slashed = await RunAsync(database, pow, store, id, browser, null, null, null, "/api/plugins/secret-sharing/public/collects/" + id + "/");
        Assert.Equal(PowService.SmallBodyBytes, slashed.MaxRequestBodySize);
        Assert.Equal(PowService.SmallBodyBytes, unproven.MaxRequestBodySize);
        Assert.False(unproven.Consumed);

        var clock = PowClock.Stamp(DateTimeOffset.UtcNow);
        var permit = pow.TryValidate("collect", id, challenge.ChallengeId, nonce, hash, browser, clock);
        Assert.Null(permit);
        Assert.Null(pow.TryValidate("collect", id, challenge.ChallengeId, nonce, hash, browser, clock));

        var proven = await RunAsync(database, pow, store, id, browser, challenge.ChallengeId, nonce, hash);
        Assert.Equal(PowService.LargeBodyBytes, proven.MaxRequestBodySize);
        Assert.True(proven.Consumed);
        Assert.NotNull(pow.TryConsume("collect", id, challenge.ChallengeId, nonce, hash, browser, clock));
    }

    [Fact]
    public async Task A_lockout_leaves_a_solved_upload_proof_in_place()
    {
        var database = new ShareDatabase(Path.Combine(_dir, "lockout.db"));
        var pow = new PowService(database, new GatePowPolicy());
        var store = new ShareStore(database);
        var scan = new ShareScanGuard(database, new GatePowPolicy());
        var id = store.CreateCollect("owner", new CollectInput(Base64Url.Encode(new byte[32]), null, null, null, true, 60, null, false, false, null));
        var browser = Convert.ToHexString(RandomNumberGenerator.GetBytes(16)).ToLowerInvariant();
        var challenge = pow.Issue("collect", id, clientId: browser);
        var (nonce, hash) = Solve(challenge);
        var remote = IPAddress.Parse("203.0.113.50");
        for (var i = 0; i < ShareScanGuard.MaxFailuresInWindow; i++) scan.RecordFailure(remote.ToString());

        var locked = await RunAsync(database, pow, store, id, browser, challenge.ChallengeId, nonce, hash, remote: remote, scan: scan);
        Assert.False(locked.Consumed);
        Assert.Equal(PowService.SmallBodyBytes, locked.MaxRequestBodySize);
        var clock = PowClock.Stamp(DateTimeOffset.UtcNow);
        Assert.Null(pow.TryConsume("collect", id, challenge.ChallengeId, nonce, hash, browser, clock));
    }

    [Fact]
    public async Task A_lockout_behind_a_known_proxy_leaves_the_upload_proof_in_place()
    {
        var database = new ShareDatabase(Path.Combine(_dir, "proxy-lockout.db"));
        var pow = new PowService(database, new GatePowPolicy());
        var store = new ShareStore(database);
        var scan = new ShareScanGuard(database, new GatePowPolicy());
        var id = store.CreateCollect("owner", new CollectInput(Base64Url.Encode(new byte[32]), null, null, null, true, 60, null, false, false, null));
        var browser = Convert.ToHexString(RandomNumberGenerator.GetBytes(16)).ToLowerInvariant();
        var challenge = pow.Issue("collect", id, clientId: browser);
        var (nonce, hash) = Solve(challenge);
        var visitor = IPAddress.Parse("203.0.113.50");
        var proxy = IPAddress.Parse("192.0.2.10");
        for (var i = 0; i < ShareScanGuard.MaxFailuresInWindow; i++) scan.RecordFailure(visitor.ToString());

        var locked = await RunAsync(database, pow, store, id, browser, challenge.ChallengeId, nonce, hash, remote: proxy, scan: scan, forwardedFor: visitor.ToString(), knownProxy: proxy);
        Assert.False(locked.Consumed);
        Assert.Equal(PowService.SmallBodyBytes, locked.MaxRequestBodySize);
        var clock = PowClock.Stamp(DateTimeOffset.UtcNow);
        Assert.Null(pow.TryConsume("collect", id, challenge.ChallengeId, nonce, hash, browser, clock));
    }

    [Fact]
    public async Task A_forwarded_address_with_a_port_still_sees_the_visitor_lockout()
    {
        var database = new ShareDatabase(Path.Combine(_dir, "port-lockout.db"));
        var pow = new PowService(database, new GatePowPolicy());
        var store = new ShareStore(database);
        var scan = new ShareScanGuard(database, new GatePowPolicy());
        var id = store.CreateCollect("owner", new CollectInput(Base64Url.Encode(new byte[32]), null, null, null, true, 60, null, false, false, null));
        var browser = Convert.ToHexString(RandomNumberGenerator.GetBytes(16)).ToLowerInvariant();
        var challenge = pow.Issue("collect", id, clientId: browser);
        var (nonce, hash) = Solve(challenge);
        var visitor = IPAddress.Parse("203.0.113.50");
        var proxy = IPAddress.Parse("192.0.2.10");
        for (var i = 0; i < ShareScanGuard.MaxFailuresInWindow; i++) scan.RecordFailure(visitor.ToString());

        var locked = await RunAsync(database, pow, store, id, browser, challenge.ChallengeId, nonce, hash, remote: proxy, scan: scan, forwardedFor: visitor + ":54321", knownProxy: proxy);
        Assert.False(locked.Consumed);
        Assert.Equal(PowService.SmallBodyBytes, locked.MaxRequestBodySize);
    }

    [Fact]
    public async Task Two_trusted_proxies_use_the_single_forwarded_hop_for_the_lockout()
    {
        var database = new ShareDatabase(Path.Combine(_dir, "two-proxy.db"));
        var pow = new PowService(database, new GatePowPolicy());
        var store = new ShareStore(database);
        var scan = new ShareScanGuard(database, new GatePowPolicy());
        var id = store.CreateCollect("owner", new CollectInput(Base64Url.Encode(new byte[32]), null, null, null, true, 60, null, false, false, null));
        var browser = Convert.ToHexString(RandomNumberGenerator.GetBytes(16)).ToLowerInvariant();
        var challenge = pow.Issue("collect", id, clientId: browser);
        var (nonce, hash) = Solve(challenge);
        var edge = IPAddress.Parse("10.0.0.2");
        var inner = IPAddress.Parse("10.0.0.1");
        var visitor = IPAddress.Parse("203.0.113.8");
        for (var i = 0; i < ShareScanGuard.MaxFailuresInWindow; i++) scan.RecordFailure(inner.ToString());

        var locked = await RunAsync(database, pow, store, id, browser, challenge.ChallengeId, nonce, hash, remote: edge, scan: scan, forwardedFor: visitor + ", " + inner, knownProxies: [edge, inner]);
        Assert.False(locked.Consumed);
        Assert.Equal(PowService.SmallBodyBytes, locked.MaxRequestBodySize);
        Assert.Null(pow.TryConsume("collect", id, challenge.ChallengeId, nonce, hash, browser, PowClock.Stamp(DateTimeOffset.UtcNow)));
    }

    [Fact]
    public async Task A_lockout_of_the_original_visitor_does_not_count_as_the_one_hop_address()
    {
        var database = new ShareDatabase(Path.Combine(_dir, "two-proxy-visitor.db"));
        var pow = new PowService(database, new GatePowPolicy());
        var store = new ShareStore(database);
        var scan = new ShareScanGuard(database, new GatePowPolicy());
        var id = store.CreateCollect("owner", new CollectInput(Base64Url.Encode(new byte[32]), null, null, null, true, 60, null, false, false, null));
        var browser = Convert.ToHexString(RandomNumberGenerator.GetBytes(16)).ToLowerInvariant();
        var challenge = pow.Issue("collect", id, clientId: browser);
        var (nonce, hash) = Solve(challenge);
        var edge = IPAddress.Parse("10.0.0.2");
        var inner = IPAddress.Parse("10.0.0.1");
        var visitor = IPAddress.Parse("203.0.113.8");
        for (var i = 0; i < ShareScanGuard.MaxFailuresInWindow; i++) scan.RecordFailure(visitor.ToString());

        var allowed = await RunAsync(database, pow, store, id, browser, challenge.ChallengeId, nonce, hash, remote: edge, scan: scan, forwardedFor: visitor + ", " + inner, knownProxies: [edge, inner]);
        Assert.True(allowed.Consumed);
        Assert.Equal(PowService.LargeBodyBytes, allowed.MaxRequestBodySize);
    }

    [Fact]
    public async Task A_trailing_slash_does_not_burn_the_upload_proof()
    {
        var database = new ShareDatabase(Path.Combine(_dir, "slash.db"));
        var pow = new PowService(database, new GatePowPolicy());
        var store = new ShareStore(database);
        var id = store.CreateCollect("owner", new CollectInput(Base64Url.Encode(new byte[32]), null, null, null, true, 60, null, false, false, null));
        var browser = Convert.ToHexString(RandomNumberGenerator.GetBytes(16)).ToLowerInvariant();
        var challenge = pow.Issue("collect", id, clientId: browser);
        var (nonce, hash) = Solve(challenge);
        var slashed = await RunAsync(database, pow, store, id, browser, challenge.ChallengeId, nonce, hash, "/api/plugins/secret-sharing/public/collects/" + id + "/");
        Assert.False(slashed.Consumed);
        Assert.Equal(PowService.SmallBodyBytes, slashed.MaxRequestBodySize);
        Assert.Null(pow.TryConsume("collect", id, challenge.ChallengeId, nonce, hash, browser, PowClock.Stamp(DateTimeOffset.UtcNow)));
    }

    [Fact]
    public async Task A_valid_proof_burns_before_the_collect_is_looked_up()
    {
        var database = new ShareDatabase(Path.Combine(_dir, "missing.db"));
        var pow = new PowService(database, new GatePowPolicy());
        var store = new ShareStore(database);
        var id = Convert.ToHexString(RandomNumberGenerator.GetBytes(16)).ToLowerInvariant();
        var browser = Convert.ToHexString(RandomNumberGenerator.GetBytes(16)).ToLowerInvariant();
        var challenge = pow.Issue("collect", id, clientId: browser);
        var (nonce, hash) = Solve(challenge);
        var proven = await RunAsync(database, pow, store, id, browser, challenge.ChallengeId, nonce, hash);
        Assert.Equal(PowService.LargeBodyBytes, proven.MaxRequestBodySize);
        Assert.True(proven.Consumed);
        Assert.Null(store.CollectMeta(id));
    }

    public void Dispose() => Directory.Delete(_dir, recursive: true);

    private static async Task<GateResult> RunAsync(ShareDatabase database, PowService pow, ShareStore store, string id, string browser, string? challenge, string? nonce, string? hash, string? path = null, IPAddress? remote = null, ShareScanGuard? scan = null, string? forwardedFor = null, IPAddress? knownProxy = null, IReadOnlyList<IPAddress>? knownProxies = null, int? forwardLimit = null)
    {
        var services = new ServiceCollection();
        services.AddSingleton(database);
        services.AddSingleton(pow);
        services.AddSingleton(store);
        services.AddSingleton(scan ?? new ShareScanGuard(database, new GatePowPolicy()));
        if (knownProxy is not null || knownProxies is not null || forwardLimit is not null)
        {
            services.Configure<ForwardedHeadersOptions>(options =>
            {
                if (knownProxy is not null)
                {
                    options.KnownProxies.Add(knownProxy);
                }

                if (knownProxies is not null)
                {
                    foreach (var proxy in knownProxies)
                    {
                        options.KnownProxies.Add(proxy);
                    }
                }

                if (forwardLimit is not null)
                {
                    options.ForwardLimit = forwardLimit;
                }
            });
        }

        var provider = services.BuildServiceProvider();
        var context = new DefaultHttpContext { RequestServices = provider };
        if (remote is not null) context.Connection.RemoteIpAddress = remote;
        context.Request.Method = HttpMethods.Post;
        context.Request.Path = path ?? "/api/plugins/secret-sharing/public/collects/" + id;
        if (forwardedFor is not null) context.Request.Headers["X-Forwarded-For"] = forwardedFor;
        context.Request.Headers.Cookie = PowBrowser.CookieName + "=" + browser;
        if (challenge is not null)
        {
            context.Request.Headers[PowService.HeaderChallenge] = challenge;
            context.Request.Headers[PowService.HeaderNonce] = nonce;
            context.Request.Headers[PowService.HeaderHash] = hash;
            context.Request.Headers[PowService.HeaderTime] = PowClock.Stamp(DateTimeOffset.UtcNow);
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
