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
    public async Task A_long_file_name_header_does_not_burn_the_upload_proof()
    {
        var database = new ShareDatabase(Path.Combine(_dir, "long-name.db"));
        var pow = new PowService(database, new GatePowPolicy());
        var store = new ShareStore(database);
        var id = store.CreateCollect("owner", new CollectInput(Base64Url.Encode(new byte[32]), null, null, null, true, 60, null, false, false, null));
        var browser = Convert.ToHexString(RandomNumberGenerator.GetBytes(16)).ToLowerInvariant();
        var challenge = pow.Issue("collect", id, clientId: browser);
        var (nonce, hash) = Solve(challenge);
        var clock = PowClock.Stamp(DateTimeOffset.UtcNow);

        var blocked = await RunAsync(database, pow, store, id, browser, challenge.ChallengeId, nonce, hash, filenameHeader: new string('a', 201));
        Assert.False(blocked.Consumed);
        Assert.Equal(PowService.SmallBodyBytes, blocked.MaxRequestBodySize);
        Assert.Null(pow.TryConsume("collect", id, challenge.ChallengeId, nonce, hash, browser, clock));
    }

    [Fact]
    public async Task A_unicode_file_name_is_percent_encoded_utf8_and_keeps_the_proof_when_it_is_short()
    {
        var database = new ShareDatabase(Path.Combine(_dir, "unicode-name.db"));
        var pow = new PowService(database, new GatePowPolicy());
        var store = new ShareStore(database);
        var id = store.CreateCollect("owner", new CollectInput(Base64Url.Encode(new byte[32]), null, null, null, true, 60, null, false, false, null));
        var browser = Convert.ToHexString(RandomNumberGenerator.GetBytes(16)).ToLowerInvariant();
        var challenge = pow.Issue("collect", id, clientId: browser);
        var (nonce, hash) = Solve(challenge);
        var encoded = Uri.EscapeDataString("秘密.txt");
        Assert.True(encoded.Length > "秘密.txt".Length);
        Assert.False(CollectUploadGate.FilenameTooLong(encoded));

        var allowed = await RunAsync(database, pow, store, id, browser, challenge.ChallengeId, nonce, hash, filenameHeader: encoded);
        Assert.True(allowed.Consumed);
        Assert.Equal(PowService.LargeBodyBytes, allowed.MaxRequestBodySize);

        var longEncoded = Uri.EscapeDataString(new string('密', CollectUploadGate.MaxFilenameLength + 1));
        Assert.True(longEncoded.Length > CollectUploadGate.MaxFilenameLength);
        Assert.True(CollectUploadGate.FilenameTooLong(longEncoded));
    }

    [Fact]
    public async Task An_extra_slash_or_a_padded_id_does_not_burn_the_real_collect_proof()
    {
        var database = new ShareDatabase(Path.Combine(_dir, "path-proof.db"));
        var pow = new PowService(database, new GatePowPolicy());
        var store = new ShareStore(database);
        var id = store.CreateCollect("owner", new CollectInput(Base64Url.Encode(new byte[32]), null, null, null, true, 60, null, false, false, null));
        var browser = Convert.ToHexString(RandomNumberGenerator.GetBytes(16)).ToLowerInvariant();
        var challenge = pow.Issue("collect", id, clientId: browser);
        var (nonce, hash) = Solve(challenge);
        var doubled = "/api/plugins/secret-sharing/public/collects//" + id;
        var spaced = "/api/plugins/secret-sharing/public/collects/" + id + " ";

        var extra = await RunAsync(database, pow, store, id, browser, challenge.ChallengeId, nonce, hash, path: doubled);
        Assert.False(extra.Consumed);
        Assert.Equal(PowService.SmallBodyBytes, extra.MaxRequestBodySize);
        Assert.Null(CollectUploadGate.RouteId(doubled));

        var padded = await RunAsync(database, pow, store, id, browser, challenge.ChallengeId, nonce, hash, path: spaced);
        Assert.False(padded.Consumed);
        Assert.Equal(id + " ", CollectUploadGate.RouteId(spaced));

        var clock = PowClock.Stamp(DateTimeOffset.UtcNow);
        Assert.Null(pow.TryConsume("collect", id, challenge.ChallengeId, nonce, hash, browser, clock));
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
    public async Task A_broken_forwarded_port_keeps_the_proxy_lockout()
    {
        var database = new ShareDatabase(Path.Combine(_dir, "broken-port.db"));
        var pow = new PowService(database, new GatePowPolicy());
        var store = new ShareStore(database);
        var scan = new ShareScanGuard(database, new GatePowPolicy());
        var id = store.CreateCollect("owner", new CollectInput(Base64Url.Encode(new byte[32]), null, null, null, true, 60, null, false, false, null));
        var browser = Convert.ToHexString(RandomNumberGenerator.GetBytes(16)).ToLowerInvariant();
        var challenge = pow.Issue("collect", id, clientId: browser);
        var (nonce, hash) = Solve(challenge);
        var proxy = IPAddress.Parse("192.0.2.10");
        for (var i = 0; i < ShareScanGuard.MaxFailuresInWindow; i++) scan.RecordFailure(proxy.ToString());

        var locked = await RunAsync(database, pow, store, id, browser, challenge.ChallengeId, nonce, hash, remote: proxy, scan: scan, forwardedFor: "203.0.113.50:80a", knownProxy: proxy);
        var quoted = await RunAsync(database, pow, store, id, browser, challenge.ChallengeId, nonce, hash, remote: proxy, scan: scan, forwardedFor: "203.0.113.50\"", knownProxy: proxy);
        Assert.False(quoted.Consumed);
        var doubled = await RunAsync(database, pow, store, id, browser, challenge.ChallengeId, nonce, hash, remote: proxy, scan: scan, forwardedFor: "\"\"203.0.113.50\"\"", knownProxy: proxy);
        Assert.False(doubled.Consumed);
        Assert.Equal(PowService.SmallBodyBytes, doubled.MaxRequestBodySize);
        Assert.False(locked.Consumed);
        var spaced = await RunAsync(database, pow, store, id, browser, challenge.ChallengeId, nonce, hash, remote: proxy, scan: scan, forwardedFor: "203.0.113.50 ", knownProxy: proxy);
        Assert.False(spaced.Consumed);
        Assert.Equal(PowService.SmallBodyBytes, locked.MaxRequestBodySize);
        Assert.Null(pow.TryConsume("collect", id, challenge.ChallengeId, nonce, hash, browser, PowClock.Stamp(DateTimeOffset.UtcNow)));
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
    public async Task A_mapped_known_proxy_does_not_burn_a_proof_for_a_locked_plain_peer()
    {
        var database = new ShareDatabase(Path.Combine(_dir, "mapped-proxy.db"));
        var pow = new PowService(database, new GatePowPolicy());
        var store = new ShareStore(database);
        var scan = new ShareScanGuard(database, new GatePowPolicy());
        var id = store.CreateCollect("owner", new CollectInput(Base64Url.Encode(new byte[32]), null, null, null, true, 60, null, false, false, null));
        var browser = Convert.ToHexString(RandomNumberGenerator.GetBytes(16)).ToLowerInvariant();
        var challenge = pow.Issue("collect", id, clientId: browser);
        var (nonce, hash) = Solve(challenge);
        var peer = IPAddress.Parse("192.0.2.10");
        var mapped = IPAddress.Parse("::ffff:192.0.2.10");
        for (var i = 0; i < ShareScanGuard.MaxFailuresInWindow; i++) scan.RecordFailure(peer.ToString());

        var locked = await RunAsync(database, pow, store, id, browser, challenge.ChallengeId, nonce, hash, remote: peer, scan: scan, forwardedFor: "203.0.113.50", knownProxy: mapped);
        Assert.False(locked.Consumed);
        Assert.Equal(PowService.SmallBodyBytes, locked.MaxRequestBodySize);
        Assert.Null(pow.TryConsume("collect", id, challenge.ChallengeId, nonce, hash, browser, PowClock.Stamp(DateTimeOffset.UtcNow)));
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

    [Fact]
    public async Task A_scoped_link_local_peer_matches_an_unscoped_proxy_and_the_budget_key_has_no_zone()
    {
        var stored = IPAddress.Parse("fe80::1");
        var peer = new IPAddress(stored.GetAddressBytes(), 12);
        Assert.Equal(12L, peer.ScopeId);
        Assert.False(stored.Equals(peer));
        Assert.Contains("%", peer.ToString(), StringComparison.Ordinal);

        var services = new ServiceCollection();
        services.Configure<ForwardedHeadersOptions>(options => options.KnownProxies.Add(stored));
        var provider = services.BuildServiceProvider();
        var context = new DefaultHttpContext { RequestServices = provider };
        context.Connection.RemoteIpAddress = peer;
        var key = CollectUploadGate.BudgetClientKey(context);
        Assert.Equal("fe80::1", key);
        Assert.DoesNotContain("%", key, StringComparison.Ordinal);

        context.Request.Headers["X-Forwarded-For"] = "203.0.113.50";
        var forwarded = CollectUploadGate.BudgetClientKey(context);
        Assert.Equal("203.0.113.50", forwarded);
        Assert.DoesNotContain("%", forwarded, StringComparison.Ordinal);

        var plain = IPAddress.Parse("192.0.2.10");
        context.Connection.RemoteIpAddress = plain;
        context.Request.Headers.Remove("X-Forwarded-For");
        Assert.Equal(plain.ToString(), CollectUploadGate.BudgetClientKey(context));

        var database = new ShareDatabase(Path.Combine(_dir, "scoped-proxy.db"));
        var pow = new PowService(database, new GatePowPolicy());
        var store = new ShareStore(database);
        var scan = new ShareScanGuard(database, new GatePowPolicy());
        var id = store.CreateCollect("owner", new CollectInput(Base64Url.Encode(new byte[32]), null, null, null, true, 60, null, false, false, null));
        var browser = Convert.ToHexString(RandomNumberGenerator.GetBytes(16)).ToLowerInvariant();
        var challenge = pow.Issue("collect", id, clientId: browser);
        var (nonce, hash) = Solve(challenge);
        var visitor = IPAddress.Parse("203.0.113.50");
        for (var i = 0; i < ShareScanGuard.MaxFailuresInWindow; i++) scan.RecordFailure(visitor.ToString());

        var locked = await RunAsync(database, pow, store, id, browser, challenge.ChallengeId, nonce, hash, remote: peer, scan: scan, forwardedFor: visitor.ToString(), knownProxy: stored);
        Assert.False(locked.Consumed);
        Assert.Equal(PowService.SmallBodyBytes, locked.MaxRequestBodySize);
        Assert.Null(pow.TryConsume("collect", id, challenge.ChallengeId, nonce, hash, browser, PowClock.Stamp(DateTimeOffset.UtcNow)));
    }

    public void Dispose() => Directory.Delete(_dir, recursive: true);

    private static async Task<GateResult> RunAsync(ShareDatabase database, PowService pow, ShareStore store, string id, string browser, string? challenge, string? nonce, string? hash, string? path = null, IPAddress? remote = null, ShareScanGuard? scan = null, string? forwardedFor = null, IPAddress? knownProxy = null, IReadOnlyList<IPAddress>? knownProxies = null, int? forwardLimit = null, string? filenameHeader = null)
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

        if (filenameHeader is not null)
        {
            context.Request.Headers[CollectUploadGate.FilenameHeader] = filenameHeader;
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
