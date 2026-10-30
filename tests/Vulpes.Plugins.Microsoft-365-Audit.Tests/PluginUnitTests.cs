using System.Globalization;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Vulpes.Host.Search;
using Vulpes.Plugins.Microsoft365Audit.Collectors;
using Vulpes.Plugins.Microsoft365Audit.Data;
using Vulpes.Plugins.Microsoft365Audit.Graph;
using Vulpes.Plugins.Microsoft365Audit.Normalization;
using Vulpes.Plugins.Microsoft365Audit.Scheduling;
using Vulpes.Plugins.Microsoft365Audit.Tenants;
using Vulpes.Sdk;
using Xunit;

namespace Vulpes.Plugins.Microsoft365Audit.Tests;

public sealed class TenantSettingsAndOptionsTests
{
    [Fact]
    public void Settings_parse_tolerantly_and_round_trip()
    {
        Assert.Empty(TenantSettings.Parse(null).Sources);
        Assert.Empty(TenantSettings.Parse("not json").Sources);
        Assert.True(TenantSettings.Parse("{}").For("signins").Enabled);
        Assert.True(TenantSettings.Parse("{}").For("signins").IncludeNonInteractive);

        var settings = new TenantSettings { Sources = { ["activity"] = new SourceSettings { Enabled = false, IntervalMinutes = 45, RecordTypes = ["sharePoint"] } } };
        var parsed = TenantSettings.Parse(settings.Serialize());
        Assert.False(parsed.For("activity").Enabled);
        Assert.Equal(45, parsed.For("activity").IntervalMinutes);
        Assert.Equal(["sharePoint"], parsed.For("activity").RecordTypes);
        Assert.True(parsed.For("signins").Enabled);
    }

    [Fact]
    public void Plugin_settings_round_trip_and_reject_bad_values()
    {
        var options = new AuditOptions();
        var path = Path.Combine(Path.GetTempPath(), "vulpes-audit-settings-" + Guid.NewGuid().ToString("n") + ".json");
        var store = new AuditSettingsStore(path, options);
        var update = AuditSettingsDocument.From(options);
        update.DefaultLookbackDays = 14;
        update.IntervalMinutes["signins"] = 12;
        update.BusinessPremiumMode = true;
        Assert.Null(store.Save(update));
        Assert.Equal(14, options.DefaultLookbackDays);
        Assert.Equal(TimeSpan.FromMinutes(12), options.IntervalFor("signins"));
        Assert.False(options.Collects("risk"));
        Assert.True(options.Collects("signins"));

        var again = new AuditOptions();
        new AuditSettingsStore(path, again).Load();
        Assert.Equal(14, again.DefaultLookbackDays);
        Assert.True(again.BusinessPremiumMode);
        File.Delete(path);

        update.SchedulerIntervalSeconds = 1;
        Assert.NotNull(AuditSettingsStore.Apply(update, options));
    }

    [Fact]
    public void Intervals_are_clamped_and_defaulted()
    {
        var options = new AuditOptions();
        Assert.Equal(TimeSpan.FromMinutes(5), options.IntervalFor("signins"));
        Assert.Equal(TimeSpan.FromMinutes(15), options.IntervalFor("unknown"));
        options.IntervalMinutes["signins"] = 0;
        Assert.Equal(TimeSpan.FromMinutes(1), options.IntervalFor("signins"));
        options.IntervalMinutes["signins"] = 1_000_000;
        Assert.Equal(TimeSpan.FromDays(7), options.IntervalFor("signins"));
    }

    [Fact]
    public void Schema_declares_every_source_with_valid_fields()
    {
        var schema = new AuditSchema();
        var catalog = new FieldCatalog([schema]); // throws on invalid ids / field paths
        Assert.Equal(9, schema.Sources.Count);
        Assert.Equal(EventStorageMode.Index, catalog.GetSource("microsoft-365-audit", "security-alerts")!.Mode);
        Assert.Equal(EventStorageMode.DataStream, catalog.GetSource("microsoft-365-audit", "signins")!.Mode);
        Assert.True(catalog.IsKnownField("microsoft-365-audit", "signins", "labels.riskLevel"));
        Assert.True(catalog.IsKnownField("microsoft-365-audit", "signins", "user.name"));
        Assert.False(catalog.IsKnownField("microsoft-365-audit", "signins", "labels.workload"));
        Assert.Equal(90, catalog.GetSource("microsoft-365-audit", "system")!.RetentionDays);
        foreach (var source in schema.Sources)
        {
            Assert.All(source.Fields, f => Assert.True(f.Path.StartsWith("labels.", StringComparison.Ordinal) || f.Path.StartsWith("data.", StringComparison.Ordinal)));
        }
    }

    [Fact]
    public void Clouds_resolve_authority_and_graph_hosts()
    {
        Assert.Equal("https://graph.microsoft.com", GraphCloud.For(null).GraphBase);
        Assert.Equal("https://graph.microsoft.com/.default", GraphCloud.For("Global").Scope);
        Assert.Equal("https://graph.microsoft.us", GraphCloud.For("usgov").GraphBase);
        Assert.Equal(Azure.Identity.AzureAuthorityHosts.AzureGovernment, GraphCloud.For("USGov").AuthorityHost);
    }
}

public sealed class CredentialFactoryTests
{
    [Fact]
    public void Builds_secret_and_certificate_credentials_from_protected_values()
    {
        var protector = new FakeProtector();
        var factory = new GraphCredentialFactory(protector);
        var tenant = new Tenant { Id = Guid.NewGuid(), DisplayName = "t", TenantId = Guid.NewGuid().ToString(), ClientId = Guid.NewGuid().ToString(), ProtectedSecret = protector.Protect("secret") };
        Assert.IsType<AzureIdentityTokenProvider>(factory.Create(tenant));

        using var rsa = RSA.Create(2048);
        using var certificate = new CertificateRequest("CN=audit-test", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1).CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(30));
        var pfx = certificate.Export(X509ContentType.Pfx, "pw");
        var certTenant = new Tenant
        {
            Id = Guid.NewGuid(),
            DisplayName = "t",
            TenantId = Guid.NewGuid().ToString(),
            ClientId = Guid.NewGuid().ToString(),
            CredentialType = CredentialTypes.Certificate,
            ProtectedCertificate = protector.Protect(Convert.ToBase64String(pfx)),
            ProtectedCertificatePassword = protector.Protect("pw"),
            Cloud = Clouds.UsGov,
        };
        Assert.IsType<AzureIdentityTokenProvider>(factory.Create(certTenant));

        Assert.Throws<InvalidOperationException>(() => factory.Create(new Tenant { Id = Guid.NewGuid(), DisplayName = "t", TenantId = "x", ClientId = "y" }));
        Assert.Throws<InvalidOperationException>(() => factory.Create(new Tenant { Id = Guid.NewGuid(), DisplayName = "t", TenantId = "x", ClientId = "y", CredentialType = CredentialTypes.Certificate }));
    }

    private sealed class NoHttp : IHttpClientFactory
    {
        public HttpClient CreateClient(string name) => new(new RoutedGraphHandler());
    }
}

public sealed class NormalizerCoverageTests
{
    private static JsonElement Json(string json) => JsonDocument.Parse(json).RootElement.Clone();

    [Fact]
    public void Successful_sign_in_is_informational_with_success_message()
    {
        var e = Normalizers.SignIn(Json("""{"id":"1","createdDateTime":"2026-10-29T09:15:22Z","userPrincipalName":"a@b.c","appDisplayName":"Teams","ipAddress":"1.2.3.4","status":{"errorCode":0}}"""), "t", "T", "servicePrincipal");
        Assert.NotNull(e);
        Assert.Equal("success", e.Outcome);
        Assert.Equal("informational", e.Severity);
        Assert.Equal("a@b.c signed in to Teams from 1.2.3.4", e.Message);
        Assert.Equal("servicePrincipal", e.Labels!["signInType"]);
        Assert.Null(e.Geo);
    }

    [Fact]
    public void Provisioning_incident_risky_identities_and_secure_score_normalize()
    {
        var provisioning = Normalizers.Provisioning(Json("""{"id":"p1","activityDateTime":"2026-10-29T01:00:00Z","provisioningAction":"create","provisioningStatusInfo":{"status":"success"},"targetIdentity":{"id":"u","displayName":"New User","identityType":"User"},"servicePrincipal":{"id":"sp","displayName":"Workday"},"sourceSystem":{"displayName":"Workday"},"targetSystem":{"displayName":"Entra ID"}}"""), "t", "T");
        Assert.NotNull(provisioning);
        Assert.Equal("provisioning", provisioning.Source);
        Assert.Equal("create", provisioning.Action);
        Assert.Equal("success", provisioning.Outcome);
        Assert.Equal("Workday", provisioning.ClientAppName);
        Assert.Equal("Entra ID", provisioning.Labels!["targetSystem"]);

        var incident = Normalizers.Incident(Json("""{"id":"i1","displayName":"Multi-stage incident","severity":"medium","status":"active","createdDateTime":"2026-10-29T02:00:00Z","lastUpdateDateTime":"2026-10-29T03:00:00Z","incidentWebUrl":"https://security.microsoft.com/incidents/1"}"""), "t", "T");
        Assert.NotNull(incident);
        Assert.Equal("alert", incident.Kind);
        Assert.Equal("incidents", incident.Source);
        Assert.Equal("medium", incident.Severity);
        Assert.Equal("Multi-stage incident", incident.Message);
        Assert.Equal("active", incident.Labels!["status"]);

        var riskyUser = Normalizers.RiskyUser(Json("""{"id":"u1","riskLevel":"high","riskState":"atRisk","riskDetail":"none","riskLastUpdatedDateTime":"2026-10-29T04:00:00Z","userPrincipalName":"jane@contoso.com","isDeleted":false}"""), "t", "T");
        Assert.NotNull(riskyUser);
        Assert.Equal("state", riskyUser.Kind);
        Assert.StartsWith("user:u1:", riskyUser.RecordId, StringComparison.Ordinal);
        Assert.Equal("high", riskyUser.Severity);
        Assert.Equal("user", riskyUser.Labels!["riskType"]);

        var riskySp = Normalizers.RiskyServicePrincipal(Json("""{"id":"sp1","riskLevel":"low","riskState":"confirmedCompromised","riskLastUpdatedDateTime":"2026-10-29T05:00:00Z","displayName":"Legacy","appId":"app","servicePrincipalType":"Application"}"""), "t", "T");
        Assert.NotNull(riskySp);
        Assert.Equal("app", riskySp.ClientAppId);
        Assert.Equal("servicePrincipal", riskySp.Labels!["riskType"]);
        Assert.Equal("Application", riskySp.Labels["servicePrincipalType"]);

        var score = Normalizers.SecureScore(Json("""{"id":"2026-10-29","createdDateTime":"2026-10-29T00:00:00Z","currentScore":61.5,"maxScore":100,"activeUserCount":250}"""), "t", "T");
        Assert.NotNull(score);
        Assert.Equal("metric", score.Kind);
        Assert.Equal("Secure score 61.5 / 100", score.Message);
        Assert.Equal("61.5", score.Labels!["percent"]);
        Assert.Equal("250", score.Labels["activeUserCount"]);

        var failure = Normalizers.CollectorFailure("t", "T", "signins", "boom", new DateTimeOffset(2026, 10, 29, 6, 0, 0, TimeSpan.Zero));
        Assert.Equal("system", failure.Source);
        Assert.Equal("failure", failure.Outcome);
        Assert.Equal("signins", failure.Labels!["collector"]);
        Assert.Contains("boom", failure.Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("High", "high")]
    [InlineData("informational", "informational")]
    [InlineData("Hidden", "informational")]
    [InlineData(null, "informational")]
    [InlineData("critical", "critical")]
    public void Severities_normalize(string? input, string expected) => Assert.Equal(expected, Normalizers.NormalizeSeverity(input));

    [Theory]
    [InlineData("Add member to role", "medium")]
    [InlineData("Update user", "informational")]
    [InlineData(null, "informational")]
    public void Directory_activities_get_severity(string? activity, string expected) => Assert.Equal(expected, Normalizers.SeverityForDirectory(activity));

    [Theory]
    [InlineData("New-InboxRule", "medium")]
    [InlineData("AnonymousLinkCreated", "medium")]
    [InlineData("FileAccessed", "informational")]
    public void Operations_get_severity(string operation, string expected) => Assert.Equal(expected, Normalizers.SeverityForOperation(operation));

    [Theory]
    [InlineData("UserManagement", "iam")]
    [InlineData("Policy", "configuration")]
    [InlineData(null, "iam")]
    public void Directory_categories_map(string? category, string expected) => Assert.Equal(expected, Normalizers.CategoryForDirectory(category));

    [Fact]
    public void Json_helpers_are_tolerant()
    {
        var e = Json("""{"s":"x","n":12,"b":true,"o":{"k":1},"a":[1],"d":"2026-10-29T00:00:00Z","bad":"nope"}""");
        Assert.Equal("x", e.Str("s"));
        Assert.Equal("12", e.Str("n"));
        Assert.Equal("true", e.Str("b"));
        Assert.Null(e.Str("o"));
        Assert.Null(e.Str("missing"));
        Assert.NotNull(e.Obj("o"));
        Assert.NotNull(e.Obj("a"));
        Assert.Null(e.Obj("s"));
        Assert.Equal(12, e.WholeNumber("n"));
        Assert.Null(e.WholeNumber("s"));
        Assert.Equal(12d, e.Num("n"));
        Assert.Equal(new DateTimeOffset(2026, 10, 29, 0, 0, 0, TimeSpan.Zero), e.Date("d"));
        Assert.Null(e.Date("bad"));
        Assert.Equal("ab", J.Truncate("abc", 2));
        Assert.Null(J.Truncate(null, 2));
    }
}

public sealed class MoreCollectorTests
{
    private static readonly DateTimeOffset Now = new(2026, 10, 30, 12, 0, 0, TimeSpan.Zero);

    [Fact]
    public async Task Provisioning_and_incidents_collect_through_the_shared_watermark_loop()
    {
        var handler = new RoutedGraphHandler()
            .Get(p => p.Contains("auditLogs/provisioning", StringComparison.Ordinal), _ => RoutedGraphHandler.Page([new { id = "p1", activityDateTime = Now.AddMinutes(-3).ToString("O", CultureInfo.InvariantCulture), provisioningAction = "update", provisioningStatusInfo = new { status = "failure" } }]))
            .Get(p => p.Contains("security/incidents", StringComparison.Ordinal), _ => RoutedGraphHandler.Page([new { id = "i1", displayName = "Incident", severity = "low", status = "resolved", createdDateTime = Now.AddDays(-2).ToString("O", CultureInfo.InvariantCulture), lastUpdateDateTime = Now.AddMinutes(-2).ToString("O", CultureInfo.InvariantCulture) }]));
        var pipeline = new FakePipeline();
        var provisioning = new Checkpoint { TenantId = TestContext.Tenant.Id, Source = "provisioning" };
        var incidents = new Checkpoint { TenantId = TestContext.Tenant.Id, Source = "incidents" };

        var r1 = await new ProvisioningCollector().CollectAsync(TestContext.Context(TestContext.Client(handler), pipeline, provisioning), CancellationToken.None);
        var r2 = await new IncidentsCollector().CollectAsync(TestContext.Context(TestContext.Client(handler), pipeline, incidents), CancellationToken.None);

        Assert.Equal(1, r1.Published);
        Assert.Equal(Now.AddMinutes(-3), provisioning.Watermark);
        Assert.Equal("failure", pipeline.Events.Single(e => e.Source == "provisioning").Outcome);
        Assert.Equal(1, r2.Published);
        Assert.Equal(Now.AddMinutes(-2), incidents.Watermark); // lastUpdateDateTime drives the incident watermark
        Assert.Equal("resolved", pipeline.Events.Single(e => e.Source == "incidents").Labels!["status"]);
    }

    [Fact]
    public async Task Running_out_of_time_yields_a_partial_result()
    {
        var time = new Microsoft.Extensions.Time.Testing.FakeTimeProvider(Now);
        var handler = new RoutedGraphHandler()
            .Get(p => p.Contains("skiptoken=p1", StringComparison.Ordinal), _ => RoutedGraphHandler.Page([new { id = "d2", activityDateTime = Now.AddHours(-2).ToString("O", CultureInfo.InvariantCulture), activityDisplayName = "x" }]))
            .Get(p => p.Contains("directoryAudits", StringComparison.Ordinal), _ =>
            {
                time.Advance(TimeSpan.FromMinutes(30)); // the first page alone exhausts the run budget
                return RoutedGraphHandler.Page([new { id = "d1", activityDateTime = Now.AddHours(-1).ToString("O", CultureInfo.InvariantCulture), activityDisplayName = "x" }], "https://graph.microsoft.com/v1.0/auditLogs/directoryAudits?$skiptoken=p1");
            });
        var checkpoint = new Checkpoint { TenantId = TestContext.Tenant.Id, Source = "directory" };
        var result = await new DirectoryAuditsCollector().CollectAsync(TestContext.Context(TestContext.Client(handler, time), new FakePipeline(), checkpoint, time: time), CancellationToken.None);
        Assert.False(result.Complete);
        Assert.Equal(1, result.Published);
        Assert.Equal(Now.AddHours(-1), checkpoint.Watermark);
        Assert.Contains("partial", result.Note, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Beta_sign_ins_carry_their_event_type()
    {
        var handler = new RoutedGraphHandler()
            .Get(p => p.Contains("/beta/auditLogs/signIns", StringComparison.Ordinal), _ => RoutedGraphHandler.Page(
            [
                new { id = "sp1", createdDateTime = Now.AddMinutes(-1).ToString("O", CultureInfo.InvariantCulture), servicePrincipalName = "automation", signInEventTypes = new[] { "servicePrincipal" }, status = new { errorCode = 0 } },
                new { id = "ni1", createdDateTime = Now.AddMinutes(-2).ToString("O", CultureInfo.InvariantCulture), userPrincipalName = "jane@contoso.com", signInEventTypes = new[] { "nonInteractiveUser" }, status = new { errorCode = 0 } },
            ]))
            .Get(p => p.Contains("/v1.0/auditLogs/signIns", StringComparison.Ordinal), _ => RoutedGraphHandler.Page([]));
        var pipeline = new FakePipeline();
        var checkpoint = new Checkpoint { TenantId = TestContext.Tenant.Id, Source = "signins" };
        await new SignInsCollector().CollectAsync(TestContext.Context(TestContext.Client(handler), pipeline, checkpoint), CancellationToken.None);
        Assert.Equal("servicePrincipal", pipeline.Events.Single(e => e.RecordId == "sp1").Labels!["signInType"]);
        Assert.Equal("nonInteractive", pipeline.Events.Single(e => e.RecordId == "ni1").Labels!["signInType"]);
        Assert.Equal("automation", pipeline.Events.Single(e => e.RecordId == "sp1").UserName);
        Assert.Contains("nonInteractiveWatermark", checkpoint.StateJson, StringComparison.Ordinal);
    }
}
