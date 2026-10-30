using System.Globalization;
using System.Net;
using System.Text.Json;
using Microsoft.Extensions.Time.Testing;
using Vulpes.Plugins.Microsoft365Audit.Collectors;
using Vulpes.Plugins.Microsoft365Audit.Data;
using Vulpes.Plugins.Microsoft365Audit.Graph;
using Vulpes.Plugins.Microsoft365Audit.Tenants;
using Xunit;

namespace Vulpes.Plugins.Microsoft365Audit.Tests;

public sealed class CollectorTests
{
    private static readonly DateTimeOffset Now = new(2026, 10, 30, 12, 0, 0, TimeSpan.Zero);

    private static object SignIn(string id, DateTimeOffset at, string upn = "jane@contoso.com", int errorCode = 0) => new
    {
        id,
        createdDateTime = at.ToString("O", CultureInfo.InvariantCulture),
        userPrincipalName = upn,
        userId = "u1",
        appDisplayName = "Outlook",
        ipAddress = "203.0.113.1",
        status = new { errorCode, failureReason = errorCode == 0 ? null : "bad password" },
    };

    [Fact]
    public async Task SignIns_first_run_uses_lookback_then_watermark_minus_overlap()
    {
        var time = new FakeTimeProvider(Now);
        var requests = new List<string>();
        var handler = new RoutedGraphHandler()
            .Get(p => p.Contains("/beta/auditLogs/signIns", StringComparison.Ordinal), r => { requests.Add(r.RequestUri!.ToString()); return RoutedGraphHandler.Page([]); })
            .Get(p => p.Contains("/v1.0/auditLogs/signIns", StringComparison.Ordinal), r =>
            {
                requests.Add(r.RequestUri!.ToString());
                return RoutedGraphHandler.Page([SignIn("s2", Now.AddMinutes(-5)), SignIn("s1", Now.AddMinutes(-10), errorCode: 50126)]);
            });
        var client = TestContext.Client(handler, time);
        var pipeline = new FakePipeline();
        var checkpoint = new Checkpoint { TenantId = TestContext.Tenant.Id, Source = "signins" };
        var context = TestContext.Context(client, pipeline, checkpoint, time: time);

        var result = await new SignInsCollector().CollectAsync(context, CancellationToken.None);

        Assert.Equal(2, result.Published);
        Assert.True(result.Complete);
        Assert.Equal(Now.AddMinutes(-5), checkpoint.Watermark);
        Assert.Contains(requests, r => r.Contains("/v1.0/auditLogs/signIns", StringComparison.Ordinal) && r.Contains(Uri.EscapeDataString(OData.Timestamp(Now.AddDays(-7))).Replace("%3A", ":", StringComparison.Ordinal), StringComparison.Ordinal) || r.Contains(OData.Timestamp(Now.AddDays(-7)), StringComparison.Ordinal));
        Assert.Contains(requests, r => r.Contains("/beta/auditLogs/signIns", StringComparison.Ordinal) && r.Contains("signInEventTypes", StringComparison.Ordinal));
        Assert.Contains(pipeline.Events, e => e.RecordId == "s1" && e.Outcome == "failure");
        Assert.Contains(pipeline.Events, e => e.Labels!["signInType"] == "interactive");

        // Second run: window starts at watermark - overlap (30 min default).
        requests.Clear();
        await new SignInsCollector().CollectAsync(TestContext.Context(client, pipeline, checkpoint, time: time), CancellationToken.None);
        var expectedFrom = OData.Timestamp(Now.AddMinutes(-35));
        Assert.Contains(requests, r => r.Contains("/v1.0/", StringComparison.Ordinal) && Uri.UnescapeDataString(r).Contains(expectedFrom, StringComparison.Ordinal));
        Assert.Equal(2, pipeline.Events.Count); // duplicates deduplicated by id
    }

    [Fact]
    public async Task Non_interactive_sign_ins_can_be_disabled_per_tenant()
    {
        var handler = new RoutedGraphHandler()
            .Get(p => p.Contains("/beta/", StringComparison.Ordinal), _ => throw new InvalidOperationException("beta must not be called"))
            .Get(p => p.Contains("/v1.0/auditLogs/signIns", StringComparison.Ordinal), _ => RoutedGraphHandler.Page([]));
        var context = TestContext.Context(TestContext.Client(handler), new FakePipeline(), settings: new SourceSettings { IncludeNonInteractive = false });
        var result = await new SignInsCollector().CollectAsync(context, CancellationToken.None);
        Assert.True(result.Complete);
        Assert.Single(handler.Requests);
    }

    [Fact]
    public async Task Partial_run_resumes_from_oldest_seen_record()
    {
        var handler = new RoutedGraphHandler()
            .Get(p => p.Contains("skiptoken=p1", StringComparison.Ordinal), _ => RoutedGraphHandler.Page([SignIn("old", Now.AddHours(-3))]))
            .Get(p => p.Contains("/v1.0/auditLogs/signIns", StringComparison.Ordinal), _ => RoutedGraphHandler.Page([SignIn("new", Now.AddHours(-1)), SignIn("mid", Now.AddHours(-2))], "https://graph.microsoft.com/v1.0/auditLogs/signIns?$skiptoken=p1"));
        var pipeline = new FakePipeline();
        var checkpoint = new Checkpoint { TenantId = TestContext.Tenant.Id, Source = "signins", Watermark = Now.AddDays(-1) };
        var context = TestContext.Context(TestContext.Client(handler), pipeline, checkpoint, new AuditOptions { MaxPagesPerRun = 1 }, new SourceSettings { IncludeNonInteractive = false });

        var result = await new SignInsCollector().CollectAsync(context, CancellationToken.None);

        Assert.False(result.Complete);
        Assert.Equal(2, result.Published);
        Assert.Equal(Now.AddHours(-2), checkpoint.Watermark); // oldest seen, so "old" is picked up next run
    }

    [Fact]
    public async Task Directory_audits_map_and_advance_watermark()
    {
        var handler = new RoutedGraphHandler().Get(p => p.Contains("directoryAudits", StringComparison.Ordinal), _ => RoutedGraphHandler.Page(
        [
            new { id = "d1", activityDateTime = Now.AddMinutes(-1).ToString("O", CultureInfo.InvariantCulture), activityDisplayName = "Add member to role", category = "RoleManagement", result = "success", initiatedBy = new { user = new { userPrincipalName = "admin@contoso.com", id = "a1" } }, targetResources = new[] { new { type = "User", userPrincipalName = "x@contoso.com" } } },
        ]));
        var pipeline = new FakePipeline();
        var checkpoint = new Checkpoint { TenantId = TestContext.Tenant.Id, Source = "directory" };
        var result = await new DirectoryAuditsCollector().CollectAsync(TestContext.Context(TestContext.Client(handler), pipeline, checkpoint), CancellationToken.None);
        Assert.Equal(1, result.Published);
        Assert.Equal(Now.AddMinutes(-1), checkpoint.Watermark);
        var e = Assert.Single(pipeline.Events);
        Assert.Equal("Add member to role", e.Action);
        Assert.Equal("medium", e.Severity);
        Assert.Equal("x@contoso.com", e.Labels!["targetName"]);
    }

    [Fact]
    public async Task Purview_collector_creates_polls_and_drains_queries()
    {
        var time = new FakeTimeProvider(Now);
        var status = "running";
        string? createdBody = null;
        var handler = new RoutedGraphHandler()
            .Post(p => p.EndsWith("security/auditLog/queries", StringComparison.Ordinal), r =>
            {
                createdBody = r.Content!.ReadAsStringAsync().GetAwaiter().GetResult();
                return FakeGraphHandler.Json(new { id = "q-123", status = "notStarted" }, HttpStatusCode.Created);
            })
            .Get(p => p.Contains("security/auditLog/queries/q-123/records", StringComparison.Ordinal) && p.Contains("skiptoken=r1", StringComparison.Ordinal), _ => RoutedGraphHandler.Page([Record("r3", Now.AddHours(-2))]))
            .Get(p => p.Contains("security/auditLog/queries/q-123/records", StringComparison.Ordinal), _ => RoutedGraphHandler.Page([Record("r1", Now.AddHours(-4)), Record("r2", Now.AddHours(-3))], "https://graph.microsoft.com/v1.0/security/auditLog/queries/q-123/records?$skiptoken=r1"))
            .Get(p => p.Contains("security/auditLog/queries/q-123", StringComparison.Ordinal), _ => FakeGraphHandler.Json(new { id = "q-123", status }));

        var pipeline = new FakePipeline();
        var checkpoint = new Checkpoint { TenantId = TestContext.Tenant.Id, Source = "activity", Watermark = Now.AddHours(-6) };
        var options = new AuditOptions { PurviewLagMinutes = 15, PurviewOverlapMinutes = 60 };
        var collector = new PurviewAuditCollector();

        // Run 1: creates the query for [watermark - overlap, now - lag].
        var r1 = await collector.CollectAsync(TestContext.Context(TestContext.Client(handler, time), pipeline, checkpoint, options, time: time), CancellationToken.None);
        Assert.Equal(0, r1.Published);
        Assert.Contains("q-123", checkpoint.StateJson, StringComparison.Ordinal);
        using (var body = JsonDocument.Parse(createdBody!))
        {
            Assert.Equal(Now.AddHours(-7).UtcDateTime, body.RootElement.GetProperty("filterStartDateTime").GetDateTime());
            Assert.Equal(Now.AddMinutes(-15).UtcDateTime, body.RootElement.GetProperty("filterEndDateTime").GetDateTime());
            Assert.Contains("sharePointFileOperation", body.RootElement.GetProperty("recordTypeFilters").EnumerateArray().Select(e => e.GetString()));
        }

        // Run 2: still running -> nothing changes.
        var r2 = await collector.CollectAsync(TestContext.Context(TestContext.Client(handler, time), pipeline, checkpoint, options, time: time), CancellationToken.None);
        Assert.Equal(0, r2.Published);
        Assert.Contains("running", r2.Note, StringComparison.Ordinal);
        Assert.Equal(Now.AddHours(-6), checkpoint.Watermark);

        // Run 3: succeeded -> records drained across pages, watermark = window end, state cleared.
        status = "succeeded";
        var r3 = await collector.CollectAsync(TestContext.Context(TestContext.Client(handler, time), pipeline, checkpoint, options, time: time), CancellationToken.None);
        Assert.Equal(3, r3.Published);
        Assert.True(r3.Complete);
        Assert.Null(checkpoint.StateJson);
        Assert.Equal(Now.AddMinutes(-15), checkpoint.Watermark);
        Assert.All(pipeline.Events, e => Assert.Equal("activity", e.Source));
        Assert.Contains(pipeline.Events, e => e.FilePath == "https://contoso.sharepoint.com/sites/x/doc.docx" && e.Action == "FileAccessed");

        // Run 4: the next window starts from the new watermark minus overlap.
        createdBody = null;
        status = "running";
        await collector.CollectAsync(TestContext.Context(TestContext.Client(handler, time), pipeline, checkpoint, options, time: time), CancellationToken.None);
        using var body2 = JsonDocument.Parse(createdBody!);
        Assert.Equal(Now.AddMinutes(-75).UtcDateTime, body2.RootElement.GetProperty("filterStartDateTime").GetDateTime());
    }

    [Fact]
    public async Task Purview_failed_query_resets_state_and_throws()
    {
        var handler = new RoutedGraphHandler().Get(p => p.Contains("security/auditLog/queries/q-9", StringComparison.Ordinal), _ => FakeGraphHandler.Json(new { id = "q-9", status = "failed" }));
        var checkpoint = new Checkpoint { TenantId = TestContext.Tenant.Id, Source = "activity", StateJson = """{"pendingQueryId":"q-9","pendingWindowEnd":"2026-10-30T11:45:00Z","pendingCreatedAt":"2026-10-30T11:00:00Z"}""" };
        await Assert.ThrowsAsync<GraphException>(() => new PurviewAuditCollector().CollectAsync(TestContext.Context(TestContext.Client(handler), new FakePipeline(), checkpoint), CancellationToken.None));
        Assert.Null(checkpoint.StateJson);
    }

    [Fact]
    public async Task Purview_rejects_malformed_pending_ids()
    {
        var checkpoint = new Checkpoint { TenantId = TestContext.Tenant.Id, Source = "activity", StateJson = """{"pendingQueryId":"../../etc"}""" };
        var handler = new RoutedGraphHandler();
        await Assert.ThrowsAsync<GraphException>(() => new PurviewAuditCollector().CollectAsync(TestContext.Context(TestContext.Client(handler), new FakePipeline(), checkpoint), CancellationToken.None));
        Assert.Empty(handler.Requests);
    }

    [Fact]
    public async Task Risk_collector_combines_three_feeds_with_change_aware_ids()
    {
        var handler = new RoutedGraphHandler()
            .Get(p => p.Contains("riskDetections", StringComparison.Ordinal), _ => RoutedGraphHandler.Page([new { id = "rd1", riskEventType = "unfamiliarFeatures", riskLevel = "high", riskState = "atRisk", detectedDateTime = Now.AddMinutes(-9).ToString("O", CultureInfo.InvariantCulture), lastUpdatedDateTime = Now.AddMinutes(-8).ToString("O", CultureInfo.InvariantCulture), userPrincipalName = "jane@contoso.com" }]))
            .Get(p => p.Contains("riskyUsers", StringComparison.Ordinal), _ => RoutedGraphHandler.Page([new { id = "u1", riskLevel = "medium", riskState = "atRisk", riskLastUpdatedDateTime = Now.AddMinutes(-7).ToString("O", CultureInfo.InvariantCulture), userPrincipalName = "jane@contoso.com" }]))
            .Get(p => p.Contains("riskyServicePrincipals", StringComparison.Ordinal), _ => RoutedGraphHandler.Page([new { id = "sp1", riskLevel = "low", riskState = "atRisk", riskLastUpdatedDateTime = Now.AddMinutes(-6).ToString("O", CultureInfo.InvariantCulture), displayName = "Legacy app", appId = "app1" }]));
        var pipeline = new FakePipeline();
        var result = await new RiskCollector().CollectAsync(TestContext.Context(TestContext.Client(handler), pipeline), CancellationToken.None);
        Assert.Equal(3, result.Published);
        Assert.Equal(["detection", "user", "servicePrincipal"], pipeline.Events.Select(e => e.Labels!["riskType"]).ToArray());
        Assert.All(pipeline.Events, e => Assert.Equal("risk", e.Source));
        Assert.StartsWith("detection:rd1:", pipeline.Events[0].RecordId, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Security_alerts_and_secure_score_collect()
    {
        var handler = new RoutedGraphHandler()
            .Get(p => p.Contains("security/alerts_v2", StringComparison.Ordinal), _ => RoutedGraphHandler.Page([new { id = "a1", title = "Suspicious", severity = "high", status = "new", category = "Malware", createdDateTime = Now.AddHours(-1).ToString("O", CultureInfo.InvariantCulture), lastUpdateDateTime = Now.AddMinutes(-1).ToString("O", CultureInfo.InvariantCulture) }]))
            .Get(p => p.Contains("security/secureScores", StringComparison.Ordinal), _ => RoutedGraphHandler.Page([new { id = "2026-10-30", createdDateTime = Now.ToString("O", CultureInfo.InvariantCulture), currentScore = 61.5, maxScore = 100 }]));
        var pipeline = new FakePipeline();
        var alerts = await new SecurityAlertsCollector().CollectAsync(TestContext.Context(TestContext.Client(handler), pipeline), CancellationToken.None);
        var score = await new SecureScoreCollector().CollectAsync(TestContext.Context(TestContext.Client(handler), pipeline), CancellationToken.None);
        Assert.Equal(1, alerts.Published);
        Assert.Equal(1, score.Published);
        Assert.Contains(pipeline.Events, e => e.Source == "security-alerts" && e.Kind == "alert" && e.Severity == "high");
        Assert.Contains(pipeline.Events, e => e.Source == "securescore" && e.Labels!["percent"] == "61.5");
    }

    private static object Record(string id, DateTimeOffset at) => new
    {
        id,
        createdDateTime = at.ToString("O", CultureInfo.InvariantCulture),
        auditLogRecordType = "sharePointFileOperation",
        operation = "FileAccessed",
        userPrincipalName = "bob@contoso.com",
        userId = "bob@contoso.com",
        service = "SharePoint",
        objectId = "https://contoso.sharepoint.com/sites/x/doc.docx",
        clientIp = "198.51.100.7",
        auditData = new { Workload = "SharePoint", ResultStatus = "Succeeded", SourceFileName = "doc.docx" },
    };
}
