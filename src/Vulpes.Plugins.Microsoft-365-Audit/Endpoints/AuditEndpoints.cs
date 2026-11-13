using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.EntityFrameworkCore;
using Vulpes.Plugins.Microsoft365Audit.Data;
using Vulpes.Plugins.Microsoft365Audit.Normalization;
using Vulpes.Plugins.Microsoft365Audit.Scheduling;
using Vulpes.Plugins.Microsoft365Audit.Tenants;
using Vulpes.Sdk;

namespace Vulpes.Plugins.Microsoft365Audit.Endpoints;

/// <summary>Plugin API under <c>/api/plugins/microsoft-365-audit</c>. The group already requires authentication; roles are added per endpoint.</summary>
public static class AuditEndpoints
{
    public sealed record FilterDto(string Field, string Operator, IReadOnlyList<string>? Values);
    public sealed record SearchRequest(string? Source, DateTimeOffset? From, DateTimeOffset? To, IReadOnlyList<FilterDto>? Filters, string? Text, int? Size, IReadOnlyList<JsonElement>? SearchAfter, string? Sort);
    public sealed record AggregationDto(string Name, string Kind, string? Field, int? Size, string? Interval);
    public sealed record AggregateRequest(string? Source, DateTimeOffset? From, DateTimeOffset? To, IReadOnlyList<FilterDto>? Filters, string? Text, IReadOnlyList<AggregationDto>? Aggregations);
    public sealed record CollectionRequest(int? LookbackDays, TenantSettings? Settings);

    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web) { DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull };

    public static void Map(IEndpointRouteBuilder group)
    {
        ArgumentNullException.ThrowIfNull(group);

        // Read-only data for every dashboard role.
        group.MapGet("/sources", GetSources).RequireAuthorization(Policies.Viewer);
        group.MapPost("/search", SearchAsync).RequireAuthorization(Policies.Viewer);
        group.MapPost("/aggregate", AggregateAsync).RequireAuthorization(Policies.Viewer);
        group.MapGet("/events/{source}/{id}", GetEventAsync).RequireAuthorization(Policies.Viewer);
        group.MapGet("/overview", OverviewAsync).RequireAuthorization(Policies.Viewer);
        group.MapGet("/tenants/names", TenantNamesAsync).RequireAuthorization(Policies.Viewer);

        // Ingestion status is for analysts. Collection settings are edited from Manage → Tenants.
        group.MapGet("/status", StatusAsync).RequireAuthorization(Policies.Analyst);
        group.MapGet("/tenants/{id:guid}", GetTenantAsync).RequireAuthorization(Policies.Analyst);
        group.MapPut("/tenants/{id:guid}/collection", UpdateCollectionAsync).RequireAuthorization(Policies.Admin);
        group.MapPost("/tenants/{id:guid}/purge", PurgeTenantAsync).RequireAuthorization(Policies.Admin);
        group.MapGet("/settings", GetSettings).RequireAuthorization(Policies.Admin);
        group.MapPut("/settings", PutSettings).RequireAuthorization(Policies.Admin);
        group.MapGet("/statistics", StatisticsAsync).RequireAuthorization(Policies.Admin);
        group.MapGet("/bot/tokens", ListBotTokensAsync).RequireAuthorization(Policies.Admin);
        group.MapPost("/bot/tokens", CreateBotTokenAsync).RequireAuthorization(Policies.Admin);
        group.MapDelete("/bot/tokens/{id:guid}", RevokeBotTokenAsync).RequireAuthorization(Policies.Admin);
        group.MapPost("/mcp", AuditMcp.HandleAsync).AllowAnonymous();
        // Streamable HTTP clients open a GET to listen for server messages. This server does not stream that way. 405 tells them to use POST, instead of the group auth turning the probe into a 401.
        group.MapGet("/mcp", McpListen).AllowAnonymous();
    }

    private static IResult McpListen(HttpResponse response)
    {
        response.Headers.Append("Allow", "POST");
        return Results.StatusCode(StatusCodes.Status405MethodNotAllowed);
    }

    private static IResult GetSettings(AuditSettingsStore store) => Results.Json(store.Current(), Json);

    private static IResult PutSettings(AuditSettingsDocument input, AuditSettingsStore store)
    {
        ArgumentNullException.ThrowIfNull(input);
        var error = store.Save(input);
        return error is null ? Results.Json(store.Current(), Json) : Error(400, "validation", error);
    }

    private static IResult Error(int status, string code, string message) => Results.Json(new { error = code, message }, Json, statusCode: status);

    private static IResult GetSources(IAlertFieldCatalog catalog, CollectionScheduler scheduler, AuditOptions options) =>
        Results.Json(catalog.GetSources(Normalizers.PluginId).Select(s => new
        {
            s.Source,
            s.Title,
            mode = s.Mode.ToString(),
            fields = catalog.GetFields(Normalizers.PluginId, s.Source).Where(f => f.Filterable).Select(f => new { f.Path, f.Label, type = f.Type.ToString() }).ToList(),
            unavailable = !options.Collects(s.Source),
            hidden = options.HideRiskMenu && s.Source == "risk",
            collector = scheduler.Collectors.TryGetValue(s.Source, out var c) ? new { c.Title, permissions = c.RequiredPermissions, defaultIntervalMinutes = (int)options.IntervalFor(s.Source).TotalMinutes } : null,
        }).ToList(), Json);

    private static async Task<IResult> SearchAsync(SearchRequest request, IEventSearch search, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (string.IsNullOrEmpty(request.Source))
        {
            return Error(400, "validation", "source is required.");
        }

        try
        {
            var result = await search.SearchAsync(new EventQuery
            {
                PluginId = Normalizers.PluginId,
                Source = request.Source,
                From = request.From,
                To = request.To,
                Filters = MapFilters(request.Filters),
                FreeText = request.Text,
                Size = request.Size ?? 50,
                SearchAfter = request.SearchAfter,
                Sort = string.Equals(request.Sort, "asc", StringComparison.OrdinalIgnoreCase) ? SortDirection.Ascending : SortDirection.Descending,
            }, ct);
            return Results.Json(new { total = result.Total, totalIsExact = result.TotalIsExact, hits = result.Hits.Select(h => new { h.Id, doc = h.Document, h.Sort }).ToList() }, Json);
        }
        catch (ArgumentException ex)
        {
            return Error(400, "validation", ex.Message);
        }
        catch (Exception ex) when (ex.GetType().Name == "SearchUnavailableException")
        {
            return Error(503, "search_unavailable", ex.Message);
        }
    }

    private static async Task<IResult> AggregateAsync(AggregateRequest request, IEventSearch search, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (string.IsNullOrEmpty(request.Source))
        {
            return Error(400, "validation", "source is required.");
        }

        try
        {
            var result = await search.AggregateAsync(new EventAggregationQuery
            {
                PluginId = Normalizers.PluginId,
                Source = request.Source,
                From = request.From,
                To = request.To,
                Filters = MapFilters(request.Filters),
                FreeText = request.Text,
                Aggregations = (request.Aggregations ?? []).Select(a => new AggregationSpec(a.Name, ParseKind(a.Kind), a.Field ?? "@timestamp", a.Size ?? 10, a.Interval)).ToList(),
            }, ct);
            return Results.Json(result, Json);
        }
        catch (ArgumentException ex)
        {
            return Error(400, "validation", ex.Message);
        }
        catch (Exception ex) when (ex.GetType().Name == "SearchUnavailableException")
        {
            return Error(503, "search_unavailable", ex.Message);
        }
    }

    private static async Task<IResult> GetEventAsync(string source, string id, IEventSearch search, CancellationToken ct)
    {
        try
        {
            var doc = await search.GetAsync(Normalizers.PluginId, source, id, ct);
            return doc is null ? Error(404, "not_found", "Event not found.") : Results.Json(doc, Json);
        }
        catch (ArgumentException ex)
        {
            return Error(400, "validation", ex.Message);
        }
    }

    /// <summary>KPIs for the overview page, computed with a handful of aggregations.</summary>
    private static async Task<IResult> OverviewAsync(int? hours, string? tenantId, IEventSearch search, AuditDbContext db, CancellationToken ct)
    {
        var window = Math.Clamp(hours ?? 24, 1, 24 * 30);
        var to = DateTimeOffset.UtcNow;
        var from = to.AddHours(-window);
        var interval = window <= 24 ? "1h" : window <= 24 * 7 ? "6h" : "1d";
        var tenantFilter = string.IsNullOrEmpty(tenantId) ? new List<FieldFilter>() : [new FieldFilter("vc.tenantId", FilterOperator.Equals, [tenantId])];

        async Task<EventAggregationResult?> Agg(string source, IReadOnlyList<FieldFilter> extra, params AggregationSpec[] specs)
        {
            try
            {
                return await search.AggregateAsync(new EventAggregationQuery { PluginId = Normalizers.PluginId, Source = source, From = from, To = to, Filters = tenantFilter.Concat(extra).ToList(), Aggregations = specs }, ct);
            }
            catch (Exception ex) when (ex is ArgumentException || ex.GetType().Name == "SearchUnavailableException")
            {
                return null;
            }
        }

        var failure = new[] { new FieldFilter("event.outcome", FilterOperator.Equals, ["failure"]) };
        var signIns = await Agg(Sources.SignIns, [], new AggregationSpec("perHour", AggregationKind.DateHistogram, "@timestamp", Interval: interval), new AggregationSpec("byCountry", AggregationKind.Terms, "source.geo.country_name", 8), new AggregationSpec("byApp", AggregationKind.Terms, "client.appName", 8));
        var failures = await Agg(Sources.SignIns, failure, new AggregationSpec("perHour", AggregationKind.DateHistogram, "@timestamp", Interval: interval), new AggregationSpec("byUser", AggregationKind.Terms, "user.name", 10), new AggregationSpec("byIp", AggregationKind.Terms, "source.address", 10), new AggregationSpec("byReason", AggregationKind.Terms, "data.status.failureReason", 8));
        var activity = await Agg(Sources.Activity, [], new AggregationSpec("perHour", AggregationKind.DateHistogram, "@timestamp", Interval: interval), new AggregationSpec("byWorkload", AggregationKind.Terms, "labels.workload", 10), new AggregationSpec("byOperation", AggregationKind.Terms, "event.action", 10), new AggregationSpec("byUser", AggregationKind.Terms, "user.name", 10));
        var directory = await Agg(Sources.Directory, [], new AggregationSpec("byActivity", AggregationKind.Terms, "event.action", 10), new AggregationSpec("byActor", AggregationKind.Terms, "user.name", 10));
        var alerts = await Agg(Sources.SecurityAlerts, [], new AggregationSpec("bySeverity", AggregationKind.Terms, "event.severity", 5), new AggregationSpec("byStatus", AggregationKind.Terms, "labels.status", 5));
        var risk = await Agg(Sources.Risk, [new FieldFilter("labels.riskType", FilterOperator.Equals, ["detection"])], new AggregationSpec("byLevel", AggregationKind.Terms, "labels.riskLevel", 5), new AggregationSpec("byType", AggregationKind.Terms, "event.action", 10));
        var system = await Agg(Sources.System, [], new AggregationSpec("byCollector", AggregationKind.Terms, "labels.collector", 10));
        var secureScores = await SecureScoresAsync(search, db, tenantId, ct);

        return Results.Json(new
        {
            from,
            to,
            interval,
            available = search.IsAvailable && signIns is not null,
            signIns = new { total = signIns?.Total ?? 0, perHour = signIns?.Aggregations.GetValueOrDefault("perHour"), byCountry = signIns?.Aggregations.GetValueOrDefault("byCountry"), byApp = signIns?.Aggregations.GetValueOrDefault("byApp") },
            failures = new { total = failures?.Total ?? 0, perHour = failures?.Aggregations.GetValueOrDefault("perHour"), byUser = failures?.Aggregations.GetValueOrDefault("byUser"), byIp = failures?.Aggregations.GetValueOrDefault("byIp"), byReason = failures?.Aggregations.GetValueOrDefault("byReason") },
            activity = new { total = activity?.Total ?? 0, perHour = activity?.Aggregations.GetValueOrDefault("perHour"), byWorkload = activity?.Aggregations.GetValueOrDefault("byWorkload"), byOperation = activity?.Aggregations.GetValueOrDefault("byOperation"), byUser = activity?.Aggregations.GetValueOrDefault("byUser") },
            directory = new { total = directory?.Total ?? 0, byActivity = directory?.Aggregations.GetValueOrDefault("byActivity"), byActor = directory?.Aggregations.GetValueOrDefault("byActor") },
            alerts = new { total = alerts?.Total ?? 0, bySeverity = alerts?.Aggregations.GetValueOrDefault("bySeverity"), byStatus = alerts?.Aggregations.GetValueOrDefault("byStatus") },
            risk = new { total = risk?.Total ?? 0, byLevel = risk?.Aggregations.GetValueOrDefault("byLevel"), byType = risk?.Aggregations.GetValueOrDefault("byType") },
            collectorFailures = new { total = system?.Total ?? 0, byCollector = system?.Aggregations.GetValueOrDefault("byCollector") },
            secureScores,
        }, Json);
    }

    private sealed record SecureScoreRow(string Name, string TenantId, string? Current, string? Max, string? Percent, string? At);

    private static async Task<IReadOnlyList<SecureScoreRow>> SecureScoresAsync(IEventSearch search, AuditDbContext db, string? tenantId, CancellationToken ct)
    {
        var clients = await db.Tenants.AsNoTracking().OrderBy(t => t.DisplayName).ToListAsync(ct);
        if (!string.IsNullOrEmpty(tenantId))
        {
            clients = clients.Where(t => t.TenantId == tenantId).ToList();
        }

        var latest = new Dictionary<string, SecureScoreRow>(StringComparer.OrdinalIgnoreCase);
        try
        {
            var found = await search.SearchAsync(new EventQuery
            {
                PluginId = Normalizers.PluginId,
                Source = Sources.SecureScore,
                Size = 200,
                Sort = SortDirection.Descending,
                Filters = string.IsNullOrEmpty(tenantId) ? [] : [new FieldFilter("vc.tenantId", FilterOperator.Equals, [tenantId])],
            }, ct);
            foreach (var hit in found.Hits)
            {
                var id = Text(hit.Document, "vc", "tenantId");
                if (string.IsNullOrEmpty(id) || latest.ContainsKey(id))
                {
                    continue;
                }

                latest[id] = new SecureScoreRow(
                    Text(hit.Document, "vc", "tenantName") ?? id,
                    id,
                    Text(hit.Document, "labels", "currentScore") ?? Text(hit.Document, "data", "currentScore"),
                    Text(hit.Document, "labels", "maxScore") ?? Text(hit.Document, "data", "maxScore"),
                    Text(hit.Document, "labels", "percent"),
                    Stamp(hit.Document));
            }
        }
        catch (Exception ex) when (ex is ArgumentException || ex.GetType().Name == "SearchUnavailableException")
        {
        }

        return clients.Select(t => latest.TryGetValue(t.TenantId, out var score)
            ? score with { Name = t.DisplayName }
            : new SecureScoreRow(t.DisplayName, t.TenantId, null, null, null, null)).ToList();
    }

    private static string? Stamp(JsonElement doc) =>
        doc.ValueKind == JsonValueKind.Object && doc.TryGetProperty("@timestamp", out var stamp) && stamp.ValueKind == JsonValueKind.String ? stamp.GetString() : null;

    private static string? Text(JsonElement doc, string parent, string name)
    {
        if (doc.ValueKind != JsonValueKind.Object || !doc.TryGetProperty(parent, out var node) || node.ValueKind != JsonValueKind.Object || !node.TryGetProperty(name, out var value))
        {
            return null;
        }

        return value.ValueKind == JsonValueKind.String ? value.GetString() : value.ToString();
    }

    private static async Task<IResult> StatisticsAsync(IEventSearch search, IAlertFieldCatalog catalog, CancellationToken ct)
    {
        if (!search.IsAvailable)
        {
            return Results.Json(new { available = false, documents = 0L, storedBytes = 0L, diskBytes = 0L, sources = Array.Empty<object>(), tenants = Array.Empty<object>() }, Json);
        }

        EventStoreUsage usage;
        try
        {
            usage = await search.StoreUsageAsync(Normalizers.PluginId, ct);
        }
        catch (Exception ex) when (ex.GetType().Name == "SearchUnavailableException")
        {
            return Error(503, "search_unavailable", "Elasticsearch is not reachable.");
        }

        var titles = catalog.GetSources(Normalizers.PluginId).ToDictionary(s => s.Source, s => s.Title, StringComparer.Ordinal);
        var tenants = new Dictionary<string, (long Docs, double Bytes)>(StringComparer.OrdinalIgnoreCase);
        var spans = new Dictionary<string, (DateTimeOffset? Oldest, DateTimeOffset? Newest)>(StringComparer.Ordinal);
        foreach (var source in usage.Sources.Where(s => s.Documents > 0))
        {
            try
            {
                var oldest = await search.SearchAsync(new EventQuery { PluginId = Normalizers.PluginId, Source = source.Source, Size = 1, Sort = SortDirection.Ascending }, ct);
                var newest = await search.SearchAsync(new EventQuery { PluginId = Normalizers.PluginId, Source = source.Source, Size = 1, Sort = SortDirection.Descending }, ct);
                spans[source.Source] = (Timestamp(oldest), Timestamp(newest));

                var agg = await search.AggregateAsync(new EventAggregationQuery
                {
                    PluginId = Normalizers.PluginId,
                    Source = source.Source,
                    Aggregations = [new AggregationSpec("tenants", AggregationKind.Terms, "vc.tenantName", 50)],
                }, ct);
                if (!agg.Aggregations.TryGetValue("tenants", out var buckets))
                {
                    continue;
                }

                long counted = 0;
                foreach (var bucket in buckets)
                {
                    counted += bucket.Count;
                    var name = string.IsNullOrWhiteSpace(bucket.Key) || bucket.Key == "(none)" ? "Unknown" : bucket.Key;
                    var share = (double)bucket.Count / source.Documents * source.StoredBytes;
                    tenants.TryGetValue(name, out var current);
                    tenants[name] = (current.Docs + bucket.Count, current.Bytes + share);
                }

                var remainder = source.Documents - counted;
                if (remainder > 0)
                {
                    var share = (double)remainder / source.Documents * source.StoredBytes;
                    tenants.TryGetValue("Other clients", out var current);
                    tenants["Other clients"] = (current.Docs + remainder, current.Bytes + share);
                }
            }
            catch (Exception ex) when (ex is ArgumentException || ex.GetType().Name == "SearchUnavailableException")
            {
            }
        }

        return Results.Json(new
        {
            available = usage.Available,
            documents = usage.Documents,
            storedBytes = usage.StoredBytes,
            diskBytes = usage.DiskBytes,
            sources = usage.Sources.Select(s =>
            {
                spans.TryGetValue(s.Source, out var span);
                return new
                {
                    s.Source,
                    title = titles.GetValueOrDefault(s.Source) ?? s.Source,
                    documents = s.Documents,
                    storedBytes = s.StoredBytes,
                    diskBytes = s.DiskBytes,
                    oldest = span.Oldest,
                    newest = span.Newest,
                };
            }).OrderByDescending(s => s.storedBytes).ThenBy(s => s.title, StringComparer.OrdinalIgnoreCase),
            tenants = tenants
                .Select(t => new { name = t.Key, documents = t.Value.Docs, estimatedBytes = (long)Math.Round(t.Value.Bytes) })
                .OrderByDescending(t => t.estimatedBytes)
                .ThenBy(t => t.name, StringComparer.OrdinalIgnoreCase),
        }, Json);
    }

    private static DateTimeOffset? Timestamp(EventSearchResult result)
    {
        if (result.Hits.Count == 0 || result.Hits[0].Document.ValueKind != JsonValueKind.Object)
        {
            return null;
        }

        if (!result.Hits[0].Document.TryGetProperty("@timestamp", out var stamp) || stamp.ValueKind != JsonValueKind.String)
        {
            return null;
        }

        return DateTimeOffset.TryParse(stamp.GetString(), System.Globalization.CultureInfo.InvariantCulture, System.Globalization.DateTimeStyles.RoundtripKind, out var parsed) ? parsed : null;
    }

    private static async Task<IResult> TenantNamesAsync(AuditDbContext db, CancellationToken ct) =>
        Results.Json(await db.Tenants.AsNoTracking().OrderBy(t => t.DisplayName).Select(t => new { t.Id, t.TenantId, t.DisplayName, t.DiscoveredName, t.Enabled }).ToListAsync(ct), Json);

    private static async Task<IResult> StatusAsync(AuditDbContext db, CollectionScheduler scheduler, IEventSearch search, CancellationToken ct)
    {
        var tenants = await db.Tenants.AsNoTracking().OrderBy(t => t.DisplayName).ToListAsync(ct);
        var checkpoints = await db.Checkpoints.AsNoTracking().ToListAsync(ct);
        var runs = RunQueries.LatestPerQuery(await db.RunLog.AsNoTracking().OrderByDescending(r => r.Id).Take(500).ToListAsync(ct)).Take(100).ToList();
        var tenantNames = tenants.ToDictionary(t => t.Id, t => t.DisplayName);
        var stored = new Dictionary<(string Source, string TenantId), long>();
        if (search.IsAvailable)
        {
            foreach (var collector in scheduler.Collectors.Values)
            {
                try
                {
                    var counts = await search.AggregateAsync(new EventAggregationQuery
                    {
                        PluginId = Normalizers.PluginId,
                        Source = collector.Source,
                        Aggregations = [new AggregationSpec("tenants", AggregationKind.Terms, "vc.tenantId", 50)],
                    }, ct);
                    if (!counts.Aggregations.TryGetValue("tenants", out var buckets))
                    {
                        continue;
                    }

                    foreach (var bucket in buckets)
                    {
                        if (bucket.Key.Length > 0)
                        {
                            stored[(collector.Source, bucket.Key)] = bucket.Count;
                        }
                    }
                }
                catch (Exception ex) when (ex is not OperationCanceledException)
                {
                    // A missing count API, or a failed count, must not take down the status page.
                }
            }
        }

        return Results.Json(new
        {
            sources = scheduler.Collectors.Values.Select(c => new { c.Source, c.Title }).OrderBy(c => c.Source, StringComparer.Ordinal).ToList(),
            tenants = tenants.Select(t => new
            {
                t.Id,
                t.DisplayName,
                t.Enabled,
                checkpoints = checkpoints.Where(c => c.TenantId == t.Id).Select(c => new
                {
                    c.Source,
                    c.Watermark,
                    c.LastRunAt,
                    c.LastSuccessAt,
                    lastStatus = scheduler.IsRunning(t.Id, c.Source) ? RunStatuses.Running : c.LastStatus,
                    c.LastError,
                    c.LastCount,
                    c.TotalCount,
                    storedCount = stored.TryGetValue((c.Source, t.TenantId), out var count) ? count : (long?)null,
                    c.NextRunAt,
                    c.ConsecutiveFailures,
                }).ToList(),
            }).ToList(),
            recentRuns = runs.Select(r => new { r.Id, r.TenantId, tenant = tenantNames.GetValueOrDefault(r.TenantId), r.Source, r.StartedAt, r.FinishedAt, r.Status, r.Count, r.Duplicates, r.Failed, r.Alerts, r.Error }).ToList(),
        }, Json);
    }

    private static async Task<IResult> GetTenantAsync(Guid id, TenantService tenants, AuditDbContext db, ITenantDirectory directory, IEntraApplication application, CancellationToken ct)
    {
        var remote = await directory.ListAsync(ct);
        var shared = await application.GetAsync(ct);
        if (remote.Count > 0 || shared is not null)
        {
            await tenants.SyncFromDirectoryAsync(remote, shared, ct);
        }

        var tenant = await tenants.FindAsync(id, ct);
        if (tenant is null)
        {
            return Error(404, "not_found", "Tenant not found.");
        }

        var checkpoints = await db.Checkpoints.AsNoTracking().Where(c => c.TenantId == id).ToListAsync(ct);
        return Results.Json(TenantService.ToDto(tenant, checkpoints), Json);
    }

    private static async Task<IResult> PurgeTenantAsync(Guid id, AuditDbContext db, CollectionScheduler scheduler, IEventStoreMaintenance store, IEventStoreReadiness readiness, IHostAuditLog audit, CancellationToken ct)
    {
        var tenant = await db.Tenants.FirstOrDefaultAsync(t => t.Id == id, ct);
        if (tenant is null)
        {
            return Error(404, "not_found", "Client not found.");
        }

        if (!readiness.IsReady)
        {
            return Error(503, "search_unavailable", "Elasticsearch is not ready.");
        }

        if (!scheduler.TryBeginPurge(id))
        {
            return Error(409, "busy", "A collector is still running for this client. Try again when it finishes.");
        }

        try
        {
            long? deleted;
            try
            {
                deleted = await store.DeleteTenantAsync(Normalizers.PluginId, tenant.TenantId, ct);
            }
            catch (ArgumentException ex)
            {
                return Error(400, "validation", ex.Message);
            }
            catch (Exception ex) when (ex.GetType().Name == "SearchUnavailableException")
            {
                return Error(503, "search_unavailable", "Elasticsearch could not delete the stored logs.");
            }

            var checkpoints = await db.Checkpoints.Where(c => c.TenantId == id).ToListAsync(ct);
            db.Checkpoints.RemoveRange(checkpoints);
            var runs = await db.RunLog.Where(r => r.TenantId == id).ToListAsync(ct);
            db.RunLog.RemoveRange(runs);
            await db.SaveChangesAsync(ct);
            await audit.RecordAsync("audit.tenant.purged", tenant.DisplayName, $"directory={tenant.TenantId} deleted={deleted?.ToString(System.Globalization.CultureInfo.InvariantCulture) ?? "0"}", cancellationToken: ct);
            return Results.Json(new { deleted = deleted ?? 0 }, Json);
        }
        finally
        {
            scheduler.EndPurge(id);
        }
    }

    private static async Task<IResult> UpdateCollectionAsync(Guid id, CollectionRequest request, TenantService tenants, ITenantDirectory directory, IEntraApplication application, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(request);
        var remote = await directory.ListAsync(ct);
        var shared = await application.GetAsync(ct);
        if (remote.Count > 0 || shared is not null)
        {
            await tenants.SyncFromDirectoryAsync(remote, shared, ct);
        }

        var error = await tenants.UpdateCollectionAsync(id, request.LookbackDays, request.Settings, ct);
        return error is null ? Results.NoContent() : Error(400, "validation", error);
    }

    private static async Task<IResult> ListBotTokensAsync(AuditDbContext db, CancellationToken ct) =>
        Results.Json(await db.BotTokens.AsNoTracking().OrderByDescending(t => t.CreatedAt).Select(t => new { t.Id, t.Name, t.Prefix, t.CreatedAt, t.ExpiresAt, t.LastUsedAt, revoked = t.RevokedAt != null }).ToListAsync(ct), Json);

    private static async Task<IResult> CreateBotTokenAsync(BotTokenName body, AuditDbContext db, IHostAuditLog audit, TimeProvider time, CancellationToken ct)
    {
        var name = body.Name?.Trim() ?? string.Empty;
        if (name.Length is < 1 or > 80)
        {
            return Error(400, "validation", "Name must be 1 to 80 characters.");
        }

        if (await db.BotTokens.CountAsync(t => t.RevokedAt == null, ct) >= 10)
        {
            return Error(400, "validation", "Revoke an existing token before creating another. Ten active tokens is the limit.");
        }

        var secret = AuditMcp.CreateSecret();
        var created = time.GetUtcNow();
        var row = new BotToken { Id = Guid.NewGuid(), Name = name, Prefix = secret[..12], TokenHash = AuditMcp.Hash(secret), CreatedAt = created, ExpiresAt = created + AuditMcp.TokenLifetime };
        db.BotTokens.Add(row);
        await db.SaveChangesAsync(ct);
        await audit.RecordAsync("audit.bot_token.created", row.Id.ToString(), name, cancellationToken: ct);
        return Results.Json(new { row.Id, row.Name, row.Prefix, token = secret }, Json);
    }

    private static async Task<IResult> RevokeBotTokenAsync(Guid id, AuditDbContext db, IHostAuditLog audit, TimeProvider time, CancellationToken ct)
    {
        var row = await db.BotTokens.FirstOrDefaultAsync(t => t.Id == id, ct);
        if (row is null)
        {
            return Error(404, "not_found", "Token not found.");
        }

        if (row.RevokedAt is null)
        {
            row.RevokedAt = time.GetUtcNow();
            await db.SaveChangesAsync(ct);
            await audit.RecordAsync("audit.bot_token.revoked", row.Id.ToString(), row.Name, cancellationToken: ct);
        }

        return Results.NoContent();
    }

    private sealed record BotTokenName(string? Name);

    internal static List<FieldFilter> MapFilters(IReadOnlyList<FilterDto>? filters)
    {
        var result = new List<FieldFilter>();
        foreach (var f in filters ?? [])
        {
            if (string.IsNullOrWhiteSpace(f.Field))
            {
                throw new ArgumentException("Filter field is required.");
            }

            var op = f.Operator?.ToLowerInvariant() switch
            {
                "equals" or "eq" or "is" => FilterOperator.Equals,
                "notequals" or "ne" or "not" => FilterOperator.NotEquals,
                "in" => FilterOperator.In,
                "notin" => FilterOperator.NotIn,
                "prefix" or "startswith" => FilterOperator.Prefix,
                "contains" => FilterOperator.Contains,
                "exists" => FilterOperator.Exists,
                "notexists" or "missing" => FilterOperator.NotExists,
                "gt" => FilterOperator.GreaterThan,
                "lt" => FilterOperator.LessThan,
                _ => throw new ArgumentException($"Unknown filter operator '{f.Operator}'."),
            };
            result.Add(new FieldFilter(f.Field.Trim(), op, f.Values ?? []));
        }

        return result;
    }

    private static AggregationKind ParseKind(string kind) => kind?.ToLowerInvariant() switch
    {
        "terms" => AggregationKind.Terms,
        "datehistogram" or "date_histogram" or "histogram" => AggregationKind.DateHistogram,
        _ => throw new ArgumentException($"Unknown aggregation kind '{kind}'."),
    };
}
