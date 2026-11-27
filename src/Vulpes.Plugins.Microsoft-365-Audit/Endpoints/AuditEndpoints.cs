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

    internal static async Task<IResult> AggregateAsync(AggregateRequest request, IEventSearch search, CancellationToken ct)
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
                Aggregations = (request.Aggregations ?? []).Select(a => new AggregationSpec(a.Name, ParseKind(a.Kind), AggregationField(a.Kind, a.Field), a.Size ?? 10, a.Interval)).ToList(),
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

    internal static async Task<IResult> GetEventAsync(string source, string id, IEventSearch search, CancellationToken ct)
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
        catch (Exception ex) when (ex.GetType().Name == "SearchUnavailableException")
        {
            return Error(503, "search_unavailable", ex.Message);
        }
    }

    /// <summary>KPIs for the overview page, computed with a handful of aggregations.</summary>
    private static async Task<IResult> OverviewAsync(int? hours, string? tenantId, IEventSearch search, AuditDbContext db, ISharedClientDirectory clients, CancellationToken ct)
    {
        var window = Math.Clamp(hours ?? 24, 1, 24 * 730);
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
        var secureScores = await SecureScoresAsync(search, db, tenantId, await DisabledClientIds.LoadAsync(clients, ct), ct);

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

    private static async Task<IReadOnlyList<SecureScoreRow>> SecureScoresAsync(IEventSearch search, AuditDbContext db, string? tenantId, HashSet<Guid> hidden, CancellationToken ct)
    {
        var clients = await db.Tenants.AsNoTracking().Where(t => !hidden.Contains(t.Id)).ToListAsync(ct);
        clients.Sort(static (left, right) => string.Compare(left.DisplayName, right.DisplayName, StringComparison.OrdinalIgnoreCase));
        if (!string.IsNullOrEmpty(tenantId))
        {
            clients = clients.Where(t => t.TenantId == tenantId).ToList();
        }

        var latest = new Dictionary<string, SecureScoreRow>(StringComparer.OrdinalIgnoreCase);
        foreach (var client in clients)
        {
            try
            {
                var found = await search.SearchAsync(new EventQuery
                {
                    PluginId = Normalizers.PluginId,
                    Source = Sources.SecureScore,
                    Size = 1,
                    Sort = SortDirection.Descending,
                    Filters = [new FieldFilter("vc.tenantId", FilterOperator.Equals, [client.TenantId])],
                }, ct);
                if (found.Hits.Count == 0)
                {
                    continue;
                }

                var hit = found.Hits[0];

                latest[client.TenantId] = new SecureScoreRow(
                    client.DisplayName,
                    client.TenantId,
                    Text(hit.Document, "labels", "currentScore") ?? Text(hit.Document, "data", "currentScore"),
                    Text(hit.Document, "labels", "maxScore") ?? Text(hit.Document, "data", "maxScore"),
                    Text(hit.Document, "labels", "percent"),
                    Stamp(hit.Document));
            }
            catch (Exception ex) when (ex is ArgumentException || ex.GetType().Name == "SearchUnavailableException")
            {
                break;
            }
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

    internal static async Task<IResult> StatisticsAsync(IEventSearch search, IAlertFieldCatalog catalog, ISharedClientDirectory clients, CancellationToken ct)
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

        var directory = await clients.ListAllAsync(ct);
        var hidden = directory.Where(client => client.Disabled && !string.IsNullOrWhiteSpace(client.DirectoryId)).Select(client => client.DirectoryId).ToList();
        var titles = catalog.GetSources(Normalizers.PluginId).ToDictionary(s => s.Source, s => s.Title, StringComparer.Ordinal);
        var usageRows = new List<(string Key, long Count, double Bytes)>();
        var spans = new Dictionary<string, (DateTimeOffset? Oldest, DateTimeOffset? Newest)>(StringComparer.Ordinal);
        foreach (var source in usage.Sources.Where(s => s.Documents > 0))
        {
            try
            {
                var oldest = await search.SearchAsync(new EventQuery { PluginId = Normalizers.PluginId, Source = source.Source, Size = 1, Sort = SortDirection.Ascending }, ct);
                var newest = await search.SearchAsync(new EventQuery { PluginId = Normalizers.PluginId, Source = source.Source, Size = 1, Sort = SortDirection.Descending }, ct);
                spans[source.Source] = (Timestamp(oldest), Timestamp(newest));

                // More than 100 values is rejected by search. Skip the filter; TenantBreakdown still drops disabled directory ids.
                var hideDisabled = hidden.Count > 0 && hidden.Count <= 100;
                var agg = await search.AggregateAsync(new EventAggregationQuery
                {
                    PluginId = Normalizers.PluginId,
                    Source = source.Source,
                    Filters = hideDisabled ? [new FieldFilter("vc.tenantId", FilterOperator.NotIn, hidden)] : [],
                    Aggregations = [new AggregationSpec("tenants", AggregationKind.Terms, "vc.tenantId", 50)],
                }, ct);
                if (!agg.Aggregations.TryGetValue("tenants", out var buckets))
                {
                    continue;
                }

                // StoredBytes is the whole index. NotIn shrinks agg.Total, which would paint hidden bytes onto the rows that remain, including Other clients.
                var denominator = hidden.Count > 0 && source.Documents > 0
                    ? source.Documents
                    : (agg.Total > 0 ? agg.Total : source.Documents);
                foreach (var bucket in buckets)
                {
                    var share = denominator == 0 ? 0 : (double)bucket.Count / denominator * source.StoredBytes;
                    var key = string.IsNullOrWhiteSpace(bucket.Key) || bucket.Key == "(none)" ? "\0unknown" : bucket.Key;
                    AddUsage(usageRows, key, bucket.Count, share);
                }
            }
            catch (Exception ex) when (ex is ArgumentException || ex.GetType().Name == "SearchUnavailableException")
            {
            }
        }

        var tenants = TenantBreakdown(usageRows, directory);

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
                .Select(t => new { name = t.Name, documents = t.Documents, estimatedBytes = t.EstimatedBytes })
                .OrderBy(t => t.name, StringComparer.OrdinalIgnoreCase)
                .ThenByDescending(t => t.estimatedBytes),
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

    private static async Task<IResult> TenantNamesAsync(AuditDbContext db, ISharedClientDirectory clients, CancellationToken ct)
    {
        var hidden = await DisabledClientIds.LoadAsync(clients, ct);
        var names = await db.Tenants.AsNoTracking().Where(t => !hidden.Contains(t.Id)).Select(t => new { t.Id, t.TenantId, t.DisplayName, t.DiscoveredName, t.Enabled }).ToListAsync(ct);
        names.Sort(static (left, right) => string.Compare(left.DisplayName, right.DisplayName, StringComparison.OrdinalIgnoreCase));
        return Results.Json(names, Json);
    }

    private static async Task<IResult> StatusAsync(AuditDbContext db, CollectionScheduler scheduler, IEventSearch search, ISharedClientDirectory clients, CancellationToken ct)
    {
        var hidden = await DisabledClientIds.LoadAsync(clients, ct);
        var tenants = await db.Tenants.AsNoTracking().Where(t => !hidden.Contains(t.Id)).ToListAsync(ct);
        tenants.Sort(static (left, right) => string.Compare(left.DisplayName, right.DisplayName, StringComparison.OrdinalIgnoreCase));
        var checkpoints = await db.Checkpoints.AsNoTracking().ToListAsync(ct);
        var runs = RunQueries.LatestPerQuery(await db.RunLog.AsNoTracking().Where(r => !hidden.Contains(r.TenantId)).OrderByDescending(r => r.Id).Take(500).ToListAsync(ct)).Take(100).ToList();
        var tenantNames = tenants.ToDictionary(t => t.Id, t => t.DisplayName);
        var stored = new Dictionary<(string Source, string TenantId), long>();
        if (search.IsAvailable)
        {
            foreach (var collector in scheduler.Collectors.Values)
            {
                await CountStoredAsync(search, collector.Source, tenants, stored, ct);
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

    /// <summary><see cref="IEventSearch.CountByTenantAsync"/> returns at most this many directory ids.</summary>
    private const int TenantCountPage = 200;

    /// <summary>
    /// Stored events per directory. A directory the count page did not return is zero when that page was not full.
    /// A full page can hide a client, so those directories are counted one by one. A failed count stays unknown.
    /// </summary>
    private static async Task CountStoredAsync(IEventSearch search, string source, IReadOnlyList<Tenant> tenants, Dictionary<(string Source, string TenantId), long> stored, CancellationToken ct)
    {
        IReadOnlyDictionary<string, long> counts;
        try
        {
            counts = await search.CountByTenantAsync(Normalizers.PluginId, source, ct);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            return;
        }

        var truncated = counts.Count >= TenantCountPage;
        foreach (var tenant in tenants)
        {
            if (counts.TryGetValue(tenant.TenantId, out var count))
            {
                stored[(source, tenant.TenantId)] = count;
                continue;
            }

            if (!truncated)
            {
                stored[(source, tenant.TenantId)] = 0;
                continue;
            }

            try
            {
                var page = await search.SearchAsync(new EventQuery
                {
                    PluginId = Normalizers.PluginId,
                    Source = source,
                    Size = 1,
                    Filters = [new FieldFilter("vc.tenantId", FilterOperator.Equals, [tenant.TenantId])],
                }, ct);
                stored[(source, tenant.TenantId)] = page.Total;
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                // This directory was past the count page and the direct count failed. Leave it unknown.
            }
        }
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

        try
        {
            var deleted = await AuditClientPurge.RunAsync(tenant, scheduler, store, readiness, db, ct);
            await audit.RecordAsync("audit.tenant.purged", tenant.DisplayName, $"directory={tenant.TenantId} deleted={deleted.ToString(System.Globalization.CultureInfo.InvariantCulture)}", cancellationToken: ct);
            return Results.Json(new { deleted }, Json);
        }
        catch (ClientUnavailableException ex)
        {
            var status = ex.Code == "busy" ? 409 : ex.Code == "validation" ? 400 : 503;
            return Error(status, ex.Code, ex.Message);
        }
    }

    private static async Task<IResult> UpdateCollectionAsync(Guid id, CollectionRequest request, TenantService tenants, ITenantDirectory directory, ISharedClientDirectory clients, IEntraApplication application, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(request);
        if ((await DisabledClientIds.LoadAsync(clients, ct)).Contains(id))
        {
            return Error(400, "validation", "This client is disabled.");
        }

        var remote = await directory.ListAsync(ct);
        var shared = await application.GetAsync(ct);
        if (remote.Count > 0 || shared is not null)
        {
            await tenants.SyncFromDirectoryAsync(remote, shared, ct);
        }

        var error = await tenants.UpdateCollectionAsync(id, request.LookbackDays, request.Settings, ct);
        return error is null ? Results.NoContent() : CollectionError(error);
    }

    /// <summary>A missing tenant is 404. Lookback, settings, and a disabled client stay 400 validation.</summary>
    internal static IResult CollectionError(string error) =>
        error is "Tenant not found."
            ? Error(404, "not_found", error)
            : Error(400, "validation", error);

    private static void AddUsage(List<(string Key, long Count, double Bytes)> rows, string key, long count, double bytes)
    {
        var index = rows.FindIndex(row => string.Equals(row.Key, key, StringComparison.OrdinalIgnoreCase));
        if (index < 0)
        {
            rows.Add((key, count, bytes));
            return;
        }

        var current = rows[index];
        rows[index] = (current.Key, current.Count + count, current.Bytes + bytes);
    }

    /// <summary>One statistics row per directory. A disabled client is omitted by directory id, so a same-named enabled client stays.</summary>
    internal static List<(string Name, long Documents, long EstimatedBytes)> TenantBreakdown(
        IReadOnlyList<(string Key, long Count, double Bytes)> buckets,
        IEnumerable<ManagedTenant> clients)
    {
        var disabled = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var names = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var client in clients)
        {
            if (string.IsNullOrWhiteSpace(client.DirectoryId) || client.DirectoryPending)
            {
                continue;
            }

            names[client.DirectoryId] = client.DisplayName;
            if (client.Disabled)
            {
                disabled.Add(client.DirectoryId);
            }
        }

        var rows = new List<(string Name, long Documents, long EstimatedBytes)>();
        foreach (var bucket in buckets)
        {
            if (bucket.Key == "\0other")
            {
                rows.Add(("Other clients", bucket.Count, (long)Math.Round(bucket.Bytes)));
                continue;
            }

            if (bucket.Key == "\0unknown")
            {
                rows.Add(("Unknown", bucket.Count, (long)Math.Round(bucket.Bytes)));
                continue;
            }

            if (disabled.Contains(bucket.Key))
            {
                continue;
            }

            var name = names.TryGetValue(bucket.Key, out var known) ? known : bucket.Key;
            rows.Add((name, bucket.Count, (long)Math.Round(bucket.Bytes)));
        }

        return rows;
    }

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

    /// <summary>A terms bucket needs a field. A date histogram with no field counts <c>@timestamp</c>.</summary>
    internal static string AggregationField(string? kind, string? field)
    {
        if (!string.IsNullOrWhiteSpace(field))
        {
            return field;
        }

        if (kind?.ToLowerInvariant() is "datehistogram" or "date_histogram" or "histogram")
        {
            return "@timestamp";
        }

        throw new ArgumentException("Each aggregation needs a name, kind, and field.");
    }

    private static AggregationKind ParseKind(string kind) => kind?.ToLowerInvariant() switch
    {
        "terms" => AggregationKind.Terms,
        "datehistogram" or "date_histogram" or "histogram" => AggregationKind.DateHistogram,
        _ => throw new ArgumentException($"Unknown aggregation kind '{kind}'."),
    };
}
