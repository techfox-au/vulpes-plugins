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
        group.MapGet("/settings", GetSettings).RequireAuthorization(Policies.Admin);
        group.MapPut("/settings", PutSettings).RequireAuthorization(Policies.Admin);
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
    private static async Task<IResult> OverviewAsync(int? hours, string? tenantId, IEventSearch search, CancellationToken ct)
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
        }, Json);
    }

    private static async Task<IResult> TenantNamesAsync(AuditDbContext db, CancellationToken ct) =>
        Results.Json(await db.Tenants.AsNoTracking().OrderBy(t => t.DisplayName).Select(t => new { t.Id, t.TenantId, t.DisplayName, t.DiscoveredName, t.Enabled }).ToListAsync(ct), Json);

    private static async Task<IResult> StatusAsync(AuditDbContext db, CollectionScheduler scheduler, CancellationToken ct)
    {
        var tenants = await db.Tenants.AsNoTracking().OrderBy(t => t.DisplayName).ToListAsync(ct);
        var checkpoints = await db.Checkpoints.AsNoTracking().ToListAsync(ct);
        var runs = await db.RunLog.AsNoTracking().OrderByDescending(r => r.Id).Take(100).ToListAsync(ct);
        var tenantNames = tenants.ToDictionary(t => t.Id, t => t.DisplayName);
        return Results.Json(new
        {
            sources = scheduler.Collectors.Values.Select(c => new { c.Source, c.Title }).OrderBy(c => c.Source, StringComparer.Ordinal).ToList(),
            tenants = tenants.Select(t => new
            {
                t.Id,
                t.DisplayName,
                t.Enabled,
                checkpoints = checkpoints.Where(c => c.TenantId == t.Id).Select(c => new { c.Source, c.Watermark, c.LastRunAt, c.LastSuccessAt, lastStatus = scheduler.IsRunning(t.Id, c.Source) ? RunStatuses.Running : c.LastStatus, c.LastError, c.LastCount, c.TotalCount, c.NextRunAt, c.ConsecutiveFailures }).ToList(),
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

    private static List<FieldFilter> MapFilters(IReadOnlyList<FilterDto>? filters)
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
