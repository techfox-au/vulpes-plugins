using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;
using Vulpes.Plugins.Microsoft365Audit.Data;
using Vulpes.Plugins.Microsoft365Audit.Normalization;
using Vulpes.Plugins.Microsoft365Audit.Scheduling;
using Vulpes.Sdk;

namespace Vulpes.Plugins.Microsoft365Audit.Endpoints;

/// <summary>Read-only MCP endpoint. Grok Bot calls tools; it cannot change tenants, settings, or events.</summary>
public static class AuditMcp
{
    public const string Instructions =
        """
        Read-only Microsoft 365 and Entra audit data collected by Vulpes. You cannot change tenants, settings, or events.

        Cite the client, source, time range, and event ids behind every recommendation.

        Sources:
        - signins: Entra sign-ins. Interactive user sign-ins are collected first. When non-interactive collection is enabled, service principal and managed identity sign-ins follow and are often the large backlog.
        - directory: Entra directory changes (users, groups, applications, roles).
        - provisioning: inbound and outbound provisioning.
        - activity: Purview unified audit log (Exchange, SharePoint, Teams, and other workloads). It backfills one window at a time and can lag the other feeds.
        - security-alerts: Defender alerts, stored by id so an update replaces the same document.
        - incidents: Defender incidents.
        - risk: Identity Protection. Not collected when Business Premium mode is on.
        - securescore: Secure Score snapshots.
        - system: collector failures.

        vc.tenantId is the Entra directory id. vc.tenantName is the client name. Useful filters include user.name, user.email, source.ip, event.action, event.outcome, event.category, and event.severity, plus the labels and data fields from list_sources.

        Call ingestion_status before you treat a quiet period as "nothing happened". A partial run stops at the page budget or the time budget and resumes later. The lifetime event count on a feed is every event ever stored, not the size of the current run.

        search_events defaults to the last 7 days, newest first, 20 hits, without the raw Graph payload. Pass from and to as ISO-8601 to widen the window, up to 366 days, and pass searchAfter from the previous page to continue. includeRaw returns at most 5 events. Use get_event for one full record.
        """;

    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);

    private static readonly JsonArray Tools = new(
        Tool("list_sources", "List the audit logs and the filter fields on each one.", new JsonObject { ["type"] = "object", ["properties"] = new JsonObject() }),
        Tool("list_clients", "List the clients whose logs are collected. tenantId is the Entra directory id.", new JsonObject { ["type"] = "object", ["properties"] = new JsonObject() }),
        Tool("ingestion_status", "Show whether each feed is caught up, still backfilling, or failing. Read this before concluding that an event did not happen.", new JsonObject { ["type"] = "object", ["properties"] = new JsonObject() }),
        Tool("search_events", "Search one log. Returns a page of events and searchAfter for the next page.", SearchSchema()),
        Tool("aggregate_events", "Count events in one log by a field or over time. kinds are terms and date_histogram.", AggregateSchema()),
        Tool("get_event", "Fetch one stored event by source and id, including its raw record.", new JsonObject
        {
            ["type"] = "object",
            ["properties"] = new JsonObject
            {
                ["source"] = new JsonObject { ["type"] = "string" },
                ["id"] = new JsonObject { ["type"] = "string", ["description"] = "The id returned by search_events." },
            },
            ["required"] = new JsonArray("source", "id"),
        }));

    private const int MaxBodyBytes = 32_768;
    private const int CallsPerMinute = 60;
    private static readonly Lock RateGate = new();
    private static readonly Dictionary<Guid, Queue<long>> RecentCalls = [];

    public static async Task<IResult> HandleAsync(HttpContext http, AuditDbContext db, IEventSearch search, IAlertFieldCatalog catalog, CollectionScheduler scheduler, TimeProvider time, IHostAuditLog audit, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(http);
        http.Response.Headers.CacheControl = "no-store";
        if (!TryBearer(http, out var token))
        {
            return RpcError(null, 401, -32001, "Send Authorization: Bearer with a token from Microsoft 365 Audit settings.");
        }

        var hash = Hash(token);
        var row = await db.BotTokens.FirstOrDefaultAsync(t => t.TokenHash == hash && t.RevokedAt == null, ct);
        var now = time.GetUtcNow();
        if (row is null || (row.ExpiresAt is { } expiry && expiry <= now))
        {
            return RpcError(null, 401, -32001, "The token was rejected.");
        }

        if (!AllowCall(row.Id, now))
        {
            await audit.RecordAsync("audit.mcp", "rate_limited", row.Name, actor: "bot:" + row.Prefix, cancellationToken: ct);
            return RpcError(null, 429, -32029, "This token is being used too quickly. Wait a minute and try again.");
        }

        if (row.LastUsedAt is null || now - row.LastUsedAt > TimeSpan.FromMinutes(1))
        {
            row.LastUsedAt = now;
            await db.SaveChangesAsync(ct);
        }

        JsonNode? id = null;
        try
        {
            if (http.Request.ContentLength is > MaxBodyBytes)
            {
                return RpcError(null, 400, -32600, "The request is too large.");
            }

            var buffer = new byte[MaxBodyBytes + 1];
            var read = 0;
            while (read < buffer.Length)
            {
                var n = await http.Request.Body.ReadAsync(buffer.AsMemory(read), ct);
                if (n == 0)
                {
                    break;
                }

                read += n;
            }

            if (read > MaxBodyBytes)
            {
                return RpcError(null, 400, -32600, "The request is too large.");
            }

            using var document = JsonDocument.Parse(buffer.AsMemory(0, read));
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object || !root.TryGetProperty("method", out var methodEl) || methodEl.ValueKind != JsonValueKind.String)
            {
                return RpcError(null, 400, -32600, "A JSON-RPC request needs a method.");
            }

            var method = methodEl.GetString() ?? string.Empty;
            if (method.Length > 64)
            {
                return RpcError(null, 400, -32601, "Unknown method.");
            }

            var hasId = root.TryGetProperty("id", out var idEl) && idEl.ValueKind is JsonValueKind.String or JsonValueKind.Number;
            if (hasId && idEl.GetRawText().Length > 64)
            {
                return RpcError(null, 400, -32600, "The request id is too long.");
            }

            id = hasId ? JsonNode.Parse(idEl.GetRawText()) : null;
            if (method.StartsWith("notifications/", StringComparison.Ordinal))
            {
                return Results.StatusCode(StatusCodes.Status202Accepted);
            }

            if (!hasId)
            {
                return RpcError(null, 400, -32600, "A request needs an id.");
            }

            var arguments = root.TryGetProperty("params", out var paramsEl) ? paramsEl : default;
            if (method == "tools/call")
            {
                var toolName = arguments.ValueKind == JsonValueKind.Object && arguments.TryGetProperty("name", out var called) && called.ValueKind == JsonValueKind.String ? called.GetString() : "unknown";
                await audit.RecordAsync("audit.mcp", toolName, CallDetail(arguments), actor: "bot:" + row.Prefix, cancellationToken: ct);
            }

            var result = method switch
            {
                "initialize" => Initialize(arguments),
                "ping" => new JsonObject(),
                "tools/list" => new JsonObject { ["tools"] = Tools.DeepClone() },
                "tools/call" => await CallToolAsync(arguments, search, catalog, db, scheduler, time, ct),
                _ => null,
            };
            if (result is null)
            {
                return RpcError(id, 200, -32601, $"Unknown method '{method}'.");
            }

            return Results.Text(Envelope(id, result), "application/json");
        }
        catch (JsonException)
        {
            return RpcError(id, 400, -32700, "The body is not JSON.");
        }
    }

    internal static string Hash(string token) => Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(token)));

    private static string ServerVersion()
    {
        var version = typeof(AuditMcp).Assembly.GetName().Version;
        return version is null ? "0" : string.Create(System.Globalization.CultureInfo.InvariantCulture, $"{version.Major}.{version.Minor}.{version.Build}");
    }

    internal static string CreateSecret() => "vba_" + Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(24));

    internal static readonly TimeSpan TokenLifetime = TimeSpan.FromDays(90);

    private static bool AllowCall(Guid id, DateTimeOffset now)
    {
        var tick = now.UtcTicks;
        var window = TimeSpan.FromMinutes(1).Ticks;
        lock (RateGate)
        {
            if (!RecentCalls.TryGetValue(id, out var queue))
            {
                RecentCalls[id] = queue = new Queue<long>();
            }

            while (queue.Count > 0 && tick - queue.Peek() > window)
            {
                queue.Dequeue();
            }

            if (queue.Count >= CallsPerMinute)
            {
                return false;
            }

            queue.Enqueue(tick);
            return true;
        }
    }

    private static string CallDetail(JsonElement arguments)
    {
        if (arguments.ValueKind != JsonValueKind.Object || !arguments.TryGetProperty("arguments", out var args) || args.ValueKind != JsonValueKind.Object)
        {
            return string.Empty;
        }

        var source = args.TryGetProperty("source", out var sourceEl) && sourceEl.ValueKind == JsonValueKind.String ? sourceEl.GetString() : null;
        var tenant = args.TryGetProperty("tenantId", out var tenantEl) && tenantEl.ValueKind == JsonValueKind.String ? tenantEl.GetString() : null;
        var detail = string.Create(System.Globalization.CultureInfo.InvariantCulture, $"source={source ?? "-"} tenant={tenant ?? "-"}");
        return detail.Length <= 200 ? detail : detail[..200];
    }

    private static JsonObject Initialize(JsonElement parameters)
    {
        var requested = parameters.ValueKind == JsonValueKind.Object && parameters.TryGetProperty("protocolVersion", out var version) && version.ValueKind == JsonValueKind.String
            ? version.GetString()
            : null;
        var protocol = requested is "2025-03-26" or "2025-06-18" ? requested : "2025-03-26";
        return new JsonObject
        {
            ["protocolVersion"] = protocol,
            ["capabilities"] = new JsonObject { ["tools"] = new JsonObject() },
            ["serverInfo"] = new JsonObject { ["name"] = "vulpes-audit", ["version"] = ServerVersion() },
            ["instructions"] = Instructions,
        };
    }

    private static async Task<JsonNode> CallToolAsync(JsonElement parameters, IEventSearch search, IAlertFieldCatalog catalog, AuditDbContext db, CollectionScheduler scheduler, TimeProvider time, CancellationToken ct)
    {
        if (parameters.ValueKind != JsonValueKind.Object || !parameters.TryGetProperty("name", out var nameEl) || nameEl.ValueKind != JsonValueKind.String)
        {
            return ToolError("tools/call needs a tool name.");
        }

        var name = nameEl.GetString() ?? string.Empty;
        var args = parameters.TryGetProperty("arguments", out var argsEl) && argsEl.ValueKind == JsonValueKind.Object ? argsEl : default;
        try
        {
            var payload = name switch
            {
                "list_sources" => ListSources(catalog),
                "list_clients" => await ListClientsAsync(db, ct),
                "ingestion_status" => await IngestionAsync(db, scheduler, ct),
                "search_events" => await SearchAsync(args, search, time, ct),
                "aggregate_events" => await AggregateAsync(args, search, time, ct),
                "get_event" => await GetAsync(args, search, ct),
                _ => throw new ArgumentException($"Unknown tool '{name}'."),
            };
            return new JsonObject
            {
                ["content"] = new JsonArray(new JsonObject { ["type"] = "text", ["text"] = payload.ToJsonString(Json) }),
                ["structuredContent"] = payload,
            };
        }
        catch (ArgumentException ex)
        {
            return ToolError(ex.Message);
        }
        catch (Exception ex) when (ex.GetType().Name == "SearchUnavailableException")
        {
            return ToolError("Elasticsearch is not reachable, so the stored events cannot be read.");
        }
    }

    private static JsonObject ListSources(IAlertFieldCatalog catalog)
    {
        var sources = new JsonArray();
        foreach (var source in catalog.GetSources(Normalizers.PluginId))
        {
            var fields = new JsonArray();
            foreach (var field in catalog.GetFields(Normalizers.PluginId, source.Source).Where(f => f.Filterable))
            {
                fields.Add(new JsonObject { ["path"] = field.Path, ["label"] = field.Label, ["type"] = field.Type.ToString() });
            }

            sources.Add(new JsonObject { ["source"] = source.Source, ["title"] = source.Title, ["fields"] = fields });
        }

        return new JsonObject { ["sources"] = sources };
    }

    private static async Task<JsonObject> ListClientsAsync(AuditDbContext db, CancellationToken ct)
    {
        var rows = await db.Tenants.AsNoTracking().OrderBy(t => t.DisplayName).Select(t => new { t.DisplayName, t.TenantId, t.Enabled, t.LookbackDays }).ToListAsync(ct);
        var clients = new JsonArray();
        foreach (var row in rows)
        {
            clients.Add(new JsonObject { ["name"] = row.DisplayName, ["tenantId"] = row.TenantId, ["enabled"] = row.Enabled, ["lookbackDays"] = row.LookbackDays });
        }

        return new JsonObject { ["clients"] = clients };
    }

    private static async Task<JsonObject> IngestionAsync(AuditDbContext db, CollectionScheduler scheduler, CancellationToken ct)
    {
        var tenants = await db.Tenants.AsNoTracking().OrderBy(t => t.DisplayName).ToListAsync(ct);
        var checkpoints = await db.Checkpoints.AsNoTracking().ToListAsync(ct);
        var clients = new JsonArray();
        foreach (var tenant in tenants)
        {
            var feeds = new JsonArray();
            foreach (var checkpoint in checkpoints.Where(c => c.TenantId == tenant.Id).OrderBy(c => c.Source, StringComparer.Ordinal))
            {
                feeds.Add(new JsonObject
                {
                    ["source"] = checkpoint.Source,
                    ["status"] = scheduler.IsRunning(tenant.Id, checkpoint.Source) ? RunStatuses.Running : checkpoint.LastStatus,
                    ["watermark"] = checkpoint.Watermark?.ToString("O"),
                    ["lastSuccessAt"] = checkpoint.LastSuccessAt?.ToString("O"),
                    ["lastCount"] = checkpoint.LastCount,
                    ["totalCount"] = checkpoint.TotalCount,
                    ["note"] = checkpoint.LastError,
                });
            }

            clients.Add(new JsonObject { ["name"] = tenant.DisplayName, ["tenantId"] = tenant.TenantId, ["enabled"] = tenant.Enabled, ["feeds"] = feeds });
        }

        return new JsonObject
        {
            ["note"] = "totalCount is the lifetime number of indexed events. A partial note means that slice stopped at the page budget or the time budget and will resume.",
            ["clients"] = clients,
        };
    }

    private static async Task<JsonObject> SearchAsync(JsonElement args, IEventSearch search, TimeProvider time, CancellationToken ct)
    {
        var (source, from, to, filters) = Query(args, time);
        var includeRawRequested = args.ValueKind == JsonValueKind.Object && args.TryGetProperty("includeRaw", out var rawFlag) && rawFlag.ValueKind == JsonValueKind.True;
        var sizeCap = includeRawRequested ? 5 : 25;
        var size = args.ValueKind == JsonValueKind.Object && args.TryGetProperty("size", out var sizeEl) && sizeEl.TryGetInt32(out var n) ? Math.Clamp(n, 1, sizeCap) : Math.Min(20, sizeCap);
        var sort = args.ValueKind == JsonValueKind.Object && args.TryGetProperty("sort", out var sortEl) && sortEl.ValueKind == JsonValueKind.String && sortEl.GetString() == "asc"
            ? SortDirection.Ascending
            : SortDirection.Descending;
        var includeRaw = includeRawRequested;
        IReadOnlyList<JsonElement>? after = null;
        if (args.ValueKind == JsonValueKind.Object && args.TryGetProperty("searchAfter", out var afterEl) && afterEl.ValueKind == JsonValueKind.Array)
        {
            after = afterEl.EnumerateArray().Select(e => e.Clone()).ToList();
        }

        var result = await search.SearchAsync(new EventQuery
        {
            PluginId = Normalizers.PluginId,
            Source = source,
            From = from,
            To = to,
            Filters = filters,
            FreeText = Text(args),
            Size = size,
            Sort = sort,
            SearchAfter = after,
        }, ct);
        var hits = new JsonArray();
        foreach (var hit in result.Hits)
        {
            var item = Summarize(hit.Document, includeRaw);
            item["id"] = hit.Id;
            var sortValues = new JsonArray();
            foreach (var value in hit.Sort)
            {
                sortValues.Add(JsonNode.Parse(value.GetRawText()));
            }

            item["searchAfter"] = sortValues;
            hits.Add(item);
        }

        return new JsonObject
        {
            ["source"] = source,
            ["from"] = from.ToString("O"),
            ["to"] = to.ToString("O"),
            ["total"] = result.Total,
            ["totalIsExact"] = result.TotalIsExact,
            ["hits"] = hits,
        };
    }

    private static async Task<JsonObject> AggregateAsync(JsonElement args, IEventSearch search, TimeProvider time, CancellationToken ct)
    {
        var (source, from, to, filters) = Query(args, time);
        if (args.ValueKind != JsonValueKind.Object || !args.TryGetProperty("aggregations", out var aggs) || aggs.ValueKind != JsonValueKind.Array || aggs.GetArrayLength() == 0)
        {
            throw new ArgumentException("aggregations needs at least one terms or date_histogram.");
        }

        var specs = new List<AggregationSpec>();
        foreach (var agg in aggs.EnumerateArray())
        {
            var name = agg.TryGetProperty("name", out var nameEl) ? nameEl.GetString() : null;
            var kind = agg.TryGetProperty("kind", out var kindEl) ? kindEl.GetString() : null;
            var field = agg.TryGetProperty("field", out var fieldEl) ? fieldEl.GetString() : "@timestamp";
            var aggSize = agg.TryGetProperty("size", out var aggSizeEl) && aggSizeEl.TryGetInt32(out var s) ? s : 10;
            var interval = agg.TryGetProperty("interval", out var intervalEl) ? intervalEl.GetString() : null;
            if (string.IsNullOrWhiteSpace(name) || string.IsNullOrWhiteSpace(kind) || string.IsNullOrWhiteSpace(field))
            {
                throw new ArgumentException("Each aggregation needs a name, kind, and field.");
            }

            specs.Add(new AggregationSpec(name, ParseKind(kind), field, aggSize, interval));
        }

        var result = await search.AggregateAsync(new EventAggregationQuery
        {
            PluginId = Normalizers.PluginId,
            Source = source,
            From = from,
            To = to,
            Filters = filters,
            FreeText = Text(args),
            Aggregations = specs,
        }, ct);
        var output = new JsonObject { ["source"] = source, ["from"] = from.ToString("O"), ["to"] = to.ToString("O"), ["total"] = result.Total, ["aggregations"] = new JsonObject() };
        var bucketRoot = (JsonObject)output["aggregations"]!;
        foreach (var (key, buckets) in result.Aggregations)
        {
            var array = new JsonArray();
            foreach (var bucket in buckets)
            {
                array.Add(new JsonObject { ["key"] = bucket.Key, ["count"] = bucket.Count });
            }

            bucketRoot[key] = array;
        }

        return output;
    }

    private static async Task<JsonObject> GetAsync(JsonElement args, IEventSearch search, CancellationToken ct)
    {
        var source = Required(args, "source");
        var id = Required(args, "id");
        var doc = await search.GetAsync(Normalizers.PluginId, source, id, ct);
        if (doc is null)
        {
            throw new ArgumentException("Event not found.");
        }

        var item = Summarize(doc.Value, includeRaw: true);
        item["id"] = id;
        return item;
    }

    private static (string Source, DateTimeOffset From, DateTimeOffset To, List<FieldFilter> Filters) Query(JsonElement args, TimeProvider time)
    {
        var source = Required(args, "source");
        var to = Time(args, "to") ?? time.GetUtcNow();
        var from = Time(args, "from") ?? to.AddDays(-7);
        if (from > to)
        {
            throw new ArgumentException("from is after to.");
        }

        if (to - from > TimeSpan.FromDays(366))
        {
            throw new ArgumentException("The time range must be 366 days or less.");
        }

        var filters = new List<FieldFilter>();
        var tenant = Optional(args, "tenantId");
        if (!string.IsNullOrWhiteSpace(tenant))
        {
            filters.Add(new FieldFilter("vc.tenantId", FilterOperator.Equals, [tenant]));
        }

        if (args.ValueKind == JsonValueKind.Object && args.TryGetProperty("filters", out var list) && list.ValueKind == JsonValueKind.Array)
        {
            if (list.GetArrayLength() > 20)
            {
                throw new ArgumentException("At most 20 filters.");
            }

            filters.AddRange(AuditEndpoints.MapFilters(list.EnumerateArray().Select(item => new AuditEndpoints.FilterDto(
                item.TryGetProperty("field", out var field) ? field.GetString() ?? string.Empty : string.Empty,
                item.TryGetProperty("operator", out var op) ? op.GetString() ?? string.Empty : string.Empty,
                item.TryGetProperty("values", out var values) && values.ValueKind == JsonValueKind.Array
                    ? values.EnumerateArray().Select(v => v.GetString() ?? string.Empty).ToList()
                    : [])).ToList()));
        }

        return (source, from, to, filters);
    }

    private static JsonObject Summarize(JsonElement doc, bool includeRaw)
    {
        var item = new JsonObject
        {
            ["timestamp"] = Str(doc, "@timestamp"),
            ["tenantId"] = Child(doc, "vc", "tenantId"),
            ["tenantName"] = Child(doc, "vc", "tenantName"),
            ["recordId"] = Child(doc, "vc", "recordId"),
            ["user"] = Child(doc, "user", "name"),
            ["email"] = Child(doc, "user", "email"),
            ["action"] = Child(doc, "event", "action"),
            ["outcome"] = Child(doc, "event", "outcome"),
            ["category"] = Child(doc, "event", "category"),
            ["severity"] = Child(doc, "event", "severity"),
            ["ip"] = Child(doc, "source", "ip") ?? Child(doc, "source", "address"),
        };
        if (doc.ValueKind == JsonValueKind.Object && doc.TryGetProperty("labels", out var labels) && labels.ValueKind == JsonValueKind.Object)
        {
            item["labels"] = JsonNode.Parse(labels.GetRawText());
        }

        if (includeRaw && doc.ValueKind == JsonValueKind.Object && doc.TryGetProperty("data", out var data))
        {
            var raw = data.GetRawText();
            if (raw.Length > 6000)
            {
                item["dataTruncated"] = true;
                item["data"] = raw[..6000];
            }
            else
            {
                item["data"] = JsonNode.Parse(raw);
            }
        }

        return item;
    }

    private static string Required(JsonElement args, string name)
    {
        var value = Optional(args, name);
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new ArgumentException($"{name} is required.");
        }

        return value;
    }

    private static string? Optional(JsonElement args, string name) =>
        args.ValueKind == JsonValueKind.Object && args.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String ? value.GetString() : null;

    private static string? Text(JsonElement args) => Optional(args, "text");

    private static DateTimeOffset? Time(JsonElement args, string name)
    {
        var text = Optional(args, name);
        if (string.IsNullOrWhiteSpace(text))
        {
            return null;
        }

        if (!DateTimeOffset.TryParse(text, System.Globalization.CultureInfo.InvariantCulture, System.Globalization.DateTimeStyles.RoundtripKind, out var parsed))
        {
            throw new ArgumentException($"{name} must be an ISO-8601 time.");
        }

        return parsed;
    }

    private static string? Str(JsonElement doc, string name) =>
        doc.ValueKind == JsonValueKind.Object && doc.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String ? value.GetString() : null;

    private static string? Child(JsonElement doc, string parent, string name)
    {
        if (doc.ValueKind != JsonValueKind.Object || !doc.TryGetProperty(parent, out var node) || node.ValueKind != JsonValueKind.Object || !node.TryGetProperty(name, out var value))
        {
            return null;
        }

        return value.ValueKind == JsonValueKind.String ? value.GetString() : value.ToString();
    }

    private static AggregationKind ParseKind(string kind) => kind.ToLowerInvariant() switch
    {
        "terms" => AggregationKind.Terms,
        "datehistogram" or "date_histogram" or "histogram" => AggregationKind.DateHistogram,
        _ => throw new ArgumentException($"Unknown aggregation kind '{kind}'."),
    };

    private static bool TryBearer(HttpContext http, out string token)
    {
        token = string.Empty;
        var header = http.Request.Headers.Authorization.ToString();
        if (!header.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        token = header["Bearer ".Length..].Trim();
        return token.Length is > 0 and <= 200;
    }

    private static JsonObject Tool(string name, string description, JsonObject schema) => new()
    {
        ["name"] = name,
        ["description"] = description,
        ["inputSchema"] = schema,
    };

    private static JsonObject SearchSchema() => new()
    {
        ["type"] = "object",
        ["properties"] = new JsonObject
        {
            ["source"] = new JsonObject { ["type"] = "string" },
            ["tenantId"] = new JsonObject { ["type"] = "string", ["description"] = "Entra directory id. Omit for every client." },
            ["from"] = new JsonObject { ["type"] = "string", ["description"] = "ISO-8601. Defaults to 7 days before to." },
            ["to"] = new JsonObject { ["type"] = "string", ["description"] = "ISO-8601. Defaults to now." },
            ["text"] = new JsonObject { ["type"] = "string" },
            ["filters"] = new JsonObject { ["type"] = "array", ["items"] = new JsonObject { ["type"] = "object" }, ["description"] = "Each item is field, operator, values. Operators: equals, notequals, in, prefix, contains, exists, gt, lt." },
            ["size"] = new JsonObject { ["type"] = "integer", ["description"] = "1 to 25. Default 20." },
            ["sort"] = new JsonObject { ["type"] = "string", ["description"] = "asc or desc. Default desc." },
            ["searchAfter"] = new JsonObject { ["type"] = "array", ["description"] = "searchAfter from the last hit of the previous page." },
            ["includeRaw"] = new JsonObject { ["type"] = "boolean", ["description"] = "Include a truncated raw record. At most 5 hits." },
        },
        ["required"] = new JsonArray("source"),
    };

    private static JsonObject AggregateSchema() => new()
    {
        ["type"] = "object",
        ["properties"] = new JsonObject
        {
            ["source"] = new JsonObject { ["type"] = "string" },
            ["tenantId"] = new JsonObject { ["type"] = "string" },
            ["from"] = new JsonObject { ["type"] = "string" },
            ["to"] = new JsonObject { ["type"] = "string" },
            ["text"] = new JsonObject { ["type"] = "string" },
            ["filters"] = new JsonObject { ["type"] = "array" },
            ["aggregations"] = new JsonObject { ["type"] = "array", ["description"] = "Each item is name, kind (terms or date_histogram), field, optional size, and interval for a histogram (1h, 1d)." },
        },
        ["required"] = new JsonArray("source", "aggregations"),
    };

    private static JsonObject ToolError(string message) => new()
    {
        ["isError"] = true,
        ["content"] = new JsonArray(new JsonObject { ["type"] = "text", ["text"] = message }),
    };

    private static string Envelope(JsonNode? id, JsonNode result) =>
        new JsonObject { ["jsonrpc"] = "2.0", ["id"] = id, ["result"] = result }.ToJsonString(Json);

    private static IResult RpcError(JsonNode? id, int status, int code, string message)
    {
        var body = new JsonObject { ["jsonrpc"] = "2.0", ["id"] = id, ["error"] = new JsonObject { ["code"] = code, ["message"] = message } };
        return Results.Text(body.ToJsonString(Json), "application/json", statusCode: status);
    }
}
