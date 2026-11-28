using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Vulpes.Plugins.Microsoft365Audit.Endpoints;
using Vulpes.Sdk;
using Xunit;

namespace Vulpes.Plugins.Microsoft365Audit.Tests;

public sealed class AuditFixTests
{
    [Fact]
    public void Statistics_keep_an_enabled_client_when_a_disabled_client_has_the_same_name()
    {
        var enabled = Guid.NewGuid().ToString();
        var disabled = Guid.NewGuid().ToString();
        var rows = AuditEndpoints.TenantBreakdown(
            [
                (enabled, 4, 40d),
                (disabled, 9, 90d),
                ("\0other", 1, 10d),
                ("\0unknown", 2, 20d),
            ],
            [
                new ManagedTenant(Guid.NewGuid(), "Contoso", enabled, true, "Contoso Legal"),
                new ManagedTenant(Guid.NewGuid(), "Contoso", disabled, false, "Contoso", Disabled: true),
            ]);

        Assert.Contains(rows, row => row.Name == "Contoso" && row.Documents == 4);
        Assert.DoesNotContain(rows, row => row.Documents == 9);
        Assert.Contains(rows, row => row.Name == "Other clients" && row.Documents == 1);
        Assert.Contains(rows, row => row.Name == "Unknown" && row.Documents == 2);
    }

    [Fact]
    public async Task Mcp_search_counts_the_client_filter_toward_the_limit()
    {
        var search = new RecordingSearch();
        var mcp = new AuditMcp(null!, search, null!, null!, TimeProvider.System);
        var tooMany = await mcp.CallAsync("search_events", Filters(20, "directory-id"), CancellationToken.None);
        Assert.True(tooMany.IsError);
        Assert.Contains("20", tooMany.Text, StringComparison.Ordinal);
        Assert.Equal(0, search.Filters);

        var accepted = await mcp.CallAsync("search_events", Filters(19, "directory-id"), CancellationToken.None);
        Assert.False(accepted.IsError);
        Assert.Equal(20, search.Filters);
    }

    [Fact]
    public async Task Mcp_get_event_returns_the_whole_raw_record()
    {
        var tail = new string('z', 80);
        var blob = new string('a', 6200) + tail;
        var doc = JsonSerializer.SerializeToElement(new JsonObject
        {
            ["@timestamp"] = "2026-11-13T00:00:00Z",
            ["data"] = new JsonObject { ["blob"] = blob },
        });
        var mcp = new AuditMcp(null!, new RecordingSearch { Document = doc }, null!, null!, TimeProvider.System);
        var result = await mcp.CallAsync("get_event", JsonSerializer.SerializeToElement(new JsonObject
        {
            ["source"] = "directory",
            ["id"] = "evt-1",
        }), CancellationToken.None);

        Assert.False(result.IsError);
        var body = JsonNode.Parse(result.Text)!.AsObject();
        Assert.Null(body["dataTruncated"]);
        var stored = body["data"]!["blob"]!.GetValue<string>();
        Assert.Equal(blob, stored);
        Assert.EndsWith(tail, stored);
    }

    [Fact]
    public async Task Mcp_search_keeps_a_raw_page_within_6000_characters()
    {
        var tail = "END-OF-RECORD";
        var blob = new string('a', 7000) + tail;
        var doc = JsonSerializer.SerializeToElement(new JsonObject
        {
            ["data"] = new JsonObject { ["blob"] = blob },
        });
        var search = new RecordingSearch { Hits = [new EventHit("evt-1", doc, [])] };
        var mcp = new AuditMcp(null!, search, null!, null!, TimeProvider.System);
        var result = await mcp.CallAsync("search_events", JsonSerializer.SerializeToElement(new JsonObject
        {
            ["source"] = "directory",
            ["includeRaw"] = true,
        }), CancellationToken.None);

        Assert.False(result.IsError);
        var hit = JsonNode.Parse(result.Text)!["hits"]![0]!.AsObject();
        Assert.True(hit["dataTruncated"]!.GetValue<bool>());
        var text = hit["data"]!.GetValue<string>();
        Assert.Equal(6000, text.Length);
        Assert.DoesNotContain(tail, text, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Mcp_search_keeps_a_numeric_filter_value()
    {
        var search = new RecordingSearch();
        var mcp = new AuditMcp(null!, search, null!, null!, TimeProvider.System);
        var result = await mcp.CallAsync("search_events", JsonSerializer.SerializeToElement(new JsonObject
        {
            ["source"] = "signins",
            ["filters"] = new JsonArray
            {
                new JsonObject
                {
                    ["field"] = "labels.errorCode",
                    ["operator"] = "equals",
                    ["values"] = new JsonArray(50126),
                },
            },
        }), CancellationToken.None);

        Assert.False(result.IsError);
        var filter = Assert.Single(search.Applied);
        Assert.Equal("labels.errorCode", filter.Field);
        Assert.Equal("50126", Assert.Single(filter.Values));
    }

    [Fact]
    public async Task Mcp_search_treats_asc_as_ascending_ignoring_case()
    {
        var search = new RecordingSearch();
        var mcp = new AuditMcp(null!, search, null!, null!, TimeProvider.System);
        foreach (var sort in new[] { "ASC", "Asc", "asc" })
        {
            var result = await mcp.CallAsync("search_events", JsonSerializer.SerializeToElement(new JsonObject
            {
                ["source"] = "signins",
                ["sort"] = sort,
            }), CancellationToken.None);
            Assert.False(result.IsError);
            Assert.Equal(SortDirection.Ascending, search.Sort);
        }

        var descending = await mcp.CallAsync("search_events", JsonSerializer.SerializeToElement(new JsonObject
        {
            ["source"] = "signins",
            ["sort"] = "DESC",
        }), CancellationToken.None);
        Assert.False(descending.IsError);
        Assert.Equal(SortDirection.Descending, search.Sort);

        var omitted = await mcp.CallAsync("search_events", JsonSerializer.SerializeToElement(new JsonObject
        {
            ["source"] = "signins",
        }), CancellationToken.None);
        Assert.False(omitted.IsError);
        Assert.Equal(SortDirection.Descending, search.Sort);
    }

    [Fact]
    public async Task Terms_aggregation_requires_a_field_on_mcp_and_rest()
    {
        var search = new RecordingSearch();
        var mcp = new AuditMcp(null!, search, null!, null!, TimeProvider.System);
        var missing = await mcp.CallAsync("aggregate_events", JsonSerializer.SerializeToElement(new JsonObject
        {
            ["source"] = "signins",
            ["aggregations"] = new JsonArray { new JsonObject { ["name"] = "byTime", ["kind"] = "terms" } },
        }), CancellationToken.None);
        Assert.True(missing.IsError);
        Assert.Equal("Each aggregation needs a name, kind, and field.", missing.Text);
        Assert.Empty(search.AggregateQueries);

        var rest = await AuditEndpoints.AggregateAsync(
            new AuditEndpoints.AggregateRequest("signins", null, null, null, null, [new AuditEndpoints.AggregationDto("byTime", "terms", null, null, null)]),
            search,
            CancellationToken.None);
        var (statusCode, body) = await ReadResultAsync(rest);
        Assert.Equal(400, statusCode);
        Assert.Contains("Each aggregation needs a name, kind, and field.", body, StringComparison.Ordinal);
        Assert.Empty(search.AggregateQueries);

        var supplied = await mcp.CallAsync("aggregate_events", JsonSerializer.SerializeToElement(new JsonObject
        {
            ["source"] = "signins",
            ["aggregations"] = new JsonArray
            {
                new JsonObject { ["name"] = "byUser", ["kind"] = "terms", ["field"] = "user.name" },
            },
        }), CancellationToken.None);
        Assert.False(supplied.IsError);
        var spec = Assert.Single(search.Specs);
        Assert.Equal(AggregationKind.Terms, spec.Kind);
        Assert.Equal("user.name", spec.Field);
    }

    [Fact]
    public async Task Date_histogram_without_a_field_still_counts_timestamp()
    {
        var search = new RecordingSearch();
        var mcp = new AuditMcp(null!, search, null!, null!, TimeProvider.System);
        var mcpResult = await mcp.CallAsync("aggregate_events", JsonSerializer.SerializeToElement(new JsonObject
        {
            ["source"] = "signins",
            ["aggregations"] = new JsonArray { new JsonObject { ["name"] = "perHour", ["kind"] = "date_histogram", ["interval"] = "1h" } },
        }), CancellationToken.None);
        Assert.False(mcpResult.IsError);
        var mcpSpec = Assert.Single(search.Specs);
        Assert.Equal(AggregationKind.DateHistogram, mcpSpec.Kind);
        Assert.Equal("@timestamp", mcpSpec.Field);

        var rest = await AuditEndpoints.AggregateAsync(
            new AuditEndpoints.AggregateRequest("signins", null, null, null, null, [new AuditEndpoints.AggregationDto("perHour", "histogram", null, null, "1d")]),
            search,
            CancellationToken.None);
        var (statusCode, _) = await ReadResultAsync(rest);
        Assert.Equal(200, statusCode);
        var restSpec = Assert.Single(search.Specs);
        Assert.Equal(AggregationKind.DateHistogram, restSpec.Kind);
        Assert.Equal("@timestamp", restSpec.Field);
    }

    [Fact]
    public async Task Get_event_returns_503_when_search_is_unavailable()
    {
        var search = new RecordingSearch { GetFailure = new SearchUnavailableException("cluster down") };
        var result = await AuditEndpoints.GetEventAsync("signins", "evt-1", search, CancellationToken.None);
        var (statusCode, body) = await ReadResultAsync(result);
        Assert.Equal(503, statusCode);
        Assert.Contains("search_unavailable", body, StringComparison.Ordinal);
        Assert.Contains("cluster down", body, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Get_event_still_returns_400_for_a_bad_argument()
    {
        var search = new RecordingSearch { GetFailure = new ArgumentException("bad id") };
        var result = await AuditEndpoints.GetEventAsync("signins", "evt-1", search, CancellationToken.None);
        var (statusCode, body) = await ReadResultAsync(result);
        Assert.Equal(400, statusCode);
        Assert.Contains("validation", body, StringComparison.Ordinal);
        Assert.Contains("bad id", body, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Get_event_does_not_swallow_unrelated_exceptions()
    {
        var search = new RecordingSearch { GetFailure = new InvalidOperationException("boom") };
        await Assert.ThrowsAsync<InvalidOperationException>(() => AuditEndpoints.GetEventAsync("signins", "evt-1", search, CancellationToken.None));
    }

    [Fact]
    public async Task Collection_update_returns_not_found_for_a_missing_tenant()
    {
        var missing = await ReadCollectionErrorAsync("Tenant not found.");
        Assert.Equal(404, missing.StatusCode);
        Assert.Equal("not_found", missing.Code);
        Assert.Equal("Tenant not found.", missing.Message);

        var lookback = await ReadCollectionErrorAsync("Lookback must be between 1 and 180 days.");
        Assert.Equal(400, lookback.StatusCode);
        Assert.Equal("validation", lookback.Code);
        Assert.Equal("Lookback must be between 1 and 180 days.", lookback.Message);

        var settings = await ReadCollectionErrorAsync("Unknown source 'nope' in settings.");
        Assert.Equal(400, settings.StatusCode);
        Assert.Equal("validation", settings.Code);
        Assert.Equal("Unknown source 'nope' in settings.", settings.Message);

        var disabled = await ReadCollectionErrorAsync("This client is disabled.");
        Assert.Equal(400, disabled.StatusCode);
        Assert.Equal("validation", disabled.Code);
        Assert.Equal("This client is disabled.", disabled.Message);
    }

    [Fact]
    public async Task Statistics_leaves_hidden_directory_bytes_out_of_enabled_and_other_rows()
    {
        var northwind = Guid.NewGuid().ToString();
        var fabrikam = Guid.NewGuid().ToString();
        var hidden = Guid.NewGuid().ToString();
        var search = new RecordingSearch
        {
            Usage = Usage(
                ("signins", 100, 10000),
                ("activity", 100, 10000)),
            OnAggregate = query =>
            {
                RejectOversizedFilter(query);
                return query.Source == "signins"
                    ? Tenants(60, (northwind, 60))
                    : Tenants(60, (fabrikam, 50), ("\0other", 10));
            },
        };

        var (statusCode, body) = await ReadResultAsync(await AuditEndpoints.StatisticsAsync(
            search,
            new EmptyCatalog(),
            new ClientDirectory(
            [
                new ManagedTenant(Guid.NewGuid(), "Northwind", northwind, true, null),
                new ManagedTenant(Guid.NewGuid(), "Fabrikam", fabrikam, true, null),
                new ManagedTenant(Guid.NewGuid(), "Hidden Co", hidden, false, null, Disabled: true),
            ]),
            CancellationToken.None));

        Assert.Equal(200, statusCode);
        Assert.Equal(2, search.AggregateQueries.Count);
        Assert.All(search.AggregateQueries, query =>
        {
            var filter = Assert.Single(query.Filters);
            Assert.Equal(FilterOperator.NotIn, filter.Operator);
            Assert.Equal("vc.tenantId", filter.Field);
            Assert.Equal(hidden, Assert.Single(filter.Values));
        });
        var tenants = TenantsOf(body);
        Assert.Equal((60L, 6000L), Counts(tenants, "Northwind"));
        Assert.Equal((50L, 5000L), Counts(tenants, "Fabrikam"));
        Assert.Equal((10L, 1000L), Counts(tenants, "Other clients"));
        Assert.DoesNotContain(tenants, row => row?["name"]?.GetValue<string>() == "Hidden Co");
    }

    [Fact]
    public async Task Statistics_with_no_disabled_directory_still_scales_by_the_hit_total()
    {
        var northwind = Guid.NewGuid().ToString();
        var search = new RecordingSearch
        {
            Usage = Usage(("signins", 100, 10000)),
            OnAggregate = query =>
            {
                RejectOversizedFilter(query);
                return Tenants(80, (northwind, 40));
            },
        };

        var (statusCode, body) = await ReadResultAsync(await AuditEndpoints.StatisticsAsync(
            search,
            new EmptyCatalog(),
            new ClientDirectory([new ManagedTenant(Guid.NewGuid(), "Northwind", northwind, true, null)]),
            CancellationToken.None));

        Assert.Equal(200, statusCode);
        var query = Assert.Single(search.AggregateQueries);
        Assert.Empty(query.Filters);
        Assert.Equal((40L, 5000L), Counts(TenantsOf(body), "Northwind"));
    }

    [Fact]
    public async Task Statistics_skips_the_notin_filter_when_more_than_100_directories_are_disabled()
    {
        var enabledId = Guid.NewGuid().ToString();
        var hiddenIds = Enumerable.Range(0, 101).Select(_ => Guid.NewGuid().ToString()).ToList();
        var clients = new List<ManagedTenant> { new(Guid.NewGuid(), "Enabled Co", enabledId, true, null) };
        clients.AddRange(hiddenIds.Select(id => new ManagedTenant(Guid.NewGuid(), "Disabled", id, false, null, Disabled: true)));
        var search = new RecordingSearch
        {
            Usage = Usage(("signins", 100, 10000)),
            OnAggregate = query =>
            {
                RejectOversizedFilter(query);
                return Tenants(100, (enabledId, 60), (hiddenIds[0], 30), ("\0other", 10));
            },
        };

        var (statusCode, body) = await ReadResultAsync(await AuditEndpoints.StatisticsAsync(search, new EmptyCatalog(), new ClientDirectory(clients), CancellationToken.None));

        Assert.Equal(200, statusCode);
        var query = Assert.Single(search.AggregateQueries);
        Assert.DoesNotContain(query.Filters, filter => filter.Operator == FilterOperator.NotIn);
        var tenants = TenantsOf(body);
        Assert.Equal((60L, 6000L), Counts(tenants, "Enabled Co"));
        Assert.Equal((10L, 1000L), Counts(tenants, "Other clients"));
        Assert.DoesNotContain(tenants, row => row?["documents"] is { } documents && Number(documents) == 30);
    }

    [Fact]
    public async Task Statistics_keeps_the_notin_filter_for_100_disabled_directories()
    {
        var enabledId = Guid.NewGuid().ToString();
        var hiddenIds = Enumerable.Range(0, 100).Select(_ => Guid.NewGuid().ToString()).ToList();
        var clients = new List<ManagedTenant> { new(Guid.NewGuid(), "Enabled Co", enabledId, true, null) };
        clients.AddRange(hiddenIds.Select(id => new ManagedTenant(Guid.NewGuid(), "Disabled", id, false, null, Disabled: true)));
        var search = new RecordingSearch
        {
            Usage = Usage(("signins", 10, 1000)),
            OnAggregate = query =>
            {
                RejectOversizedFilter(query);
                return Tenants(10, (enabledId, 10));
            },
        };

        var (statusCode, body) = await ReadResultAsync(await AuditEndpoints.StatisticsAsync(search, new EmptyCatalog(), new ClientDirectory(clients), CancellationToken.None));

        Assert.Equal(200, statusCode);
        var filter = Assert.Single(Assert.Single(search.AggregateQueries).Filters);
        Assert.Equal(FilterOperator.NotIn, filter.Operator);
        Assert.Equal(100, filter.Values.Count);
        Assert.Equal((10L, 1000L), Counts(TenantsOf(body), "Enabled Co"));
    }

    [Fact]
    public async Task Statistics_fails_when_one_source_search_throws()
    {
        var search = new RecordingSearch
        {
            Usage = Usage(("signins", 10, 1000), ("activity", 5, 500)),
            OnAggregate = _ => Tenants(10, ("tenant", 10)),
            SearchFailure = new SearchUnavailableException("activity shard missing"),
            FailSource = "activity",
        };

        var (statusCode, body) = await ReadResultAsync(await AuditEndpoints.StatisticsAsync(
            search,
            new EmptyCatalog(),
            new ClientDirectory([]),
            CancellationToken.None));

        Assert.NotEqual(200, statusCode);
        Assert.Equal(503, statusCode);
        var json = JsonNode.Parse(body)!;
        Assert.Equal("search_unavailable", json["error"]!.GetValue<string>());
        Assert.Equal("activity shard missing", json["message"]!.GetValue<string>());
        Assert.Null(json["tenants"]);
        Assert.Null(json["documents"]);
    }

    private static JsonElement Filters(int count, string tenantId)
    {
        var filters = new JsonArray();
        for (var i = 0; i < count; i++)
        {
            filters.Add(new JsonObject
            {
                ["field"] = "user.name",
                ["operator"] = "equals",
                ["values"] = new JsonArray("a"),
            });
        }

        return JsonSerializer.SerializeToElement(new JsonObject
        {
            ["source"] = "signins",
            ["tenantId"] = tenantId,
            ["filters"] = filters,
        });
    }

    private static async Task<(int StatusCode, string Code, string Message)> ReadCollectionErrorAsync(string error)
    {
        var (statusCode, body) = await ReadResultAsync(AuditEndpoints.CollectionError(error));
        var json = JsonNode.Parse(body)!;
        return (statusCode, json["error"]!.GetValue<string>(), json["message"]!.GetValue<string>());
    }

    private static async Task<(int StatusCode, string Body)> ReadResultAsync(IResult result)
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.Configure<Microsoft.AspNetCore.Http.Json.JsonOptions>(_ => { });
        var context = new DefaultHttpContext { RequestServices = services.BuildServiceProvider() };
        context.Response.Body = new MemoryStream();
        await result.ExecuteAsync(context);
        context.Response.Body.Position = 0;
        using var reader = new StreamReader(context.Response.Body);
        return (context.Response.StatusCode, await reader.ReadToEndAsync());
    }

    private static EventStoreUsage Usage(params (string Source, long Documents, long StoredBytes)[] sources) =>
        new(true, sources.Sum(source => source.Documents), sources.Sum(source => source.StoredBytes), sources.Sum(source => source.StoredBytes), sources.Select(source => new EventSourceUsage(source.Source, source.Documents, source.StoredBytes, source.StoredBytes)).ToList());

    private static EventAggregationResult Tenants(long total, params (string Key, long Count)[] buckets) =>
        new(total, new Dictionary<string, IReadOnlyList<AggregationBucket>>
        {
            ["tenants"] = buckets.Select(bucket => new AggregationBucket(bucket.Key, bucket.Count)).ToList(),
        });

    private static void RejectOversizedFilter(EventAggregationQuery query)
    {
        var oversized = query.Filters.FirstOrDefault(filter => filter.Values.Count > 100);
        if (oversized is not null)
        {
            throw new ArgumentException($"'{oversized.Field}' filters are limited to 100 values.");
        }
    }

    private static JsonArray TenantsOf(string body) => JsonNode.Parse(body)!["tenants"]!.AsArray();

    private static (long Documents, long EstimatedBytes) Counts(JsonArray tenants, string name)
    {
        var row = Assert.Single(tenants, item => item?["name"]?.GetValue<string>() == name);
        return (Number(row!["documents"]), Number(row["estimatedBytes"]));
    }

    private static long Number(JsonNode? node) => node!.GetValue<JsonElement>().GetInt64();

    private sealed class RecordingSearch : IEventSearch
    {
        public int Filters { get; private set; }

        public IReadOnlyList<FieldFilter> Applied { get; private set; } = [];

        public SortDirection Sort { get; private set; } = SortDirection.Descending;

        public List<EventAggregationQuery> AggregateQueries { get; } = [];

        public IReadOnlyList<AggregationSpec> Specs { get; private set; } = [];

        public JsonElement? Document { get; init; }

        public IReadOnlyList<EventHit> Hits { get; init; } = [];

        public EventStoreUsage Usage { get; init; } = new(true, 0, 0, 0, []);

        public EventAggregationResult Aggregation { get; init; } = new(0, new Dictionary<string, IReadOnlyList<AggregationBucket>>());

        public Func<EventAggregationQuery, EventAggregationResult>? OnAggregate { get; init; }

        public Exception? GetFailure { get; init; }

        public Exception? SearchFailure { get; init; }

        public string? FailSource { get; init; }

        public bool IsAvailable => true;

        public Task<EventSearchResult> SearchAsync(EventQuery query, CancellationToken cancellationToken)
        {
            Filters = query.Filters.Count;
            Applied = query.Filters;
            Sort = query.Sort;
            if (SearchFailure is not null && (FailSource is null || string.Equals(query.Source, FailSource, StringComparison.Ordinal)))
            {
                throw SearchFailure;
            }

            return Task.FromResult(new EventSearchResult(Hits, Hits.Count, true));
        }

        public Task<EventAggregationResult> AggregateAsync(EventAggregationQuery query, CancellationToken cancellationToken)
        {
            AggregateQueries.Add(query);
            Specs = query.Aggregations;
            return Task.FromResult(OnAggregate is null ? Aggregation : OnAggregate(query));
        }

        public Task<JsonElement?> GetAsync(string pluginId, string source, string documentId, CancellationToken cancellationToken)
        {
            if (GetFailure is not null)
            {
                throw GetFailure;
            }

            return Task.FromResult(Document);
        }

        public Task<EventStoreUsage> StoreUsageAsync(string pluginId, CancellationToken cancellationToken) =>
            Task.FromResult(Usage);

        public Task<IReadOnlyDictionary<string, long>> CountByTenantAsync(string pluginId, string source, CancellationToken cancellationToken) =>
            throw new NotSupportedException();
    }

    private sealed class SearchUnavailableException(string message) : Exception(message);

    private sealed class EmptyCatalog : IAlertFieldCatalog
    {
        public IReadOnlyList<EventSourceDefinition> GetSources(string pluginId) => [];

        public EventSourceDefinition? GetSource(string pluginId, string source) => null;

        public IReadOnlyList<FieldDefinition> GetFields(string pluginId, string source) => [];

        public bool IsKnownField(string pluginId, string source, string path) => false;
    }

    private sealed class ClientDirectory(IReadOnlyList<ManagedTenant> tenants) : ISharedClientDirectory
    {
        public Task<IReadOnlyList<ManagedTenant>> ListAllAsync(CancellationToken cancellationToken) => Task.FromResult(tenants);

        public Task<ManagedTenant> EnsureAsync(Guid? id, string displayName, string? directoryId, bool enabled, CancellationToken cancellationToken) => throw new NotSupportedException();

        public Task RenameAsync(Guid id, string displayName, CancellationToken cancellationToken) => throw new NotSupportedException();

        public Task SetShortNameAsync(Guid id, string shortName, CancellationToken cancellationToken) => throw new NotSupportedException();

        public Task DeleteAsync(Guid id, CancellationToken cancellationToken) => throw new NotSupportedException();

        public Task<bool> SetDisabledAsync(Guid id, bool disabled, CancellationToken cancellationToken) => throw new NotSupportedException();
    }
}
