using System.Text.Json;
using System.Text.Json.Nodes;
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

    private sealed class RecordingSearch : IEventSearch
    {
        public int Filters { get; private set; }

        public IReadOnlyList<FieldFilter> Applied { get; private set; } = [];

        public JsonElement? Document { get; init; }

        public IReadOnlyList<EventHit> Hits { get; init; } = [];

        public bool IsAvailable => true;

        public Task<EventSearchResult> SearchAsync(EventQuery query, CancellationToken cancellationToken)
        {
            Filters = query.Filters.Count;
            Applied = query.Filters;
            return Task.FromResult(new EventSearchResult(Hits, Hits.Count, true));
        }

        public Task<EventAggregationResult> AggregateAsync(EventAggregationQuery query, CancellationToken cancellationToken) =>
            throw new NotSupportedException();

        public Task<JsonElement?> GetAsync(string pluginId, string source, string documentId, CancellationToken cancellationToken) =>
            Task.FromResult(Document);

        public Task<EventStoreUsage> StoreUsageAsync(string pluginId, CancellationToken cancellationToken) =>
            throw new NotSupportedException();

        public Task<IReadOnlyDictionary<string, long>> CountByTenantAsync(string pluginId, string source, CancellationToken cancellationToken) =>
            throw new NotSupportedException();
    }
}
