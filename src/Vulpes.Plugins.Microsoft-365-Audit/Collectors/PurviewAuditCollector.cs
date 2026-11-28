using System.Globalization;
using System.Net;
using System.Text.Json;
using System.Text.Json.Nodes;
using Vulpes.Plugins.Microsoft365Audit.Graph;
using Vulpes.Plugins.Microsoft365Audit.Normalization;
using Vulpes.Sdk;

namespace Vulpes.Plugins.Microsoft365Audit.Collectors;

/// <summary>
/// Microsoft Purview unified audit log through the asynchronous <c>security/auditLog/queries</c> API.
/// One query per tenant per run: create it for the next window, then on later runs poll it and page its records.
/// </summary>
public sealed class PurviewAuditCollector : ICollector
{
    private const string PendingIdKey = "pendingQueryId";
    private const string PendingStartKey = "pendingWindowStart";
    private const string PendingEndKey = "pendingWindowEnd";
    private const string PendingCreatedKey = "pendingCreatedAt";
    private const string PendingNextKey = "pendingNextLink";
    private static readonly TimeSpan PendingTimeout = TimeSpan.FromHours(6);

    public string Source => Sources.Activity;
    public string Title => "Microsoft 365 unified audit log (Purview)";
    public IReadOnlyList<string> RequiredPermissions => ["AuditLogsQuery.Read.All (or the per-workload AuditLogsQuery-*.Read.All set)"];
    public string ProbePath => "security/auditLog/queries?$top=1";

    public async Task<CollectorResult> CollectAsync(CollectorContext context, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        var state = context.State;
        if (state.TryGetValue(PendingIdKey, out var pendingId) && pendingId.ValueKind == JsonValueKind.String)
        {
            return await ContinuePendingAsync(context, pendingId.GetString()!, state, cancellationToken);
        }

        return await StartQueryAsync(context, cancellationToken);
    }

    private static async Task<CollectorResult> StartQueryAsync(CollectorContext context, CancellationToken cancellationToken)
    {
        var now = context.Now;
        var lag = TimeSpan.FromMinutes(Math.Clamp(context.Options.PurviewLagMinutes, 0, 24 * 60));
        var overlap = TimeSpan.FromMinutes(Math.Clamp(context.Options.PurviewOverlapMinutes, 0, 24 * 60));
        var maxWindow = TimeSpan.FromHours(Math.Clamp(context.Options.PurviewMaxWindowHours, 1, 24 * 7));

        var start = context.Checkpoint.Watermark is { } wm ? wm - overlap : now.AddDays(-Math.Clamp(context.Tenant.LookbackDays, 1, 180));
        var latest = now - lag;
        var end = start + maxWindow < latest ? start + maxWindow : latest;
        // An overlap at least as long as the window would end on or before the watermark and then repeat.
        if (context.Checkpoint.Watermark is { } held && end <= held && latest > held)
        {
            start = held;
            end = start + maxWindow < latest ? start + maxWindow : latest;
        }
        if (end - start < TimeSpan.FromMinutes(5))
        {
            return CollectorResult.Empty("window too small; waiting for more data");
        }

        var recordTypes = context.Settings.RecordTypes is { Count: > 0 } custom ? custom : context.Options.PurviewRecordTypes;
        var body = new JsonObject
        {
            ["@odata.type"] = "#microsoft.graph.security.auditLogQuery",
            ["displayName"] = string.Create(CultureInfo.InvariantCulture, $"vulpes {start:yyyy-MM-ddTHH:mm}Z..{end:HH:mm}Z"),
            ["filterStartDateTime"] = start.UtcDateTime.ToString("O", CultureInfo.InvariantCulture),
            ["filterEndDateTime"] = end.UtcDateTime.ToString("O", CultureInfo.InvariantCulture),
            ["recordTypeFilters"] = new JsonArray(recordTypes.Where(IsValidRecordType).Select(r => (JsonNode)JsonValue.Create(r)).ToArray()),
        };

        using var created = await context.Graph.PostAsync("security/auditLog/queries", body.ToJsonString(), cancellationToken);
        var id = created.RootElement.Str("id");
        if (string.IsNullOrEmpty(id))
        {
            throw new GraphException("Purview query creation returned no id.");
        }

        context.SaveState(new Dictionary<string, object?>
        {
            [PendingIdKey] = id,
            [PendingStartKey] = start.ToString("O", CultureInfo.InvariantCulture),
            [PendingEndKey] = end.ToString("O", CultureInfo.InvariantCulture),
            [PendingCreatedKey] = now.ToString("O", CultureInfo.InvariantCulture),
        });
        context.Logger.LogDebug("Purview audit query {QueryId} created for {Tenant}: {Start} .. {End}", id, context.Tenant.DisplayName, start, end);
        return CollectorResult.Waiting($"query {id} submitted for {start:O}..{end:O}", id);
    }

    private static async Task<CollectorResult> ContinuePendingAsync(CollectorContext context, string queryId, Dictionary<string, JsonElement> state, CancellationToken cancellationToken)
    {
        if (!IsSafeId(queryId))
        {
            context.SaveState([]);
            throw new GraphException("Stored Purview query id is malformed; state reset.");
        }

        var windowEnd = state.TryGetValue(PendingEndKey, out var endEl) && DateTimeOffset.TryParse(endEl.GetString(), CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out var e) ? e : (DateTimeOffset?)null;
        var createdAt = state.TryGetValue(PendingCreatedKey, out var cEl) && DateTimeOffset.TryParse(cEl.GetString(), CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out var c) ? c : context.Now;

        JsonDocument query;
        try
        {
            query = await context.Graph.GetAsync($"security/auditLog/queries/{Uri.EscapeDataString(queryId)}", cancellationToken);
        }
        catch (GraphException ex)
        {
            context.SaveState([]);
            throw new GraphException($"Purview query {queryId} could not be read ({ex.Message}); a new query will be submitted.", ex);
        }

        using (query)
        {
            var status = query.RootElement.Str("status") ?? "unknown";
            if (status is "failed" or "cancelled")
            {
                context.SaveState([]);
                throw new GraphException($"Purview query {queryId} ended with status '{status}'; it will be retried next run.");
            }

            var choice = Decide(status, RecordCapExceeded(query.RootElement));
            if (choice == QueryDecision.Wait)
            {
                if (context.Now - createdAt > PendingTimeout)
                {
                    context.SaveState([]);
                    throw new GraphException($"Purview query {queryId} did not complete within {PendingTimeout.TotalHours} hours; a new query will be submitted.");
                }

                return CollectorResult.Waiting($"query {queryId} is {status}", queryId);
            }

            return await DrainAsync(context, queryId, windowEnd, choice == QueryDecision.Complete, cancellationToken);
        }
    }

    /// <summary>
    /// A succeeded query finishes its window unless <c>isRecordCountLimitExceeded</c> is true.
    /// Any other status is still waiting. A missing flag is not a cap.
    /// </summary>
    internal static QueryDecision Decide(string? status, bool? recordCountLimitExceeded)
    {
        if (status != "succeeded")
        {
            return QueryDecision.Wait;
        }

        return recordCountLimitExceeded == true ? QueryDecision.Open : QueryDecision.Complete;
    }

    internal enum QueryDecision
    {
        Wait,
        Complete,
        Open,
    }

    private static async Task<CollectorResult> DrainAsync(CollectorContext context, string queryId, DateTimeOffset? windowEnd, bool closeWindow, CancellationToken cancellationToken)
    {
        var prior = context.State;
        var savedNext = prior.TryGetValue(PendingNextKey, out var nextEl) && nextEl.ValueKind == JsonValueKind.String ? nextEl.GetString() : null;
        var first = $"security/auditLog/queries/{Uri.EscapeDataString(queryId)}/records?$top={Math.Clamp(context.Options.GraphPageSize, 1, 999)}";
        var path = string.IsNullOrEmpty(savedNext) ? first : savedNext;
        try
        {
            return await ReadRecordsAsync(context, queryId, windowEnd, prior, path, closeWindow, cancellationToken);
        }
        catch (GraphException ex) when (IsRejectedRecordPage(ex))
        {
            if (string.IsNullOrEmpty(savedNext))
            {
                // This read started at the first page, so the bad link is not a saved cursor. Drop the query.
                context.SaveState([]);
                throw new GraphException($"Purview query {queryId} records could not be read ({ex.Message}); a new query will be submitted.", ex);
            }

            // A saved or later records link must not pin the drain. Read the query from the first page once.
            context.Logger.LogDebug("Purview query {QueryId} records link was rejected; reading the first page", queryId);
            context.SaveState(PendingState(prior, queryId, null));
            try
            {
                return await ReadRecordsAsync(context, queryId, windowEnd, prior, first, closeWindow, cancellationToken);
            }
            catch (GraphException again) when (IsRejectedRecordPage(again))
            {
                context.SaveState([]);
                throw new GraphException($"Purview query {queryId} records could not be read ({again.Message}); a new query will be submitted.", again);
            }
        }
    }

    private static async Task<CollectorResult> ReadRecordsAsync(CollectorContext context, string queryId, DateTimeOffset? windowEnd, Dictionary<string, JsonElement> prior, string path, bool closeWindow, CancellationToken cancellationToken)
    {
        var buffer = new List<SecurityEvent>(500);
        var totals = (Indexed: 0, Duplicates: 0, Failed: 0, Alerts: 0);
        var complete = true;
        DateTimeOffset? max = null;
        string? resume = null;

        try
        {
            await foreach (var record in context.Graph.GetPagedAsync(path, context.Options.MaxPagesPerRun * 5, cancellationToken, false, c => complete &= c, url => resume = url))
            {
                var mapped = Normalizers.AuditLogRecord(record, context.Tenant.TenantId, context.Tenant.DiscoveredName ?? context.Tenant.DisplayName);
                if (mapped is null)
                {
                    continue;
                }

                buffer.Add(mapped);
                max = max is null || mapped.Timestamp > max ? mapped.Timestamp : max;
                if (buffer.Count >= 500)
                {
                    var r = await context.PublishAsync(buffer, cancellationToken);
                    totals = (totals.Indexed + r.Indexed, totals.Duplicates + r.Duplicates, totals.Failed + r.Failed, totals.Alerts + r.Alerts);
                }

                if (context.OutOfTime)
                {
                    complete = false;
                    break;
                }
            }
        }
        catch (OperationCanceledException)
        {
            // The run budget cancelled the page read. Keep the resume URL the pager already stored.
            complete = false;
        }

        var last = await context.PublishAsync(buffer, cancellationToken.IsCancellationRequested ? CancellationToken.None : cancellationToken);
        totals = (totals.Indexed + last.Indexed, totals.Duplicates + last.Duplicates, totals.Failed + last.Failed, totals.Alerts + last.Alerts);

        if (totals.Failed > 0)
        {
            return new CollectorResult(totals.Indexed, totals.Duplicates, totals.Failed, totals.Alerts, false, $"query {queryId} index rejected records; the watermark was not moved") { QueryId = queryId };
        }

        if (!complete)
        {
            // Keep the query and the next page. The following run continues there instead of downloading page 1 again.
            context.SaveState(PendingState(prior, queryId, resume));
            return new CollectorResult(totals.Indexed, totals.Duplicates, totals.Failed, totals.Alerts, false, $"query {queryId} partially drained; resuming next run") { QueryId = queryId };
        }

        if (!closeWindow)
        {
            return LeaveCappedWindowOpen(context, queryId, prior, windowEnd, max, totals);
        }

        context.SaveState([]);
        var watermark = windowEnd ?? max ?? context.Checkpoint.Watermark;
        if (watermark is { } w && (context.Checkpoint.Watermark is null || w > context.Checkpoint.Watermark))
        {
            context.Checkpoint.Watermark = w;
        }

        return new CollectorResult(totals.Indexed, totals.Duplicates, totals.Failed, totals.Alerts, true) { QueryId = queryId };
    }

    /// <summary>
    /// The record cap stopped the query before the filter end. Resume from the newest indexed record, or keep this query.
    /// </summary>
    private static CollectorResult LeaveCappedWindowOpen(CollectorContext context, string queryId, Dictionary<string, JsonElement> prior, DateTimeOffset? windowEnd, DateTimeOffset? newest, (int Indexed, int Duplicates, int Failed, int Alerts) totals)
    {
        var resume = CappedWatermark(newest, context.Checkpoint.Watermark, windowEnd);
        if (resume is { } next)
        {
            // Drop the capped query. The next one starts at this record minus the overlap, not at the filter end.
            context.Checkpoint.Watermark = next;
            context.SaveState([]);
            return new CollectorResult(totals.Indexed, totals.Duplicates, totals.Failed, totals.Alerts, false, $"query {queryId} hit the record cap; resuming from the last indexed record") { QueryId = queryId };
        }

        context.SaveState(PendingState(prior, queryId, null));
        return new CollectorResult(totals.Indexed, totals.Duplicates, totals.Failed, totals.Alerts, false, $"query {queryId} hit the record cap; the window stays open") { QueryId = queryId };
    }

    /// <summary>Newest indexed record when it is ahead of the watermark and still before the filter end.</summary>
    private static DateTimeOffset? CappedWatermark(DateTimeOffset? newest, DateTimeOffset? watermark, DateTimeOffset? windowEnd)
    {
        if (newest is not { } indexed)
        {
            return null;
        }

        if (windowEnd is { } end && indexed >= end)
        {
            return null;
        }

        if (watermark is { } held && indexed <= held)
        {
            return null;
        }

        return indexed;
    }

    private static bool? RecordCapExceeded(JsonElement query)
    {
        if (query.ValueKind != JsonValueKind.Object || !query.TryGetProperty("isRecordCountLimitExceeded", out var flag))
        {
            return null;
        }

        return flag.ValueKind switch
        {
            JsonValueKind.True => true,
            JsonValueKind.False => false,
            _ => null,
        };
    }

    private static Dictionary<string, object?> PendingState(Dictionary<string, JsonElement> prior, string queryId, string? next) => new()
    {
        [PendingIdKey] = queryId,
        [PendingStartKey] = StateString(prior, PendingStartKey),
        [PendingEndKey] = StateString(prior, PendingEndKey),
        [PendingCreatedKey] = StateString(prior, PendingCreatedKey),
        [PendingNextKey] = next,
    };

    private static bool IsRejectedRecordPage(GraphException exception) =>
        exception.StatusCode is HttpStatusCode.BadRequest or HttpStatusCode.NotFound or HttpStatusCode.Gone;

    private static string? StateString(Dictionary<string, JsonElement> state, string key) =>
        state.TryGetValue(key, out var value) && value.ValueKind == JsonValueKind.String ? value.GetString() : null;

    private static bool IsSafeId(string id) => id.Length <= 128 && id.All(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '_');

    private static bool IsValidRecordType(string value) => value.Length <= 64 && value.All(char.IsAsciiLetterOrDigit);
}
