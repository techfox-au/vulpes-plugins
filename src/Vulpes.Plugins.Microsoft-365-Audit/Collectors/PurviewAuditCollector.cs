using System.Globalization;
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
        context.Logger.LogInformation("Purview audit query {QueryId} created for {Tenant}: {Start} .. {End}", id, context.Tenant.DisplayName, start, end);
        return CollectorResult.Empty($"query {id} submitted for {start:O}..{end:O}");
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

        using var query = await context.Graph.GetAsync($"security/auditLog/queries/{Uri.EscapeDataString(queryId)}", cancellationToken);
        var status = query.RootElement.Str("status") ?? "unknown";
        switch (status)
        {
            case "succeeded":
                return await DrainAsync(context, queryId, windowEnd, cancellationToken);
            case "failed":
            case "cancelled":
                context.SaveState([]);
                throw new GraphException($"Purview query {queryId} ended with status '{status}'; it will be retried next run.");
            default:
                if (context.Now - createdAt > PendingTimeout)
                {
                    context.SaveState([]);
                    throw new GraphException($"Purview query {queryId} did not complete within {PendingTimeout.TotalHours} hours; a new query will be submitted.");
                }

                return new CollectorResult(0, 0, 0, 0, true, $"query {queryId} is {status}");
        }
    }

    private static async Task<CollectorResult> DrainAsync(CollectorContext context, string queryId, DateTimeOffset? windowEnd, CancellationToken cancellationToken)
    {
        var buffer = new List<SecurityEvent>(500);
        var totals = (Indexed: 0, Duplicates: 0, Failed: 0, Alerts: 0);
        var complete = true;
        DateTimeOffset? max = null;
        var path = $"security/auditLog/queries/{Uri.EscapeDataString(queryId)}/records?$top={Math.Clamp(context.Options.GraphPageSize, 1, 1000)}";

        await foreach (var record in context.Graph.GetPagedAsync(path, context.Options.MaxPagesPerRun * 5, cancellationToken, false, c => complete &= c))
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

        var last = await context.PublishAsync(buffer, cancellationToken);
        totals = (totals.Indexed + last.Indexed, totals.Duplicates + last.Duplicates, totals.Failed + last.Failed, totals.Alerts + last.Alerts);

        if (!complete)
        {
            // Keep the pending query so the next run resumes paging (duplicates are harmless).
            return new CollectorResult(totals.Indexed, totals.Duplicates, totals.Failed, totals.Alerts, false, $"query {queryId} partially drained; resuming next run");
        }

        context.SaveState([]);
        var watermark = windowEnd ?? max ?? context.Checkpoint.Watermark;
        if (watermark is { } w && (context.Checkpoint.Watermark is null || w > context.Checkpoint.Watermark))
        {
            context.Checkpoint.Watermark = w;
        }

        return new CollectorResult(totals.Indexed, totals.Duplicates, totals.Failed, totals.Alerts, true, $"query {queryId} drained");
    }

    private static bool IsSafeId(string id) => id.Length <= 128 && id.All(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '_');

    private static bool IsValidRecordType(string value) => value.Length <= 64 && value.All(char.IsAsciiLetterOrDigit);
}
