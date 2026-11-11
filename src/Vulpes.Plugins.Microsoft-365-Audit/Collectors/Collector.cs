using System.Globalization;
using System.Text.Json;
using System.Text.RegularExpressions;
using Vulpes.Plugins.Microsoft365Audit.Data;
using Vulpes.Plugins.Microsoft365Audit.Graph;
using Vulpes.Plugins.Microsoft365Audit.Tenants;
using Vulpes.Sdk;

namespace Vulpes.Plugins.Microsoft365Audit.Collectors;

public sealed record CollectorResult(int Published, int Duplicates, int Failed, int Alerts, bool Complete, string? Note = null)
{
    /// <summary>Purview query this run checked. A later row for the same query replaces the earlier one in Recent runs.</summary>
    public string? QueryId { get; init; }

    public static CollectorResult Empty(string? note = null) => new(0, 0, 0, 0, true, note);

    /// <summary>The run is not finished. The scheduler polls again shortly instead of waiting the full interval.</summary>
    public static CollectorResult Waiting(string? note = null, string? queryId = null) => new(0, 0, 0, 0, false, note) { QueryId = queryId };
}

/// <summary>Everything a collector needs for one run against one tenant.</summary>
public sealed class CollectorContext
{
    public required Tenant Tenant { get; init; }
    public required SourceSettings Settings { get; init; }
    public required GraphClient Graph { get; init; }
    public required Checkpoint Checkpoint { get; init; }
    public required IEventPipeline Pipeline { get; init; }
    public required AuditOptions Options { get; init; }
    public required TimeProvider Time { get; init; }
    public required ILogger Logger { get; init; }
    public required DateTimeOffset Deadline { get; init; }

    public DateTimeOffset Now => Time.GetUtcNow();

    public bool OutOfTime => Now >= Deadline;

    /// <summary>Starting point for a window: watermark minus overlap, or the configured lookback for first runs.</summary>
    public DateTimeOffset WindowStart(TimeSpan overlap)
    {
        if (Checkpoint.Watermark is { } watermark)
        {
            return watermark - overlap;
        }

        return Now.AddDays(-Math.Clamp(Tenant.LookbackDays, 1, 180));
    }

    public Dictionary<string, JsonElement> State =>
        string.IsNullOrEmpty(Checkpoint.StateJson) ? [] : JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(Checkpoint.StateJson) ?? [];

    public void SaveState(Dictionary<string, object?> state) => Checkpoint.StateJson = state.Count == 0 ? null : JsonSerializer.Serialize(state);

    /// <summary>Publishes in batches and accumulates the result.</summary>
    public async Task<(int Indexed, int Duplicates, int Failed, int Alerts)> PublishAsync(List<SecurityEvent> buffer, CancellationToken cancellationToken)
    {
        if (buffer.Count == 0)
        {
            return (0, 0, 0, 0);
        }

        var result = await Pipeline.PublishAsync(buffer, cancellationToken);
        buffer.Clear();
        return (result.Indexed, result.Duplicates, result.Failed, result.AlertsRaised);
    }
}

public interface ICollector
{
    string Source { get; }
    string Title { get; }
    IReadOnlyList<string> RequiredPermissions { get; }

    /// <summary>Graph path (relative to v1.0) used by the connection test to probe permissions.</summary>
    string ProbePath { get; }

    Task<CollectorResult> CollectAsync(CollectorContext context, CancellationToken cancellationToken);
}

/// <summary>Shared loop for "list with a time filter, advance the watermark" collectors.</summary>
public abstract class WatermarkCollector : ICollector
{
    public abstract string Source { get; }
    public abstract string Title { get; }
    public abstract IReadOnlyList<string> RequiredPermissions { get; }
    public abstract string ProbePath { get; }

    /// <summary>Builds the Graph request path for records at or after <paramref name="from"/>.</summary>
    protected abstract string BuildPath(CollectorContext context, DateTimeOffset from);

    /// <summary>Date field used to page oldest-first. Must be the same field the filter and <see cref="Map"/> use.</summary>
    protected abstract string OrderByField { get; }

    protected virtual bool UseBeta => false;

    protected virtual TimeSpan Overlap(CollectorContext context) => TimeSpan.FromMinutes(context.Options.LogOverlapMinutes);

    /// <summary>Graph refuses a filter older than this. Null means the source has no such floor.</summary>
    protected virtual TimeSpan? Retention => null;

    /// <summary>Maps a record to an event and returns its timestamp for watermark tracking; null to skip.</summary>
    protected abstract (SecurityEvent Event, DateTimeOffset Timestamp)? Map(CollectorContext context, JsonElement record);

    public async Task<CollectorResult> CollectAsync(CollectorContext context, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        var requested = context.WindowStart(Overlap(context));
        var from = Clamp(context, requested);
        string? moved = from > requested ? RetentionNote(from) : null;
        GraphException? rejected = null;
        // Graph names the oldest activityDateTime it will accept. A single step of one minute
        // can still fall on the rejected day, and the overlap would walk the next run back into it.
        for (var attempt = 0; attempt < 6; attempt++)
        {
            try
            {
                return await ReadAsync(context, from, moved, cancellationToken);
            }
            catch (GraphException ex) when (ActivityTimeFloor.TryParse(ex.Message, out var minimum))
            {
                rejected = ex;
                if (AdvancePastFloor(from, minimum, context.Now) is not { } advanced)
                {
                    throw;
                }

                from = advanced;
                RememberAcceptedStart(context, from);
                moved = RetentionNote(from);
            }
        }

        throw rejected!;
    }

    /// <summary>The next UTC day after the floor Graph named, or one day after <paramref name="from"/> when that day was already rejected.</summary>
    private static DateTimeOffset? AdvancePastFloor(DateTimeOffset from, DateTimeOffset minimum, DateTimeOffset now)
    {
        var afterNamedDay = new DateTimeOffset(minimum.UtcDateTime.Date.AddDays(1), TimeSpan.Zero);
        var candidate = afterNamedDay > from
            ? afterNamedDay
            : new DateTimeOffset(from.UtcDateTime.Date.AddDays(1), TimeSpan.Zero);
        if (candidate > now)
        {
            candidate = now;
        }

        return candidate > from ? candidate : null;
    }

    private void RememberAcceptedStart(CollectorContext context, DateTimeOffset from)
    {
        var remembered = from + Overlap(context);
        if (remembered > context.Now)
        {
            remembered = context.Now;
        }

        if (context.Checkpoint.Watermark is null || remembered > context.Checkpoint.Watermark)
        {
            context.Checkpoint.Watermark = remembered;
        }
    }

    private static string RetentionNote(DateTimeOffset from) =>
        $"started at {from:O}; earlier records are outside Microsoft's retention";

    private async Task<CollectorResult> ReadAsync(CollectorContext context, DateTimeOffset from, string? moved, CancellationToken cancellationToken)
    {
        var path = BuildPath(context, from);
        path += path.Contains('?', StringComparison.Ordinal) ? "&" : "?";
        path += "%24orderby=" + Uri.EscapeDataString(OrderByField + " asc");
        var buffer = new List<SecurityEvent>(500);
        DateTimeOffset? max = null;
        var totals = (Indexed: 0, Duplicates: 0, Failed: 0, Alerts: 0);
        var complete = true;
        var seen = 0;

        await foreach (var record in context.Graph.GetPagedAsync(path, context.Options.MaxPagesPerRun, cancellationToken, UseBeta, c => complete &= c))
        {
            if (Map(context, record) is not { } mapped)
            {
                continue;
            }

            seen++;
            buffer.Add(mapped.Event);
            max = max is null || mapped.Timestamp > max ? mapped.Timestamp : max;
            if (buffer.Count >= 500)
            {
                var r = await context.PublishAsync(buffer, cancellationToken);
                totals = Add(totals, r);
            }

            if (context.OutOfTime)
            {
                complete = false;
                break;
            }
        }

        var last = await context.PublishAsync(buffer, cancellationToken);
        totals = Add(totals, last);

        // A rejected index is retried from the same watermark. Moving it forward would drop those events
        // once they fall outside the overlap.
        if (totals.Failed > 0)
        {
            return new CollectorResult(totals.Indexed, totals.Duplicates, totals.Failed, totals.Alerts, false, "Elasticsearch rejected records; the watermark was not moved");
        }

        // Oldest-first: a partial run has ingested everything from the window start through max.
        // The next run continues after max. An empty finished run moves the watermark to now.
        DateTimeOffset? newWatermark = max ?? (complete ? context.Checkpoint.Watermark ?? context.Now : context.Checkpoint.Watermark);
        if (newWatermark is { } w && (context.Checkpoint.Watermark is null || w > context.Checkpoint.Watermark))
        {
            context.Checkpoint.Watermark = w;
        }

        var reason = context.OutOfTime ? "time budget" : "page budget";
        var partial = complete ? null : $"partial run: {seen} records read ({reason}), resuming from {newWatermark:O}";
        return new CollectorResult(totals.Indexed, totals.Duplicates, totals.Failed, totals.Alerts, complete, partial ?? moved);
    }

    private DateTimeOffset Clamp(CollectorContext context, DateTimeOffset from)
    {
        if (Retention is not { } retention)
        {
            return from;
        }

        // One day inside the published retention. Graph rejects a filter on the exact 30-day boundary.
        var earliest = context.Now - retention + TimeSpan.FromDays(1);
        return from < earliest ? earliest : from;
    }

    private static (int, int, int, int) Add((int Indexed, int Duplicates, int Failed, int Alerts) a, (int Indexed, int Duplicates, int Failed, int Alerts) b) =>
        (a.Indexed + b.Indexed, a.Duplicates + b.Duplicates, a.Failed + b.Failed, a.Alerts + b.Alerts);
}

/// <summary>Reads the oldest activityDateTime Graph will accept out of a 400 response.</summary>
public static class ActivityTimeFloor
{
    private static readonly Regex Pattern = new(@"Minimum allowed time for \w+ is (?<when>[^']+)", RegexOptions.CultureInvariant | RegexOptions.Compiled);

    public static bool TryParse(string? message, out DateTimeOffset minimum)
    {
        minimum = default;
        if (string.IsNullOrWhiteSpace(message))
        {
            return false;
        }

        var match = Pattern.Match(message);
        if (!match.Success)
        {
            return false;
        }

        // Graph prints the floor with a narrow no-break space before AM/PM.
        var text = match.Groups["when"].Value.Trim().Replace('\u00A0', ' ').Replace('\u202F', ' ').Replace('\u2007', ' ');
        var styles = DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal;
        return DateTimeOffset.TryParse(text, CultureInfo.GetCultureInfo("en-US"), styles, out minimum)
            || DateTimeOffset.TryParse(text, CultureInfo.InvariantCulture, styles, out minimum);
    }
}

/// <summary>JSON helpers tolerant of missing properties.</summary>
public static class J
{
    public static string? Str(this JsonElement e, string name) =>
        e.ValueKind == JsonValueKind.Object && e.TryGetProperty(name, out var v) ? v.ValueKind switch
        {
            JsonValueKind.String => v.GetString(),
            JsonValueKind.Number or JsonValueKind.True or JsonValueKind.False => v.GetRawText(),
            _ => null,
        } : null;

    public static JsonElement? Obj(this JsonElement e, string name) =>
        e.ValueKind == JsonValueKind.Object && e.TryGetProperty(name, out var v) && v.ValueKind is JsonValueKind.Object or JsonValueKind.Array ? v : null;

    public static DateTimeOffset? Date(this JsonElement e, string name)
    {
        var text = e.Str(name);
        return text is not null && DateTimeOffset.TryParse(text, System.Globalization.CultureInfo.InvariantCulture, System.Globalization.DateTimeStyles.AssumeUniversal, out var d) ? d : null;
    }

    public static double? Num(this JsonElement e, string name) =>
        e.ValueKind == JsonValueKind.Object && e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.Number ? v.GetDouble() : null;

    public static int? WholeNumber(this JsonElement e, string name) =>
        e.ValueKind == JsonValueKind.Object && e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.Number && v.TryGetInt32(out var i) ? i : null;

    public static string? Truncate(string? value, int max) => value is null ? null : value.Length <= max ? value : value[..max];
}
