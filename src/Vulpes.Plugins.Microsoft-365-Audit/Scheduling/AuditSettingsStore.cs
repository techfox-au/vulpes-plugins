using System.Text.Json;
using System.Text.Json.Serialization;

namespace Vulpes.Plugins.Microsoft365Audit.Scheduling;

/// <summary>Plugin-only collection settings. Defaults come from configuration; saved values override them and stay on the options object the collectors already read.</summary>
public sealed class AuditSettingsStore
{
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web) { DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull };
    private static readonly string[] IntervalSources = ["signins", "directory", "provisioning", "activity", "security-alerts", "incidents", "risk", "securescore"];
    private readonly string _path;
    private readonly AuditOptions _options;

    public AuditSettingsStore(string path, AuditOptions options)
    {
        _path = path;
        _options = options;
    }

    public void Load()
    {
        if (!File.Exists(_path))
        {
            return;
        }

        AuditSettingsDocument? saved;
        try
        {
            saved = JsonSerializer.Deserialize<AuditSettingsDocument>(File.ReadAllText(_path), Json);
        }
        catch (JsonException)
        {
            return;
        }

        if (saved is not null)
        {
            Apply(saved, _options);
        }
    }

    public AuditSettingsDocument Current() => AuditSettingsDocument.From(_options);

    public string? Save(AuditSettingsDocument input)
    {
        var error = Apply(input, _options);
        if (error is not null)
        {
            return error;
        }

        Directory.CreateDirectory(Path.GetDirectoryName(_path)!);
        File.WriteAllText(_path, JsonSerializer.Serialize(_options is null ? input : AuditSettingsDocument.From(_options), Json));
        return null;
    }

    public static string? Apply(AuditSettingsDocument input, AuditOptions target)
    {
        ArgumentNullException.ThrowIfNull(input);
        ArgumentNullException.ThrowIfNull(target);
        if (input.SchedulerIntervalSeconds is < 5 or > 600)
        {
            return "Scheduler interval must be between 5 and 600 seconds.";
        }

        if (input.MaxConcurrentJobs is < 1 or > 32)
        {
            return "Concurrent jobs must be between 1 and 32.";
        }

        if (input.RunTimeBudgetMinutes is < 1 or > 180)
        {
            return "Run time budget must be between 1 and 180 minutes.";
        }

        if (input.DefaultLookbackDays is < 1 or > 180)
        {
            return "Default lookback must be between 1 and 180 days.";
        }

        if (input.LogOverlapMinutes is < 0 or > 24 * 60)
        {
            return "Log overlap must be between 0 and 1440 minutes.";
        }

        if (input.PurviewLagMinutes is < 0 or > 24 * 60)
        {
            return "Activity lag must be between 0 and 1440 minutes.";
        }

        if (input.PurviewOverlapMinutes is < 0 or > 24 * 60)
        {
            return "Activity overlap must be between 0 and 1440 minutes.";
        }

        if (input.PurviewMaxWindowHours is < 1 or > 24 * 7)
        {
            return "Activity window must be between 1 and 168 hours.";
        }

        if (input.MaxPagesPerRun is < 1 or > 5000)
        {
            return "Max pages per run must be between 1 and 5000.";
        }

        if (input.GraphPageSize is < 1 or > 999)
        {
            return "Page size must be between 1 and 999.";
        }

        var intervals = new Dictionary<string, int>(StringComparer.Ordinal);
        foreach (var source in IntervalSources)
        {
            if (input.IntervalMinutes is null || !input.IntervalMinutes.TryGetValue(source, out var minutes) || minutes is < 1 or > 24 * 60 * 7)
            {
                return $"Interval for {source} must be between 1 and 10080 minutes.";
            }

            intervals[source] = minutes;
        }

        var recordTypes = (input.PurviewRecordTypes ?? []).Select(s => s.Trim()).Where(s => s.Length > 0).Distinct(StringComparer.Ordinal).ToList();
        if (recordTypes.Count == 0 || recordTypes.Any(s => s.Length > 80 || s.Any(c => !char.IsLetterOrDigit(c))))
        {
            return "Activity record types must be a list of names.";
        }

        target.SchedulerIntervalSeconds = input.SchedulerIntervalSeconds;
        target.MaxConcurrentJobs = input.MaxConcurrentJobs;
        target.RunTimeBudgetMinutes = input.RunTimeBudgetMinutes;
        target.DefaultLookbackDays = input.DefaultLookbackDays;
        target.LogOverlapMinutes = input.LogOverlapMinutes;
        target.PurviewLagMinutes = input.PurviewLagMinutes;
        target.PurviewOverlapMinutes = input.PurviewOverlapMinutes;
        target.PurviewMaxWindowHours = input.PurviewMaxWindowHours;
        target.MaxPagesPerRun = input.MaxPagesPerRun;
        target.GraphPageSize = input.GraphPageSize;
        target.IntervalMinutes = intervals;
        target.PurviewRecordTypes = recordTypes;
        target.BusinessPremiumMode = input.BusinessPremiumMode;
        target.HideRiskMenu = input.BusinessPremiumMode && input.HideRiskMenu;
        return null;
    }
}

public sealed class AuditSettingsDocument
{
    public int SchedulerIntervalSeconds { get; set; }
    public int MaxConcurrentJobs { get; set; }
    public int RunTimeBudgetMinutes { get; set; }
    public int DefaultLookbackDays { get; set; }
    public int LogOverlapMinutes { get; set; }
    public int PurviewLagMinutes { get; set; }
    public int PurviewOverlapMinutes { get; set; }
    public int PurviewMaxWindowHours { get; set; }
    public int MaxPagesPerRun { get; set; }
    public int GraphPageSize { get; set; }
    public Dictionary<string, int> IntervalMinutes { get; set; } = new(StringComparer.Ordinal);
    public List<string> PurviewRecordTypes { get; set; } = [];

    public bool BusinessPremiumMode { get; set; }

    public bool HideRiskMenu { get; set; }

    public static AuditSettingsDocument From(AuditOptions options) => new()
    {
        SchedulerIntervalSeconds = options.SchedulerIntervalSeconds,
        MaxConcurrentJobs = options.MaxConcurrentJobs,
        RunTimeBudgetMinutes = options.RunTimeBudgetMinutes,
        DefaultLookbackDays = options.DefaultLookbackDays,
        LogOverlapMinutes = options.LogOverlapMinutes,
        PurviewLagMinutes = options.PurviewLagMinutes,
        PurviewOverlapMinutes = options.PurviewOverlapMinutes,
        PurviewMaxWindowHours = options.PurviewMaxWindowHours,
        MaxPagesPerRun = options.MaxPagesPerRun,
        GraphPageSize = options.GraphPageSize,
        IntervalMinutes = new Dictionary<string, int>(options.IntervalMinutes, StringComparer.Ordinal),
        PurviewRecordTypes = [.. options.PurviewRecordTypes],
        BusinessPremiumMode = options.BusinessPremiumMode,
        HideRiskMenu = options.HideRiskMenu,
    };
}
