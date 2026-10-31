namespace Vulpes.Plugins.Microsoft365Audit;

/// <summary>Plugin settings (host configuration section <c>Plugins:Settings:audit</c>).</summary>
public sealed class AuditOptions
{
    /// <summary>How often the scheduler looks for due jobs.</summary>
    public int SchedulerIntervalSeconds { get; set; } = 20;

    public int MaxConcurrentJobs { get; set; } = 4;

    /// <summary>Upper bound for a single collector run; incomplete runs resume from the oldest record seen.</summary>
    public int RunTimeBudgetMinutes { get; set; } = 20;

    /// <summary>Default history fetched for a newly added tenant.</summary>
    public int DefaultLookbackDays { get; set; } = 7;

    /// <summary>Sign-in / directory / risk logs are re-read this far behind the watermark to catch late arrivals (deduplicated by id).</summary>
    public int LogOverlapMinutes { get; set; } = 30;

    /// <summary>Purview audit records can take a while to appear; queries end this far in the past.</summary>
    public int PurviewLagMinutes { get; set; } = 15;

    public int PurviewOverlapMinutes { get; set; } = 60;

    /// <summary>Maximum window per Purview query (backfill proceeds in windows of this size).</summary>
    public int PurviewMaxWindowHours { get; set; } = 24;

    /// <summary>Maximum number of Graph pages fetched per run per endpoint.</summary>
    public int MaxPagesPerRun { get; set; } = 400;

    public int GraphPageSize { get; set; } = 500;

    /// <summary>Default record types for the Purview unified audit log query (tenant settings may override).</summary>
    public List<string> PurviewRecordTypes { get; set; } =
    [
        "sharePoint", "sharePointFileOperation", "sharePointSharingOperation", "sharePointListOperation", "oneDrive",
        "exchangeAdmin", "exchangeItem", "exchangeItemGroup", "exchangeAggregatedOperation", "mailSubmission",
        "azureActiveDirectory", "azureActiveDirectoryAccountLogon", "azureActiveDirectoryStsLogon",
        "microsoftTeams", "microsoftTeamsAdmin", "securityComplianceAlerts", "securityComplianceCenterEOPCmdlet",
        "threatIntelligence", "threatIntelligenceUrl", "threatIntelligenceAtpContent", "threatFinder",
        "complianceDLPSharePoint", "complianceDLPExchange", "dataGovernance", "powerBIAudit", "microsoftFlow", "powerAppsApp",
    ];

    /// <summary>Microsoft 365 Business Premium includes Entra ID P1. Identity Protection risk reports need P2, so that source is not collected.</summary>
    public bool BusinessPremiumMode { get; set; }

    /// <summary>When Business Premium mode is on, omit the Risk page from the menu. Turning the mode off clears this.</summary>
    public bool HideRiskMenu { get; set; }

    /// <summary>Sources the Graph APIs will not serve on a Business Premium tenant.</summary>
    public static readonly string[] BusinessPremiumUnavailableSources = ["risk"];

    public bool Collects(string source) =>
        !(BusinessPremiumMode && BusinessPremiumUnavailableSources.Contains(source, StringComparer.Ordinal));

    /// <summary>Default run intervals per source in minutes.</summary>
    public Dictionary<string, int> IntervalMinutes { get; set; } = new(StringComparer.Ordinal)
    {
        ["signins"] = 5,
        ["directory"] = 5,
        ["provisioning"] = 15,
        ["activity"] = 30,
        ["security-alerts"] = 5,
        ["incidents"] = 10,
        ["risk"] = 10,
        ["securescore"] = 24 * 60,
    };

    public TimeSpan IntervalFor(string source) =>
        TimeSpan.FromMinutes(Math.Clamp(IntervalMinutes.GetValueOrDefault(source, 15), 1, 24 * 60 * 7));
}
