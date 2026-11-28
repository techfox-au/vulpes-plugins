using System.Globalization;
using System.Text.Json;
using Vulpes.Plugins.Microsoft365Audit.Graph;
using Vulpes.Plugins.Microsoft365Audit.Normalization;
using Vulpes.Sdk;

namespace Vulpes.Plugins.Microsoft365Audit.Collectors;

/// <summary>Interactive sign-ins (v1.0) plus, when enabled per tenant, non-interactive / service principal / managed identity sign-ins (beta).</summary>
public sealed class SignInsCollector : ICollector
{
    /// <summary>Remembered so turning non-interactive users back on can drop a service-principal-only cursor.</summary>
    private const string IncludeNonInteractiveKey = "includeNonInteractive";

    public string Source => Sources.SignIns;
    public string Title => "Entra ID sign-ins";
    public IReadOnlyList<string> RequiredPermissions => ["AuditLog.Read.All", "Directory.Read.All"];
    public string ProbePath => "auditLogs/signIns?$top=1";

    public async Task<CollectorResult> CollectAsync(CollectorContext context, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        var interactive = new Interactive();
        var result = await interactive.CollectAsync(context, cancellationToken);
        if (!result.Complete)
        {
            return result;
        }

        // The non-interactive feed keeps its own watermark in the checkpoint state.
        // A cursor saved while user sign-ins were off is only service principals. Drop it when they are turned back on
        // so this run starts at the tenant lookback instead of that cursor.
        var includeUsers = context.Settings.IncludeNonInteractive;
        if (NonInteractiveUsersTurnedOn(context.State, includeUsers))
        {
            DropNonInteractiveCursor(context);
        }

        var state = context.State;
        var nonInteractiveWatermark = state.TryGetValue("nonInteractiveWatermark", out var w) && w.ValueKind == JsonValueKind.String && DateTimeOffset.TryParse(w.GetString(), CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out var parsed) ? parsed : (DateTimeOffset?)null;
        var shadow = new Data.Checkpoint { TenantId = context.Checkpoint.TenantId, Source = Source, Watermark = nonInteractiveWatermark, StateJson = context.Checkpoint.StateJson };
        var shadowContext = new CollectorContext
        {
            Tenant = context.Tenant,
            Settings = context.Settings,
            Graph = context.Graph,
            Checkpoint = shadow,
            Pipeline = context.Pipeline,
            Options = context.Options,
            Time = context.Time,
            Logger = context.Logger,
            Deadline = context.Deadline,
        };
        var second = await new NonInteractive().CollectAsync(shadowContext, cancellationToken);
        // The beta feed's resume link lives on the shadow checkpoint. Keep it beside the interactive cursor.
        var merged = new Dictionary<string, object?>();
        foreach (var pair in shadowContext.State)
        {
            if (pair.Value.ValueKind == JsonValueKind.String)
            {
                merged[pair.Key] = pair.Value.GetString();
            }
        }

        merged["nonInteractiveWatermark"] = shadow.Watermark?.ToString("O", CultureInfo.InvariantCulture);
        merged[IncludeNonInteractiveKey] = includeUsers ? "true" : "false";
        context.SaveState(merged);
        var note = second.Note is not null && !second.Complete ? "non-interactive " + second.Note : second.Note ?? result.Note;
        return new CollectorResult(result.Published + second.Published, result.Duplicates + second.Duplicates, result.Failed + second.Failed, result.Alerts + second.Alerts, second.Complete, note);
    }

    private sealed class Interactive : WatermarkCollector
    {
        public override string Source => Sources.SignIns;
        public override string Title => "Interactive sign-ins";
        public override IReadOnlyList<string> RequiredPermissions => ["AuditLog.Read.All"];
        public override string ProbePath => "auditLogs/signIns?$top=1";

        protected override string OrderByField => "createdDateTime";

        // List sign-ins does not support $orderby and returns newest createdDateTime first.
        protected override bool OrderByAscending => false;

        protected override string BuildPath(CollectorContext context, DateTimeOffset from) =>
            $"auditLogs/signIns?$filter=createdDateTime%20ge%20{OData.Timestamp(from)}&$top={Math.Clamp(context.Options.GraphPageSize, 1, 999)}";

        protected override (SecurityEvent Event, DateTimeOffset Timestamp)? Map(CollectorContext context, JsonElement record)
        {
            var e = Normalizers.SignIn(record, context.Tenant.TenantId, context.Tenant.DiscoveredName ?? context.Tenant.DisplayName, "interactive");
            return e is null ? null : (e, e.Timestamp);
        }
    }

    private sealed class NonInteractive : WatermarkCollector
    {
        public override string Source => Sources.SignIns;
        public override string Title => "Non-interactive sign-ins";
        public override IReadOnlyList<string> RequiredPermissions => ["AuditLog.Read.All"];
        public override string ProbePath => "auditLogs/signIns?$top=1";
        protected override bool UseBeta => true;

        protected override string OrderByField => "createdDateTime";

        // The beta sign-in feed also rejects $orderby and is newest createdDateTime first.
        protected override bool OrderByAscending => false;

        /// <summary>Shares the sign-in checkpoint with the interactive feed, so its cursor uses its own keys.</summary>
        protected override string StatePrefix => "nonInteractive";

        /// <summary>Service-principal-only passes must not plant a cursor that later hides non-interactive user sign-ins.</summary>
        protected override bool AdvanceEmptyWatermarkToNow(CollectorContext context) => context.Settings.IncludeNonInteractive;

        protected override string BuildPath(CollectorContext context, DateTimeOffset from)
        {
            var types = context.Settings.IncludeNonInteractive
                ? "t%20eq%20'nonInteractiveUser'%20or%20t%20eq%20'servicePrincipal'%20or%20t%20eq%20'managedIdentity'"
                : "t%20eq%20'servicePrincipal'%20or%20t%20eq%20'managedIdentity'";
            return $"auditLogs/signIns?$filter=createdDateTime%20ge%20{OData.Timestamp(from)}%20and%20signInEventTypes/any(t:%20{types})&$top={Math.Clamp(context.Options.GraphPageSize, 1, 999)}";
        }

        protected override (SecurityEvent Event, DateTimeOffset Timestamp)? Map(CollectorContext context, JsonElement record)
        {
            var type = "nonInteractive";
            if (record.TryGetProperty("signInEventTypes", out var types) && types.ValueKind == JsonValueKind.Array)
            {
                foreach (var t in types.EnumerateArray())
                {
                    var value = t.GetString();
                    if (value is "servicePrincipal" or "managedIdentity")
                    {
                        type = value;
                        break;
                    }
                }
            }

            var e = Normalizers.SignIn(record, context.Tenant.TenantId, context.Tenant.DiscoveredName ?? context.Tenant.DisplayName, type);
            return e is null ? null : (e, e.Timestamp);
        }
    }

    private static bool NonInteractiveUsersTurnedOn(Dictionary<string, JsonElement> state, bool includeNonInteractive)
    {
        if (!includeNonInteractive
            || !state.TryGetValue(IncludeNonInteractiveKey, out var previous)
            || previous.ValueKind != JsonValueKind.String)
        {
            return false;
        }

        return string.Equals(previous.GetString(), "false", StringComparison.OrdinalIgnoreCase);
    }

    private static void DropNonInteractiveCursor(CollectorContext context)
    {
        var kept = new Dictionary<string, object?>();
        foreach (var pair in context.State)
        {
            if (pair.Value.ValueKind != JsonValueKind.String)
            {
                continue;
            }

            if (pair.Key is "nonInteractiveWatermark" or "nonInteractiveResumeUrl" or "nonInteractiveWindowNewest")
            {
                continue;
            }

            kept[pair.Key] = pair.Value.GetString();
        }

        context.SaveState(kept);
    }
}

public sealed class DirectoryAuditsCollector : WatermarkCollector
{
    public override string Source => Sources.Directory;
    public override string Title => "Entra ID directory audits";
    public override IReadOnlyList<string> RequiredPermissions => ["AuditLog.Read.All", "Directory.Read.All"];
    public override string ProbePath => "auditLogs/directoryAudits?$top=1";

    protected override TimeSpan? Retention => TimeSpan.FromDays(30);

    protected override string OrderByField => "activityDateTime";

    protected override string BuildPath(CollectorContext context, DateTimeOffset from) =>
        $"auditLogs/directoryAudits?$filter=activityDateTime%20ge%20{OData.Timestamp(from)}&$top={Math.Clamp(context.Options.GraphPageSize, 1, 999)}";

    protected override (SecurityEvent Event, DateTimeOffset Timestamp)? Map(CollectorContext context, JsonElement record)
    {
        var e = Normalizers.DirectoryAudit(record, context.Tenant.TenantId, context.Tenant.DiscoveredName ?? context.Tenant.DisplayName);
        return e is null ? null : (e, e.Timestamp);
    }
}

public sealed class ProvisioningCollector : WatermarkCollector
{
    public override string Source => Sources.Provisioning;
    public override string Title => "Entra ID provisioning logs";
    public override IReadOnlyList<string> RequiredPermissions => ["AuditLog.Read.All"];
    public override string ProbePath => "auditLogs/provisioning?$top=1";

    protected override TimeSpan? Retention => TimeSpan.FromDays(30);

    protected override string OrderByField => "activityDateTime";

    protected override string BuildPath(CollectorContext context, DateTimeOffset from) =>
        $"auditLogs/provisioning?$filter=activityDateTime%20ge%20{OData.Timestamp(from)}&$top={Math.Clamp(context.Options.GraphPageSize, 1, 999)}";

    protected override (SecurityEvent Event, DateTimeOffset Timestamp)? Map(CollectorContext context, JsonElement record)
    {
        var e = Normalizers.Provisioning(record, context.Tenant.TenantId, context.Tenant.DiscoveredName ?? context.Tenant.DisplayName);
        return e is null ? null : (e, e.Timestamp);
    }
}

public sealed class SecurityAlertsCollector : WatermarkCollector
{
    public override string Source => Sources.SecurityAlerts;
    public override string Title => "Microsoft Defender alerts";
    public override IReadOnlyList<string> RequiredPermissions => ["SecurityAlert.Read.All"];
    public override string ProbePath => "security/alerts_v2?$top=1";

    protected override TimeSpan Overlap(CollectorContext context) => TimeSpan.FromMinutes(10);

    protected override string OrderByField => "lastUpdateDateTime";

    protected override bool OrderByAscending => false;

    protected override string BuildPath(CollectorContext context, DateTimeOffset from) =>
        $"security/alerts_v2?$filter=lastUpdateDateTime%20ge%20{OData.Timestamp(from)}&$top={Math.Clamp(context.Options.GraphPageSize, 1, 999)}";

    protected override (SecurityEvent Event, DateTimeOffset Timestamp)? Map(CollectorContext context, JsonElement record)
    {
        var e = Normalizers.SecurityAlert(record, context.Tenant.TenantId, context.Tenant.DiscoveredName ?? context.Tenant.DisplayName);
        return e is null ? null : (e, record.Date("lastUpdateDateTime") ?? e.Timestamp);
    }
}

public sealed class IncidentsCollector : WatermarkCollector
{
    public override string Source => Sources.Incidents;
    public override string Title => "Microsoft Defender incidents";
    public override IReadOnlyList<string> RequiredPermissions => ["SecurityIncident.Read.All"];
    public override string ProbePath => "security/incidents?$top=1";

    protected override TimeSpan Overlap(CollectorContext context) => TimeSpan.FromMinutes(10);

    protected override string OrderByField => "lastUpdateDateTime";

    protected override bool OrderByAscending => false;

    protected override string BuildPath(CollectorContext context, DateTimeOffset from) =>
        $"security/incidents?$filter=lastUpdateDateTime%20ge%20{OData.Timestamp(from)}&$top={Math.Clamp(context.Options.GraphPageSize, 1, 50)}";

    protected override (SecurityEvent Event, DateTimeOffset Timestamp)? Map(CollectorContext context, JsonElement record)
    {
        var e = Normalizers.Incident(record, context.Tenant.TenantId, context.Tenant.DiscoveredName ?? context.Tenant.DisplayName);
        return e is null ? null : (e, record.Date("lastUpdateDateTime") ?? e.Timestamp);
    }
}

/// <summary>Identity Protection: risk detections, risky users and risky service principals, appended as they change.</summary>
public sealed class RiskCollector : ICollector
{
    public string Source => Sources.Risk;
    public string Title => "Entra ID Protection risk";
    public IReadOnlyList<string> RequiredPermissions => ["IdentityRiskEvent.Read.All", "IdentityRiskyUser.Read.All", "IdentityRiskyServicePrincipal.Read.All"];
    public string ProbePath => "identityProtection/riskDetections?$top=1";

    public async Task<CollectorResult> CollectAsync(CollectorContext context, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        // Each feed has its own watermark. Sharing the checkpoint would make a finished detection pass
        // shrink the user and service-principal lookback to the overlap window.
        var r1 = await new Detections().CollectAsync(context, cancellationToken);
        var r2 = await CollectFeed(context, "riskyUsersWatermark", new Users(), cancellationToken);
        var r3 = await CollectFeed(context, "riskyServicePrincipalsWatermark", new ServicePrincipals(), cancellationToken);
        return new CollectorResult(r1.Published + r2.Published + r3.Published, r1.Duplicates + r2.Duplicates + r3.Duplicates, r1.Failed + r2.Failed + r3.Failed, r1.Alerts + r2.Alerts + r3.Alerts, r1.Complete && r2.Complete && r3.Complete, SelectNote(r1, r2, r3));
    }

    /// <summary>
    /// The first feed that did not finish, or that failed to index, owns the note.
    /// When every feed succeeded, the first note is kept.
    /// </summary>
    internal static string? SelectNote(CollectorResult first, CollectorResult second, CollectorResult third)
    {
        if (!first.Complete || first.Failed > 0)
        {
            return first.Note;
        }

        if (!second.Complete || second.Failed > 0)
        {
            return second.Note;
        }

        if (!third.Complete || third.Failed > 0)
        {
            return third.Note;
        }

        return first.Note ?? second.Note ?? third.Note;
    }

    private static async Task<CollectorResult> CollectFeed(CollectorContext context, string stateKey, WatermarkCollector collector, CancellationToken cancellationToken)
    {
        var state = context.State;
        DateTimeOffset? watermark = null;
        if (state.TryGetValue(stateKey, out var raw) && raw.ValueKind == JsonValueKind.String && DateTimeOffset.TryParse(raw.GetString(), CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out var parsed))
        {
            watermark = parsed;
        }

        var shadow = new Data.Checkpoint { TenantId = context.Checkpoint.TenantId, Source = context.Checkpoint.Source, Watermark = watermark, StateJson = context.Checkpoint.StateJson };
        var shadowContext = new CollectorContext
        {
            Tenant = context.Tenant,
            Settings = context.Settings,
            Graph = context.Graph,
            Checkpoint = shadow,
            Pipeline = context.Pipeline,
            Options = context.Options,
            Time = context.Time,
            Logger = context.Logger,
            Deadline = context.Deadline,
        };
        var result = await collector.CollectAsync(shadowContext, cancellationToken);
        // The shadow started as a copy of the checkpoint and the feed rewrote its own continuation there.
        // Copy that back so a cleared resume link does not linger on the parent.
        var next = new Dictionary<string, object?>();
        foreach (var pair in shadowContext.State)
        {
            if (pair.Value.ValueKind == JsonValueKind.String)
            {
                next[pair.Key] = pair.Value.GetString();
            }
        }

        next[stateKey] = shadow.Watermark?.ToString("O", CultureInfo.InvariantCulture);
        context.SaveState(next);
        return result;
    }

    private sealed class Detections : WatermarkCollector
    {
        public override string Source => Sources.Risk;
        public override string Title => "Risk detections";
        public override IReadOnlyList<string> RequiredPermissions => ["IdentityRiskEvent.Read.All"];
        public override string ProbePath => "identityProtection/riskDetections?$top=1";

        protected override string OrderByField => "lastUpdatedDateTime";

        protected override string BuildPath(CollectorContext context, DateTimeOffset from) =>
            $"identityProtection/riskDetections?$filter=lastUpdatedDateTime%20ge%20{OData.Timestamp(from)}&$top={Math.Clamp(context.Options.GraphPageSize, 1, 500)}";

        protected override (SecurityEvent Event, DateTimeOffset Timestamp)? Map(CollectorContext context, JsonElement record)
        {
            var e = Normalizers.RiskDetection(record, context.Tenant.TenantId, context.Tenant.DiscoveredName ?? context.Tenant.DisplayName);
            return e is null ? null : (e, record.Date("lastUpdatedDateTime") ?? e.Timestamp);
        }
    }

    private sealed class Users : WatermarkCollector
    {
        public override string Source => Sources.Risk;
        public override string Title => "Risky users";
        public override IReadOnlyList<string> RequiredPermissions => ["IdentityRiskyUser.Read.All"];
        public override string ProbePath => "identityProtection/riskyUsers?$top=1";

        protected override string OrderByField => "riskLastUpdatedDateTime";

        /// <summary>Shares the risk checkpoint, so this feed's continuation uses its own keys.</summary>
        protected override string StatePrefix => "riskyUsers";

        protected override string BuildPath(CollectorContext context, DateTimeOffset from) =>
            $"identityProtection/riskyUsers?$filter=riskLastUpdatedDateTime%20ge%20{OData.Timestamp(from)}&$top={Math.Clamp(context.Options.GraphPageSize, 1, 500)}";

        protected override (SecurityEvent Event, DateTimeOffset Timestamp)? Map(CollectorContext context, JsonElement record)
        {
            var e = Normalizers.RiskyUser(record, context.Tenant.TenantId, context.Tenant.DiscoveredName ?? context.Tenant.DisplayName);
            return e is null ? null : (e, e.Timestamp);
        }
    }

    private sealed class ServicePrincipals : WatermarkCollector
    {
        public override string Source => Sources.Risk;
        public override string Title => "Risky service principals";
        public override IReadOnlyList<string> RequiredPermissions => ["IdentityRiskyServicePrincipal.Read.All"];
        public override string ProbePath => "identityProtection/riskyServicePrincipals?$top=1";

        protected override string OrderByField => "riskLastUpdatedDateTime";

        /// <summary>Shares the risk checkpoint, so this feed's continuation uses its own keys.</summary>
        protected override string StatePrefix => "riskyServicePrincipals";

        protected override string BuildPath(CollectorContext context, DateTimeOffset from) =>
            $"identityProtection/riskyServicePrincipals?$filter=riskLastUpdatedDateTime%20ge%20{OData.Timestamp(from)}&$top={Math.Clamp(context.Options.GraphPageSize, 1, 500)}";

        protected override (SecurityEvent Event, DateTimeOffset Timestamp)? Map(CollectorContext context, JsonElement record)
        {
            var e = Normalizers.RiskyServicePrincipal(record, context.Tenant.TenantId, context.Tenant.DiscoveredName ?? context.Tenant.DisplayName);
            return e is null ? null : (e, e.Timestamp);
        }
    }
}

/// <summary>Daily Secure Score snapshot (the newest document per tenant is upserted by its id).</summary>
public sealed class SecureScoreCollector : ICollector
{
    public string Source => Sources.SecureScore;
    public string Title => "Microsoft Secure Score";
    public IReadOnlyList<string> RequiredPermissions => ["SecurityEvents.Read.All"];
    public string ProbePath => "security/secureScores?$top=1";

    public async Task<CollectorResult> CollectAsync(CollectorContext context, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        var events = new List<SecurityEvent>();
        // List secureScores is already newest-first. $top=7 is the newest seven days. $orderby is not a supported query option and Graph rejects it.
        await foreach (var record in context.Graph.GetPagedAsync("security/secureScores?$top=7", 1, cancellationToken))
        {
            var e = Normalizers.SecureScore(record, context.Tenant.TenantId, context.Tenant.DiscoveredName ?? context.Tenant.DisplayName);
            if (e is not null)
            {
                events.Add(e);
            }
        }

        var newest = events.Count > 0 ? events.Max(e => e.Timestamp) : (DateTimeOffset?)null;
        var (indexed, duplicates, failed, alerts) = await context.PublishAsync(events, cancellationToken);
        if (failed > 0)
        {
            return new CollectorResult(indexed, duplicates, failed, alerts, false, "Elasticsearch rejected records; the watermark was not moved");
        }

        if (newest is { } n)
        {
            // A clock-skewed createdDateTime must not move the watermark past now. Cap only the new value.
            if (n > context.Now)
            {
                n = context.Now;
            }

            if (context.Checkpoint.Watermark is null || n > context.Checkpoint.Watermark)
            {
                context.Checkpoint.Watermark = n;
            }
        }

        return new CollectorResult(indexed, duplicates, failed, alerts, true);
    }
}
