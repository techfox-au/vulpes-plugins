using System.Globalization;
using System.Text.Json;
using Vulpes.Plugins.Microsoft365Audit.Graph;
using Vulpes.Plugins.Microsoft365Audit.Normalization;
using Vulpes.Sdk;

namespace Vulpes.Plugins.Microsoft365Audit.Collectors;

/// <summary>Interactive sign-ins (v1.0) plus, when enabled per tenant, non-interactive / service principal / managed identity sign-ins (beta).</summary>
public sealed class SignInsCollector : ICollector
{
    public string Source => Sources.SignIns;
    public string Title => "Entra ID sign-ins";
    public IReadOnlyList<string> RequiredPermissions => ["AuditLog.Read.All", "Directory.Read.All"];
    public string ProbePath => "auditLogs/signIns?$top=1";

    public async Task<CollectorResult> CollectAsync(CollectorContext context, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        var interactive = new Interactive();
        var result = await interactive.CollectAsync(context, cancellationToken);
        if (!context.Settings.IncludeNonInteractive || !result.Complete)
        {
            return result;
        }

        // The non-interactive feed keeps its own watermark in the checkpoint state.
        var state = context.State;
        var nonInteractiveWatermark = state.TryGetValue("nonInteractiveWatermark", out var w) && w.ValueKind == JsonValueKind.String && DateTimeOffset.TryParse(w.GetString(), CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out var parsed) ? parsed : (DateTimeOffset?)null;
        var shadow = new Data.Checkpoint { TenantId = context.Checkpoint.TenantId, Source = Source, Watermark = nonInteractiveWatermark };
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
        context.SaveState(new Dictionary<string, object?> { ["nonInteractiveWatermark"] = shadow.Watermark?.ToString("O", CultureInfo.InvariantCulture) });
        return new CollectorResult(result.Published + second.Published, result.Duplicates + second.Duplicates, result.Failed + second.Failed, result.Alerts + second.Alerts, second.Complete, second.Note ?? result.Note);
    }

    private sealed class Interactive : WatermarkCollector
    {
        public override string Source => Sources.SignIns;
        public override string Title => "Interactive sign-ins";
        public override IReadOnlyList<string> RequiredPermissions => ["AuditLog.Read.All"];
        public override string ProbePath => "auditLogs/signIns?$top=1";

        protected override string OrderByField => "createdDateTime";

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

        protected override string BuildPath(CollectorContext context, DateTimeOffset from) =>
            $"auditLogs/signIns?$filter=createdDateTime%20ge%20{OData.Timestamp(from)}%20and%20signInEventTypes/any(t:%20t%20eq%20'nonInteractiveUser'%20or%20t%20eq%20'servicePrincipal'%20or%20t%20eq%20'managedIdentity')&$top={Math.Clamp(context.Options.GraphPageSize, 1, 999)}";

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
}

public sealed class DirectoryAuditsCollector : WatermarkCollector
{
    public override string Source => Sources.Directory;
    public override string Title => "Entra ID directory audits";
    public override IReadOnlyList<string> RequiredPermissions => ["AuditLog.Read.All", "Directory.Read.All"];
    public override string ProbePath => "auditLogs/directoryAudits?$top=1";

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

    protected override string BuildPath(CollectorContext context, DateTimeOffset from) =>
        $"security/alerts_v2?$filter=lastUpdateDateTime%20ge%20{OData.Timestamp(from)}&$top={Math.Clamp(context.Options.GraphPageSize, 1, 2000)}";

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
        var detections = new Detections();
        var users = new Users();
        var principals = new ServicePrincipals();
        var r1 = await detections.CollectAsync(context, cancellationToken);
        var r2 = await users.CollectAsync(context, cancellationToken);
        var r3 = await principals.CollectAsync(context, cancellationToken);
        return new CollectorResult(r1.Published + r2.Published + r3.Published, r1.Duplicates + r2.Duplicates + r3.Duplicates, r1.Failed + r2.Failed + r3.Failed, r1.Alerts + r2.Alerts + r3.Alerts, r1.Complete && r2.Complete && r3.Complete, r1.Note ?? r2.Note ?? r3.Note);
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
        if (newest is { } n && (context.Checkpoint.Watermark is null || n > context.Checkpoint.Watermark))
        {
            context.Checkpoint.Watermark = n;
        }

        return new CollectorResult(indexed, duplicates, failed, alerts, true);
    }
}
