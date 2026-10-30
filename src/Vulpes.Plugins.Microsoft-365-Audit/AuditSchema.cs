using Vulpes.Plugins.Microsoft365Audit.Normalization;
using Vulpes.Sdk;

namespace Vulpes.Plugins.Microsoft365Audit;

/// <summary>Event sources and their extra searchable fields (labels are indexed as flattened keywords).</summary>
public sealed class AuditSchema : IIndexSchemaContributor
{
    public string ModuleId => Normalizers.ModuleId;

    public IReadOnlyList<EventSourceDefinition> Sources { get; } =
    [
        new()
        {
            Source = Normalization.Sources.SignIns,
            Title = "Sign-ins",
            Fields =
            [
                F("labels.signInType", "Sign-in type"), F("labels.errorCode", "Error code"), F("labels.conditionalAccessStatus", "Conditional Access"),
                F("labels.clientAppUsed", "Client app used"), F("labels.riskLevel", "Risk level"), F("labels.riskState", "Risk state"),
                F("labels.os", "Operating system"), F("labels.browser", "Browser"), F("labels.resource", "Resource"),
                F("data.status.failureReason", "Failure reason"), F("data.deviceDetail.isCompliant", "Device compliant"), F("data.deviceDetail.trustType", "Device trust type"),
            ],
        },
        new()
        {
            Source = Normalization.Sources.Directory,
            Title = "Directory audit",
            Fields = [F("labels.category", "Category"), F("labels.service", "Logged by service"), F("labels.targetType", "Target type"), F("labels.targetName", "Target"), F("labels.resultReason", "Result reason")],
        },
        new()
        {
            Source = Normalization.Sources.Provisioning,
            Title = "Provisioning",
            Fields = [F("labels.status", "Status"), F("labels.targetType", "Target type"), F("labels.sourceSystem", "Source system"), F("labels.targetSystem", "Target system")],
        },
        new()
        {
            Source = Normalization.Sources.Activity,
            Title = "Activity (unified audit log)",
            Fields =
            [
                F("labels.recordType", "Record type"), F("labels.workload", "Workload"), F("labels.userType", "User type"), F("labels.resultStatus", "Result status"),
                F("labels.siteUrl", "Site URL"), F("labels.objectId", "Object id"), F("labels.sourceRelativeUrl", "Relative URL"), F("labels.mailboxOwner", "Mailbox owner"), F("labels.targetUser", "Target user / group"),
                F("data.auditData.ItemType", "Item type"), F("data.auditData.EventSource", "Event source"), F("data.auditData.SourceFileExtension", "File extension"),
            ],
        },
        new()
        {
            Source = Normalization.Sources.SecurityAlerts,
            Title = "Defender alerts",
            Mode = EventStorageMode.Index,
            Fields = [F("labels.status", "Status"), F("labels.serviceSource", "Service source"), F("labels.detectionSource", "Detection source"), F("labels.incidentId", "Incident id"), F("labels.classification", "Classification"), F("labels.determination", "Determination"), F("labels.assignedTo", "Assigned to")],
        },
        new()
        {
            Source = Normalization.Sources.Incidents,
            Title = "Defender incidents",
            Mode = EventStorageMode.Index,
            Fields = [F("labels.status", "Status"), F("labels.classification", "Classification"), F("labels.determination", "Determination"), F("labels.assignedTo", "Assigned to")],
        },
        new()
        {
            Source = Normalization.Sources.Risk,
            Title = "Identity Protection risk",
            Fields = [F("labels.riskType", "Risk type"), F("labels.riskLevel", "Risk level"), F("labels.riskState", "Risk state"), F("labels.riskDetail", "Risk detail"), F("labels.activity", "Activity"), F("labels.detectionTiming", "Detection timing")],
        },
        new()
        {
            Source = Normalization.Sources.SecureScore,
            Title = "Secure Score",
            Mode = EventStorageMode.Index,
            Fields = [F("labels.currentScore", "Current score"), F("labels.maxScore", "Max score"), F("labels.percent", "Percent")],
        },
        new()
        {
            Source = Normalization.Sources.System,
            Title = "Collector status events",
            Fields = [F("labels.collector", "Collector"), F("labels.error", "Error")],
            RetentionDays = 90,
        },
    ];

    private static FieldDefinition F(string path, string label) => new() { Path = path, Label = label };
}
