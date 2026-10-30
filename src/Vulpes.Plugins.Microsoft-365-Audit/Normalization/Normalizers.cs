using System.Globalization;
using System.Text.Json;
using Vulpes.Plugins.Microsoft365Audit.Collectors;
using Vulpes.Sdk;

namespace Vulpes.Plugins.Microsoft365Audit.Normalization;

public static class Sources
{
    public const string SignIns = "signins";
    public const string Directory = "directory";
    public const string Provisioning = "provisioning";
    public const string Activity = "activity";
    public const string SecurityAlerts = "security-alerts";
    public const string Incidents = "incidents";
    public const string Risk = "risk";
    public const string SecureScore = "securescore";
    public const string System = "system";
}

/// <summary>Pure functions from Graph records to <see cref="SecurityEvent"/>. Kept free of I/O so they can be golden-tested.</summary>
public static class Normalizers
{
    public const string PluginId = "microsoft-365-audit";

    public static SecurityEvent? SignIn(JsonElement r, string tenantId, string? tenantName, string signInType)
    {
        var id = r.Str("id");
        var created = r.Date("createdDateTime");
        if (id is null || created is null)
        {
            return null;
        }

        var status = r.Obj("status");
        var errorCode = status?.WholeNumber("errorCode") ?? 0;
        var failureReason = status?.Str("failureReason");
        var outcome = errorCode == 0 ? "success" : "failure";
        var location = r.Obj("location");
        var coords = location?.Obj("geoCoordinates");
        var upn = r.Str("userPrincipalName") ?? r.Str("servicePrincipalName");
        var app = r.Str("appDisplayName") ?? r.Str("resourceDisplayName");
        var ip = r.Str("ipAddress");
        var riskLevel = r.Str("riskLevelDuringSignIn") ?? r.Str("riskLevelAggregated");

        return new SecurityEvent
        {
            PluginId = PluginId,
            Source = Sources.SignIns,
            RecordId = id,
            Timestamp = created.Value,
            TenantId = tenantId,
            TenantName = tenantName,
            Kind = "event",
            Category = "authentication",
            Action = "sign-in",
            Outcome = outcome,
            Dataset = "entra.signins",
            Severity = SeverityFromRisk(riskLevel, outcome),
            UserId = r.Str("userId") ?? r.Str("servicePrincipalId"),
            UserName = upn,
            UserEmail = upn is not null && upn.Contains('@', StringComparison.Ordinal) ? upn : null,
            SourceIp = ip,
            Geo = location is null ? null : new GeoLocation(null, location.Value.Str("countryOrRegion"), location.Value.Str("state"), location.Value.Str("city"), coords?.Num("latitude"), coords?.Num("longitude")),
            UserAgent = r.Str("userAgent"),
            ClientAppId = r.Str("appId"),
            ClientAppName = app,
            Message = J.Truncate($"{upn ?? "(unknown)"} {(outcome == "success" ? "signed in to" : "failed to sign in to")} {app ?? "(unknown app)"} from {ip ?? "?"}{(failureReason is null || errorCode == 0 ? string.Empty : $": {failureReason}")}", 1000),
            Labels = Labels(
                ("signInType", signInType),
                ("errorCode", errorCode.ToString(CultureInfo.InvariantCulture)),
                ("conditionalAccessStatus", r.Str("conditionalAccessStatus")),
                ("clientAppUsed", r.Str("clientAppUsed")),
                ("riskLevel", riskLevel),
                ("riskState", r.Str("riskState")),
                ("isInteractive", r.Str("isInteractive")),
                ("os", r.Obj("deviceDetail")?.Str("operatingSystem")),
                ("browser", r.Obj("deviceDetail")?.Str("browser")),
                ("resource", r.Str("resourceDisplayName"))),
            Data = r,
        };
    }

    public static SecurityEvent? DirectoryAudit(JsonElement r, string tenantId, string? tenantName)
    {
        var id = r.Str("id");
        var at = r.Date("activityDateTime");
        if (id is null || at is null)
        {
            return null;
        }

        var initiatedBy = r.Obj("initiatedBy");
        var user = initiatedBy?.Obj("user");
        var app = initiatedBy?.Obj("app");
        var targets = r.Obj("targetResources");
        var firstTarget = targets is { ValueKind: JsonValueKind.Array } arr && arr.GetArrayLength() > 0 ? arr[0] : (JsonElement?)null;
        var result = r.Str("result");
        var activity = r.Str("activityDisplayName");
        var actor = user?.Str("userPrincipalName") ?? app?.Str("displayName");
        var targetName = firstTarget?.Str("userPrincipalName") ?? firstTarget?.Str("displayName");

        return new SecurityEvent
        {
            PluginId = PluginId,
            Source = Sources.Directory,
            RecordId = id,
            Timestamp = at.Value,
            TenantId = tenantId,
            TenantName = tenantName,
            Category = CategoryForDirectory(r.Str("category")),
            Action = activity,
            Outcome = result is null ? null : result.Equals("success", StringComparison.OrdinalIgnoreCase) ? "success" : result.Equals("failure", StringComparison.OrdinalIgnoreCase) ? "failure" : "unknown",
            Dataset = "entra.directory",
            Severity = SeverityForDirectory(activity),
            UserId = user?.Str("id"),
            UserName = user?.Str("userPrincipalName"),
            UserEmail = user?.Str("userPrincipalName"),
            SourceIp = user?.Str("ipAddress"),
            ClientAppId = app?.Str("appId") ?? app?.Str("servicePrincipalId"),
            ClientAppName = app?.Str("displayName"),
            Message = J.Truncate($"{actor ?? "(system)"}: {activity ?? "activity"}{(targetName is null ? string.Empty : " on " + targetName)}{(result is null ? string.Empty : $" ({result})")}", 1000),
            Labels = Labels(
                ("category", r.Str("category")),
                ("service", r.Str("loggedByService")),
                ("targetType", firstTarget?.Str("type")),
                ("targetName", targetName),
                ("resultReason", J.Truncate(r.Str("resultReason"), 256))),
            Data = r,
        };
    }

    public static SecurityEvent? Provisioning(JsonElement r, string tenantId, string? tenantName)
    {
        var id = r.Str("id");
        var at = r.Date("activityDateTime");
        if (id is null || at is null)
        {
            return null;
        }

        var status = r.Obj("provisioningStatusInfo")?.Str("status") ?? r.Obj("statusInfo")?.Str("status");
        var target = r.Obj("targetIdentity");
        var source = r.Obj("sourceIdentity");
        var sp = r.Obj("servicePrincipal");
        return new SecurityEvent
        {
            PluginId = PluginId,
            Source = Sources.Provisioning,
            RecordId = id,
            Timestamp = at.Value,
            TenantId = tenantId,
            TenantName = tenantName,
            Category = "iam",
            Action = r.Str("provisioningAction") ?? r.Str("action"),
            Outcome = status is null ? null : status.Equals("success", StringComparison.OrdinalIgnoreCase) ? "success" : status.Equals("failure", StringComparison.OrdinalIgnoreCase) ? "failure" : "unknown",
            Dataset = "entra.provisioning",
            Severity = "informational",
            UserId = target?.Str("id"),
            UserName = target?.Str("displayName") ?? source?.Str("displayName"),
            ClientAppId = sp?.Str("id"),
            ClientAppName = sp?.Str("displayName"),
            Message = J.Truncate($"{sp?.Str("displayName") ?? "Provisioning"}: {r.Str("provisioningAction") ?? r.Str("action")} {target?.Str("displayName")} ({status})", 1000),
            Labels = Labels(("status", status), ("targetType", target?.Str("identityType")), ("sourceSystem", r.Obj("sourceSystem")?.Str("displayName")), ("targetSystem", r.Obj("targetSystem")?.Str("displayName"))),
            Data = r,
        };
    }

    /// <summary>Microsoft Purview unified audit log record (<c>microsoft.graph.security.auditLogRecord</c>).</summary>
    public static SecurityEvent? AuditLogRecord(JsonElement r, string tenantId, string? tenantName)
    {
        var id = r.Str("id");
        var created = r.Date("createdDateTime");
        if (id is null || created is null)
        {
            return null;
        }

        var data = r.Obj("auditData");
        var recordType = r.Str("auditLogRecordType") ?? data?.Str("RecordType");
        var operation = r.Str("operation") ?? data?.Str("Operation");
        var workload = data?.Str("Workload") ?? r.Str("service");
        var upn = r.Str("userPrincipalName") ?? data?.Str("UserId");
        var ip = r.Str("clientIp") ?? data?.Str("ClientIP") ?? data?.Str("ClientIPAddress") ?? data?.Str("ActorIpAddress");
        var objectId = r.Str("objectId") ?? data?.Str("ObjectId");
        var resultStatus = data?.Str("ResultStatus");
        var category = CategoryForRecordType(recordType);
        var isFile = category == "file";
        var fileName = data?.Str("SourceFileName") ?? (isFile && objectId is not null ? LastSegment(objectId) : null);

        return new SecurityEvent
        {
            PluginId = PluginId,
            Source = Sources.Activity,
            RecordId = id,
            Timestamp = created.Value,
            TenantId = tenantId,
            TenantName = tenantName,
            Category = category,
            Action = operation,
            Outcome = resultStatus is null ? null : resultStatus.StartsWith("Succe", StringComparison.OrdinalIgnoreCase) || resultStatus.Equals("True", StringComparison.OrdinalIgnoreCase) ? "success" : resultStatus.StartsWith("Fail", StringComparison.OrdinalIgnoreCase) ? "failure" : "unknown",
            Dataset = workload is null ? "purview.audit" : "purview." + workload.ToLowerInvariant(),
            Severity = SeverityForOperation(operation),
            UserId = r.Str("userId") is { } uid && Guid.TryParse(uid, out _) ? uid : data?.Str("UserKey"),
            UserName = upn,
            UserEmail = upn is not null && upn.Contains('@', StringComparison.Ordinal) ? upn : null,
            SourceIp = CleanIp(ip),
            UserAgent = data?.Str("UserAgent"),
            ClientAppId = data?.Str("ApplicationId") ?? data?.Str("AppId"),
            ClientAppName = data?.Str("ClientAppId") ?? data?.Str("ApplicationDisplayName") ?? data?.Str("ClientInfoString"),
            FilePath = isFile ? objectId : null,
            FileName = isFile ? fileName : null,
            Message = J.Truncate($"{upn ?? "(unknown)"} {operation ?? "?"}{(objectId is null ? string.Empty : " " + objectId)}", 1000),
            Labels = Labels(
                ("recordType", recordType),
                ("workload", workload),
                ("userType", r.Str("userType")),
                ("resultStatus", resultStatus),
                ("siteUrl", J.Truncate(data?.Str("SiteUrl"), 512)),
                ("objectId", J.Truncate(objectId, 1024)),
                ("sourceRelativeUrl", J.Truncate(data?.Str("SourceRelativeUrl"), 512)),
                ("mailboxOwner", data?.Str("MailboxOwnerUPN")),
                ("targetUser", data?.Str("TargetUserOrGroupName"))),
            Data = r,
        };
    }

    public static SecurityEvent? SecurityAlert(JsonElement r, string tenantId, string? tenantName)
    {
        var id = r.Str("id");
        var created = r.Date("createdDateTime");
        if (id is null || created is null)
        {
            return null;
        }

        string? upn = null;
        string? ip = null;
        if (r.Obj("evidence") is { ValueKind: JsonValueKind.Array } evidence)
        {
            foreach (var item in evidence.EnumerateArray())
            {
                upn ??= item.Obj("userAccount")?.Str("userPrincipalName");
                ip ??= item.Str("ipAddress");
            }
        }

        return new SecurityEvent
        {
            PluginId = PluginId,
            Source = Sources.SecurityAlerts,
            RecordId = id,
            Timestamp = created.Value,
            TenantId = tenantId,
            TenantName = tenantName,
            Kind = "alert",
            Category = "threat",
            Action = r.Str("category") ?? "alert",
            Outcome = null,
            Dataset = "defender.alerts",
            Severity = NormalizeSeverity(r.Str("severity")),
            UserName = upn,
            UserEmail = upn,
            SourceIp = CleanIp(ip),
            Message = J.Truncate(r.Str("title"), 1000),
            Labels = Labels(
                ("status", r.Str("status")),
                ("serviceSource", r.Str("serviceSource")),
                ("detectionSource", r.Str("detectionSource")),
                ("incidentId", r.Str("incidentId")),
                ("classification", r.Str("classification")),
                ("determination", r.Str("determination")),
                ("assignedTo", r.Str("assignedTo")),
                ("lastUpdate", r.Str("lastUpdateDateTime"))),
            Data = r,
        };
    }

    public static SecurityEvent? Incident(JsonElement r, string tenantId, string? tenantName)
    {
        var id = r.Str("id");
        var created = r.Date("createdDateTime");
        if (id is null || created is null)
        {
            return null;
        }

        return new SecurityEvent
        {
            PluginId = PluginId,
            Source = Sources.Incidents,
            RecordId = id,
            Timestamp = created.Value,
            TenantId = tenantId,
            TenantName = tenantName,
            Kind = "alert",
            Category = "threat",
            Action = "incident",
            Dataset = "defender.incidents",
            Severity = NormalizeSeverity(r.Str("severity")),
            Message = J.Truncate(r.Str("displayName"), 1000),
            Labels = Labels(
                ("status", r.Str("status")),
                ("classification", r.Str("classification")),
                ("determination", r.Str("determination")),
                ("assignedTo", r.Str("assignedTo")),
                ("incidentWebUrl", J.Truncate(r.Str("incidentWebUrl"), 512)),
                ("lastUpdate", r.Str("lastUpdateDateTime"))),
            Data = r,
        };
    }

    public static SecurityEvent? RiskDetection(JsonElement r, string tenantId, string? tenantName)
    {
        var id = r.Str("id");
        var at = r.Date("detectedDateTime") ?? r.Date("activityDateTime");
        var updated = r.Date("lastUpdatedDateTime") ?? at;
        if (id is null || at is null)
        {
            return null;
        }

        var location = r.Obj("location");
        var coords = location?.Obj("geoCoordinates");
        var upn = r.Str("userPrincipalName");
        return new SecurityEvent
        {
            PluginId = PluginId,
            Source = Sources.Risk,
            RecordId = string.Create(CultureInfo.InvariantCulture, $"detection:{id}:{updated!.Value.UtcTicks}"),
            Timestamp = at.Value,
            TenantId = tenantId,
            TenantName = tenantName,
            Category = "threat",
            Action = r.Str("riskEventType") ?? "riskDetection",
            Dataset = "entra.identityprotection",
            Severity = NormalizeSeverity(r.Str("riskLevel")),
            UserId = r.Str("userId"),
            UserName = upn,
            UserEmail = upn,
            SourceIp = CleanIp(r.Str("ipAddress")),
            Geo = location is null ? null : new GeoLocation(null, location.Value.Str("countryOrRegion"), location.Value.Str("state"), location.Value.Str("city"), coords?.Num("latitude"), coords?.Num("longitude")),
            Message = J.Truncate($"{r.Str("riskEventType")} ({r.Str("riskLevel")}, {r.Str("riskState")}) for {upn ?? r.Str("userDisplayName") ?? "?"}", 1000),
            Labels = Labels(("riskType", "detection"), ("riskLevel", r.Str("riskLevel")), ("riskState", r.Str("riskState")), ("riskDetail", r.Str("riskDetail")), ("activity", r.Str("activity")), ("detectionTiming", r.Str("detectionTimingType")), ("source", r.Str("source"))),
            Data = r,
        };
    }

    public static SecurityEvent? RiskyUser(JsonElement r, string tenantId, string? tenantName)
    {
        var id = r.Str("id");
        var updated = r.Date("riskLastUpdatedDateTime");
        if (id is null || updated is null)
        {
            return null;
        }

        var upn = r.Str("userPrincipalName");
        return new SecurityEvent
        {
            PluginId = PluginId,
            Source = Sources.Risk,
            RecordId = string.Create(CultureInfo.InvariantCulture, $"user:{id}:{updated.Value.UtcTicks}"),
            Timestamp = updated.Value,
            TenantId = tenantId,
            TenantName = tenantName,
            Kind = "state",
            Category = "threat",
            Action = "riskyUser",
            Dataset = "entra.identityprotection",
            Severity = NormalizeSeverity(r.Str("riskLevel")),
            UserId = id,
            UserName = upn,
            UserEmail = upn,
            Message = J.Truncate($"User {upn ?? r.Str("userDisplayName")} risk {r.Str("riskLevel")} ({r.Str("riskState")})", 1000),
            Labels = Labels(("riskType", "user"), ("riskLevel", r.Str("riskLevel")), ("riskState", r.Str("riskState")), ("riskDetail", r.Str("riskDetail")), ("isDeleted", r.Str("isDeleted"))),
            Data = r,
        };
    }

    public static SecurityEvent? RiskyServicePrincipal(JsonElement r, string tenantId, string? tenantName)
    {
        var id = r.Str("id");
        var updated = r.Date("riskLastUpdatedDateTime");
        if (id is null || updated is null)
        {
            return null;
        }

        return new SecurityEvent
        {
            PluginId = PluginId,
            Source = Sources.Risk,
            RecordId = string.Create(CultureInfo.InvariantCulture, $"sp:{id}:{updated.Value.UtcTicks}"),
            Timestamp = updated.Value,
            TenantId = tenantId,
            TenantName = tenantName,
            Kind = "state",
            Category = "threat",
            Action = "riskyServicePrincipal",
            Dataset = "entra.identityprotection",
            Severity = NormalizeSeverity(r.Str("riskLevel")),
            ClientAppId = r.Str("appId"),
            ClientAppName = r.Str("displayName"),
            Message = J.Truncate($"Service principal {r.Str("displayName")} risk {r.Str("riskLevel")} ({r.Str("riskState")})", 1000),
            Labels = Labels(("riskType", "servicePrincipal"), ("riskLevel", r.Str("riskLevel")), ("riskState", r.Str("riskState")), ("riskDetail", r.Str("riskDetail")), ("servicePrincipalType", r.Str("servicePrincipalType"))),
            Data = r,
        };
    }

    public static SecurityEvent? SecureScore(JsonElement r, string tenantId, string? tenantName)
    {
        var id = r.Str("id");
        var created = r.Date("createdDateTime");
        if (id is null || created is null)
        {
            return null;
        }

        var current = r.Num("currentScore");
        var max = r.Num("maxScore");
        return new SecurityEvent
        {
            PluginId = PluginId,
            Source = Sources.SecureScore,
            RecordId = id,
            Timestamp = created.Value,
            TenantId = tenantId,
            TenantName = tenantName,
            Kind = "metric",
            Category = "configuration",
            Action = "secureScore",
            Dataset = "defender.securescore",
            Severity = "informational",
            Message = string.Create(CultureInfo.InvariantCulture, $"Secure score {current:0.##} / {max:0.##}"),
            Labels = Labels(
                ("currentScore", current?.ToString("0.##", CultureInfo.InvariantCulture)),
                ("maxScore", max?.ToString("0.##", CultureInfo.InvariantCulture)),
                ("percent", current is { } c && max is { } m && m > 0 ? Math.Round(100 * c / m, 1).ToString("0.#", CultureInfo.InvariantCulture) : null),
                ("activeUserCount", r.Str("activeUserCount"))),
            Data = r,
        };
    }

    public static SecurityEvent CollectorFailure(string tenantId, string? tenantName, string source, string error, DateTimeOffset at) => new()
    {
        PluginId = PluginId,
        Source = Sources.System,
        RecordId = string.Create(CultureInfo.InvariantCulture, $"{source}:{at.UtcTicks}"),
        Timestamp = at,
        TenantId = tenantId,
        TenantName = tenantName,
        Kind = "event",
        Category = "process",
        Action = "audit.collector.failed",
        Outcome = "failure",
        Dataset = "vulpeschama.audit",
        Severity = "medium",
        Message = J.Truncate($"Collector '{source}' failed for tenant {tenantName ?? tenantId}: {error}", 1000),
        Labels = Labels(("collector", source), ("error", J.Truncate(error, 1024))),
    };

    // ---------------------------------------------------------------- helpers

    internal static IReadOnlyDictionary<string, string>? Labels(params (string Key, string? Value)[] pairs)
    {
        Dictionary<string, string>? result = null;
        foreach (var (key, value) in pairs)
        {
            if (!string.IsNullOrEmpty(value))
            {
                (result ??= new Dictionary<string, string>(StringComparer.Ordinal))[key] = value;
            }
        }

        return result;
    }

    internal static string NormalizeSeverity(string? value) => value?.ToLowerInvariant() switch
    {
        "high" => "high",
        "medium" => "medium",
        "low" => "low",
        "informational" or "info" => "informational",
        "critical" => "critical",
        "hidden" or "none" or "unknown" => "informational",
        _ => "informational",
    };

    internal static string SeverityFromRisk(string? riskLevel, string outcome) => riskLevel?.ToLowerInvariant() switch
    {
        "high" => "high",
        "medium" => "medium",
        "low" => "low",
        _ => outcome == "failure" ? "low" : "informational",
    };

    internal static string CategoryForRecordType(string? recordType)
    {
        if (recordType is null)
        {
            return "unknown";
        }

        var t = recordType.ToLowerInvariant();
        if (t.StartsWith("sharepoint", StringComparison.Ordinal) || t.StartsWith("onedrive", StringComparison.Ordinal))
        {
            return "file";
        }

        if (t.StartsWith("exchange", StringComparison.Ordinal) || t.StartsWith("mail", StringComparison.Ordinal))
        {
            return "email";
        }

        if (t.StartsWith("azureactivedirectory", StringComparison.Ordinal))
        {
            return t.Contains("logon", StringComparison.Ordinal) ? "authentication" : "iam";
        }

        if (t.Contains("dlp", StringComparison.Ordinal) || t.Contains("threat", StringComparison.Ordinal) || t.Contains("securitycompliance", StringComparison.Ordinal))
        {
            return "threat";
        }

        if (t.StartsWith("microsoftteams", StringComparison.Ordinal) || t.StartsWith("yammer", StringComparison.Ordinal))
        {
            return "collaboration";
        }

        return "configuration";
    }

    internal static string CategoryForDirectory(string? category) => category?.ToLowerInvariant() switch
    {
        "usermanagement" or "groupmanagement" or "rolemanagement" or "applicationmanagement" or "directorymanagement" => "iam",
        "policy" or "authentication" => "configuration",
        _ => "iam",
    };

    private static readonly string[] HighRiskDirectoryActivities =
    [
        "Add member to role", "Add eligible member to role", "Add app role assignment to service principal", "Add owner to application", "Add service principal credentials",
        "Update application – Certificates and secrets management", "Consent to application", "Add delegated permission grant", "Set domain authentication", "Add unverified domain",
        "Update conditional access policy", "Delete conditional access policy", "Disable Strong Authentication", "Reset user password", "Change user password",
    ];

    internal static string SeverityForDirectory(string? activity)
    {
        if (activity is null)
        {
            return "informational";
        }

        return HighRiskDirectoryActivities.Any(a => activity.Contains(a, StringComparison.OrdinalIgnoreCase)) ? "medium" : "informational";
    }

    private static readonly string[] NotableOperations =
    [
        "New-InboxRule", "Set-InboxRule", "UpdateInboxRules", "Add-MailboxPermission", "Set-Mailbox", "New-TransportRule", "Set-TransportRule",
        "AnonymousLinkCreated", "SharingInvitationCreated", "SharingSet", "AddedToSecureLink", "CompanyLinkCreated",
        "FileMalwareDetected", "FileDeletedFirstStageRecycleBin", "SiteCollectionAdminAdded", "Add-RoleGroupMember",
    ];

    internal static string SeverityForOperation(string? operation)
    {
        if (operation is null)
        {
            return "informational";
        }

        return NotableOperations.Any(o => operation.Equals(o, StringComparison.OrdinalIgnoreCase)) ? "medium" : "informational";
    }

    internal static string? CleanIp(string? ip)
    {
        if (string.IsNullOrWhiteSpace(ip))
        {
            return null;
        }

        var value = ip.Trim();
        // Purview sometimes reports "1.2.3.4:443" or "[2001:db8::1]:443".
        if (value.StartsWith('[') && value.Contains("]:", StringComparison.Ordinal))
        {
            value = value[1..value.IndexOf("]:", StringComparison.Ordinal)];
        }
        else if (value.Count(c => c == ':') == 1)
        {
            value = value[..value.IndexOf(':', StringComparison.Ordinal)];
        }

        return value.Length <= 64 ? value : null;
    }

    private static string LastSegment(string path)
    {
        var trimmed = path.TrimEnd('/');
        var index = trimmed.LastIndexOf('/');
        var segment = index >= 0 ? trimmed[(index + 1)..] : trimmed;
        return Uri.UnescapeDataString(segment);
    }
}
