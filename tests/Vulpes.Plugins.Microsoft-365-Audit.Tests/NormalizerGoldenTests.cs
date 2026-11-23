using System.Globalization;
using System.Text.Json;
using System.Text.Json.Nodes;
using Vulpes.Plugins.Microsoft365Audit.Normalization;
using Vulpes.Sdk;
using Xunit;

namespace Vulpes.Plugins.Microsoft365Audit.Tests;

/// <summary>Each Graph fixture in Golden/*.input.json must normalize to the fields in the matching *.expected.json.</summary>
public sealed class NormalizerGoldenTests
{
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);
    private const string TenantId = "9c5f0d9b-7c2d-4b1a-9a2f-0e0d1c2b3a44";

    public static TheoryData<string> Cases => ["signin", "auditlogrecord", "directoryaudit", "alert", "riskdetection"];

    [Theory]
    [MemberData(nameof(Cases))]
    public void Matches_golden_file(string name)
    {
        var input = JsonElement.Parse(File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "Golden", name + ".input.json")));
        var expected = JsonNode.Parse(File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "Golden", name + ".expected.json")))!.AsObject();

        SecurityEvent? actual = name switch
        {
            "signin" => Normalizers.SignIn(input, TenantId, "Contoso", "interactive"),
            "auditlogrecord" => Normalizers.AuditLogRecord(input, TenantId, "Contoso"),
            "directoryaudit" => Normalizers.DirectoryAudit(input, TenantId, "Contoso"),
            "alert" => Normalizers.SecurityAlert(input, TenantId, "Contoso"),
            "riskdetection" => Normalizers.RiskDetection(input, TenantId, "Contoso"),
            _ => throw new ArgumentOutOfRangeException(nameof(name)),
        };

        Assert.NotNull(actual);
        Assert.Equal("microsoft-365-audit", actual.PluginId);
        Assert.Equal(TenantId, actual.TenantId);
        Assert.NotNull(actual.Data);

        // Serialize the event (minus raw data) and compare every property named in the golden file.
        var serialized = JsonNode.Parse(JsonSerializer.Serialize(actual, Json))!.AsObject();
        foreach (var (key, expectedValue) in expected)
        {
            var actualValue = serialized[key];
            var expectedText = Normalize(expectedValue, input);
            var actualText = Normalize(actualValue, input);
            Assert.True(expectedText == actualText, $"{name}.{key}: expected {expectedText} but got {actualText}");
        }
    }

    private static string Normalize(JsonNode? node, JsonElement input)
    {
        if (node is null)
        {
            return "null";
        }

        if (node is JsonValue value && value.TryGetValue<string>(out var text))
        {
            // "{ticks:<iso>}" placeholders let golden files express tick-based ids readably.
            text = System.Text.RegularExpressions.Regex.Replace(text, @"\{ticks:([^}]+)\}", m => DateTimeOffset.Parse(m.Groups[1].Value, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal).UtcTicks.ToString(CultureInfo.InvariantCulture));

            if (DateTimeOffset.TryParse(text, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out var dto) && text.Contains('T', StringComparison.Ordinal))
            {
                return dto.UtcDateTime.ToString("O", CultureInfo.InvariantCulture);
            }

            return text;
        }

        return node.ToJsonString();
    }
}

public sealed class NormalizerEdgeCaseTests
{
    [Fact]
    public void Skips_records_without_id_or_timestamp()
    {
        Assert.Null(Normalizers.SignIn(JsonElement.Parse("""{"createdDateTime":"2026-10-29T09:15:22Z"}"""), "t", null, "interactive"));
        Assert.Null(Normalizers.SignIn(JsonElement.Parse("""{"id":"x"}"""), "t", null, "interactive"));
        Assert.Null(Normalizers.AuditLogRecord(JsonElement.Parse("""{"id":"x"}"""), "t", null));
    }

    [Theory]
    [InlineData("198.51.100.7:51234", "198.51.100.7")]
    [InlineData("[2001:db8::1]:443", "2001:db8::1")]
    [InlineData("2001:db8::1", "2001:db8::1")]
    [InlineData("  ", null)]
    public void Cleans_ip_addresses_with_ports(string input, string? expected)
    {
        Assert.Equal(expected, Normalizers.CleanIp(input));
    }

    [Theory]
    [InlineData("sharePointFileOperation", "file")]
    [InlineData("oneDrive", "file")]
    [InlineData("exchangeItem", "email")]
    [InlineData("azureActiveDirectoryStsLogon", "authentication")]
    [InlineData("azureActiveDirectory", "iam")]
    [InlineData("complianceDLPSharePoint", "threat")]
    [InlineData("microsoftTeams", "collaboration")]
    [InlineData("powerBIAudit", "configuration")]
    public void Maps_record_types_to_categories(string recordType, string category)
    {
        Assert.Equal(category, Normalizers.CategoryForRecordType(recordType));
    }

    [Fact]
    public void Exchange_records_do_not_get_file_fields()
    {
        var e = Normalizers.AuditLogRecord(JsonElement.Parse("""{"id":"e1","createdDateTime":"2026-10-29T10:03:11Z","auditLogRecordType":"exchangeAdmin","operation":"New-InboxRule","userPrincipalName":"bob@contoso.com","objectId":"bob@contoso.com\\Forward all","auditData":{"Workload":"Exchange","ResultStatus":"True"}}"""), "t", null);
        Assert.NotNull(e);
        Assert.Equal("email", e.Category);
        Assert.Null(e.FilePath);
        Assert.Equal("medium", e.Severity);
        Assert.Equal("success", e.Outcome);
        Assert.Equal("purview.exchange", e.Dataset);
    }

    [Fact]
    public void Exchange_admin_false_is_a_failure_and_a_sts_logon_error_is_not_a_success()
    {
        var failedCmdlet = Normalizers.AuditLogRecord(JsonElement.Parse("""{"id":"e2","createdDateTime":"2026-10-29T10:03:11Z","auditLogRecordType":"exchangeAdmin","operation":"New-InboxRule","userPrincipalName":"bob@contoso.com","auditData":{"Workload":"Exchange","ResultStatus":"False"}}"""), "t", null);
        Assert.Equal("failure", failedCmdlet!.Outcome);

        var failedLogon = Normalizers.AuditLogRecord(JsonElement.Parse("""{"id":"e3","createdDateTime":"2026-10-29T10:04:11Z","auditLogRecordType":"azureActiveDirectoryStsLogon","operation":"UserLoginFailed","userPrincipalName":"bob@contoso.com","auditData":{"Workload":"AzureActiveDirectory","ResultStatus":"Succeeded","LogonError":"InvalidPassword"}}"""), "t", null);
        Assert.Equal("failure", failedLogon!.Outcome);

        var signedIn = Normalizers.AuditLogRecord(JsonElement.Parse("""{"id":"e4","createdDateTime":"2026-10-29T10:05:11Z","auditLogRecordType":"azureActiveDirectoryStsLogon","operation":"UserLoggedIn","userPrincipalName":"bob@contoso.com","auditData":{"Workload":"AzureActiveDirectory","ResultStatus":"Succeeded"}}"""), "t", null);
        Assert.Equal("success", signedIn!.Outcome);
    }

    [Fact]
    public void Mailbox_access_uses_the_client_description_instead_of_the_app_id()
    {
        var e = Normalizers.AuditLogRecord(JsonElement.Parse("""{"id":"e5","createdDateTime":"2026-10-29T10:06:11Z","auditLogRecordType":"exchangeItem","operation":"MailItemsAccessed","userPrincipalName":"bob@contoso.com","auditData":{"Workload":"Exchange","ResultStatus":"Success","ClientAppId":"00000002-0000-0ff1-ce00-000000000000","ClientInfoString":"Client=ActiveSync;Apple-iPhone/1309.63"}}"""), "t", null);
        Assert.Equal("Client=ActiveSync;Apple-iPhone/1309.63", e!.ClientAppName);
    }

    [Fact]
    public void Directory_timeout_is_a_failure()
    {
        var timedOut = Directory("timeout");
        Assert.Equal("failure", timedOut.Outcome);
        Assert.Contains("(timeout)", timedOut.Message, StringComparison.Ordinal);

        Assert.Equal("success", Directory("success").Outcome);
        Assert.Equal("failure", Directory("failure").Outcome);
        Assert.Equal("unknown", Directory("unknownFutureValue").Outcome);
    }

    private static SecurityEvent Directory(string result)
    {
        var parsed = Normalizers.DirectoryAudit(JsonSerializer.SerializeToElement(new JsonObject
        {
            ["id"] = "d1",
            ["activityDateTime"] = "2026-10-28T23:44:01Z",
            ["result"] = result,
            ["activityDisplayName"] = "Update user",
            ["initiatedBy"] = new JsonObject
            {
                ["user"] = new JsonObject { ["userPrincipalName"] = "admin@contoso.com" },
            },
        }), "t", null);
        Assert.NotNull(parsed);
        return parsed;
    }
}
