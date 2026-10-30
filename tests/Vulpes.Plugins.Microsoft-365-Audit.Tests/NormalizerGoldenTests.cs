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
        var input = JsonDocument.Parse(File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "Golden", name + ".input.json"))).RootElement;
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
        Assert.Equal("microsoft-365-audit", actual.ModuleId);
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
        Assert.Null(Normalizers.SignIn(JsonDocument.Parse("""{"createdDateTime":"2026-10-29T09:15:22Z"}""").RootElement, "t", null, "interactive"));
        Assert.Null(Normalizers.SignIn(JsonDocument.Parse("""{"id":"x"}""").RootElement, "t", null, "interactive"));
        Assert.Null(Normalizers.AuditLogRecord(JsonDocument.Parse("""{"id":"x"}""").RootElement, "t", null));
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
        var e = Normalizers.AuditLogRecord(JsonDocument.Parse("""{"id":"e1","createdDateTime":"2026-10-29T10:03:11Z","auditLogRecordType":"exchangeAdmin","operation":"New-InboxRule","userPrincipalName":"bob@contoso.com","objectId":"bob@contoso.com\\Forward all","auditData":{"Workload":"Exchange","ResultStatus":"True"}}""").RootElement, "t", null);
        Assert.NotNull(e);
        Assert.Equal("email", e.Category);
        Assert.Null(e.FilePath);
        Assert.Equal("medium", e.Severity);
        Assert.Equal("success", e.Outcome);
        Assert.Equal("purview.exchange", e.Dataset);
    }
}
