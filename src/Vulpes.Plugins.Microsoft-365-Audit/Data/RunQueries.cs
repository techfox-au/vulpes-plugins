using System.Text.RegularExpressions;

namespace Vulpes.Plugins.Microsoft365Audit.Data;

/// <summary>One Purview query is one Recent runs row. A later check replaces the earlier rows.</summary>
public static partial class RunQueries
{
    [GeneratedRegex(@"query (?<id>[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})", RegexOptions.CultureInvariant)]
    private static partial Regex QueryIdPattern();

    public static string? IdIn(string? text)
    {
        if (string.IsNullOrEmpty(text))
        {
            return null;
        }

        var match = QueryIdPattern().Match(text);
        return match.Success ? match.Groups["id"].Value : null;
    }

    public static List<RunLogEntry> LatestPerQuery(IEnumerable<RunLogEntry> newestFirst)
    {
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var kept = new List<RunLogEntry>();
        foreach (var run in newestFirst)
        {
            var id = IdIn(run.Error);
            if (id is null || seen.Add($"{run.TenantId:N}:{id}"))
            {
                kept.Add(run);
            }
        }

        return kept;
    }
}
