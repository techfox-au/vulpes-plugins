using Microsoft.AspNetCore.Http;
using Vulpes.Plugins.SecretSharing.Data;

namespace Vulpes.Plugins.SecretSharing.Services;

/// <summary>
/// Per-IP budget for public send and collect lookups. Failures and challenge issues count.
/// A success does not clear the budget. Shared through the plugin database.
/// </summary>
public sealed class ShareScanGuard(ShareDatabase database)
{
    public const int MaxFailuresInWindow = 10;
    public const int MaxChallengeIssuesInWindow = 30;
    private const double WindowSeconds = 60;
    private const string KindFailure = "fail";
    private const string KindIssue = "pow_issue";
    private long _opsSinceCleanup;

    public bool IsFailureBudgetExceeded(string clientKey, out double retryAfterSeconds)
        => IsBudgetExceeded(KindFailure, clientKey, MaxFailuresInWindow, out retryAfterSeconds);

    public void RecordFailure(string clientKey) => Record(KindFailure, clientKey);

    public bool IsChallengeIssueBudgetExceeded(string clientKey, out double retryAfterSeconds)
        => IsBudgetExceeded(KindIssue, clientKey, MaxChallengeIssuesInWindow, out retryAfterSeconds);

    public void RecordChallengeIssue(string clientKey) => Record(KindIssue, clientKey);

    public static string ClientKey(HttpContext http) => http.Connection.RemoteIpAddress?.ToString() ?? "unknown";

    private bool IsBudgetExceeded(string kind, string clientKey, int max, out double retryAfterSeconds)
    {
        MaybeCleanup();
        retryAfterSeconds = 0;
        var nowMs = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        var cutoff = nowMs - (long)(WindowSeconds * 1000);
        using var conn = database.Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT AtMs FROM scan_events WHERE Kind = @kind AND ClientKey = @ck AND AtMs >= @cut ORDER BY AtMs ASC";
        cmd.Parameters.AddWithValue("@kind", kind);
        cmd.Parameters.AddWithValue("@ck", clientKey);
        cmd.Parameters.AddWithValue("@cut", cutoff);
        long? oldest = null;
        var count = 0;
        using var reader = cmd.ExecuteReader();
        while (reader.Read())
        {
            count++;
            oldest ??= reader.GetInt64(0);
        }

        if (count < max) return false;
        retryAfterSeconds = oldest is long at
            ? Math.Max(0.1, (at + (long)(WindowSeconds * 1000) - nowMs) / 1000.0)
            : WindowSeconds;
        return true;
    }

    private void Record(string kind, string clientKey)
    {
        using var conn = database.Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "INSERT INTO scan_events (Kind, ClientKey, AtMs) VALUES (@k, @c, @t)";
        cmd.Parameters.AddWithValue("@k", kind);
        cmd.Parameters.AddWithValue("@c", clientKey);
        cmd.Parameters.AddWithValue("@t", DateTimeOffset.UtcNow.ToUnixTimeMilliseconds());
        cmd.ExecuteNonQuery();
        MaybeCleanup();
    }

    private void MaybeCleanup()
    {
        if (Interlocked.Increment(ref _opsSinceCleanup) % 256 != 0) return;
        var cutoff = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() - (long)(WindowSeconds * 1000);
        using var conn = database.Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "DELETE FROM scan_events WHERE AtMs < @cut";
        cmd.Parameters.AddWithValue("@cut", cutoff);
        cmd.ExecuteNonQuery();
    }
}
