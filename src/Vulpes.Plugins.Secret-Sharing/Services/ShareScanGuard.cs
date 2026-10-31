using Microsoft.AspNetCore.Http;
using Vulpes.Plugins.SecretSharing.Data;
using Vulpes.Sdk;

namespace Vulpes.Plugins.SecretSharing.Services;

/// <summary>
/// Per-IP budget for public send and collect lookups. Failures and challenge issues count.
/// A success does not clear the budget. Shared through the plugin database.
/// </summary>
public sealed class ShareScanGuard(ShareDatabase database, IPowPolicy? policy = null)
{
    private readonly IPowPolicy _policy = policy ?? DefaultScanPolicy.Instance;
    public const int MaxFailuresInWindow = 10;
    public const int MaxChallengeIssuesInWindow = 30;
    private const string KindFailure = "fail";
    internal const string IssueKind = "pow_issue";
    private long _opsSinceCleanup;

    public bool IsFailureBudgetExceeded(string clientKey, out double retryAfterSeconds)
        => IsBudgetExceeded(KindFailure, clientKey, MaxFailuresInWindow, out retryAfterSeconds);

    public void RecordFailure(string clientKey) => Record(KindFailure, clientKey);

    public bool IsChallengeIssueBudgetExceeded(string clientKey, out double retryAfterSeconds)
        => IsBudgetExceeded(IssueKind, clientKey, MaxChallengeIssuesInWindow, out retryAfterSeconds);

    public void RecordChallengeIssue(string clientKey) => Record(IssueKind, clientKey);

    public static string ClientKey(HttpContext http) => http.Connection.RemoteIpAddress?.ToString() ?? "unknown";

    private bool IsBudgetExceeded(string kind, string clientKey, int max, out double retryAfterSeconds)
    {
        MaybeCleanup();
        retryAfterSeconds = 0;
        var nowMs = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        var windowSeconds = _policy.ScanBudgetWindowSeconds;
        var cutoff = nowMs - (long)(windowSeconds * 1000);
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
            ? Math.Max(0.1, (at + (long)(windowSeconds * 1000) - nowMs) / 1000.0)
            : windowSeconds;
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
        var cutoff = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() - (long)(_policy.ScanBudgetWindowSeconds * 1000);
        using var conn = database.Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "DELETE FROM scan_events WHERE AtMs < @cut";
        cmd.Parameters.AddWithValue("@cut", cutoff);
        cmd.ExecuteNonQuery();
        using var challenges = conn.CreateCommand();
        challenges.CommandText = "DELETE FROM pow_challenges WHERE ExpiresAt < @now";
        challenges.Parameters.AddWithValue("@now", DateTimeOffset.UtcNow.ToString("O"));
        challenges.ExecuteNonQuery();
    }

    private sealed class DefaultScanPolicy : IPowPolicy
    {
        public static readonly DefaultScanPolicy Instance = new();
        public int DifficultyBits => PowPolicyLimits.DefaultDifficultyBits;
        public int ChallengeTtlSeconds => PowPolicyLimits.DefaultChallengeTtlSeconds;
        public int CollectChallengeTtlSeconds => PowPolicyLimits.DefaultCollectChallengeTtlSeconds;
        public int ScanBudgetWindowSeconds => PowPolicyLimits.DefaultScanBudgetWindowSeconds;
    }
}
