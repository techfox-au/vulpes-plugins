using Microsoft.EntityFrameworkCore;
using Vulpes.Plugins.Mcp.Data;
using Vulpes.Sdk;

namespace Vulpes.Plugins.Mcp.Endpoints;

/// <summary>Emails the dashboard default recipients once, 10 days before a token expires.</summary>
internal static class TokenExpiryMail
{
    internal static readonly TimeSpan Lead = TimeSpan.FromDays(10);

    internal static async Task<int> SendDueAsync(McpDbContext db, IHostEmail email, IDefaultMailRecipients recipients, IHostAuditLog audit, TimeProvider time, CancellationToken cancellationToken)
    {
        var now = time.GetUtcNow();
        var horizon = now.Add(Lead);
        var due = await db.BotTokens
            .Where(t => t.RevokedAt == null && t.ExpiryNoticeSentAt == null && t.ExpiresAt != null && t.ExpiresAt > now && t.ExpiresAt <= horizon)
            .ToListAsync(cancellationToken);
        if (due.Count == 0)
        {
            return 0;
        }

        var addresses = (await recipients.GetAsync(cancellationToken))
            .Where(address => !string.IsNullOrWhiteSpace(address))
            .Select(address => address.Trim())
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();
        if (addresses.Count == 0)
        {
            return 0;
        }

        var sent = 0;
        foreach (var token in due)
        {
            var expires = token.ExpiresAt!.Value;
            var days = Math.Max(1, (int)Math.Ceiling((expires - now).TotalDays));
            var when = expires.ToString("yyyy-MM-dd", System.Globalization.CultureInfo.InvariantCulture);
            var origin = email.PublicOrigin.TrimEnd('/');
            var page = origin.Length == 0 ? "/p/mcp/settings" : origin + "/p/mcp/settings";
            var sentence = "The Grok Bot token \"" + token.Name + "\" (" + token.Prefix + ") expires on " + when + ", in " + days.ToString(System.Globalization.CultureInfo.InvariantCulture) + (days == 1 ? " day." : " days.") + " Create a replacement in MCP settings before that date.";
            var html = "<p>" + System.Net.WebUtility.HtmlEncode(sentence) + "</p><p><a href=\"" + System.Net.WebUtility.HtmlEncode(page) + "\">" + System.Net.WebUtility.HtmlEncode(page) + "</a></p>";
            var ok = true;
            foreach (var address in addresses)
            {
                if (!await email.TrySendAsync(address, "Grok Bot token expires on " + when, sentence + "\n\n" + page, html, cancellationToken))
                {
                    ok = false;
                }
            }

            if (!ok)
            {
                continue;
            }

            token.ExpiryNoticeSentAt = now;
            sent++;
            await audit.RecordAsync("mcp.bot_token.expiry_notice", token.Id.ToString(), token.Name + " " + token.Prefix, actor: "system:mcp", cancellationToken: cancellationToken);
        }

        if (sent > 0)
        {
            await db.SaveChangesAsync(cancellationToken);
        }

        return sent;
    }
}
