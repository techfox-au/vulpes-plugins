using System.Net;
using Microsoft.Extensions.Logging;
using Vulpes.Sdk;

namespace Vulpes.Plugins.SecretSharing.Services;

/// <summary>Owner emails for a ready collect or an opened send. Failures are logged and do not fail the request.</summary>
public sealed class NotificationMail(ShareStore store, IHostEmail email, IHostAuditLog audit, IUserRoles roles, ILogger<NotificationMail> logger)
{
    public void TryCollectReady(string collectId) => _ = DeliverCollectReadyAsync(collectId);

    /// <summary>Sends the collect-ready email, or turns that notification off when the owner can no longer collect.</summary>
    public async Task DeliverCollectReadyAsync(string collectId)
    {
        try
        {
            var target = store.CollectReadyTarget(collectId);
            if (target is null)
            {
                return;
            }

            if (!ShareAccess.CanCollect(await roles.GetRolesAsync(target.UserId)))
            {
                var prefs = store.GetNotifications(target.UserId);
                store.SaveNotifications(target.UserId, prefs.Email, false, prefs.NotifySendOpened);
                return;
            }

            await SendAsync(target, collectId, "collect_ready", "Vulpes - A collect is ready",
                "Someone submitted a response to one of your collect links.",
                "Collect id:");
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "Notification collect_ready failed for {CollectId}", collectId);
        }
    }

    public void TrySendOpened(string sendId)
    {
        var target = store.SendOpenedTarget(sendId);
        if (target is null)
        {
            return;
        }

        Queue(target, sendId, "send_opened", "Vulpes - A send was opened",
            "Someone opened one of your links and downloaded the encrypted payload for decryption in their browser.",
            "Send id:");
    }

    private void Queue(NotifyTarget target, string id, string kind, string subject, string intro, string idLabel)
    {
        _ = SendAsync(target, id, kind, subject, intro, idLabel);
    }

    private async Task SendAsync(NotifyTarget target, string id, string kind, string subject, string intro, string idLabel)
    {
        try
        {
            if (!store.TryAllowNotifyEmail(target.Email, out var retryAfter))
            {
                logger.LogWarning("Notification {Kind} throttled for {UserId} (retry in {Retry:0}s).", kind, target.UserId, retryAfter.TotalSeconds);
                return;
            }

            var home = email.PublicOrigin + "/";
            var footer = "If you did not expect this, you can ignore this email or turn these emails off in Secret Sharing settings.";
            var text = intro + "\n\n" + idLabel + " " + id + "\n\nDashboard\n" + home + "\n\n" + footer;
            var html = "<p>" + WebUtility.HtmlEncode(intro) + "</p><p><strong>" + WebUtility.HtmlEncode(idLabel) + "</strong> " + WebUtility.HtmlEncode(id) + "</p><p><a href=\"" + WebUtility.HtmlEncode(home) + "\">Open dashboard</a></p><p>" + WebUtility.HtmlEncode(footer) + "</p>";
            if (!await email.TrySendAsync(target.Email, subject, text, html))
            {
                return;
            }

            store.NoteNotifyEmailSent(target.Email);
            await audit.RecordAsync("secret.notify.sent", id, "kind=" + kind, actor: target.UserId);
            logger.LogInformation("Notification {Kind} sent for user {UserId}", kind, target.UserId);
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "Notification {Kind} failed for user {UserId}", kind, target.UserId);
        }
    }
}
