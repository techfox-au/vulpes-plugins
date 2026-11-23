using System.Net;
using Microsoft.Extensions.Logging;
using Vulpes.Sdk;

namespace Vulpes.Plugins.SecretSharing.Services;

/// <summary>Owner emails for a ready collect or an opened send. Failures are logged and do not fail the request.</summary>
public sealed class NotificationMail(ShareStore store, IHostEmail email, IHostAuditLog audit, IUserRoles roles, IUserEmail accounts, ILogger<NotificationMail> logger)
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

            var address = await CurrentAddressAsync(target.UserId);
            if (address is null)
            {
                return;
            }

            if (!ShareAccess.CanCollect(await roles.GetRolesAsync(target.UserId)))
            {
                var prefs = store.GetNotifications(target.UserId);
                store.SaveNotifications(target.UserId, address, false, prefs.NotifySendOpened);
                return;
            }

            await SendAsync(target.UserId, address, collectId, "collect_ready", "Vulpes - A collect is ready",
                "Someone submitted a response to one of your collect links.",
                "Collect id:");
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "Notification collect_ready failed for {CollectId}", collectId);
        }
    }

    public void TrySendOpened(string sendId) => _ = DeliverSendOpenedAsync(sendId);

    /// <summary>Sends the send-opened email to the owner's current account address.</summary>
    public async Task DeliverSendOpenedAsync(string sendId)
    {
        try
        {
            var target = store.SendOpenedTarget(sendId);
            if (target is null)
            {
                return;
            }

            var address = await CurrentAddressAsync(target.UserId);
            if (address is null)
            {
                return;
            }

            await SendAsync(target.UserId, address, sendId, "send_opened", "Vulpes - A send was opened",
                "Someone opened one of your links and downloaded the encrypted payload for decryption in their browser.",
                "Send id:");
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "Notification send_opened failed for {SendId}", sendId);
        }
    }

    /// <summary>The account address now, written back onto the notification row. A missing address turns the switches off.</summary>
    private async Task<string?> CurrentAddressAsync(string userId)
    {
        var live = (await accounts.GetEmailAsync(userId))?.Trim();
        var prefs = store.GetNotifications(userId);
        if (string.IsNullOrEmpty(live))
        {
            if (!string.IsNullOrEmpty(prefs.Email) || prefs.NotifyCollectReady || prefs.NotifySendOpened)
            {
                store.SaveNotifications(userId, "", false, false);
            }

            return null;
        }

        if (!string.Equals(prefs.Email, live, StringComparison.Ordinal))
        {
            store.SaveNotifications(userId, live, prefs.NotifyCollectReady, prefs.NotifySendOpened);
        }

        return live;
    }

    private async Task SendAsync(string userId, string address, string id, string kind, string subject, string intro, string idLabel)
    {
        try
        {
            if (!store.TryReserveNotifyEmail(address))
            {
                logger.LogWarning("Notification {Kind} throttled for {UserId}.", kind, userId);
                return;
            }

            var home = email.PublicOrigin + "/";
            var footer = "If you did not expect this, you can ignore this email or turn these emails off in Secret Sharing settings.";
            var text = intro + "\n\n" + idLabel + " " + id + "\n\nDashboard\n" + home + "\n\n" + footer;
            var html = "<p>" + WebUtility.HtmlEncode(intro) + "</p><p><strong>" + WebUtility.HtmlEncode(idLabel) + "</strong> " + WebUtility.HtmlEncode(id) + "</p><p><a href=\"" + WebUtility.HtmlEncode(home) + "\">Open dashboard</a></p><p>" + WebUtility.HtmlEncode(footer) + "</p>";
            if (!await email.TrySendAsync(address, subject, text, html))
            {
                return;
            }

            await audit.RecordAsync("secret.notify.sent", id, "kind=" + kind, actor: userId);
            logger.LogInformation("Notification {Kind} sent for user {UserId}", kind, userId);
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "Notification {Kind} failed for user {UserId}", kind, userId);
        }
    }
}
