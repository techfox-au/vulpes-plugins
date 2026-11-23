using Microsoft.Extensions.Logging.Abstractions;
using Vulpes.Plugins.SecretSharing.Data;
using Vulpes.Plugins.SecretSharing.Services;
using Vulpes.Sdk;
using Xunit;

namespace Vulpes.Plugins.SecretSharing.Tests;

public sealed class NotificationRoleTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "ss-notify-" + Guid.NewGuid().ToString("N"));

    [Fact]
    public async Task A_viewer_collect_notification_is_turned_off_instead_of_sent()
    {
        var database = new ShareDatabase(Path.Combine(_dir, "share.db"));
        var store = new ShareStore(database);
        var id = store.CreateCollect("owner", new CollectInput(Base64Url.Encode(new byte[32]), null, null, null, true, 60, null, false, false, null));
        store.SaveNotifications("owner", "owner@example.com", true, true);
        var email = new FakeEmail();
        var mail = new NotificationMail(store, email, new FakeAudit(), new FakeRoles(DashboardRoles.Viewer), new FakeAccountEmail("owner@example.com"), NullLogger<NotificationMail>.Instance);

        await mail.DeliverCollectReadyAsync(id);

        Assert.False(email.Sent);
        var prefs = store.GetNotifications("owner");
        Assert.False(prefs.NotifyCollectReady);
        Assert.True(prefs.NotifySendOpened);
    }

    [Fact]
    public async Task An_analyst_collect_notification_is_sent()
    {
        var database = new ShareDatabase(Path.Combine(_dir, "share.db"));
        var store = new ShareStore(database);
        var id = store.CreateCollect("owner", new CollectInput(Base64Url.Encode(new byte[32]), null, null, null, true, 60, null, false, false, null));
        store.SaveNotifications("owner", "owner@example.com", true, false);
        var email = new FakeEmail();
        var mail = new NotificationMail(store, email, new FakeAudit(), new FakeRoles(DashboardRoles.Analyst), new FakeAccountEmail("owner@example.com"), NullLogger<NotificationMail>.Instance);

        await mail.DeliverCollectReadyAsync(id);

        Assert.True(email.Sent);
        Assert.Equal("owner@example.com", email.To);
        Assert.True(store.GetNotifications("owner").NotifyCollectReady);
    }

    [Fact]
    public async Task A_changed_account_email_receives_the_open_notice()
    {
        var database = new ShareDatabase(Path.Combine(_dir, "changed.db"));
        var store = new ShareStore(database);
        var id = store.CreateSend("owner", new SendInput("ct", "iv", "wk", "eph", "text/plain", null, true, 60, null, null, null, false, false));
        store.SaveNotifications("owner", "old@example.com", false, true);
        var email = new FakeEmail();
        var mail = new NotificationMail(store, email, new FakeAudit(), new FakeRoles(DashboardRoles.Analyst), new FakeAccountEmail("new@example.com"), NullLogger<NotificationMail>.Instance);

        await mail.DeliverSendOpenedAsync(id);

        Assert.Equal("new@example.com", email.To);
        var prefs = store.GetNotifications("owner");
        Assert.Equal("new@example.com", prefs.Email);
        Assert.True(prefs.NotifySendOpened);
    }

    [Fact]
    public async Task A_removed_account_email_stops_the_notice_and_clears_the_switches()
    {
        var database = new ShareDatabase(Path.Combine(_dir, "cleared.db"));
        var store = new ShareStore(database);
        var id = store.CreateCollect("owner", new CollectInput(Base64Url.Encode(new byte[32]), null, null, null, true, 60, null, false, false, null));
        store.SaveNotifications("owner", "old@example.com", true, true);
        var email = new FakeEmail();
        var mail = new NotificationMail(store, email, new FakeAudit(), new FakeRoles(DashboardRoles.Analyst), new FakeAccountEmail(null), NullLogger<NotificationMail>.Instance);

        await mail.DeliverCollectReadyAsync(id);

        Assert.False(email.Sent);
        var prefs = store.GetNotifications("owner");
        Assert.Equal("", prefs.Email);
        Assert.False(prefs.NotifyCollectReady);
        Assert.False(prefs.NotifySendOpened);
    }

    public void Dispose()
    {
        try
        {
            Directory.Delete(_dir, recursive: true);
        }
        catch (IOException)
        {
        }
    }

    private sealed class FakeRoles(string role) : IUserRoles
    {
        public Task<IReadOnlyList<string>> GetRolesAsync(string userId, CancellationToken cancellationToken = default) =>
            Task.FromResult<IReadOnlyList<string>>([role]);
    }

    private sealed class FakeAccountEmail(string? email) : IUserEmail
    {
        public Task<string?> GetEmailAsync(string userId, CancellationToken cancellationToken = default) =>
            Task.FromResult(email);
    }

    private sealed class FakeEmail : IHostEmail
    {
        public string PublicOrigin => "http://localhost";

        public bool Sent { get; private set; }

        public string? To { get; private set; }

        public Task<bool> TrySendAsync(string to, string subject, string text, string html, CancellationToken cancellationToken = default)
        {
            Sent = true;
            To = to;
            return Task.FromResult(true);
        }

        public Task<bool> TrySendAsync(string to, string subject, string text, string html, IReadOnlyList<HostEmailAttachment> attachments, CancellationToken cancellationToken = default) =>
            TrySendAsync(to, subject, text, html, cancellationToken);
    }

    private sealed class FakeAudit : IHostAuditLog
    {
        public Task RecordAsync(string action, string? target, string? details, string? actor = null, CancellationToken cancellationToken = default) =>
            Task.CompletedTask;
    }
}
