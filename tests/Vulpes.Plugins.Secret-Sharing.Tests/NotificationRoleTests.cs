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
        var mail = new NotificationMail(store, email, new FakeAudit(), new FakeRoles(DashboardRoles.Viewer), NullLogger<NotificationMail>.Instance);

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
        var mail = new NotificationMail(store, email, new FakeAudit(), new FakeRoles(DashboardRoles.Analyst), NullLogger<NotificationMail>.Instance);

        await mail.DeliverCollectReadyAsync(id);

        Assert.True(email.Sent);
        Assert.True(store.GetNotifications("owner").NotifyCollectReady);
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

    private sealed class FakeEmail : IHostEmail
    {
        public string PublicOrigin => "http://localhost";

        public bool Sent { get; private set; }

        public Task<bool> TrySendAsync(string to, string subject, string text, string html, CancellationToken cancellationToken = default)
        {
            Sent = true;
            return Task.FromResult(true);
        }
    }

    private sealed class FakeAudit : IHostAuditLog
    {
        public Task RecordAsync(string action, string? target, string? details, string? actor = null, CancellationToken cancellationToken = default) =>
            Task.CompletedTask;
    }
}
