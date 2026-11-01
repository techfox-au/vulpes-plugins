using System.Net;
using Vulpes.Plugins.SecretSharing.Data;
using Vulpes.Plugins.SecretSharing.Services;
using Xunit;

namespace Vulpes.Plugins.SecretSharing.Tests;

public sealed class CollectRetrieveIpTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "ss-collect-ip-" + Guid.NewGuid().ToString("N"));

    [Fact]
    public void An_empty_list_allows_any_address_and_a_saved_list_does_not()
    {
        var store = new ShareStore(new ShareDatabase(Path.Combine(_dir, "share.db")));
        Assert.Null(store.CollectRetrieveAllowedIps());
        Assert.True(IpRestriction.IsClientAllowed(store.CollectRetrieveAllowedIps(), IPAddress.Parse("203.0.113.8")));

        Assert.True(IpRestriction.TryNormalize("203.0.113.0/24, 2001:db8::1", out var canonical, out var error));
        Assert.Null(error);
        store.SaveCollectRetrieveAllowedIps(canonical);
        Assert.Equal(canonical, store.CollectRetrieveAllowedIps());
        Assert.True(IpRestriction.IsClientAllowed(canonical, IPAddress.Parse("203.0.113.8")));
        Assert.False(IpRestriction.IsClientAllowed(canonical, IPAddress.Parse("198.51.100.8")));

        store.SaveCollectRetrieveAllowedIps(null);
        Assert.Null(store.CollectRetrieveAllowedIps());
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
}
