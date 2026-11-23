using Vulpes.Plugins.SecretSharing.Endpoints;
using Xunit;

namespace Vulpes.Plugins.SecretSharing.Tests;

public sealed class ExpiryMinutesTests
{
    [Fact]
    public void A_huge_hour_count_does_not_wrap_into_a_short_expiry()
    {
        Assert.Equal(int.MaxValue, ShareEndpoints.ExpiryMinutes(214748365, 0));
        Assert.Equal(64800, ShareEndpoints.ExpiryMinutes(1080, 0));
        Assert.Equal(60, ShareEndpoints.ExpiryMinutes(1, 0));
        Assert.Equal(30, ShareEndpoints.ExpiryMinutes(1000, 30));
    }
}
