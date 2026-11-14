using Vulpes.Plugins.Microsoft365Audit.Endpoints;
using Xunit;

namespace Vulpes.Plugins.Microsoft365Audit.Tests;

public sealed class AuditMcpToolTests
{
    [Fact]
    public void Audit_tools_read_logs_and_do_not_take_the_psa_names()
    {
        var names = new AuditMcp(null!, null!, null!, null!, TimeProvider.System).Tools.Select(tool => tool.Name).ToArray();
        Assert.Contains("search_events", names);
        Assert.Contains("list_clients", names);
        Assert.DoesNotContain("list_invoices", names);
        Assert.DoesNotContain("list_psa_clients", names);
    }
}
