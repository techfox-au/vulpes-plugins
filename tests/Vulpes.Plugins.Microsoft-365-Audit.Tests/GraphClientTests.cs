using System.Net;
using System.Net.Http.Headers;
using System.Text;
using Vulpes.Plugins.Microsoft365Audit.Graph;
using Xunit;

namespace Vulpes.Plugins.Microsoft365Audit.Tests;

public sealed class GraphClientTests
{
    [Fact]
    public async Task Follows_next_links_and_stops_at_max_pages()
    {
        var handler = new RoutedGraphHandler()
            .Get(p => p.Contains("auditLogs/signIns", StringComparison.Ordinal) && p.Contains("skiptoken=page2", StringComparison.Ordinal), _ => RoutedGraphHandler.Page([new { id = "c" }]))
            .Get(p => p.Contains("auditLogs/signIns", StringComparison.Ordinal) && p.Contains("skiptoken=page1", StringComparison.Ordinal), _ => RoutedGraphHandler.Page([new { id = "b" }], "https://graph.microsoft.com/v1.0/auditLogs/signIns?$skiptoken=page2"))
            .Get(p => p.Contains("auditLogs/signIns", StringComparison.Ordinal), _ => RoutedGraphHandler.Page([new { id = "a" }], "https://graph.microsoft.com/v1.0/auditLogs/signIns?$skiptoken=page1"));
        var client = TestContext.Client(handler);

        var ids = new List<string>();
        bool? complete = null;
        await foreach (var item in client.GetPagedAsync("auditLogs/signIns?$top=1", 10, CancellationToken.None, onCompleted: c => complete = c))
        {
            ids.Add(item.GetProperty("id").GetString()!);
        }

        Assert.Equal(["a", "b", "c"], ids);
        Assert.True(complete);
        Assert.Equal(3, handler.Requests.Count);
        Assert.All(handler.Requests, r => Assert.Equal("Bearer", r.Headers.Authorization!.Scheme));

        ids.Clear();
        await foreach (var item in client.GetPagedAsync("auditLogs/signIns?$top=1", 2, CancellationToken.None, onCompleted: c => complete = c))
        {
            ids.Add(item.GetProperty("id").GetString()!);
        }

        Assert.Equal(["a", "b"], ids);
        Assert.False(complete);
    }

    [Fact]
    public async Task Ignores_next_links_that_leave_the_graph_host()
    {
        var handler = new RoutedGraphHandler()
            .Get(p => p.Contains("auditLogs/signIns", StringComparison.Ordinal), _ => RoutedGraphHandler.Page([new { id = "a" }], "https://evil.example/v1.0/auditLogs/signIns?$skiptoken=page1"));
        var client = TestContext.Client(handler);
        var ids = new List<string>();
        await foreach (var item in client.GetPagedAsync("auditLogs/signIns", 10, CancellationToken.None))
        {
            ids.Add(item.GetProperty("id").GetString()!);
        }

        Assert.Equal(["a"], ids);
        Assert.Single(handler.Requests);
    }

    [Fact]
    public async Task Retries_on_429_honouring_retry_after()
    {
        var attempts = 0;
        var handler = new RoutedGraphHandler().Get(p => p.Contains("organization", StringComparison.Ordinal), _ =>
        {
            attempts++;
            if (attempts < 3)
            {
                var throttled = new HttpResponseMessage(HttpStatusCode.TooManyRequests) { Content = new StringContent("{}", Encoding.UTF8, "application/json") };
                throttled.Headers.RetryAfter = new RetryConditionHeaderValue(TimeSpan.FromMilliseconds(50));
                return throttled;
            }

            return FakeGraphHandler.Json(new { value = new[] { new { displayName = "Contoso" } } });
        });
        var client = TestContext.Client(handler);

        using var result = await client.GetAsync("organization", CancellationToken.None);
        Assert.Equal("Contoso", result.RootElement.GetProperty("value")[0].GetProperty("displayName").GetString());
        Assert.Equal(3, attempts);
        Assert.Equal(2, client.ThrottledCount);
    }

    [Fact]
    public async Task Surfaces_graph_errors_with_status_and_code()
    {
        var handler = new RoutedGraphHandler().Get(_ => true, _ => FakeGraphHandler.Json(new { error = new { code = "Authorization_RequestDenied", message = "Insufficient privileges" } }, HttpStatusCode.Forbidden));
        var client = TestContext.Client(handler);
        var ex = await Assert.ThrowsAsync<GraphException>(() => client.GetAsync("auditLogs/signIns", CancellationToken.None));
        Assert.True(ex.IsForbidden);
        Assert.Equal("Authorization_RequestDenied", ex.GraphErrorCode);
        Assert.Contains("Insufficient privileges", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Refuses_absolute_urls_outside_graph()
    {
        var client = TestContext.Client(new RoutedGraphHandler());
        await Assert.ThrowsAsync<GraphException>(() => client.GetAsync("https://evil.example/v1.0/me", CancellationToken.None));
    }

    [Fact]
    public void OData_literals_are_escaped()
    {
        Assert.Equal("'O''Brien'", Uri.UnescapeDataString(OData.Literal("O'Brien")));
        Assert.Equal("2026-10-29T08:00:05Z", OData.Timestamp(new DateTimeOffset(2026, 10, 29, 8, 0, 5, TimeSpan.Zero)));
    }
}
