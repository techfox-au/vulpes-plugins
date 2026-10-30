using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.Extensions.Logging.Abstractions;
using Vulpes.Plugins.Microsoft365Audit;
using Vulpes.Plugins.Microsoft365Audit.Collectors;
using Vulpes.Plugins.Microsoft365Audit.Data;
using Vulpes.Plugins.Microsoft365Audit.Graph;
using Vulpes.Plugins.Microsoft365Audit.Tenants;
using Vulpes.Sdk;

namespace Vulpes.Plugins.Microsoft365Audit.Tests;

/// <summary>Routes Graph requests to canned responses; records every call.</summary>
public sealed class FakeGraphHandler : HttpMessageHandler
{
    private readonly List<(Func<HttpRequestMessage, bool> Match, Func<HttpRequestMessage, HttpResponseMessage> Respond)> _routes = [];

    public List<HttpRequestMessage> Requests { get; } = [];

    public FakeGraphHandler On(string method, string pathContains, Func<HttpRequestMessage, HttpResponseMessage> respond)
    {
        _routes.Add((r => r.Method.Method == method && r.RequestUri!.PathAndQuery.Contains(pathContains, StringComparison.Ordinal), respond));
        return this;
    }

    public FakeGraphHandler OnJson(string method, string pathContains, Func<HttpRequestMessage, object> body, HttpStatusCode status = HttpStatusCode.OK) =>
        On(method, pathContains, r => Json(body(r), status));

    /// <summary>Serves a paged collection: page N links to page N+1 through @odata.nextLink.</summary>
    public FakeGraphHandler Paged(string pathContains, IReadOnlyList<IReadOnlyList<object>> pages, string host = "https://graph.microsoft.com")
    {
        for (var i = 0; i < pages.Count; i++)
        {
            var index = i;
            var marker = index == 0 ? pathContains : $"{pathContains}&$skiptoken=page{index}";
            On("GET", marker, _ =>
            {
                var obj = new JsonObject { ["value"] = new JsonArray(pages[index].Select(v => JsonNode.Parse(JsonSerializer.Serialize(v))).ToArray()) };
                if (index + 1 < pages.Count)
                {
                    obj["@odata.nextLink"] = $"{host}/v1.0/{pathContains}&$skiptoken=page{index + 1}";
                }

                return Json(obj);
            });
        }

        return this;
    }

    public static HttpResponseMessage Json(object body, HttpStatusCode status = HttpStatusCode.OK)
    {
        var text = body is string s ? s : body is JsonNode n ? n.ToJsonString() : JsonSerializer.Serialize(body);
        return new HttpResponseMessage(status) { Content = new StringContent(text, Encoding.UTF8, "application/json") };
    }

    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        Requests.Add(request);
        // Most specific (longest marker) first so "&$skiptoken=page1" wins over the bare path.
        foreach (var (match, respond) in _routes.OrderByDescending(r => r.Match.Method.Name.Length).ToList())
        {
            if (match(request) && !(request.RequestUri!.PathAndQuery.Contains("$skiptoken", StringComparison.Ordinal) && !MatchesSkipToken(request)))
            {
                return Task.FromResult(respond(request));
            }
        }

        return Task.FromResult(new HttpResponseMessage(HttpStatusCode.NotFound) { Content = new StringContent($"{{\"error\":{{\"code\":\"NotFound\",\"message\":\"no fake route for {request.Method} {request.RequestUri!.PathAndQuery}\"}}}}", Encoding.UTF8, "application/json") });

        static bool MatchesSkipToken(HttpRequestMessage r) => true;
    }
}

/// <summary>A handler whose routes are evaluated in registration order with exact skiptoken awareness.</summary>
public sealed class RoutedGraphHandler : HttpMessageHandler
{
    private readonly List<(string Method, Func<string, bool> Match, Func<HttpRequestMessage, HttpResponseMessage> Respond)> _routes = [];

    public List<HttpRequestMessage> Requests { get; } = [];

    public RoutedGraphHandler Route(string method, Func<string, bool> match, Func<HttpRequestMessage, HttpResponseMessage> respond)
    {
        _routes.Add((method, match, respond));
        return this;
    }

    public RoutedGraphHandler Get(Func<string, bool> match, Func<HttpRequestMessage, HttpResponseMessage> respond) => Route("GET", match, respond);

    public RoutedGraphHandler Post(Func<string, bool> match, Func<HttpRequestMessage, HttpResponseMessage> respond) => Route("POST", match, respond);

    public static HttpResponseMessage Page(IEnumerable<object> items, string? nextLink = null)
    {
        var obj = new JsonObject { ["value"] = new JsonArray(items.Select(v => JsonNode.Parse(JsonSerializer.Serialize(v))).ToArray()) };
        if (nextLink is not null)
        {
            obj["@odata.nextLink"] = nextLink;
        }

        return FakeGraphHandler.Json(obj);
    }

    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        Requests.Add(request);
        var pathAndQuery = Uri.UnescapeDataString(request.RequestUri!.PathAndQuery);
        foreach (var (method, match, respond) in _routes)
        {
            if (request.Method.Method == method && match(pathAndQuery))
            {
                return Task.FromResult(respond(request));
            }
        }

        return Task.FromResult(new HttpResponseMessage(HttpStatusCode.NotFound) { Content = new StringContent($"{{\"error\":{{\"code\":\"NotFound\",\"message\":\"no fake route for {request.Method} {pathAndQuery}\"}}}}", Encoding.UTF8, "application/json") });
    }
}

public sealed class FakeTokenProvider : IGraphTokenProvider
{
    public int Calls { get; private set; }

    public Task<string> GetTokenAsync(CancellationToken cancellationToken)
    {
        Calls++;
        return Task.FromResult("fake-token");
    }
}

public sealed class FakePipeline : IEventPipeline
{
    public List<SecurityEvent> Events { get; } = [];

    public Task<PublishResult> PublishAsync(IReadOnlyList<SecurityEvent> events, CancellationToken cancellationToken)
    {
        var existing = new HashSet<string>(Events.Select(Key), StringComparer.Ordinal);
        var duplicates = events.Count(e => existing.Contains(Key(e)));
        Events.AddRange(events.Where(e => !existing.Contains(Key(e))));
        return Task.FromResult(new PublishResult(events.Count - duplicates, duplicates, 0, 0));
    }

    private static string Key(SecurityEvent e) => $"{e.TenantId}:{e.Source}:{e.RecordId}";
}

public sealed class FakeProtector : ISecretProtector
{
    public string Protect(string plaintext) => "v1." + Convert.ToBase64String(Encoding.UTF8.GetBytes(plaintext));

    public string Unprotect(string protectedValue) => Encoding.UTF8.GetString(Convert.FromBase64String(protectedValue[3..]));
}

public static class TestContext
{
    public static readonly Tenant Tenant = new()
    {
        Id = Guid.Parse("11111111-1111-1111-1111-111111111111"),
        DisplayName = "Contoso",
        TenantId = "9c5f0d9b-7c2d-4b1a-9a2f-0e0d1c2b3a44",
        ClientId = "22222222-2222-2222-2222-222222222222",
        LookbackDays = 7,
    };

    public static GraphClient Client(HttpMessageHandler handler, TimeProvider? time = null) =>
        new(new HttpClient(handler) { BaseAddress = new Uri("https://graph.microsoft.com") }, new FakeTokenProvider(), GraphCloud.Global, NullLogger.Instance, time);

    public static CollectorContext Context(GraphClient graph, FakePipeline pipeline, Checkpoint? checkpoint = null, AuditOptions? options = null, SourceSettings? settings = null, TimeProvider? time = null)
    {
        time ??= TimeProvider.System;
        return new CollectorContext
        {
            Tenant = Tenant,
            Settings = settings ?? new SourceSettings(),
            Graph = graph,
            Checkpoint = checkpoint ?? new Checkpoint { TenantId = Tenant.Id, Source = "test" },
            Pipeline = pipeline,
            Options = options ?? new AuditOptions(),
            Time = time,
            Logger = NullLogger.Instance,
            Deadline = time.GetUtcNow().AddMinutes(20),
        };
    }
}
