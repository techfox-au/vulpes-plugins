using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.EntityFrameworkCore;
using Vulpes.Plugins.Mcp.Data;
using Vulpes.Sdk;

namespace Vulpes.Plugins.Mcp.Endpoints;

/// <summary>MCP JSON-RPC at <c>/api/plugins/mcp</c>, plus the token list for Settings.</summary>
public static class McpEndpoints
{
    private const int MaxBodyBytes = 100 * 1024 * 1024;
    private const int CallsPerMinute = 60;
    private static readonly Lock RateGate = new();
    private static readonly Dictionary<Guid, Queue<long>> RecentCalls = [];
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);

    public static void Map(IEndpointRouteBuilder group)
    {
        ArgumentNullException.ThrowIfNull(group);
        group.MapPost(string.Empty, HandleAsync).AllowAnonymous();
        group.MapGet(string.Empty, Listen).AllowAnonymous();
        group.MapGet("/tokens", ListTokensAsync).RequireAuthorization(Policies.Admin);
        group.MapPost("/tokens", CreateTokenAsync).RequireAuthorization(Policies.Admin);
        group.MapDelete("/tokens/{id:guid}", DeleteTokenAsync).RequireAuthorization(Policies.Admin);
    }

    private static IResult Listen(HttpResponse response)
    {
        response.Headers.Append("Allow", "POST");
        return Results.StatusCode(StatusCodes.Status405MethodNotAllowed);
    }

    internal static async Task<IResult> HandleAsync(HttpContext http, McpDbContext db, IEnumerable<IMcpToolSource> sources, TimeProvider time, IHostAuditLog audit, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(http);
        http.Response.Headers.CacheControl = "no-store";
        if (!TryBearer(http, out var token))
        {
            return RpcError(null, 401, -32001, "Send Authorization: Bearer with a token from MCP settings.");
        }

        var hash = McpTokens.Hash(token);
        var row = await db.BotTokens.FirstOrDefaultAsync(t => t.TokenHash == hash && t.RevokedAt == null, ct);
        var now = time.GetUtcNow();
        if (row is null || (row.ExpiresAt is { } expiry && expiry <= now))
        {
            return RpcError(null, 401, -32001, "The token was rejected.");
        }

        if (!AllowCall(row.Id, now))
        {
            await audit.RecordAsync("mcp.rate_limited", row.Name, row.Prefix, actor: "bot:" + row.Prefix, cancellationToken: ct);
            return RpcError(null, 429, -32029, "This token is being used too quickly. Wait a minute and try again.");
        }

        if (row.LastUsedAt is null || now - row.LastUsedAt > TimeSpan.FromMinutes(1))
        {
            row.LastUsedAt = now;
            await db.SaveChangesAsync(ct);
        }

        var registered = Register(sources);
        JsonNode? id = null;
        try
        {
            if (http.Request.ContentLength is > MaxBodyBytes)
            {
                return RpcError(null, 400, -32600, "The request is too large.");
            }

            using var body = new MemoryStream();
            var chunk = new byte[8192];
            while (true)
            {
                var n = await http.Request.Body.ReadAsync(chunk, ct);
                if (n == 0)
                {
                    break;
                }

                if (body.Length + n > MaxBodyBytes)
                {
                    return RpcError(null, 400, -32600, "The request is too large.");
                }

                body.Write(chunk, 0, n);
            }

            var raw = body.ToArray();
            try
            {
            using var document = JsonDocument.Parse(raw);
            CryptographicOperations.ZeroMemory(chunk);
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object || !root.TryGetProperty("method", out var methodEl) || methodEl.ValueKind != JsonValueKind.String)
            {
                return RpcError(null, 400, -32600, "A JSON-RPC request needs a method.");
            }

            var method = methodEl.GetString() ?? string.Empty;
            if (method.Length > 64)
            {
                return RpcError(null, 400, -32601, "Unknown method.");
            }

            var hasId = root.TryGetProperty("id", out var idEl) && idEl.ValueKind is JsonValueKind.String or JsonValueKind.Number;
            if (hasId && idEl.GetRawText().Length > 64)
            {
                return RpcError(null, 400, -32600, "The request id is too long.");
            }

            id = hasId ? JsonNode.Parse(idEl.GetRawText()) : null;
            if (method.StartsWith("notifications/", StringComparison.Ordinal))
            {
                return Results.StatusCode(StatusCodes.Status202Accepted);
            }

            if (!hasId)
            {
                return RpcError(null, 400, -32600, "A request needs an id.");
            }

            var arguments = root.TryGetProperty("params", out var paramsEl) ? paramsEl : default;
            if (method == "tools/call")
            {
                var called = ToolName(arguments);
                await audit.RecordAsync("mcp.tool", called, CallDetail(registered, called, arguments), actor: "bot:" + row.Prefix, cancellationToken: ct);
            }

            JsonNode? result;
            if (method == "tools/call")
            {
                var udk = await BotUdk.ForAsync(db, row, token, ct);
                try
                {
                    result = await CallToolAsync(arguments, registered, new McpCaller(row.Id.ToString("D"), udk), ct);
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(udk);
                }
            }
            else
            {
                result = method switch
                {
                    "initialize" => Initialize(arguments, registered, sources),
                    "ping" => new JsonObject(),
                    "tools/list" => new JsonObject { ["tools"] = ListTools(registered) },
                    _ => null,
                };
            }
            if (result is null)
            {
                return RpcError(id, 200, -32601, $"Unknown method '{method}'.");
            }

            return Results.Text(Envelope(id, result), "application/json");
            }
            finally
            {
                CryptographicOperations.ZeroMemory(raw);
            }
        }
        catch (JsonException)
        {
            return RpcError(id, 400, -32700, "The body is not JSON.");
        }
    }

    internal static async Task<IResult> DeleteTokenAsync(Guid id, McpDbContext db, IHostAuditLog audit, CancellationToken ct)
    {
        var row = await db.BotTokens.FirstOrDefaultAsync(t => t.Id == id, ct);
        if (row is null)
        {
            return Error(404, "not_found", "Token not found.");
        }

        var name = row.Name;
        var prefix = row.Prefix;
        db.BotTokens.Remove(row);
        await db.SaveChangesAsync(ct);
        await audit.RecordAsync("mcp.bot_token.deleted", id.ToString(), name + " " + prefix, cancellationToken: ct);
        return Results.NoContent();
    }

    private static async Task<IResult> ListTokensAsync(McpDbContext db, CancellationToken ct) =>
        Results.Json(await db.BotTokens.AsNoTracking().OrderByDescending(t => t.CreatedAt).Select(t => new { t.Id, t.Name, t.Prefix, t.CreatedAt, t.ExpiresAt, t.LastUsedAt, revoked = t.RevokedAt != null }).ToListAsync(ct), Json);

    private static async Task<IResult> CreateTokenAsync(TokenName body, McpDbContext db, IHostAuditLog audit, TimeProvider time, CancellationToken ct)
    {
        var name = body.Name?.Trim() ?? string.Empty;
        if (name.Length is < 1 or > 80)
        {
            return Error(400, "validation", "Name must be 1 to 80 characters.");
        }

        if (await db.BotTokens.CountAsync(t => t.RevokedAt == null, ct) >= McpTokens.ActiveLimit)
        {
            return Error(400, "validation", "Delete an existing token before creating another. Ten active tokens is the limit.");
        }

        var secret = McpTokens.CreateSecret();
        var created = time.GetUtcNow();
        var row = new BotToken { Id = Guid.NewGuid(), Name = name, Prefix = secret[..12], TokenHash = McpTokens.Hash(secret), CreatedAt = created, ExpiresAt = created + McpTokens.Lifetime };
        db.BotTokens.Add(row);
        await db.SaveChangesAsync(ct);
        await audit.RecordAsync("mcp.bot_token.created", row.Id.ToString(), name, cancellationToken: ct);
        return Results.Json(new { row.Id, row.Name, row.Prefix, token = secret }, Json);
    }

    private static IResult Error(int status, string code, string message) => Results.Json(new { error = code, message }, Json, statusCode: status);

    private sealed record TokenName(string? Name);

    private sealed record RegisteredTool(IMcpToolSource Source, string Name, string ExposedName, string Description, string InputSchemaJson);

    private static List<RegisteredTool> Register(IEnumerable<IMcpToolSource> sources)
    {
        var used = new HashSet<string>(StringComparer.Ordinal);
        var list = new List<RegisteredTool>();
        foreach (var source in sources)
        {
            foreach (var tool in source.Tools)
            {
                if (string.IsNullOrWhiteSpace(tool.Name) || tool.Name.Length > 80 || tool.Name.Contains('.', StringComparison.Ordinal))
                {
                    continue;
                }

                var exposed = tool.Name;
                if (!used.Add(exposed))
                {
                    exposed = source.PluginId + "." + tool.Name;
                    if (!used.Add(exposed))
                    {
                        continue;
                    }
                }

                list.Add(new RegisteredTool(source, tool.Name, exposed, tool.Description, tool.InputSchemaJson));
            }
        }

        return list;
    }

    private static JsonObject Initialize(JsonElement parameters, List<RegisteredTool> tools, IEnumerable<IMcpToolSource> sources)
    {
        var requested = parameters.ValueKind == JsonValueKind.Object && parameters.TryGetProperty("protocolVersion", out var version) && version.ValueKind == JsonValueKind.String
            ? version.GetString()
            : null;
        var protocol = requested is "2025-03-26" or "2025-06-18" ? requested : "2025-03-26";
        return new JsonObject
        {
            ["protocolVersion"] = protocol,
            ["capabilities"] = new JsonObject { ["tools"] = new JsonObject() },
            ["serverInfo"] = new JsonObject { ["name"] = "vulpes", ["version"] = ServerVersion() },
            ["instructions"] = Instructions(sources, tools),
        };
    }

    private static string Instructions(IEnumerable<IMcpToolSource> sources, List<RegisteredTool> tools)
    {
        var builder = new StringBuilder("Tools on this server come from installed Vulpes plugins. A token can call every listed tool.");
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var source in tools.Select(t => t.Source))
        {
            if (!seen.Add(source.PluginId) || string.IsNullOrWhiteSpace(source.Instructions))
            {
                continue;
            }

            builder.Append("\n\n").Append(source.Instructions.Trim());
        }

        foreach (var source in sources)
        {
            if (!seen.Add(source.PluginId) || string.IsNullOrWhiteSpace(source.Instructions))
            {
                continue;
            }

            builder.Append("\n\n").Append(source.Instructions.Trim());
        }

        return builder.ToString();
    }

    private static JsonArray ListTools(List<RegisteredTool> tools)
    {
        var array = new JsonArray();
        foreach (var tool in tools)
        {
            JsonNode? schema;
            try
            {
                schema = JsonNode.Parse(tool.InputSchemaJson);
            }
            catch (JsonException)
            {
                schema = new JsonObject { ["type"] = "object" };
            }

            if (schema is not JsonObject)
            {
                schema = new JsonObject { ["type"] = "object" };
            }

            array.Add(new JsonObject
            {
                ["name"] = tool.ExposedName,
                ["description"] = tool.Description,
                ["inputSchema"] = schema,
            });
        }

        return array;
    }

    private static async Task<JsonNode> CallToolAsync(JsonElement parameters, List<RegisteredTool> tools, McpCaller caller, CancellationToken ct)
    {
        var exposed = ToolName(parameters);
        var tool = tools.FirstOrDefault(t => t.ExposedName == exposed);
        if (tool is null)
        {
            return ToolError(string.IsNullOrEmpty(exposed) ? "tools/call needs a tool name." : $"Unknown tool '{exposed}'.");
        }

        var args = parameters.ValueKind == JsonValueKind.Object && parameters.TryGetProperty("arguments", out var argsEl) && argsEl.ValueKind == JsonValueKind.Object
            ? argsEl
            : default;
        var result = await tool.Source.CallAsync(tool.Name, args, caller, ct);
        if (result.IsError)
        {
            return ToolError(result.Text);
        }

        JsonNode? structured = null;
        if (!string.IsNullOrWhiteSpace(result.StructuredJson))
        {
            try
            {
                structured = JsonNode.Parse(result.StructuredJson);
            }
            catch (JsonException)
            {
                structured = null;
            }
        }

        var content = new JsonArray(new JsonObject { ["type"] = "text", ["text"] = result.Text });
        if (result.FileBytes is { Length: > 0 } && !string.IsNullOrWhiteSpace(result.FileName))
        {
            var fileName = result.FileName.Trim();
            content.Add(new JsonObject
            {
                ["type"] = "resource",
                ["resource"] = new JsonObject
                {
                    ["uri"] = "file:///" + Uri.EscapeDataString(fileName),
                    ["name"] = fileName,
                    ["mimeType"] = string.IsNullOrWhiteSpace(result.MediaType) ? "application/octet-stream" : result.MediaType,
                    ["blob"] = Convert.ToBase64String(result.FileBytes),
                },
            });
        }

        var body = new JsonObject
        {
            ["content"] = content,
        };
        if (structured is JsonObject)
        {
            body["structuredContent"] = structured;
        }

        return body;
    }

    private static string ToolName(JsonElement parameters) =>
        parameters.ValueKind == JsonValueKind.Object && parameters.TryGetProperty("name", out var called) && called.ValueKind == JsonValueKind.String
            ? called.GetString() ?? string.Empty
            : string.Empty;

    private static string CallDetail(List<RegisteredTool> tools, string exposed, JsonElement parameters)
    {
        var tool = tools.FirstOrDefault(t => t.ExposedName == exposed);
        var plugin = tool?.Source.PluginId ?? "-";
        var args = parameters.ValueKind == JsonValueKind.Object && parameters.TryGetProperty("arguments", out var argsEl) && argsEl.ValueKind == JsonValueKind.Object
            ? argsEl
            : default;
        var source = Arg(args, "source");
        var tenant = Arg(args, "tenantId");
        var detail = string.Create(CultureInfo.InvariantCulture, $"plugin={plugin} source={source ?? "-"} tenant={tenant ?? "-"}");
        return detail.Length <= 200 ? detail : detail[..200];
    }

    private static string? Arg(JsonElement args, string name) =>
        args.ValueKind == JsonValueKind.Object && args.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String ? value.GetString() : null;

    private static string ServerVersion()
    {
        var version = typeof(McpEndpoints).Assembly.GetName().Version;
        return version is null ? "0" : string.Create(CultureInfo.InvariantCulture, $"{version.Major}.{version.Minor}.{version.Build}");
    }

    private static bool AllowCall(Guid id, DateTimeOffset now)
    {
        var tick = now.UtcTicks;
        var window = TimeSpan.FromMinutes(1).Ticks;
        lock (RateGate)
        {
            if (!RecentCalls.TryGetValue(id, out var queue))
            {
                RecentCalls[id] = queue = new Queue<long>();
            }

            while (queue.Count > 0 && tick - queue.Peek() > window)
            {
                queue.Dequeue();
            }

            if (queue.Count >= CallsPerMinute)
            {
                return false;
            }

            queue.Enqueue(tick);
            return true;
        }
    }

    private static bool TryBearer(HttpContext http, out string token)
    {
        token = string.Empty;
        var header = http.Request.Headers.Authorization.ToString();
        if (!header.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        token = header["Bearer ".Length..].Trim();
        return token.Length is > 0 and <= 200;
    }

    private static JsonObject ToolError(string message) => new()
    {
        ["isError"] = true,
        ["content"] = new JsonArray(new JsonObject { ["type"] = "text", ["text"] = message }),
    };

    private static string Envelope(JsonNode? id, JsonNode result) =>
        new JsonObject { ["jsonrpc"] = "2.0", ["id"] = id, ["result"] = result }.ToJsonString(Json);
    private static IResult RpcError(JsonNode? id, int status, int code, string message)
    {
        var body = new JsonObject { ["jsonrpc"] = "2.0", ["id"] = id, ["error"] = new JsonObject { ["code"] = code, ["message"] = message } };
        return Results.Text(body.ToJsonString(Json), "application/json", statusCode: status);
    }
}
