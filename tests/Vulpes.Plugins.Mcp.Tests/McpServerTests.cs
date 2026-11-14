using System.Net;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Vulpes.Plugins.Mcp.Data;
using Vulpes.Plugins.Mcp.Endpoints;
using Vulpes.Sdk;
using Xunit;

namespace Vulpes.Plugins.Mcp.Tests;

public sealed class McpServerTests
{
    [Fact]
    public async Task A_token_is_stored_as_a_hash_and_delete_removes_it()
    {
        await using var db = await NewDbAsync();
        var secret = McpTokens.CreateSecret();
        Assert.StartsWith("vba_", secret, StringComparison.Ordinal);
        Assert.NotEqual(secret, McpTokens.Hash(secret));
        var id = Guid.NewGuid();
        db.BotTokens.Add(new BotToken
        {
            Id = id,
            Name = "Grok Bot",
            Prefix = secret[..12],
            TokenHash = McpTokens.Hash(secret),
            CreatedAt = DateTimeOffset.UtcNow,
            ExpiresAt = DateTimeOffset.UtcNow.AddDays(90),
        });
        await db.SaveChangesAsync();
        var found = await db.BotTokens.SingleAsync(t => t.TokenHash == McpTokens.Hash(secret));
        Assert.Equal("Grok Bot", found.Name);

        var audit = new MemoryAudit();
        var missing = await McpEndpoints.DeleteTokenAsync(Guid.NewGuid(), db, audit, CancellationToken.None);
        Assert.Equal(404, Status(missing));
        var deleted = await McpEndpoints.DeleteTokenAsync(id, db, audit, CancellationToken.None);
        Assert.Equal(204, Status(deleted));
        Assert.Empty(await db.BotTokens.ToListAsync());
        Assert.Equal("mcp.bot_token.deleted", audit.Entries[0].Action);
        Assert.Contains(secret[..12], audit.Entries[0].Details, StringComparison.Ordinal);
    }

    [Fact]
    public async Task The_default_recipients_are_mailed_ten_days_before_a_token_expires()
    {
        await using var db = await NewDbAsync();
        var now = new DateTimeOffset(2026, 11, 14, 0, 0, 0, TimeSpan.Zero);
        var soon = new BotToken { Id = Guid.NewGuid(), Name = "Soon", Prefix = "vba_soon1234", TokenHash = new string('a', 64), CreatedAt = now.AddDays(-80), ExpiresAt = now.AddDays(9) };
        var later = new BotToken { Id = Guid.NewGuid(), Name = "Later", Prefix = "vba_later123", TokenHash = new string('b', 64), CreatedAt = now, ExpiresAt = now.AddDays(40) };
        var gone = new BotToken { Id = Guid.NewGuid(), Name = "Gone", Prefix = "vba_gone1234", TokenHash = new string('c', 64), CreatedAt = now.AddDays(-100), ExpiresAt = now.AddDays(-1) };
        db.BotTokens.AddRange(soon, later, gone);
        await db.SaveChangesAsync();
        var mail = new RecordingEmail("https://dash.example");
        var audit = new MemoryAudit();
        var clock = new FixedTime(now);
        var sent = await TokenExpiryMail.SendDueAsync(db, mail, new FixedRecipients("ops@example.test"), audit, clock, CancellationToken.None);
        Assert.Equal(1, sent);
        Assert.Contains("Soon", mail.Bodies[0], StringComparison.Ordinal);
        Assert.Contains("vba_soon1234", mail.Bodies[0], StringComparison.Ordinal);
        Assert.DoesNotContain("vba_", mail.Bodies[0].Replace("vba_soon1234", "", StringComparison.Ordinal), StringComparison.Ordinal);
        Assert.Equal("ops@example.test", mail.Recipients.Single());
        Assert.NotNull(soon.ExpiryNoticeSentAt);
        Assert.Null(later.ExpiryNoticeSentAt);
        Assert.Null(gone.ExpiryNoticeSentAt);

        mail.Bodies.Clear();
        var again = await TokenExpiryMail.SendDueAsync(db, mail, new FixedRecipients("ops@example.test"), audit, clock, CancellationToken.None);
        Assert.Equal(0, again);
        Assert.Empty(mail.Bodies);
    }

    [Fact]
    public async Task The_plugin_root_is_the_mcp_endpoint_and_plugins_add_tools()
    {
        var path = TempDb();
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        builder.Services.AddAuthorization();
        builder.Services.AddDbContext<McpDbContext>(o => o.UseSqlite($"Data Source={path}"));
        builder.Services.AddSingleton(TimeProvider.System);
        builder.Services.AddSingleton<IHostAuditLog, MemoryAudit>();
        builder.Services.AddSingleton<IMcpToolSource>(new Fake("microsoft-365-audit", "Audit instructions", new McpTool("search_events", "Search", """{"type":"object"}""")));
        builder.Services.AddSingleton<IMcpToolSource>(new Fake("invoices", "Invoice instructions", new McpTool("search_events", "Other search", """{"type":"object"}"""), new McpTool("list_invoices", "List", """{"type":"object"}""")));
        var app = builder.Build();
        await using (var scope = app.Services.CreateAsyncScope())
        {
            await scope.ServiceProvider.GetRequiredService<McpDbContext>().Database.MigrateAsync();
        }

        McpEndpoints.Map(app.MapGroup("/api/plugins/mcp"));
        await app.StartAsync();
        try
        {
            var client = app.GetTestClient();
            var get = await client.GetAsync(new Uri("/api/plugins/mcp", UriKind.Relative));
            Assert.Equal(HttpStatusCode.MethodNotAllowed, get.StatusCode);
            Assert.Equal("POST", get.Content.Headers.Allow.Single());

            var secret = McpTokens.CreateSecret();
            await using (var scope = app.Services.CreateAsyncScope())
            {
                var db = scope.ServiceProvider.GetRequiredService<McpDbContext>();
                db.BotTokens.Add(new BotToken
                {
                    Id = Guid.NewGuid(),
                    Name = "Grok Bot",
                    Prefix = secret[..12],
                    TokenHash = McpTokens.Hash(secret),
                    CreatedAt = DateTimeOffset.UtcNow,
                    ExpiresAt = DateTimeOffset.UtcNow.AddDays(90),
                });
                await db.SaveChangesAsync();
            }

            var listed = await PostAsync(client, secret, """{"jsonrpc":"2.0","id":1,"method":"tools/list"}""");
            Assert.Contains("search_events", listed, StringComparison.Ordinal);
            Assert.Contains("invoices.search_events", listed, StringComparison.Ordinal);
            Assert.Contains("list_invoices", listed, StringComparison.Ordinal);
            Assert.Contains("Audit instructions", await PostAsync(client, secret, """{"jsonrpc":"2.0","id":2,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}"""), StringComparison.Ordinal);

            var called = await PostAsync(client, secret, """{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"list_invoices","arguments":{}}}""");
            Assert.Contains("\"ok\":true", called, StringComparison.Ordinal);
            Assert.Contains("\"mimeType\":\"application/pdf\"", called, StringComparison.Ordinal);
            Assert.Contains(Convert.ToBase64String("%PDF"u8.ToArray()), called, StringComparison.Ordinal);
            var rejected = await client.PostAsync(new Uri("/api/plugins/mcp", UriKind.Relative), new StringContent("{}", Encoding.UTF8, "application/json"));
            Assert.Equal(HttpStatusCode.Unauthorized, rejected.StatusCode);
        }
        finally
        {
            await app.StopAsync();
            TryDelete(path);
        }
    }

    [Fact]
    public async Task Existing_audit_tokens_are_copied_once()
    {
        var root = Path.Combine(Path.GetTempPath(), "vulpes-mcp-" + Guid.NewGuid().ToString("N"));
        var auditDir = Path.Combine(root, "microsoft-365-audit");
        var mcpDir = Path.Combine(root, "mcp");
        Directory.CreateDirectory(auditDir);
        Directory.CreateDirectory(mcpDir);
        var auditDb = Path.Combine(auditDir, "microsoft-365-audit.db");
        var id = Guid.NewGuid();
        var created = DateTimeOffset.UtcNow;
        await using (var connection = new SqliteConnection($"Data Source={auditDb}"))
        {
            await connection.OpenAsync();
            await using var command = connection.CreateCommand();
            command.CommandText = """
                CREATE TABLE BotTokens (
                    Id TEXT NOT NULL PRIMARY KEY,
                    Name TEXT NOT NULL,
                    TokenHash TEXT NOT NULL,
                    Prefix TEXT NOT NULL,
                    CreatedAt INTEGER NOT NULL,
                    ExpiresAt INTEGER NULL,
                    LastUsedAt INTEGER NULL,
                    RevokedAt INTEGER NULL
                );
                INSERT INTO BotTokens (Id, Name, TokenHash, Prefix, CreatedAt, ExpiresAt)
                VALUES ($id, 'Grok Bot', 'abc', 'vba_01234567', $created, $expires);
                """;
            command.Parameters.AddWithValue("$id", id.ToString());
            command.Parameters.AddWithValue("$created", created.UtcTicks);
            command.Parameters.AddWithValue("$expires", created.AddDays(90).UtcTicks);
            await command.ExecuteNonQueryAsync();
        }

        var path = Path.Combine(mcpDir, "mcp.db");
        var options = new DbContextOptionsBuilder<McpDbContext>().UseSqlite($"Data Source={path}").Options;
        try
        {
            await using var db = new McpDbContext(options);
            await db.Database.MigrateAsync();
            Assert.Equal(1, await AuditTokenImport.CopyIfEmptyAsync(db, mcpDir, CancellationToken.None));
            var row = await db.BotTokens.SingleAsync();
            Assert.Equal(id, row.Id);
            Assert.Equal("abc", row.TokenHash);
            Assert.Equal("vba_01234567", row.Prefix);
            Assert.Equal(0, await AuditTokenImport.CopyIfEmptyAsync(db, mcpDir, CancellationToken.None));
        }
        finally
        {
            TryDelete(path);
            TryDelete(auditDb);
        }
    }

    private static async Task<string> PostAsync(HttpClient client, string secret, string body)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, new Uri("/api/plugins/mcp", UriKind.Relative));
        request.Headers.TryAddWithoutValidation("Authorization", "Bearer " + secret);
        request.Content = new StringContent(body, Encoding.UTF8, "application/json");
        var response = await client.SendAsync(request);
        var text = await response.Content.ReadAsStringAsync();
        Assert.True(response.IsSuccessStatusCode, text);
        using var document = JsonDocument.Parse(text);
        Assert.True(document.RootElement.TryGetProperty("result", out _));
        return text;
    }

    private static async Task<McpDbContext> NewDbAsync()
    {
        var options = new DbContextOptionsBuilder<McpDbContext>().UseSqlite($"Data Source={TempDb()}").Options;
        var db = new McpDbContext(options);
        await db.Database.MigrateAsync();
        return db;
    }

    private static string TempDb() => Path.Combine(Path.GetTempPath(), "vulpes-mcp-" + Guid.NewGuid().ToString("N") + ".db");

    private static int? Status(IResult result) => (result as IStatusCodeHttpResult)?.StatusCode;

    private static void TryDelete(string path)
    {
        try { File.Delete(path); } catch (IOException) { }
    }

    private sealed class Fake(string id, string instructions, params McpTool[] tools) : IMcpToolSource
    {
        public string PluginId => id;

        public string Instructions => instructions;

        public IReadOnlyList<McpTool> Tools => tools;

        public ValueTask<McpToolResult> CallAsync(string name, JsonElement arguments, CancellationToken cancellationToken) =>
            ValueTask.FromResult(name == "list_invoices"
                ? new McpToolResult("ok", """{"ok":true}""", FileName: "Invoice-1.pdf", MediaType: "application/pdf", FileBytes: "%PDF"u8.ToArray())
                : new McpToolResult("ok", """{"ok":true}"""));
    }

    private sealed class FixedTime(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }

    private sealed class FixedRecipients(params string[] addresses) : IDefaultMailRecipients
    {
        public Task<IReadOnlyList<string>> GetAsync(CancellationToken cancellationToken = default) => Task.FromResult<IReadOnlyList<string>>(addresses);
    }

    private sealed class RecordingEmail(string origin) : IHostEmail
    {
        public string PublicOrigin => origin;

        public List<string> Recipients { get; } = [];

        public List<string> Bodies { get; } = [];

        public Task<bool> TrySendAsync(string to, string subject, string text, string html, CancellationToken cancellationToken = default)
        {
            Recipients.Add(to);
            Bodies.Add(text);
            return Task.FromResult(true);
        }

        public Task<bool> TrySendAsync(string to, string subject, string text, string html, IReadOnlyList<HostEmailAttachment> attachments, CancellationToken cancellationToken = default) =>
            TrySendAsync(to, subject, text, html, cancellationToken);

        public Task<bool> TrySendAsync(string to, string subject, string text, string html, IReadOnlyList<HostEmailAttachment> attachments, string? fromName, string? fromAddress, CancellationToken cancellationToken = default) =>
            TrySendAsync(to, subject, text, html, cancellationToken);

        public Task<bool> TrySendAsync(string to, string subject, string text, string html, IReadOnlyList<HostEmailAttachment> attachments, string? fromName, string? fromAddress, IReadOnlyList<string>? cc, CancellationToken cancellationToken = default) =>
            TrySendAsync(to, subject, text, html, cancellationToken);
    }

    private sealed class MemoryAudit : IHostAuditLog
    {
        public List<(string Action, string? Target, string? Details)> Entries { get; } = [];

        public Task RecordAsync(string action, string? target, string? details, string? actor = null, CancellationToken cancellationToken = default)
        {
            Entries.Add((action, target, details));
            return Task.CompletedTask;
        }
    }
}
