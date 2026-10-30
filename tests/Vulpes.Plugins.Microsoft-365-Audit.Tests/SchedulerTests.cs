using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Time.Testing;
using Vulpes.Plugins.Microsoft365Audit.Collectors;
using Vulpes.Plugins.Microsoft365Audit.Data;
using Vulpes.Plugins.Microsoft365Audit.Graph;
using Vulpes.Plugins.Microsoft365Audit.Scheduling;
using Vulpes.Plugins.Microsoft365Audit.Tenants;
using Vulpes.Sdk;
using Xunit;

namespace Vulpes.Plugins.Microsoft365Audit.Tests;

public sealed class SchedulerTests : IDisposable
{
    private readonly SqliteConnection _connection = new("Data Source=:memory:");
    private readonly ServiceProvider _provider;
    private readonly FakeTimeProvider _time = new(new DateTimeOffset(2026, 10, 30, 12, 0, 0, TimeSpan.Zero));
    private readonly FakePipeline _pipeline = new();
    private readonly ScriptedCollector _collector = new();

    public SchedulerTests()
    {
        _connection.Open();
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddDbContext<AuditDbContext>(o => o.UseSqlite(_connection));
        _provider = services.BuildServiceProvider();
        using (var scope = _provider.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<AuditDbContext>();
            db.Database.EnsureCreated();
            db.Tenants.Add(new Tenant { Id = TestContext.Tenant.Id, DisplayName = "Contoso", TenantId = TestContext.Tenant.TenantId, ClientId = TestContext.Tenant.ClientId, ProtectedSecret = new FakeProtector().Protect("s") });
            db.SaveChanges();
        }
    }

    private CollectionScheduler CreateScheduler(AuditOptions? options = null) => new(
        _provider.GetRequiredService<IServiceScopeFactory>(),
        [_collector],
        new GraphClientFactory(new NoHttp(), new GraphCredentialFactory(new FakeProtector()), NullLoggerFactory.Instance, _time),
        _pipeline,
        options ?? new AuditOptions(),
        _time,
        NullLogger<CollectionScheduler>.Instance);

    private Tenant Tenant()
    {
        using var scope = _provider.CreateScope();
        return scope.ServiceProvider.GetRequiredService<AuditDbContext>().Tenants.AsNoTracking().Single();
    }

    private Checkpoint Checkpoint()
    {
        using var scope = _provider.CreateScope();
        return scope.ServiceProvider.GetRequiredService<AuditDbContext>().Checkpoints.AsNoTracking().Single();
    }

    [Fact]
    public async Task Successful_run_updates_checkpoint_schedules_next_run_and_logs()
    {
        _collector.Behaviour = ctx => { ctx.Checkpoint.Watermark = _time.GetUtcNow(); return new CollectorResult(5, 1, 0, 2, true); };
        var scheduler = CreateScheduler(new AuditOptions { IntervalMinutes = { ["scripted"] = 10 } });

        var entry = await scheduler.RunJobAsync(Tenant(), "scripted", CancellationToken.None);

        Assert.Equal(RunStatuses.Succeeded, entry.Status);
        Assert.Equal(5, entry.Count);
        Assert.Equal(1, entry.Duplicates);
        Assert.Equal(2, entry.Alerts);
        var checkpoint = Checkpoint();
        Assert.Equal(RunStatuses.Succeeded, checkpoint.LastStatus);
        Assert.Equal(5, checkpoint.LastCount);
        Assert.Equal(5, checkpoint.TotalCount);
        Assert.Equal(_time.GetUtcNow(), checkpoint.Watermark);
        Assert.InRange(checkpoint.NextRunAt!.Value, _time.GetUtcNow().AddMinutes(9), _time.GetUtcNow().AddMinutes(11));
        Assert.Equal(0, checkpoint.ConsecutiveFailures);
        Assert.False(scheduler.IsRunning(TestContext.Tenant.Id, "scripted"));
    }

    [Fact]
    public async Task Partial_runs_resume_quickly_and_tenant_interval_overrides_apply()
    {
        _collector.Behaviour = _ => new CollectorResult(1, 0, 0, 0, false, "partial");
        var scheduler = CreateScheduler();
        var entry = await scheduler.RunJobAsync(Tenant(), "scripted", CancellationToken.None);
        Assert.Equal(RunStatuses.Succeeded, entry.Status);
        var checkpoint = Checkpoint();
        Assert.Equal(RunStatuses.Pending, checkpoint.LastStatus);
        Assert.Equal("partial", checkpoint.LastError);
        Assert.Equal(_time.GetUtcNow().AddSeconds(5), checkpoint.NextRunAt);

        _collector.Behaviour = _ => new CollectorResult(0, 0, 0, 0, true);
        var tenant = Tenant();
        tenant.SettingsJson = new TenantSettings { Sources = { ["scripted"] = new SourceSettings { IntervalMinutes = 60 } } }.Serialize();
        await scheduler.RunJobAsync(tenant, "scripted", CancellationToken.None);
        Assert.InRange(Checkpoint().NextRunAt!.Value, _time.GetUtcNow().AddMinutes(54), _time.GetUtcNow().AddMinutes(66));
    }

    [Fact]
    public async Task Failures_back_off_record_the_error_and_publish_a_system_event()
    {
        _collector.Behaviour = _ => throw new GraphException("Graph auditLogs/signIns returned 403 Forbidden");
        var scheduler = CreateScheduler(new AuditOptions { IntervalMinutes = { ["scripted"] = 5 } });

        var entry = await scheduler.RunJobAsync(Tenant(), "scripted", CancellationToken.None);
        Assert.Equal(RunStatuses.Failed, entry.Status);
        Assert.Contains("403", entry.Error, StringComparison.Ordinal);

        var checkpoint = Checkpoint();
        Assert.Equal(RunStatuses.Failed, checkpoint.LastStatus);
        Assert.Equal(1, checkpoint.ConsecutiveFailures);
        Assert.True(checkpoint.NextRunAt >= _time.GetUtcNow().AddMinutes(5));

        var systemEvent = Assert.Single(_pipeline.Events);
        Assert.Equal("system", systemEvent.Source);
        Assert.Equal("audit.collector.failed", systemEvent.Action);
        Assert.Equal("scripted", systemEvent.Labels!["collector"]);
        Assert.Contains("403", systemEvent.Message, StringComparison.Ordinal);

        // Repeated failures back off further (capped at 4x the interval).
        await scheduler.RunJobAsync(Tenant(), "scripted", CancellationToken.None);
        await scheduler.RunJobAsync(Tenant(), "scripted", CancellationToken.None);
        var later = Checkpoint();
        Assert.Equal(3, later.ConsecutiveFailures);
        Assert.True(later.NextRunAt >= _time.GetUtcNow().AddMinutes(8));
        Assert.True(later.NextRunAt <= _time.GetUtcNow().AddMinutes(20));

        // Recovery resets the failure counter.
        _collector.Behaviour = _ => new CollectorResult(0, 0, 0, 0, true);
        await scheduler.RunJobAsync(Tenant(), "scripted", CancellationToken.None);
        Assert.Equal(0, Checkpoint().ConsecutiveFailures);

        using var scope = _provider.CreateScope();
        Assert.Equal(4, await scope.ServiceProvider.GetRequiredService<AuditDbContext>().RunLog.CountAsync());
    }

    [Fact]
    public async Task Collector_context_exposes_window_start_deadline_and_state_helpers()
    {
        var checkpoint = new Checkpoint { TenantId = TestContext.Tenant.Id, Source = "x" };
        var context = TestContext.Context(TestContext.Client(new RoutedGraphHandler()), _pipeline, checkpoint, time: _time);
        Assert.Equal(_time.GetUtcNow().AddDays(-7), context.WindowStart(TimeSpan.FromMinutes(30)));
        checkpoint.Watermark = _time.GetUtcNow().AddHours(-1);
        Assert.Equal(_time.GetUtcNow().AddMinutes(-90), context.WindowStart(TimeSpan.FromMinutes(30)));
        Assert.False(context.OutOfTime);
        _time.Advance(TimeSpan.FromMinutes(21));
        Assert.True(context.OutOfTime);

        Assert.Empty(context.State);
        context.SaveState(new Dictionary<string, object?> { ["a"] = "b" });
        Assert.Equal("b", context.State["a"].GetString());
        context.SaveState([]);
        Assert.Null(checkpoint.StateJson);

        var (indexed, _, _, _) = await context.PublishAsync([], CancellationToken.None);
        Assert.Equal(0, indexed);
    }

    public void Dispose()
    {
        _provider.Dispose();
        _connection.Dispose();
    }

    private sealed class ScriptedCollector : ICollector
    {
        public Func<CollectorContext, CollectorResult> Behaviour { get; set; } = _ => CollectorResult.Empty();
        public string Source => "scripted";
        public string Title => "Scripted";
        public IReadOnlyList<string> RequiredPermissions => [];
        public string ProbePath => string.Empty;
        public Task<CollectorResult> CollectAsync(CollectorContext context, CancellationToken cancellationToken) => Task.FromResult(Behaviour(context));
    }

    private sealed class NoHttp : IHttpClientFactory
    {
        public HttpClient CreateClient(string name) => new(new RoutedGraphHandler());
    }
}
