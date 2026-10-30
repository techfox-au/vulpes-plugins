using Microsoft.EntityFrameworkCore;
using Vulpes.Plugins.Microsoft365Audit.Collectors;
using Vulpes.Plugins.Microsoft365Audit.Data;
using Vulpes.Plugins.Microsoft365Audit.Graph;
using Vulpes.Plugins.Microsoft365Audit.Normalization;
using Vulpes.Plugins.Microsoft365Audit.Tenants;
using Vulpes.Sdk;

namespace Vulpes.Plugins.Microsoft365Audit.Scheduling;

/// <summary>Runs collectors per tenant and source on their intervals with a concurrency cap, jitter and failure backoff.</summary>
public sealed class CollectionScheduler(
    IServiceScopeFactory scopeFactory,
    IEnumerable<ICollector> collectors,
    GraphClientFactory graphFactory,
    IEventPipeline pipeline,
    AuditOptions options,
    TimeProvider timeProvider,
    ILogger<CollectionScheduler> logger) : BackgroundService
{
    private readonly Dictionary<string, ICollector> _collectors = collectors.ToDictionary(c => c.Source, StringComparer.Ordinal);
    private readonly SemaphoreSlim _concurrency = new(Math.Clamp(options.MaxConcurrentJobs, 1, 32));
    private readonly HashSet<(Guid, string)> _running = [];
    private readonly Lock _lock = new();
    private readonly SemaphoreSlim _wake = new(0, int.MaxValue);

    public IReadOnlyDictionary<string, ICollector> Collectors => _collectors;

    /// <summary>Asks the loop to look for due jobs immediately (after "run now").</summary>
    public void Wake() => _wake.Release();

    public bool IsRunning(Guid tenantId, string source)
    {
        lock (_lock)
        {
            return _running.Contains((tenantId, source));
        }
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        logger.LogInformation("Audit collection scheduler started with {Count} collectors", _collectors.Count);
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await DispatchDueJobsAsync(stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                return;
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Scheduler loop failed");
            }

            try
            {
                await _wake.WaitAsync(TimeSpan.FromSeconds(Math.Clamp(options.SchedulerIntervalSeconds, 5, 600)), stoppingToken);
            }
            catch (OperationCanceledException)
            {
                return;
            }
        }
    }

    private async Task DispatchDueJobsAsync(CancellationToken stoppingToken)
    {
        var now = timeProvider.GetUtcNow();
        List<(Tenant Tenant, string Source)> due;
        await using (var scope = scopeFactory.CreateAsyncScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<AuditDbContext>();
            var directory = scope.ServiceProvider.GetService<ITenantDirectory>();
            var application = scope.ServiceProvider.GetService<IEntraApplication>();
            if (directory is not null)
            {
                var shared = application is null ? null : await application.GetAsync(stoppingToken);
                var remote = await directory.ListAsync(stoppingToken);
                // An empty host with no application means tenants still live only in the plugin database.
                if (remote.Count > 0 || shared is not null)
                {
                    await scope.ServiceProvider.GetRequiredService<TenantService>().SyncFromDirectoryAsync(remote, shared, stoppingToken);
                }
            }

            var tenants = await db.Tenants.AsNoTracking().Where(t => t.Enabled).ToListAsync(stoppingToken);
            var checkpoints = await db.Checkpoints.AsNoTracking().ToListAsync(stoppingToken);
            var lookup = checkpoints.ToDictionary(c => (c.TenantId, c.Source));
            due = [];
            foreach (var tenant in tenants)
            {
                var settings = TenantSettings.Parse(tenant.SettingsJson);
                foreach (var source in _collectors.Keys)
                {
                    if (!options.Collects(source) || !settings.For(source).Enabled)
                    {
                        continue;
                    }

                    if (lookup.TryGetValue((tenant.Id, source), out var checkpoint) && checkpoint.NextRunAt is { } next && next > now)
                    {
                        continue;
                    }

                    due.Add((tenant, source));
                }
            }
        }

        foreach (var (tenant, source) in due)
        {
            lock (_lock)
            {
                if (!_running.Add((tenant.Id, source)))
                {
                    continue;
                }
            }

            _ = Task.Run(() => RunJobAsync(tenant, source, stoppingToken), stoppingToken);
        }
    }

    /// <summary>Runs one collector for one tenant now (used by the scheduler and by "run now").</summary>
    public async Task<RunLogEntry> RunJobAsync(Tenant tenant, string source, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(tenant);
        var collector = _collectors[source];
        var startedAt = timeProvider.GetUtcNow();
        var entry = new RunLogEntry { TenantId = tenant.Id, Source = source, StartedAt = startedAt };
        await _concurrency.WaitAsync(cancellationToken);
        try
        {
            lock (_lock)
            {
                _running.Add((tenant.Id, source));
            }

            await using var scope = scopeFactory.CreateAsyncScope();
            var db = scope.ServiceProvider.GetRequiredService<AuditDbContext>();
            var checkpoint = await db.Checkpoints.FirstOrDefaultAsync(c => c.TenantId == tenant.Id && c.Source == source, cancellationToken);
            if (checkpoint is null)
            {
                checkpoint = new Checkpoint { TenantId = tenant.Id, Source = source };
                db.Checkpoints.Add(checkpoint);
            }

            checkpoint.LastStatus = RunStatuses.Running;
            checkpoint.LastRunAt = startedAt;
            await db.SaveChangesAsync(cancellationToken);

            var settings = TenantSettings.Parse(tenant.SettingsJson).For(source);
            var interval = settings.IntervalMinutes is { } custom ? TimeSpan.FromMinutes(Math.Clamp(custom, 1, 24 * 60 * 7)) : options.IntervalFor(source);
            try
            {
                var context = new CollectorContext
                {
                    Tenant = tenant,
                    Settings = settings,
                    Graph = graphFactory.Create(tenant),
                    Checkpoint = checkpoint,
                    Pipeline = pipeline,
                    Options = options,
                    Time = timeProvider,
                    Logger = logger,
                    Deadline = startedAt.AddMinutes(Math.Clamp(options.RunTimeBudgetMinutes, 1, 180)),
                };
                var result = await collector.CollectAsync(context, cancellationToken);
                var finished = timeProvider.GetUtcNow();
                checkpoint.LastStatus = result.Complete ? RunStatuses.Succeeded : RunStatuses.Pending;
                checkpoint.LastSuccessAt = finished;
                checkpoint.LastError = result.Note;
                checkpoint.LastCount = result.Published;
                checkpoint.TotalCount += result.Published;
                checkpoint.ConsecutiveFailures = 0;
                checkpoint.NextRunAt = result.Complete ? finished + Jitter(interval) : finished.AddSeconds(5);
                entry.Status = RunStatuses.Succeeded;
                entry.Count = result.Published;
                entry.Duplicates = result.Duplicates;
                entry.Failed = result.Failed;
                entry.Alerts = result.Alerts;
                entry.Error = result.Note;
                logger.LogInformation("{Source} for {Tenant}: {Count} new, {Duplicates} duplicates, {Failed} failed, {Alerts} alerts in {Seconds:F1}s{Note}", source, tenant.DisplayName, result.Published, result.Duplicates, result.Failed, result.Alerts, (finished - startedAt).TotalSeconds, result.Note is null ? string.Empty : " (" + result.Note + ")");
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                var finished = timeProvider.GetUtcNow();
                checkpoint.LastStatus = RunStatuses.Failed;
                checkpoint.LastError = ex.Message.Length <= 2000 ? ex.Message : ex.Message[..2000];
                checkpoint.ConsecutiveFailures++;
                var backoff = TimeSpan.FromMinutes(Math.Min(Math.Pow(2, checkpoint.ConsecutiveFailures), interval.TotalMinutes * 4));
                checkpoint.NextRunAt = finished + (backoff > interval ? backoff : interval);
                entry.Status = RunStatuses.Failed;
                entry.Error = checkpoint.LastError;
                logger.LogError(ex, "{Source} for {Tenant} failed (failure #{Failures}); next attempt at {Next}", source, tenant.DisplayName, checkpoint.ConsecutiveFailures, checkpoint.NextRunAt);
                try
                {
                    await pipeline.PublishAsync([Normalizers.CollectorFailure(tenant.TenantId, tenant.DiscoveredName ?? tenant.DisplayName, source, ex.Message, finished)], cancellationToken);
                }
                catch (Exception publishEx) when (publishEx is not OperationCanceledException)
                {
                    logger.LogWarning(publishEx, "Could not publish collector failure event");
                }
            }

            entry.FinishedAt = timeProvider.GetUtcNow();
            db.RunLog.Add(entry);
            await db.SaveChangesAsync(cancellationToken);
            await PruneRunLogAsync(db, cancellationToken);
            return entry;
        }
        finally
        {
            lock (_lock)
            {
                _running.Remove((tenant.Id, source));
            }

            _concurrency.Release();
        }
    }

    private static TimeSpan Jitter(TimeSpan interval)
    {
        var factor = 0.9 + Random.Shared.NextDouble() * 0.2;
        return TimeSpan.FromTicks((long)(interval.Ticks * factor));
    }

    private static async Task PruneRunLogAsync(AuditDbContext db, CancellationToken cancellationToken)
    {
        var count = await db.RunLog.CountAsync(cancellationToken);
        if (count > 2000)
        {
            var cutoff = await db.RunLog.OrderByDescending(r => r.Id).Skip(1500).Select(r => r.Id).FirstOrDefaultAsync(cancellationToken);
            await db.RunLog.Where(r => r.Id <= cutoff).ExecuteDeleteAsync(cancellationToken);
        }
    }

    public override void Dispose()
    {
        _concurrency.Dispose();
        _wake.Dispose();
        base.Dispose();
    }
}
