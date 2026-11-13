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
    IEventStoreReadiness store,
    AuditOptions options,
    TimeProvider timeProvider,
    ILogger<CollectionScheduler> logger) : BackgroundService
{
    private readonly Dictionary<string, ICollector> _collectors = collectors.ToDictionary(c => c.Source, StringComparer.Ordinal);
    private readonly SemaphoreSlim _concurrency = new(Math.Clamp(options.MaxConcurrentJobs, 1, 32));
    private readonly HashSet<(Guid, string)> _running = [];
    private readonly HashSet<Guid> _purging = [];
    private readonly Dictionary<Guid, (DateTimeOffset Until, string Reason)> _credentialBlock = [];
    private readonly Lock _lock = new();
    private bool _secureScoreOnStartup;

    public IReadOnlyDictionary<string, ICollector> Collectors => _collectors;

    public bool IsRunning(Guid tenantId, string source)
    {
        lock (_lock)
        {
            return _running.Contains((tenantId, source));
        }
    }

    /// <summary>Stops this client from starting collectors until <see cref="EndPurge"/> . Fails when one is already running.</summary>
    public bool TryBeginPurge(Guid tenantId)
    {
        lock (_lock)
        {
            if (_purging.Contains(tenantId))
            {
                return false;
            }

            foreach (var (runningTenant, _) in _running)
            {
                if (runningTenant == tenantId)
                {
                    return false;
                }
            }

            _purging.Add(tenantId);
            return true;
        }
    }

    public void EndPurge(Guid tenantId)
    {
        lock (_lock)
        {
            _purging.Remove(tenantId);
        }
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        logger.LogDebug("Audit collection scheduler started with {Count} collectors", _collectors.Count);
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
                await Task.Delay(TimeSpan.FromSeconds(Math.Clamp(options.SchedulerIntervalSeconds, 5, 600)), stoppingToken);
            }
            catch (OperationCanceledException)
            {
                return;
            }
        }
    }

    private async Task DispatchDueJobsAsync(CancellationToken stoppingToken)
    {
        foreach (var (tenant, source) in await DueJobsAsync(stoppingToken))
        {
            lock (_lock)
            {
                if (_purging.Contains(tenant.Id) || !_running.Add((tenant.Id, source)))
                {
                    continue;
                }
            }

            _ = Task.Run(() => RunJobAsync(tenant, source, stoppingToken), stoppingToken);
        }
    }

    /// <summary>
    /// Jobs whose interval has elapsed. Once per process, the first time Elasticsearch is ready, Secure Score is included even when its next run is still in the future.
    /// </summary>
    internal async Task<IReadOnlyList<(Tenant Tenant, string Source)>> DueJobsAsync(CancellationToken stoppingToken)
    {
        if (!store.IsReady)
        {
            logger.LogDebug("Elasticsearch is not ready; collection is waiting");
            return [];
        }

        var secureScoreNow = !_secureScoreOnStartup;
        _secureScoreOnStartup = true;
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
                lock (_lock)
                {
                    if (_purging.Contains(tenant.Id))
                    {
                        continue;
                    }
                }

                var settings = TenantSettings.Parse(tenant.SettingsJson);
                foreach (var source in _collectors.Keys)
                {
                    if (!options.Collects(source) || !settings.For(source).Enabled)
                    {
                        continue;
                    }

                    var intervalPending = lookup.TryGetValue((tenant.Id, source), out var checkpoint) && checkpoint.NextRunAt is { } next && next > now;
                    if (intervalPending && !(secureScoreNow && source == Sources.SecureScore))
                    {
                        continue;
                    }

                    due.Add((tenant, source));
                }
            }
        }

        if (secureScoreNow && due.Any(job => job.Source == Sources.SecureScore))
        {
            logger.LogInformation("Elasticsearch is ready; Secure Score will be collected once at startup");
        }

        return due;
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
                if (_purging.Contains(tenant.Id))
                {
                    return entry;
                }

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
            string? blocked = null;
            lock (_lock)
            {
                if (_credentialBlock.TryGetValue(tenant.Id, out var block) && block.Until > startedAt)
                {
                    blocked = block.Reason;
                }
            }

            if (blocked is not null)
            {
                checkpoint.LastStatus = RunStatuses.Failed;
                checkpoint.LastError = blocked;
                checkpoint.NextRunAt = startedAt.Add(TimeSpan.FromMinutes(15));
                entry.Status = RunStatuses.Failed;
                entry.Error = blocked;
                entry.FinishedAt = timeProvider.GetUtcNow();
                db.RunLog.Add(entry);
                await db.SaveChangesAsync(cancellationToken);
                return entry;
            }

            await db.SaveChangesAsync(cancellationToken);

            var settings = TenantSettings.Parse(tenant.SettingsJson).For(source);
            var interval = settings.IntervalMinutes is { } custom ? TimeSpan.FromMinutes(Math.Clamp(custom, 1, 24 * 60 * 7)) : options.IntervalFor(source);
            string? queryTracked = null;
            try
            {
                using var graph = graphFactory.Create(tenant);
                var context = new CollectorContext
                {
                    Tenant = tenant,
                    Settings = settings,
                    Graph = graph,
                    Checkpoint = checkpoint,
                    Pipeline = pipeline,
                    Options = options,
                    Time = timeProvider,
                    Logger = logger,
                    Deadline = startedAt.AddMinutes(Math.Clamp(options.RunTimeBudgetMinutes, 1, 180)),
                };
                var result = await collector.CollectAsync(context, cancellationToken);
                queryTracked = result.QueryId;
                var finished = timeProvider.GetUtcNow();
                var indexedCleanly = result.Failed == 0;
                checkpoint.LastStatus = result.Failed > 0
                    ? RunStatuses.Failed
                    : result.Complete ? RunStatuses.Succeeded : RunStatuses.Running;
                if (result.Complete && indexedCleanly)
                {
                    checkpoint.LastSuccessAt = finished;
                }

                checkpoint.LastError = result.Note;
                checkpoint.LastCount = result.Published;
                checkpoint.TotalCount += result.Published;
                checkpoint.ConsecutiveFailures = result.Failed > 0 ? checkpoint.ConsecutiveFailures + 1 : 0;
                TimeSpan wait;
                if (result.Failed > 0)
                {
                    var backoff = TimeSpan.FromMinutes(Math.Min(Math.Pow(2, checkpoint.ConsecutiveFailures), interval.TotalMinutes * 4));
                    wait = backoff > interval ? backoff : interval;
                }
                else if (!result.Complete)
                {
                    wait = TimeSpan.FromSeconds(5);
                }
                else
                {
                    wait = Jitter(interval);
                }

                checkpoint.NextRunAt = finished + wait;
                entry.Status = result.Failed > 0
                    ? RunStatuses.Failed
                    : result.Complete ? RunStatuses.Succeeded : RunStatuses.Running;
                entry.Count = result.Published;
                entry.Duplicates = result.Duplicates;
                entry.Failed = result.Failed;
                entry.Alerts = result.Alerts;
                entry.Error = result.Note;
                logger.LogDebug("{Source} for {Tenant}: {Count} new, {Duplicates} duplicates, {Failed} failed, {Alerts} alerts in {Seconds:F1}s{Note}", source, tenant.DisplayName, result.Published, result.Duplicates, result.Failed, result.Alerts, (finished - startedAt).TotalSeconds, result.Note is null ? string.Empty : " (" + result.Note + ")");
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                var finished = timeProvider.GetUtcNow();
                checkpoint.LastStatus = RunStatuses.Failed;
                var credential = CredentialFailure(ex);
                checkpoint.LastError = (credential ?? ex.Message).Length <= 2000 ? (credential ?? ex.Message) : (credential ?? ex.Message)[..2000];
                checkpoint.ConsecutiveFailures++;
                var backoff = TimeSpan.FromMinutes(Math.Min(Math.Pow(2, checkpoint.ConsecutiveFailures), interval.TotalMinutes * 4));
                checkpoint.NextRunAt = finished + (backoff > interval ? backoff : interval);
                entry.Status = RunStatuses.Failed;
                entry.Error = checkpoint.LastError;
                if (credential is not null)
                {
                    lock (_lock)
                    {
                        _credentialBlock[tenant.Id] = (checkpoint.NextRunAt.Value, credential);
                    }

                    logger.LogWarning("{Source} for {Tenant} cannot sign in: {Reason} Next attempt at {Next}", source, tenant.DisplayName, credential, checkpoint.NextRunAt);
                }
                else
                {
                    logger.LogError(ex, "{Source} for {Tenant} failed (failure #{Failures}); next attempt at {Next}", source, tenant.DisplayName, checkpoint.ConsecutiveFailures, checkpoint.NextRunAt);
                }
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
            var queryId = queryTracked ?? RunQueries.IdIn(entry.Error);
            if (queryId is not null)
            {
                await db.RunLog.Where(r => r.TenantId == tenant.Id && r.Source == source && r.Error != null && r.Error.Contains(queryId)).ExecuteDeleteAsync(cancellationToken);
            }

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

    /// <summary>Entra rejected the app credential. The same failure hits every collector, so the stack is not useful.</summary>
    private static string? CredentialFailure(Exception exception)
    {
        string? reason = null;
        for (var current = exception; current is not null; current = current.InnerException)
        {
            var text = current.Message;
            if (current is not Azure.Identity.AuthenticationFailedException
                && text.Contains("AADSTS", StringComparison.Ordinal) == false
                && text.Contains("invalid_client", StringComparison.Ordinal) == false)
            {
                continue;
            }

            const string original = "Original exception:";
            var start = text.IndexOf(original, StringComparison.Ordinal);
            var detail = start >= 0 ? text[(start + original.Length)..].Trim() : text.Trim();
            var trace = detail.IndexOf("Trace ID:", StringComparison.Ordinal);
            if (trace > 0)
            {
                detail = detail[..trace].Trim();
            }

            reason = detail.Length <= 500 ? detail : detail[..500];
        }

        return reason;
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
        base.Dispose();
    }
}
