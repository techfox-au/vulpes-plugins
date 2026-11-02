# Microsoft 365 Audit (`microsoft-365-audit.7z`)

Collects Microsoft 365 / Entra security logs from any number of tenants into Elasticsearch and exposes them in the
dashboard. The plugin id is `microsoft-365-audit`. Its API is `/api/plugins/microsoft-365-audit`. Clients are added under **Manage → Tenants**. Per-source collection for a client is edited there too. Plugin-wide intervals live in `Plugins:Settings:microsoft-365-audit`.

## Screens

The pages show a title only. What each one is:

- **Overview.** Sign-ins, activity, alerts and risk across the connected tenants.
- **Sign-ins.** Interactive and non-interactive Entra ID sign-ins. Choosing a value in the table filters by it.
- **Directory.** Changes to users, groups, roles, applications and policies in Entra ID, plus provisioning events.
- **Activity.** The Microsoft 365 unified audit log: SharePoint and OneDrive file activity, Exchange, Teams, admin operations and more.
- **Security alerts.** Microsoft Defender XDR alerts and incidents, updated as they change.
- **Identity Protection risk.** Risk detections and the risk state of users and service principals from Entra ID Protection.
- **Ingestion.** Collector health per tenant and source. The page refreshes on its own.

Clients, the shared Entra application, and the connection test are under **Manage → Tenants**. The registration steps and the PowerShell to turn auditing on are in [entra-setup.md](entra-setup.md).

## Sources

| Source | Index | Mode | Graph endpoint | Watermark field | Default interval |
| --- | --- | --- | --- | --- | --- |
| `signins` | `vc-microsoft-365-audit-signins` | data stream | `v1.0/auditLogs/signIns`; `beta/auditLogs/signIns` with `signInEventTypes` for non-interactive, service principal and managed identity sign-ins (per-tenant toggle) | `createdDateTime` | 5 min |
| `directory` | `vc-microsoft-365-audit-directory` | data stream | `v1.0/auditLogs/directoryAudits` | `activityDateTime` | 5 min |
| `provisioning` | `vc-microsoft-365-audit-provisioning` | data stream | `v1.0/auditLogs/provisioning` | `activityDateTime` | 15 min |
| `activity` | `vc-microsoft-365-audit-activity` | data stream | `v1.0/security/auditLog/queries` (asynchronous Purview query, polled, records paged) | query window end | 30 min |
| `security-alerts` | `vc-microsoft-365-audit-security-alerts` | index (upsert) | `v1.0/security/alerts_v2` | `lastUpdateDateTime` | 5 min |
| `incidents` | `vc-microsoft-365-audit-incidents` | index (upsert) | `v1.0/security/incidents` | `lastUpdateDateTime` | 10 min |
| `risk` | `vc-microsoft-365-audit-risk` | data stream | `identityProtection/riskDetections`, `riskyUsers`, `riskyServicePrincipals` (change-aware ids) | `lastUpdatedDateTime` / `riskLastUpdatedDateTime` | 10 min |
| `securescore` | `vc-microsoft-365-audit-securescore` | index (upsert) | `v1.0/security/secureScores` | `createdDateTime` | 24 h |
| `system` | `vc-microsoft-365-audit-system` | data stream | collector failures (`audit.collector.failed`) | – | – |

Every document carries the common envelope (`@timestamp`, `event.*`, `vc.*`, `user.*`, `source.*`, `client.*`,
`file.*`, `message`), a `labels` object with source-specific keywords (for example `labels.workload`,
`labels.riskLevel`, `labels.signInType`) and the complete upstream record under `data` (flattened mapping, searchable).

## Collection behaviour

- **First run** reads the tenant's lookback window (default 7 days, max 180). Afterwards each run starts at
  `watermark - overlap` (30 minutes for Entra logs, 60 minutes for Purview) to catch late arrivals; duplicates are
  dropped by Elasticsearch thanks to deterministic ids.
- **Partial runs** (page cap `MaxPagesPerRun`, time budget `RunTimeBudgetMinutes`) resume from the oldest record seen.
- **Purview**: one query per tenant per cycle; windows are capped at `PurviewMaxWindowHours` (24 h) and end
  `PurviewLagMinutes` (15) before now. Pending queries are polled on the next runs; failed queries are retried with the
  same window; queries older than 6 hours are abandoned and resubmitted. Record types default to SharePoint, OneDrive,
  Exchange, Entra, Teams, security & compliance, threat intelligence, DLP, Power BI and Power Platform types; override
  per tenant or in `PurviewRecordTypes`.
- **Throttling**: 429/503/504 responses are retried honouring `Retry-After` (cap 5 minutes) with exponential backoff
  and jitter, up to 6 times. Collector failures back off exponentially (capped at 4x the interval), are recorded on the
  checkpoint and published as `system` events so a rule can email on ingestion problems.
- **Concurrency**: `MaxConcurrentJobs` (4) jobs run in parallel across tenants and sources.

## Settings (`Plugins:Settings:microsoft-365-audit`)

| Key | Default | Meaning |
| --- | --- | --- |
| `SchedulerIntervalSeconds` | 20 | Scheduler tick |
| `MaxConcurrentJobs` | 4 | Parallel collector runs |
| `RunTimeBudgetMinutes` | 20 | Time budget per run |
| `DefaultLookbackDays` | 7 | Lookback for new tenants (UI default) |
| `LogOverlapMinutes` | 30 | Overlap for Entra / Defender / risk feeds |
| `PurviewLagMinutes` | 15 | Purview query end lag |
| `PurviewOverlapMinutes` | 60 | Purview overlap |
| `PurviewMaxWindowHours` | 24 | Max Purview window per query |
| `MaxPagesPerRun` | 400 | Graph pages per run |
| `GraphPageSize` | 500 | `$top` |
| `PurviewRecordTypes` | see `AuditOptions` | Record type filter |
| `IntervalMinutes:<source>` | per table above | Run intervals |

Per tenant (UI → Edit tenant → Per-source settings): enable/disable a source, custom interval, include non-interactive
sign-ins, Purview record types.

**Microsoft 365 Business Premium mode** (plugin Settings) stops Identity Protection risk collection. Business Premium
includes Entra ID P1. The risk detections, risky users and risky service principal Graph reports need Entra ID P2.
Sign-ins, directory audit, provisioning, the unified audit log, Defender alerts and incidents, and Secure Score stay on.
The Risk page keeps any events already stored. New alert rules cannot select Identity Protection risk while the mode is on.
A rule that already uses that source keeps it, locked, so saving the rule does not remove it.

## Alert rule examples

| Goal | Source | Conditions |
| --- | --- | --- |
| Email when a specific user signs in | `signins` | `user.name equals ceo@contoso.com` |
| Failed sign-ins from outside Australia | `signins` | `event.outcome equals failure` AND `source.geo.country_iso_code notEquals AU` |
| Brute force | `signins` | `event.outcome equals failure`, threshold `≥ 10 in 5 minutes grouped by user.name` |
| Access to board documents | `activity` | `event.action in FileAccessed,FileDownloaded,FileSyncDownloadedFull` AND `file.path contains /Board/` |
| Anonymous sharing links | `activity` | `event.action in AnonymousLinkCreated,SharingSet` |
| New inbox forwarding rules | `activity` | `event.action in New-InboxRule,Set-InboxRule,UpdateInboxRules` |
| Privileged role changes | `directory` | `event.action equals Add member to role` |
| High-severity Defender alerts | `security-alerts` | `event.severity in high,critical` |
| Collector broken | `system` | `event.action equals audit.collector.failed` with throttle 60 min per `labels.collector` |

## API (under `/api/plugins/microsoft-365-audit`)

| Method and path | Role | Purpose |
| --- | --- | --- |
| `GET /sources` | Viewer | Sources, fields, collector permissions |
| `POST /search`, `POST /aggregate`, `GET /events/{source}/{id}`, `GET /overview` | Viewer | Explorer and dashboard data |
| `GET /tenants/names` | Viewer | Tenant picker |
| `GET /status`, `GET /tenants`, `GET /tenants/{id}`, `POST /tenants/{id}/run` | Analyst | Operations |
| `POST /tenants`, `PUT /tenants/{id}`, `DELETE /tenants/{id}`, `POST /tenants/{id}/test`, `POST /tenants/{id}/reset` | Admin | Tenant management |

Credentials are write-only: responses expose `hasSecret` / `hasCertificate` flags, never the values.
