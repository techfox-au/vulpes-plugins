// Microsoft 365 unified audit log: SharePoint, OneDrive, Exchange, Teams, admin operations (docs/audit-plugin.md).
import { createExplorer, outcomeBadge, severityBadge, get } from './common.js?v=shell84';

let explorer;
const QUICK = [
  ['File access', { field: 'event.action', operator: 'in', values: ['FileAccessed', 'FileDownloaded', 'FileSyncDownloadedFull', 'FilePreviewed'] }],
  ['Sharing', { field: 'event.action', operator: 'in', values: ['AnonymousLinkCreated', 'SharingSet', 'SharingInvitationCreated', 'AddedToSecureLink', 'CompanyLinkCreated', 'SecureLinkCreated'] }],
  ['Deletions', { field: 'event.action', operator: 'in', values: ['FileDeleted', 'FileDeletedFirstStageRecycleBin', 'FileDeletedSecondStageRecycleBin', 'FolderDeleted'] }],
  ['Inbox rules', { field: 'event.action', operator: 'in', values: ['New-InboxRule', 'Set-InboxRule', 'UpdateInboxRules', 'Remove-InboxRule'] }],
  ['Mailbox permissions', { field: 'event.action', operator: 'in', values: ['Add-MailboxPermission', 'Remove-MailboxPermission', 'Add-RecipientPermission', 'Set-Mailbox'] }],
  ['Notable', { field: 'event.severity', operator: 'in', values: ['medium', 'high', 'critical'] }],
];

export async function mount(el, ctx) {
  const { h, fmt } = ctx.ui;
  const q = ctx.query || {};
  const initialFilters = [];
  if (q.workload) initialFilters.push({ field: 'labels.workload', operator: 'equals', values: [q.workload] });
  if (q.operation) initialFilters.push({ field: 'event.action', operator: 'equals', values: [q.operation] });
  if (q.user) initialFilters.push({ field: 'user.name', operator: 'equals', values: [q.user] });
  if (q.file) initialFilters.push({ field: 'file.path', operator: 'contains', values: [q.file] });

  explorer = createExplorer(el.querySelector('[data-role="explorer"]'), ctx, {
    source: 'activity',
    defaultRange: q.range || '24h',
    initialFilters,
    columns: [
      { title: 'Time', render: (d) => h('span', { class: 'nowrap' }, fmt.dateTime(d['@timestamp'])) },
      { title: 'User', path: 'user.name', filterField: 'user.name' },
      { title: 'Operation', render: (d) => h('div', null, h('div', null, get(d, 'event.action')), get(d, 'event.severity') && get(d, 'event.severity') !== 'informational' ? severityBadge(ctx.ui, get(d, 'event.severity')) : null), path: 'event.action', filterField: 'event.action' },
      { title: 'Workload', path: 'labels.workload', filterField: 'labels.workload' },
      { title: 'Object / file', render: (d) => { const p = get(d, 'file.path') || get(d, 'labels.objectId'); return p ? h('span', { class: 'truncate', title: p }, get(d, 'file.name') || p) : ''; } },
      { title: 'Result', render: (d) => outcomeBadge(ctx.ui, get(d, 'event.outcome')) },
      { title: 'IP', path: 'source.address', filterField: 'source.address', class: 'mono' },
      { title: 'Client', render: (d) => get(d, 'client.appName') || (get(d, 'user_agent.original') ? h('span', { class: 'truncate small muted', title: get(d, 'user_agent.original') }, get(d, 'user_agent.original')) : '') },
      { title: 'Tenant', path: 'vc.tenantName', filterField: 'vc.tenantName' },
    ],
    detailFields: [{ label: 'Record type', path: 'labels.recordType' }, { label: 'Site', path: 'labels.siteUrl' }, { label: 'Target user / group', path: 'labels.targetUser' }, { label: 'Mailbox owner', path: 'labels.mailboxOwner' }],
  });

  const quick = el.querySelector('[data-role="quick"]');
  for (const [label, filter] of QUICK) {
    quick.append(h('button', { class: 'btn sm', onClick: () => { explorer.state.filters = explorer.state.filters.filter((f) => f.field !== filter.field); explorer.state.filters.push(filter); explorer.reload(); } }, label));
  }
}

export function unmount() { explorer?.destroy(); explorer = null; }
