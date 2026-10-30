// Interactive and non-interactive Entra ID sign-ins (docs/audit-module.md).
import { createExplorer, outcomeBadge, severityBadge, get } from './common.js?v=shell84';

let explorer;
export async function mount(el, ctx) {
  const { h, fmt } = ctx.ui;
  const q = ctx.query || {};
  const initialFilters = [];
  if (q.user) initialFilters.push({ field: 'user.name', operator: 'equals', values: [q.user] });
  if (q.ip) initialFilters.push({ field: 'source.address', operator: 'equals', values: [q.ip] });
  if (q.country) initialFilters.push({ field: 'source.geo.country_name', operator: 'equals', values: [q.country] });
  if (q.app) initialFilters.push({ field: 'client.appName', operator: 'equals', values: [q.app] });
  if (q.outcome) initialFilters.push({ field: 'event.outcome', operator: 'equals', values: [q.outcome] });

  explorer = createExplorer(el.querySelector('[data-role="explorer"]'), ctx, {
    source: 'signins',
    defaultRange: q.range || '24h',
    initialFilters,
    columns: [
      { title: 'Time', render: (d) => h('span', { class: 'nowrap' }, fmt.dateTime(d['@timestamp'])) },
      { title: 'User', path: 'user.name', filterField: 'user.name' },
      { title: 'Outcome', render: (d) => h('div', null, outcomeBadge(ctx.ui, get(d, 'event.outcome')), get(d, 'labels.errorCode') && get(d, 'labels.errorCode') !== '0' ? h('div', { class: 'small muted' }, `code ${get(d, 'labels.errorCode')}`) : null) },
      { title: 'Application', path: 'client.appName', filterField: 'client.appName' },
      { title: 'IP', path: 'source.address', filterField: 'source.address', class: 'mono' },
      { title: 'Location', render: (d) => [get(d, 'source.geo.city_name'), get(d, 'source.geo.country_name')].filter(Boolean).join(', ') },
      { title: 'Type', path: 'labels.signInType', filterField: 'labels.signInType' },
      { title: 'CA', path: 'labels.conditionalAccessStatus', filterField: 'labels.conditionalAccessStatus' },
      { title: 'Risk', render: (d) => { const r = get(d, 'labels.riskLevel'); return r && r !== 'none' ? severityBadge(ctx.ui, r) : ''; } },
      { title: 'Tenant', path: 'vc.tenantName', filterField: 'vc.tenantName' },
    ],
    detailFields: [{ label: 'Failure reason', path: 'data.status.failureReason' }, { label: 'Client app used', path: 'labels.clientAppUsed' }, { label: 'OS / browser', path: 'labels.os' }],
  });
}

export function unmount() { explorer?.destroy(); explorer = null; }
