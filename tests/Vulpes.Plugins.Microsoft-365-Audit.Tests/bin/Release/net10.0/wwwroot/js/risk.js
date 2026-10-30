import { createExplorer, severityBadge, get } from './common.js';

let explorer;
export async function mount(el, ctx) {
  const { h, fmt, clear } = ctx.ui;
  const q = ctx.query || {};
  const tabs = el.querySelector('[data-role="tabs"]');
  const host = el.querySelector('[data-role="explorer"]');

  function show(type) {
    clear(tabs).append(
      h('button', { class: 'tab' + (type === 'detection' ? ' active' : ''), role: 'tab', onClick: () => show('detection') }, 'Detections'),
      h('button', { class: 'tab' + (type === 'user' ? ' active' : ''), role: 'tab', onClick: () => show('user') }, 'Risky users'),
      h('button', { class: 'tab' + (type === 'servicePrincipal' ? ' active' : ''), role: 'tab', onClick: () => show('servicePrincipal') }, 'Risky service principals'));
    explorer?.destroy();
    clear(host);
    const initialFilters = [{ field: 'labels.riskType', operator: 'equals', values: [type] }];
    if (q.level) initialFilters.push({ field: 'labels.riskLevel', operator: 'equals', values: [q.level] });
    explorer = createExplorer(host, ctx, {
      source: 'risk',
      defaultRange: q.range || '30d',
      initialFilters,
      columns: [
        { title: type === 'detection' ? 'Detected' : 'Updated', render: (d) => h('span', { class: 'nowrap' }, fmt.dateTime(d['@timestamp'])) },
        { title: 'Level', render: (d) => severityBadge(ctx.ui, get(d, 'labels.riskLevel')) },
        type === 'detection' ? { title: 'Detection', path: 'event.action', filterField: 'event.action' } : { title: 'Identity', render: (d) => get(d, 'user.name') || get(d, 'client.appName') },
        { title: 'State', path: 'labels.riskState', filterField: 'labels.riskState' },
        type === 'detection' ? { title: 'User', path: 'user.name', filterField: 'user.name' } : { title: 'Detail', path: 'labels.riskDetail' },
        type === 'detection' ? { title: 'IP', path: 'source.address', filterField: 'source.address', class: 'mono' } : { title: 'Type', path: type === 'user' ? 'labels.isDeleted' : 'labels.servicePrincipalType' },
        type === 'detection' ? { title: 'Location', render: (d) => [get(d, 'source.geo.city_name'), get(d, 'source.geo.country_name')].filter(Boolean).join(', ') } : { title: '', render: () => '' },
        { title: 'Tenant', path: 'vc.tenantName', filterField: 'vc.tenantName' },
      ],
    });
  }

  show(q.tab || 'detection');
}

export function unmount() { explorer?.destroy(); explorer = null; }
