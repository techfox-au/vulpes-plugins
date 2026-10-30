// Microsoft Defender XDR alerts and incidents, updated as they change (docs/audit-plugin.md).
import { createExplorer, severityBadge, get } from './common.js?v=shell84';

let explorer;
export async function mount(el, ctx) {
  const { h, fmt, clear } = ctx.ui;
  const q = ctx.query || {};
  const tabs = el.querySelector('[data-role="tabs"]');
  const host = el.querySelector('[data-role="explorer"]');

  function show(which) {
    clear(tabs).append(
      h('button', { class: 'tab' + (which === 'security-alerts' ? ' active' : ''), role: 'tab', onClick: () => show('security-alerts') }, 'Alerts'),
      h('button', { class: 'tab' + (which === 'incidents' ? ' active' : ''), role: 'tab', onClick: () => show('incidents') }, 'Incidents'));
    explorer?.destroy();
    clear(host);
    const initialFilters = [];
    if (q.severity) initialFilters.push({ field: 'event.severity', operator: 'equals', values: [q.severity] });
    explorer = createExplorer(host, ctx, {
      source: which,
      defaultRange: q.range || '30d',
      initialFilters,
      columns: [
        { title: 'Created', render: (d) => h('span', { class: 'nowrap' }, fmt.dateTime(d['@timestamp'])) },
        { title: 'Severity', render: (d) => severityBadge(ctx.ui, get(d, 'event.severity')) },
        { title: which === 'incidents' ? 'Incident' : 'Alert', render: (d) => h('div', null, h('div', null, d.message), which === 'incidents' ? null : h('div', { class: 'small muted' }, get(d, 'event.action'))) },
        { title: 'Status', path: 'labels.status', filterField: 'labels.status' },
        which === 'incidents' ? { title: 'Classification', path: 'labels.classification', filterField: 'labels.classification' } : { title: 'Source', path: 'labels.serviceSource', filterField: 'labels.serviceSource' },
        which === 'incidents' ? { title: 'Assigned to', path: 'labels.assignedTo' } : { title: 'User', path: 'user.name', filterField: 'user.name' },
        which === 'incidents' ? { title: 'Portal', render: (d) => get(d, 'labels.incidentWebUrl') ? h('a', { href: get(d, 'labels.incidentWebUrl'), target: '_blank', rel: 'noopener noreferrer' }, 'Open') : '' } : { title: 'Incident', path: 'labels.incidentId' },
        { title: 'Updated', render: (d) => fmt.relative(get(d, 'labels.lastUpdate')) },
        { title: 'Tenant', path: 'vc.tenantName', filterField: 'vc.tenantName' },
      ],
    });
  }

  show(q.tab === 'incidents' ? 'incidents' : 'security-alerts');
}

export function unmount() { explorer?.destroy(); explorer = null; }
