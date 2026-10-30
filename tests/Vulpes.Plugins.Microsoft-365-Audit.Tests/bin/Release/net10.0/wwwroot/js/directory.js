import { createExplorer, outcomeBadge, severityBadge, get } from './common.js';

let explorer;
export async function mount(el, ctx) {
  const { h, fmt, clear } = ctx.ui;
  const q = ctx.query || {};
  const tabs = el.querySelector('[data-role="tabs"]');
  const host = el.querySelector('[data-role="explorer"]');
  let current = q.tab || 'directory';

  function show(which) {
    current = which;
    clear(tabs).append(
      h('button', { class: 'tab' + (which === 'directory' ? ' active' : ''), role: 'tab', onClick: () => show('directory') }, 'Directory audit'),
      h('button', { class: 'tab' + (which === 'provisioning' ? ' active' : ''), role: 'tab', onClick: () => show('provisioning') }, 'Provisioning'));
    explorer?.destroy();
    clear(host);
    const initialFilters = [];
    if (q.activity && which === 'directory') initialFilters.push({ field: 'event.action', operator: 'equals', values: [q.activity] });
    if (q.user) initialFilters.push({ field: 'user.name', operator: 'equals', values: [q.user] });
    explorer = createExplorer(host, ctx, {
      source: which,
      defaultRange: q.range || '7d',
      initialFilters,
      columns: which === 'directory' ? [
        { title: 'Time', render: (d) => h('span', { class: 'nowrap' }, fmt.dateTime(d['@timestamp'])) },
        { title: 'Activity', render: (d) => h('div', null, h('div', null, get(d, 'event.action')), get(d, 'event.severity') === 'medium' ? severityBadge(ctx.ui, 'medium') : null), filterField: 'event.action', path: 'event.action' },
        { title: 'Actor', render: (d) => get(d, 'user.name') || get(d, 'client.appName') || '(system)', filterField: 'user.name', path: 'user.name' },
        { title: 'Target', path: 'labels.targetName', filterField: 'labels.targetName' },
        { title: 'Result', render: (d) => h('div', null, outcomeBadge(ctx.ui, get(d, 'event.outcome')), get(d, 'labels.resultReason') ? h('div', { class: 'small muted truncate', title: get(d, 'labels.resultReason') }, get(d, 'labels.resultReason')) : null) },
        { title: 'Category', path: 'labels.category', filterField: 'labels.category' },
        { title: 'Service', path: 'labels.service', filterField: 'labels.service' },
        { title: 'IP', path: 'source.address', filterField: 'source.address', class: 'mono' },
        { title: 'Tenant', path: 'vc.tenantName', filterField: 'vc.tenantName' },
      ] : [
        { title: 'Time', render: (d) => h('span', { class: 'nowrap' }, fmt.dateTime(d['@timestamp'])) },
        { title: 'Action', path: 'event.action', filterField: 'event.action' },
        { title: 'Target', path: 'user.name', filterField: 'user.name' },
        { title: 'Status', render: (d) => outcomeBadge(ctx.ui, get(d, 'event.outcome')) },
        { title: 'Application', path: 'client.appName', filterField: 'client.appName' },
        { title: 'Source → target', render: (d) => `${get(d, 'labels.sourceSystem') || '?'} → ${get(d, 'labels.targetSystem') || '?'}` },
        { title: 'Tenant', path: 'vc.tenantName', filterField: 'vc.tenantName' },
      ],
    });
  }

  show(current);
}

export function unmount() { explorer?.destroy(); explorer = null; }
