// Entra directory changes and provisioning (docs/audit-plugin.md).
import { createExplorer, outcomeBadge, severityBadge, get, drillFilter } from './common.js?v=shell374';

let explorer;
export async function mount(el, ctx) {
  const { h, fmt, clear } = ctx.ui;
  const q = ctx.query || {};
  const tabs = el.querySelector('[data-role="tabs"]');
  const host = el.querySelector('[data-role="explorer"]');
  let current = q.tab || 'directory';
  let carried = null;

  function show(which) {
    if (explorer?.snapshot) carried = explorer.snapshot();
    current = which;
    clear(tabs).append(
      h('button', { class: 'tab' + (which === 'directory' ? ' active' : ''), role: 'tab', onClick: () => show('directory') }, 'Directory audit'),
      h('button', { class: 'tab' + (which === 'provisioning' ? ' active' : ''), role: 'tab', onClick: () => show('provisioning') }, 'Provisioning'));
    explorer?.destroy();
    clear(host);
    let filters;
    if (!carried) {
      filters = [];
      if (which === 'directory') {
        const activity = drillFilter(q, 'activity', 'event.action');
        const user = drillFilter(q, 'user', 'user.name');
        if (activity) filters.push({ ...activity, drill: true });
        if (user) filters.push({ ...user, drill: true });
      }
    } else {
      filters = carried.filters.map((f) => ({ field: f.field, operator: f.operator, values: [...(f.values || [])], ...(f.drill ? { drill: true } : {}) }));
    }
    explorer = createExplorer(host, ctx, {
      initialFilters: filters,
      initialState: carried ? { ...carried, filters } : null,
      skipFilter: which === 'provisioning' ? (f) => f.drill === true : null,
      source: which,
      defaultRange: carried?.range || q.range || '7d',
      columns: which === 'directory' ? [
        { title: 'Time', render: (d) => h('span', { class: 'nowrap' }, fmt.dateTime(d['@timestamp'])) },
        { title: 'Activity', render: (d) => h('div', null, h('div', null, get(d, 'event.action')), get(d, 'event.severity') === 'medium' ? severityBadge(ctx.ui, 'medium') : null), filterField: 'event.action', path: 'event.action' },
        { title: 'Actor', render: (d) => actorCell(h, d) },
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

function actorCell(h, doc) {
  const name = get(doc, 'user.name');
  if (name) return h('a', { href: '#', class: 'truncate', title: 'Filter by this value', onClick: (e) => { e.preventDefault(); e.stopPropagation(); explorer?.addQuickFilter('user.name', name); } }, name);
  const app = get(doc, 'client.appName');
  if (app) return h('a', { href: '#', class: 'truncate', title: 'Filter by this value', onClick: (e) => { e.preventDefault(); e.stopPropagation(); explorer?.addQuickFilter('client.appName', app); } }, app);
  return '(system)';
}
