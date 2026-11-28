// Microsoft Defender XDR alerts and incidents, updated as they change (docs/audit-plugin.md).
import { createExplorer, severityBadge, get, drillFilter } from './common.js?v=shell393';

let explorer;
export async function mount(el, ctx) {
  const { h, clear } = ctx.ui;
  const q = ctx.query || {};
  const tabs = el.querySelector('[data-role="tabs"]');
  const host = el.querySelector('[data-role="explorer"]');

  let carried = null;

  function show(which) {
    if (explorer?.snapshot) carried = explorer.snapshot();
    clear(tabs).append(
      h('button', { class: 'tab' + (which === 'security-alerts' ? ' active' : ''), role: 'tab', onClick: () => show('security-alerts') }, 'Alerts'),
      h('button', { class: 'tab' + (which === 'incidents' ? ' active' : ''), role: 'tab', onClick: () => show('incidents') }, 'Incidents'));
    explorer?.destroy();
    clear(host);
    const filters = carried ? carriedAlertFilters(which, carried.filters) : [];
    if (!carried) {
      const severity = drillFilter(q, 'severity', 'event.severity');
      if (severity) filters.push(severity);
    }
    explorer = createExplorer(host, ctx, {
      source: which,
      defaultRange: carried?.range || q.range || '30d',
      initialFilters: filters,
      initialState: carried ? { ...carried, filters } : null,
      columns: alertColumns(which, ctx),
    });
  }

  show(q.tab === 'incidents' ? 'incidents' : 'security-alerts');
}

export function unmount() { explorer?.destroy(); explorer = null; }

function columnFields(which) {
  return which === 'incidents'
    ? ['labels.status', 'labels.classification', 'labels.assignedTo', 'vc.tenantName']
    : ['labels.status', 'labels.serviceSource', 'user.name', 'vc.tenantName'];
}

// Both sources store severity, classification, determination, and assignedTo. Incidents do not store serviceSource or user.name.
const sharedAlertFields = ['event.severity', 'labels.status', 'labels.classification', 'labels.determination', 'labels.assignedTo', 'labels.lastUpdate', 'vc.tenantId', 'vc.tenantName'];

function storedAlertFields(which) {
  const fields = new Set(sharedAlertFields);
  if (which !== 'incidents') {
    fields.add('labels.serviceSource');
    fields.add('user.name');
  }
  return fields;
}

export function alertColumns(which, ctx) {
  const { h, fmt } = ctx.ui;
  const incidents = which === 'incidents';
  const [statusField, extraField, personField, tenantField] = columnFields(which);
  return [
    { title: 'Created', render: (d) => h('span', { class: 'nowrap' }, fmt.dateTime(d['@timestamp'])) },
    { title: 'Severity', render: (d) => severityBadge(ctx.ui, get(d, 'event.severity')) },
    { title: incidents ? 'Incident' : 'Alert', render: (d) => h('div', null, h('div', null, d.message), incidents ? null : h('div', { class: 'small muted' }, get(d, 'event.action'))) },
    { title: 'Status', path: statusField, filterField: statusField },
    incidents ? { title: 'Classification', path: extraField, filterField: extraField } : { title: 'Source', path: extraField, filterField: extraField },
    { title: incidents ? 'Assigned to' : 'User', path: personField, filterField: personField },
    incidents ? { title: 'Portal', render: (d) => get(d, 'labels.incidentWebUrl') ? h('a', { href: get(d, 'labels.incidentWebUrl'), target: '_blank', rel: 'noopener noreferrer' }, 'Open') : '' } : { title: 'Incident', path: 'labels.incidentId' },
    { title: 'Updated', render: (d) => fmt.relative(get(d, 'labels.lastUpdate')) },
    { title: 'Tenant', path: tenantField, filterField: tenantField },
  ];
}

export function carriedAlertFilters(which, filters) {
  const allowed = storedAlertFields(which);
  return (filters || []).filter((filter) => allowed.has(filter.field)).map((filter) => ({
    field: filter.field,
    operator: filter.operator,
    values: [...(filter.values || [])],
    ...(filter.drill ? { drill: true } : {}),
  }));
}
