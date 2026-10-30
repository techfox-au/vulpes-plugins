import { h, badge, fmt, empty, errorMessage, icon } from '../ui.js?v=shell83';

export async function mount(el, ctx) {
  ctx.setTitle(['Home']);
  const greeting = h('div', { class: 'page-header' },
    h('h1', null, 'Home'));
  const statusGrid = h('div', { class: 'grid cols-4' });
  const modulesCard = h('div', { class: 'card' }, h('div', { class: 'card-header' }, h('h2', null, 'Plugins')), h('div', { class: 'muted' }, 'Loading…'));
  const alertsCard = h('div', { class: 'card' }, h('div', { class: 'card-header' }, h('h2', null, 'Recent alerts'), ctx.hasRole('Admin', 'Analyst') ? h('a', { class: 'btn sm', href: '#/alerts' }, 'All alerts') : null), h('div', { class: 'muted' }, 'Loading…'));
  el.append(greeting, statusGrid, h('div', { class: 'grid cols-2' }, modulesCard, alertsCard));

  try {
    const status = await ctx.api.get('/api/status');
    statusGrid.append(
      kpi('Search backend', status.elasticsearch?.enabled ? (status.elasticsearch.healthy ? 'Healthy' : 'Unreachable') : 'Not configured', status.elasticsearch?.enabled ? (status.elasticsearch.healthy ? 'success' : 'danger') : 'warning', esDetail(status.elasticsearch)),
      kpi('Plugins loaded', String(status.modules?.loaded ?? 0), status.modules?.failed ? 'warning' : '', status.modules?.failed ? `${status.modules.failed} failed to load` : 'all healthy'),
      kpi('Alert rules', String(status.alerts?.enabledRules ?? 0), '', `${fmt.number(status.alerts?.alertsLast24h ?? 0)} alerts in 24h`),
      kpi('Notifications', status.notifications?.smtpConfigured ? 'Email ready' : 'Email not set', status.notifications?.smtpConfigured ? 'success' : 'warning', status.notifications?.pending ? `${status.notifications.pending} pending` : ''),
    );
  } catch (err) {
    statusGrid.append(h('div', { class: 'alert danger' }, errorMessage(err)));
  }

  try {
    const modules = await ctx.api.get('/api/modules');
    const body = modulesCard.lastChild;
    body.replaceWith(modules.length === 0 ? empty('No plugins installed.', 'plug')
      : h('div', { class: 'col' }, modules.map((m) => h('div', { class: 'flex between' },
        h('div', null, h('div', null, h('strong', null, m.name), ' ', badge('v' + m.version))),
        h('a', { class: 'btn sm', href: `#/p/${m.id}/${m.pages[0] || ''}` }, 'Open')))));
  } catch (err) {
    modulesCard.lastChild.replaceWith(h('div', { class: 'alert danger' }, errorMessage(err)));
  }

  if (ctx.hasRole('Admin', 'Analyst')) {
    try {
      const alerts = await ctx.api.get('/api/alerts/instances?pageSize=8');
      alertsCard.lastChild.replaceWith(alerts.items.length === 0 ? empty('No alerts yet.', 'bell')
        : h('div', { class: 'col' }, alerts.items.map((a) => h('div', { class: 'flex between' },
          h('div', { class: 'grow' }, h('div', { class: 'truncate' }, badge(a.severity, severityKind(a.severity)), ' ', a.summary), h('div', { class: 'small muted' }, `${a.ruleName} · ${fmt.relative(a.createdAt)}${a.count > 1 ? ` · ×${a.count}` : ''}`)),
          badge(a.status, a.status === 'new' ? 'primary' : '')))));
    } catch (err) {
      alertsCard.lastChild.replaceWith(h('div', { class: 'alert danger' }, errorMessage(err)));
    }
  } else {
    alertsCard.lastChild.replaceWith(empty('No alerts.', 'bell'));
  }
}

export function unmount() {}

function esDetail(es) {
  if (!es?.enabled) return '';
  if (es.healthy) return es.version ? `Elasticsearch ${es.version}` : '';
  return es.error || '';
}

function kpi(label, value, kind, delta) {
  return h('div', { class: 'card kpi ' + (kind || '') }, h('div', { class: 'label' }, label), h('div', { class: 'value' }, value), h('div', { class: 'delta' }, delta || ''));
}

export function severityKind(sev) {
  return { critical: 'danger', high: 'danger', medium: 'warning', low: 'info', informational: '' }[sev] || '';
}
