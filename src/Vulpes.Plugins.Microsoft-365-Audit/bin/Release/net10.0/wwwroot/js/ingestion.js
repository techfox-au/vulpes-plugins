import { statusBadge } from './common.js?v=shell84';

let timer;
// Collector health per tenant and source. Refreshes every 15 seconds (docs/audit-plugin.md).
export async function mount(el, ctx) {
  const { h } = ctx.ui;
  el.querySelector('[data-role="actions"]').append(h('button', { class: 'btn ghost', 'aria-label': 'Refresh', onClick: () => render(el, ctx) }, ctx.ui.icon('refresh')));
  await render(el, ctx);
  timer = setInterval(() => render(el, ctx), 15000);
}

export function unmount() { clearInterval(timer); timer = null; }

async function render(el, ctx) {
  const { h, clear, table, fmt, errorMessage, badge } = ctx.ui;
  const matrix = el.querySelector('[data-role="matrix"]');
  const runs = el.querySelector('[data-role="runs"]');
  let status;
  try { status = await ctx.api.get(`${ctx.plugin.apiBase}/status`); }
  catch (err) { clear(matrix).append(h('div', { class: 'alert danger' }, errorMessage(err))); return; }

  clear(matrix);
  if (status.tenants.length === 0) { matrix.append(h('div', { class: 'card muted' }, 'No tenants configured.')); }
  const sources = status.sources;
  const rows = status.tenants.map((t) => ({ tenant: t, byName: Object.fromEntries((t.checkpoints || []).map((c) => [c.source, c])) }));
  matrix.append(table({
    columns: [
      { title: 'Tenant', render: (r) => h('div', null, h('strong', null, r.tenant.displayName), r.tenant.enabled ? null : h('div', null, badge('disabled', 'warning'))) },
      ...sources.map((s) => ({ title: s.title.replace(/^(Entra ID|Microsoft 365|Microsoft) /, ''), render: (r) => {
        const c = r.byName[s.source];
        if (!c) return h('span', { class: 'cell-muted' }, '-');
        return h('div', { title: c.lastError || '' }, statusBadge(ctx.ui, c.lastStatus), h('div', { class: 'small muted nowrap' }, c.lastSuccessAt ? fmt.relative(c.lastSuccessAt) : 'never'), h('div', { class: 'small faint nowrap' }, `${fmt.number(c.totalCount)} ev`));
      } })),
    ],
    rows,
    emptyText: 'No tenants.',
  }));

  clear(runs).append(table({
    columns: [
      { title: 'Started', render: (r) => h('span', { class: 'nowrap' }, fmt.dateTime(r.startedAt)) },
      { title: 'Tenant', path: 'tenant', render: (r) => r.tenant || r.tenantId },
      { title: 'Source', render: (r) => sources.find((s) => s.source === r.source)?.title || r.source },
      { title: 'Status', render: (r) => statusBadge(ctx.ui, r.status) },
      { title: 'Duration', render: (r) => r.finishedAt ? `${Math.max(0, (new Date(r.finishedAt) - new Date(r.startedAt)) / 1000).toFixed(1)}s` : '' },
      { title: 'New', class: 'num', render: (r) => fmt.number(r.count) },
      { title: 'Dupes', class: 'num', render: (r) => fmt.number(r.duplicates) },
      { title: 'Failed', class: 'num', render: (r) => r.failed ? h('span', { class: 'badge danger' }, fmt.number(r.failed)) : '0' },
      { title: 'Alerts', class: 'num', render: (r) => fmt.number(r.alerts) },
      { title: 'Note', render: (r) => h('span', { class: 'small muted' }, r.error || '') },
    ],
    rows: status.recentRuns,
    emptyText: 'No runs yet.',
  }));
}
