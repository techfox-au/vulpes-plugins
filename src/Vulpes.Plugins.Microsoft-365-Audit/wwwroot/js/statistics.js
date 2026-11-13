import { kpiCard } from './common.js?v=shell365';

let timer;

export async function mount(el, ctx) {
  ctx.setTitle(['Statistics']);
  const { h } = ctx.ui;
  el.querySelector('[data-role="actions"]').append(
    h('button', { class: 'btn ghost', 'aria-label': 'Refresh', onClick: () => render(el, ctx) }, ctx.ui.icon('refresh')),
  );
  await render(el, ctx);
  timer = setInterval(() => render(el, ctx), 60000);
}

export function unmount() {
  clearInterval(timer);
  timer = null;
}

function share(part, total) {
  if (!total) return '0%';
  const pct = (part / total) * 100;
  if (pct > 0 && pct < 10) return `${pct.toFixed(1)}%`;
  return `${pct.toFixed(0)}%`;
}

async function render(el, ctx) {
  const { h, clear, table, fmt, errorMessage } = ctx.ui;
  const note = el.querySelector('[data-role="note"]');
  const kpis = el.querySelector('[data-role="kpis"]');
  const sources = el.querySelector('[data-role="sources"]');
  const tenants = el.querySelector('[data-role="tenants"]');
  let data;
  try {
    data = await ctx.api.get(`${ctx.plugin.apiBase}/statistics`);
  } catch (err) {
    clear(note).append(h('div', { class: 'alert danger' }, errorMessage(err)));
    clear(kpis);
    clear(sources);
    clear(tenants);
    return;
  }

  clear(note);
  if (!data.available) {
    note.append(h('div', { class: 'alert' }, 'Elasticsearch is not configured, so storage statistics are unavailable.'));
  }

  const docs = data.documents || 0;
  const stored = data.storedBytes || 0;
  const disk = data.diskBytes || 0;
  const average = docs > 0 ? fmt.bytes(stored / docs) : '—';
  const replica = disk > stored ? `${fmt.bytes(disk - stored)} in replicas` : 'No replica copies';
  clear(kpis).append(
    kpiCard(ctx.ui, 'Documents', fmt.number(docs)),
    kpiCard(ctx.ui, 'Stored', fmt.bytes(stored), '', 'Primary copy'),
    kpiCard(ctx.ui, 'On disk', fmt.bytes(disk), '', replica),
    kpiCard(ctx.ui, 'Average document', average, '', 'Stored size divided by documents'),
  );

  clear(sources).append(table({
    columns: [
      { title: 'Log', render: (r) => r.title },
      { title: 'Documents', class: 'num', render: (r) => fmt.number(r.documents) },
      { title: 'Share', class: 'num', render: (r) => share(r.storedBytes, stored) },
      { title: 'Stored', class: 'num', render: (r) => fmt.bytes(r.storedBytes) },
      { title: 'On disk', class: 'num', render: (r) => fmt.bytes(r.diskBytes) },
      { title: 'Oldest', render: (r) => (r.oldest ? fmt.date(r.oldest) : '') },
      { title: 'Newest', render: (r) => (r.newest ? fmt.date(r.newest) : '') },
    ],
    rows: data.sources || [],
    emptyText: 'No audit logs are stored.',
  }));

  clear(tenants).append(table({
    columns: [
      { title: 'Client', render: (r) => r.name },
      { title: 'Documents', class: 'num', render: (r) => fmt.number(r.documents) },
      { title: 'Share', class: 'num', render: (r) => share(r.documents, docs) },
      { title: 'Estimated storage', class: 'num', render: (r) => fmt.bytes(r.estimatedBytes) },
    ],
    rows: data.tenants || [],
    emptyText: 'No documents stored.',
  }));
}
