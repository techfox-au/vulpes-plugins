// Shared building blocks for the audit module pages. Uses only ctx.ui / ctx.api from the shell.

export const RANGES = [['1h', 'Last hour'], ['24h', 'Last 24 hours'], ['7d', 'Last 7 days'], ['30d', 'Last 30 days'], ['90d', 'Last 90 days']];

export function rangeToDates(range) {
  const to = new Date();
  const m = /^(\d+)([hd])$/.exec(range || '24h');
  const n = m ? Number(m[1]) : 24;
  const unit = m ? m[2] : 'h';
  const from = new Date(to.getTime() - n * (unit === 'h' ? 3600e3 : 86400e3));
  return { from: from.toISOString(), to: to.toISOString(), hours: unit === 'h' ? n : n * 24 };
}

export function get(doc, path) {
  return path.split('.').reduce((o, k) => (o === null || o === undefined ? undefined : o[k]), doc);
}

export function severityBadge(ui, sev) {
  const kind = { critical: 'danger', high: 'danger', medium: 'warning', low: 'info', informational: '' }[sev] || '';
  return ui.badge(sev || 'informational', kind);
}

export function outcomeBadge(ui, outcome) {
  if (!outcome) return ui.badge('-');
  return ui.badge(outcome, outcome === 'success' ? 'success' : outcome === 'failure' ? 'danger' : '');
}

export function statusBadge(ui, status) {
  const kind = { succeeded: 'success', running: 'info', pending: 'warning', failed: 'danger', idle: '' }[status] || '';
  return ui.badge(status || 'idle', kind, status === 'running');
}

export async function tenantSelect(ctx, onChange, selected) {
  const sel = ctx.ui.dropdown([{ value: '', label: 'All tenants' }], { value: selected || '', ariaLabel: 'Tenant' });
  try {
    const tenants = await ctx.api.get(`${ctx.module.apiBase}/tenants/names`);
    sel.setOptions([
      { value: '', label: 'All tenants' },
      ...tenants.map((t) => ({ value: t.tenantId, label: `${t.displayName}${t.discoveredName && t.discoveredName !== t.displayName ? ` (${t.discoveredName})` : ''}` })),
    ], selected || '');
  } catch { /* viewer without tenants endpoint access still gets "all" */ }
  sel.addEventListener('change', () => onChange(sel.value));
  return sel;
}

export function kpiCard(ui, label, value, kind = '', delta = '') {
  return ui.h('div', { class: 'card kpi ' + kind }, ui.h('div', { class: 'label' }, label), ui.h('div', { class: 'value' }, value), ui.h('div', { class: 'delta' }, delta));
}

export function bucketsToBarList(ui, buckets, opts) {
  return ui.barList((buckets || []).map((b) => ({ key: b.key, count: b.count })), opts);
}

/**
 * Generic event explorer: time range, tenant, free text, filter chips, paginated table and a detail drawer.
 * columns: [{ title, path | render(doc, row), filterField?, class? }]
 */
export function createExplorer(el, ctx, { source, columns, sort = 'desc', defaultRange = '24h', pageSize = 50, initialFilters = [], detailFields = [] }) {
  const { h, clear, table, drawer, fmt, errorMessage, jsonView, kv, badge } = ctx.ui;
  const state = { range: defaultRange, tenant: '', text: '', filters: [...initialFilters], hits: [], total: 0, searchAfter: null, loading: false, fields: [] };

  const toolbar = h('div', { class: 'toolbar' });
  const chips = h('div', { class: 'flex wrap' });
  const results = h('div', { class: 'fill' });
  const pager = h('div', { class: 'pager' });
  el.append(toolbar, chips, results, pager);

  const rangeSel = ctx.ui.dropdown(RANGES.map(([value, label]) => ({ value, label })), { value: state.range, ariaLabel: 'Time range' });
  rangeSel.addEventListener('change', () => { state.range = rangeSel.value; reload(); });
  const textInput = h('input', { class: 'input', placeholder: 'Search text (AND, OR, "phrase", prefix*)', 'aria-label': 'Search text' });
  textInput.addEventListener('keydown', (e) => { if (e.key === 'Enter') { state.text = textInput.value.trim(); reload(); } });
  const searchBtn = h('button', { class: 'btn', onClick: () => { state.text = textInput.value.trim(); reload(); } }, 'Search');
  const addFilterBtn = h('button', { class: 'btn', onClick: () => addFilterDialog() }, 'Add filter');
  const refreshBtn = h('button', { class: 'btn ghost', 'aria-label': 'Refresh', onClick: () => reload() }, ctx.ui.icon('refresh'));
  toolbar.append(rangeSel, textInput, searchBtn, addFilterBtn, refreshBtn);
  tenantSelect(ctx, (v) => { state.tenant = v; reload(); }).then((sel) => toolbar.insertBefore(sel, textInput));

  ctx.api.get(`${ctx.module.apiBase}/sources`).then((sources) => { state.fields = sources.find((s) => s.source === source)?.fields || []; }).catch(() => {});

  function renderChips() {
    clear(chips);
    state.filters.forEach((f, i) => {
      chips.append(h('span', { class: 'chip' }, `${f.field} ${f.operator} ${(f.values || []).join(' | ')}`, h('button', { type: 'button', 'aria-label': 'Remove filter', onClick: () => { state.filters.splice(i, 1); reload(); } }, '×')));
    });
    if (state.filters.length > 0) chips.append(h('button', { class: 'btn ghost sm', onClick: () => { state.filters = []; reload(); } }, 'Clear all'));
  }

  async function addFilterDialog(preset) {
    const fieldSel = ctx.ui.dropdown(state.fields.map((f) => ({ value: f.path, label: `${f.label} (${f.path})` })), { value: preset?.field || '', ariaLabel: 'Field' });
    const opSel = ctx.ui.dropdown([['equals', 'equals'], ['notEquals', 'does not equal'], ['in', 'is one of (comma separated)'], ['notIn', 'is not one of'], ['prefix', 'starts with'], ['contains', 'contains'], ['exists', 'exists'], ['notExists', 'does not exist'], ['gt', 'greater than'], ['lt', 'less than']], { value: 'equals', ariaLabel: 'Operator' });
    const valueInput = h('input', { class: 'input', value: preset?.value || '', placeholder: 'value' });
    const box = h('div', { class: 'col' }, h('div', { class: 'field' }, h('label', null, 'Field'), fieldSel), h('div', { class: 'field' }, h('label', null, 'Operator'), opSel), h('div', { class: 'field' }, h('label', null, 'Value'), valueInput));
    valueInput.addEventListener('input', () => valueInput.classList.remove('invalid'));
    await ctx.ui.modal.show({ title: 'Add filter', content: box, actions: [{ label: 'Cancel', value: false }, { label: 'Add', kind: 'primary', onClick: () => {
      const op = opSel.value;
      const values = op.endsWith('xists') ? [] : (op === 'in' || op === 'notIn' ? valueInput.value.split(',').map((s) => s.trim()).filter(Boolean) : [valueInput.value.trim()]);
      if (!op.endsWith('xists') && values.length === 0) { ctx.ui.panelNote(box, 'A value is required.'); valueInput.classList.add('invalid'); return false; }
      state.filters.push({ field: fieldSel.value, operator: op, values });
      reload();
      return true;
    } }] });
  }

  function addQuickFilter(field, value) {
    if (value === undefined || value === null || value === '') return;
    state.filters.push({ field, operator: 'equals', values: [String(value)] });
    reload();
  }

  function buildBody(more) {
    const { from, to } = rangeToDates(state.range);
    const filters = [...state.filters];
    if (state.tenant) filters.push({ field: 'vc.tenantId', operator: 'equals', values: [state.tenant] });
    return { source, from, to, filters, text: state.text || null, size: pageSize, sort, searchAfter: more ? state.searchAfter : null };
  }

  function renderTable() {
    clear(results);
    const cols = columns.map((c) => ({
      title: c.title,
      class: c.class,
      render: (row) => {
        const doc = row.doc;
        let content = c.render ? c.render(doc, row) : (c.path ? get(doc, c.path) : '');
        if (content === undefined || content === null) content = '';
        if (c.filterField && content !== '' && !(content instanceof Node)) {
          const value = c.path ? get(doc, c.path) : content;
          return h('a', { href: '#', class: 'truncate', title: 'Filter by this value', onClick: (e) => { e.preventDefault(); e.stopPropagation(); addQuickFilter(c.filterField, value); } }, String(content));
        }
        return content;
      },
    }));
    results.append(table({ columns: cols, rows: state.hits, onRowClick: (row) => openDetail(row), emptyText: state.loading ? 'Loading…' : 'No events match.' }));
    clear(pager);
    pager.append(h('span', null, state.loading ? 'Loading…' : `${fmt.number(state.total)}${state.hits.length < state.total ? ` events · showing ${state.hits.length}` : ' events'}`));
    if (state.hits.length < state.total && state.searchAfter) pager.append(h('button', { class: 'btn sm', onClick: () => load(true) }, 'Load more'));
  }

  function openDetail(row) {
    const doc = row.doc;
    const pairs = [['Time', fmt.dateTime(doc['@timestamp'])], ['Tenant', get(doc, 'vc.tenantName') || get(doc, 'vc.tenantId')], ['Source', get(doc, 'vc.source')], ['Action', get(doc, 'event.action')], ['Outcome', get(doc, 'event.outcome')], ['Severity', get(doc, 'event.severity')], ['User', get(doc, 'user.name')], ['IP', get(doc, 'source.address')], ['Location', [get(doc, 'source.geo.city_name'), get(doc, 'source.geo.country_name')].filter(Boolean).join(', ')], ['App', get(doc, 'client.appName')], ['File / object', get(doc, 'file.path')], ['User agent', get(doc, 'user_agent.original')], ['Message', doc.message]];
    for (const f of detailFields) pairs.push([f.label, get(doc, f.path)]);
    const labels = doc.labels ? Object.entries(doc.labels).map(([k, v]) => [k, String(v)]) : [];
    drawer.open({ title: doc.message || get(doc, 'event.action') || 'Event', content: h('div', { class: 'col gap-lg' }, kv(pairs), labels.length ? h('div', null, h('h3', null, 'Labels'), kv(labels)) : null, h('details', { class: 'json', open: true }, h('summary', null, 'Raw record'), jsonView(doc.data || doc))) });
  }

  async function load(more) {
    state.loading = true;
    if (!more) { state.hits = []; state.total = 0; state.searchAfter = null; renderTable(); }
    try {
      const res = await ctx.api.post(`${ctx.module.apiBase}/search`, buildBody(more));
      state.hits = more ? state.hits.concat(res.hits) : res.hits;
      state.total = res.total;
      state.searchAfter = res.hits.length ? res.hits[res.hits.length - 1].sort : null;
    } catch (err) {
      clear(results).append(h('div', { class: 'alert ' + (err.status === 503 ? 'warning' : 'danger') }, err.status === 503 ? 'Search backend unavailable: ' + errorMessage(err) : errorMessage(err)));
      state.loading = false;
      return;
    }
    state.loading = false;
    renderTable();
  }

  function reload() { renderChips(); load(false); }

  reload();
  return { reload, addQuickFilter, state, destroy() { drawer.close(); } };
}
