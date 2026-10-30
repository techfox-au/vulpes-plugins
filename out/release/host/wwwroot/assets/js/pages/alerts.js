import { h, badge, fmt, table, modal, drawer, errorMessage, clear, jsonView, dropdown, panelNote, pageNote } from '../ui.js?v=shell84';
import { severityKind } from './home.js';

let root;
let catalog = null;
export async function mount(el, ctx) { root = el; ctx.setTitle(['Alerts']); catalog = await ctx.api.get('/api/alerts/catalog'); await render(ctx, { tab: ctx.query.tab || 'history' }); }
export function unmount() { root = null; catalog = null; }

const OPERATORS = [
  ['equals', 'equals'], ['notEquals', 'does not equal'], ['contains', 'contains'], ['startsWith', 'starts with'], ['in', 'is one of'], ['notIn', 'is not one of'],
  ['exists', 'exists'], ['notExists', 'does not exist'], ['gt', 'greater than'], ['lt', 'less than'], ['cidr', 'in CIDR range'], ['regex', 'matches regex'],
];
const SEVERITIES = ['informational', 'low', 'medium', 'high', 'critical'];

async function render(ctx, state) {
  clear(root);
  const isAdmin = ctx.hasRole('Admin');
  // Rules run on ingested events. Matches are stored and emailed (docs/audit-plugin.md, Notifications.cs).
  root.append(h('div', { class: 'page-header' },
    h('h1', null, 'Alerts'),
    isAdmin ? h('button', { class: 'btn primary', onClick: () => editRule(ctx, null) }, 'New rule') : null));

  const tabs = h('div', { class: 'tabs', role: 'tablist' },
    h('button', { class: 'tab' + (state.tab === 'history' ? ' active' : ''), onClick: () => render(ctx, { tab: 'history' }) }, 'History'),
    h('button', { class: 'tab' + (state.tab === 'rules' ? ' active' : ''), onClick: () => render(ctx, { tab: 'rules' }) }, 'Rules'));
  root.append(tabs);
  if (state.tab === 'rules') await renderRules(ctx, isAdmin); else await renderHistory(ctx, state);
}

async function renderRules(ctx, isAdmin) {
  const rules = await ctx.api.get('/api/alerts/rules');
  root.append(table({
    columns: [
      { title: 'Rule', render: (r) => h('div', null, h('div', null, h('strong', null, r.name), ' ', r.enabled ? null : badge('disabled', 'warning')), h('div', { class: 'small muted' }, r.description || '')) },
      { title: 'Scope', render: (r) => h('div', null, h('div', null, `${moduleName(r.moduleId)} · ${r.sources.join(', ')}`), h('div', { class: 'small muted' }, describeConditions(r))) },
      { title: 'Severity', render: (r) => badge(r.severity, severityKind(r.severity)) },
      { title: 'Threshold', render: (r) => r.threshold ? `≥ ${r.threshold.count} in ${r.threshold.windowMinutes} min${r.threshold.groupBy ? ` per ${r.threshold.groupBy}` : ''}` : h('span', { class: 'cell-muted' }, 'every match') },
      { title: 'Notify', render: (r) => h('span', { class: 'small' }, (r.actions?.email?.recipients || []).join(', ') || h('span', { class: 'cell-muted' }, 'default recipients')) },
      { title: '', class: 'right', render: (r) => isAdmin ? h('div', { class: 'btn-group' },
        h('button', { class: 'btn sm', onClick: () => editRule(ctx, r) }, 'Edit'),
        h('button', { class: 'btn sm', onClick: async () => { try { await ctx.api.post(`/api/alerts/rules/${r.id}/test`); pageNote(root, 'Test notification queued.', 'success'); } catch (err) { pageNote(root, errorMessage(err)); } } }, 'Test'),
        h('button', { class: 'btn sm danger', onClick: async () => {
          if (!(await modal.confirm('Delete rule', `Delete "${r.name}"?`, { danger: true, confirmLabel: 'Delete' }))) return;
          try { await ctx.api.delete(`/api/alerts/rules/${r.id}`); await render(ctx, { tab: 'rules' }); pageNote(root, 'Deleted.', 'success'); }
          catch (err) { pageNote(root, errorMessage(err)); }
        } }, 'Delete')) : null },
    ],
    rows: rules,
    emptyText: 'No rules.',
  }));
}

async function renderHistory(ctx, state) {
  const statusSel = dropdown([['', 'All statuses'], ['new', 'New'], ['acknowledged', 'Acknowledged']], { value: state.status || '', ariaLabel: 'Status' });
  statusSel.addEventListener('change', () => render(ctx, { ...state, status: statusSel.value, page: 1 }));
  root.append(h('div', { class: 'toolbar' }, statusSel, h('button', { class: 'btn sm', onClick: () => render(ctx, state) }, 'Refresh')));
  const data = await ctx.api.get('/api/alerts/instances' + ctx.api.qs({ page: state.page || 1, pageSize: 50, status: state.status }));
  root.append(table({
    columns: [
      { title: 'When', render: (a) => h('span', { class: 'nowrap' }, fmt.dateTime(a.createdAt)) },
      { title: 'Severity', render: (a) => badge(a.severity, severityKind(a.severity)) },
      { title: 'Rule', render: (a) => h('div', null, h('div', null, a.ruleName), h('div', { class: 'small muted' }, `${moduleName(a.moduleId)} · ${a.source}${a.tenantId ? ' · ' + a.tenantId : ''}`)) },
      { title: 'Summary', render: (a) => h('div', null, a.summary, a.count > 1 ? h('span', { class: 'muted small' }, ` (×${a.count}, last ${fmt.relative(a.lastEventAt)})`) : null) },
      { title: 'Status', render: (a) => a.status === 'new' ? badge('new', 'primary', true) : badge(`acknowledged by ${a.acknowledgedBy}`, '') },
      { title: '', class: 'right', render: (a) => a.status === 'new' ? h('button', { class: 'btn sm', onClick: async (e) => { e.stopPropagation(); await ctx.api.post(`/api/alerts/instances/${a.id}/acknowledge`); render(ctx, state); } }, 'Acknowledge') : null },
    ],
    rows: data.items,
    onRowClick: (a) => drawer.open({ title: a.summary, content: h('div', { class: 'col' }, h('div', { class: 'flex wrap' }, badge(a.severity, severityKind(a.severity)), badge(a.status), h('span', { class: 'muted small' }, `${a.ruleName} · event ${fmt.dateTime(a.eventTimestamp)}`)), a.eventJson ? jsonView(JSON.parse(a.eventJson)) : h('p', { class: 'muted' }, 'No event details stored.')) }),
    emptyText: 'No alerts recorded.',
  }));
  const pages = Math.max(1, Math.ceil(data.total / data.pageSize));
  root.append(h('div', { class: 'pager' }, h('span', null, `${fmt.number(data.total)} alerts · page ${data.page} of ${pages}`), h('div', { class: 'btn-group' },
    h('button', { class: 'btn sm', disabled: data.page <= 1, onClick: () => render(ctx, { ...state, page: data.page - 1 }) }, 'Previous'),
    h('button', { class: 'btn sm', disabled: data.page >= pages, onClick: () => render(ctx, { ...state, page: data.page + 1 }) }, 'Next'))));
}

function moduleName(id) { return catalog?.modules.find((m) => m.id === id)?.name || id; }

function describeConditions(rule) {
  if (!rule.conditions?.length) return 'any event';
  return rule.conditions.map((c) => `${c.field} ${OPERATORS.find((o) => o[0] === c.operator)?.[1] || c.operator} ${(c.values || []).join(' | ')}`).join(' AND ');
}

async function editRule(ctx, rule) {
  const modules = catalog.modules;
  if (modules.length === 0) { pageNote(root, 'No plugin has registered event sources yet.'); return; }
  const firstSource = (mod) => mod.sources.find((s) => !s.unavailable)?.source;
  const r = rule ? structuredClone(rule) : { name: '', description: '', enabled: true, moduleId: modules[0].id, sources: [firstSource(modules[0])].filter(Boolean), severity: 'medium', conditions: [], threshold: null, actions: { email: { recipients: [], subject: '', body: '' } }, throttle: null };

  const moduleSel = dropdown(modules.map((m) => ({ value: m.id, label: m.name })), { value: r.moduleId, ariaLabel: 'Plugin' });
  const sourcesBox = h('div', { class: 'flex wrap' });
  const conditionsBox = h('div', { class: 'col' });
  const currentModule = () => modules.find((m) => m.id === moduleSel.value);
  const fieldsForSources = () => {
    const mod = currentModule();
    const selected = [...sourcesBox.querySelectorAll('input:checked')].map((i) => i.value);
    const map = new Map();
    for (const s of mod.sources) if (selected.length === 0 || selected.includes(s.source)) for (const f of s.fields) if (!map.has(f.path)) map.set(f.path, f);
    return [...map.values()];
  };
  const renderSources = () => {
    clear(sourcesBox);
    for (const s of currentModule().sources) {
      const blocked = s.unavailable === true;
      const kept = blocked && r.sources.includes(s.source);
      sourcesBox.append(h('label', { class: 'checkbox', title: blocked ? 'Disabled in Microsoft 365 Business Premium mode' : undefined },
        h('input', { type: 'checkbox', value: s.source, checked: kept || (!blocked && r.sources.includes(s.source)), disabled: blocked, onChange: renderConditions }),
        h('span', null, s.title)));
    }
  };
  const conditionRow = (c) => {
    const fieldSel = dropdown(fieldsForSources().map((f) => ({ value: f.path, label: `${f.label} (${f.path})` })), { value: c.field || '', ariaLabel: 'Field' });
    const opSel = dropdown(OPERATORS.map(([value, label]) => ({ value, label })), { value: c.operator || 'equals', ariaLabel: 'Operator' });
    const valueInput = h('input', { class: 'input', value: (c.values || []).join(', '), placeholder: 'value(s), comma separated' });
    const row = h('div', { class: 'form-row' }, fieldSel, opSel, valueInput, h('button', { class: 'btn ghost sm', type: 'button', onClick: () => row.remove() }, 'Remove'));
    row.read = () => ({ field: fieldSel.value, operator: opSel.value, values: opSel.value.endsWith('xists') ? [] : valueInput.value.split(',').map((s) => s.trim()).filter(Boolean) });
    return row;
  };
  const renderConditions = () => { const existing = [...conditionsBox.children].map((row) => row.read?.()).filter(Boolean); clear(conditionsBox); for (const c of (existing.length ? existing : r.conditions)) conditionsBox.append(conditionRow(c)); };
  moduleSel.addEventListener('change', () => { r.sources = [firstSource(currentModule())].filter(Boolean); renderSources(); r.conditions = []; renderConditions(); });
  renderSources();
  renderConditions();

  const input = (label, value, attrs = {}) => { const i = h('input', { class: 'input', value: value ?? '', ...attrs }); return [h('div', { class: 'field' }, h('label', null, label), i), i]; };
  const [nameF, nameI] = input('Name', r.name, { required: true });
  const [descF, descI] = input('Description', r.description);
  const sevSel = dropdown(SEVERITIES.map((s) => ({ value: s, label: s })), { value: r.severity, ariaLabel: 'Severity' });
  const enabledCb = h('input', { type: 'checkbox', checked: r.enabled });
  const [thCountF, thCountI] = input('Threshold: count (blank = alert on every match)', r.threshold?.count ?? '', { type: 'number', min: 1 });
  const [thWinF, thWinI] = input('Threshold: window (minutes)', r.threshold?.windowMinutes ?? 10, { type: 'number', min: 1 });
  const [thGroupF, thGroupI] = input('Threshold: group by field', r.threshold?.groupBy ?? '', { placeholder: 'e.g. user.name' });
  const [recF, recI] = input('Email recipients (comma separated; blank = default recipients)', (r.actions?.email?.recipients || []).join(', '));
  const [subjF, subjI] = input('Email subject template', r.actions?.email?.subject || '', { placeholder: '[{{severity}}] {{rule.name}}: {{event.action}} by {{user.name}}' });
  // Body placeholders such as {{user.name}} are HTML-escaped (docs/security.md).
  const bodyI = h('textarea', { class: 'textarea', placeholder: '{{user.name}}' }, r.actions?.email?.body || '');
  const [throtWinF, throtWinI] = input('Throttle: at most one notification per (minutes)', r.throttle?.windowMinutes ?? '', { type: 'number', min: 1 });
  const [throtGroupF, throtGroupI] = input('Throttle: group by field', r.throttle?.groupBy ?? '', { placeholder: 'e.g. user.name' });

  const form = h('div', { class: 'col' },
    h('div', { class: 'form-row' }, nameF, descF),
    h('div', { class: 'form-row' }, h('div', { class: 'field' }, h('label', null, 'Plugin'), moduleSel), h('div', { class: 'field' }, h('label', null, 'Severity'), sevSel), h('label', { class: 'checkbox mt' }, enabledCb, h('span', null, 'Enabled'))),
    h('div', { class: 'field' }, h('label', null, 'Sources'), sourcesBox),
    h('div', { class: 'field' }, h('label', null, 'Conditions (all must match)'), conditionsBox, h('div', null, h('button', { class: 'btn sm', type: 'button', onClick: () => conditionsBox.append(conditionRow({ field: fieldsForSources()[0]?.path, operator: 'equals', values: [] })) }, 'Add condition'))),
    h('div', { class: 'form-row' }, thCountF, thWinF, thGroupF),
    h('div', { class: 'form-row' }, recF, subjF),
    h('div', { class: 'field' }, h('label', null, 'Email body template'), bodyI),
    h('div', { class: 'form-row' }, throtWinF, throtGroupF));

  const saved = await modal.show({ title: rule ? 'Edit rule' : 'New rule', content: form, wide: true, actions: [{ label: 'Cancel', value: false }, { label: 'Save', kind: 'primary', onClick: async () => {
    const payload = {
      name: nameI.value.trim(), description: descI.value.trim() || null, enabled: enabledCb.checked, moduleId: moduleSel.value,
      sources: [...sourcesBox.querySelectorAll('input:checked')].map((i) => i.value), severity: sevSel.value,
      conditions: [...conditionsBox.children].map((row) => row.read()),
      threshold: thCountI.value ? { count: Number(thCountI.value), windowMinutes: Number(thWinI.value || 10), groupBy: thGroupI.value.trim() || null } : null,
      actions: { email: { recipients: recI.value.split(',').map((s) => s.trim()).filter(Boolean), subject: subjI.value.trim() || null, body: bodyI.value.trim() || null } },
      throttle: throtWinI.value ? { windowMinutes: Number(throtWinI.value), groupBy: throtGroupI.value.trim() || null } : null,
    };
    if (!payload.name) { panelNote(form, 'A name is required.'); nameI.classList.add('invalid'); return false; }
    if (payload.sources.length === 0) { panelNote(form, 'Select at least one source.'); return false; }
    try { if (rule) await ctx.api.put(`/api/alerts/rules/${rule.id}`, payload); else await ctx.api.post('/api/alerts/rules', payload); return true; }
    catch (err) { panelNote(form, errorMessage(err)); return false; }
  } }] });
  if (saved) { await render(ctx, { tab: 'rules' }); pageNote(root, 'Rule saved.', 'success'); }
}
