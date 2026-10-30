import { h, fmt, table, clear, errorMessage } from '../ui.js?v=shell104';

let root;
export async function mount(el, ctx) { root = el; ctx.setTitle(['Audit trail']); await render(ctx, { page: 1 }); }
export function unmount() { root = null; }

function focusHref(id) {
  return '#/?focus=' + encodeURIComponent(id);
}

/** Ids still on this account's secret list. Anything else stays plain text. */
async function ownedSecretIds(ctx) {
  try {
    const data = await ctx.api.get('/api/plugins/secret-sharing/home');
    return new Set((data.items || []).map((item) => item.id).filter(Boolean));
  } catch {
    return new Set();
  }
}

function secretLink(id) {
  return h('a', { class: 'audit-resource-link mono', href: focusHref(id), title: 'Open on dashboard' }, id);
}

/** Wrap owned secret ids inside a details string. Longest id wins when one contains another. */
function linkify(text, owned) {
  const source = text || '';
  const ids = [...owned].filter((id) => source.includes(id)).sort((a, b) => b.length - a.length);
  if (!ids.length) return source;
  const frag = document.createDocumentFragment();
  let rest = source;
  while (rest) {
    let at = -1;
    let found = '';
    for (const id of ids) {
      const index = rest.indexOf(id);
      if (index !== -1 && (at === -1 || index < at)) { at = index; found = id; }
    }
    if (at === -1) { frag.append(rest); break; }
    if (at > 0) frag.append(rest.slice(0, at));
    frag.append(secretLink(found));
    rest = rest.slice(at + found.length);
  }
  return frag;
}

async function render(ctx, state) {
  clear(root);
  const filterAction = h('input', { class: 'input sm', placeholder: 'Action prefix (e.g. auth., user.)', value: state.action || '' });
  const filterActor = h('input', { class: 'input sm', placeholder: 'Actor', value: state.actor || '' });
  const apply = () => render(ctx, { page: 1, action: filterAction.value.trim(), actor: filterActor.value.trim() });
  for (const i of [filterAction, filterActor]) i.addEventListener('keydown', (e) => { if (e.key === 'Enter') apply(); });

  // Host audit trail: admin and authentication events, not Microsoft 365 activity (docs/security.md).
  root.append(h('div', { class: 'page-header' }, h('h1', null, 'Audit trail'),
    h('div', { class: 'toolbar' }, filterAction, filterActor, h('button', { class: 'btn', onClick: apply }, 'Filter'))));

  try {
    const [data, owned] = await Promise.all([
      ctx.api.get('/api/admin/audit' + ctx.api.qs({ page: state.page, pageSize: 25, action: state.action, actor: state.actor })),
      ownedSecretIds(ctx),
    ]);
    root.append(table({
      className: 'cols-audit',
      columns: [
        { title: 'When', render: (a) => h('span', { class: 'nowrap' }, fmt.dateTime(a.timestamp)) },
        { title: 'Actor', render: (a) => h('div', null, h('div', null, a.actor), h('div', { class: 'small muted' }, a.actorIp || '')) },
        { title: 'Action', render: (a) => h('code', null, a.action) },
        { title: 'Target', render: (a) => a.target && owned.has(a.target) ? secretLink(a.target) : (a.target || '') },
        { title: 'Details', render: (a) => h('span', { class: 'cell-muted' }, linkify(a.details, owned)) },
      ],
      rows: data.items,
      emptyText: 'No entries.',
    }));
    const pages = Math.max(1, Math.ceil(data.total / data.pageSize));
    root.append(h('div', { class: 'pager' }, h('span', null, `${fmt.number(data.total)} entries · page ${data.page} of ${pages}`),
      h('div', { class: 'btn-group' },
        h('button', { class: 'btn sm', disabled: data.page <= 1, onClick: () => render(ctx, { ...state, page: data.page - 1 }) }, 'Previous'),
        h('button', { class: 'btn sm', disabled: data.page >= pages, onClick: () => render(ctx, { ...state, page: data.page + 1 }) }, 'Next'))));
  } catch (err) {
    root.append(h('div', { class: 'alert danger' }, errorMessage(err)));
  }
}
