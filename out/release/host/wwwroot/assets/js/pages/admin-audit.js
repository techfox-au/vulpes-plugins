import { h, fmt, table, clear, errorMessage } from '../ui.js?v=shell83';

let root;
export async function mount(el, ctx) { root = el; ctx.setTitle(['Audit trail']); await render(ctx, { page: 1 }); }
export function unmount() { root = null; }

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
    const data = await ctx.api.get('/api/admin/audit' + ctx.api.qs({ page: state.page, pageSize: 25, action: state.action, actor: state.actor }));
    root.append(table({
      columns: [
        { title: 'When', render: (a) => h('span', { class: 'nowrap' }, fmt.dateTime(a.timestamp)) },
        { title: 'Actor', render: (a) => h('div', null, h('div', null, a.actor), h('div', { class: 'small muted' }, a.actorIp || '')) },
        { title: 'Action', render: (a) => h('code', null, a.action) },
        { title: 'Target', key: 'target' },
        { title: 'Details', render: (a) => h('span', { class: 'cell-muted' }, a.details || '') },
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
