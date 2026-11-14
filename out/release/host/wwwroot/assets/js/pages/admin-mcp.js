import { h, badge, fmt, table, modal, errorMessage, clear, copyToClipboard, panelNote } from '../ui.js?v=shell379';
import { confirmIdentity } from '../reauth.js?v=shell258';

let root;
export async function mount(el, ctx) { root = el; ctx.setTitle(['MCP']); await render(ctx); }
export function unmount() { root = null; }

async function render(ctx) {
  clear(root);
  const settings = await ctx.api.get('/api/mcp/settings');
  const enabled = h('input', { type: 'checkbox', checked: settings.enabled === true, 'aria-label': 'MCP server enabled' });
  enabled.addEventListener('change', () => setEnabled(ctx, enabled, card));
  const card = h('div', { class: 'card' });
  const list = h('div', { class: 'mt' });
  const name = h('input', { class: 'input', placeholder: 'Grok Bot', 'aria-label': 'Token name', maxlength: '80' });
  const revealed = h('div');
  card.append(
    h('label', { class: 'checkbox' }, enabled, h('span', null, 'MCP server enabled')),
    h('p', { class: 'muted' }, 'While this is off, a connection to /api/mcp is closed with no response. Turning it on requires you to confirm it is you.'),
    h('div', { class: 'card-header' }, h('h2', null, 'Grok Bot')),
    h('p', { class: 'muted' }, 'The token is shown once and expires 90 days after it is created. The default mail recipients are emailed 10 days before that date. Each use is written to the audit trail. Installed plugins add their own tools. Send the token only to the HTTPS dashboard.'),
    h('p', { class: 'muted' }, 'MCP endpoint: /api/mcp'),
    h('div', { class: 'form-row' }, name, h('button', { class: 'btn', type: 'button', onClick: () => create(ctx, name, revealed, card, list) }, 'Create token')),
    revealed,
    list);
  root.append(card);
  await load(ctx, list);
}

function expiry(row) {
  if (!row.expiresAt) return '—';
  const when = new Date(row.expiresAt);
  const label = fmt.date(row.expiresAt);
  if (Number.isNaN(when.getTime())) return label;
  const days = Math.ceil((when.getTime() - Date.now()) / 86400000);
  if (days < 0) return h('span', null, label, ' ', badge('Expired', 'danger'));
  if (days <= 10) return h('span', null, label, ' ', badge(days === 1 ? 'Expires in 1 day' : `Expires in ${days} days`, 'warning'));
  return label;
}

async function setEnabled(ctx, box, card) {
  const enabled = box.checked;
  try {
    await ctx.api.put('/api/mcp/settings', { enabled });
  } catch (err) {
    if (err.code !== 'reauth_required') {
      box.checked = !enabled;
      panelNote(card, errorMessage(err));
      return;
    }
    const me = await ctx.api.get('/api/account');
    if (!(await confirmIdentity(ctx, me))) {
      box.checked = false;
      return;
    }
    try {
      await ctx.api.put('/api/mcp/settings', { enabled: true });
    } catch (again) {
      box.checked = false;
      panelNote(card, errorMessage(again));
    }
  }
}

async function load(ctx, list) {
  let rows;
  try { rows = await ctx.api.get('/api/mcp/tokens'); }
  catch (err) { clear(list).append(h('div', { class: 'alert danger' }, errorMessage(err))); return; }
  clear(list).append(table({
    columns: [
      { title: 'Name', render: (r) => r.name },
      { title: 'Prefix', render: (r) => r.prefix },
      { title: 'Created', render: (r) => fmt.date(r.createdAt) },
      { title: 'Expires', render: expiry },
      { title: 'Last used', render: (r) => r.lastUsedAt ? fmt.relative(r.lastUsedAt) : 'never' },
      { title: '', render: (r) => h('div', { class: 'flex' }, r.revoked ? badge('Revoked', 'danger') : null, h('button', { class: 'btn sm danger', type: 'button', onClick: () => remove(ctx, list, r) }, 'Delete')) },
    ],
    rows,
    emptyText: 'No tokens yet.',
  }));
}

async function create(ctx, name, revealed, card, list) {
  clear(revealed);
  try {
    const created = await ctx.api.post('/api/mcp/tokens', { name: name.value.trim() || 'Grok Bot' });
    revealed.append(h('div', { class: 'alert success' },
      h('div', null, 'Copy this token now. It is not shown again.'),
      h('code', null, created.token),
      h('button', { class: 'btn ghost', type: 'button', onClick: () => copyToClipboard(created.token, card) }, 'Copy')));
    name.value = '';
    await load(ctx, list);
  } catch (err) {
    panelNote(card, errorMessage(err));
  }
}

async function remove(ctx, list, row) {
  if (!(await modal.confirm('Delete token', `Delete ${row.name}? Its token stops working.`, { danger: true, confirmLabel: 'Delete' }))) return;
  try {
    await ctx.api.delete(`/api/mcp/tokens/${row.id}`);
    await load(ctx, list);
  } catch (err) {
    panelNote(list, errorMessage(err));
  }
}
