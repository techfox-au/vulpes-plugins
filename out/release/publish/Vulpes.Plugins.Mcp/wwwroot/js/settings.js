export async function mount(el, ctx) {
  const { h, clear, table, fmt, badge, errorMessage, panelNote, copyToClipboard, modal } = ctx.ui;
  const root = el.querySelector('[data-role="root"]');
  const card = h('div', { class: 'card' });
  const list = h('div', { class: 'mt' });
  const name = h('input', { class: 'input', placeholder: 'Grok Bot', 'aria-label': 'Token name', maxlength: '80' });
  const revealed = h('div');
  card.append(
    h('div', { class: 'card-header' }, h('h2', null, 'Grok Bot')),
    h('p', { class: 'muted' }, 'The token is shown once and expires 90 days after it is created. The default mail recipients are emailed 10 days before that date. Each use is written to the audit trail. Installed plugins add their own tools. Send the token only to the HTTPS dashboard.'),
    h('p', { class: 'muted' }, 'MCP endpoint: /api/plugins/mcp'),
    h('div', { class: 'form-row' }, name, h('button', { class: 'btn', type: 'button', onClick: create }, 'Create token')),
    revealed,
    list,
  );
  root.append(card);
  load();

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

  async function load() {
    let rows;
    try { rows = await ctx.api.get(`${ctx.plugin.apiBase}/tokens`); }
    catch (err) { clear(list).append(h('div', { class: 'alert danger' }, errorMessage(err))); return; }
    clear(list).append(table({
      columns: [
        { title: 'Name', render: (r) => r.name },
        { title: 'Prefix', render: (r) => r.prefix },
        { title: 'Created', render: (r) => fmt.date(r.createdAt) },
        { title: 'Expires', render: expiry },
        { title: 'Last used', render: (r) => r.lastUsedAt ? fmt.relative(r.lastUsedAt) : 'never' },
        { title: '', render: (r) => h('div', { class: 'flex' }, r.revoked ? h('span', { class: 'badge' }, 'Revoked') : null, h('button', { class: 'btn sm danger', type: 'button', onClick: () => remove(r) }, 'Delete')) },
      ],
      rows,
      emptyText: 'No tokens yet.',
    }));
  }

  async function create() {
    clear(revealed);
    try {
      const created = await ctx.api.post(`${ctx.plugin.apiBase}/tokens`, { name: name.value.trim() || 'Grok Bot' });
      revealed.append(h('div', { class: 'alert success' },
        h('div', null, 'Copy this token now. It is not shown again.'),
        h('code', null, created.token),
        h('button', { class: 'btn ghost', type: 'button', onClick: () => copyToClipboard(created.token, card) }, 'Copy')));
      name.value = '';
      await load();
    } catch (err) {
      panelNote(card, errorMessage(err));
    }
  }

  async function remove(row) {
    if (!(await modal.confirm('Delete token', `Delete ${row.name}? Its token stops working.`, { danger: true, confirmLabel: 'Delete' }))) return;
    try {
      await ctx.api.delete(`${ctx.plugin.apiBase}/tokens/${row.id}`);
      await load();
    } catch (err) {
      panelNote(card, errorMessage(err));
    }
  }
}

export function unmount() {}
