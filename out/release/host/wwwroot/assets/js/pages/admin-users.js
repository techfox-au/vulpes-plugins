import { h, badge, fmt, table, modal, drawer, errorMessage, clear, copyToClipboard, kv, panelNote, pageNote } from '../ui.js?v=shell84';

let root;
export async function mount(el, ctx) { root = el; ctx.setTitle(['Users']); await render(ctx); }
export function unmount() { root = null; }

const roleOptions = [{ value: 'Viewer', label: 'Viewer' }, { value: 'Analyst', label: 'Analyst' }, { value: 'Admin', label: 'Admin' }];

async function render(ctx) {
  clear(root);
  const users = await ctx.api.get('/api/admin/users');
  // Accounts are created here and enrolled with a single-use link (docs/security.md).
  root.append(h('div', { class: 'page-header' },
    h('h1', null, 'Users'),
    h('button', { class: 'btn primary', onClick: () => createUser(ctx) }, 'New user')));

  root.append(table({
    columns: [
      { title: 'User', render: (u) => h('div', null, h('div', null, h('strong', null, u.displayName || u.username)), h('div', { class: 'small muted' }, u.username)) },
      { title: 'Role', render: (u) => badge(u.role || '-', u.role === 'Admin' ? 'primary' : '') },
      { title: 'Sign-in', render: (u) => h('div', { class: 'flex wrap' },
        u.passwordSet ? badge(u.mustChangePassword ? 'temp password' : 'password', u.mustChangePassword ? 'warning' : '') : null,
        u.passkeyCount > 0 ? badge(`${u.passkeyCount} passkey${u.passkeyCount > 1 ? 's' : ''}`, 'success') : null,
        !u.passwordSet && u.passkeyCount === 0 ? badge('not enrolled', 'warning') : null) },
      { title: 'Status', render: (u) => u.isActive ? (u.lockedOut ? badge('locked', 'danger', true) : badge('active', 'success', true)) : badge('disabled', 'danger', true) },
      { title: 'Last login', render: (u) => h('span', { class: 'cell-muted' }, u.lastLoginAt ? `${fmt.relative(u.lastLoginAt)} (${u.lastLoginMethod})` : 'never') },
    ],
    rows: users,
    onRowClick: (u) => openUser(ctx, u.id),
    emptyText: 'No users.',
  }));
}

async function createUser(ctx) {
  const res = await modal.form('New user', [
    { name: 'username', label: 'Username', required: true, autocomplete: 'off' },
    { name: 'displayName', label: 'Display name' },
    { name: 'email', label: 'Email (for notifications)', type: 'email' },
    { name: 'role', label: 'Role', type: 'select', options: roleOptions, value: 'Viewer' },
    { name: 'passwordLoginEnabled', label: 'Allow password sign-in (otherwise passkey only)', type: 'checkbox', value: true },
  ], {
    submitLabel: 'Create',
    onSubmit: (values) => ctx.api.post('/api/admin/users', { ...values, email: values.email || null }),
  });
  if (!res) return;
  await showEnrollmentLink(res.enrollment, res.user.username);
  await render(ctx);
}

async function showEnrollmentLink(enrollment, username) {
  const input = h('input', { class: 'input mono', readonly: true, value: enrollment.url });
  await modal.show({
    title: 'Enrollment link',
    content: h('div', { class: 'col' },
      h('p', null, `Send this link to ${username} through a trusted channel. It can be used once and expires ${fmt.relative(enrollment.expiresAt)}. It will not be shown again.`),
      input,
      h('button', { class: 'btn', onClick: () => copyToClipboard(enrollment.url) }, 'Copy link')),
    actions: [{ label: 'Done', kind: 'primary' }],
  });
}

async function openUser(ctx, id, note) {
  const { user, passkeys } = await ctx.api.get(`/api/admin/users/${encodeURIComponent(id)}`);
  const body = h('div', { class: 'col gap-lg' });
  if (note) panelNote(body, note.message, note.kind);

  body.append(kv([
    ['Username', user.username], ['Display name', user.displayName], ['Email', user.email], ['Role', user.role],
    ['Created', fmt.dateTime(user.createdAt)], ['Last login', user.lastLoginAt ? `${fmt.dateTime(user.lastLoginAt)} via ${user.lastLoginMethod}` : 'never'],
    ['Status', user.isActive ? 'Active' : 'Disabled'], ['Locked out', user.lockedOut ? `until ${fmt.dateTime(user.lockoutEnd)}` : 'No'],
  ]));

  const actions = h('div', { class: 'btn-group' });
  actions.append(h('button', { class: 'btn', onClick: () => editUser(ctx, user) }, 'Edit'));
  actions.append(h('button', { class: 'btn', onClick: async () => {
    if (!(await modal.confirm('Issue recovery link', `Create a new single-use enrollment link for ${user.username}? Any previous unused link is revoked.`))) return;
    try { const res = await ctx.api.post(`/api/admin/users/${encodeURIComponent(id)}/enrollment-link`); drawer.close(); await showEnrollmentLink(res, user.username); } catch (err) { panelNote(body, errorMessage(err)); }
  } }, 'Recovery link'));
  actions.append(h('button', { class: 'btn', onClick: async () => {
    if (!(await modal.confirm('Set temporary password', `Replace ${user.username}'s password with a random temporary one? They must change it at next sign-in and existing sessions are revoked.`))) return;
    try {
      const res = await ctx.api.post(`/api/admin/users/${encodeURIComponent(id)}/temporary-password`);
      const input = h('input', { class: 'input mono', readonly: true, value: res.temporaryPassword });
      await modal.show({ title: 'Temporary password', content: h('div', { class: 'col' }, h('p', null, 'Share it through a trusted channel. It is shown only once.'), input, h('button', { class: 'btn', onClick: () => copyToClipboard(res.temporaryPassword) }, 'Copy')), actions: [{ label: 'Done', kind: 'primary' }] });
      drawer.close(); await render(ctx);
    } catch (err) { panelNote(body, errorMessage(err)); }
  } }, 'Temporary password'));
  if (user.lockedOut) actions.append(h('button', { class: 'btn', onClick: async () => {
    try { await ctx.api.post(`/api/admin/users/${encodeURIComponent(id)}/unlock`); drawer.close(); await render(ctx); pageNote(root, 'Unlocked.', 'success'); }
    catch (err) { panelNote(body, errorMessage(err)); }
  } }, 'Unlock'));
  actions.append(h('button', { class: 'btn', onClick: async () => {
    if (!(await modal.confirm('Revoke sessions', 'Sign this user out everywhere?'))) return;
    try { await ctx.api.post(`/api/admin/users/${encodeURIComponent(id)}/revoke-sessions`); panelNote(body, 'Sessions revoked.', 'success'); }
    catch (err) { panelNote(body, errorMessage(err)); }
  } }, 'Revoke sessions'));
  actions.append(h('button', { class: 'btn ' + (user.isActive ? 'danger' : 'primary'), onClick: async () => {
    try {
      await ctx.api.patch(`/api/admin/users/${encodeURIComponent(id)}`, { isActive: !user.isActive });
      const message = user.isActive ? 'Account disabled.' : 'Account enabled.';
      drawer.close(); await render(ctx); pageNote(root, message, 'success');
    } catch (err) { panelNote(body, errorMessage(err)); }
  } }, user.isActive ? 'Disable' : 'Enable'));
  actions.append(h('button', { class: 'btn danger', onClick: async () => {
    if (!(await modal.confirm('Delete user', `Permanently delete ${user.username}? This cannot be undone.`, { danger: true, confirmLabel: 'Delete' }))) return;
    try { await ctx.api.delete(`/api/admin/users/${encodeURIComponent(id)}`); drawer.close(); await render(ctx); pageNote(root, 'User deleted.', 'success'); }
    catch (err) { panelNote(body, errorMessage(err)); }
  } }, 'Delete'));
  body.append(actions);

  body.append(h('h3', null, 'Passkeys'), table({
    columns: [
      { title: 'Name', key: 'name' },
      { title: 'Added', render: (p) => fmt.date(p.createdAt) },
      { title: 'Transports', render: (p) => (p.transports || []).join(', ') },
      { title: '', class: 'right', render: (p) => h('button', { class: 'btn sm danger', onClick: async () => {
        if (!(await modal.confirm('Revoke passkey', `Revoke "${p.name}"? The user's sessions are also revoked.`, { danger: true, confirmLabel: 'Revoke' }))) return;
        try { await ctx.api.delete(`/api/admin/users/${encodeURIComponent(id)}/passkeys/${encodeURIComponent(p.id)}`); openUser(ctx, id, { message: 'Passkey revoked.', kind: 'success' }); } catch (err) { panelNote(body, errorMessage(err)); }
      } }, 'Revoke') },
    ],
    rows: passkeys,
    emptyText: 'No passkeys.',
  }));

  drawer.open({ title: user.displayName || user.username, content: body });
}

async function editUser(ctx, user) {
  const fields = [
    { name: 'displayName', label: 'Display name', value: user.displayName || '' },
    { name: 'email', label: 'Email', type: 'email', value: user.email || '' },
    { name: 'role', label: 'Role', type: 'select', options: roleOptions, value: user.role },
    { name: 'passwordLoginEnabled', label: 'Allow password sign-in', type: 'checkbox', value: user.passwordLoginEnabled },
  ];
  const values = await modal.form('Edit user', fields, {
    onSubmit: (v) => ctx.api.patch(`/api/admin/users/${encodeURIComponent(user.id)}`, { displayName: v.displayName, email: v.email || '', role: v.role, passwordLoginEnabled: v.passwordLoginEnabled }),
  });
  if (!values) return;
  drawer.close();
  await render(ctx);
  pageNote(root, 'Saved.', 'success');
}
