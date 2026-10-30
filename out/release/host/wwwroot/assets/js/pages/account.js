import { h, badge, fmt, table, modal, setBusy, errorMessage, formValues, clear, kv, panelNote } from '../ui.js?v=shell83';
import * as webauthn from '../webauthn.js?v=shell51';

let root;
let flash;

export async function mount(el, ctx) {
  root = el;
  ctx.setTitle(['Account']);
  await render(ctx);
}

export function unmount() { root = null; }

async function render(ctx) {
  const el = root;
  clear(el);
  const me = await ctx.api.get('/api/account');
  const passkeys = await ctx.api.get('/api/account/passkeys');
  if (root !== el) return;
  const pending = flash;
  flash = null;

  const roleLabel = me.roles.length === 1 ? 'Role' : 'Roles';
  el.append(h('div', { class: 'page-header' }, h('h1', null, 'Account')));
  el.append(h('div', { class: 'grid cols-2' },
    h('div', { class: 'card' }, kv([['Display name', me.displayName || '—'], ['Username', me.username], ['Email', me.email || '—'], [roleLabel, me.roles.join(', ')]])),
    h('div', { class: 'card' }, h('div', { class: 'card-header' }, h('h2', null, 'Session')),
      h('dl', { class: 'kv' },
        h('dt', null, 'Signed in with'), h('dd', null, { password: 'Password', pwd: 'Password', passkey: 'Passkey' }[me.authMethod] || '-'),
        h('dt', null, 'Last sign-in'), h('dd', null, fmt.dateTime(me.lastLoginAt)),
        h('dt', null, 'Recently authenticated'), h('dd', null, me.recentlyAuthenticated ? 'Yes' : 'No')))));

  if (me.mustChangePassword || ctx.query.changePassword) {
    el.append(h('div', { class: 'alert warning' }, 'You are using a temporary password. Please set a new one now.'));
  }

  const grid = h('div', { class: 'grid cols-2' });
  el.append(grid);

  // ---- passkeys
  const passkeyCard = h('div', { class: 'card' });
  passkeyCard.dataset.panel = 'passkeys';
  passkeyCard.append(h('div', { class: 'card-header' }, h('h2', null, 'Passkeys'), h('span', { class: 'muted small' }, `${passkeys.length} / ${me.maxPasskeys}`)));
  // Passkeys (YubiKey or platform) sign in without a password. Add/remove needs a sign-in within 5 minutes (docs/security.md).
  passkeyCard.append(table({
    columns: [
      { title: 'Name', render: (p) => h('div', null, h('div', null, p.name), h('div', { class: 'small muted' }, (p.transports || []).join(', '))) },
      { title: 'Added', render: (p) => fmt.date(p.createdAt) },
      { title: 'Backed up', render: (p) => badge(p.isBackedUp ? 'synced' : 'device-bound', p.isBackedUp ? 'info' : '') },
      { title: '', class: 'right', render: (p) => h('div', { class: 'btn-group' },
        h('button', { class: 'btn sm', onClick: () => rename(ctx, p) }, 'Rename'),
        h('button', { class: 'btn sm danger', onClick: () => remove(ctx, p) }, 'Remove')) },
    ],
    rows: passkeys,
    emptyText: 'No passkeys registered yet.',
  }));
  const addBtn = h('button', { class: 'btn primary mt', onClick: () => addPasskey(ctx, addBtn) }, 'Add a passkey');
  if (!webauthn.isSupported()) { addBtn.disabled = true; addBtn.textContent = 'Passkeys are not supported in this browser'; }
  passkeyCard.append(addBtn);
  if (me.passwordLoginAvailable) {
    const disablePassword = h('input', { type: 'checkbox', checked: !me.mustChangePassword && passkeys.length > 0 && !me.userPasswordLoginEnabled, disabled: me.mustChangePassword || passkeys.length === 0 });
    disablePassword.addEventListener('change', () => setPasswordLogin(ctx, me, disablePassword));
    passkeyCard.append(h('label', { class: 'checkbox mt' }, disablePassword, 'Disable password sign-in'));
  }
  grid.append(passkeyCard);

  // ---- password
  const passwordCard = h('div', { class: 'card' });
  passwordCard.dataset.panel = 'password';
  passwordCard.append(h('div', { class: 'card-header' }, h('h2', null, 'Password')));
  // A disabled password means passkey-only (docs/security.md).
  if (me.passwordLoginAvailable) {
    const form = h('form', { class: 'col', novalidate: true });
    if (me.passwordSet) form.append(field('Current password', 'currentPassword', 'current-password'));
    form.append(field('New password', 'newPassword', 'new-password'), field('Repeat new password', 'repeat', 'new-password'));
    const submit = h('button', { class: 'btn primary', type: 'submit' }, me.passwordSet ? 'Change password' : 'Set password');
    form.append(h('div', { class: 'form-actions' }, submit));
    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      const v = formValues(form);
      panelNote(passwordCard, '');
      if (v.newPassword.length < 12) { panelNote(passwordCard, 'Use at least 12 characters.'); return; }
      if (v.newPassword !== v.repeat) { panelNote(passwordCard, 'The passwords do not match.'); return; }
      setBusy(submit, true, 'Saving…');
      try {
        await ctx.api.post('/api/account/password', { currentPassword: v.currentPassword || null, newPassword: v.newPassword });
        if (me.mustChangePassword) { location.assign('/'); return; }
        flash = { panel: 'password', message: 'Password updated.', kind: 'success' };
        await render(ctx);
      } catch (err) {
        if (err.code === 'reauth_required') { if (await reauth(ctx, me)) { form.requestSubmit(); } }
        else panelNote(passwordCard, errorMessage(err));
      } finally { setBusy(submit, false); }
    });
    passwordCard.append(form);
    grid.append(passwordCard);
  }

  if (pending?.panel === 'password') panelNote(passwordCard, pending.message, pending.kind);
  if (pending?.panel === 'passkeys') panelNote(passkeyCard, pending.message, pending.kind);
}

function field(label, name, autocomplete) {
  return h('div', { class: 'field' }, h('label', null, label), h('input', { class: 'input', type: 'password', name, autocomplete }));
}

async function reauth(ctx, me, { passkeyOnly = false } = {}) {
  const hasPassword = !passkeyOnly && me.passwordSet && me.passwordLoginEnabled;
  const container = h('div', { class: 'col' });
  let done = false;
  const modalError = h('div', { class: 'alert danger hidden', role: 'alert' });
  const showModalError = (message) => { modalError.textContent = message; modalError.classList.remove('hidden'); };
  const passwordInput = h('input', { class: 'input', type: 'password', autocomplete: 'current-password', placeholder: 'Current password' });
  if (hasPassword) container.append(h('div', { class: 'field' }, h('label', null, 'Password'), passwordInput));
  container.append(modalError);
  const passkeyBtn = h('button', { class: 'btn', type: 'button' }, passkeyOnly ? 'Use a passkey' : 'Use a passkey instead');
  if (me.passkeyCount > 0 && webauthn.isSupported()) container.append(passkeyBtn);
  const result = await new Promise((resolve) => {
    passkeyBtn.addEventListener('click', async () => {
      setBusy(passkeyBtn, true, 'Waiting for your key…');
      try { await webauthn.authenticate({ optionsUrl: '/api/account/reauth/passkey/options', finishUrl: '/api/account/reauth/passkey' }); done = true; document.querySelector('.modal-card')?.closeModal(true); }
      catch (err) { showModalError(webauthn.describeError(err) || errorMessage(err)); }
      finally { setBusy(passkeyBtn, false); }
    });
    modal.show({ title: 'Confirm it is you', content: container, actions: [
      { label: 'Cancel', value: false },
      ...(hasPassword ? [{ label: 'Confirm', kind: 'primary', onClick: async () => { try { await ctx.api.post('/api/account/reauth/password', { password: passwordInput.value }); done = true; return true; } catch (err) { showModalError(err.status === 401 ? 'Incorrect password.' : errorMessage(err)); return false; } } }] : []),
    ] }).then(resolve);
  });
  return done || result === true;
}

async function setPasswordLogin(ctx, me, box) {
  const enabled = !box.checked;
  try {
    if (!enabled) {
      if (!webauthn.isSupported()) {
        box.checked = false;
        panelNote(document.querySelector('[data-panel="passkeys"]'), 'Passkeys are not supported in this browser.');
        return;
      }
      if (!(await reauth(ctx, me, { passkeyOnly: true }))) {
        box.checked = false;
        return;
      }
    }
    await ctx.api.patch('/api/account/password-login', { enabled });
    flash = { panel: 'passkeys', message: enabled ? 'Password sign-in enabled.' : 'Password sign-in disabled.', kind: 'success' };
    await render(ctx);
  } catch (err) {
    box.checked = !box.checked;
    if (enabled && err.code === 'reauth_required') {
      if (await reauth(ctx, me)) return setPasswordLogin(ctx, me, box);
    } else {
      panelNote(document.querySelector('[data-panel="passkeys"]'), webauthn.describeError(err) || errorMessage(err));
    }
  }
}

async function addPasskey(ctx, btn) {
  const values = await modal.form('Add a passkey', [{ name: 'name', label: 'Name (e.g. "YubiKey 5C NFC")', value: 'Passkey', required: true }], { submitLabel: 'Continue' });
  if (!values) return;
  setBusy(btn, true, 'Waiting for your passkey…');
  try {
    await webauthn.register({ optionsUrl: '/api/account/passkeys/options', finishUrl: '/api/account/passkeys', extra: { name: values.name } });
    flash = { panel: 'passkeys', message: 'Passkey added.', kind: 'success' };
    await render(ctx);
  } catch (err) {
    if (err.code === 'reauth_required') {
      const me = await ctx.api.get('/api/account');
      if (await reauth(ctx, me)) { setBusy(btn, false); return addPasskey(ctx, btn); }
    } else {
      panelNote(document.querySelector('[data-panel="passkeys"]'), webauthn.describeError(err) || errorMessage(err));
    }
  } finally { setBusy(btn, false); }
}

async function rename(ctx, passkey) {
  const values = await modal.form('Rename passkey', [{ name: 'name', label: 'Name', value: passkey.name, required: true }]);
  if (!values) return;
  try {
    await ctx.api.patch(`/api/account/passkeys/${encodeURIComponent(passkey.id)}`, { name: values.name });
    flash = { panel: 'passkeys', message: 'Renamed.', kind: 'success' };
    await render(ctx);
  } catch (err) { panelNote(document.querySelector('[data-panel="passkeys"]'), errorMessage(err)); }
}

async function remove(ctx, passkey) {
  if (!(await modal.confirm('Remove passkey', `Remove "${passkey.name}"? You will no longer be able to sign in with it.`, { danger: true, confirmLabel: 'Remove' }))) return;
  try {
    await ctx.api.delete(`/api/account/passkeys/${encodeURIComponent(passkey.id)}`);
    flash = { panel: 'passkeys', message: 'Passkey removed.', kind: 'success' };
    await render(ctx);
  } catch (err) {
    if (err.code === 'reauth_required') { const me = await ctx.api.get('/api/account'); if (await reauth(ctx, me)) return remove(ctx, passkey); }
    else panelNote(document.querySelector('[data-panel="passkeys"]'), errorMessage(err));
  }
}
