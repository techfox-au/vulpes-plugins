import { invalidateSession } from '../api.js';
import { h, badge, fmt, table, modal, setBusy, errorMessage, formValues, clear, kv, panelNote, pageNote, avatar, dropdown } from '../ui.js?v=shell184';
import * as webauthn from '../webauthn.js?v=shell127';
import { preparePasswordWrap, commitPasswordWrap, replaceAfterTemporaryPassword, unlockWithPasskey, dropPasskey } from '../data-key.js?v=shell213';
import { confirmIdentity as reauth } from '../reauth.js?v=shell258';

let root;
let flash;

export async function mount(el, ctx) {
  root = el;
  ctx.setTitle(['Account']);
  await render(ctx);
}

export function unmount() { root = null; }

const maxAvatarBytes = 500 * 1024;

async function uploadAvatar(ctx, input) {
  const file = input.files && input.files[0];
  if (!file) return;
  const name = file.name.toLowerCase();
  if (!/\.(webp|jpe?g|png)$/.test(name)) {
    pageNote(root, 'Choose a WebP, JPEG, or PNG image.');
    input.value = '';
    return;
  }
  if (file.size > maxAvatarBytes) {
    pageNote(root, 'The image must be 500 KB or smaller.');
    input.value = '';
    return;
  }
  try {
    const bitmap = await createImageBitmap(file);
    const tooBig = bitmap.width > 512 || bitmap.height > 512;
    bitmap.close();
    if (tooBig) {
      pageNote(root, 'The image must be 512×512 pixels or smaller.');
      input.value = '';
      return;
    }
  } catch {
    // The server still checks the file.
  }
  const body = new FormData();
  body.append('file', file);
  try {
    await ctx.api.upload('/api/account/avatar', body);
    if (ctx.refreshChrome) await ctx.refreshChrome();
    await render(ctx);
  } catch (err) {
    pageNote(root, errorMessage(err));
  }
}

const sessionLengths = [
  [900, '15m'],
  [1800, '30m'],
  [3600, '1h'],
  [7200, '2h'],
  [14400, '4h'],
  [28800, '8h'],
  [43200, '12h'],
  [86400, '1d'],
  [259200, '3d'],
  [604800, '7d'],
  [1209600, '14d'],
  [2592000, '30d'],
  [7776000, '90d'],
];

function sessionLength(ctx, current) {
  const control = dropdown(sessionLengths, { value: String(current || 28800), name: 'sessionLifetime', ariaLabel: 'Session length' });
  control.addEventListener('change', async () => {
    const seconds = Number(control.querySelector('input[name="sessionLifetime"]')?.value);
    const button = control.querySelector('button');
    if (button) button.disabled = true;
    try {
      const result = await ctx.api.put('/api/account/session-lifetime', { seconds });
      if (result?.signedOut) {
        invalidateSession();
        location.assign('/login');
        return;
      }
      if (button) button.disabled = false;
    } catch (err) {
      pageNote(root, errorMessage(err));
      if (button) button.disabled = false;
    }
  });
  return control;
}

function plusBadge() {
  const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
  svg.setAttribute('class', 'avatar-plus');
  svg.setAttribute('viewBox', '0 0 16 16');
  svg.setAttribute('aria-hidden', 'true');
  const circle = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
  circle.setAttribute('cx', '8');
  circle.setAttribute('cy', '8');
  circle.setAttribute('r', '8');
  circle.setAttribute('fill', 'var(--primary)');
  const plus = document.createElementNS('http://www.w3.org/2000/svg', 'path');
  plus.setAttribute('fill', 'var(--primary-contrast)');
  plus.setAttribute('d', 'M8.5 4.5a.5.5 0 0 0-1 0v3h-3a.5.5 0 0 0 0 1h3v3a.5.5 0 0 0 1 0v-3h3a.5.5 0 0 0 0-1h-3z');
  svg.append(circle, plus);
  return svg;
}

async function render(ctx) {
  const el = root;
  clear(el);
  const me = await ctx.api.get('/api/account');
  const passkeys = await ctx.api.get('/api/account/passkeys');
  if (root !== el) return;
  const pending = flash;
  flash = null;

  const roleLabel = me.roles.length === 1 ? 'Role' : 'Roles';
  const fileInput = h('input', { class: 'file-input-native', type: 'file', accept: '.webp,.jpg,.jpeg,.png,image/webp,image/jpeg,image/png', 'aria-label': 'Account image' });
  const editor = h('label', { class: 'avatar-edit' },
    fileInput,
    avatar(me.displayName || me.username, { large: true, updatedAt: me.avatarUpdatedAt }),
    plusBadge());
  fileInput.addEventListener('change', () => uploadAvatar(ctx, fileInput));
  fileInput.addEventListener('click', () => {
    window.addEventListener('focus', () => {
      fileInput.blur();
      editor.classList.add('plus-hidden');
      window.addEventListener('pointermove', () => editor.classList.remove('plus-hidden'), { once: true });
    }, { once: true });
  });
  el.append(h('div', { class: 'page-header' }, h('h1', null, 'Account')));
  const profileCard = h('div', { class: 'card', dataset: { panel: 'profile' } },
    editor,
    kv([['Display name', me.displayName || '—'], ['Username', me.username], ['Email', me.email || '—'], [roleLabel, me.roles.join(', ')]]));
  if (pending?.panel === 'profile') panelNote(profileCard, pending.message, pending.kind);
  el.append(h('div', { class: 'grid cols-2' },
    profileCard,
    h('div', { class: 'card' }, h('div', { class: 'card-header' }, h('h2', null, 'Session')),
      h('dl', { class: 'kv' },
        h('dt', null, 'Signed in with'), h('dd', null, { password: 'Password', pwd: 'Password', passkey: 'Passkey' }[me.authMethod] || '-'),
        h('dt', null, 'Last sign-in'), h('dd', null, fmt.dateTime(me.lastLoginAt)),
        h('dt', null, 'Recently authenticated'), h('dd', null, me.recentlyAuthenticated ? 'Yes' : 'No')),
      h('div', { class: 'field mt' }, h('label', null, 'Session length'), sessionLength(ctx, me.sessionLifetimeSeconds)))));

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
      { title: '', class: 'right', render: (p) => {
        const passwordActive = me.passwordSet && me.userPasswordLoginEnabled && me.passwordLoginAvailable;
        const lastWayIn = passkeys.length === 1 && !passwordActive;
        return h('div', { class: 'btn-group' },
          h('button', { class: 'btn sm', onClick: () => rename(ctx, p) }, 'Rename'),
          h('button', { class: 'btn sm danger', disabled: lastWayIn, title: lastWayIn ? 'Add another passkey or a password first.' : '', onClick: () => remove(ctx, p) }, 'Remove'));
      } },
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
  // Password controls stay available when the person turned password sign-in off. An administrator locking the account to passkeys removes them.
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
        if (me.mustChangePassword) await replaceAfterTemporaryPassword(v.newPassword);
        else await preparePasswordWrap(v.currentPassword || null);
        await ctx.api.post('/api/account/password', { currentPassword: v.currentPassword || null, newPassword: v.newPassword });
        if (!me.mustChangePassword) await commitPasswordWrap(v.newPassword);
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

async function setPasswordLogin(ctx, me, box) {
  await applyPasswordLogin(ctx, me, box, !box.checked);
}

async function applyPasswordLogin(ctx, me, box, enabled) {
  try {
    if (!enabled) {
      if (!webauthn.isSupported()) {
        box.checked = enabled;
        panelNote(document.querySelector('[data-panel="passkeys"]'), 'Passkeys are not supported in this browser.');
        return;
      }
      if (!(await reauth(ctx, me, { passkeyOnly: true }))) {
        box.checked = enabled;
        return;
      }
    }
    await ctx.api.patch('/api/account/password-login', { enabled });
    flash = { panel: 'passkeys', message: enabled ? 'Password sign-in enabled.' : 'Password sign-in disabled.', kind: 'success' };
    await render(ctx);
  } catch (err) {
    // The checkbox means "disable password sign-in", so put it back to the state before this attempt.
    box.checked = enabled;
    if (enabled && err.code === 'reauth_required') {
      if (await reauth(ctx, me)) return applyPasswordLogin(ctx, me, box, enabled);
      return;
    }
    panelNote(document.querySelector('[data-panel="passkeys"]'), webauthn.describeError(err) || errorMessage(err));
  }
}

async function addPasskey(ctx, btn) {
  const values = await modal.form('Add a passkey', [{ name: 'name', label: 'Name (e.g. "YubiKey 5C NFC")', value: 'Passkey', required: true }], { submitLabel: 'Continue' });
  if (!values) return;
  await registerPasskey(ctx, btn, values.name);
}

async function registerPasskey(ctx, btn, name) {
  setBusy(btn, true, 'Waiting for your passkey…');
  try {
    await webauthn.register({ optionsUrl: '/api/account/passkeys/options', finishUrl: '/api/account/passkeys', extra: { name }, onCredential: (credential) => unlockWithPasskey(credential) });
    flash = { panel: 'passkeys', message: 'Passkey added.', kind: 'success' };
    await render(ctx);
  } catch (err) {
    if (err.code === 'reauth_required') {
      const me = await ctx.api.get('/api/account');
      setBusy(btn, false);
      if (await reauth(ctx, me)) return registerPasskey(ctx, btn, name);
      return;
    }
    panelNote(document.querySelector('[data-panel="passkeys"]'), webauthn.describeError(err) || errorMessage(err));
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
  await deletePasskey(ctx, passkey);
}

async function deletePasskey(ctx, passkey) {
  try {
    await ctx.api.delete(`/api/account/passkeys/${encodeURIComponent(passkey.id)}`);
    await dropPasskey(passkey.id);
    flash = { panel: 'passkeys', message: 'Passkey removed.', kind: 'success' };
    await render(ctx);
  } catch (err) {
    if (err.code === 'reauth_required') {
      const me = await ctx.api.get('/api/account');
      if (await reauth(ctx, me)) return deletePasskey(ctx, passkey);
      return;
    }
    panelNote(document.querySelector('[data-panel="passkeys"]'), errorMessage(err));
  }
}
