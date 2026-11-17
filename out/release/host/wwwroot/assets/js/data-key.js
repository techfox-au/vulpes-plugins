// Every account gets a user data key when its first credential is added, whether or not a plugin is installed.
// A later password or passkey wraps that same key. Sign-in only unwraps a wrap that already exists.
import { api } from './api.js';

const BASE = '/api/account/data-key';

// Set by webauthn.register while an enrollment passkey ceremony is in progress. Null the rest of the time.
let enrollmentToken = null;
let enrollmentWrapStored = false;

export function armEnrollment(token) {
  enrollmentToken = token || null;
  enrollmentWrapStored = false;
}

function rememberEnrollmentWrap() {
  if (enrollmentToken) enrollmentWrapStored = true;
}

function loadScript() {
  if (window.SecretUdk && window.SecretUdk.ready) return window.SecretUdk.ready();
  return new Promise((resolve, reject) => {
    const s = document.createElement('script');
    s.src = '/assets/js/udk.js?v=udk6';
    s.onload = () => window.SecretUdk.ready().then(resolve, reject);
    s.onerror = () => reject(new Error('Could not load encryption.'));
    document.head.append(s);
  });
}

function wrapsOf(pack) {
  const wraps = Array.isArray(pack?.wraps) ? pack.wraps.slice() : [];
  if (pack?.wrappedUserDataKey && !wraps.some((wrap) => wrap.kind === 'password')) {
    wraps.push({ kind: 'legacy', wrapped: pack.wrappedUserDataKey });
  }
  return wraps;
}

async function save(kind, wrapped, credentialId) {
  await api.put(BASE, { kind, credentialId: credentialId || null, wrapped });
}

async function accountId() {
  const me = await api.get('/api/account');
  if (!me?.id) throw new Error('Could not load encryption.');
  return me.id;
}

async function passwordMaterial(wraps, password, userId) {
  let udk = window.SecretUdk.loadUserDataKey(userId);
  if (udk && !(await window.SecretUdk.canRewrap())) udk = null;
  const passwordWrap = wraps.find((wrap) => wrap.kind === 'password');
  const legacy = wraps.find((wrap) => wrap.kind === 'legacy');
  if (!udk && passwordWrap) {
    try { udk = await window.SecretUdk.unwrapUserDataKey(passwordWrap.wrapped, password); } catch { /* not this password */ }
  }
  if (!udk && legacy) {
    try { udk = await window.SecretUdk.unwrapUserDataKey(legacy.wrapped, password); } catch { /* older wrap password */ }
  }
  return { udk, passwordWrap };
}

/** First password on the account. Creates the key only in the same step that stores its wrap. */
export async function establishWithPassword(password) {
  if (!password) return;
  await loadScript();
  const userId = await accountId();
  const wraps = wrapsOf(await api.get(BASE));
  const found = await passwordMaterial(wraps, password, userId);
  if (found.udk) {
    if (!found.passwordWrap) await save('password', await window.SecretUdk.wrapUserDataKey(found.udk, password));
    await window.SecretUdk.storeUserDataKey(found.udk, userId);
    return;
  }
  if (wraps.length > 0) throw new Error('This password could not unlock the existing encryption key.');
  const udk = await window.SecretUdk.generateUserDataKey();
  await save('password', await window.SecretUdk.wrapUserDataKey(udk, password));
  await window.SecretUdk.storeUserDataKey(udk, userId);
}

/** First passkey on the account. No key is created when the authenticator cannot wrap it. */
export async function establishWithPasskey(credential) {
  if (!credential) return;
  await loadScript();
  const prf = prfBytes(credential);
  if (!prf) throw new Error('This passkey cannot protect encryption. Use one that supports the PRF extension.');
  const credentialId = credential.id;
  const userId = await accountId();
  const wraps = wrapsOf(await api.get(BASE));
  const existing = wraps.find((wrap) => wrap.kind === 'passkey' && wrap.credentialId === credentialId);
  let udk = window.SecretUdk.loadUserDataKey(userId);
  if (udk && !(await window.SecretUdk.canRewrap())) udk = null;
  if (!udk && existing) {
    try { udk = await window.SecretUdk.unwrapUserDataKeyWithPrf(existing.wrapped, prf); }
    catch { throw new Error('This passkey could not unlock encryption.'); }
  }
  if (udk) {
    if (!existing) {
      await save('passkey', await window.SecretUdk.wrapUserDataKeyWithPrf(udk, prf), credentialId);
      rememberEnrollmentWrap();
    }
    await window.SecretUdk.storeUserDataKey(udk, userId);
    return;
  }
  if (wraps.length > 0) {
    // Recovery: this passkey cannot open a wrap that is already stored. One call saves the new wrap and drops the others.
    if (!enrollmentToken) throw new Error('This passkey could not unlock the existing encryption key.');
    udk = await window.SecretUdk.generateUserDataKey();
    await api.post('/auth/enroll/passkey/wrap', {
      token: enrollmentToken,
      credentialId,
      wrapped: await window.SecretUdk.wrapUserDataKeyWithPrf(udk, prf),
    });
    rememberEnrollmentWrap();
    await window.SecretUdk.storeUserDataKey(udk, userId);
    return;
  }
  udk = await window.SecretUdk.generateUserDataKey();
  await save('passkey', await window.SecretUdk.wrapUserDataKeyWithPrf(udk, prf), credentialId);
  rememberEnrollmentWrap();
  await window.SecretUdk.storeUserDataKey(udk, userId);
}

/** Gives back the enrollment link and drops the new passkey when its wrap was not stored. A passkey that still has a wrap is left signed in. */
export async function abandonEnrollment(credential) {
  const token = enrollmentToken;
  const id = credential?.id;
  const wrapStored = enrollmentWrapStored;
  let hasWrap = false;
  if (id) {
    try {
      const wraps = wrapsOf(await api.get(BASE));
      hasWrap = wraps.some((wrap) => wrap.kind === 'passkey' && wrap.credentialId === id);
    } catch {
      // The lookup did not return a wrap. Release unless this attempt's wrap POST already succeeded.
      hasWrap = wrapStored;
    }
  }
  if (hasWrap) return;
  if (token) {
    try { await api.post('/auth/enroll/release', { token, credentialId: id || null }); } catch { /* already usable, or the session ended */ }
  }
  if (!id) return;
  try { await api.delete(`/api/account/passkeys/${encodeURIComponent(id)}`); } catch { /* the last sign-in cannot be removed here */ }
}

/** This tab has no key. Ask for the password or passkey that already wraps it, and keep the dialog open until it unwraps. */
export async function requireUserDataKey() {
  await loadScript();
  const userId = await accountId();
  const existing = window.SecretUdk.loadUserDataKey(userId);
  if (existing) return existing;
  const [pack, me] = await Promise.all([api.get(BASE), api.get('/api/account')]);
  const wraps = wrapsOf(pack);
  const passwordAllowed = me.passwordLoginEnabled === true;
  const hasPassword = passwordAllowed && wraps.some((wrap) => wrap.kind === 'password' || wrap.kind === 'legacy');
  const hasPasskey = me.passkeyCount > 0 || wraps.some((wrap) => wrap.kind === 'passkey');
  if (!hasPassword && !hasPasskey) {
    throw new Error(passwordAllowed
      ? 'This account has no encryption key. Add a password or passkey on the account page, then try again.'
      : 'This account has no passkey that can unlock encryption.');
  }
  if (hasPassword) {
    const { modal } = await import('./ui.js?v=shell104');
    const unlocked = await modal.form('Unlock encryption', [
      { name: 'password', label: 'Account password', type: 'password', required: true, autocomplete: 'current-password' },
    ], {
      submitLabel: 'Unlock',
      onSubmit: async (values) => {
        await unlockWithPassword(values.password);
        if (!window.SecretUdk.loadUserDataKey(userId)) throw new Error('Could not unlock encryption. Check your password and try again.');
      },
    });
    if (!unlocked) throw new Error('Password required to unlock encryption.');
    return window.SecretUdk.loadUserDataKey(userId);
  }
  const { modal } = await import('./ui.js?v=shell104');
  const agreed = await modal.confirm('Unlock encryption', 'Use your passkey to unlock encryption in this browser tab.', { confirmLabel: 'Use passkey' });
  if (!agreed) throw new Error('Passkey required to unlock encryption.');
  const webauthn = await import('./webauthn.js?v=shell407');
  await webauthn.authenticate({ optionsUrl: '/api/account/reauth/passkey/options', finishUrl: '/api/account/reauth/passkey', onCredential: (credential) => unlockWithPasskey(credential) });
  const udk = window.SecretUdk.loadUserDataKey(userId);
  if (!udk) throw new Error('This passkey could not unlock encryption.');
  return udk;
}

export async function unlockWithPassword(password) {
  if (!password) return;
  await loadScript();
  const userId = await accountId();
  const wraps = wrapsOf(await api.get(BASE));
  if (wraps.length === 0) {
    window.SecretUdk.clearUserDataKey();
    return;
  }
  const found = await passwordMaterial(wraps, password, userId);
  if (found.udk) await window.SecretUdk.storeUserDataKey(found.udk, userId);
}

/** After a temporary password is replaced. The previous key was destroyed, so this always creates a new one. */
export async function replaceAfterTemporaryPassword(newPassword) {
  if (!newPassword) return;
  await loadScript();
  const userId = await accountId();
  let udk = window.SecretUdk.loadUserDataKey(userId);
  if (!udk) {
    udk = await window.SecretUdk.generateUserDataKey();
    await window.SecretUdk.storeUserDataKey(udk, userId);
  }
  await save('password', await window.SecretUdk.wrapUserDataKey(udk, newPassword));
  await window.SecretUdk.storeUserDataKey(udk, userId);
}

export async function unlockWithPasskey(credential) {
  if (!credential) return;
  await loadScript();
  const prf = prfBytes(credential);
  if (!prf) throw new Error('This passkey cannot unlock encryption. Use one that supports the PRF extension, or sign in with a password.');
  const credentialId = credential.id;
  const userId = await accountId();
  const wraps = wrapsOf(await api.get(BASE));
  const existing = wraps.find((wrap) => wrap.kind === 'passkey' && wrap.credentialId === credentialId);
  let udk = window.SecretUdk.loadUserDataKey(userId);
  if (udk && !(await window.SecretUdk.canRewrap())) udk = null;
  if (!udk && existing) {
    try { udk = await window.SecretUdk.unwrapUserDataKeyWithPrf(existing.wrapped, prf); }
    catch { throw new Error('This passkey could not unlock encryption.'); }
  }
  if (!udk) throw new Error('This passkey could not unlock encryption.');
  if (!existing) await save('passkey', await window.SecretUdk.wrapUserDataKeyWithPrf(udk, prf), credentialId);
  await window.SecretUdk.storeUserDataKey(udk, userId);
}

/** Puts raw key bytes back so a new passkey can wrap the same key. Nothing is saved yet. */
export async function preparePasskeyWrap() {
  await loadScript();
  const userId = await accountId();
  let udk = window.SecretUdk.loadUserDataKey(userId);
  if (udk && await window.SecretUdk.canRewrap()) return;
  const wraps = wrapsOf(await api.get(BASE));
  udk = null;
  const passwordWrap = wraps.find((wrap) => wrap.kind === 'password' || wrap.kind === 'legacy');
  if (passwordWrap) udk = await unlockWithPasswordPrompt(passwordWrap);
  if (!udk && wraps.some((wrap) => wrap.kind === 'passkey')) {
    udk = await unlockWithPasskeyPrompt('Use a passkey you already have so this one wraps the same encryption key.');
  }
  if (!udk && wraps.length === 0) udk = await window.SecretUdk.generateUserDataKey();
  if (!udk || !(await window.SecretUdk.canRewrap())) {
    throw new Error(passwordWrap && !wraps.some((wrap) => wrap.kind === 'passkey')
      ? 'Password required to unlock encryption.'
      : 'Could not unlock encryption to wrap it with this passkey.');
  }
  await window.SecretUdk.storeUserDataKey(udk, userId);
}

/** Puts the existing key in this tab. A passkey-only account is asked for the passkey. Nothing is saved yet. */
export async function preparePasswordWrap(currentPassword, options = {}) {
  await loadScript();
  const userId = await accountId();
  const wraps = wrapsOf(await api.get(BASE));
  let udk = window.SecretUdk.loadUserDataKey(userId);
  if (udk && !(await window.SecretUdk.canRewrap())) udk = null;
  if (!udk && currentPassword) {
    const passwordWrap = wraps.find((wrap) => wrap.kind === 'password' || wrap.kind === 'legacy');
    if (passwordWrap) {
      try { udk = await window.SecretUdk.unwrapUserDataKey(passwordWrap.wrapped, currentPassword); } catch { /* try the passkey next */ }
    }
  }
  if (!udk && wraps.some((wrap) => wrap.kind === 'passkey')) udk = await unlockWithPasskeyPrompt();
  if (!udk && wraps.length === 0 && options.createIfMissing) udk = await window.SecretUdk.generateUserDataKey();
  if (!udk) throw new Error(wraps.length === 0
    ? 'Could not wrap encryption. This account has no wrapped key, so a new one would leave any existing secrets unreadable.'
    : 'Could not unlock encryption to wrap it with this password.');
  await window.SecretUdk.storeUserDataKey(udk, userId);
}

/** Wraps the key already held in this tab. Call only after the new password has been accepted. */
export async function commitPasswordWrap(newPassword) {
  if (!newPassword) return;
  await loadScript();
  const userId = await accountId();
  const udk = window.SecretUdk.loadUserDataKey(userId);
  if (!udk) throw new Error('Could not unlock encryption to wrap it with this password.');
  await save('password', await window.SecretUdk.wrapUserDataKey(udk, newPassword));
  await window.SecretUdk.storeUserDataKey(udk, userId);
}

async function unlockWithPasswordPrompt(passwordWrap) {
  const { modal } = await import('./ui.js?v=shell104');
  let opened = null;
  const values = await modal.form('Unlock encryption', [
    { name: 'password', label: 'Account password', type: 'password', required: true, autocomplete: 'current-password' },
  ], {
    submitLabel: 'Unlock',
    onSubmit: async (form) => {
      try {
        opened = await window.SecretUdk.unwrapUserDataKey(passwordWrap.wrapped, form.password);
      } catch {
        opened = null;
        throw new Error('Could not unlock encryption. Check your password and try again.');
      }
      if (!(await window.SecretUdk.canRewrap())) {
        opened = null;
        throw new Error('Could not unlock encryption. Check your password and try again.');
      }
    },
  });
  return values ? opened : null;
}

async function unlockWithPasskeyPrompt(message) {
  const { modal } = await import('./ui.js?v=shell104');
  const agreed = await modal.confirm('Unlock encryption', message || 'Use your passkey so this password wraps the same encryption key.', { confirmLabel: 'Use passkey' });
  if (!agreed) throw new Error('Passkey required to wrap encryption for this password.');
  const webauthn = await import('./webauthn.js?v=shell407');
  await webauthn.authenticate({ optionsUrl: '/api/account/reauth/passkey/options', finishUrl: '/api/account/reauth/passkey', onCredential: (credential) => unlockWithPasskey(credential) });
  return window.SecretUdk.loadUserDataKey(await accountId());
}

export async function dropPasskey(credentialId) {
  if (!credentialId) return;
  try { await api.delete(`${BASE}/passkey/${encodeURIComponent(credentialId)}`); } catch { /* already gone */ }
}

function prfBytes(credential) {
  const first = credential.getClientExtensionResults?.().prf?.results?.first;
  if (!first) return null;
  const bytes = new Uint8Array(first);
  return bytes.length === 32 ? bytes : null;
}
