// Every account gets a user data key when its first credential is added, whether or not a plugin is installed.
// A later password or passkey wraps that same key. Sign-in only unwraps a wrap that already exists.
import { api } from './api.js';

const BASE = '/api/account/data-key';

function loadScript() {
  if (window.SecretUdk) return Promise.resolve();
  return new Promise((resolve, reject) => {
    const s = document.createElement('script');
    s.src = '/assets/js/udk.js?v=shell133';
    s.onload = () => resolve();
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

async function passwordMaterial(wraps, password) {
  let udk = window.SecretUdk.loadUserDataKey();
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
  const wraps = wrapsOf(await api.get(BASE));
  const found = await passwordMaterial(wraps, password);
  if (found.udk) {
    if (!found.passwordWrap) await save('password', await window.SecretUdk.wrapUserDataKey(found.udk, password));
    window.SecretUdk.storeUserDataKey(found.udk);
    return;
  }
  if (wraps.length > 0) return;
  const udk = window.SecretUdk.generateUserDataKey();
  await save('password', await window.SecretUdk.wrapUserDataKey(udk, password));
  window.SecretUdk.storeUserDataKey(udk);
}

/** First passkey on the account. No key is created when the authenticator cannot wrap it. */
export async function establishWithPasskey(credential) {
  if (!credential) return;
  await loadScript();
  const prf = prfBytes(credential);
  if (!prf) return;
  const credentialId = credential.id;
  const wraps = wrapsOf(await api.get(BASE));
  const existing = wraps.find((wrap) => wrap.kind === 'passkey' && wrap.credentialId === credentialId);
  let udk = window.SecretUdk.loadUserDataKey();
  if (!udk && existing) {
    try { udk = await window.SecretUdk.unwrapUserDataKeyWithPrf(existing.wrapped, prf); } catch { return; }
  }
  if (udk) {
    if (!existing) await save('passkey', await window.SecretUdk.wrapUserDataKeyWithPrf(udk, prf), credentialId);
    window.SecretUdk.storeUserDataKey(udk);
    return;
  }
  if (wraps.length > 0) return;
  udk = window.SecretUdk.generateUserDataKey();
  await save('passkey', await window.SecretUdk.wrapUserDataKeyWithPrf(udk, prf), credentialId);
  window.SecretUdk.storeUserDataKey(udk);
}

/** This tab has no key. Ask for the password or passkey that already wraps it, and keep the dialog open until it unwraps. */
export async function requireUserDataKey() {
  await loadScript();
  const existing = window.SecretUdk.loadUserDataKey();
  if (existing) return existing;
  const wraps = wrapsOf(await api.get(BASE));
  const hasPassword = wraps.some((wrap) => wrap.kind === 'password' || wrap.kind === 'legacy');
  const hasPasskey = wraps.some((wrap) => wrap.kind === 'passkey');
  if (!hasPassword && !hasPasskey) {
    throw new Error('This account has no encryption key. Add a password or passkey on the account page, then try again.');
  }
  if (hasPassword) {
    const { modal } = await import('./ui.js?v=shell104');
    const unlocked = await modal.form('Unlock encryption', [
      { name: 'password', label: 'Account password', type: 'password', required: true, autocomplete: 'current-password' },
    ], {
      submitLabel: 'Unlock',
      onSubmit: async (values) => {
        await unlockWithPassword(values.password);
        if (!window.SecretUdk.loadUserDataKey()) throw new Error('Could not unlock encryption. Check your password and try again.');
      },
    });
    if (!unlocked) throw new Error('Password required to unlock encryption.');
    return window.SecretUdk.loadUserDataKey();
  }
  const { modal } = await import('./ui.js?v=shell104');
  const agreed = await modal.confirm('Unlock encryption', 'Use your passkey to unlock encryption in this browser tab.', { confirmLabel: 'Use passkey' });
  if (!agreed) throw new Error('Passkey required to unlock encryption.');
  const webauthn = await import('./webauthn.js?v=shell127');
  await webauthn.authenticate({ optionsUrl: '/api/account/reauth/passkey/options', finishUrl: '/api/account/reauth/passkey', onCredential: (credential) => unlockWithPasskey(credential) });
  const udk = window.SecretUdk.loadUserDataKey();
  if (!udk) throw new Error('This passkey could not unlock encryption.');
  return udk;
}

export async function unlockWithPassword(password) {
  if (!password) return;
  await loadScript();
  const wraps = wrapsOf(await api.get(BASE));
  if (wraps.length === 0) {
    window.SecretUdk.clearUserDataKey();
    return;
  }
  const found = await passwordMaterial(wraps, password);
  if (found.udk) window.SecretUdk.storeUserDataKey(found.udk);
}

/** After a temporary password is replaced. The previous key was destroyed, so this always creates a new one. */
export async function replaceAfterTemporaryPassword(newPassword) {
  if (!newPassword) return;
  await loadScript();
  window.SecretUdk.clearUserDataKey();
  const udk = window.SecretUdk.generateUserDataKey();
  await save('password', await window.SecretUdk.wrapUserDataKey(udk, newPassword));
  window.SecretUdk.storeUserDataKey(udk);
}

export async function unlockWithPasskey(credential) {
  if (!credential) return;
  await loadScript();
  const prf = prfBytes(credential);
  if (!prf) return;
  const credentialId = credential.id;
  const wraps = wrapsOf(await api.get(BASE));
  const existing = wraps.find((wrap) => wrap.kind === 'passkey' && wrap.credentialId === credentialId);
  let udk = window.SecretUdk.loadUserDataKey();
  if (!udk && existing) {
    try { udk = await window.SecretUdk.unwrapUserDataKeyWithPrf(existing.wrapped, prf); } catch { return; }
  }
  if (!udk) return;
  if (!existing) await save('passkey', await window.SecretUdk.wrapUserDataKeyWithPrf(udk, prf), credentialId);
  window.SecretUdk.storeUserDataKey(udk);
}

export async function rewrapPassword(currentPassword, newPassword) {
  if (!newPassword) return;
  await loadScript();
  const wraps = wrapsOf(await api.get(BASE));
  let udk = window.SecretUdk.loadUserDataKey();
  if (!udk && currentPassword) {
    const passwordWrap = wraps.find((wrap) => wrap.kind === 'password' || wrap.kind === 'legacy');
    if (passwordWrap) {
      try { udk = await window.SecretUdk.unwrapUserDataKey(passwordWrap.wrapped, currentPassword); } catch { return; }
    }
  }
  if (!udk) return;
  await save('password', await window.SecretUdk.wrapUserDataKey(udk, newPassword));
  window.SecretUdk.storeUserDataKey(udk);
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
