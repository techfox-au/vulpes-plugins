import { api, session, invalidateSession, setRedirectOnUnauthorized } from './api.js';
import { setBusy, errorMessage } from './ui.js';
import * as webauthn from './webauthn.js?v=shell51';

setRedirectOnUnauthorized(false);

const $ = (id) => document.getElementById(id);
const errorBox = $('error');
const params = new URLSearchParams(location.search);
const returnUrl = safeReturnUrl(params.get('returnUrl'));

function safeReturnUrl(url) {
  if (!url || !url.startsWith('/') || url.startsWith('//') || url.startsWith('/\\')) return '/';
  return url;
}

function showError(message) {
  if (!message) { errorBox.classList.add('hidden'); return; }
  errorBox.textContent = message;
  errorBox.classList.remove('hidden');
}

if (params.get('error')) showError('Sign-in failed.');

async function init() {
  const s = await session(true);
  if (s.app?.name) document.title = `Sign in · ${s.app.name}`;
  if (s.authenticated) { location.replace(returnUrl); return; }
  if (s.setupRequired) $('setup-hint').classList.remove('hidden');
  if (s.app && s.app.passwordLoginEnabled === false) $('password-form').classList.add('hidden');
  const passkeyBtn = $('passkey-btn');
  if (s.app?.passkeysConfigured) {
    passkeyBtn.classList.remove('hidden');
    if (!webauthn.isSupported()) {
      passkeyBtn.disabled = true;
      passkeyBtn.textContent = 'Passkeys are not supported in this browser';
    }
  }
  const passwordShown = !$('password-form').classList.contains('hidden');
  const moreWays = !passkeyBtn.classList.contains('hidden');
  $('or-1').classList.toggle('hidden', !(passwordShown && moreWays));
}

function closePluginMenus() {
  try { localStorage.removeItem('vc.nav.openPlugin'); } catch { /* storage can be blocked */ }
}

function onSignedIn() {
  invalidateSession();
  closePluginMenus();
  location.assign(returnUrl);
}

$('password-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  showError('');
  const btn = $('password-btn');
  setBusy(btn, true, 'Signing in…');
  try {
    const res = await api.post('/auth/login/password', { username: $('username').value.trim(), password: $('password').value }, { noRedirect: true });
    if (res?.mustChangePassword) { invalidateSession(); closePluginMenus(); location.assign('/#/account?changePassword=1'); return; }
    onSignedIn();
  } catch (err) {
    showError(err.status === 401 ? 'Invalid username or password.' : err.status === 429 ? 'Too many attempts. Please wait a minute and try again.' : errorMessage(err));
    $('password').value = '';
    $('password').focus();
  } finally {
    setBusy(btn, false);
  }
});

$('passkey-btn').addEventListener('click', async () => {
  showError('');
  const username = $('username').value.trim();
  if (!username) {
    showError('Enter your username before using a passkey.');
    $('username').focus();
    return;
  }
  const btn = $('passkey-btn');
  setBusy(btn, true, 'Waiting for your passkey…');
  try {
    await webauthn.authenticate({ optionsUrl: '/auth/login/passkey/options', finishUrl: '/auth/login/passkey', optionsBody: { username } });
    onSignedIn();
  } catch (err) {
    const text = err?.status === 401 ? 'Invalid credentials.' : err?.status === 429 ? 'Too many attempts. Please wait a minute and try again.' : webauthn.describeError(err);
    if (text) showError(text);
  } finally {
    setBusy(btn, false);
  }
});

init().catch((err) => showError(errorMessage(err)));
