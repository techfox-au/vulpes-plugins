import { api, session, invalidateSession, setRedirectOnUnauthorized } from './api.js';
import { setBusy, errorMessage } from './ui.js?v=shell195';
import * as webauthn from './webauthn.js?v=shell160';
import { unlockWithPassword, unlockWithPasskey } from './data-key.js?v=shell133';
import { powBody, createPowKeeper, syncServerTime } from './pow.js?v=shell200';

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
  return true;
}

function closePluginMenus() {
  try { localStorage.removeItem('vc.nav.openPlugin'); } catch { /* storage can be blocked */ }
}

function onSignedIn() {
  invalidateSession();
  closePluginMenus();
  location.assign(returnUrl);
}

const powKeeper = createPowKeeper(() => api.get('/auth/login/pow', { noRedirect: true }));

$('password-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  showError('');
  const btn = $('password-btn');
  const username = $('username').value.trim();
  const solving = !powKeeper.ready();
  setBusy(btn, true, solving ? 'Performing proof-of-work…' : 'Signing in…');
  try {
    const password = $('password').value;
    const pow = await powKeeper.take();
    if (solving) setBusy(btn, true, 'Signing in…');
    const res = await api.post('/auth/login/password', { username, password, ...powBody(pow) }, { noRedirect: true });
    try { await unlockWithPassword(password); } catch { /* encryption unlock can wait until the next sign-in */ }
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
  const solving = !powKeeper.ready();
  setBusy(btn, true, solving ? 'Performing proof-of-work…' : 'Waiting for your passkey…');
  try {
    const optionsPow = powBody(await powKeeper.take());
    setBusy(btn, true, 'Waiting for your passkey…');
    await webauthn.authenticate({
      optionsUrl: '/auth/login/passkey/options',
      finishUrl: '/auth/login/passkey',
      optionsBody: { username, ...optionsPow },
      extra: async () => {
        if (!powKeeper.ready()) setBusy(btn, true, 'Performing proof-of-work…');
        const proof = { username, ...powBody(await powKeeper.take()) };
        setBusy(btn, true, 'Signing in…');
        return proof;
      },
      onCredential: (credential) => unlockWithPasskey(credential),
    });
    onSignedIn();
  } catch (err) {
    const text = err?.status === 401 ? 'Invalid credentials.' : err?.status === 429 ? 'Too many attempts. Please wait a minute and try again.' : webauthn.describeError(err);
    if (text) showError(text);
  } finally {
    setBusy(btn, false);
  }
});

init().then(async (stay) => {
  if (!stay) return;
  await syncServerTime();
  powKeeper.start();
}).catch((err) => showError(errorMessage(err)));
