import { api, invalidateSession, setRedirectOnUnauthorized } from './api.js';
import { setBusy, errorMessage, fmt } from './ui.js';
import * as webauthn from './webauthn.js?v=shell51';

setRedirectOnUnauthorized(false);
const $ = (id) => document.getElementById(id);
const token = new URLSearchParams(location.search).get('token') || '';
const errorBox = $('error');

function showError(message) {
  if (!message) { errorBox.classList.add('hidden'); return; }
  errorBox.textContent = message;
  errorBox.classList.remove('hidden');
}

function switchTab(which) {
  $('tab-password').classList.toggle('active', which === 'password');
  $('tab-passkey').classList.toggle('active', which === 'passkey');
  $('panel-password').classList.toggle('hidden', which !== 'password');
  $('panel-passkey').classList.toggle('hidden', which !== 'passkey');
}
$('tab-password').addEventListener('click', () => switchTab('password'));
$('tab-passkey').addEventListener('click', () => switchTab('passkey'));

async function init() {
  // The token stays in the address until sign-in succeeds, so a failed passkey attempt can be retried.
  const info = await api.post('/auth/enroll/verify', { token });
  $('loading').classList.add('hidden');
  // The link is single-use and expires (docs/security.md). The page does not spell that out.
  $('who').textContent = info.displayName || info.username;
  $('content').classList.remove('hidden');
  if (!info.allowPassword) { $('tab-password').classList.add('hidden'); }
  if (!webauthn.isSupported()) {
    $('tab-passkey').disabled = true;
    if (info.allowPassword) switchTab('password'); else showError('This browser does not support passkeys. Use a browser that does, or ask an administrator to enable password sign-in.');
  }
}

$('submit-passkey').addEventListener('click', async () => {
  showError('');
  const btn = $('submit-passkey');
  setBusy(btn, true, 'Waiting for your passkey…');
  try {
    await webauthn.register({ optionsUrl: '/auth/enroll/passkey/options', finishUrl: '/auth/enroll/passkey', optionsBody: { token }, extra: { token, passkeyName: $('passkeyName').value } });
    invalidateSession();
    try { localStorage.removeItem('vc.nav.openPlugin'); } catch { /* storage can be blocked */ }
    history.replaceState(null, '', '/enroll');
    location.assign('/');
  } catch (err) {
    showError(webauthn.describeError(err) || errorMessage(err));
  } finally { setBusy(btn, false); }
});

$('panel-password').addEventListener('submit', async (e) => {
  e.preventDefault();
  showError('');
  const password = $('password').value;
  if (password.length < 12) { showError('Use a password of at least 12 characters.'); return; }
  if (password !== $('password2').value) { showError('The passwords do not match.'); return; }
  const btn = $('submit-password');
  setBusy(btn, true, 'Saving…');
  try {
    await api.post('/auth/enroll/password', { token, password });
    invalidateSession();
    try { localStorage.removeItem('vc.nav.openPlugin'); } catch { /* storage can be blocked */ }
    history.replaceState(null, '', '/enroll');
    location.assign('/');
  } catch (err) {
    showError(errorMessage(err));
  } finally { setBusy(btn, false); }
});

init().catch((err) => {
  $('loading').classList.add('hidden');
  showError(err.status === 404 ? 'This link is invalid, expired, or has already been used. Ask an administrator for a new one.' : errorMessage(err));
});
