import { api, session, invalidateSession, setRedirectOnUnauthorized } from './api.js';
import { setBusy, errorMessage } from './ui.js';
import * as webauthn from './webauthn.js?v=shell125';
import { establishWithPassword, establishWithPasskey } from './data-key.js?v=shell133';

setRedirectOnUnauthorized(false);
const $ = (id) => document.getElementById(id);
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

function common() {
  return { token: $('token').value.trim(), username: $('username').value.trim(), displayName: $('displayName').value.trim() || null, email: $('email').value.trim() };
}

function validateCommon(values) {
  if (!values.token) return 'The setup token is required.';
  if (!values.username) return 'A username is required.';
  if (!values.email) return 'Email is required.';
  if (!$('email').checkValidity()) return 'Email is not a valid address.';
  return null;
}

async function init() {
  const s = await session(true);
  if (!s.setupRequired) { location.replace(s.authenticated ? '/' : '/login'); return; }
  if (!webauthn.isSupported()) $('tab-passkey').disabled = true;
}

$('form').addEventListener('submit', async (e) => {
  e.preventDefault();
  showError('');
  const values = { ...common(), password: $('password').value };
  const invalid = validateCommon(values) || (values.password.length < 12 ? 'Use a password of at least 12 characters.' : null);
  if (invalid) { showError(invalid); return; }
  const btn = $('submit-password');
  setBusy(btn, true, 'Creating…');
  try {
    await api.post('/auth/setup', values);
    await establishWithPassword(values.password);
    invalidateSession();
    try { localStorage.removeItem('vc.nav.openPlugin'); } catch { /* storage can be blocked */ }
    location.assign('/#/account');
  } catch (err) {
    showError(err.code === 'bad_setup_token' ? 'The setup token is incorrect.' : errorMessage(err));
  } finally { setBusy(btn, false); }
});

$('submit-passkey').addEventListener('click', async () => {
  showError('');
  const values = common();
  const invalid = validateCommon(values);
  if (invalid) { showError(invalid); return; }
  const btn = $('submit-passkey');
  setBusy(btn, true, 'Waiting for your passkey…');
  try {
    await webauthn.register({ optionsUrl: '/auth/setup/passkey/options', finishUrl: '/auth/setup/passkey', optionsBody: values, extra: { ...values, passkeyName: 'Primary key' }, onCredential: (credential) => establishWithPasskey(credential) });
    invalidateSession();
    try { localStorage.removeItem('vc.nav.openPlugin'); } catch { /* storage can be blocked */ }
    location.assign('/#/account');
  } catch (err) {
    showError(err.code === 'bad_setup_token' ? 'The setup token is incorrect.' : (webauthn.describeError(err) || errorMessage(err)));
  } finally { setBusy(btn, false); }
});

init().catch((err) => showError(errorMessage(err)));
