import { api, session, invalidateSession, setRedirectOnUnauthorized } from './api.js';
import { setBusy, errorMessage } from './ui.js';
import * as webauthn from './webauthn.js?v=shell467';
import { establishWithPassword, establishWithPasskey } from './data-key.js?v=shell467';
import './pwa.js?v=shell388';

setRedirectOnUnauthorized(false);
const $ = (id) => document.getElementById(id);
const errorBox = $('error');

function showError(message) {
  if (!message) { errorBox.classList.add('hidden'); return; }
  errorBox.textContent = message;
  errorBox.classList.remove('hidden');
}

let activeTab = 'password';

/** Password setup runs only while this tab is showing. The passkey tab must not post the hidden password form. */
export function passwordTabIsActive(tab) {
  return tab === 'password';
}

function switchTab(which) {
  activeTab = which === 'password' ? 'password' : 'passkey';
  $('tab-password').classList.toggle('active', passwordTabIsActive(activeTab));
  $('tab-passkey').classList.toggle('active', !passwordTabIsActive(activeTab));
  $('panel-password').classList.toggle('hidden', !passwordTabIsActive(activeTab));
  $('panel-passkey').classList.toggle('hidden', passwordTabIsActive(activeTab));
  const passwordButton = $('submit-password');
  if (passwordButton) passwordButton.type = passwordTabIsActive(activeTab) ? 'submit' : 'button';
}
$('tab-password').addEventListener('click', () => switchTab('password'));
$('tab-passkey').addEventListener('click', () => switchTab('passkey'));

function common() {
  return { token: $('token').value.trim(), username: $('username').value.trim(), displayName: $('displayName').value.trim(), email: $('email').value.trim() };
}

function validateCommon(values) {
  if (!values.token) return 'The setup token is required.';
  if (!values.username) return 'A username is required.';
  if (!values.displayName) return 'A display name is required.';
  if (values.email && !$('email').checkValidity()) return 'Email is not a valid address.';
  return null;
}

async function init() {
  const s = await session(true);
  if (!s.setupRequired) { location.replace(s.authenticated ? '/' : '/login'); return; }
  if (!webauthn.isSupported()) $('tab-passkey').disabled = true;
}

let created = false;
$('form').addEventListener('keydown', (event) => {
  if (event.key !== 'Enter' || passwordTabIsActive(activeTab)) return;
  if (event.target && event.target.id === 'submit-passkey') return;
  event.preventDefault();
});
$('form').addEventListener('submit', async (e) => {
  e.preventDefault();
  if (!passwordTabIsActive(activeTab)) return;
  showError('');
  const values = { ...common(), password: $('password').value };
  const invalid = validateCommon(values) || (values.password.length < 12 ? 'Use a password of at least 12 characters.' : null);
  if (invalid) { showError(invalid); return; }
  const btn = $('submit-password');
  setBusy(btn, true, 'Creating…');
  try {
    if (!created) {
      await api.post('/auth/setup', values);
      created = true;
    }
    await establishWithPassword(values.password);
    invalidateSession();
    try { localStorage.removeItem('vc.nav.openPlugin'); } catch { /* storage can be blocked */ }
    location.assign('/account');
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
    location.assign('/account');
  } catch (err) {
    showError(err.code === 'bad_setup_token' ? 'The setup token is incorrect.' : (webauthn.describeError(err) || errorMessage(err)));
  } finally { setBusy(btn, false); }
});

init().catch((err) => showError(errorMessage(err)));
