import { h, modal, setBusy, errorMessage } from './ui.js?v=shell231';
import * as webauthn from './webauthn.js?v=shell446';
import { unlockWithPasskey } from './data-key.js?v=shell446';

/** Password or passkey confirmation. Returns true only after the server accepts it. */
export async function confirmIdentity(ctx, me, { passkeyOnly = false } = {}) {
  const hasPassword = !passkeyOnly && me.passwordSet && me.passwordLoginEnabled;
  const passkey = me.passkeyCount > 0 && webauthn.isSupported();
  const container = h('div', { class: 'col' });
  let done = false;
  const modalError = h('div', { class: 'alert danger hidden', role: 'alert' });
  const showModalError = (message) => { modalError.textContent = message; modalError.classList.remove('hidden'); };
  const passwordInput = h('input', { class: 'input', type: 'password', autocomplete: 'current-password', placeholder: 'Current password' });
  if (hasPassword) container.append(h('div', { class: 'field' }, h('label', null, 'Password'), passwordInput));
  if (!hasPassword && !passkey) container.append(h('p', null, 'Add a password or passkey on your account before continuing.'));
  container.append(modalError);
  const passkeyBtn = h('button', { class: 'btn', type: 'button' }, passkeyOnly || !hasPassword ? 'Use a passkey' : 'Use a passkey instead');
  if (passkey) container.append(passkeyBtn);
  let confirmCard = null;
  const result = await new Promise((resolve) => {
    passkeyBtn.addEventListener('click', async () => {
      setBusy(passkeyBtn, true, 'Waiting for your key…');
      try {
        await webauthn.authenticate({
          optionsUrl: '/api/account/reauth/passkey/options',
          finishUrl: '/api/account/reauth/passkey',
          onCredential: (credential) => unlockWithPasskey(credential),
        });
        if (confirmCard?.isConnected) confirmCard.closeModal(true);
      } catch (err) {
        showModalError(webauthn.describeError(err) || errorMessage(err));
      } finally {
        setBusy(passkeyBtn, false);
      }
    });
    modal.show({
      title: 'Confirm it is you',
      content: container,
      actions: [
        { label: 'Cancel', value: false },
        ...(hasPassword ? [{
          label: 'Confirm',
          kind: 'primary',
          value: true,
          onClick: async () => {
            try {
              await ctx.api.post('/api/account/reauth/password', { password: passwordInput.value });
              return true;
            } catch (err) {
              showModalError(err.status === 401 ? 'Incorrect password.' : errorMessage(err));
              return false;
            }
          },
        }] : []),
      ],
    }).then((value) => {
      if (value === true) done = true;
      resolve(value);
    });
    const open = document.querySelectorAll('.modal-card');
    confirmCard = open[open.length - 1] || null;
  });
  return done || result === true;
}
