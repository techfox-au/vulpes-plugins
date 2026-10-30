import { requireUserDataKey } from '/assets/js/data-key.js?v=shell154';

const pub = '/plugins/secret-sharing/public';
const expiryChoices = [
  ['1', '1 minute'],
  ['10', '10 minutes'],
  ['30', '30 minutes'],
  ['60', '1 hour'],
  ['1440', '1 day'],
  ['4320', '3 days'],
  ['10080', '7 days'],
  ['20160', '14 days'],
  ['43200', '30 days'],
  ['64800', '45 days'],
];

export async function mount(el, ctx) {
  const root = el.querySelector('#collect-root');
  await loadScript(`${pub}/nacl-fast.js`).then(() => loadScript(`${pub}/crypto.js?v=crypto2`)).then(() => loadScript(`${pub}/udk.js?v=crypto2`));
  const { h, dropdown } = ctx.ui;
  const name = h('input', { class: 'input', maxlength: '256', placeholder: 'e.g. Give me credentials', autocomplete: 'off' });
  const mode = dropdown([['true', 'One-time'], ['false', 'Multi-view until expiry']], { value: 'true', ariaLabel: 'Collect mode' });
  const expiry = dropdown(expiryChoices, { value: '1440', ariaLabel: 'Expires in' });
  const max = h('input', { class: 'input', type: 'number', inputmode: 'numeric', min: '1', max: '100000', step: '1', placeholder: 'e.g. 5 — leave blank for unlimited' });
  const maxWrap = h('div', { class: 'field', hidden: true }, h('label', null, 'Maximum access count'), max);
  const hide = h('input', { type: 'checkbox' });
  const note = h('textarea', { class: 'input', rows: '3', maxlength: '5000000', placeholder: 'Only you see this on the dashboard (encrypted with your account key)' });
  const password = h('input', { class: 'input', type: 'password', maxlength: '256', placeholder: 'Leave blank for key-only collect link', autocomplete: 'new-password' });
  const confirm = h('input', { class: 'input', type: 'password', maxlength: '256', autocomplete: 'new-password' });
  const confirmWrap = h('div', { class: 'field', hidden: true }, h('label', null, 'Confirm link password'), confirm);
  const button = h('button', { class: 'btn primary', type: 'button', onClick: () => create() }, 'Create collect links');
  const out = h('div', { class: 'col' });
  mode.addEventListener('change', () => {
    const multi = mode.value === 'false';
    maxWrap.hidden = !multi;
    if (!multi) max.value = '';
  });
  max.addEventListener('input', () => { max.value = max.value.replace(/\D/g, ''); });
  password.addEventListener('input', () => {
    confirmWrap.hidden = password.value.length === 0;
    if (!password.value) confirm.value = '';
  });
  const field = (label, control) => h('div', { class: 'field' }, h('label', null, label), control);
  root.append(h('div', { class: 'card col gap-lg' },
    field('Collect name', name),
    h('div', { class: 'form-row' }, field('Collect mode', mode), maxWrap, field('Expires in', expiry)),
    h('label', { class: 'checkbox' }, hide, h('span', null, 'Hide text by default')),
    field('Private note', note),
    field('Link password', password),
    confirmWrap,
    button,
    out));

  async function create() {
    button.disabled = true;
    try {
      const udk = await ensureUdk(ctx);
      const oneTime = mode.value !== 'false';
      let maxAccessCount = null;
      if (!oneTime && max.value.trim()) {
        const n = parseInt(max.value.trim(), 10);
        if (!Number.isFinite(n) || n < 1 || n > 100000) throw new Error('Maximum access count must be between 1 and 100000.');
        maxAccessCount = n;
      }
      const linkPassword = password.value;
      if (linkPassword && linkPassword !== confirm.value) throw new Error('Link password and confirmation do not match.');
      const label = name.value.trim();
      if (label.length > 256) throw new Error('Collect name is too long (max 256 characters).');
      const privateNote = note.value.trim();
      if (privateNote.length > 5000000) throw new Error('Private note is too long.');
      const pair = SenditCrypto.generateKeyPair();
      let storedKey = pair.secretKey;
      let fragment = SenditCrypto.buildFragment(pair.secretKey);
      if (linkPassword) {
        const pkg = await SenditCrypto.wrapSecretKeyWithPassword(pair.secretKey, linkPassword);
        fragment = SenditCrypto.buildPasswordProtectedFragment(pkg);
        storedKey = new TextEncoder().encode(pkg);
      }
      const protectedKey = await SecretUdk.encryptWithUserDataKey(storedKey, udk);
      const ownerLabel = label ? await SecretUdk.encryptWithUserDataKey(new TextEncoder().encode(label), udk) : null;
      const publicLabel = label ? await SenditCrypto.encryptCollectName(new TextEncoder().encode(label), pair.publicKey) : null;
      const noteCipher = privateNote ? await SecretUdk.encryptWithUserDataKey(new TextEncoder().encode(privateNote), udk) : null;
      const created = await ctx.api.post(`${ctx.plugin.apiBase}/collects`, {
        publicKey: SenditCrypto.b64urlEncode(pair.publicKey),
        ownerPrivateKeyProtected: protectedKey,
        encryptedLabel: ownerLabel,
        publicLabel,
        privateNoteCiphertext: noteCipher,
        oneTime,
        expiresInMinutes: Number(expiry.value),
        maxAccessCount,
        passwordProtected: !!linkPassword,
        hideTextByDefault: hide.checked,
      });
      const upload = `${location.origin}/upload?id=${encodeURIComponent(created.id)}`;
      const owner = `${location.origin}/collect?id=${encodeURIComponent(created.id)}${fragment}`;
      out.replaceChildren(
        h('p', null, 'Upload link. It does not contain the decryption key.'),
        h('code', { class: 'share-link' }, upload),
        h('p', null, 'Collect link. Keep this private.'),
        h('code', { class: 'share-link' }, owner));
    } catch (err) {
      out.replaceChildren(h('div', { class: 'alert danger' }, err.message || 'Could not create the collect.'));
    } finally {
      button.disabled = false;
    }
  }
}

export function unmount() {}

function ensureUdk() {
  return requireUserDataKey();
}

function loadScript(src) {
  if (document.querySelector(`script[src="${src}"]`)) return Promise.resolve();
  return new Promise((resolve, reject) => {
    const s = document.createElement('script');
    s.src = src; s.onload = () => resolve(); s.onerror = () => reject(new Error('Could not load encryption.'));
    document.head.append(s);
  });
}
