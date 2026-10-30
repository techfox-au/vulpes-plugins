import { requireUserDataKey } from '/assets/js/data-key.js?v=shell154';

const pub = '/plugins/secret-sharing/public';
const FILE_LIMIT = 40 * 1024 * 1024;
const expiryChoices = [
  ['1', '1 minute'], ['10', '10 minutes'], ['30', '30 minutes'], ['60', '1 hour'],
  ['1440', '1 day'], ['4320', '3 days'], ['10080', '7 days'], ['20160', '14 days'],
  ['43200', '30 days'], ['64800', '45 days'],
];

export async function mount(el, ctx) {
  const root = el.querySelector('#send-root');
  await loadCrypto();
  await loadScript(`${pub}/transfer.js?v=crypto2`);
  await loadScript(`${pub}/cidr.js?v=crypto2`);
  const { h, dropdown } = ctx.ui;
  const field = (label, control) => h('div', { class: 'field' }, h('label', null, label), control);
  const name = h('input', { class: 'input', maxlength: '256', placeholder: 'e.g. VPN credentials', autocomplete: 'off' });
  const textRadio = h('input', { type: 'radio', name: 'content-kind', value: 'text', checked: true });
  const fileRadio = h('input', { type: 'radio', name: 'content-kind', value: 'file' });
  const secret = h('textarea', { class: 'input chalkboard', rows: '6', maxlength: '1000000', placeholder: 'Paste token, note, or other secret…' });
  const file = h('input', { class: 'input', type: 'file' });
  const textPanel = field('Secret text', secret);
  const filePanel = field('File (max 40 MB)', file);
  filePanel.hidden = true;
  const mode = dropdown([['true', 'One-time (destroy after reveal)'], ['false', 'Multi-view until expiry']], { value: 'true', ariaLabel: 'Burn mode' });
  const expiry = dropdown(expiryChoices, { value: '1440', ariaLabel: 'Expires in' });
  const max = h('input', { class: 'input', type: 'number', inputmode: 'numeric', min: '1', max: '100000', step: '1', placeholder: 'e.g. 5 — leave blank for unlimited' });
  const maxWrap = h('div', { class: 'field', hidden: true }, h('label', null, 'Maximum access count'), max);
  const hide = h('input', { type: 'checkbox' });
  const hideWrap = h('label', { class: 'checkbox' }, hide, h('span', null, 'Hide text by default'));
  const note = h('textarea', { class: 'input', rows: '3', maxlength: '5000000', placeholder: 'Only you see this on the dashboard (encrypted with your account key)' });
  const password = h('input', { class: 'input', type: 'password', maxlength: '256', placeholder: 'Leave blank for key-only link', autocomplete: 'new-password' });
  const confirm = h('input', { class: 'input', type: 'password', maxlength: '256', autocomplete: 'new-password' });
  const confirmWrap = h('div', { class: 'field', hidden: true }, h('label', null, 'Confirm link password'), confirm);
  const cidr = h('input', { class: 'input', maxlength: '5000000', placeholder: 'e.g. 203.0.113.10, 192.168.1.0/24, 2001:db8::/32', autocomplete: 'off', spellcheck: 'false' });
  const button = h('button', { class: 'btn primary', type: 'button' }, 'Encrypt & create link');
  const out = h('div', { class: 'col' });
  const syncKind = () => {
    const isFile = fileRadio.checked;
    textPanel.hidden = isFile;
    filePanel.hidden = !isFile;
    hideWrap.hidden = isFile;
    if (isFile) hide.checked = false;
  };
  textRadio.addEventListener('change', syncKind);
  fileRadio.addEventListener('change', syncKind);
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
  button.addEventListener('click', () => create());
  root.append(h('div', { class: 'card col gap-lg' },
    field('Send name', name),
    h('fieldset', { class: 'choice' }, h('legend', null, 'Content type'), h('label', null, textRadio, ' Text'), h('label', null, fileRadio, ' File')),
    textPanel,
    filePanel,
    h('div', { class: 'form-row' }, field('Burn mode', mode), maxWrap, field('Expires in', expiry)),
    hideWrap,
    field('Private note', note),
    field('Link password', password),
    confirmWrap,
    field('Allowed IPs / CIDRs', cidr),
    h('div', null, button),
    out));

  async function create() {
    button.disabled = true;
    try {
      const udk = await ensureUdk();
      const label = name.value.trim();
      if (label.length > 256) throw new Error('Send name is too long (max 256 characters).');
      const privateNote = note.value.trim();
      if (privateNote.length > 5000000) throw new Error('Private note is too long.');
      const cidrParsed = SecretCidr.parseAllowedCidr(cidr.value);
      if (!cidrParsed.ok) throw new Error(cidrParsed.error);
      const oneTime = mode.value !== 'false';
      let maxAccessCount = null;
      if (!oneTime && max.value.trim()) {
        const n = parseInt(max.value.trim(), 10);
        if (!Number.isFinite(n) || n < 1 || n > 100000) throw new Error('Maximum access count must be a whole number from 1 to 100000.');
        maxAccessCount = n;
      }
      const linkPassword = password.value;
      if (linkPassword && linkPassword !== confirm.value) throw new Error('Link password and confirmation do not match.');
      const chosen = fileRadio.checked ? file.files && file.files[0] : null;
      if (fileRadio.checked) {
        if (!chosen) throw new Error('Choose a file to encrypt.');
        if (chosen.size > FILE_LIMIT) throw new Error('File exceeds 40 MB limit.');
      } else if (!secret.value) {
        throw new Error('Enter a secret to encrypt.');
      }
      const plain = chosen ? new Uint8Array(await chosen.arrayBuffer()) : new TextEncoder().encode(secret.value);
      const kp = SenditCrypto.generateKeyPair();
      const wire = await SenditCrypto.encryptForRecipient(plain, kp.publicKey);
      let recipientLabel = null;
      if (label) {
        recipientLabel = await SenditCrypto.encryptForRecipient(new TextEncoder().encode(label), kp.publicKey);
        if (recipientLabel.ciphertext instanceof Uint8Array) recipientLabel.ciphertext = new TextDecoder().decode(recipientLabel.ciphertext);
        recipientLabel = JSON.stringify(recipientLabel);
      }
      let fragment = SenditCrypto.buildFragment(kp.secretKey);
      let passwordProtected = false;
      if (linkPassword) {
        const pkg = await SenditCrypto.wrapSecretKeyWithPassword(kp.secretKey, linkPassword);
        fragment = SenditCrypto.buildPasswordProtectedFragment(pkg);
        passwordProtected = true;
      }
      kp.secretKey.fill(0);
      const created = await SecretTransfer.postJson(`${ctx.plugin.apiBase}/sends`, {
        ciphertext: wire.ciphertext,
        iv: wire.iv,
        wrappedKey: wire.wrappedKey,
        ephemeralPublicKey: wire.ephemeralPublicKey,
        contentType: chosen ? chosen.type || 'application/octet-stream' : 'text/plain',
        filename: chosen ? chosen.name : null,
        encryptedLabel: label ? await SecretUdk.encryptWithUserDataKey(new TextEncoder().encode(label), udk) : null,
        oneTime,
        expiresInMinutes: Number(expiry.value),
        allowedCidr: cidrParsed.value,
        hideTextByDefault: hide.checked && !chosen,
        privateNoteCiphertext: privateNote ? await SecretUdk.encryptWithUserDataKey(new TextEncoder().encode(privateNote), udk) : null,
        maxAccessCount,
        passwordProtected,
        recipientLabel,
      });
      wire.ciphertext = null;
      const link = `${location.origin}/send?id=${encodeURIComponent(created.id)}${fragment}`;
      out.replaceChildren(h('p', null, 'Your link. The decryption key is only in the # fragment.'), h('code', { class: 'share-link' }, link));
    } catch (err) {
      out.replaceChildren(h('div', { class: 'alert danger' }, err.message || 'Could not create the send.'));
    } finally {
      button.disabled = false;
    }
  }
}

export function unmount() {}

function ensureUdk() {
  return requireUserDataKey();
}

function loadCrypto() {
  return loadScript(`${pub}/nacl-fast.js`).then(() => loadScript(`${pub}/crypto.js?v=crypto2`)).then(() => loadScript(`${pub}/udk.js?v=crypto2`));
}
function loadScript(src) {
  if (document.querySelector(`script[src="${src}"]`)) return Promise.resolve();
  return new Promise((resolve, reject) => {
    const s = document.createElement('script');
    s.src = src;
    s.onload = () => resolve();
    s.onerror = () => reject(new Error('Could not load encryption.'));
    document.head.append(s);
  });
}
