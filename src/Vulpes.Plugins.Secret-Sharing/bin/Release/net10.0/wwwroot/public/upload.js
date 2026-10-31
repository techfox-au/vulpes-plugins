(async function () {
  const FILE_LIMIT = 40 * 1024 * 1024;
  const TEXT_LIMIT = 1000000;
  const id = new URLSearchParams(location.search).get('id');
  const panel = document.getElementById('upload-panel');
  const form = document.getElementById('upload-form');
  const textPanel = document.getElementById('panel-text');
  const filePanel = document.getElementById('panel-file');
  const textEl = document.getElementById('secret-text');
  const fileEl = document.getElementById('secret-file');
  const fileNameEl = document.getElementById('secret-file-name');
  fileEl.addEventListener('change', () => {
    const chosen = fileEl.files && fileEl.files[0];
    if (fileNameEl) fileNameEl.textContent = chosen ? chosen.name : 'No file chosen';
  });
  const nameEl = document.getElementById('collect-name');
  const metaEl = document.getElementById('meta');
  const alertEl = document.getElementById('alert');

  function setAlert(kind, message) {
    if (!message) { alertEl.className = 'alert hidden'; alertEl.textContent = ''; return; }
    alertEl.className = 'alert ' + (kind === 'ok' ? 'success' : kind === 'error' ? 'danger' : 'info');
    alertEl.textContent = message;
  }

  function selectedKind() {
    const selected = form.querySelector('input[name="content-kind"]:checked');
    return selected ? selected.value : 'text';
  }

  function applyKind() {
    const file = selectedKind() === 'file';
    textPanel.hidden = file;
    filePanel.hidden = !file;
  }

  form.querySelectorAll('input[name="content-kind"]').forEach((radio) => radio.addEventListener('change', applyKind));
  applyKind();

  if (!id) { setAlert('error', 'Missing collect id.'); return; }
  await SenditPow.syncServerTime();

  let meta;
  const opening = SecretTransfer.showProgress('Opening upload');
  try {
    opening.setStatus('Performing proof-of-work…');
    opening.setProgress(null);
    const solved = await SenditPow.solveRefreshing(() => fetch('/api/plugins/secret-sharing/public/collects/' + encodeURIComponent(id) + '/pow').then(readJson), { onProgress: (_t, attempt) => opening.setStatus(SenditPow.statusLabel('Performing proof-of-work…', attempt)) });
    meta = await SecretTransfer.postJson('/api/plugins/secret-sharing/public/collects/' + encodeURIComponent(id) + '/meta', solved);
  } catch (err) {
    setAlert('error', err.message || 'This collect is not open.');
    return;
  } finally {
    opening.close();
  }

  let when = '';
  try { when = new Date(meta.expiresAt).toLocaleString(); } catch { when = ''; }
  metaEl.textContent = 'Expires ' + when + (meta.oneTime ? ' · one-time collect' : '');

  if (meta.status !== 'waiting') {
    setAlert('info', meta.status === 'ready' ? 'This collect already has an upload.' : 'This collect is not open.');
    return;
  }

  const publicKey = SenditCrypto.b64urlDecode(meta.publicKey);
  if (meta.publicLabel) {
    try {
      const wire = typeof meta.publicLabel === 'string' ? JSON.parse(meta.publicLabel) : meta.publicLabel;
      const title = await SenditCrypto.plainToText(await SenditCrypto.decryptCollectName(wire, publicKey));
      if (title) { nameEl.textContent = title; document.getElementById('collect-head').hidden = false; document.title = title + ' · Upload secret'; }
    } catch { /* name stays hidden */ }
  }
  panel.hidden = false;
  const uploadPow = SenditPow.createKeeper(function () {
    return fetch('/api/plugins/secret-sharing/public/collects/' + encodeURIComponent(id) + '/pow').then(readJson);
  });
  uploadPow.start();

  let busy = false;
  form.addEventListener('submit', async (ev) => {
    ev.preventDefault();
    if (busy) return;
    busy = true;
    const button = document.querySelector('#upload-panel button[type="submit"]');
    button.disabled = true;
    try {
      if (selectedKind() === 'file') {
        const picked = fileEl.files && fileEl.files[0];
        if (!picked) throw new Error('Choose a file to encrypt.');
        if (picked.size > FILE_LIMIT) throw new Error('File exceeds 40 MB limit.');
      } else if (!textEl.value) {
        throw new Error('Enter a secret to encrypt.');
      }
      const progress = SecretTransfer.showProgress('Uploading secret');
      try {
      progress.setStatus('Reading and encrypting…');
      progress.setProgress(null);
      const input = await readSecret();
      const payload = await SenditCrypto.encryptForRecipient(input.plain, publicKey, (msg, frac) => {
        progress.setStatus(msg || 'Encrypting…');
        progress.setProgress(frac == null || !Number.isFinite(frac) ? null : frac);
      });
      if (!uploadPow.ready()) {
        progress.setStatus('Performing proof-of-work…');
        progress.setProgress(null);
      }
      const solved = await uploadPow.take();
      progress.setTitle('Uploading');
      progress.setStatus('Uploading encrypted payload…');
      progress.setProgress(0);
      await SecretTransfer.postJson('/api/plugins/secret-sharing/public/collects/' + encodeURIComponent(id), {
        ciphertext: payload.ciphertext,
        iv: payload.iv,
        wrappedKey: payload.wrappedKey,
        ephemeralPublicKey: payload.ephemeralPublicKey,
        contentType: input.contentType,
        filename: input.filename,
        challengeId: solved.challengeId,
        nonce: solved.nonce,
        hash: solved.hash,
      }, (fraction) => progress.setProgress(fraction));
      payload.ciphertext = null;
      progress.setProgress(1);
      progress.setStatus('Done');
      panel.hidden = true;
      setAlert('ok', 'Encrypted secret uploaded. You can close this page.');
      } finally {
        progress.close();
      }
    } catch (err) {
      setAlert('error', err.message || 'Upload failed.');
      busy = false;
      button.disabled = false;
    }
  });

  async function readJson(res) {
    const text = await res.text();
    let body = null;
    try { body = text ? JSON.parse(text) : null; } catch { body = null; }
    if (!res.ok) throw new Error((body && (body.message || body.error)) || 'This collect is not open.');
    return body;
  }

  async function readSecret() {
    if (selectedKind() === 'file') {
      const file = fileEl.files && fileEl.files[0];
      if (!file) throw new Error('Choose a file to encrypt.');
      if (file.size > FILE_LIMIT) throw new Error('File exceeds 40 MB limit.');
      return { plain: new Uint8Array(await file.arrayBuffer()), contentType: file.type || 'application/octet-stream', filename: file.name };
    }
    const text = textEl.value;
    if (!text) throw new Error('Enter a secret to encrypt.');
    if (text.length > TEXT_LIMIT) throw new Error('Secret text is too long (max ' + TEXT_LIMIT + ' characters).');
    return { plain: new TextEncoder().encode(text), contentType: 'text/plain', filename: null };
  }
})();
