(async function () {
  const params = new URLSearchParams(location.search);
  const id = params.get('id');
  const kind = location.pathname.replace(/\/+$/, '') === '/collect' || params.get('kind') === 'collect' ? 'collect' : 'send';
  const alertEl = document.getElementById('alert');
  const metaBox = document.getElementById('meta');
  const confirmBox = document.getElementById('confirm-box');
  const revealBtn = document.getElementById('reveal');
  const passwordWrap = document.getElementById('link-password-wrap');
  const passwordEl = document.getElementById('link-password');
  const title = document.getElementById('page-title');
  if (!id) { fail('Missing secret id.'); return; }
  const hasFragment = !!(SenditCrypto.secretKeyFromLocationHash(location.hash) || SenditCrypto.secretKeyPackageFromLocationHash(location.hash));
  if (!hasFragment) { fail('Missing decryption key. Open the full link including the #sk= fragment.'); return; }
  await SenditPow.syncServerTime();

  let meta;
  const opening = SecretTransfer.showProgress('Opening secret');
  try {
    opening.setStatus('Performing proof-of-work…');
    opening.setProgress(null);
    if (kind === 'collect') {
      const solution = await SenditPow.solveRefreshing(() => fetchPow('collects'), { onProgress: (_t, attempt) => opening.setStatus(SenditPow.statusLabel('Performing proof-of-work…', attempt)) });
      meta = await SecretTransfer.postJson('/api/plugins/secret-sharing/public/collects/' + encodeURIComponent(id) + '/meta', solution);
    } else {
      const solution = await SenditPow.solveRefreshing(() => fetchPow('sends'), { onProgress: (_t, attempt) => opening.setStatus(SenditPow.statusLabel('Performing proof-of-work…', attempt)) });
      meta = await SecretTransfer.postJson('/api/plugins/secret-sharing/public/sends/' + encodeURIComponent(id) + '/meta', solution);
    }
  } catch (err) {
    fail(err.message || 'This secret is no longer available.');
    return;
  } finally {
    opening.close();
  }

  let sk = kind === 'collect' || !meta.passwordProtected ? SenditCrypto.secretKeyFromLocationHash(location.hash) : null;
  const skPackage = SenditCrypto.secretKeyPackageFromLocationHash(location.hash);
  let displayName = null;
  if (meta.passwordProtected) {
    if (!skPackage) { fail('This secret is password-protected, but the link does not contain a wrapped key.'); return; }
    passwordWrap.classList.remove('hidden');
    revealBtn.disabled = true;
    passwordEl.addEventListener('input', () => { revealBtn.disabled = passwordEl.value.length === 0; });
  } else if (!sk) {
    fail('Missing or invalid decryption key. Open the full link including the #sk= fragment.');
    return;
  } else if (meta.encryptedLabel) {
    try { displayName = await decryptName(meta.encryptedLabel, sk); } catch { fail('Incorrect decryption key.'); return; }
  } else if (meta.publicLabel && sk) {
    try { displayName = new TextDecoder().decode(await SenditCrypto.decryptCollectName(typeof meta.publicLabel === 'string' ? JSON.parse(meta.publicLabel) : meta.publicLabel, SenditCrypto.b64urlDecode(meta.publicKey))); } catch { displayName = null; }
  }

  function renderMeta(extra) {
    const when = meta.expiresAt ? new Date(meta.expiresAt).toLocaleString() : '';
    const mode = meta.oneTime ? 'One-time (destroyed after reveal)' : meta.maxAccessCount ? 'Multi-view (max ' + meta.maxAccessCount + ' opens)' : 'Multi-view until expiry';
    const bits = [];
    if (displayName) bits.push('<p><strong>' + escapeHtml(displayName) + '</strong></p>');
    else if (meta.passwordProtected && (meta.encryptedLabel || meta.publicLabel)) bits.push('<p><strong>Hidden</strong> <span class="muted">(enter the link password to reveal)</span></p>');
    if (kind === 'collect' && !meta.hasPayload) bits.push('<p><strong>Status:</strong> ' + (meta.status === 'waiting' ? 'Waiting for upload' : 'Unavailable') + '</p>');
    if (!(meta.oneTime && extra)) bits.push('<p><strong>Expires:</strong> ' + escapeHtml(when) + '</p>');
    bits.push('<p><strong>Mode:</strong> ' + escapeHtml(mode) + '</p>');
    if (meta.filename) bits.push('<p><strong>File:</strong> ' + escapeHtml(meta.filename) + '</p>');
    if (extra) bits.push(extra);
    metaBox.innerHTML = bits.join('');
    metaBox.classList.remove('hidden');
  }
  renderMeta(null);

  if (kind === 'collect' && !meta.hasPayload) {
    setAlert('info', 'Nothing to collect yet.');
    return;
  }
  if (meta.status === 'consumed' || meta.status === 'expired') {
    fail('This secret is no longer available.');
    return;
  }

  if (meta.oneTime) {
    setAlert('warning', 'This secret can only be displayed once. If you open it, it will be permanently deleted from the server.');
  } else if (meta.maxAccessCount) {
    const left = Math.max(0, meta.maxAccessCount - (meta.accessCount || 0));
    setAlert('info', 'This ' + (kind === 'collect' ? 'collect' : 'send') + ' allows up to ' + meta.maxAccessCount + ' opens (' + left + ' remaining).');
  }
  confirmBox.classList.remove('hidden');
  const revealResource = kind === 'collect' ? 'collects' : 'sends';
  const revealPow = SenditPow.createKeeper(function () { return fetchPow(revealResource); });
  revealPow.start();
  revealBtn.addEventListener('click', reveal);
  if (passwordEl) passwordEl.addEventListener('keydown', (ev) => { if (ev.key === 'Enter') { ev.preventDefault(); reveal(); } });

  async function reveal() {
    revealBtn.disabled = true;
    try {
      if (meta.passwordProtected && !passwordEl.value) {
        setAlert('danger', 'Link password is required.');
        revealBtn.disabled = false;
        return;
      }
      const progress = SecretTransfer.showProgress('Opening secret');
      let key;
      let payload;
      let plain;
      try {
        progress.setStatus(meta.passwordProtected ? 'Unlocking key…' : 'Performing proof-of-work…');
        progress.setProgress(null);
        key = await resolveKey();
        progress.setStatus('Performing proof-of-work…');
        progress.setProgress(null);
        const solution = await revealPow.take();
        progress.setStatus('Downloading encrypted payload…');
        progress.setProgress(0);
        const path = kind === 'collect'
          ? '/api/plugins/secret-sharing/public/collects/' + encodeURIComponent(id) + '/open'
          : '/api/plugins/secret-sharing/public/sends/' + encodeURIComponent(id);
        const buf = await SecretTransfer.requestArrayBuffer('POST', path, solution, (fraction) => progress.setProgress(fraction));
        payload = await SenditCrypto.ingestPayloadResponse(buf);
        progress.setStatus('Decrypting…');
        progress.setProgress(null);
        plain = await SenditCrypto.decryptWithSecretKey(payload, key, (msg, frac) => {
          progress.setStatus(msg || 'Decrypting…');
          progress.setProgress(frac == null || !Number.isFinite(frac) ? null : frac);
        });
      } finally {
        progress.close();
      }
      key.fill(0);
      confirmBox.classList.add('hidden');
      title.textContent = 'Secret';
      document.title = 'Secret';
      const burned = meta.oneTime || (meta.maxAccessCount != null && (meta.accessCount || 0) + 1 >= meta.maxAccessCount);
      setAlert(burned ? 'warning' : 'success', burned ? 'Decrypted. This secret has been destroyed on the server.' : 'Decrypted successfully.');
      const filename = payload.filename || meta.filename;
      const hide = !!(payload.hideTextByDefault || meta.hideTextByDefault);
      if (filename) {
        const blob = SenditCrypto.plainToBlob(plain, payload.contentType || 'application/octet-stream');
        plain = null;
        const url = URL.createObjectURL(blob);
        renderMeta('<p><a class="btn" download="' + escapeHtml(filename) + '" href="' + url + '">Download</a></p>');
      } else {
        const text = await SenditCrypto.plainToText(plain);
        plain = null;
        const shown = hide ? '••••••••' : escapeHtml(text);
        renderMeta('<pre class="secret-reveal" id="secret-text">' + shown + '</pre>' + (hide ? '<div class="show-secret"><button type="button" class="btn" id="show-secret">Show</button></div>' : ''));
        const show = document.getElementById('show-secret');
        if (show) show.addEventListener('click', () => { document.getElementById('secret-text').textContent = text; show.remove(); });
      }
    } catch (err) {
      setAlert('danger', err.message || 'Could not decrypt the secret.');
      revealBtn.disabled = meta.passwordProtected && !passwordEl.value;
    }
  }

  async function resolveKey() {
    if (sk) return sk;
    const password = passwordEl ? passwordEl.value : '';
    if (!password) throw new Error('Link password is required.');
    sk = await SenditCrypto.unwrapSecretKeyWithPassword(skPackage, password);
    if (meta.encryptedLabel && !displayName) {
      try { displayName = await decryptName(meta.encryptedLabel, sk); renderMeta(null); }
      catch { sk.fill(0); sk = null; throw new Error('Incorrect password or decryption key.'); }
    }
    if (passwordEl) passwordEl.value = '';
    return sk;
  }

  function setAlert(kind, message) {
    if (!message) { alertEl.className = 'alert hidden'; alertEl.textContent = ''; return; }
    alertEl.className = 'alert ' + (kind || 'info');
    alertEl.textContent = message;
  }
  function fail(message) {
    metaBox.classList.add('hidden');
    confirmBox.classList.add('hidden');
    setAlert('danger', message);
  }
  function escapeHtml(s) {
    return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  }
  async function fetchPow(resource) {
    const res = await fetch('/api/plugins/secret-sharing/public/' + resource + '/' + encodeURIComponent(id) + '/pow');
    const text = await res.text();
    if (!res.ok) {
      let message = 'This secret is no longer available.';
      try { const body = JSON.parse(text); if (body && body.message) message = body.message; } catch { /* empty */ }
      throw new Error(message);
    }
    return JSON.parse(text);
  }
  async function decryptName(wire, key) {
    const parsed = typeof wire === 'string' ? JSON.parse(wire) : wire;
    const bytes = await SenditCrypto.plainToBytes(await SenditCrypto.decryptWithSecretKey(parsed, key));
    return new TextDecoder().decode(bytes);
  }
})();
