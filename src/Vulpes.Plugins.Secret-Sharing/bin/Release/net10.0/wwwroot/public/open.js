import { VulpesPow, statusLabel } from '/assets/js/pow.js?v=pow1';

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
  await VulpesPow.sync();

  let meta;
  const opening = SecretTransfer.showProgress('Opening secret');
  try {
    opening.setStatus('Performing proof-of-work…');
    opening.setProgress(null);
    if (kind === 'collect') {
      const solution = await VulpesPow.solve(() => fetchPow('collects'), { onProgress: (_t, attempt) => opening.setStatus(statusLabel('Performing proof-of-work…', attempt)) });
      meta = await SecretTransfer.postJson('/api/plugins/secret-sharing/public/collects/' + encodeURIComponent(id) + '/meta', solution);
    } else {
      const solution = await VulpesPow.solve(() => fetchPow('sends'), { onProgress: (_t, attempt) => opening.setStatus(statusLabel('Performing proof-of-work…', attempt)) });
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
    if (displayName) bits.push('<p class="upload-name">' + escapeHtml(displayName) + '</p>');
    else if (meta.passwordProtected && (meta.encryptedLabel || meta.publicLabel)) bits.push('<p><span class="upload-name">Hidden</span> <span class="muted">(enter the link password to reveal)</span></p>');
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
  const revealPow = VulpesPow.keeper(() => fetchPow(kind === 'collect' ? 'collects' : 'sends'));
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
        const solving = revealPow && !revealPow.ready();
        progress.setStatus(meta.passwordProtected ? 'Unlocking key…' : (solving ? 'Performing proof-of-work…' : 'Downloading encrypted payload…'));
        progress.setProgress(null);
        key = await resolveKey();
        let solution = null;
        if (revealPow) {
          if (!revealPow.ready()) {
            progress.setStatus('Performing proof-of-work…');
            progress.setProgress(null);
          }
          solution = await revealPow.take();
        }
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
      if (revealPow) revealPow.stop();
      confirmBox.classList.add('hidden');
      title.textContent = 'Secret';
      document.title = 'Secret';
      const burned = meta.oneTime || (meta.maxAccessCount != null && (meta.accessCount || 0) + 1 >= meta.maxAccessCount);
      if (burned) setAlert('warning', 'This secret has been destroyed on the server.');
      else setAlert(null);
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
        renderMeta(null);
        metaBox.append(secretBox(text, hide));
      }
    } catch (err) {
      const message = err.message || 'Could not decrypt the secret.';
      if (message.indexOf('not available from your IP') !== -1) {
        fail(message);
        return;
      }
      setAlert('danger', message);
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
    if (String(message).indexOf('not available from your IP') !== -1) {
      metaBox.classList.add('hidden');
      confirmBox.classList.add('hidden');
      metaBox.hidden = true;
      confirmBox.hidden = true;
    }
  }
  function fail(message) {
    metaBox.classList.add('hidden');
    confirmBox.classList.add('hidden');
    setAlert('danger', message);
  }
  function secretBox(text, mask) {
    const wrap = document.createElement('div');
    wrap.className = 'secret-box';
    const tools = document.createElement('div');
    tools.className = 'secret-box-tools';
    const pre = document.createElement('pre');
    pre.className = 'secret-reveal';
    let visible = !mask;
    const eye = document.createElement('button');
    eye.type = 'button';
    eye.className = 'secret-tool';
    const copy = document.createElement('button');
    copy.type = 'button';
    copy.className = 'secret-tool';
    copy.title = 'Copy secret';
    copy.setAttribute('aria-label', 'Copy secret');
    copy.append(svgIcon(['M9 9h11a2 2 0 0 1 2 2v11a2 2 0 0 1-2 2H9a2 2 0 0 1-2-2V11a2 2 0 0 1 2-2z', 'M5 15V6a2 2 0 0 1 2-2h9']));
    function paint() {
      pre.textContent = visible ? text : '\u2022'.repeat(Math.max(text.length, 8));
      pre.classList.toggle('is-hidden', !visible);
      if (!mask) return;
      eye.replaceChildren(svgIcon(visible
        ? ['M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94', 'M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19', 'M14.12 14.12a3 3 0 1 1-4.24-4.24', 'M1 1l22 22']
        : ['M2 12s3.5-6 10-6 10 6 10 6-3.5 6-10 6S2 12 2 12z', 'M12 9a3 3 0 1 0 0 6 3 3 0 0 0 0-6z']));
      eye.title = visible ? 'Hide secret' : 'Show secret';
      eye.setAttribute('aria-label', eye.title);
      eye.setAttribute('aria-pressed', visible ? 'true' : 'false');
    }
    if (mask) {
      eye.addEventListener('click', () => { visible = !visible; paint(); });
      tools.append(eye);
    }
    copy.addEventListener('click', async () => {
      try {
        await navigator.clipboard.writeText(text);
        copy.title = 'Copied';
        setTimeout(() => { copy.title = 'Copy secret'; }, 1500);
      } catch { copy.title = 'Could not copy'; }
    });
    tools.append(copy);
    paint();
    wrap.append(tools, pre);
    return wrap;
  }
  function svgIcon(paths) {
    const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    svg.setAttribute('viewBox', '0 0 24 24');
    svg.setAttribute('aria-hidden', 'true');
    for (const d of paths) {
      const path = document.createElementNS(svg.namespaceURI, 'path');
      path.setAttribute('d', d);
      svg.append(path);
    }
    return svg;
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
