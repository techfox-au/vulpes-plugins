import { confirmIdentity } from '../reauth.js?v=shell258';
import { h, icon, errorMessage, setBusy, formValues, dropdown, filePicker, panelNote, pageNote } from '../ui.js?v=shell370';

export async function appendApplication(ctx, host, rerender) {
  let data;
  try { data = await ctx.api.get('/api/admin/tenants'); }
  catch (err) { host.append(h('div', { class: 'alert danger' }, errorMessage(err))); return; }
  host.append(applicationCard(ctx, data.application || {}, data.permissions || [], data.tenants || [], host, rerender));
}

function applicationCard(ctx, app, permissions, tenants, host, rerender) {
  const card = h('div', { class: 'card' });
  const form = h('form', { class: 'stack' });
  const credential = dropdown([['secret', 'Client secret'], ['certificate', 'Certificate (PFX)']], { value: app.credentialType || 'secret', name: 'credentialType', ariaLabel: 'Credential' });
  const mask = '••••••••';
  let revealedSecrets = null;
  const secretField = (key, label, configured) => {
    const field = h('input', { class: 'input', type: configured ? 'password' : 'text', value: configured ? mask : '', autocomplete: 'off', spellcheck: false, readOnly: configured });
    const button = h('button', { class: 'secret-tool secret-eye', type: 'button', title: 'Show secret', 'aria-label': 'Show secret' }, icon('eye'));
    button.hidden = !configured;
    let revealed = false;
    const eyeLabel = (showing) => {
      const text = showing ? 'Hide secret' : 'Show secret';
      button.title = text;
      button.setAttribute('aria-label', text);
    };
    button.addEventListener('click', async () => {
      if (!revealed) {
        if (!revealedSecrets) {
          const me = await ctx.api.get('/api/account');
          if (!(await confirmIdentity(ctx, me))) return;
          try { revealedSecrets = await ctx.api.get('/api/admin/tenants/application/secrets'); }
          catch (err) {
            if (err.code !== 'reauth_required') { panelNote(card, errorMessage(err)); return; }
            if (!(await confirmIdentity(ctx, me))) return;
            revealedSecrets = await ctx.api.get('/api/admin/tenants/application/secrets');
          }
        }
        field.value = revealedSecrets[key] || '';
        field.readOnly = false;
        field.type = 'text';
        revealed = true;
        button.hidden = false;
        eyeLabel(true);
        return;
      }
      const hidden = field.type === 'text';
      field.type = hidden ? 'password' : 'text';
      eyeLabel(hidden);
    });
    const payload = () => {
      if (field.readOnly) return { secret: '', remove: false };
      const text = field.value.trim();
      if (text === mask) return { secret: '', remove: false };
      return { secret: text, remove: revealed && text.length === 0 };
    };
    return {
      line: h('div', { class: 'field' }, h('label', null, label), h('div', { class: 'secret-box secret-line' }, field, h('div', { class: 'secret-box-tools' }, button))),
      payload,
    };
  };
  const clientSecret = secretField('secret', 'Client secret', app.hasSecret === true);
  const certificatePassword = secretField('certificatePassword', 'PFX password', app.hasCertificatePassword === true);
  const certificateRow = h('div', { class: 'form-row' },
    h('div', { class: 'field' }, h('label', null, 'Certificate (PFX)'), filePicker({ name: 'pfx', accept: '.pfx,.p12' })),
    certificatePassword.line);
  const showCredential = () => {
    const certificate = credential.value === 'certificate';
    clientSecret.line.hidden = certificate;
    certificateRow.hidden = !certificate;
  };
  credential.addEventListener('change', showCredential);
  showCredential();
  const clientIdInput = h('input', { class: 'input', name: 'clientId', value: app.clientId || '', spellcheck: false, required: true, autocomplete: 'off' });
  const cloud = dropdown([['Global', 'Global'], ['USGov', 'US Government']], { value: app.cloud || 'Global', name: 'cloud', ariaLabel: 'Cloud' });
  const directoryInput = h('input', { class: 'input', spellcheck: false, autocomplete: 'off', placeholder: '00000000-0000-0000-0000-000000000000', 'aria-label': 'Customer directory id' });
  const consentUrl = h('input', { class: 'input', readOnly: true, spellcheck: false, 'aria-label': 'Admin consent URL' });
  const redirectInput = h('input', { class: 'input', type: 'url', spellcheck: false, autocomplete: 'off', placeholder: 'https://invoice.techfox.au', 'aria-label': 'Redirect URI' });
  const openConsent = h('a', { class: 'btn sm', target: '_blank', rel: 'noopener noreferrer', hidden: true }, 'Open');
  const copyConsent = h('button', { class: 'btn sm', type: 'button' }, 'Copy');
  const guid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
  const paintConsent = () => {
    const clientId = clientIdInput.value.trim();
    const directoryId = directoryInput.value.trim();
    const login = cloud.value === 'USGov' ? 'https://login.microsoftonline.us' : 'https://login.microsoftonline.com';
    const graph = cloud.value === 'USGov' ? 'https://graph.microsoft.us' : 'https://graph.microsoft.com';
    let reply = '';
    try {
      const parsed = new URL(redirectInput.value.trim());
      if (parsed.protocol === 'https:') reply = parsed.href.replace(/\/$/, '');
    } catch { /* blank until the redirect is https */ }
    const ready = guid.test(clientId) && guid.test(directoryId) && reply;
    const url = ready
      ? `${login}/${directoryId}/v2.0/adminconsent?client_id=${encodeURIComponent(clientId)}&scope=${encodeURIComponent(graph + '/.default')}&redirect_uri=${encodeURIComponent(reply)}`
      : '';
    consentUrl.value = url;
    openConsent.hidden = !url;
    if (url) openConsent.href = url;
    copyConsent.disabled = !url;
  };
  clientIdInput.addEventListener('input', paintConsent);
  directoryInput.addEventListener('input', paintConsent);
  redirectInput.addEventListener('input', paintConsent);
  cloud.addEventListener('change', paintConsent);
  copyConsent.addEventListener('click', async () => {
    if (!consentUrl.value) return;
    try { await navigator.clipboard.writeText(consentUrl.value); pageNote(host, 'Consent link copied.', 'success'); }
    catch (err) { panelNote(card, errorMessage(err)); }
  });
  paintConsent();
  const savedClients = (tenants || []).filter((t) => guid.test(t.directoryId || ''));
  const savedClient = savedClients.length
    ? dropdown([['', 'Choose a saved client'], ...savedClients.map((t) => [t.directoryId, t.displayName])], { value: '', ariaLabel: 'Saved client' })
    : null;
  if (savedClient) savedClient.addEventListener('change', () => {
    if (savedClient.value) directoryInput.value = savedClient.value;
    paintConsent();
  });
  form.append(
    h('div', { class: 'form-row' },
      h('div', { class: 'field' }, h('label', null, 'Application (client) id'), clientIdInput),
      h('div', { class: 'field' }, h('label', null, 'Cloud'), cloud)),
    h('div', { class: 'form-row' },
      h('div', { class: 'field' }, h('label', null, 'Credential'), credential),
      clientSecret.line),
    certificateRow,
    h('div', { class: 'field' },
      h('label', null, 'Admin consent'),
      h('div', { class: 'field' }, h('label', null, 'Redirect URI'), redirectInput),
      savedClient ? h('div', { class: 'field' }, h('label', null, 'Saved client'), savedClient) : null,
      h('div', { class: 'field' }, h('label', null, 'Customer directory id'), directoryInput),
      h('div', { class: 'form-row' },
        h('div', { class: 'field' }, consentUrl),
        h('div', { class: 'flex' }, copyConsent, openConsent))),
    h('div', { class: 'field' }, h('label', null, 'Application permissions'), permissions.length
      ? h('div', { class: 'stack' }, ...permissions.map((p) => h('div', null, h('span', { class: 'mono' }, p.name), h('span', { class: 'small muted' }, ' ' + p.purpose))))
      : h('p', { class: 'small muted' }, 'No plugin has declared permissions yet.')),
    h('div', { class: 'flex end' }, h('button', { class: 'btn primary', type: 'submit' }, 'Save application')));
  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    panelNote(card, '');
    const button = form.querySelector('button[type="submit"]');
    const values = formValues(form);
    const certificate = values.credentialType === 'certificate';
    const secret = clientSecret.payload();
    const pfxPassword = certificatePassword.payload();
    const file = certificate ? form.querySelector('input[name="pfx"]').files?.[0] : null;
    let pfx = null;
    if (file) {
      const buf = await file.arrayBuffer();
      pfx = btoa(String.fromCharCode(...new Uint8Array(buf)));
    }
    setBusy(button, true, 'Saving…');
    try {
      await ctx.api.put('/api/admin/tenants/application', {
        clientId: values.clientId, credentialType: values.credentialType, cloud: values.cloud,
        secret: certificate ? null : (secret.secret || null),
        removeSecret: !certificate && secret.remove,
        certificatePfxBase64: pfx,
        certificatePassword: certificate ? (pfxPassword.secret || null) : null,
        removeCertificatePassword: certificate && pfxPassword.remove,
      });
      await rerender();
      pageNote(host, 'Application saved.', 'success');
    } catch (err) { panelNote(card, errorMessage(err)); }
    finally { setBusy(button, false); }
  });
  card.append(h('div', { class: 'card-header' }, h('h2', null, 'Application')), form);
  return card;
}
