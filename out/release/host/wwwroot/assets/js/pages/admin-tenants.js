import { confirmIdentity } from '../reauth.js?v=shell258';
import { h, icon, table, modal, errorMessage, clear, dropdown, filePicker, panelNote, pageNote, badge } from '../ui.js?v=shell161';

let root;
const plugin = '/api/plugins/microsoft-365-audit';

export async function mount(el, ctx) { root = el; root.classList.add('page-scroll'); ctx.setTitle(['Tenants']); await render(ctx); }
export function unmount() { root = null; }

async function render(ctx) {
  clear(root);
  let data;
  try { data = await ctx.api.get('/api/admin/tenants'); }
  catch (err) { root.append(h('div', { class: 'alert danger' }, errorMessage(err))); return; }
  const app = data.application || {};
  let pluginReady = false;
  try { await ctx.api.get(plugin + '/sources'); pluginReady = true; } catch { /* collection controls stay hidden */ }

  root.append(h('div', { class: 'page-header' }, h('h1', null, 'Tenants')));
  root.append(applicationCard(ctx, app, data.permissions || [], data.tenants || []));
  const applicationReady = !!(app.clientId && (app.credentialType === 'certificate' ? app.hasCertificate : app.hasSecret));
  root.append(h('div', { class: 'page-header' },
    h('h2', null, 'Clients'),
    h('button', { class: 'btn primary', disabled: !applicationReady, title: applicationReady ? undefined : 'Save the application first.', onClick: () => editTenant(ctx, null) }, 'Add client')));
  root.append(table({
    columns: [
      { title: 'Name', render: (t) => h('div', null, h('strong', null, t.displayName), t.shortName ? h('span', { class: 'small muted' }, ' ' + t.shortName) : null, t.discoveredName && t.discoveredName !== t.displayName ? h('div', { class: 'small muted' }, t.discoveredName) : null) },
      { title: 'Directory id', render: (t) => h('span', { class: 'mono small' }, t.directoryId) },
      { title: 'Status', render: (t) => t.enabled ? badge('enabled', 'success') : badge('disabled', 'warning') },
      { title: '', class: 'right', render: (t) => h('div', { class: 'flex' },
        h('button', { class: 'btn sm', onClick: (e) => { e.stopPropagation(); editTenant(ctx, t); } }, 'Edit'),
        pluginReady ? h('button', { class: 'btn sm', onClick: (e) => { e.stopPropagation(); collection(ctx, t); } }, 'Collection') : null,
        pluginReady ? h('button', { class: 'btn sm', onClick: (e) => { e.stopPropagation(); testTenant(ctx, t, e.currentTarget); } }, 'Test') : null,
        h('button', { class: 'btn sm danger', onClick: (e) => { e.stopPropagation(); removeTenant(ctx, t); } }, 'Delete')) },
    ],
    rows: data.tenants || [],
    emptyText: 'No clients yet.',
  }));
}

function applicationCard(ctx, app, permissions, tenants) {
  const { h, setBusy, formValues } = ctx.ui;
  const card = h('div', { class: 'card' });
  const form = h('form', { class: 'stack' });
  const input = (label, name, attrs) => h('div', { class: 'field' }, h('label', null, label), h('input', { class: 'input', name, autocomplete: 'off', ...attrs }));
  const credential = dropdown([['secret', 'Client secret'], ['certificate', 'Certificate (PFX)']], { value: app.credentialType || 'secret', name: 'credentialType', ariaLabel: 'Credential' });
  const mask = '••••••••';
  let revealedSecrets = null;
  const secretField = (key, label, configured) => {
    const field = h('input', {
      class: 'input',
      type: configured ? 'password' : 'text',
      value: configured ? mask : '',
      autocomplete: 'off',
      spellcheck: false,
      readOnly: configured,
    });
    const button = h('button', {
      class: 'secret-tool secret-eye',
      type: 'button',
      title: 'Show secret',
      'aria-label': 'Show secret',
    }, icon('eye'));
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
          try {
            revealedSecrets = await ctx.api.get('/api/admin/tenants/application/secrets');
          } catch (err) {
            if (err.code !== 'reauth_required') {
              panelNote(card, errorMessage(err));
              return;
            }
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
  const certificatePassword = secretField('certificatePassword', app.hasCertificatePassword ? 'PFX password (blank keeps the stored one)' : 'PFX password', app.hasCertificatePassword === true);
  const certificateRow = h('div', { class: 'form-row' },
    h('div', { class: 'field' }, h('label', null, app.hasCertificate ? 'Certificate (leave empty to keep the stored one)' : 'Certificate (PFX)'), filePicker({ name: 'pfx', accept: '.pfx,.p12' })),
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
    } catch { /* the consent link stays blank until the redirect is a public https address */ }
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
    try {
      await navigator.clipboard.writeText(consentUrl.value);
      pageNote(root, 'Consent link copied.', 'success');
    } catch (err) {
      panelNote(card, errorMessage(err));
    }
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
      await render(ctx);
      pageNote(root, 'Application saved.', 'success');
    } catch (err) { panelNote(card, errorMessage(err)); }
    finally { setBusy(button, false); }
  });
  card.append(h('div', { class: 'card-header' }, h('h2', null, 'Application')), form);
  return card;
}

async function editTenant(ctx, existing) {
  const { h, modal } = ctx.ui;
  const name = h('input', { class: 'input', value: existing?.displayName || '', required: true });
  const shortName = h('input', { class: 'input', value: existing?.shortName || '', maxlength: '16', spellcheck: false, autocomplete: 'off' });
  const directory = h('input', { class: 'input', value: existing?.directoryId || '', spellcheck: false, placeholder: '00000000-0000-0000-0000-000000000000' });
  const enabled = h('input', { type: 'checkbox', checked: existing ? existing.enabled : true });
  const form = h('div', { class: 'col' },
    h('div', { class: 'field' }, h('label', null, 'Display name'), name),
    h('div', { class: 'field' }, h('label', null, 'Short name'), shortName),
    h('div', { class: 'field' }, h('label', null, 'Directory id'), directory),
    h('label', { class: 'checkbox' }, enabled, h('span', null, 'Collection enabled')));
  const saved = await modal.show({ title: existing ? 'Edit client' : 'Add client', content: form, actions: [{ label: 'Cancel', value: false }, { label: existing ? 'Save' : 'Add', kind: 'primary', value: true, onClick: async () => {
    try {
      const body = { displayName: name.value.trim(), shortName: shortName.value.trim(), directoryId: directory.value.trim(), enabled: enabled.checked };
      if (existing) await ctx.api.put(`/api/admin/tenants/${existing.id}`, body);
      else await ctx.api.post('/api/admin/tenants', body);
    } catch (err) { panelNote(form, errorMessage(err)); return false; }
  } }] });
  if (saved) { await render(ctx); pageNote(root, existing ? 'Client saved.' : 'Client added.', 'success'); }
}

async function removeTenant(ctx, tenant) {
  if (!(await ctx.ui.modal.confirm('Delete client', `Stop collecting from ${tenant.displayName}?`, { danger: true, confirmLabel: 'Delete' }))) return;
  try {
    await ctx.api.delete(`/api/admin/tenants/${tenant.id}`);
    await render(ctx);
    pageNote(root, 'Client removed.', 'success');
  } catch (err) { pageNote(root, errorMessage(err)); }
}

async function testTenant(ctx, tenant, button) {
  ctx.ui.setBusy(button, true, 'Testing…');
  try {
    const result = await ctx.api.post(`/api/admin/tenants/${tenant.id}/test`);
    await render(ctx);
    const report = result?.reports?.[0];
    if (!report) { pageNote(root, 'No plugin tested this client.'); return; }
    const probes = report.probes || [];
    const failed = !report.tokenAcquired || probes.some((p) => p.status === 'forbidden' || p.status === 'error');
    pageNote(root, describeTest(report), failed ? 'danger' : 'success');
  } catch (err) {
    if (button?.isConnected) ctx.ui.setBusy(button, false);
    pageNote(root, errorMessage(err));
  }
}

function describeTest(report) {
  if (!report.tokenAcquired) return report.error || 'Token acquisition failed.';
  const lines = [];
  lines.push(report.organizationName ? `Connected to ${report.organizationName}.` : 'Connected.');
  for (const probe of report.probes || []) {
    lines.push(`${probe.title || probe.source}: ${probe.status}${probe.detail ? ` — ${probe.detail}` : ''}`);
  }
  if ((report.probes || []).length === 0) lines.push('No sources were checked.');
  if (report.error) lines.push(report.error);
  return lines.join('\n');
}

async function collection(ctx, tenant) {
  const { h, modal } = ctx.ui;
  const [detail, sources] = await Promise.all([
    ctx.api.get(`${plugin}/tenants/${tenant.id}`),
    ctx.api.get(`${plugin}/sources`),
  ]);
  const look = h('input', { class: 'input', type: 'number', min: 1, max: 180, value: detail.lookbackDays ?? 7 });
  const rows = [];
  const box = h('div', { class: 'col' });
  for (const s of sources.filter((x) => x.collector)) {
    const cfg = (detail.settings?.sources || {})[s.source] || {};
    const blocked = s.unavailable === true;
    const en = h('input', { type: 'checkbox', checked: blocked ? false : cfg.enabled !== false, disabled: blocked });
    const interval = h('input', { class: 'input sm', type: 'number', min: 1, placeholder: String(s.collector.defaultIntervalMinutes), value: cfg.intervalMinutes ?? '' });
    const nonInteractive = s.source === 'signins' ? h('input', { type: 'checkbox', checked: cfg.includeNonInteractive !== false }) : null;
    const recordTypes = s.source === 'activity' ? h('input', { class: 'input sm', placeholder: 'default record types', value: (cfg.recordTypes || []).join(',') }) : null;
    rows.push({ source: s.source, en, interval, nonInteractive, recordTypes, keepEnabled: blocked ? cfg.enabled !== false : null });
    box.append(h('div', { class: 'form-row' },
      h('label', { class: 'checkbox', title: blocked ? 'Disabled in Microsoft 365 Business Premium mode' : undefined }, en, h('span', null, s.collector.title), blocked ? h('span', { class: 'small muted' }, 'Not included with Business Premium') : null),
      h('div', { class: 'flex' }, h('span', { class: 'small muted nowrap' }, 'every'), interval, h('span', { class: 'small muted' }, 'min')),
      nonInteractive ? h('label', { class: 'checkbox' }, nonInteractive, h('span', { class: 'small' }, 'incl. non-interactive')) : (recordTypes || h('span'))));
  }
  const form = h('div', { class: 'col' }, h('div', { class: 'field' }, h('label', null, 'Initial lookback (days)'), look), box);
  const saved = await modal.show({ title: tenant.displayName, content: form, wide: true, actions: [{ label: 'Cancel', value: false }, { label: 'Save', kind: 'primary', value: true, onClick: async () => {
    const settings = { sources: {} };
    for (const r of rows) {
      const entry = { enabled: r.keepEnabled === null ? r.en.checked : r.keepEnabled };
      if (r.interval.value) entry.intervalMinutes = Number(r.interval.value);
      if (r.nonInteractive) entry.includeNonInteractive = r.nonInteractive.checked;
      if (r.recordTypes && r.recordTypes.value.trim()) entry.recordTypes = r.recordTypes.value.split(',').map((s) => s.trim()).filter(Boolean);
      settings.sources[r.source] = entry;
    }
    try { await ctx.api.put(`${plugin}/tenants/${tenant.id}/collection`, { lookbackDays: Number(look.value || 7), settings }); }
    catch (err) { panelNote(form, errorMessage(err)); return false; }
  } }] });
  if (saved) pageNote(root, 'Collection saved.', 'success');
}
