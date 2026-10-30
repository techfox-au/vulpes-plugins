import { h, table, modal, errorMessage, clear, dropdown, panelNote, pageNote, badge } from '../ui.js?v=shell84';

let root;
const plugin = '/api/plugins/microsoft-365-audit';

export async function mount(el, ctx) { root = el; ctx.setTitle(['Tenants']); await render(ctx); }
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
  root.append(applicationCard(ctx, app, data.permissions || []));
  const applicationReady = !!(app.clientId && (app.credentialType === 'certificate' ? app.hasCertificate : app.hasSecret));
  root.append(h('div', { class: 'page-header' },
    h('h2', null, 'Clients'),
    h('button', { class: 'btn primary', disabled: !applicationReady, title: applicationReady ? undefined : 'Save the application first.', onClick: () => editTenant(ctx, null) }, 'Add client')));
  root.append(table({
    columns: [
      { title: 'Name', render: (t) => h('div', null, h('strong', null, t.displayName), t.discoveredName && t.discoveredName !== t.displayName ? h('div', { class: 'small muted' }, t.discoveredName) : null) },
      { title: 'Directory id', render: (t) => h('span', { class: 'mono small' }, t.directoryId) },
      { title: 'Status', render: (t) => t.enabled ? badge('enabled', 'success') : badge('disabled', 'warning') },
      { title: '', class: 'right', render: (t) => h('div', { class: 'flex' },
        h('button', { class: 'btn sm', onClick: (e) => { e.stopPropagation(); editTenant(ctx, t); } }, 'Edit'),
        pluginReady ? h('button', { class: 'btn sm', onClick: (e) => { e.stopPropagation(); collection(ctx, t); } }, 'Collection') : null,
        pluginReady ? h('button', { class: 'btn sm', onClick: (e) => { e.stopPropagation(); testTenant(ctx, t); } }, 'Test') : null,
        h('button', { class: 'btn sm danger', onClick: (e) => { e.stopPropagation(); removeTenant(ctx, t); } }, 'Delete')) },
    ],
    rows: data.tenants || [],
    emptyText: 'No clients yet.',
  }));
}

function applicationCard(ctx, app, permissions) {
  const { h, setBusy, formValues } = ctx.ui;
  const card = h('div', { class: 'card' });
  const form = h('form', { class: 'stack' });
  const input = (label, name, attrs) => h('div', { class: 'field' }, h('label', null, label), h('input', { class: 'input', name, autocomplete: 'off', ...attrs }));
  form.append(
    h('div', { class: 'form-row' },
      input('Application (client) id', 'clientId', { value: app.clientId || '', spellcheck: false, required: true }),
      h('div', { class: 'field' }, h('label', null, 'Cloud'), dropdown([['Global', 'Global'], ['USGov', 'US Government']], { value: app.cloud || 'Global', name: 'cloud', ariaLabel: 'Cloud' }))),
    h('div', { class: 'form-row' },
      h('div', { class: 'field' }, h('label', null, 'Credential'), dropdown([['secret', 'Client secret'], ['certificate', 'Certificate (PFX)']], { value: app.credentialType || 'secret', name: 'credentialType', ariaLabel: 'Credential' })),
      input(app.hasSecret ? 'Client secret (blank keeps the stored one)' : 'Client secret', 'secret', { type: 'password' })),
    h('div', { class: 'form-row' },
      h('div', { class: 'field' }, h('label', null, app.hasCertificate ? 'Certificate (leave empty to keep the stored one)' : 'Certificate (PFX)'), h('input', { class: 'input', name: 'pfx', type: 'file', accept: '.pfx,.p12' })),
      input('PFX password', 'certificatePassword', { type: 'password' })),
    h('div', { class: 'field' }, h('label', null, 'Application permissions'), permissions.length
      ? h('div', { class: 'stack' }, ...permissions.map((p) => h('div', null, h('span', { class: 'mono' }, p.name), h('span', { class: 'small muted' }, ' ' + p.purpose))))
      : h('p', { class: 'small muted' }, 'No plugin has declared permissions yet.')),
    h('div', { class: 'flex end' }, h('button', { class: 'btn primary', type: 'submit' }, 'Save application')));
  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    panelNote(card, '');
    const button = form.querySelector('button[type="submit"]');
    const values = formValues(form);
    const file = form.querySelector('input[name="pfx"]').files?.[0];
    let pfx = null;
    if (file) {
      const buf = await file.arrayBuffer();
      pfx = btoa(String.fromCharCode(...new Uint8Array(buf)));
    }
    setBusy(button, true, 'Saving…');
    try {
      await ctx.api.put('/api/admin/tenants/application', {
        clientId: values.clientId, credentialType: values.credentialType, cloud: values.cloud,
        secret: values.secret || null, certificatePfxBase64: pfx, certificatePassword: values.certificatePassword || null,
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
  const directory = h('input', { class: 'input', value: existing?.directoryId || '', spellcheck: false, placeholder: '00000000-0000-0000-0000-000000000000' });
  const enabled = h('input', { type: 'checkbox', checked: existing ? existing.enabled : true });
  const form = h('div', { class: 'col' },
    h('div', { class: 'field' }, h('label', null, 'Display name'), name),
    h('div', { class: 'field' }, h('label', null, 'Directory id'), directory),
    h('label', { class: 'checkbox' }, enabled, h('span', null, 'Collection enabled')));
  const saved = await modal.show({ title: existing ? 'Edit client' : 'Add client', content: form, actions: [{ label: 'Cancel', value: false }, { label: existing ? 'Save' : 'Add', kind: 'primary', value: true, onClick: async () => {
    try {
      const body = { displayName: name.value.trim(), directoryId: directory.value.trim(), enabled: enabled.checked };
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

async function testTenant(ctx, tenant) {
  try {
    const result = await ctx.api.post(`/api/admin/tenants/${tenant.id}/test`);
    const report = result.reports?.[0];
    if (!report) { pageNote(root, 'No plugin tested this client.'); return; }
    if (!report.tokenAcquired) { pageNote(root, report.error || 'Token acquisition failed.'); return; }
    const ok = (report.probes || []).filter((p) => p.status === 'ok').length;
    pageNote(root, report.organizationName ? `Connected to ${report.organizationName}. ${ok} sources accessible.` : `${ok} sources accessible.`, report.error ? 'danger' : 'success');
    if (report.error) pageNote(root, report.error);
    await render(ctx);
  } catch (err) { pageNote(root, errorMessage(err)); }
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
