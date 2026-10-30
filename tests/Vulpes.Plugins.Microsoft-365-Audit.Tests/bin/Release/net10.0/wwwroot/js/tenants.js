import { statusBadge } from './common.js';

let root;
export async function mount(el, ctx) {
  root = el;
  const { h } = ctx.ui;
  if (ctx.hasRole('Admin')) el.querySelector('[data-role="actions"]').append(h('button', { class: 'btn primary', onClick: () => editTenant(ctx, null) }, 'Add tenant'));
  await render(ctx);
}
export function unmount() { root = null; }

async function render(ctx) {
  const { h, clear, table, badge, fmt, errorMessage } = ctx.ui;
  const list = root.querySelector('[data-role="list"]');
  clear(list);
  let tenants; let sources;
  try { [tenants, sources] = await Promise.all([ctx.api.get(`${ctx.module.apiBase}/tenants`), ctx.api.get(`${ctx.module.apiBase}/sources`)]); }
  catch (err) { list.append(h('div', { class: 'alert danger' }, errorMessage(err))); return; }

  if (tenants.length === 0) {
    list.append(h('div', { class: 'card' },
      h('h2', null, 'No tenants yet'),
      h('p', { class: 'muted' }, 'Register an application in Microsoft Entra ID, grant it the application permissions listed below with admin consent, then add the tenant here with its client secret or certificate.'),
      h('ul', { class: 'small' }, sources.filter((s) => s.collector).map((s) => h('li', null, h('strong', null, s.collector.title), ': ', s.collector.permissions.join(', ')))),
      h('h3', { class: 'mt' }, 'Turn on Microsoft 365 audit logging'),
      h('p', { class: 'muted' }, 'The Activity feed is the unified audit log. If recording is off, Exchange, SharePoint, OneDrive and Teams events are never written, and the collector has nothing to fetch.'),
      h('p', null, 'In the Purview portal (purview.microsoft.com) or the Defender portal (security.microsoft.com), open Audit. If the banner Start recording user and admin activity is shown, select it. If that banner is absent, recording is already on. You need the Audit Logs role, or Compliance Administrator or Global Administrator.'),
      h('p', { class: 'muted' }, 'Or with Exchange Online PowerShell:'),
      h('pre', { class: 'mono' }, 'Connect-ExchangeOnline\nGet-AdminAuditLogConfig | Format-List UnifiedAuditLogIngestionEnabled\nSet-AdminAuditLogConfig -UnifiedAuditLogIngestionEnabled $true'),
      h('p', { class: 'muted' }, 'The change can take up to 60 minutes. Mailbox auditing is on by default and is what produces Exchange item activity. Confirm it has not been switched off:'),
      h('pre', { class: 'mono' }, 'Get-OrganizationConfig | Format-List AuditDisabled'),
      h('p', { class: 'muted' }, 'AuditDisabled must be False.')));
    return;
  }

  list.append(table({
    columns: [
      { title: 'Tenant', render: (t) => h('div', null, h('div', null, h('strong', null, t.displayName), ' ', t.enabled ? null : badge('disabled', 'warning')), h('div', { class: 'small muted mono' }, t.tenantId), t.discoveredName ? h('div', { class: 'small muted' }, t.discoveredName) : null) },
      { title: 'Credential', render: (t) => h('div', null, badge(t.credentialType === 'certificate' ? 'certificate' : 'client secret'), h('div', { class: 'small muted mono' }, t.clientId)) },
      { title: 'Cloud', path: 'cloud', render: (t) => t.cloud },
      { title: 'Last test', render: (t) => t.lastTest ? h('div', null, t.lastTest.tokenAcquired ? badge(`${t.lastTest.probes.filter((p) => p.status === 'ok').length}/${t.lastTest.probes.length} sources ok`, t.lastTest.probes.every((p) => p.status === 'ok') ? 'success' : 'warning') : badge('token failed', 'danger'), h('div', { class: 'small muted' }, fmt.relative(t.lastTestAt))) : h('span', { class: 'cell-muted' }, 'never') },
      { title: 'Collection', render: (t) => {
        const cps = t.checkpoints || [];
        const failed = cps.filter((c) => c.lastStatus === 'failed').length;
        const total = cps.reduce((a, c) => a + (c.totalCount || 0), 0);
        return h('div', null, cps.length === 0 ? badge('not started') : failed ? badge(`${failed} failing`, 'danger') : badge('healthy', 'success'), h('div', { class: 'small muted' }, `${fmt.number(total)} events total`));
      } },
      { title: 'Lookback', render: (t) => `${t.lookbackDays} d` },
    ],
    rows: tenants,
    onRowClick: (t) => openTenant(ctx, t.id, sources),
  }));
}

async function openTenant(ctx, id, sources) {
  const { h, kv, fmt, badge, drawer, modal, toast, errorMessage, table } = ctx.ui;
  const t = await ctx.api.get(`${ctx.module.apiBase}/tenants/${id}`);
  const isAdmin = ctx.hasRole('Admin');
  const body = h('div', { class: 'col gap-lg' });
  body.append(kv([['Tenant id', t.tenantId], ['Client id', t.clientId], ['Credential', t.credentialType], ['Cloud', t.cloud], ['Enabled', fmt.bool(t.enabled)], ['Lookback', `${t.lookbackDays} days`], ['Added', `${fmt.dateTime(t.createdAt)}${t.createdBy ? ' by ' + t.createdBy : ''}`], ['Organisation', t.discoveredName]]));

  const actions = h('div', { class: 'btn-group' });
  if (isAdmin) {
    actions.append(h('button', { class: 'btn', onClick: () => { drawer.close(); editTenant(ctx, t); } }, 'Edit'));
    const testBtn = h('button', { class: 'btn', onClick: async () => {
      ctx.ui.setBusy(testBtn, true, 'Testing…');
      try { const r = await ctx.api.post(`${ctx.module.apiBase}/tenants/${id}/test`); toast[r.tokenAcquired ? 'success' : 'error'](r.tokenAcquired ? `Connected to ${r.organizationName || 'tenant'}` : 'Token failed: ' + r.error); drawer.close(); await render(ctx); openTenant(ctx, id, sources); }
      catch (err) { toast.error(errorMessage(err)); } finally { ctx.ui.setBusy(testBtn, false); }
    } }, 'Test connection');
    actions.append(testBtn);
  }
  actions.append(h('button', { class: 'btn', onClick: async () => { try { await ctx.api.post(`${ctx.module.apiBase}/tenants/${id}/run`, {}); toast.success('Collection scheduled for all sources.'); } catch (err) { toast.error(errorMessage(err)); } } }, 'Run all now'));
  if (isAdmin) {
    actions.append(h('button', { class: 'btn danger', onClick: async () => {
      if (!(await modal.confirm('Reset checkpoints', 'Forget watermarks for this tenant so the next run re-reads the lookback window? Existing events are deduplicated.', { danger: true, confirmLabel: 'Reset' }))) return;
      await ctx.api.post(`${ctx.module.apiBase}/tenants/${id}/reset`, {}); toast.success('Checkpoints reset.'); drawer.close(); await render(ctx);
    } }, 'Reset checkpoints'));
    actions.append(h('button', { class: 'btn danger', onClick: async () => {
      if (!(await modal.confirm('Delete tenant', `Delete ${t.displayName} and its credentials? Collected events remain in the search index.`, { danger: true, confirmLabel: 'Delete' }))) return;
      await ctx.api.delete(`${ctx.module.apiBase}/tenants/${id}`); toast.success('Tenant deleted.'); drawer.close(); await render(ctx);
    } }, 'Delete'));
  }
  body.append(actions);

  if (t.lastTest) {
    body.append(h('h3', null, `Connection test (${fmt.relative(t.lastTestAt)})`),
      t.lastTest.tokenAcquired ? null : h('div', { class: 'alert danger' }, t.lastTest.error || 'Token acquisition failed.'),
      table({ columns: [
        { title: 'Source', render: (p) => p.title },
        { title: 'Status', render: (p) => badge(p.status, p.status === 'ok' ? 'success' : p.status === 'forbidden' ? 'warning' : 'danger') },
        { title: 'Detail', render: (p) => h('span', { class: 'small' }, p.detail || '') },
      ], rows: t.lastTest.probes, emptyText: 'No probes recorded.' }));
  }

  body.append(h('h3', null, 'Collection status'), table({
    columns: [
      { title: 'Source', render: (c) => sources.find((s) => s.source === c.source)?.title || c.source },
      { title: 'Status', render: (c) => h('div', null, statusBadge(ctx.ui, c.lastStatus), c.lastError ? h('div', { class: 'small muted truncate', title: c.lastError }, c.lastError) : null) },
      { title: 'Watermark', render: (c) => fmt.dateTime(c.watermark) },
      { title: 'Last run', render: (c) => fmt.relative(c.lastRunAt) },
      { title: 'Next run', render: (c) => fmt.relative(c.nextRunAt) },
      { title: 'Events', class: 'num', render: (c) => `${fmt.number(c.lastCount)} / ${fmt.number(c.totalCount)}` },
      { title: '', class: 'right', render: (c) => h('button', { class: 'btn sm', onClick: async () => { await ctx.api.post(`${ctx.module.apiBase}/tenants/${id}/run`, { source: c.source }); toast.success(`${c.source} scheduled.`); } }, 'Run') },
    ],
    rows: t.checkpoints || [],
    emptyText: 'No runs yet.',
  }));

  drawer.open({ title: t.displayName, content: body, width: 'min(860px, 100vw)' });
}

async function editTenant(ctx, existing) {
  const { h, modal, toast, errorMessage } = ctx.ui;
  const sources = await ctx.api.get(`${ctx.module.apiBase}/sources`);
  const t = existing || { displayName: '', tenantId: '', clientId: '', credentialType: 'secret', cloud: 'Global', enabled: true, lookbackDays: 7, settings: { sources: {} } };
  const input = (label, name, value, attrs = {}) => { const i = h('input', { class: 'input', name, value: value ?? '', autocomplete: 'off', ...attrs }); return [h('div', { class: 'field' }, h('label', null, label), i), i]; };
  const [nameF, nameI] = input('Display name', 'displayName', t.displayName, { required: true });
  const [tidF, tidI] = input('Tenant (directory) id', 'tenantId', t.tenantId, { placeholder: '00000000-0000-0000-0000-000000000000', spellcheck: false });
  const [cidF, cidI] = input('Application (client) id', 'clientId', t.clientId, { spellcheck: false });
  const credSel = h('select', { class: 'select' }, [['secret', 'Client secret'], ['certificate', 'Certificate (PFX)']].map(([v, l]) => h('option', { value: v, selected: v === t.credentialType }, l)));
  const [secretF, secretI] = input(existing?.hasSecret ? 'Client secret (blank keeps the stored one)' : 'Client secret', 'clientSecret', '', { type: 'password' });
  const pfxInput = h('input', { class: 'input', type: 'file', accept: '.pfx,.p12' });
  const [pfxPwF, pfxPwI] = input('PFX password', 'certificatePassword', '', { type: 'password' });
  const pfxF = h('div', { class: 'field' }, h('label', null, existing?.hasCertificate ? 'Certificate (leave empty to keep the stored one)' : 'Certificate (PFX with private key)'), pfxInput);
  const cloudSel = h('select', { class: 'select' }, [['Global', 'Global (login.microsoftonline.com)'], ['USGov', 'US Government (login.microsoftonline.us)']].map(([v, l]) => h('option', { value: v, selected: v === t.cloud }, l)));
  const [lookF, lookI] = input('Initial lookback (days)', 'lookbackDays', t.lookbackDays, { type: 'number', min: 1, max: 180 });
  const enabledCb = h('input', { type: 'checkbox', checked: t.enabled });

  const perSource = h('div', { class: 'col' });
  const sourceRows = [];
  for (const s of sources.filter((x) => x.collector)) {
    const cfg = (t.settings?.sources || {})[s.source] || {};
    const en = h('input', { type: 'checkbox', checked: cfg.enabled !== false });
    const interval = h('input', { class: 'input sm', type: 'number', min: 1, placeholder: String(s.collector.defaultIntervalMinutes), value: cfg.intervalMinutes ?? '' });
    const nonInteractive = s.source === 'signins' ? h('input', { type: 'checkbox', checked: cfg.includeNonInteractive !== false }) : null;
    const recordTypes = s.source === 'activity' ? h('input', { class: 'input sm', placeholder: 'default record types', value: (cfg.recordTypes || []).join(',') }) : null;
    sourceRows.push({ source: s.source, en, interval, nonInteractive, recordTypes });
    perSource.append(h('div', { class: 'form-row' },
      h('label', { class: 'checkbox' }, en, h('span', null, s.collector.title)),
      h('div', { class: 'flex' }, h('span', { class: 'small muted nowrap' }, 'every'), interval, h('span', { class: 'small muted' }, 'min')),
      nonInteractive ? h('label', { class: 'checkbox' }, nonInteractive, h('span', { class: 'small' }, 'incl. non-interactive / service principal')) : (recordTypes || h('span')),
    ));
  }

  const toggleCred = () => { const cert = credSel.value === 'certificate'; secretF.classList.toggle('hidden', cert); pfxF.classList.toggle('hidden', !cert); pfxPwF.classList.toggle('hidden', !cert); };
  credSel.addEventListener('change', toggleCred); toggleCred();

  const form = h('div', { class: 'col' },
    h('div', { class: 'form-row' }, nameF, h('div', { class: 'field' }, h('label', null, 'Cloud'), cloudSel)),
    h('div', { class: 'form-row' }, tidF, cidF),
    h('div', { class: 'form-row' }, h('div', { class: 'field' }, h('label', null, 'Credential type'), credSel), secretF, pfxF, pfxPwF),
    h('div', { class: 'form-row' }, lookF, h('label', { class: 'checkbox mt' }, enabledCb, h('span', null, 'Collection enabled'))),
    h('details', null, h('summary', { class: 'muted' }, 'Per-source settings'), h('div', { class: 'mt' }, perSource)),
    h('p', { class: 'small faint' }, 'Secrets are encrypted with the dashboard master key before they are stored and are never returned by the API.'));

  const saved = await modal.show({ title: existing ? 'Edit tenant' : 'Add tenant', content: form, wide: true, actions: [{ label: 'Cancel', value: false }, { label: existing ? 'Save' : 'Add', kind: 'primary', onClick: async () => {
    const settings = { sources: {} };
    for (const r of sourceRows) {
      const entry = { enabled: r.en.checked };
      if (r.interval.value) entry.intervalMinutes = Number(r.interval.value);
      if (r.nonInteractive) entry.includeNonInteractive = r.nonInteractive.checked;
      if (r.recordTypes && r.recordTypes.value.trim()) entry.recordTypes = r.recordTypes.value.split(',').map((s) => s.trim()).filter(Boolean);
      settings.sources[r.source] = entry;
    }
    let pfxBase64 = null;
    if (credSel.value === 'certificate' && pfxInput.files?.[0]) {
      const buf = await pfxInput.files[0].arrayBuffer();
      pfxBase64 = btoa(String.fromCharCode(...new Uint8Array(buf)));
    }
    const payload = { displayName: nameI.value.trim(), tenantId: tidI.value.trim(), clientId: cidI.value.trim(), credentialType: credSel.value, clientSecret: secretI.value || null, certificatePfxBase64: pfxBase64, certificatePassword: pfxPwI.value || null, cloud: cloudSel.value, enabled: enabledCb.checked, lookbackDays: Number(lookI.value || 7), settings };
    try {
      const res = existing ? await ctx.api.put(`${ctx.module.apiBase}/tenants/${existing.id}`, payload) : await ctx.api.post(`${ctx.module.apiBase}/tenants`, payload);
      if (!existing) {
        toast.success('Tenant added. Running a connection test…');
        try { const r = await ctx.api.post(`${ctx.module.apiBase}/tenants/${res.id}/test`); toast[r.tokenAcquired ? 'success' : 'error'](r.tokenAcquired ? `Connected to ${r.organizationName || 'tenant'}; ${r.probes.filter((p) => p.status === 'ok').length}/${r.probes.length} sources accessible.` : 'Connection failed: ' + r.error); } catch { /* shown in drawer later */ }
      }
      return true;
    } catch (err) { toast.error(errorMessage(err)); return false; }
  } }] });
  if (saved) { toast.success('Saved.'); await render(ctx); }
}
