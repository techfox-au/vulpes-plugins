let root;
const psa = '/api/plugins/psa/clients';

export async function mount(el, ctx) {
  el.classList.add('page-scroll');
  root = el.querySelector('#clients-root') || el;
  ctx.setTitle(['Clients']);
  await render(ctx);
}
export function unmount() { root = null; }

async function render(ctx) {
  const { h, clear, table, badge, errorMessage } = ctx.ui;
  clear(root);
  let data;
  try { data = await ctx.api.get('/api/admin/tenants'); }
  catch (err) { root.append(h('div', { class: 'alert danger' }, errorMessage(err))); return; }
  const app = data.application || {};
  const applicationReady = !!(app.clientId && (app.credentialType === 'certificate' ? app.hasCertificate : app.hasSecret));
  root.append(h('div', { class: 'page-header' },
    h('h1', null, 'Clients'),
    h('button', { class: 'btn primary', disabled: !applicationReady, onClick: () => editClient(ctx, null) }, 'Add client')));
  root.append(table({
    columns: [
      { title: 'Name', render: (t) => h('div', null, h('strong', null, t.displayName), t.discoveredName && t.discoveredName !== t.displayName ? h('div', { class: 'small muted' }, t.discoveredName) : null) },
      { title: 'Directory id', render: (t) => h('span', { class: 'mono small' }, t.directoryId || '') },
      { title: 'Status', render: (t) => t.enabled ? badge('enabled', 'success') : badge('disabled', 'warning') },
      { title: '', class: 'right', render: (t) => h('div', { class: 'flex' },
        h('button', { class: 'btn sm', onClick: (e) => { e.stopPropagation(); editClient(ctx, t); } }, 'Edit'),
        t.directoryId ? h('button', { class: 'btn sm', onClick: (e) => { e.stopPropagation(); collection(ctx, t); } }, 'Collection') : null,
        t.directoryId ? h('button', { class: 'btn sm', onClick: (e) => { e.stopPropagation(); testClient(ctx, t, e.currentTarget); } }, 'Test') : null,
        h('button', { class: 'btn sm danger', onClick: (e) => { e.stopPropagation(); removeClient(ctx, t); } }, 'Delete')) },
    ],
    rows: data.tenants || [],
    emptyText: 'No clients yet.',
  }));
}

async function mirrorPsa(ctx, id, organisationName) {
  try { await ctx.api.post(psa + '/ensure', { id, organisationName }); }
  catch (err) { if (err.status !== 404) throw err; }
}

async function editClient(ctx, existing) {
  const { h, modal, errorMessage, panelNote } = ctx.ui;
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
      const savedClient = existing
        ? await ctx.api.put(`/api/admin/tenants/${existing.id}`, body)
        : await ctx.api.post('/api/admin/tenants', body);
      const id = existing ? existing.id : savedClient.id;
      await mirrorPsa(ctx, id, name.value.trim());
    } catch (err) { panelNote(form, errorMessage(err)); return false; }
  } }] });
  if (saved) { await render(ctx); ctx.ui.pageNote(root, existing ? 'Client saved.' : 'Client added.', 'success'); }
}

async function removeClient(ctx, tenant) {
  if (!(await ctx.ui.modal.confirm('Delete client', `Stop collecting from ${tenant.displayName}?`, { danger: true, confirmLabel: 'Delete' }))) return;
  try {
    try { await ctx.api.delete(`${psa}/${tenant.id}`); } catch (err) { if (err.status !== 404) throw err; }
    await ctx.api.delete(`/api/admin/tenants/${tenant.id}`);
    await render(ctx);
    ctx.ui.pageNote(root, 'Client removed.', 'success');
  } catch (err) { ctx.ui.pageNote(root, ctx.ui.errorMessage(err)); }
}

async function testClient(ctx, tenant, button) {
  ctx.ui.setBusy(button, true, 'Testing…');
  try {
    const result = await ctx.api.post(`/api/admin/tenants/${tenant.id}/test`);
    await render(ctx);
    const report = result?.reports?.[0];
    if (!report) { ctx.ui.pageNote(root, 'No plugin tested this client.'); return; }
    const probes = report.probes || [];
    const failed = !report.tokenAcquired || probes.some((p) => p.status === 'forbidden' || p.status === 'error');
    const lines = [report.organizationName ? `Connected to ${report.organizationName}.` : 'Connected.'];
    for (const probe of probes) lines.push(`${probe.title || probe.source}: ${probe.status}${probe.detail ? ` — ${probe.detail}` : ''}`);
    if (report.error) lines.push(report.error);
    ctx.ui.pageNote(root, lines.join('\n'), failed ? 'danger' : 'success');
  } catch (err) {
    if (button?.isConnected) ctx.ui.setBusy(button, false);
    ctx.ui.pageNote(root, ctx.ui.errorMessage(err));
  }
}

async function collection(ctx, tenant) {
  const { h, modal, errorMessage, panelNote } = ctx.ui;
  const [detail, sources] = await Promise.all([
    ctx.api.get(`${ctx.plugin.apiBase}/tenants/${tenant.id}`),
    ctx.api.get(`${ctx.plugin.apiBase}/sources`),
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
      h('label', { class: 'checkbox' }, en, h('span', null, s.collector.title)),
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
    try { await ctx.api.put(`${ctx.plugin.apiBase}/tenants/${tenant.id}/collection`, { lookbackDays: Number(look.value || 7), settings }); }
    catch (err) { panelNote(form, errorMessage(err)); return false; }
  } }] });
  if (saved) ctx.ui.pageNote(root, 'Collection saved.', 'success');
}
