let root;
let renderToken = 0;
const psa = '/api/plugins/psa/clients';

export async function mount(el, ctx) {
  el.classList.add('page-scroll');
  root = el.querySelector('#clients-root') || el;
  ctx.setTitle(['Clients']);
  await render(ctx);
}
export function unmount() {
  renderToken += 1;
  root = null;
}

function alphabetical(rows, name) {
  return rows.slice().sort((left, right) => (name(left) || '').localeCompare(name(right) || '', undefined, { sensitivity: 'base' }));
}

async function render(ctx) {
  const token = ++renderToken;
  const page = root;
  if (!page) return;
  const { h, clear, table, badge, errorMessage } = ctx.ui;
  clear(page);
  let data;
  try { data = await ctx.api.get('/api/admin/tenants'); }
  catch (err) {
    if (token !== renderToken || root !== page) return;
    page.append(h('div', { class: 'alert danger' }, errorMessage(err)));
    return;
  }
  if (token !== renderToken || root !== page) return;
  const app = data.application || {};
  const applicationReady = !!(app.clientId && (app.credentialType === 'certificate' ? app.hasCertificate : app.hasSecret));
  page.append(h('div', { class: 'page-header' },
    h('h1', null, 'Clients'),
    h('button', { class: 'btn primary', disabled: !applicationReady, onClick: () => editClient(ctx, null) }, 'Add client')));
  page.append(table({
    columns: [
      { title: 'Name', render: (t) => h('div', null, h('strong', null, t.displayName), t.discoveredName && t.discoveredName !== t.displayName ? h('div', { class: 'small muted' }, t.discoveredName) : null) },
      { title: 'Directory id', render: (t) => h('span', { class: 'mono small' }, t.directoryId || '') },
      { title: 'Short name', render: (t) => t.shortName || '' },
      { title: 'Status', render: (t) => t.disabled ? badge('Disabled', 'warning') : t.enabled ? badge('enabled', 'success') : badge('collection off', 'warning') },
      { title: '', class: 'right', render: (t) => h('div', { class: 'flex' },
        h('button', { class: 'btn sm', onClick: (e) => { e.stopPropagation(); return editClient(ctx, t); } }, 'Edit'),
        t.directoryId && !t.disabled ? h('button', { class: 'btn sm', onClick: (e) => { e.stopPropagation(); collection(ctx, t); } }, 'Collection') : null,
        t.directoryId && !t.disabled ? h('button', { class: 'btn sm', onClick: (e) => { e.stopPropagation(); testClient(ctx, t, e.currentTarget); } }, 'Test') : null,
        h('button', { class: t.disabled ? 'btn sm' : 'btn sm danger', onClick: (e) => { e.stopPropagation(); setClientEnabled(ctx, t); } }, t.disabled ? 'Enable' : 'Disable')) },
    ],
    rows: alphabetical(data.tenants || [], (row) => row.displayName),
    rowClass: (t) => t.disabled ? 'is-disabled' : '',
    emptyText: 'No clients yet.',
  }));
}

async function mirrorPsa(ctx, id, organisationName, shortName) {
  try { await ctx.api.post(psa + '/ensure', { id, organisationName, shortName }); }
  catch (err) { if (err.status !== 404) throw err; }
}

async function editClient(ctx, existing) {
  const { h, modal, errorMessage, panelNote } = ctx.ui;
  const name = h('input', { class: 'input', value: existing?.displayName || '', required: true });
  const shortName = h('input', { class: 'input', value: existing?.shortName || '', maxlength: '16', spellcheck: false });
  const directory = h('input', { class: 'input', value: existing?.directoryId || '', spellcheck: false, readOnly: !!existing?.directoryId, placeholder: '00000000-0000-0000-0000-000000000000' });
  const enabled = h('input', { type: 'checkbox', checked: existing ? existing.enabled && !existing.disabled : true, disabled: !!existing?.disabled });
  const form = h('div', { class: 'col' },
    h('div', { class: 'field' }, h('label', null, 'Display name'), name),
    h('div', { class: 'field' }, h('label', null, 'Short name'), shortName),
    h('div', { class: 'field' }, h('label', null, 'Directory id'), directory),
    h('label', { class: 'checkbox' }, enabled, h('span', null, 'Collection enabled')),
    existing ? h('div', { class: 'stack mt' },
      h('h3', null, 'Danger'),
      h('p', { class: 'small muted' }, 'Deletes this client’s stored audit logs and collects them again from the lookback window.'),
      h('button', { class: 'btn danger', type: 'button', onClick: () => purgeClient(ctx, existing, form, (message) => { purgeFailure = message; }) }, 'Purge & Reset')) : null);
  let addedId = null;
  let purgeFailure = '';
  const saved = await modal.show({ title: existing ? 'Edit client' : 'Add client', content: form, actions: [{ label: 'Cancel', value: false }, { label: existing ? 'Save' : 'Add', kind: 'primary', value: true, onClick: async () => {
    try {
      const directoryId = directory.value.trim();
      if (existing?.directoryId && !directoryId) { panelNote(form, 'Directory id cannot be cleared.'); return false; }
      const body = { displayName: name.value.trim(), enabled: enabled.checked, shortName: shortName.value.trim() };
      if (directoryId) body.directoryId = directoryId;
      let id = existing?.id || addedId;
      if (existing) await ctx.api.put(`/api/admin/tenants/${existing.id}`, body);
      else if (!addedId) {
        const savedClient = await ctx.api.post('/api/admin/tenants', body);
        addedId = savedClient.id;
        id = addedId;
      }
      else await ctx.api.put(`/api/admin/tenants/${addedId}`, body);
      try { await mirrorPsa(ctx, id, name.value.trim(), shortName.value.trim()); }
      catch (err) {
        await render(ctx);
        const message = 'The PSA mirror did not update. ' + errorMessage(err);
        ctx.ui.pageNote(root, message);
        panelNote(form, message);
        return false;
      }
    } catch (err) { panelNote(form, errorMessage(err)); return false; }
  } }] });
  if (saved) {
    await render(ctx);
    ctx.ui.pageNote(root, purgeFailure ? `Client saved. Purge did not finish. ${purgeFailure}` : (existing ? 'Client saved.' : 'Client added.'), purgeFailure ? 'danger' : 'success');
  }
}

async function purgeClient(ctx, tenant, form, notePurge) {
  if (!(await ctx.ui.modal.confirm('Purge & Reset', `Delete every stored audit log for ${tenant.displayName} and collect them again from the lookback window?`, { danger: true, confirmLabel: 'Purge & Reset' }))) return;
  try {
    const result = await ctx.api.post(`${ctx.plugin.apiBase}/tenants/${tenant.id}/purge`);
    notePurge('');
    const message = `Purged ${ctx.ui.fmt.number(result.deleted || 0)} stored events. Collection will start again.`;
    ctx.ui.panelNote(form, message, 'success');
    ctx.ui.pageNote(root, message, 'success');
  } catch (err) {
    const message = ctx.ui.errorMessage(err);
    notePurge(message);
    ctx.ui.panelNote(form, message);
    ctx.ui.pageNote(root, message);
  }
}

async function setClientEnabled(ctx, tenant) {
  const disabling = !tenant.disabled;
  const title = disabling ? 'Disable client' : 'Enable client';
  const message = disabling
    ? `Disable ${tenant.displayName}? Audit collection stops and their stored audit logs are deleted.`
    : `Enable ${tenant.displayName}?`;
  if (!(await ctx.ui.modal.confirm(title, message, { danger: disabling, confirmLabel: disabling ? 'Disable' : 'Enable' }))) return;
  try {
    await ctx.api.post(`/api/admin/tenants/${tenant.id}/${disabling ? 'disable' : 'enable'}`, {});
    await render(ctx);
    ctx.ui.pageNote(root, disabling ? 'Client disabled.' : 'Client enabled.', 'success');
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
    const en = h('input', { type: 'checkbox', checked: cfg.enabled !== false, disabled: blocked });
    const interval = h('input', { class: 'input sm', type: 'number', min: 1, placeholder: String(s.collector.defaultIntervalMinutes), value: cfg.intervalMinutes ?? '' });
    const nonInteractive = s.source === 'signins' ? h('input', { type: 'checkbox', checked: cfg.includeNonInteractive !== false }) : null;
    const recordTypes = s.source === 'activity' ? h('input', { class: 'input sm', placeholder: 'default record types', value: (cfg.recordTypes || []).join(',') }) : null;
    rows.push({ source: s.source, en, interval, nonInteractive, recordTypes });
    box.append(h('div', { class: 'form-row' },
      h('label', { class: 'checkbox' }, en, h('span', null, s.collector.title)),
      h('div', { class: 'flex' }, h('span', { class: 'small muted nowrap' }, 'every'), interval, h('span', { class: 'small muted' }, 'min')),
      nonInteractive ? h('label', { class: 'checkbox' }, nonInteractive, h('span', { class: 'small' }, 'incl. non-interactive users')) : (recordTypes || h('span'))));
  }
  const form = h('div', { class: 'col' }, h('div', { class: 'field' }, h('label', null, 'Initial lookback (days)'), look), box);
  const saved = await modal.show({ title: tenant.displayName, content: form, wide: true, actions: [{ label: 'Cancel', value: false }, { label: 'Save', kind: 'primary', value: true, onClick: async () => {
    const settings = { sources: {} };
    for (const r of rows) {
      const entry = { enabled: r.en.checked };
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
