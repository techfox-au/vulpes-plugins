const intervals = [
  ['signins', 'Sign-ins'],
  ['directory', 'Directory audit'],
  ['provisioning', 'Provisioning'],
  ['activity', 'Activity'],
  ['security-alerts', 'Security alerts'],
  ['incidents', 'Incidents'],
  ['risk', 'Risk'],
  ['securescore', 'Secure Score'],
];

export async function mount(el, ctx) {
  const { h, errorMessage, setBusy, panelNote } = ctx.ui;
  const form = el.querySelector('[data-role="form"]');
  let current;
  try { current = await ctx.api.get(`${ctx.plugin.apiBase}/settings`); }
  catch (err) { form.append(h('div', { class: 'alert danger' }, errorMessage(err))); return; }

  const number = (name, label, value) => h('div', { class: 'field' }, h('label', null, label), h('input', { class: 'input', name, type: 'number', value, required: true }));
  const card = (title, ...fields) => h('div', { class: 'card' }, h('div', { class: 'card-header' }, h('h2', null, title)), h('div', { class: 'stack' }, ...fields));
  const savedIntervals = current.intervalMinutes || {};
  const premium = h('input', { type: 'checkbox', checked: current.businessPremiumMode === true });
  const hideRisk = h('input', { type: 'checkbox', checked: current.businessPremiumMode === true && current.hideRiskMenu === true });
  const hideRiskLabel = h('label', { class: 'checkbox' }, hideRisk, h('span', null, 'Hide risk menu item'));
  const intervalFields = intervals.map(([source, label]) => {
    const input = h('input', { class: 'input', name: `interval-${source}`, type: 'number', value: savedIntervals[source] ?? '', required: true });
    return { source, input, field: h('div', { class: 'field' }, h('label', null, label), input) };
  });
  const applyPremium = () => {
    const risk = intervalFields.find((f) => f.source === 'risk');
    if (risk) risk.input.disabled = premium.checked;
    if (!premium.checked) hideRisk.checked = false;
    hideRiskLabel.hidden = !premium.checked;
  };
  premium.addEventListener('change', applyPremium);
  applyPremium();
  form.append(
    card('Collection',
      h('div', { class: 'flex wrap' },
        h('label', { class: 'checkbox' }, premium, h('span', null, 'Microsoft 365 Business Premium mode')),
        hideRiskLabel),
      h('div', { class: 'form-row' },
        number('schedulerIntervalSeconds', 'Scheduler interval (seconds)', current.schedulerIntervalSeconds),
        number('maxConcurrentJobs', 'Concurrent jobs', current.maxConcurrentJobs)),
      h('div', { class: 'form-row' },
        number('runTimeBudgetMinutes', 'Run time budget (minutes)', current.runTimeBudgetMinutes),
        number('defaultLookbackDays', 'Default lookback (days)', current.defaultLookbackDays)),
      h('div', { class: 'form-row' },
        number('logOverlapMinutes', 'Log overlap (minutes)', current.logOverlapMinutes),
        number('graphPageSize', 'Page size', current.graphPageSize)),
      number('maxPagesPerRun', 'Max pages per run', current.maxPagesPerRun)),
    card('Activity log',
      h('div', { class: 'form-row' },
        number('purviewLagMinutes', 'Lag (minutes)', current.purviewLagMinutes),
        number('purviewOverlapMinutes', 'Overlap (minutes)', current.purviewOverlapMinutes),
        number('purviewMaxWindowHours', 'Window (hours)', current.purviewMaxWindowHours)),
      h('div', { class: 'field' }, h('label', null, 'Record types'), h('textarea', { class: 'textarea', name: 'purviewRecordTypes', spellcheck: false, autocorrect: 'off', autocapitalize: 'off' }, (current.purviewRecordTypes || []).join(', ')))),
    card('Intervals (minutes)', h('div', { class: 'form-row' }, ...intervalFields.map((f) => f.field))));

  const save = h('button', { class: 'btn primary', type: 'submit' }, 'Save');
  form.append(botCard(ctx), h('div', { class: 'flex end' }, save));
  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    const data = new FormData(form);
    const read = (name) => Number(data.get(name));
    const button = save;
    setBusy(button, true, 'Saving…');
    try {
      await ctx.api.put(`${ctx.plugin.apiBase}/settings`, {
        schedulerIntervalSeconds: read('schedulerIntervalSeconds'),
        maxConcurrentJobs: read('maxConcurrentJobs'),
        runTimeBudgetMinutes: read('runTimeBudgetMinutes'),
        defaultLookbackDays: read('defaultLookbackDays'),
        logOverlapMinutes: read('logOverlapMinutes'),
        graphPageSize: read('graphPageSize'),
        maxPagesPerRun: read('maxPagesPerRun'),
        purviewLagMinutes: read('purviewLagMinutes'),
        purviewOverlapMinutes: read('purviewOverlapMinutes'),
        purviewMaxWindowHours: read('purviewMaxWindowHours'),
        purviewRecordTypes: String(data.get('purviewRecordTypes') || '').split(',').map((s) => s.trim()).filter(Boolean),
        intervalMinutes: Object.fromEntries(intervalFields.map((f) => [f.source, Number(f.input.value)])),
        businessPremiumMode: premium.checked,
        hideRiskMenu: premium.checked && hideRisk.checked,
      });
      if (ctx.refreshNav) await ctx.refreshNav();
      panelNote(form, 'Settings saved.', 'success');
    } catch (err) {
      panelNote(form, errorMessage(err));
    } finally {
      setBusy(button, false);
    }
  });
}

function botCard(ctx) {
  const { h, clear, table, fmt, errorMessage, panelNote, copyToClipboard } = ctx.ui;
  const card = h('div', { class: 'card' });
  const list = h('div', { class: 'mt' });
  const name = h('input', { class: 'input', placeholder: 'Grok Bot', 'aria-label': 'Token name', maxlength: '80' });
  const revealed = h('div');
  card.append(
    h('div', { class: 'card-header' }, h('h2', null, 'Grok Bot')),
    h('p', { class: 'muted' }, 'A read-only connection for every client’s logs. It cannot change anything. The token is shown once, expires after 90 days, and each use is written to the audit trail. Send it only to the HTTPS dashboard.'),
    h('p', { class: 'muted' }, 'MCP endpoint: /api/plugins/microsoft-365-audit/mcp'),
    h('div', { class: 'form-row' }, name, h('button', { class: 'btn', type: 'button', onClick: create }, 'Create token')),
    revealed,
    list,
  );
  load();
  return card;

  async function load() {
    let rows;
    try { rows = await ctx.api.get(`${ctx.plugin.apiBase}/bot/tokens`); }
    catch (err) { clear(list).append(h('div', { class: 'alert danger' }, errorMessage(err))); return; }
    clear(list).append(table({
      columns: [
        { title: 'Name', render: (r) => r.name },
        { title: 'Prefix', render: (r) => r.prefix },
        { title: 'Created', render: (r) => fmt.date(r.createdAt) },
        { title: 'Expires', render: (r) => r.expiresAt ? fmt.date(r.expiresAt) : '—' },
        { title: 'Last used', render: (r) => r.lastUsedAt ? fmt.relative(r.lastUsedAt) : 'never' },
        { title: '', render: (r) => r.revoked ? h('span', { class: 'badge' }, 'Revoked') : h('button', { class: 'btn ghost', type: 'button', onClick: () => revoke(r) }, 'Revoke') },
      ],
      rows,
      emptyText: 'No tokens yet.',
    }));
  }

  async function create() {
    clear(revealed);
    try {
      const created = await ctx.api.post(`${ctx.plugin.apiBase}/bot/tokens`, { name: name.value.trim() || 'Grok Bot' });
      revealed.append(h('div', { class: 'alert success' },
        h('div', null, 'Copy this token now. It is not shown again.'),
        h('code', null, created.token),
        h('button', { class: 'btn ghost', type: 'button', onClick: () => copyToClipboard(created.token, card) }, 'Copy')));
      name.value = '';
      await load();
    } catch (err) {
      panelNote(card, errorMessage(err));
    }
  }

  async function revoke(row) {
    try {
      await ctx.api.delete(`${ctx.plugin.apiBase}/bot/tokens/${row.id}`);
      await load();
    } catch (err) {
      panelNote(card, errorMessage(err));
    }
  }
}

export function unmount() { }
