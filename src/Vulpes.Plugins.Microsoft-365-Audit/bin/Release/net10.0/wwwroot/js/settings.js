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
  const intervalFields = intervals.map(([source, label]) => {
    const input = h('input', { class: 'input', name: `interval-${source}`, type: 'number', value: savedIntervals[source] ?? '', required: true });
    return { source, input, field: h('div', { class: 'field' }, h('label', null, label), input) };
  });
  const applyPremium = () => { const risk = intervalFields.find((f) => f.source === 'risk'); if (risk) risk.input.disabled = premium.checked; };
  premium.addEventListener('change', applyPremium);
  applyPremium();
  form.append(
    card('Collection',
      h('label', { class: 'checkbox' }, premium, h('span', null, 'Microsoft 365 Business Premium mode')),
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
    card('Intervals (minutes)', h('div', { class: 'form-row' }, ...intervalFields.map((f) => f.field))),
    h('div', { class: 'flex end' }, h('button', { class: 'btn primary', type: 'submit' }, 'Save')));

  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    const data = new FormData(form);
    const read = (name) => Number(data.get(name));
    const button = form.querySelector('button[type="submit"]');
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

export function unmount() { }
