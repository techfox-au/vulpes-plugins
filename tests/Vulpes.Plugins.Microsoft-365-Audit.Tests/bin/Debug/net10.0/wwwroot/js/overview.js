import { RANGES, kpiCard, bucketsToBarList, tenantSelect } from './common.js?v=shell84';

let root;
export async function mount(el, ctx) {
  root = el;
  const { h, clear, dropdown } = ctx.ui;
  const state = { range: '24h', tenant: '' };
  const toolbar = el.querySelector('[data-role="toolbar"]');
  const rangeSel = dropdown(RANGES.filter(([v]) => v !== '1h').map(([value, label]) => ({ value, label })), { value: state.range, ariaLabel: 'Time range' });
  rangeSel.addEventListener('change', () => { state.range = rangeSel.value; render(); });
  toolbar.append(await tenantSelect(ctx, (v) => { state.tenant = v; render(); }), rangeSel, h('button', { class: 'btn ghost', 'aria-label': 'Refresh', onClick: render }, ctx.ui.icon('refresh')));

  async function render() {
    const kpis = el.querySelector('[data-role="kpis"]');
    const charts = el.querySelector('[data-role="charts"]');
    const lists = el.querySelector('[data-role="lists"]');
    clear(kpis).append(h('div', { class: 'card skeleton' }), h('div', { class: 'card skeleton' }), h('div', { class: 'card skeleton' }), h('div', { class: 'card skeleton' }));
    clear(charts); clear(lists);
    const hours = { '24h': 24, '7d': 24 * 7, '30d': 24 * 30, '90d': 24 * 90 }[state.range] || 24;
    let o;
    try { o = await ctx.api.get(`${ctx.plugin.apiBase}/overview${ctx.api.qs({ hours, tenantId: state.tenant })}`); }
    catch (err) { clear(kpis).append(h('div', { class: 'alert danger' }, ctx.ui.errorMessage(err))); return; }

    clear(kpis);
    // Elasticsearch comes from the environment (README). Tenants are added on the Tenants page (docs/entra-setup.md).
    if (!o.available) kpis.append(h('div', { class: 'alert warning' }, 'Search backend unavailable.'));
    kpis.append(
      kpiCard(ctx.ui, 'Sign-ins', ctx.ui.fmt.number(o.signIns.total), '', `${ctx.ui.fmt.number(o.failures.total)} failed`),
      kpiCard(ctx.ui, 'Failed sign-ins', ctx.ui.fmt.number(o.failures.total), o.failures.total > 0 ? 'warning' : '', o.signIns.total ? `${((100 * o.failures.total) / o.signIns.total).toFixed(1)}% of sign-ins` : ''),
      kpiCard(ctx.ui, 'Activity events', ctx.ui.fmt.number(o.activity.total), '', `${ctx.ui.fmt.number(o.directory.total)} directory changes`),
      kpiCard(ctx.ui, 'Defender alerts', ctx.ui.fmt.number(o.alerts.total), o.alerts.total > 0 ? 'danger' : 'success', `${ctx.ui.fmt.number(o.risk.total)} risk detections`),
    );

    const signBuckets = o.signIns.perHour || [];
    const activityBuckets = o.activity.perHour || [];
    const labels = signBuckets.map((b) => fmtBucket(b.key, hours));
    const signSeries = [{ label: 'sign-ins', values: signBuckets.map((b) => b.count) }, { label: 'failures', values: alignSeries(signBuckets, o.failures.perHour), alt: true }];
    charts.append(
      card(h, 'Sign-ins over time', ctx.ui.columnChart({ labels, axis: axisTicks(signBuckets, hours), series: signSeries, height: 200 }), h('div', { class: 'legend' }, h('span', null, h('span', { class: 'swatch' }), 'Sign-ins'), h('span', null, h('span', { class: 'swatch alt' }), 'Failures'))),
      card(h, 'Activity over time', ctx.ui.columnChart({ labels: activityBuckets.map((b) => fmtBucket(b.key, hours)), axis: axisTicks(activityBuckets, hours), series: [{ label: 'events', values: activityBuckets.map((b) => b.count) }], height: 200 })),
    );

    const link = (page, field) => (item) => ctx.navigate(`/p/${ctx.plugin.id}/${page}?${field}=${encodeURIComponent(item.key)}&range=${state.range}`);
    lists.append(
      card(h, 'Top failing users', bucketsToBarList(ctx.ui, o.failures.byUser, { alt: true, onClick: link('signins', 'user') })),
      card(h, 'Top failing IPs', bucketsToBarList(ctx.ui, o.failures.byIp, { alt: true, onClick: link('signins', 'ip') })),
      card(h, 'Failure reasons', bucketsToBarList(ctx.ui, o.failures.byReason, { alt: true })),
      card(h, 'Sign-ins by country', bucketsToBarList(ctx.ui, o.signIns.byCountry, { onClick: link('signins', 'country') })),
      card(h, 'Sign-ins by application', bucketsToBarList(ctx.ui, o.signIns.byApp, { onClick: link('signins', 'app') })),
      card(h, 'Activity by workload', bucketsToBarList(ctx.ui, o.activity.byWorkload, { onClick: link('activity', 'workload') })),
      card(h, 'Top operations', bucketsToBarList(ctx.ui, o.activity.byOperation, { onClick: link('activity', 'operation') })),
      card(h, 'Most active users', bucketsToBarList(ctx.ui, o.activity.byUser, { onClick: link('activity', 'user') })),
      card(h, 'Directory changes', bucketsToBarList(ctx.ui, o.directory.byActivity, { onClick: link('directory', 'activity') })),
      card(h, 'Alerts by severity', bucketsToBarList(ctx.ui, o.alerts.bySeverity, { alt: true, onClick: link('security-alerts', 'severity') })),
      card(h, 'Risk detections by level', bucketsToBarList(ctx.ui, o.risk.byLevel, { alt: true, onClick: link('risk', 'level') })),
      card(h, 'Collector failures', o.collectorFailures.total ? bucketsToBarList(ctx.ui, o.collectorFailures.byCollector, { alt: true, onClick: () => ctx.navigate(`/p/${ctx.plugin.id}/ingestion`) }) : h('div', { class: 'muted small' }, 'No collector failures in this period.')),
    );
  }

  render();
}

export function unmount() { root = null; }

function card(h, title, ...body) { return h('div', { class: 'card' }, h('div', { class: 'card-header' }, h('h3', null, title)), ...body); }

function fmtBucket(key, hours) {
  const d = new Date(key);
  if (Number.isNaN(d.getTime())) return String(key);
  return hours <= 24 ? d.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' }) : d.toLocaleDateString(undefined, { month: 'short', day: 'numeric' }) + (hours <= 24 * 7 ? ' ' + d.toLocaleTimeString(undefined, { hour: '2-digit' }) : '');
}

// Hourly charts label 9am, 1pm, 5pm (and 9pm, 1am, 5am), not 8am, 12pm, 4pm.
function axisTicks(buckets, hours) {
  if (hours > 24) return null;
  return buckets.map((b) => {
    const d = new Date(b.key);
    return !Number.isNaN(d.getTime()) && d.getHours() % 4 === 1;
  });
}

function alignSeries(base, other) {
  const map = new Map((other || []).map((b) => [b.key, b.count]));
  return (base || []).map((b) => map.get(b.key) || 0);
}
