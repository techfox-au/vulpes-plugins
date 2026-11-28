import { RANGES, kpiCard, tenantSelect } from './common.js?v=shell392';

let root;
export async function mount(el, ctx) {
  root = el;
  const { h, clear, dropdown } = ctx.ui;
  const state = { range: '24h', tenant: '' };
  const toolbar = el.querySelector('[data-role="toolbar"]');
  const rangeSel = dropdown(RANGES.filter(([v]) => v !== '1h').map(([value, label]) => ({ value, label })), { value: state.range, ariaLabel: 'Time range' });
  rangeSel.addEventListener('change', () => { state.range = rangeSel.value; render(); });
  toolbar.append(await tenantSelect(ctx, (v) => { state.tenant = v; render(); }), rangeSel, h('button', { class: 'btn ghost', 'aria-label': 'Refresh', onClick: render }, ctx.ui.icon('refresh')));

  let renderToken = 0;
  async function render() {
    const token = ++renderToken;
    const kpis = el.querySelector('[data-role="kpis"]');
    const scores = el.querySelector('[data-role="scores"]');
    const charts = el.querySelector('[data-role="charts"]');
    const lists = el.querySelector('[data-role="lists"]');
    clear(kpis).append(h('div', { class: 'card skeleton' }), h('div', { class: 'card skeleton' }), h('div', { class: 'card skeleton' }), h('div', { class: 'card skeleton' }));
    clear(scores); clear(charts); clear(lists);
    const hours = { '24h': 24, '7d': 24 * 7, '30d': 24 * 30, '90d': 24 * 90, '180d': 24 * 180, '365d': 24 * 365, '730d': 24 * 730 }[state.range] || 24;
    let o;
    try { o = await ctx.api.get(`${ctx.plugin.apiBase}/overview${ctx.api.qs({ hours, tenantId: state.tenant })}`); }
    catch (err) { if (token !== renderToken) return; clear(kpis); clear(scores); noteUnderKpis(h, kpis, ctx.ui.errorMessage(err)); return; }
    if (token !== renderToken) return;

    clear(kpis);
    clear(scores).append(secureScoreCard(ctx, o.secureScores || []));
    // Elasticsearch comes from the environment (README). Tenants are added on the Tenants page (docs/entra-setup.md).
    noteUnderKpis(h, kpis, o.available ? '' : 'Search backend unavailable.', 'warning');
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
      card(h, 'Sign-ins over time', ctx.ui.columnChart({ labels, axis: axisTicks(signBuckets, hours), series: signSeries, height: 200, maxBars: Math.max(labels.length, 1) }), h('div', { class: 'legend' }, h('span', null, h('span', { class: 'swatch' }), 'Sign-ins'), h('span', null, h('span', { class: 'swatch alt' }), 'Failures'))),
      card(h, 'Activity over time', ctx.ui.columnChart({ labels: activityBuckets.map((b) => fmtBucket(b.key, hours)), axis: axisTicks(activityBuckets, hours), series: [{ label: 'events', values: activityBuckets.map((b) => b.count) }], height: 200, maxBars: Math.max(activityBuckets.length, 1) })),
    );

    const link = (page, field, extra) => (item) => {
      const href = overviewDrill(ctx.plugin.id, item, page, field, { tenant: state.tenant, range: state.range, extra });
      if (href) ctx.navigate(href);
    };
    lists.append(
      card(h, 'Top failing users', bars(ctx.ui, o.failures.byUser, { alt: true, onClick: link('signins', 'user', 'outcome=failure') })),
      card(h, 'Top failing IPs', bars(ctx.ui, o.failures.byIp, { alt: true, onClick: link('signins', 'ip', 'outcome=failure') })),
      card(h, 'Failure reasons', bars(ctx.ui, o.failures.byReason, { alt: true })),
      card(h, 'Sign-ins by country', bars(ctx.ui, o.signIns.byCountry, { onClick: link('signins', 'country') })),
      card(h, 'Sign-ins by application', bars(ctx.ui, o.signIns.byApp, { onClick: link('signins', 'app') })),
      card(h, 'Activity by workload', bars(ctx.ui, o.activity.byWorkload, { onClick: link('activity', 'workload') })),
      card(h, 'Top operations', bars(ctx.ui, o.activity.byOperation, { onClick: link('activity', 'operation') })),
      card(h, 'Most active users', bars(ctx.ui, o.activity.byUser, { onClick: link('activity', 'user') })),
      card(h, 'Directory changes', bars(ctx.ui, o.directory.byActivity, { onClick: link('directory', 'activity') })),
      card(h, 'Alerts by severity', bars(ctx.ui, o.alerts.bySeverity, { alt: true, onClick: link('security-alerts', 'severity') })),
      card(h, 'Risk detections by level', bars(ctx.ui, o.risk.byLevel, { alt: true, onClick: link('risk', 'level') })),
      card(h, 'Collector failures', o.collectorFailures.total ? bars(ctx.ui, o.collectorFailures.byCollector, { alt: true, onClick: () => ctx.navigate(`/p/${ctx.plugin.id}/ingestion`) }) : h('div', { class: 'muted small' }, 'No collector failures in this period.')),
    );
  }

  render();
}

export function unmount() { root = null; }

function noteUnderKpis(h, kpis, message, kind = 'danger') {
  kpis.parentElement?.querySelector(':scope > .overview-note')?.remove();
  if (!message) return;
  kpis.after(h('div', { class: `alert overview-note ${kind}`, role: 'alert' }, message));
}

function card(h, title, ...body) { return h('div', { class: 'card' }, h('div', { class: 'card-header' }, h('h3', null, title)), ...body); }

function secureScoreCard(ctx, rows) {
  const { h, table, fmt } = ctx.ui;
  const body = rows.length
    ? table({
        columns: [
          { title: 'Client', render: (r) => r.name },
          { title: 'Score', class: 'num', render: (r) => r.current ? `${r.current} / ${r.max || '—'}` : '—' },
          { title: 'Percent', class: 'num', render: (r) => r.percent ? `${r.percent}%` : '—' },
          { title: 'Collected', render: (r) => r.at ? fmt.date(r.at) : (r.unavailable ? 'Unavailable' : 'Not collected') },
        ],
        rows,
        emptyText: 'No clients.',
      })
    : h('div', { class: 'muted small' }, 'No clients are configured.');
  return card(h, 'Secure Score', body);
}

function bars(ui, buckets, opts = {}) {
  const items = presentBuckets(buckets);
  return ui.barList(items, {
    alt: !!opts.alt,
    onClick: opts.onClick ? (item) => { if (!item.remainder) opts.onClick(item); } : undefined,
  });
}

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

/** The terms remainder is not a stored value. `\0other` is the old sentinel. */
export function bucketLabel(key) {
  return key === '\0other' ? 'Other' : key;
}

/** `\0other` is not a stored value, so it is not an equals filter. `(none)` stays a missing-value drill. */
export function bucketEqualsValue(key) {
  return key === '\0other' ? null : key;
}

function isRemainder(bucket) {
  return !!bucket && (bucket.remainder === true || (typeof bucket.key === 'string' && bucketEqualsValue(bucket.key) === null));
}

/** A remainder bucket is labelled Other. It is not a stored value and must not become an equals filter. */
export function presentBuckets(buckets) {
  return (buckets || []).map((bucket) => {
    if (isRemainder(bucket)) return { key: bucketLabel('\0other'), count: bucket.count, remainder: true };
    return { key: bucketLabel(bucket.key), count: bucket.count };
  });
}

/** Null when the bar is the remainder. A missing bucket stays notExists. Anything else is an equals drill. */
export function overviewDrill(pluginId, item, page, field, state = {}) {
  if (!item || isRemainder(item)) return null;
  const tenant = state.tenant ? `&tenant=${encodeURIComponent(state.tenant)}` : '';
  const value = item.key === '(none)' ? `${field}Missing=1` : `${field}=${encodeURIComponent(item.key)}`;
  const tail = state.extra ? `&${state.extra}` : '';
  return `/p/${pluginId}/${page}?${value}${tail}&range=${state.range || ''}${tenant}`;
}

function alignSeries(base, other) {
  const map = new Map((other || []).map((b) => [b.key, b.count]));
  return (base || []).map((b) => map.get(b.key) || 0);
}
