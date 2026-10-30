import { h, badge, fmt, empty, errorMessage, icon, panelNote, modal } from '../ui.js?v=shell119';
import { requireUserDataKey } from '../data-key.js?v=shell154';

let status = null;
let shareTimer = null;
let cryptoReady = null;
let keyPrompted = false;
let pendingFocus = '';
let focusScroll = false;
let focusNote = '';

export async function mount(el, ctx) {
  status = null;
  ctx.setTitle(['Home']);
  const greeting = h('div', { class: 'page-header' },
    h('h1', null, 'Home'));
  const statusGrid = h('div', { class: 'grid cols-4' });
  const pluginsCard = h('div', { class: 'card' }, h('div', { class: 'card-header' }, h('h2', null, 'Plugins')), h('div', { class: 'muted' }, 'Loading…'));
  const alertsCard = h('div', { class: 'card' }, h('div', { class: 'card-header' }, h('h2', null, 'Recent alerts'), ctx.hasRole('Admin', 'Analyst') ? h('a', { class: 'btn sm', href: '#/alerts' }, 'All alerts') : null), h('div', { class: 'muted' }, 'Loading…'));
  const sharesCard = h('div', { class: 'card share-panel', hidden: true });
  el.append(greeting, statusGrid, h('div', { class: 'grid cols-2' }, pluginsCard, alertsCard), sharesCard);

  try {
    status = await ctx.api.get('/api/status');
    statusGrid.append(
      kpi('Search backend', status.elasticsearch?.enabled ? (status.elasticsearch.healthy ? 'Healthy' : 'Unreachable') : 'Not configured', status.elasticsearch?.enabled ? (status.elasticsearch.healthy ? 'success' : 'danger') : 'warning', esDetail(status.elasticsearch)),
      kpi('Plugins loaded', String(status.plugins?.loaded ?? 0), status.plugins?.failed ? 'warning' : '', status.plugins?.failed ? `${status.plugins.failed} failed to load` : ''),
      kpi('Alert rules', String(status.alerts?.enabledRules ?? 0), '', `${fmt.number(status.alerts?.alertsLast24h ?? 0)} alerts in 24h`),
      kpi('Notifications', status.notifications?.smtpConfigured ? 'Email ready' : 'Email not set', status.notifications?.smtpConfigured ? 'success' : 'warning', status.notifications?.pending ? `${status.notifications.pending} pending` : ''),
    );
  } catch (err) {
    statusGrid.append(h('div', { class: 'alert danger' }, errorMessage(err)));
  }

  try {
    const pluginsPromise = ctx.api.get('/api/plugins');
    const updatesPromise = ctx.hasRole('Admin') ? ctx.api.get('/api/admin/plugins').catch(() => null) : Promise.resolve(null);
    const [plugins, adminPlugins] = await Promise.all([pluginsPromise, updatesPromise]);
    const updateIds = new Set();
    for (const offer of adminPlugins?.available || []) {
      if (offer.action !== 'upgrade') continue;
      if (offer.pluginId) updateIds.add(offer.pluginId);
      for (const plugin of plugins) {
        if (offerMatches(plugin.id, offer.name)) updateIds.add(plugin.id);
      }
    }
    const loadedIds = new Set(plugins.map((m) => m.id));
    const failures = (status?.plugins?.failures || []).filter((f) => f.id && !loadedIds.has(f.id));
    const rows = [
      ...plugins.map((m) => h('div', { class: 'flex between' },
        h('div', null, h('div', null, h('strong', null, m.name), ' ', badge('v' + m.version), ' ', pluginHealth(m.id, updateIds))),
        h('a', { class: 'btn sm', href: `#/p/${m.id}/${m.pages[0] || ''}` }, 'Open'))),
      ...failures.map((f) => h('div', { class: 'flex between' },
        h('div', null, h('div', null, h('strong', null, f.id), ' ', badge('unhealthy', 'danger', true))))),
    ];
    const body = pluginsCard.lastChild;
    body.replaceWith(rows.length === 0 ? empty('No plugins installed.', 'plug') : h('div', { class: 'col' }, rows));
    if (plugins.some((plugin) => plugin.id === 'secret-sharing')) {
      pendingFocus = String(ctx.query?.focus || '').trim();
      focusScroll = !!pendingFocus;
      focusNote = '';
      await renderShares(ctx, sharesCard);
      if (shareTimer) clearInterval(shareTimer);
      shareTimer = setInterval(() => {
        if (document.hidden || document.querySelector('.modal')) return;
        renderShares(ctx, sharesCard, true);
      }, 5000);
    }
  } catch (err) {
    pluginsCard.lastChild.replaceWith(h('div', { class: 'alert danger' }, errorMessage(err)));
  }

  if (ctx.hasRole('Admin', 'Analyst')) {
    try {
      const alerts = await ctx.api.get('/api/alerts/instances?pageSize=8');
      alertsCard.lastChild.replaceWith(alerts.items.length === 0 ? empty('No alerts yet.', 'bell')
        : h('div', { class: 'col' }, alerts.items.map((a) => h('div', { class: 'flex between' },
          h('div', { class: 'grow' }, h('div', { class: 'truncate' }, badge(a.severity, severityKind(a.severity)), ' ', a.summary), h('div', { class: 'small muted' }, `${a.ruleName} · ${fmt.relative(a.createdAt)}${a.count > 1 ? ` · ×${a.count}` : ''}`)),
          badge(a.status, a.status === 'new' ? 'primary' : '')))));
    } catch (err) {
      alertsCard.lastChild.replaceWith(h('div', { class: 'alert danger' }, errorMessage(err)));
    }
  } else {
    alertsCard.lastChild.replaceWith(empty('No alerts.', 'bell'));
  }
}

export function unmount() {
  if (shareTimer) clearInterval(shareTimer);
  shareTimer = null;
  pendingFocus = '';
  focusScroll = false;
  focusNote = '';
  keyPrompted = false;
}

function offerMatches(pluginId, offerName) {
  const stem = String(offerName || '').replace(/\.7z$/i, '').toLowerCase().replace(/[._]/g, '-');
  const id = String(pluginId || '').toLowerCase();
  return stem === id || stem.endsWith('-' + id);
}

function applyFocus(card) {
  if (focusNote) panelNote(card, focusNote, 'warning');
  if (!pendingFocus) return;
  const item = card.querySelector('.share-item[data-id="' + CSS.escape(pendingFocus) + '"]');
  if (!item) {
    focusNote = 'That item is not on your dashboard (deleted, expired, or not yours).';
    panelNote(card, focusNote, 'warning');
    pendingFocus = '';
    focusScroll = false;
    return;
  }
  focusNote = '';
  item.classList.add('share-item-focus');
  if (focusScroll) {
    item.scrollIntoView({ block: 'center' });
    const id = pendingFocus;
    focusScroll = false;
    setTimeout(() => { if (pendingFocus === id) pendingFocus = ''; }, 2400);
  }
}

function shareHeader() {
  return h('div', { class: 'card-header' }, h('h2', null, 'Secret sharing'), h('div', { class: 'btn-group' },
    h('a', { class: 'btn sm', href: '#/p/secret-sharing/send' }, 'Send secret'),
    h('a', { class: 'btn sm', href: '#/p/secret-sharing/collect' }, 'Collect secret')));
}

async function renderShares(ctx, card, quiet) {
  card.hidden = false;
  if (!quiet) card.replaceChildren(shareHeader(), h('p', { class: 'muted' }, 'Loading…'));
  try {
    await ensureCrypto();
    const data = await ctx.api.get('/api/plugins/secret-sharing/home');
    const items = data.items || [];
    if (!keyPrompted && !window.SecretUdk.loadUserDataKey() && items.some((item) => item.encryptedLabel || item.privateNoteCiphertext || item.hasOwnerKey)) {
      keyPrompted = true;
      try { await requireUserDataKey(); } catch { /* names stay locked until a later attempt */ }
    }
    const rows = [];
    for (const item of items) rows.push(await shareItem(ctx, card, item));
    const list = items.length === 0
      ? h('p', { class: 'muted share-empty' }, 'No sends or collects yet.')
      : h('div', { class: 'share-list' }, rows);
    const header = card.querySelector(':scope > .card-header') || shareHeader();
    card.replaceChildren(header, list);
    applyFocus(card);
  } catch (err) {
    const note = h('div', { class: 'alert danger' }, errorMessage(err));
    if (quiet && card.querySelector('.share-list, .share-empty')) panelNote(card, errorMessage(err));
    else card.replaceChildren(shareHeader(), note);
  }
}

async function shareItem(ctx, panel, item) {
  const collect = item.kind === 'collect';
  const noun = collect ? 'collect' : 'send';
  const shown = item.status === 'waiting' ? 'pending' : item.status;
  const title = await ownerText(item.encryptedLabel);
  const note = item.privateNoteCiphertext ? await ownerText(item.privateNoteCiphertext) : '';
  const canCollect = collect && item.hasOwnerKey && item.status === 'ready';
  const modeTitle = item.oneTime ? `This ${noun} can only be viewed once` : `This ${noun} can be accessed multiple times`;
  const meta = [
    chip(noun),
    chip(item.oneTime ? 'one-time' : 'multi', '', modeTitle),
  ];
  if (item.passwordProtected) meta.push(chip('Password', 'password', `This ${noun} is protected by a password`));
  if (item.ipRestricted) meta.push(chip('IP', 'ip', `This ${noun} is IP address restricted`));
  if (!item.oneTime) {
    const count = item.accessCount || 0;
    if (item.maxAccessCount != null && item.maxAccessCount !== '') meta.push(chip(`${count}/${item.maxAccessCount} opens`, 'access'));
    else if (count > 0) meta.push(chip(`${count} ${count === 1 ? 'open' : 'opens'}`, 'access'));
  }
  let when = '';
  try { when = new Date(item.expiresAt).toLocaleString(); } catch { when = String(item.expiresAt || ''); }
  meta.push(h('span', { class: 'share-expires' }, `Expires ${when}`));

  const article = h('article', { class: 'share-item' + (canCollect ? ' clickable' : ''), dataset: { id: item.id, kind: item.kind, status: item.status } });
  const actions = [];
  if (collect && item.hasOwnerKey && item.status !== 'consumed') {
    actions.push(h('button', {
      class: 'btn sm', type: 'button', disabled: !canCollect,
      title: collectTitle(item.status),
      onClick: (ev) => { ev.stopPropagation(); if (canCollect) openCollect(ctx, article, item); },
    }, 'Collect'));
  }
  if (collect && item.status === 'waiting') {
    actions.push(h('button', { class: 'btn sm', type: 'button', onClick: (ev) => { ev.stopPropagation(); copyUpload(panel, item); } }, 'Copy upload link'));
  }
  actions.push(h('button', { class: 'btn sm danger', type: 'button', onClick: (ev) => { ev.stopPropagation(); removeShare(ctx, panel, item); } }, 'Delete'));
  const parts = [
    h('div', { class: 'share-item-head' },
      h('div', { class: 'share-item-title' }, title == null ? '(unlock encryption to view name)' : title),
      h('div', { class: 'share-item-tags' }, chip(item.id, 'id', 'ID'), statusBadge(shown))),
    h('div', { class: 'share-meta' }, meta),
    item.privateNoteCiphertext ? h('div', { class: 'share-note' }, h('strong', null, 'Private note: '), note == null ? '(unlock encryption with your account password)' : note) : null,
    h('div', { class: 'share-actions' }, actions),
  ].filter(Boolean);
  article.append(...parts);
  if (canCollect) article.addEventListener('click', (ev) => { if (ev.target.closest('button, a')) return; openCollect(ctx, article, item); });
  return article;
}

function chip(text, className, tooltip) {
  const props = { class: 'share-chip' + (className ? ' ' + className : '') };
  if (tooltip) props['data-tooltip'] = tooltip;
  return h('span', props, className === 'id' ? h('span', null, text) : text);
}

function statusBadge(status) {
  const kind = status === 'active' || status === 'ready' ? 'success' : status === 'consumed' || status === 'expired' ? 'danger' : '';
  return h('span', { class: 'badge share-status ' + status + (kind ? ' ' + kind : '') }, status);
}

function collectTitle(status) {
  if (status === 'waiting') return 'Waiting for upload';
  if (status === 'consumed') return 'Already collected (will be removed when purged)';
  if (status === 'expired') return 'Expired (will be removed when purged)';
  if (status === 'ready') return 'Open collect page';
  return 'Not ready to collect';
}

async function ownerText(cipher) {
  if (!cipher) return '';
  const udk = window.SecretUdk && window.SecretUdk.loadUserDataKey();
  if (!udk) return null;
  try {
    const bytes = await window.SecretUdk.decryptWithUserDataKey(cipher, udk);
    const text = new TextDecoder().decode(bytes);
    bytes.fill(0);
    return text;
  } catch {
    return null;
  }
}

function ensureCrypto() {
  if (!cryptoReady) {
    cryptoReady = loadScript('/assets/js/udk.js?v=shell133').then(() => loadScript('/plugins/secret-sharing/public/crypto.js?v=crypto2')).catch((err) => {
      cryptoReady = null;
      throw err;
    });
  }
  return cryptoReady;
}

async function copyUpload(panel, item) {
  const upload = `${location.origin}/upload?id=${encodeURIComponent(item.id)}`;
  try {
    await navigator.clipboard.writeText(upload);
    panelNote(panel, 'Upload link copied.', 'success');
  } catch {
    panelNote(panel, 'Could not copy; select and copy manually.');
  }
}

async function openCollect(ctx, card, item) {
  const note = card.querySelector('.share-error') || h('div', { class: 'alert danger share-error' });
  note.textContent = '';
  try {
    await loadScript('/assets/js/udk.js?v=shell133');
    await loadScript('/plugins/secret-sharing/public/crypto.js?v=crypto2');
    const udk = await requireUserDataKey();
    const pack = await ctx.api.get(`/api/plugins/secret-sharing/collects/${encodeURIComponent(item.id)}/owner-key`);
    const plain = await window.SecretUdk.decryptWithUserDataKey(pack.ownerPrivateKeyProtected, udk);
    const fragment = item.passwordProtected
      ? window.SenditCrypto.buildPasswordProtectedFragment(new TextDecoder().decode(plain))
      : plain.length === 32
        ? window.SenditCrypto.buildFragment(plain)
        : '#sk=' + window.SenditCrypto.b64urlEncode(plain);
    plain.fill(0);
    location.assign(`${location.origin}/collect?id=${encodeURIComponent(item.id)}${fragment}`);
  } catch (err) {
    note.textContent = err.message || 'Could not open the collect.';
    card.append(note);
  }
}

function loadScript(src) {
  if (document.querySelector(`script[src="${src}"]`)) return Promise.resolve();
  return new Promise((resolve, reject) => {
    const s = document.createElement('script');
    s.src = src;
    s.onload = () => resolve();
    s.onerror = () => reject(new Error('Could not load encryption.'));
    document.head.append(s);
  });
}

async function removeShare(ctx, card, item) {
  if (!(await modal.confirm('Delete item', 'Delete this item? This cannot be undone.', { danger: true, confirmLabel: 'Delete' }))) return;
  try {
    await ctx.api.delete(`/api/plugins/secret-sharing/${item.kind === 'collect' ? 'collects' : 'sends'}/${encodeURIComponent(item.id)}`);
    await renderShares(ctx, card, true);
  } catch (err) {
    panelNote(card, err.message || 'Could not delete the item.');
  }
}

function pluginHealth(id, updateIds) {
  if (updateIds.has(id)) return badge('update', 'warning', true);
  return badge('healthy', 'success', true);
}

function esDetail(es) {
  if (!es?.enabled || es.healthy) return '';
  return es.error || '';
}

function kpi(label, value, kind, delta) {
  return h('div', { class: 'card kpi ' + (kind || '') }, h('div', { class: 'label' }, label), h('div', { class: 'value' }, value), h('div', { class: 'delta' }, delta || ''));
}

export function severityKind(sev) {
  return { critical: 'danger', high: 'danger', medium: 'warning', low: 'info', informational: '' }[sev] || '';
}
