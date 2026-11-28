import { showAllAlerts } from '../home-role.js?v=shell462';
import { h, badge, fmt, empty, errorMessage, icon, panelNote, modal } from '../ui.js?v=shell119';
import { requireUserDataKey } from '../data-key.js?v=shell468';

let status = null;
let shareTimer = null;
let cveTimer = null;
let newsTimer = null;
let cryptoReady = null;
let keyPrompted = false;
let pendingFocus = '';
let focusScroll = false;
let focusNote = '';
let generation = 0;
let homeUserId = '';

export async function mount(el, ctx) {
  const gen = ++generation;
  homeUserId = String(ctx.user?.id || '');
  let ownedTimer = null;
  let ownedCveTimer = null;
  let ownedNewsTimer = null;
  const leave = () => {
    if (ownedTimer && shareTimer === ownedTimer) {
      clearInterval(ownedTimer);
      shareTimer = null;
    }
    if (ownedCveTimer && cveTimer === ownedCveTimer) {
      clearInterval(ownedCveTimer);
      cveTimer = null;
    }
    if (ownedNewsTimer && newsTimer === ownedNewsTimer) {
      clearInterval(ownedNewsTimer);
      newsTimer = null;
    }
    return gen;
  };
  status = null;
  ctx.setTitle(['Home']);
  const greeting = h('div', { class: 'page-header' },
    h('h1', null, 'Home'));
  const statusGrid = h('div', { class: 'grid cols-3' });
  const pluginsCard = h('div', { class: 'card' }, h('div', { class: 'card-header' }, h('h2', null, 'Plugins')), h('div', { class: 'muted' }, 'Loading…'));
  const cveCard = h('div', { class: 'card' }, cveHeader('Top CVEs', 'https://radar.cloudflare.com/zero-wire/cves'), h('div', { class: 'muted' }, 'Loading…'));
  const highCard = h('div', { class: 'card' }, cveHeader('High & Critical', 'https://radar.cloudflare.com/zero-wire/cves'), h('div', { class: 'muted' }, 'Loading…'));
  const alertsCard = h('div', { class: 'card' }, h('div', { class: 'card-header' }, h('h2', null, 'Recent alerts'), showAllAlerts(ctx.user?.roles) ? h('a', { class: 'btn sm', href: '/alerts' }, 'All alerts') : null), h('div', { class: 'muted' }, 'Loading…'));
  const newsCard = h('div', { class: 'card' }, newsHeader(), h('div', { class: 'muted' }, 'Loading…'));
  const sharesCard = h('div', { class: 'card share-panel', hidden: true });
  el.append(greeting, statusGrid, h('div', { class: 'grid cols-2' }, pluginsCard, alertsCard), h('div', { class: 'grid cols-2' }, cveCard, highCard), newsCard, sharesCard);
  const cachedStatus = homeRead('status');
  const cachedPlugins = homeRead('plugins');
  const cachedAlerts = homeRead('alerts');
  const cachedCves = homeRead('cves');
  const cachedNews = homeRead('news');
  const cachedShares = homeRead('shares');
  const paintCachedShares = !!(cachedShares && cachedPlugins?.plugins?.some((plugin) => plugin.id === 'secret-sharing'));
  const focusOrder = shareFocusOrder(ctx.query?.focus, paintCachedShares ? cachedShares : null);
  pendingFocus = focusOrder.focus;
  focusScroll = focusOrder.focusScroll;
  focusNote = '';
  if (cachedStatus) paintStatus(statusGrid, cachedStatus);
  if (cachedPlugins) paintPlugins(pluginsCard, cachedPlugins.plugins, cachedPlugins.admin, cachedStatus);
  if (cachedAlerts) paintAlerts(alertsCard, cachedAlerts, showAllAlerts(ctx.user?.roles));
  else if (!ctx.hasRole('Admin', 'Analyst')) alertsCard.lastChild.replaceWith(empty('No alerts.', 'bell'));
  if (cachedCves) paintCves(cveCard, highCard, cachedCves);
  if (cachedNews) paintNews(newsCard, cachedNews);
  const cachedSharePaint = paintCachedShares
    ? renderShares(ctx, sharesCard, true, cachedShares)
    : Promise.resolve();
  const watchFeeds = () => {
    if (gen !== generation || document.hidden) return;
    renderNews(ctx, newsCard, true);
    renderCves(ctx, cveCard, highCard, true);
  };
  newsTimer = ownedNewsTimer = setInterval(watchFeeds, 60 * 1000);
  void loadStatus(ctx, statusGrid, pluginsCard, gen);
  void loadPlugins(ctx, pluginsCard, sharesCard, gen, (timer) => { ownedTimer = timer; }, cachedSharePaint);
  void loadAlerts(ctx, alertsCard, gen);
  void renderNews(ctx, newsCard, !!cachedNews);
  void renderCves(ctx, cveCard, highCard, !!cachedCves);
  return gen;
}

export function unmount(gen) {
  if (gen !== generation) return;
  generation += 1;
  if (shareTimer) clearInterval(shareTimer);
  shareTimer = null;
  if (cveTimer) clearInterval(cveTimer);
  cveTimer = null;
  if (newsTimer) clearInterval(newsTimer);
  newsTimer = null;
  pendingFocus = '';
  focusScroll = false;
  focusNote = '';
  keyPrompted = false;
}

function offerPackageKey(offerName) {
  let name = String(offerName || '').toLowerCase();
  if (name.endsWith('.7z')) name = name.slice(0, -3);
  const tokens = name.replaceAll('.', '-').replaceAll('_', '-').split('-').filter(Boolean);
  if (tokens[0] === 'vulpes' && tokens[1] === 'plugins') tokens.splice(0, 2);
  return tokens.join('-');
}

function offerMatches(pluginId, offerName) {
  return offerPackageKey(offerName) === String(pluginId || '').toLowerCase();
}

function applyFocus(card, giveUp) {
  if (focusNote) panelNote(card, focusNote, 'warning');
  if (!pendingFocus) return;
  const item = card.querySelector('.share-item[data-id="' + CSS.escape(pendingFocus) + '"]');
  if (!item) {
    // A cached paint must not drop the id before the network list is on screen.
    if (!giveUp || !card.querySelector('.share-list, .share-empty')) return;
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
    const focusGen = generation;
    focusScroll = false;
    // The cached paint must leave the id armed until the network list is on screen.
    const delay = focusClearDelay(giveUp);
    if (delay > 0) setTimeout(() => { if (focusGen !== generation || pendingFocus !== id) return; pendingFocus = ''; }, delay);
  }
}

export function focusClearDelay(networkPaint) {
  return networkPaint ? 2400 : 0;
}

function shareHeader(ctx) {
  const actions = [h('a', { class: 'btn sm', href: '/p/secret-sharing/send' }, 'Send secret')];
  if (ctx.hasRole('Admin', 'Analyst')) actions.push(h('a', { class: 'btn sm', href: '/p/secret-sharing/collect' }, 'Collect secret'));
  return h('div', { class: 'card-header' }, h('h2', null, 'Secret sharing'), h('div', { class: 'btn-group' }, actions));
}

async function renderShares(ctx, card, quiet, preloaded) {
  const gen = generation;
  card.hidden = false;
  const canCollect = ctx.hasRole('Admin', 'Analyst');
  if (!quiet && !preloaded) card.replaceChildren(shareHeader(ctx), h('p', { class: 'muted' }, 'Loading…'));
  try {
    await ensureCrypto();
    if (gen !== generation) return;
    const data = preloaded || await ctx.api.get('/api/plugins/secret-sharing/home');
    if (gen !== generation) return;
    if (!preloaded) {
      if (quiet && homeSame(homeRead('shares'), data)) {
        applyFocus(card, true);
        return;
      }
      homeWrite('shares', data);
    }
    const items = (data.items || []).filter((item) => canCollect || item.kind !== 'collect');
    if (gen === generation && !keyPrompted && !window.SecretUdk.loadUserDataKey(ctx.user?.id) && items.some((item) => item.encryptedLabel || item.privateNoteCiphertext || item.hasOwnerKey)) {
      try { await requireUserDataKey(); } catch { /* names stay locked until a later attempt */ }
      if (gen !== generation) return;
      keyPrompted = true;
    }
    if (gen !== generation) return;
    const rows = [];
    for (const item of items) rows.push(await shareItem(ctx, card, item));
    if (gen !== generation) return;
    const list = items.length === 0
      ? h('p', { class: 'muted share-empty' }, canCollect ? 'No sends or collects yet.' : 'No sends yet.')
      : h('div', { class: 'share-list' }, rows);
    const header = card.querySelector(':scope > .card-header') || shareHeader(ctx);
    card.replaceChildren(header, list);
    if (ctx.query?.panel === 'secrets' && card.dataset.secretsScroll !== '1') {
      card.dataset.secretsScroll = '1';
      card.scrollIntoView({ block: 'start' });
    }
    applyFocus(card, !preloaded);
  } catch (err) {
    if (gen !== generation) return;
    const note = h('div', { class: 'alert danger' }, errorMessage(err));
    if (quiet && card.querySelector('.share-list, .share-empty')) panelNote(card, errorMessage(err));
    else card.replaceChildren(shareHeader(ctx), note);
  }
}

async function shareItem(ctx, panel, item) {
  const collect = item.kind === 'collect';
  const noun = collect ? 'collect' : 'send';
  const shown = item.status === 'waiting' ? 'pending' : item.status;
  const title = await ownerText(item.encryptedLabel, ctx.user?.id);
  const note = item.privateNoteCiphertext ? await ownerText(item.privateNoteCiphertext, ctx.user?.id) : '';
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
    item.privateNoteCiphertext ? h('div', { class: 'share-note' }, h('strong', null, 'Private note: '), note == null ? '(unlock encryption to view the note)' : note) : null,
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

async function ownerText(cipher, userId) {
  if (!cipher) return '';
  const udk = window.SecretUdk && window.SecretUdk.loadUserDataKey(userId);
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
    cryptoReady = loadScript('/assets/js/crypto/vulpes-crypto.js?v=crypto4')
      .then(() => window.VulpesCrypto.ready())
      .then(() => loadScript('/assets/js/udk.js?v=udk10'))
      .then(() => window.SecretUdk.ready())
      .catch((err) => {
        cryptoReady = null;
        throw err;
      });
  }
  return cryptoReady;
}

async function copyUpload(panel, item) {
  if (!item.publicKey) {
    panelNote(panel, 'This collect has no public key to put in the upload link.');
    return;
  }
  const upload = `${location.origin}/upload?id=${encodeURIComponent(item.id)}#pk=${encodeURIComponent(item.publicKey)}`;
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
    await loadScript('/assets/js/crypto/vulpes-crypto.js?v=crypto4');
    await window.VulpesCrypto.ready();
    await loadScript('/assets/js/udk.js?v=udk10');
    await window.SecretUdk.ready();
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
    s.onerror = () => {
      s.remove();
      reject(new Error('Could not load encryption.'));
    };
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

function newsWire(label, href) {
  return h('a', { class: 'btn sm', href, target: '_blank', rel: 'noopener noreferrer' }, label);
}

function newsHeader() {
  return h('div', { class: 'card-header' }, h('h2', null, 'Security news'));
}

function newsColumn(items, label, href) {
  return h('div', { class: 'col' },
    h('div', { class: 'flex end' }, newsWire(label, href)),
    newsRows(items));
}

function newsRows(items) {
  return items.length === 0 ? empty('No security news.')
    : h('div', { class: 'col' }, items.map((item) => h('a', {
      class: 'flex between cve-row news-row',
      href: item.url,
      target: '_blank',
      rel: 'noopener noreferrer',
    },
      h('div', { class: 'grow' }, h('div', { class: 'news-title' }, item.title)),
      item.published ? h('div', { class: 'small muted cve-when' }, fmt.relative(item.published)) : null)));
}

function paintNews(card, data) {
  card.replaceChildren(newsHeader(), h('div', { class: 'grid cols-3' },
    newsColumn(data.items || [], 'Cyber Daily', 'https://www.cyberdaily.au/security'),
    newsColumn(data.itNews || [], 'iTnews', 'https://www.itnews.com.au/category/security'),
    newsColumn(data.hackerNews || [], 'The Hacker News', 'https://thehackernews.com')));
}

async function renderNews(ctx, card, quiet, preloaded) {
  const gen = generation;
  if (preloaded) {
    paintNews(card, preloaded);
    return;
  }
  try {
    const data = await ctx.api.get('/api/news/security');
    if (gen !== generation) return;
    if (homeSame(homeRead('news'), data)) return;
    homeWrite('news', data);
    paintNews(card, data);
  } catch (err) {
    if (gen !== generation || quiet || homeRead('news')) return;
    card.replaceChildren(newsHeader(), h('div', { class: 'alert danger' }, errorMessage(err)));
  }
}

function cveHeader(title, href) {
  return h('div', { class: 'card-header' },
    h('h2', null, title),
    h('a', { class: 'btn sm', href: href, target: '_blank', rel: 'noopener noreferrer' }, 'Cloudflare Radar'));
}

function cveRows(items, emptyText) {
  return items.length === 0 ? empty(emptyText, 'shield')
    : h('div', { class: 'col' }, items.map((item) => {
      const severity = (item.severity || 'not scored').toLowerCase();
      return h('a', {
        class: 'flex between cve-row',
        href: item.url,
        target: '_blank',
        rel: 'noopener noreferrer',
      },
        h('div', { class: 'grow' },
          h('div', { class: 'cve-copy' }, h('strong', null, item.id), ' ', badge(severity, severityKind(severity)), item.score != null ? ' ' + item.score : ''),
          h('div', { class: 'small muted cve-copy' }, item.title || item.summary || '')),
        h('div', { class: 'small muted cve-when' }, fmt.relative(item.published)));
    }));
}

function paintCves(card, highCard, data) {
  card.replaceChildren(cveHeader('Top CVEs', 'https://radar.cloudflare.com/zero-wire/cves'), cveRows(data.items || [], 'No CVEs published.'));
  highCard.replaceChildren(cveHeader('High & Critical', 'https://radar.cloudflare.com/zero-wire/cves'), cveRows(data.high || [], 'No High or Critical CVEs published.'));
}

async function renderCves(ctx, card, highCard, quiet, preloaded) {
  const gen = generation;
  if (preloaded) {
    paintCves(card, highCard, preloaded);
    return;
  }
  try {
    const data = await ctx.api.get('/api/radar/cves');
    if (gen !== generation) return;
    if (homeSame(homeRead('cves'), data)) return;
    homeWrite('cves', data);
    paintCves(card, highCard, data);
  } catch (err) {
    if (gen !== generation || quiet || homeRead('cves')) return;
    const alert = h('div', { class: 'alert danger' }, errorMessage(err));
    card.replaceChildren(cveHeader('Top CVEs', 'https://radar.cloudflare.com/zero-wire/cves'), alert);
    highCard.replaceChildren(cveHeader('High & Critical', 'https://radar.cloudflare.com/zero-wire/cves'), alert.cloneNode(true));
  }
}

function paintStatus(grid, data) {
  status = data;
  grid.replaceChildren(
    kpi('Search backend', data.elasticsearch?.enabled ? (data.elasticsearch.healthy ? 'Healthy' : 'Unreachable') : 'Not configured', data.elasticsearch?.enabled ? (data.elasticsearch.healthy ? 'success' : 'danger') : 'warning', esDetail(data.elasticsearch)),
    kpi('Alert rules', String(data.alerts?.enabledRules ?? 0), '', `${fmt.number(data.alerts?.alertsLast24h ?? 0)} alerts in 24h`),
    kpi('Notifications', data.notifications?.smtpConfigured ? 'Email ready' : 'Email not set', data.notifications?.smtpConfigured ? 'success' : 'warning', data.notifications?.pending ? `${data.notifications.pending} pending` : ''),
  );
}

function paintPlugins(card, plugins, adminPlugins, snapshot) {
  const updateIds = new Set();
  for (const offer of adminPlugins?.available || []) {
    if (offer.action !== 'upgrade') continue;
    if (offer.pluginId) updateIds.add(offer.pluginId);
    for (const plugin of plugins || []) {
      if (offerMatches(plugin.id, offer.name)) updateIds.add(plugin.id);
    }
  }
  const loadedIds = new Set((plugins || []).map((item) => item.id));
  const failures = (snapshot?.plugins?.failures || []).filter((item) => item.id && !loadedIds.has(item.id));
  const rows = [
    ...(plugins || []).map((item) => h('div', { class: 'flex between' },
      h('div', null, h('div', null, h('strong', null, item.name), ' ', badge('v' + item.version), ' ', pluginHealth(item.id, updateIds))),
      h('a', { class: 'btn sm', href: `/p/${item.id}/${item.pages[0] || ''}` }, 'Open'))),
    ...failures.map((item) => h('div', { class: 'flex between' },
      h('div', null, h('div', null, h('strong', null, item.id), ' ', badge(item.unhealthy ? 'unhealthy' : 'failed', 'danger', true))))),
  ];
  card.replaceChildren(h('div', { class: 'card-header' }, h('h2', null, 'Plugins')), rows.length === 0 ? empty('No plugins installed.', 'plug') : h('div', { class: 'col' }, rows));
}

function paintAlerts(card, alerts, showAll) {
  card.replaceChildren(
    h('div', { class: 'card-header' }, h('h2', null, 'Recent alerts'), showAll ? h('a', { class: 'btn sm', href: '/alerts' }, 'All alerts') : null),
    !alerts?.items?.length ? empty('No alerts yet.', 'bell')
      : h('div', { class: 'col' }, alerts.items.map((item) => h('div', { class: 'flex between' },
        h('div', { class: 'grow' }, h('div', { class: 'truncate' }, badge(item.severity, severityKind(item.severity)), ' ', item.summary), h('div', { class: 'small muted' }, `${item.ruleName} · ${fmt.relative(item.createdAt)}${item.count > 1 ? ` · ×${item.count}` : ''}`)),
        badge(item.status, item.status === 'new' ? 'primary' : '')))));
}

async function loadStatus(ctx, grid, pluginsCard, gen) {
  try {
    const data = await ctx.api.get('/api/status');
    if (gen !== generation) return;
    status = data;
    if (homeSame(homeRead('status'), data)) return;
    homeWrite('status', data);
    paintStatus(grid, data);
    const plugins = homeRead('plugins');
    if (plugins) paintPlugins(pluginsCard, plugins.plugins, plugins.admin, data);
  } catch (err) {
    if (gen !== generation || homeRead('status')) return;
    grid.replaceChildren(h('div', { class: 'alert danger' }, errorMessage(err)));
  }
}

async function loadPlugins(ctx, card, sharesCard, gen, assignTimer, cachedSharePaint) {
  try {
    const pluginsPromise = ctx.api.get('/api/plugins');
    const updatesPromise = ctx.hasRole('Admin') ? ctx.api.get('/api/admin/plugins').catch(() => null) : Promise.resolve(null);
    const [plugins, admin] = await Promise.all([pluginsPromise, updatesPromise]);
    if (gen !== generation) return;
    const pack = { plugins, admin };
    if (!homeSame(homeRead('plugins'), pack)) {
      homeWrite('plugins', pack);
      paintPlugins(card, plugins, admin, status || homeRead('status'));
    }
    if (!plugins.some((plugin) => plugin.id === 'secret-sharing')) return;
    try { await cachedSharePaint; } catch { /* the cached paint already showed its error */ }
    if (gen !== generation) return;
    if (!shareTimer) {
      const timer = setInterval(() => {
        if (gen !== generation) {
          clearInterval(timer);
          if (shareTimer === timer) shareTimer = null;
          return;
        }
        if (document.hidden || document.querySelector('.modal')) return;
        renderShares(ctx, sharesCard, true);
      }, 5000);
      shareTimer = timer;
      assignTimer(timer);
    }
    void renderShares(ctx, sharesCard, true);
  } catch (err) {
    if (gen !== generation || homeRead('plugins')) return;
    card.replaceChildren(h('div', { class: 'card-header' }, h('h2', null, 'Plugins')), h('div', { class: 'alert danger' }, errorMessage(err)));
  }
}

async function loadAlerts(ctx, card, gen) {
  if (!ctx.hasRole('Admin', 'Analyst')) {
    card.lastChild.replaceWith(empty('No alerts.', 'bell'));
    return;
  }
  try {
    const data = await ctx.api.get('/api/alerts/instances?pageSize=8');
    if (gen !== generation) return;
    if (homeSame(homeRead('alerts'), data)) return;
    homeWrite('alerts', data);
    paintAlerts(card, data, true);
  } catch (err) {
    if (gen !== generation || homeRead('alerts')) return;
    card.lastChild.replaceWith(h('div', { class: 'alert danger' }, errorMessage(err)));
  }
}

const homeCachePrefix = 'vulpes-home:';

export function homeCacheKey(userId, name) {
  return homeCachePrefix + String(userId ?? '') + ':' + String(name ?? '');
}

export function homeCacheKeysToClear(keys) {
  const drop = [];
  for (const key of keys || []) {
    if (typeof key === 'string' && key.startsWith(homeCachePrefix)) drop.push(key);
  }
  return drop;
}

// Focus is armed before the cached share paint. Refresh still focuses when the list is unchanged.
export function shareFocusOrder(focusQuery, cachedShares) {
  const focus = String(focusQuery ?? '').trim();
  const hasCache = cachedShares != null;
  const steps = [];
  if (focus) steps.push('arm');
  if (hasCache) steps.push('paint-cache');
  if (focus && hasCache) steps.push('focus-cache');
  steps.push('refresh');
  if (focus) steps.push('focus');
  return { focus, focusScroll: focus.length > 0, steps };
}

function homeRead(name) {
  try {
    const text = sessionStorage.getItem(homeCacheKey(homeUserId, name));
    return text ? JSON.parse(text) : null;
  } catch {
    return null;
  }
}

function homeWrite(name, value) {
  try {
    sessionStorage.setItem(homeCacheKey(homeUserId, name), JSON.stringify(value));
  } catch {
    // The page still paints when storage is full.
  }
}

function homeSame(left, right) {
  try {
    return JSON.stringify(left) === JSON.stringify(right);
  } catch {
    return false;
  }
}

function kpi(label, value, kind, delta) {
  return h('div', { class: 'card kpi ' + (kind || '') }, h('div', { class: 'label' }, label), h('div', { class: 'value' }, value), h('div', { class: 'delta' }, delta || ''));
}

export function severityKind(sev) {
  return { critical: 'danger', high: 'danger', medium: 'warning', low: 'info', informational: '' }[sev] || '';
}
