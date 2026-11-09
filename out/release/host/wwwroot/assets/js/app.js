// Application shell: session bootstrap, navigation, path router, plugin page host.
import { api, session, invalidateSession, redirectToLogin } from './api.js';
import { h, clear, icon, errorMessage, ui, avatar } from './ui.js?v=shell231';

const content = document.getElementById('content');
const navEl = document.getElementById('nav');
let state = { user: null, app: null, nav: null };
let current = null; // { unmount, key }

const corePages = {
  '/': () => import('./pages/home.js?v=shell296'),
  '/account': () => import('./pages/account.js?v=shell258'),
  '/alerts': () => import('./pages/alerts.js?v=shell312'),
  '/admin/users': () => import('./pages/admin-users.js?v=shell235'),
  '/admin/plugins': () => import('./pages/admin-plugins.js?v=shell289'),
  '/admin/tenants': () => import('./pages/admin-tenants.js?v=shell311'),
  '/admin/settings': () => import('./pages/admin-settings.js?v=shell284'),
  '/admin/audit': () => import('./pages/admin-audit.js?v=shell219'),
  '/admin/console': () => import('./pages/admin-console.js?v=shell303'),
};

function parseLocation() {
  const path = location.pathname && location.pathname.startsWith('/') ? location.pathname : '/';
  const query = Object.fromEntries(new URLSearchParams(location.search));
  return { path, query };
}

function isHomeLink(href, path) {
  return path === '/' && href === '/';
}

function isShellPath(path) {
  return path === '/' || path === '/account' || path === '/alerts'
    || path.startsWith('/admin/') || path.startsWith('/p/');
}

export function navigate(path) {
  let target = path.startsWith('#') ? path.slice(1) : path;
  if (target === '' || target === '/') target = '/';
  else if (!target.startsWith('/')) target = '/' + target;
  const next = new URL(target, location.origin);
  if (next.origin !== location.origin) return;
  const dest = next.pathname + next.search;
  if (dest === location.pathname + location.search) { route(); return; }
  history.pushState(null, '', dest);
  route();
}

function hasRole(...roles) { return roles.some((r) => state.user?.roles?.includes(r)); }

const NAV_OPEN_PLUGIN = 'vc.nav.openPlugin';

function pluginId(section) {
  for (const item of section.items || []) if (item.pluginId) return item.pluginId;
  return '';
}

function openPlugin() {
  try { return localStorage.getItem(NAV_OPEN_PLUGIN); }
  catch { return null; }
}

function saveOpenPlugin(id) {
  try {
    localStorage.setItem(NAV_OPEN_PLUGIN, id || '');
    localStorage.removeItem('vc.nav.collapsed');
  } catch { /* storage can be blocked */ }
}

function applyOpenPlugin(id) {
  for (const sec of navEl.querySelectorAll('.nav-section[data-plugin]')) {
    const open = sec.dataset.plugin === id;
    sec.classList.toggle('collapsed', !open);
    sec.querySelector('button.title')?.setAttribute('aria-expanded', open ? 'true' : 'false');
  }
}

function navSections() {
  const sections = state.nav?.sections || [];
  if (!state.user?.mustChangePassword) return sections;
  return sections
    .map((section) => ({ ...section, items: section.items.filter((item) => item.id === 'account') }))
    .filter((section) => section.items.length > 0);
}

function renderNav() {
  clear(navEl);
  const { path } = parseLocation();
  const open = openPlugin() || '';
  navSections().forEach((section, index) => {
    const plugin = pluginId(section);
    const isCollapsed = plugin !== '' && plugin !== open;
    const sec = h('div', {
      class: 'nav-section' + (isCollapsed ? ' collapsed' : ''),
      dataset: plugin ? { section: section.title, plugin } : { section: section.title },
    });
    if (plugin) {
      const title = h('button', {
        class: 'title draggable', type: 'button',
        'aria-expanded': isCollapsed ? 'false' : 'true',
        'aria-controls': `nav-items-${index}`,
        onClick: (event) => {
          if (event.currentTarget.dataset.dragged === '1') {
            delete event.currentTarget.dataset.dragged;
            return;
          }
          const stored = openPlugin();
          const effective = stored == null ? open : stored;
          const next = effective === plugin ? '' : plugin;
          saveOpenPlugin(next);
          applyOpenPlugin(next);
        },
      }, section.title);
      bindPluginDrag(title);
      sec.append(title);
    } else {
      sec.append(h('div', { class: 'title' }, section.title));
    }
    const items = h('div', { class: 'nav-items', id: `nav-items-${index}` });
    for (const item of section.items) {
      if (item.hidden) continue;
      const disabled = item.disabled === true;
      const active = !disabled && (isHomeLink(item.href, path) || item.href === path);
      const label = [icon(item.icon || 'dot'), h('span', { class: 'truncate' }, item.title)];
      items.append(disabled
        ? h('span', { class: 'nav-link disabled', 'aria-disabled': 'true', title: 'Disabled in Microsoft 365 Business Premium mode' }, ...label)
        : h('a', { class: 'nav-link' + (active ? ' active' : ''), href: item.href, dataset: { navId: item.id } }, ...label));
    }
    sec.append(items);
    navEl.append(sec);
  });
}

const DRAG_THRESHOLD = 8;

function bindPluginDrag(button) {
  let startY = 0;
  let pointerId = null;
  let dragging = false;

  function clearDragStyle() {
    for (const section of navEl.querySelectorAll('.nav-section.dragging')) section.classList.remove('dragging');
  }

  function onPointerMove(event) {
    if (pointerId === null || event.pointerId !== pointerId) return;
    if (!dragging && Math.abs(event.clientY - startY) < DRAG_THRESHOLD) return;
    const section = button.closest('.nav-section');
    if (!section) return;
    if (!dragging) {
      dragging = true;
      section.dataset.restoreExpanded = section.classList.contains('collapsed') ? '' : '1';
      section.classList.add('dragging', 'collapsed');
    }
    movePluginSection(section, event.clientY);
  }

  function onPointerEnd(event) {
    if (pointerId === null || event.pointerId !== pointerId) return;
    const moved = dragging;
    const section = button.closest('.nav-section');
    pointerId = null;
    dragging = false;
    window.removeEventListener('pointermove', onPointerMove);
    window.removeEventListener('pointerup', onPointerEnd);
    window.removeEventListener('pointercancel', onPointerEnd);
    clearDragStyle();
    if (section?.dataset.restoreExpanded === '1') section.classList.remove('collapsed');
    if (section) delete section.dataset.restoreExpanded;
    try {
      if (button.hasPointerCapture(event.pointerId)) button.releasePointerCapture(event.pointerId);
    } catch { /* the pointer is already inactive once it is released */ }
    if (!moved) return;
    button.dataset.dragged = '1';
    const order = [...navEl.querySelectorAll('.nav-section[data-plugin]')].map((section) => section.dataset.plugin);
    const current = (state.nav?.sections || []).map(pluginId).filter(Boolean);
    if (order.length === current.length && order.every((id, index) => id === current[index])) return;
    void savePluginOrder(order);
  }

  button.addEventListener('pointerdown', (event) => {
    if (event.button !== 0 || pointerId !== null) return;
    startY = event.clientY;
    pointerId = event.pointerId;
    dragging = false;
    clearDragStyle();
    window.addEventListener('pointermove', onPointerMove);
    window.addEventListener('pointerup', onPointerEnd);
    window.addEventListener('pointercancel', onPointerEnd);
  });
}

function movePluginSection(section, clientY) {
  const plugins = [...navEl.querySelectorAll(':scope > .nav-section[data-plugin]')].filter((item) => item !== section);
  let before = null;
  for (const item of plugins) {
    const title = item.querySelector(':scope > button.title');
    if (!title) continue;
    const box = title.getBoundingClientRect();
    if (clientY < box.top + box.height / 2) {
      before = item;
      break;
    }
  }
  if (before) {
    if (before.previousElementSibling !== section) navEl.insertBefore(section, before);
    return;
  }
  if (navEl.lastElementChild !== section) navEl.append(section);
}

async function savePluginOrder(order) {
  try {
    await api.put('/api/nav/plugin-order', { pluginIds: order });
    const sections = state.nav?.sections || [];
    const fixed = sections.filter((section) => !pluginId(section));
    const byId = new Map(sections.filter((section) => pluginId(section)).map((section) => [pluginId(section), section]));
    const ordered = order.map((id) => byId.get(id)).filter(Boolean);
    for (const section of sections) {
      const id = pluginId(section);
      if (id && !order.includes(id)) ordered.push(section);
    }
    state.nav = { ...state.nav, sections: [...fixed, ...ordered] };
  } catch {
    renderNav();
  }
}

function setActiveNav(path) {
  let activePlugin = '';
  for (const link of navEl.querySelectorAll('.nav-link')) {
    const href = link.getAttribute('href');
    const active = isHomeLink(href, path) || href === path;
    link.classList.toggle('active', active);
    if (active) activePlugin = link.closest('.nav-section')?.dataset.plugin || '';
  }
  if (!activePlugin || openPlugin() === activePlugin) return;
  saveOpenPlugin(activePlugin);
  applyOpenPlugin(activePlugin);
}

function setCrumbs(parts) {
  document.title = `${parts[parts.length - 1]} · ${state.app?.name || 'Vulpes'}`;
}

async function applyBusinessPremiumNav() {
  const loaded = (state.nav?.sections || []).some((section) =>
    section.items.some((item) => item.pluginId === 'microsoft-365-audit'));
  if (!loaded) return;
  let riskOff = false;
  let hideRisk = false;
  try {
    const sources = await api.get('/api/plugins/microsoft-365-audit/sources');
    const risk = sources.find((s) => s.source === 'risk');
    riskOff = risk?.unavailable === true;
    hideRisk = risk?.hidden === true;
  } catch { /* the plugin is not loaded */ }
  for (const section of state.nav?.sections || []) {
    for (const item of section.items) {
      if (item.pluginId !== 'microsoft-365-audit' || item.page !== 'risk') continue;
      item.hidden = hideRisk;
      item.disabled = riskOff && !hideRisk;
    }
  }
}

function pageContext(params, query, pluginId) {
  return {
    api, ui, user: state.user, app: state.app, navigate, params, query,
    refreshNav: async () => { await applyBusinessPremiumNav(); renderNav(); },
    refreshChrome: async () => {
      const s = await session(true);
      if (!s.authenticated) return;
      state.user = s.user;
      renderChip();
    },
    plugin: pluginId ? { id: pluginId, apiBase: `/api/plugins/${pluginId}`, assetBase: `/plugins/${pluginId}` } : null,
    hasRole,
    setTitle: (parts) => setCrumbs(Array.isArray(parts) ? parts : [parts]),
  };
}

let routeToken = 0;

async function mountCore(path, query, stale) {
  const loader = corePages[path];
  if (!loader) return false;
  const mod = await loader();
  if (stale()) return true;
  const el = h('div', { class: 'stack' });
  clear(content).append(el);
  await mod.mount(el, pageContext({}, query, null));
  if (stale()) return true;
  current = { unmount: mod.unmount, key: path };
  return true;
}

async function mountPluginPage(pluginId, page, query) {
  if (!/^[a-z][a-z0-9-]{1,31}$/.test(pluginId) || !/^[a-z][a-z0-9-]{0,63}$/.test(page)) throw new Error('Invalid page');
  const navItem = state.nav.sections.flatMap((s) => s.items).find((i) => i.pluginId === pluginId && i.page === page);
  if (!navItem) throw Object.assign(new Error('You do not have access to that page.'), { status: 403 });
  setCrumbs([navItem.title]);
  const el = h('div', { class: 'stack' });
  clear(content).append(el);

  if (page === 'permissions') {
    const mod = await import(`./pages/permissions.js?v=shell100`);
    await mod.mount(el, pageContext({ plugin: pluginId, page }, query, pluginId));
    current = { unmount: mod.unmount, key: `${pluginId}/${page}` };
    return;
  }

  const res = await fetch(`/plugins/${pluginId}/pages/${page}.html?v=shell308`, { credentials: 'same-origin' });
  if (!res.ok) throw new Error(`Page not found (${res.status})`);
  const html = await res.text();
  // Fragments are trusted plugin content served from our own origin under CSP (no inline script can run).
  const template = document.createElement('template');
  template.innerHTML = html;
  el.append(template.content);

  const mod = await import(`/plugins/${pluginId}/js/${page}.js?v=shell308`);
  await mod.mount(el, pageContext({ plugin: pluginId, page }, query, pluginId));
  current = { unmount: mod.unmount, key: `${pluginId}/${page}` };
}

async function route() {
  const token = ++routeToken;
  const stale = () => token !== routeToken;
  // Old bookmarks used /#/alerts. The fragment never reached the server, so rewrite it here.
  if (location.pathname === '/' && location.hash.startsWith('#/')) {
    history.replaceState(null, '', location.hash.slice(1));
  }
  let { path, query } = parseLocation();
  if (state.nav?.sections?.some((section) => section.items.some((item) => item.disabled && item.href === path))) {
    history.replaceState(null, '', '/p/microsoft-365-audit/overview');
    path = '/p/microsoft-365-audit/overview';
    query = {};
  }
  if (state.user?.mustChangePassword && path !== '/account') {
    history.replaceState(null, '', '/account?changePassword=1');
    path = '/account';
    query = { changePassword: '1' };
  }
  try {
    if (current?.unmount) { try { await current.unmount(); } catch { /* ignore */ } }
    current = null;
    if (stale()) return;
    setActiveNav(path);
    const pluginMatch = path.match(/^\/p\/([^/]+)\/([^/]+)\/?$/);
    if (pluginMatch) { await mountPluginPage(pluginMatch[1], pluginMatch[2], query); return; }
    if (await mountCore(path, query, stale)) return;
    if (stale()) return;
    clear(content).append(h('div', { class: 'card' }, h('h2', null, 'Page not found'), h('p', { class: 'muted' }, 'The page you requested does not exist.'), h('a', { class: 'btn', href: '/' }, 'Go home')));
    setCrumbs(['Not found']);
  } catch (err) {
    if (err?.status === 401) { redirectToLogin(); return; }
    clear(content).append(h('div', { class: 'alert danger' }, errorMessage(err)));
    setCrumbs(['Error']);
  }
}

function renderChip() {
  const chip = document.getElementById('user-chip');
  const name = state.user.displayName || state.user.username || '';
  clear(chip).append(avatar(name, { updatedAt: state.user.avatarUpdatedAt }), h('span', { class: 'truncate' }, name));
}

function renderChrome() {
  renderChip();
  const logoutBtn = document.getElementById('logout-btn');
  clear(logoutBtn).append(icon('logout'));
  logoutBtn.addEventListener('click', async () => {
    try { await api.post('/auth/logout'); } catch { /* fall through */ }
    invalidateSession();
    location.assign('/login');
  });
  document.getElementById('footer').textContent = `v${state.app?.version || ''} · ${state.user.roles?.join(', ') || ''}`;
}

async function boot() {
  const s = await session(true);
  if (!s.authenticated) { redirectToLogin(); return; }
  state.user = s.user;
  state.app = s.app;
  state.nav = await api.get('/api/nav');
  await applyBusinessPremiumNav();
  renderChrome();
  renderNav();
  window.addEventListener('popstate', route);
  await route();
}

document.addEventListener('click', (event) => {
  if (event.defaultPrevented || event.button !== 0 || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return;
  const link = event.target instanceof Element ? event.target.closest('a') : null;
  if (!link || link.target || link.hasAttribute('download')) return;
  const href = link.getAttribute('href');
  if (!href || href.startsWith('#')) return;
  let url;
  try { url = new URL(href, location.origin); } catch { return; }
  if (url.origin !== location.origin || !isShellPath(url.pathname)) return;
  event.preventDefault();
  navigate(url.pathname + url.search);
});

boot().catch((err) => { clear(content).append(h('div', { class: 'alert danger' }, errorMessage(err))); });
