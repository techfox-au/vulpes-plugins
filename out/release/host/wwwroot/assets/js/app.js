// Application shell: session bootstrap, navigation, hash router, plugin page host.
import { api, session, invalidateSession, redirectToLogin } from './api.js';
import { h, clear, icon, errorMessage, ui } from './ui.js?v=shell161';

const content = document.getElementById('content');
const navEl = document.getElementById('nav');
let state = { user: null, app: null, nav: null };
let current = null; // { unmount, key }

const corePages = {
  '/': () => import('./pages/home.js?v=shell155'),
  '/account': () => import('./pages/account.js?v=shell133'),
  '/alerts': () => import('./pages/alerts.js?v=shell101'),
  '/admin/users': () => import('./pages/admin-users.js?v=shell127'),
  '/admin/plugins': () => import('./pages/admin-plugins.js?v=shell156'),
  '/admin/tenants': () => import('./pages/admin-tenants.js?v=shell161'),
  '/admin/settings': () => import('./pages/admin-settings.js?v=shell164'),
  '/admin/audit': () => import('./pages/admin-audit.js?v=shell144'),
};

function parseHash() {
  const raw = location.hash.startsWith('#') ? location.hash.slice(1) : location.hash;
  const [pathPart, queryPart] = raw.split('?');
  const path = pathPart && pathPart.startsWith('/') ? pathPart : '/';
  const query = Object.fromEntries(new URLSearchParams(queryPart || ''));
  return { path, query };
}

function isHomeLink(href, path) {
  return path === '/' && (href === '/' || href === '#/' || href === '#');
}

export function navigate(path) {
  const target = path.startsWith('#') ? path.slice(1) : path;
  if (target === '' || target === '/') {
    if (location.pathname !== '/' || location.hash) history.pushState(null, '', '/');
    route();
    return;
  }
  location.hash = target.startsWith('/') ? '#' + target : '#/' + target;
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
  const { path } = parseHash();
  const open = openPlugin() || '';
  navSections().forEach((section, index) => {
    const plugin = pluginId(section);
    const isCollapsed = plugin !== '' && plugin !== open;
    const sec = h('div', {
      class: 'nav-section' + (isCollapsed ? ' collapsed' : ''),
      dataset: plugin ? { section: section.title, plugin } : { section: section.title },
    });
    if (plugin) {
      sec.append(h('button', {
        class: 'title', type: 'button',
        'aria-expanded': isCollapsed ? 'false' : 'true',
        'aria-controls': `nav-items-${index}`,
        onClick: () => {
          const stored = openPlugin();
          const effective = stored == null ? open : stored;
          const next = effective === plugin ? '' : plugin;
          saveOpenPlugin(next);
          applyOpenPlugin(next);
        },
      }, section.title));
    } else {
      sec.append(h('div', { class: 'title' }, section.title));
    }
    const items = h('div', { class: 'nav-items', id: `nav-items-${index}` });
    for (const item of section.items) {
      const disabled = item.disabled === true;
      const active = !disabled && (isHomeLink(item.href, path) || item.href === '#' + path);
      const label = [icon(item.icon || 'dot'), h('span', { class: 'truncate' }, item.title)];
      items.append(disabled
        ? h('span', { class: 'nav-link disabled', 'aria-disabled': 'true', title: 'Disabled in Microsoft 365 Business Premium mode' }, ...label)
        : h('a', { class: 'nav-link' + (active ? ' active' : ''), href: item.href, dataset: { navId: item.id } }, ...label));
    }
    sec.append(items);
    navEl.append(sec);
  });
}

function setActiveNav(path) {
  let activePlugin = '';
  for (const link of navEl.querySelectorAll('.nav-link')) {
    const href = link.getAttribute('href');
    const active = isHomeLink(href, path) || href === '#' + path;
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
  let riskOff = false;
  try {
    const sources = await api.get('/api/plugins/microsoft-365-audit/sources');
    riskOff = sources.some((s) => s.source === 'risk' && s.unavailable);
  } catch { /* the plugin is not loaded */ }
  for (const section of state.nav?.sections || []) {
    for (const item of section.items) {
      if (item.pluginId === 'microsoft-365-audit' && item.page === 'risk') item.disabled = riskOff;
    }
  }
}

function pageContext(params, query, pluginId) {
  return {
    api, ui, user: state.user, app: state.app, navigate, params, query,
    refreshNav: async () => { await applyBusinessPremiumNav(); renderNav(); },
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

  const res = await fetch(`/plugins/${pluginId}/pages/${page}.html?v=shell48`, { credentials: 'same-origin' });
  if (!res.ok) throw new Error(`Page not found (${res.status})`);
  const html = await res.text();
  // Fragments are trusted plugin content served from our own origin under CSP (no inline script can run).
  const template = document.createElement('template');
  template.innerHTML = html;
  el.append(template.content);

  const mod = await import(`/plugins/${pluginId}/js/${page}.js?v=shell163`);
  await mod.mount(el, pageContext({ plugin: pluginId, page }, query, pluginId));
  current = { unmount: mod.unmount, key: `${pluginId}/${page}` };
}

async function route() {
  const token = ++routeToken;
  const stale = () => token !== routeToken;
  const raw = location.hash.startsWith('#') ? location.hash.slice(1) : '';
  if (raw === '' || raw === '/' || raw.startsWith('/?')) {
    if (location.hash || location.pathname !== '/') history.replaceState(null, '', '/' + (raw.startsWith('/?') ? '?' + raw.slice(2) : ''));
  }
  if (raw === '/m/audit' || raw.startsWith('/m/audit/') || raw.startsWith('/m/audit?')) {
    location.replace('#' + '/p/microsoft-365-audit' + raw.slice('/m/audit'.length));
    return;
  }
  if (raw === '/m' || raw.startsWith('/m/') || raw.startsWith('/m?')) {
    location.replace('#' + '/p' + raw.slice(2));
    return;
  }
  const { path, query } = parseHash();
  if (state.nav?.sections?.some((section) => section.items.some((item) => item.disabled && item.href === '#' + path))) {
    location.hash = '#/p/microsoft-365-audit/overview';
    return;
  }
  if (state.user?.mustChangePassword && path !== '/account') {
    location.hash = '#/account?changePassword=1';
    return;
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

function renderChrome() {
  const chip = document.getElementById('user-chip');
  clear(chip).append(h('span', { class: 'avatar' }, (state.user.displayName || state.user.username || '?').slice(0, 2).toUpperCase()), h('span', { class: 'truncate' }, state.user.displayName || state.user.username));
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
  window.addEventListener('hashchange', route);
  if (state.user.mustChangePassword && !location.hash.startsWith('#/account')) {
    location.hash = '#/account?changePassword=1';
  } else {
    await route();
  }
}

boot().catch((err) => { clear(content).append(h('div', { class: 'alert danger' }, errorMessage(err))); });
