import { h, badge, fmt, modal, errorMessage, clear, kv, pageNote, setBusy } from '../ui.js?v=shell84';

let root;
let renderToken = 0;
export async function mount(el, ctx) { root = el; ctx.setTitle(['Plugins']); await render(ctx); }
export function unmount() { renderToken += 1; root = null; }

function dedupeReleases(offers) {
  const chosen = new Map();
  for (const offer of offers || []) {
    const key = releaseKey(offer);
    const existing = chosen.get(key);
    if (!existing || preferRelease(offer, existing)) chosen.set(key, offer);
  }
  return [...chosen.values()];
}

function releaseKey(offer) {
  if (offer.pluginId) return String(offer.pluginId).toLowerCase();
  let name = String(offer.asset || offer.name || '').toLowerCase();
  if (name.endsWith('.7z')) name = name.slice(0, -3);
  const tokens = name.replaceAll('.', '-').replaceAll('_', '-').split('-').filter(Boolean);
  if (tokens[0] === 'vulpes' && tokens[1] === 'plugins') tokens.splice(0, 2);
  return tokens.join('-');
}

function preferRelease(offer, existing) {
  const offerPrivate = offer.source === 'private';
  const existingPrivate = existing.source === 'private';
  if (offerPrivate !== existingPrivate) return offerPrivate;
  return false;
}

async function render(ctx) {
  const token = ++renderToken;
  const data = await ctx.api.get('/api/admin/plugins');
  if (token !== renderToken || !root) return;
  clear(root);
  const plugins = dedupePlugins(data.plugins);
  // Releases of techfox-au/vulpes-plugins. Each offer's action is install, upgrade, reinstall, or current.
  const restartButton = data.restartRequired
    ? h('button', { class: 'btn danger', onClick: (event) => restart(ctx, event.currentTarget) }, 'Restart to apply')
    : null;
  root.append(h('div', { class: 'page-header' },
    h('h1', null, 'Plugins'),
    h('div', { class: 'btn-group' }, restartButton)));

  if (data.restartRequired) root.append(h('div', { class: 'alert warning' }, 'The plugin set on disk has changed. Restart the dashboard to load the new set.'));
  if (data.failures.length > 0) {
    const failures = data.failures.map((f) => {
      const repair = dedupeReleases(data.available || []).find((offer) => offer.pluginId === f.id && (offer.action === 'reinstall' || offer.action === 'upgrade'));
      return h('div', { class: 'alert danger flex between' },
        h('div', { class: 'grow' },
          badge(f.unhealthy ? 'unhealthy' : 'failed', 'danger', true),
          ' ',
          h('strong', null, f.id || f.directory),
          '. ',
          f.error),
        repair ? h('button', {
          class: 'btn sm',
          dataset: { pluginAction: repair.action, asset: repair.asset },
          onClick: (event) => install(ctx, repair, event.currentTarget),
        }, repair.action === 'upgrade' ? 'Upgrade' : 'Reinstall') : null);
    });
    root.append(h('div', { class: 'card' }, h('h2', null, 'Failed to load'), h('div', { class: 'col' }, failures)));
  }

  const grid = h('div', { class: 'grid' });
  for (const m of plugins) {
    grid.append(h('div', { class: 'card' },
      h('div', { class: 'card-header' }, h('h2', null, m.name), badge('v' + m.version)),
      // Description and requirements stay in plugin.json; they are not shown here.
      kv([
        ['ID', m.id], ['Entry assembly', m.entryAssembly], ['SDK', m.sdkVersion],
        ['Installed', m.installed ? `${fmt.dateTime(m.installed.installedAt)}${m.installed.source && m.installed.source !== 'private' ? ' from ' + m.installed.source : ''}${m.installed.installedBy ? ' by ' + m.installed.installedBy : ''}` : 'unknown'],
        ['HMAC-SHA512', m.installed && m.installed.packageHmac ? h('code', { class: 'hmac' }, m.installed.packageHmac) : null],
        ['Pages', m.pages.map((p) => p.title).join(', ')],
      ]),

      h('div', { class: 'btn-group mt' },
        h('a', { class: 'btn sm', href: `/p/${m.id}/${m.pages[0]?.page || ''}` }, 'Open'),
        h('button', { class: 'btn sm danger', dataset: { pluginAction: 'uninstall', pluginId: m.id }, onClick: (event) => uninstall(ctx, m.id, event.currentTarget) }, 'Uninstall'))));
  }
  if (plugins.length === 0) grid.append(h('div', { class: 'card muted' }, 'No plugins loaded.'));
  root.append(grid);

  root.append(h('h2', { class: 'mt' }, 'Available plugins'));
  if (data.catalogError) root.append(h('div', { class: 'alert warning' }, data.catalogError));
  const releases = dedupeReleases(data.available || [])
    .filter((offer) => offer.action === 'upgrade' || offer.action === 'reinstall' || offer.action === 'install' || !offer.action)
    .sort((a, b) => actionRank(a.action) - actionRank(b.action) || a.name.localeCompare(b.name));
  const offers = h('div', { class: 'grid cols-2' });
  for (const offer of releases) {
    const action = offer.action === 'upgrade' ? 'upgrade' : offer.action === 'reinstall' ? 'reinstall' : 'install';
    offers.append(h('div', { class: 'card' },
      h('div', { class: 'card-header' }, h('h2', null, offer.name), offer.version ? badge(versionLabel(offer.version)) : null),
      offer.description ? h('p', null, offer.description) : null,
      h('p', { class: 'muted small' }, fmt.bytes(offer.size)),
      h('button', {
        class: 'btn sm primary',
        dataset: { pluginAction: action, asset: offer.asset },
        onClick: (event) => install(ctx, offer, event.currentTarget),
      }, action === 'upgrade' ? 'Upgrade' : action === 'reinstall' ? 'Reinstall' : 'Install')));
  }
  if (!data.catalogError && releases.length === 0) offers.append(h('div', { class: 'card muted' }, (data.available || []).length === 0 ? 'No plugins available.' : 'No updates or new plugins.'));
  const refreshButton = h('button', { class: 'btn', onClick: (event) => refreshCatalog(ctx, event.currentTarget) }, 'Refresh');
  root.append(offers, h('div', { class: 'btn-group mt' }, refreshButton));
  if (!data.catalogFetchedAt) refreshCatalog(ctx, refreshButton);
}

function dedupePlugins(items) {
  const seen = new Set();
  const unique = [];
  for (const item of items || []) {
    if (seen.has(item.id)) continue;
    seen.add(item.id);
    unique.push(item);
  }
  return unique;
}

function versionLabel(version) {
  return /^\d+\.\d+\.\d+/.test(version) ? 'v' + version : version;
}

function actionRank(action) {
  return action === 'reinstall' ? 0 : action === 'upgrade' ? 1 : 2;
}

async function refreshCatalog(ctx, button) {
  if (button?.disabled) return;
  if (button) setBusy(button, true, 'Refresh');
  try {
    await ctx.api.post('/api/admin/plugins/catalog/refresh');
    await render(ctx);
  } catch (err) {
    if (button && button.isConnected) setBusy(button, false);
    pageNote(root, errorMessage(err));
  }
}

async function install(ctx, offer, button) {
  if (button?.disabled) return;
  if (button) setBusy(button, true);
  try {
    const res = await ctx.api.post('/api/admin/plugins/install', { asset: offer.asset, source: offer.source || 'public' });
    await render(ctx);
    const verb = offer.action === 'upgrade' ? 'Upgraded' : offer.action === 'reinstall' ? 'Reinstalled' : 'Installed';
    pageNote(root, `${verb} ${res.installed.id} ${res.installed.version}. Restart to load it.`, 'success');
  } catch (err) {
    if (button && button.isConnected) setBusy(button, false);
    pageNote(root, errorMessage(err));
  }
}

async function uninstall(ctx, id, button) {
  const purge = h('input', { type: 'checkbox' });
  const confirmed = await modal.show({ title: `Uninstall ${id}`, content: h('div', { class: 'col' }, h('p', null, 'The plugin package is moved to the trash folder and no longer loaded after a restart.'), h('label', { class: 'checkbox' }, purge, h('span', null, 'Also delete the plugin\'s data (database, checkpoints, credentials)'))), actions: [{ label: 'Cancel', value: false }, { label: 'Uninstall', kind: 'danger', value: true }] });
  if (!confirmed) return;
  if (button?.disabled) return;
  if (button) setBusy(button, true);
  try {
    await ctx.api.delete(`/api/admin/plugins/${encodeURIComponent(id)}?purge=${purge.checked}`);
    await render(ctx);
    pageNote(root, 'Uninstalled. Restart to apply.', 'success');
  } catch (err) {
    if (button && button.isConnected) setBusy(button, false);
    pageNote(root, errorMessage(err));
  }
}

async function restart(ctx, button) {
  if (!(await modal.confirm('Restart dashboard', 'The process stops gracefully and the container runtime restarts it. Users may see a brief interruption.', { danger: true, confirmLabel: 'Restart' }))) return;
  if (button) setBusy(button, true, 'Restarting…');
  try { await ctx.api.post('/api/admin/restart'); pageNote(root, 'Restarting… this page will reload shortly.', 'success'); setTimeout(() => location.reload(), 8000); }
  catch (err) {
    if (button) setBusy(button, false);
    pageNote(root, errorMessage(err));
  }
}
