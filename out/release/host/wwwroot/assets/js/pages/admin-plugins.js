import { h, badge, fmt, modal, errorMessage, clear, kv, pageNote } from '../ui.js?v=shell84';

let root;
export async function mount(el, ctx) { root = el; ctx.setTitle(['Plugins']); await render(ctx); }
export function unmount() { root = null; }

async function render(ctx) {
  clear(root);
  const data = await ctx.api.get('/api/admin/plugins');
  // Releases of techfox-au/vulpes-plugins. Each offer's action is install, upgrade, reinstall, or current.
  root.append(h('div', { class: 'page-header' },
    h('h1', null, 'Plugins'),
    h('div', { class: 'btn-group' },
      data.restartRequired ? h('button', { class: 'btn danger', onClick: () => restart(ctx) }, 'Restart to apply') : null)));

  if (data.restartRequired) root.append(h('div', { class: 'alert warning' }, 'The plugin set on disk has changed. Restart the dashboard to load the new set.'));
  if (data.failures.length > 0) {
    const failures = data.failures.map((f) => {
      const repair = (data.available || []).find((offer) => offer.pluginId === f.id && (offer.action === 'reinstall' || offer.action === 'upgrade'));
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
          onClick: () => install(ctx, repair),
        }, repair.action === 'upgrade' ? 'Upgrade' : 'Reinstall') : null);
    });
    root.append(h('div', { class: 'card' }, h('h2', null, 'Failed to load'), h('div', { class: 'col' }, failures)));
  }

  const grid = h('div', { class: 'grid' });
  for (const m of data.plugins) {
    grid.append(h('div', { class: 'card' },
      h('div', { class: 'card-header' }, h('h2', null, m.name), badge('v' + m.version)),
      // Description and requirements stay in plugin.json; they are not shown here.
      kv([
        ['ID', m.id], ['Entry assembly', m.entryAssembly], ['SDK', m.sdkVersion],
        ['Installed', m.installed ? `${fmt.dateTime(m.installed.installedAt)} from ${m.installed.source}${m.installed.installedBy ? ' by ' + m.installed.installedBy : ''}` : 'unknown'],
        ['HMAC-SHA512', m.installed && m.installed.packageHmac ? h('code', { class: 'hmac' }, m.installed.packageHmac) : null],
        ['Pages', m.pages.map((p) => p.title).join(', ')],
      ]),

      h('div', { class: 'btn-group mt' },
        h('a', { class: 'btn sm', href: `#/p/${m.id}/${m.pages[0]?.page || ''}` }, 'Open'),
        h('button', { class: 'btn sm danger', dataset: { pluginAction: 'uninstall', pluginId: m.id }, onClick: () => uninstall(ctx, m.id) }, 'Uninstall'))));
  }
  if (data.plugins.length === 0) grid.append(h('div', { class: 'card muted' }, 'No plugins loaded.'));
  root.append(grid);

  root.append(h('h2', { class: 'mt' }, 'Available releases'));
  if (data.catalogError) root.append(h('div', { class: 'alert warning' }, data.catalogError));
  const releases = (data.available || [])
    .filter((offer) => offer.action === 'upgrade' || offer.action === 'reinstall' || offer.action === 'install' || !offer.action)
    .sort((a, b) => actionRank(a.action) - actionRank(b.action) || a.name.localeCompare(b.name));
  const offers = h('div', { class: 'grid cols-2' });
  for (const offer of releases) {
    const action = offer.action === 'upgrade' ? 'upgrade' : offer.action === 'reinstall' ? 'reinstall' : 'install';
    offers.append(h('div', { class: 'card' },
      h('div', { class: 'card-header' }, h('h2', null, offer.name), offer.version ? badge(versionLabel(offer.version)) : null),
      offer.description ? h('p', null, offer.description) : null,
      h('p', { class: 'muted small' }, `${fmt.bytes(offer.size)}${offer.publishedAt ? ' · ' + fmt.dateTime(offer.publishedAt) : ''}`),
      h('button', {
        class: 'btn sm primary',
        dataset: { pluginAction: action, asset: offer.asset },
        onClick: () => install(ctx, offer),
      }, action === 'upgrade' ? 'Upgrade' : action === 'reinstall' ? 'Reinstall' : 'Install')));
  }
  if (!data.catalogError && releases.length === 0) offers.append(h('div', { class: 'card muted' }, (data.available || []).length === 0 ? 'No plugin releases found.' : 'No updates or new plugins.'));
  root.append(offers);
}

function versionLabel(version) {
  return /^\d+\.\d+\.\d+/.test(version) ? 'v' + version : version;
}

function actionRank(action) {
  return action === 'reinstall' ? 0 : action === 'upgrade' ? 1 : 2;
}

async function install(ctx, offer) {
  try {
    const res = await ctx.api.post('/api/admin/plugins/install', { asset: offer.asset });
    await render(ctx);
    const verb = offer.action === 'upgrade' ? 'Upgraded' : offer.action === 'reinstall' ? 'Reinstalled' : 'Installed';
    pageNote(root, `${verb} ${res.installed.id} ${res.installed.version}. Restart to load it.`, 'success');
  } catch (err) { pageNote(root, errorMessage(err)); }
}

async function uninstall(ctx, id) {
  const purge = h('input', { type: 'checkbox' });
  const confirmed = await modal.show({ title: `Uninstall ${id}`, content: h('div', { class: 'col' }, h('p', null, 'The plugin package is moved to the trash folder and no longer loaded after a restart.'), h('label', { class: 'checkbox' }, purge, h('span', null, 'Also delete the plugin\'s data (database, checkpoints, credentials)'))), actions: [{ label: 'Cancel', value: false }, { label: 'Uninstall', kind: 'danger', value: true }] });
  if (!confirmed) return;
  try { await ctx.api.delete(`/api/admin/plugins/${encodeURIComponent(id)}?purge=${purge.checked}`); await render(ctx); pageNote(root, 'Uninstalled. Restart to apply.', 'success'); }
  catch (err) { pageNote(root, errorMessage(err)); }
}

async function restart(ctx) {
  if (!(await modal.confirm('Restart dashboard', 'The process stops gracefully and the container runtime restarts it. Users may see a brief interruption.', { danger: true, confirmLabel: 'Restart' }))) return;
  try { await ctx.api.post('/api/admin/restart'); pageNote(root, 'Restarting… this page will reload shortly.', 'success'); setTimeout(() => location.reload(), 8000); }
  catch (err) { pageNote(root, errorMessage(err)); }
}
