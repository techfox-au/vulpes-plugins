import { h, badge, fmt, modal, errorMessage, clear, kv, pageNote } from '../ui.js?v=shell84';

let root;
export async function mount(el, ctx) { root = el; ctx.setTitle(['Plugins']); await render(ctx); }
export function unmount() { root = null; }

async function render(ctx) {
  clear(root);
  const data = await ctx.api.get('/api/admin/modules');
  // Releases of techfox-au/vulpes-plugins, verified by files.sha256, applied after restart (docs/plugins.md).
  root.append(h('div', { class: 'page-header' },
    h('h1', null, 'Plugins'),
    h('div', { class: 'btn-group' },
      data.restartRequired ? h('button', { class: 'btn danger', onClick: () => restart(ctx) }, 'Restart to apply') : null)));

  if (data.restartRequired) root.append(h('div', { class: 'alert warning' }, 'The plugin set on disk has changed. Restart the dashboard to load the new set.'));
  if (data.failures.length > 0) {
    root.append(h('div', { class: 'card' }, h('h2', null, 'Failed to load'), ...data.failures.map((f) => h('div', { class: 'alert danger' }, h('strong', null, f.id || f.directory), ': ', f.error))));
  }

  const grid = h('div', { class: 'grid cols-2' });
  for (const m of data.modules) {
    grid.append(h('div', { class: 'card' },
      h('div', { class: 'card-header' }, h('h2', null, m.name), badge('v' + m.version)),
      // Description and requirements stay in plugin.json; they are not shown here.
      kv([
        ['Id', m.id], ['Entry assembly', m.entryAssembly], ['SDK', m.sdkVersion],
        ['Installed', m.installed ? `${fmt.dateTime(m.installed.installedAt)} from ${m.installed.source}${m.installed.installedBy ? ' by ' + m.installed.installedBy : ''}` : 'unknown'],
        ['Package SHA-256', m.installed ? h('code', { class: 'small' }, m.installed.packageSha256) : null],
        ['Signed', m.installed ? (m.installed.isSigned ? 'Yes' : 'No') : null],
        ['Pages', m.pages.map((p) => p.title).join(', ')],
      ]),

      h('div', { class: 'btn-group mt' },
        h('a', { class: 'btn sm', href: `#/p/${m.id}/${m.pages[0]?.page || ''}` }, 'Open'),
        h('button', { class: 'btn sm danger', onClick: () => uninstall(ctx, m.id) }, 'Uninstall'))));
  }
  if (data.modules.length === 0) grid.append(h('div', { class: 'card muted' }, 'No plugins loaded.'));
  root.append(grid);

  root.append(h('h2', { class: 'mt' }, 'Available releases'));
  if (data.catalogError) root.append(h('div', { class: 'alert warning' }, data.catalogError));
  const offers = h('div', { class: 'grid cols-2' });
  for (const offer of data.available || []) {
    const already = data.modules.some((m) => m.installed && (m.installed.version === offer.version || offer.name.startsWith(m.id + '-')));
    offers.append(h('div', { class: 'card' },
      h('div', { class: 'card-header' }, h('h2', null, offer.name), badge(offer.version)),
      h('p', { class: 'muted small' }, `${fmt.bytes(offer.size)}${offer.publishedAt ? ' · ' + fmt.dateTime(offer.publishedAt) : ''}`),
      already ? h('p', { class: 'small' }, 'Installed') : h('button', { class: 'btn sm primary', onClick: () => install(ctx, offer) }, 'Install')));
  }
  if (!data.catalogError && (data.available || []).length === 0) offers.append(h('div', { class: 'card muted' }, 'No plugin releases found.'));
  root.append(offers);
  root.append(h('p', { class: 'small faint' }, `Host SDK ${data.sdkVersion} · max package size ${fmt.bytes(data.maxPackageBytes)}`));
}

async function install(ctx, offer) {
  try {
    const res = await ctx.api.post('/api/admin/modules/install', { asset: offer.asset });
    await render(ctx);
    pageNote(root, `Installed ${res.installed.id} ${res.installed.version}. Restart to load it.`, 'success');
  } catch (err) { pageNote(root, errorMessage(err)); }
}

async function uninstall(ctx, id) {
  const purge = h('input', { type: 'checkbox' });
  const confirmed = await modal.show({ title: `Uninstall ${id}`, content: h('div', { class: 'col' }, h('p', null, 'The plugin package is moved to the trash folder and no longer loaded after a restart.'), h('label', { class: 'checkbox' }, purge, h('span', null, 'Also delete the plugin\'s data (database, checkpoints, credentials)'))), actions: [{ label: 'Cancel', value: false }, { label: 'Uninstall', kind: 'danger', value: true }] });
  if (!confirmed) return;
  try { await ctx.api.delete(`/api/admin/modules/${encodeURIComponent(id)}?purge=${purge.checked}`); await render(ctx); pageNote(root, 'Uninstalled. Restart to apply.', 'success'); }
  catch (err) { pageNote(root, errorMessage(err)); }
}

async function restart(ctx) {
  if (!(await modal.confirm('Restart dashboard', 'The process stops gracefully and the container runtime restarts it. Users may see a brief interruption.', { danger: true, confirmLabel: 'Restart' }))) return;
  try { await ctx.api.post('/api/admin/restart'); pageNote(root, 'Restarting… this page will reload shortly.', 'success'); setTimeout(() => location.reload(), 8000); }
  catch (err) { pageNote(root, errorMessage(err)); }
}
