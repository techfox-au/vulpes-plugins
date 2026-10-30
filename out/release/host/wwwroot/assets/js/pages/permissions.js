import { h, clear, errorMessage, badge, setBusy } from '../ui.js?v=shell84';

let root;
export async function mount(el, ctx) {
  root = el;
  ctx.setTitle(['Permissions diagnostic']);
  await render(ctx);
}
export function unmount() { root = null; }

async function render(ctx) {
  clear(root);
  const header = h('div', { class: 'page-header' }, h('h1', null, 'Permissions diagnostic'));
  const button = h('button', { class: 'btn', onClick: () => load(ctx, button) }, 'Check again');
  header.append(button);
  root.append(header);
  await load(ctx, button);
}

async function load(ctx, button) {
  const host = root.querySelector('[data-role="results"]') || h('div', { dataset: { role: 'results' } });
  if (!host.parentNode) root.append(host);
  clear(host);
  setBusy(button, true, 'Checking…');
  try {
    const data = await ctx.api.get(`/api/plugins/${ctx.plugin.id}/permissions`);
    if (!data.configured) {
      host.append(h('div', { class: 'alert danger' }, 'The Entra application is not configured. Save it under Manage → Tenants.'));
      return;
    }
    if (!data.tenants?.length) {
      host.append(h('div', { class: 'card muted' }, 'No clients added yet.'));
      return;
    }
    for (const tenant of data.tenants) {
      const missing = tenant.missing || [];
      host.append(h('div', { class: 'card' },
        h('div', { class: 'card-header' }, h('h2', null, tenant.displayName), tenant.enabled ? null : badge('disabled', 'warning')),
        h('p', { class: 'mono small muted' }, tenant.directoryId),
        tenant.error ? h('div', { class: 'alert danger' }, tenant.error) : null,
        !tenant.error && missing.length === 0 ? h('div', null, badge('All required permissions granted', 'success')) : null,
        missing.length ? h('div', { class: 'col' }, h('div', { class: 'small muted' }, 'Missing'), ...missing.map((p) => h('div', null, h('span', { class: 'mono' }, p.name), h('span', { class: 'small muted' }, ' ' + p.purpose)))) : null));
    }
  } catch (err) {
    host.append(h('div', { class: 'alert danger' }, errorMessage(err)));
  } finally {
    setBusy(button, false);
  }
}
