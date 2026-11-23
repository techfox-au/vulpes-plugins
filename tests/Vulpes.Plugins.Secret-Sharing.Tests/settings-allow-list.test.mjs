import assert from 'node:assert/strict';
import test from 'node:test';

const originalSetTimeout = globalThis.setTimeout;
globalThis.setTimeout = (fn, ms, ...args) => ms === 3500 ? 0 : originalSetTimeout(fn, ms, ...args);
globalThis.document = { addEventListener() {}, createElement() { return {}; }, head: { append() {} } };
globalThis.window = globalThis;
globalThis.SecretCidr = {
  parseAllowedCidr(input) {
    const text = String(input).trim();
    return text ? { ok: true, value: text } : { ok: true, value: null };
  },
};

function element(tag, props, children) {
  const node = {
    tag,
    props: props || {},
    children: children || [],
    disabled: false,
    hidden: !!(props && props.hidden),
    value: props && props.value != null ? props.value : '',
    checked: !!(props && props.checked),
    listeners: {},
    classList: { add() {}, remove() {} },
  };
  node.append = (...items) => { node.children.push(...items); };
  node.addEventListener = (type, fn) => { node.listeners[type] = fn; };
  node.querySelector = () => null;
  return node;
}

function h(tag, props, ...children) {
  return element(tag, props, children.flat());
}

function walk(node, visit) {
  if (!node || typeof node !== 'object') return;
  visit(node);
  for (const child of node.children || []) walk(child, visit);
}

function find(root, match) {
  let found = null;
  walk(root, (node) => { if (!found && match(node)) found = node; });
  return found;
}

const { mount } = await import('../../src/Vulpes.Plugins.Secret-Sharing/wwwroot/js/settings.js');

function page(initial, put) {
  const settingsRoot = element('div');
  const notes = [];
  const ctx = {
    hasRole: () => true,
    plugin: { apiBase: '/api/plugins/secret-sharing' },
    api: {
      get: async (url) => {
        if (url.endsWith('/notifications')) return { canCollect: true, notifyCollectReady: false, notifySendOpened: false, mailConfigured: true, email: 'owner@example.com' };
        if (url.endsWith('/collect-retrieve-ips')) return { allowedIps: initial, publicAddressVisible: true };
        if (url.endsWith('/capability')) return { ipRestrictionsEnabled: true };
        throw new Error(url);
      },
      put,
    },
    ui: {
      h,
      panelNote(_note, message) { notes.push(message || ''); },
    },
  };
  return { settingsRoot, notes, ctx, el: { querySelector: (sel) => sel === '#settings-root' ? settingsRoot : null } };
}

test('an enabled notification can be turned off when mail is not configured', async () => {
  const view = page('198.51.100.0/24', async () => ({ notifyCollectReady: false, notifySendOpened: false }));
  view.ctx.api.get = async (url) => {
    if (url.endsWith('/notifications')) return { canCollect: true, notifyCollectReady: true, notifySendOpened: true, mailConfigured: false, email: '' };
    if (url.endsWith('/collect-retrieve-ips')) return { allowedIps: '', publicAddressVisible: false };
    if (url.endsWith('/capability')) return { ipRestrictionsEnabled: false };
    throw new Error(url);
  };
  await mount(view.el, view.ctx);
  const boxes = [];
  walk(view.settingsRoot, (node) => { if (node.tag === 'input' && node.props.type === 'checkbox') boxes.push(node); });
  assert.equal(boxes.length, 2);
  assert.equal(boxes.every((box) => box.disabled), false);
  boxes.forEach((box) => { box.checked = false; });
});

test('a collect retrieval save keeps a newer edit in the box', async () => {
  let release;
  const pending = new Promise((resolve) => { release = resolve; });
  const view = page('198.51.100.0/24', () => pending);
  await mount(view.el, view.ctx);
  const box = find(view.settingsRoot, (node) => node.tag === 'textarea');
  const save = find(view.settingsRoot, (node) => node.tag === 'button' && node.children.includes('Save'));
  assert.equal(box.value, '198.51.100.0/24');

  const click = save.listeners.click();
  assert.equal(box.disabled, true);
  box.value = '198.51.100.0/24, 203.0.113.10';
  release({ allowedIps: '198.51.100.0/24' });
  await click;

  assert.equal(box.value, '198.51.100.0/24, 203.0.113.10');
  assert.equal(box.disabled, false);
  assert.equal(view.notes.at(-1), 'Saved. Save again to keep the newer list in this box.');
});

test('a collect retrieval save shows the stored list when the box is unchanged', async () => {
  let release;
  const pending = new Promise((resolve) => { release = resolve; });
  const view = page('198.51.100.1/24', () => pending);
  await mount(view.el, view.ctx);
  const box = find(view.settingsRoot, (node) => node.tag === 'textarea');
  const save = find(view.settingsRoot, (node) => node.tag === 'button' && node.children.includes('Save'));
  const click = save.listeners.click();
  release({ allowedIps: '198.51.100.0/24' });
  await click;
  assert.equal(box.value, '198.51.100.0/24');
  assert.equal(view.notes.at(-1), 'Saved.');
  assert.equal(box.disabled, false);
});
