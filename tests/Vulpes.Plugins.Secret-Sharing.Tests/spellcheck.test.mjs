import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

const originalSetTimeout = globalThis.setTimeout;
globalThis.setTimeout = (fn, ms, ...args) => ms === 3500 ? 0 : originalSetTimeout(fn, ms, ...args);
globalThis.document = {
  addEventListener() {},
  createElement() { return { remove() {} }; },
  head: { append() {} },
  querySelector() { return { remove() {} }; },
};
globalThis.window = globalThis;
globalThis.VulpesCrypto = { ready() { return Promise.resolve(); } };
globalThis.SecretUdk = { ready() { return Promise.resolve(); } };
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

function assertSpellcheckOff(node, label) {
  assert.ok(node, label);
  assert.equal(typeof node.props.spellcheck, 'boolean', label);
  assert.equal(node.props.spellcheck, false, label);
}

const { mount: mountSettings } = await import('../../src/Vulpes.Plugins.Secret-Sharing/wwwroot/js/settings.js');

const sendSource = readFileSync(new URL('../../src/Vulpes.Plugins.Secret-Sharing/wwwroot/js/send.js', import.meta.url), 'utf8')
  .replace(/import \{ requireUserDataKey \} from '[^']+';/, 'const requireUserDataKey = () => Promise.resolve();')
  .replace(/import \{ sendLinkNote \} from '[^']+';/, 'const sendLinkNote = () => "";');
const { mount: mountSend } = await import('data:text/javascript,' + encodeURIComponent(sendSource));

test('secret fields pass spellcheck as boolean false', async () => {
  const root = element('div');
  const ctx = {
    plugin: { apiBase: '/api/plugins/secret-sharing' },
    api: { get: async () => ({ ipRestrictionsEnabled: true }) },
    ui: {
      h,
      dropdown(_choices, opts) { return element('select', opts); },
      filePicker() {
        const input = element('input', { type: 'file' });
        const row = element('div');
        row.querySelector = () => input;
        return row;
      },
      copyToClipboard() {},
    },
  };
  await mountSend({ querySelector: (sel) => sel === '#send-root' ? root : null }, ctx);
  assertSpellcheckOff(find(root, (node) => node.tag === 'textarea' && String(node.props.placeholder || '').includes('Paste token')), 'secret text');
  assertSpellcheckOff(find(root, (node) => node.tag === 'textarea' && String(node.props.placeholder || '').includes('Only you see this')), 'private note');
  assertSpellcheckOff(find(root, (node) => node.tag === 'input' && String(node.props.placeholder || '').includes('203.0.113.10')), 'allowed cidr');
  walk(root, (node) => {
    if (node.props && Object.prototype.hasOwnProperty.call(node.props, 'spellcheck')) assertSpellcheckOff(node, node.tag);
  });
});

test('the collect retrieval allow-list passes spellcheck as boolean false', async () => {
  const root = element('div');
  const ctx = {
    hasRole: () => true,
    plugin: { apiBase: '/api/plugins/secret-sharing' },
    api: {
      get: async (url) => {
        if (url.endsWith('/notifications')) return { canCollect: false, notifyCollectReady: false, notifySendOpened: false, mailConfigured: true, email: 'owner@example.com' };
        if (url.endsWith('/collect-retrieve-ips')) return { allowedIps: '', publicAddressVisible: true };
        if (url.endsWith('/capability')) return { ipRestrictionsEnabled: true };
        throw new Error(url);
      },
      put: async () => ({}),
    },
    ui: { h, panelNote() {} },
  };
  await mountSettings({ querySelector: (sel) => sel === '#settings-root' ? root : null }, ctx);
  assertSpellcheckOff(find(root, (node) => node.tag === 'textarea'), 'allow-list');
});
