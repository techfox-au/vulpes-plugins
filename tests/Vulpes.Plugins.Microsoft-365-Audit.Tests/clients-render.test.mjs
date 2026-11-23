import assert from 'node:assert/strict';
import test from 'node:test';

function element(tag, props, children) {
  const node = {
    tag,
    props: props || {},
    children: children || [],
    disabled: !!(props && props.disabled),
    value: props && props.value != null ? props.value : '',
    checked: !!(props && props.checked),
    listeners: {},
    classList: { add() {} },
    notes: [],
  };
  node.append = (...items) => { node.children.push(...items); };
  node.querySelector = (sel) => (sel === '#clients-root' ? node : null);
  if (props && typeof props.onClick === 'function') node.listeners.click = props.onClick;
  return node;
}

function h(tag, props, ...children) {
  return element(tag, props, children.flat().filter((child) => child != null && child !== false));
}

function walk(node, visit) {
  if (!node || typeof node !== 'object') return;
  visit(node);
  for (const child of node.children || []) walk(child, visit);
}

function labeled(root, tag, text) {
  const found = [];
  walk(root, (node) => {
    if (node.tag === tag && (node.children || []).includes(text)) found.push(node);
  });
  return found;
}

function deferred() {
  let resolve;
  let reject;
  const promise = new Promise((ok, fail) => { resolve = ok; reject = fail; });
  return { promise, resolve, reject };
}

function tenant() {
  return { id: 'c1', displayName: 'Contoso', directoryId: '11111111-1111-1111-1111-111111111111', enabled: true, disabled: false };
}

function ready(rows) {
  return { application: { clientId: 'app', credentialType: 'secret', hasSecret: true }, tenants: rows };
}

const { mount, unmount } = await import('../../src/Vulpes.Plugins.Microsoft-365-Audit/wwwroot/js/clients.js');

test('client loads stay one list, and a failed purge remains after save', async () => {
  const notes = [];
  const gets = [];
  let lastForm = null;
  const ui = {
    h,
    clear(node) { if (node) node.children = []; },
    table({ columns, rows }) {
      const body = element('tbody');
      for (const row of rows || []) {
        for (const column of columns) {
          const cell = column.render ? column.render(row) : null;
          if (cell) body.append(cell);
        }
      }
      return body;
    },
    badge: (text) => element('span', {}, [text]),
    errorMessage: (err) => err.message || String(err),
    pageNote(_root, message) { notes.push(message); },
    panelNote(panel, message) { panel.notes.push(message); },
    setBusy() {},
    fmt: { number: (value) => String(value) },
    modal: {
      async confirm() { return true; },
      show({ content, actions }) {
        content.actions = actions;
        lastForm = content;
        return new Promise((resolve) => { content.resolve = resolve; });
      },
    },
  };
  const root = element('div');
  const api = {
    get() {
      const next = gets.shift();
      if (!next) throw new Error('unexpected client list request');
      return next.promise;
    },
    post(url) {
      if (url.endsWith('/purge')) return Promise.reject(new Error('Search is busy.'));
      const next = posts.shift();
      return next ? next.promise : Promise.resolve({});
    },
    put: async () => ({}),
  };
  const posts = [];
  const ctx = { setTitle() {}, api, ui, plugin: { apiBase: '/api/plugins/microsoft-365-audit' } };

  const opened = deferred();
  gets.push(opened);
  const mounted = mount(root, ctx);
  opened.resolve(ready([tenant()]));
  await mounted;
  assert.equal(labeled(root, 'h1', 'Clients').length, 1);

  const testPost = deferred();
  const disablePost = deferred();
  const disableList = deferred();
  const testList = deferred();
  posts.push(testPost, disablePost);
  gets.push(disableList, testList);
  api.post = (url) => {
    if (url.endsWith('/test')) return testPost.promise;
    if (url.endsWith('/disable')) return disablePost.promise;
    if (url.endsWith('/purge')) return Promise.reject(new Error('Search is busy.'));
    return Promise.resolve({});
  };
  const testing = labeled(root, 'button', 'Test')[0].listeners.click({ stopPropagation() {}, currentTarget: element('button') });
  const disabling = labeled(root, 'button', 'Disable')[0].listeners.click({ stopPropagation() {} });
  await Promise.resolve();
  disablePost.resolve({});
  await Promise.resolve();
  testPost.resolve({ reports: [{ tokenAcquired: true, probes: [] }] });
  disableList.resolve(ready([{ ...tenant(), disabled: true }]));
  testList.resolve(ready([tenant()]));
  await Promise.all([testing, disabling]);
  assert.equal(labeled(root, 'h1', 'Clients').length, 1);

  unmount();
  const again = element('div');
  const listed = deferred();
  gets.push(listed);
  const remounted = mount(again, ctx);
  listed.resolve(ready([tenant()]));
  await remounted;
  const editing = labeled(again, 'button', 'Edit')[0].listeners.click({ stopPropagation() {} });
  await Promise.resolve();
  assert.ok(lastForm);
  await labeled(lastForm, 'button', 'Purge & Reset')[0].listeners.click();
  assert.equal(lastForm.notes.at(-1), 'Search is busy.');
  const save = lastForm.actions.find((action) => action.label === 'Save');
  await save.onClick();
  lastForm.resolve(true);
  await editing;
  assert.equal(notes.at(-1), 'Client saved. Purge did not finish. Search is busy.');
});

test('a failed mirror keeps later edits on the next add', async () => {
  unmount();
  const notes = [];
  const calls = [];
  const gets = [];
  let lastForm = null;
  let mirrorFails = true;
  const ui = {
    h,
    clear(node) { if (node) node.children = []; },
    table() { return element('tbody'); },
    badge: (text) => element('span', {}, [text]),
    errorMessage: (err) => err.message || String(err),
    pageNote(_root, message) { notes.push(message); },
    panelNote(panel, message) { panel.notes.push(message); },
    setBusy() {},
    fmt: { number: (value) => String(value) },
    modal: {
      async confirm() { return true; },
      show({ content, actions }) {
        content.actions = actions;
        lastForm = content;
        return new Promise((resolve) => { content.resolve = resolve; });
      },
    },
  };
  const api = {
    get() {
      const next = gets.shift();
      if (!next) throw new Error('unexpected client list request');
      return next.promise;
    },
    post(url, body) {
      calls.push({ method: 'POST', url, body });
      if (String(url).endsWith('/ensure')) {
        return mirrorFails ? Promise.reject(Object.assign(new Error('PSA down'), { status: 500 })) : Promise.resolve({});
      }
      if (url === '/api/admin/tenants') return Promise.resolve({ id: 'new-1' });
      return Promise.resolve({});
    },
    put(url, body) {
      calls.push({ method: 'PUT', url, body });
      return Promise.resolve({});
    },
  };
  const ctx = { setTitle() {}, api, ui, plugin: { apiBase: '/api/plugins/microsoft-365-audit' } };
  const root = element('div');
  const opened = deferred();
  gets.push(opened);
  const mounted = mount(root, ctx);
  opened.resolve(ready([]));
  await mounted;
  const adding = labeled(root, 'button', 'Add client')[0].listeners.click();
  await Promise.resolve();
  const fields = [];
  walk(lastForm, (node) => { if (node.tag === 'input' && node.props.type !== 'checkbox') fields.push(node); });
  fields[0].value = 'First name';
  fields[2].value = '11111111-1111-1111-1111-111111111111';
  const listed = deferred();
  listed.resolve(ready([]));
  gets.push(listed);
  const add = lastForm.actions.find((action) => action.label === 'Add');
  assert.equal(await add.onClick(), false);
  assert.equal(calls.filter((call) => call.method === 'PUT').length, 0);

  fields[0].value = 'Corrected name';
  fields[2].value = '22222222-2222-2222-2222-222222222222';
  mirrorFails = false;
  assert.notEqual(await add.onClick(), false);
  const saved = calls.filter((call) => call.method === 'PUT');
  assert.equal(saved.length, 1);
  assert.equal(saved[0].url, '/api/admin/tenants/new-1');
  assert.equal(saved[0].body.displayName, 'Corrected name');
  assert.equal(saved[0].body.directoryId, '22222222-2222-2222-2222-222222222222');
  lastForm.resolve(true);
  await adding;
});
