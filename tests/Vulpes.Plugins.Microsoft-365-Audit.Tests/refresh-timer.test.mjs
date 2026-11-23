import assert from 'node:assert/strict';
import test from 'node:test';

function element() {
  const node = {
    children: [],
    append(...items) { node.children.push(...items); },
    querySelector() { return element(); },
  };
  return node;
}

function deferred() {
  let resolve;
  const promise = new Promise((ok) => { resolve = ok; });
  return { promise, resolve };
}

const timers = new Map();
let nextTimer = 1;
const realSet = global.setInterval;
const realClear = global.clearInterval;
global.setInterval = (fn) => {
  const id = nextTimer++;
  timers.set(id, fn);
  return id;
};
global.clearInterval = (id) => { timers.delete(id); };

const ingestion = await import('../../src/Vulpes.Plugins.Microsoft-365-Audit/wwwroot/js/ingestion.js');
const statistics = await import('../../src/Vulpes.Plugins.Microsoft-365-Audit/wwwroot/js/statistics.js');

function ctx(pending) {
  return {
    setTitle() {},
    plugin: { apiBase: '/api/plugins/microsoft-365-audit' },
    api: { get: () => pending.promise },
    ui: {
      h: () => element(),
      icon: () => element(),
      clear(node) { if (node) node.children = []; return node; },
      table: () => element(),
      badge: () => element(),
      errorMessage: (err) => err.message || String(err),
      fmt: { number: (v) => String(v), dateTime: (v) => String(v), relative: () => '', bytes: () => '' },
    },
  };
}

async function leaveAndReturn(mod) {
  const first = deferred();
  const started = mod.mount(element(), ctx(first));
  await Promise.resolve();
  const before = timers.size;
  const secondWait = deferred();
  const again = mod.mount(element(), ctx(secondWait));
  first.resolve({ tenants: [], sources: [], recentRuns: [], available: true, documents: 0, storedBytes: 0, diskBytes: 0, sources: [] });
  await started;
  assert.equal(timers.size, before);
  secondWait.resolve({ tenants: [], sources: [], recentRuns: [], available: true, documents: 0, storedBytes: 0, diskBytes: 0 });
  await again;
  assert.equal(timers.size, before + 1);
  mod.unmount();
  assert.equal(timers.size, before);
}

test('ingestion does not keep a timer from a mount that already moved on', async () => {
  await leaveAndReturn(ingestion);
});

test('statistics does not keep a timer from a mount that already moved on', async () => {
  await leaveAndReturn(statistics);
});

test.after(() => {
  global.setInterval = realSet;
  global.clearInterval = realClear;
});
