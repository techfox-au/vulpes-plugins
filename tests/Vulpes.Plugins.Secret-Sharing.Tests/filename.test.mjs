import assert from 'node:assert/strict';
import test from 'node:test';
import { registerHooks } from 'node:module';

const stripQuery = registerHooks({
  resolve(specifier, context, nextResolve) {
    const query = specifier.indexOf('?');
    return nextResolve(query === -1 ? specifier : specifier.slice(0, query), context);
  },
});
test.after(() => stripQuery.deregister());

const { rejectedFileName } = await import('../../src/Vulpes.Plugins.Secret-Sharing/wwwroot/js/filename.js');

test('a filename that is only next-line or a byte order mark is rejected', () => {
  assert.equal(rejectedFileName('\u0085'), 'Enter a file name.');
  assert.equal(rejectedFileName('\uFEFF'), 'Enter a file name.');
  assert.equal(rejectedFileName('notes.txt'), '');
  assert.equal(rejectedFileName('   '), 'Enter a file name.');
});
