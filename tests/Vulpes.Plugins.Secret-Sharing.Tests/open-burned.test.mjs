import assert from 'node:assert/strict';
import fs from 'node:fs';
import test from 'node:test';

const source = fs.readFileSync(new URL('../../src/Vulpes.Plugins.Secret-Sharing/wwwroot/public/open.js', import.meta.url), 'utf8');

test('reveal uses the burned flag from this open', () => {
  assert.match(source, /const burned = payload\.burned === true/);
  assert.doesNotMatch(source, /\(meta\.accessCount \|\| 0\) \+ 1 >= meta\.maxAccessCount/);
});
