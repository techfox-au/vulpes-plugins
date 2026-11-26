import assert from 'node:assert/strict';
import test from 'node:test';
import { openKind } from '../../src/Vulpes.Plugins.Secret-Sharing/wwwroot/public/open-kind.js';

test('a collect alias keeps its kind in any case', () => {
  assert.equal(openKind('/collect', null), 'collect');
  assert.equal(openKind('/Collect', null), 'collect');
  assert.equal(openKind('/COLLECT/', null), 'collect');
  assert.equal(openKind('/send', null), 'send');
  assert.equal(openKind('/Send', 'collect'), 'collect');
  assert.equal(openKind('/collect', 'send'), 'collect');
});
