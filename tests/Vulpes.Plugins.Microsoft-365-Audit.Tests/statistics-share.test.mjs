import assert from 'node:assert/strict';
import test from 'node:test';
import { share } from '../../src/Vulpes.Plugins.Microsoft-365-Audit/wwwroot/js/statistics.js';

test('a share under ten percent does not round up to 10.0', () => {
  assert.equal(share(995, 10000), '10%');
  assert.equal(share(949, 10000), '9.5%');
  assert.equal(share(10, 100), '10%');
});
