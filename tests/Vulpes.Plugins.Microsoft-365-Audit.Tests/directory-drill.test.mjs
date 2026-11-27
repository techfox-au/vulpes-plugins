import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

test('provisioning keeps a user drill and drops a directory activity drill', () => {
  const source = readFileSync(new URL('../../src/Vulpes.Plugins.Microsoft-365-Audit/wwwroot/js/directory.js', import.meta.url), 'utf8');
  assert.match(source, /f\.drill === true && f\.field !== 'user\.name'/);
  assert.match(source, /which === 'provisioning' \? user/);
});
