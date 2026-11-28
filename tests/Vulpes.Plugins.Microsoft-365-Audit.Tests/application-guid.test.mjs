import assert from 'node:assert/strict';
import test from 'node:test';
import { applicationGuid } from '../../src/Vulpes.Plugins.Microsoft-365-Audit/wwwroot/js/application.js';

test('a no-hyphen application id is the same guid the server stores', () => {
  assert.equal(applicationGuid('0123456789abcdef0123456789abcdef'), '01234567-89ab-cdef-0123-456789abcdef');
  assert.equal(applicationGuid('{01234567-89ab-cdef-0123-456789abcdef}'), '01234567-89ab-cdef-0123-456789abcdef');
  assert.equal(applicationGuid('(01234567-89ab-cdef-0123-456789abcdef)'), '01234567-89ab-cdef-0123-456789abcdef');
  assert.equal(applicationGuid('not-a-guid'), '');
});
