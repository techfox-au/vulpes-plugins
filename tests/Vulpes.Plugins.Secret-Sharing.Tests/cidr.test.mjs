import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import vm from 'node:vm';

const context = {};
vm.createContext(context);
vm.runInContext(readFileSync(new URL('../../src/Vulpes.Plugins.Secret-Sharing/wwwroot/public/cidr.js', import.meta.url), 'utf8'), context);
const parse = context.SecretCidr.parseAllowedCidr;

test('a dotted IPv6 address is stored in the same hex form as the server', () => {
  assert.equal(parse('2001:db8::192.0.2.1').value, '2001:db8::c000:201');
  assert.equal(parse('fe80::192.168.1.1').value, 'fe80::c0a8:101');
  assert.equal(parse('2001:db8::192.0.2.0/120').value, '2001:db8::c000:200/120');
  assert.equal(parse('2001:db8::c000:201').value, '2001:db8::c000:201');
});

test('a bracketed IPv6 address is stored without the brackets', () => {
  assert.equal(parse('[2001:db8::1]').value, '2001:db8::1');
  assert.equal(parse('[2001:db8::]/32').value, '2001:db8::/32');
  assert.equal(parse('[::ffff:192.0.2.1]').ok, false);
});

test('an IPv4-mapped IPv6 address is still rejected', () => {
  const mapped = parse('::ffff:192.0.2.1');
  assert.equal(mapped.ok, false);
  assert.match(mapped.error, /IPv4-mapped/);
  const plain = parse('192.0.2.1');
  assert.equal(plain.ok, true);
  assert.equal(plain.value, '192.0.2.1');
});

test('a prefix that is not canonical decimal is rejected', () => {
  for (const bad of ['203.0.113.10/00', '203.0.113.10/01', '203.0.113.10/008', '2001:db8::/032']) {
    const parsed = parse(bad);
    assert.equal(parsed.ok, false, bad);
    assert.match(parsed.error, /decimal integer/);
  }
  assert.equal(parse('203.0.113.10/0').ok, true);
  assert.equal(parse('203.0.113.10/0').value, '203.0.113.10/0');
  assert.equal(parse('203.0.113.10/24').value, '203.0.113.10/24');
  assert.equal(parse('203.0.113.10/32').value, '203.0.113.10/32');
  assert.equal(parse('2001:db8::/32').ok, true);
  assert.equal(parse('2001:db8::/32').value, '2001:db8::/32');
});
