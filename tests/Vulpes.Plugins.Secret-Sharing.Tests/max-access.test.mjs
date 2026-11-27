import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

function leadingWhole(value) {
  const whole = /^\d+/.exec(value);
  return whole ? whole[0] : '';
}

test('a decimal max-access value keeps the whole number in front', () => {
  assert.equal(leadingWhole('1.2'), '1');
  assert.equal(leadingWhole('12'), '12');
  assert.equal(leadingWhole('.5'), '');
  for (const name of ['send.js', 'collect.js']) {
    const source = readFileSync(new URL(`../../src/Vulpes.Plugins.Secret-Sharing/wwwroot/js/${name}`, import.meta.url), 'utf8');
    assert.match(source, /const whole = \/\^\\d\+\/\.exec\(max\.value\)/);
  }
});
