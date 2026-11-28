import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

function extractFunction(source, name) {
  const start = source.indexOf(`function ${name}(`);
  if (start < 0) throw new Error(`missing ${name}`);
  const open = source.indexOf('{', start);
  let depth = 0;
  for (let i = open; i < source.length; i++) {
    if (source[i] === '{') depth++;
    else if (source[i] === '}') {
      depth--;
      if (depth === 0) return new Function(`${source.slice(start, i + 1)}\nreturn ${name};`)();
    }
  }
  throw new Error(`unclosed ${name}`);
}

function stored(parse, value) {
  const parsed = parse(value);
  if (parsed === false) return { ok: false, value: null };
  return { ok: true, value: parsed };
}

for (const name of ['send.js', 'collect.js']) {
  const source = readFileSync(new URL(`../../src/Vulpes.Plugins.Secret-Sharing/wwwroot/js/${name}`, import.meta.url), 'utf8');
  const parse = extractFunction(source, 'parseMaxAccess');

  test(`${name} keeps only a whole max-access count from 1 to 100000`, () => {
    assert.equal(stored(parse, '1e5').ok, false);
    assert.notEqual(stored(parse, '1e5').value, 1);
    assert.equal(stored(parse, '10.9').ok, false);
    assert.notEqual(stored(parse, '10.9').value, 10);
    assert.equal(stored(parse, '1.2').ok, false);
    assert.notEqual(stored(parse, '1.2').value, 1);
    assert.equal(stored(parse, '.5').ok, false);
    assert.equal(stored(parse, '5').value, 5);
    assert.equal(stored(parse, '12').value, 12);
    assert.equal(stored(parse, ' 5 ').value, 5);
    assert.equal(stored(parse, '').value, null);
    assert.equal(stored(parse, '   ').value, null);
    assert.equal(stored(parse, '0').ok, false);
    assert.equal(stored(parse, '100001').ok, false);
    assert.equal(stored(parse, '100000').value, 100000);
    assert.match(source, /if \(parseMaxAccess\(max\.value\) === false\) max\.value = ''/);
    assert.match(source, /const parsed = parseMaxAccess\(max\.value\)/);
    assert.doesNotMatch(source, /parseInt\(max\.value/);
    assert.doesNotMatch(source, /const whole = \/\^\\d\+\/\.exec\(max\.value\)/);
  });
}
