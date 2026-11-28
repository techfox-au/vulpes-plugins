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

const files = [
  ['send.js', '../../src/Vulpes.Plugins.Secret-Sharing/wwwroot/js/send.js'],
  ['upload.js', '../../src/Vulpes.Plugins.Secret-Sharing/wwwroot/public/upload.js'],
];

for (const [name, path] of files) {
  const source = readFileSync(new URL(path, import.meta.url), 'utf8');
  const within = extractFunction(source, 'fileNameWithinLimit');

  test(`${name} rejects a file name longer than 200 characters before it is clipped`, () => {
    assert.equal(within('a'.repeat(200)), true);
    assert.equal(within('a'.repeat(201)), false);
    assert.equal(within(''), true);
    assert.equal(within(null), true);
    const kept = `${'a'.repeat(196)}.pdf`;
    assert.equal(kept.length, 200);
    assert.equal(within(kept), true);
    const dropped = `${'a'.repeat(197)}.pdf`;
    assert.equal(dropped.length, 201);
    assert.equal(within(dropped), false);
    assert.equal(dropped.slice(0, 200).endsWith('.pdf'), false);
    assert.match(source, /File name is too long \(max 200 characters\)\./);
  });
}
