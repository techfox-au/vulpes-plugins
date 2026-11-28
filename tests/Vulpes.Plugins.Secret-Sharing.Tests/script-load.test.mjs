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

for (const name of ['send.js', 'collect.js']) {
  const source = readFileSync(new URL(`../../src/Vulpes.Plugins.Secret-Sharing/wwwroot/js/${name}`, import.meta.url), 'utf8');
  const decide = extractFunction(source, 'scriptLoadDecision');

  test(`${name} reloads a udk tag when the global is missing and drops it on error`, () => {
    assert.equal(decide(true, false, false), 'load');
    assert.equal(decide(true, true, false), 'resolve');
    assert.equal(decide(false, false, false), 'load');
    assert.equal(decide(true, true, true), 'remove');
    assert.equal(decide(true, false, true), 'remove');
    assert.match(source, /scriptLoadDecision\(true, false, true\) === 'remove'\) s\.remove\(\)/);
    assert.match(source, /loadScript\(`\$\{pub\}\/udk\.js\?v=udk9`, 'SecretUdk'\)/);
  });
}
