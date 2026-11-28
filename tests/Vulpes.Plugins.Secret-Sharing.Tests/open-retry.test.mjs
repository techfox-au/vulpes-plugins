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

const source = readFileSync(new URL('../../src/Vulpes.Plugins.Secret-Sharing/wwwroot/public/open.js', import.meta.url), 'utf8');
const canRetry = extractFunction(source, 'canRetry');

test('a reveal retry does not need the password once the key is unwrapped', () => {
  assert.equal(canRetry(null, ''), false);
  assert.equal(canRetry(undefined, ''), false);
  assert.equal(canRetry(null, 'secret'), true);
  assert.equal(canRetry(new Uint8Array(32), ''), true);
  const reveal = source.slice(source.indexOf('async function reveal'), source.indexOf('async function resolveKey'));
  const resolve = source.slice(source.indexOf('async function resolveKey'), source.indexOf('async function proveLinkKey'));
  assert.match(reveal, /canRetry\(sk, passwordEl\.value\)/);
  assert.doesNotMatch(resolve, /passwordEl\.value = ''/);
  const cleared = reveal.indexOf("passwordEl.value = ''");
  assert.ok(cleared > reveal.indexOf('requestArrayBuffer'));
  assert.ok(cleared > reveal.indexOf('secretBox'));
  assert.ok(cleared > reveal.indexOf('createObjectURL'));
});
