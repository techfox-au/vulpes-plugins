import assert from 'node:assert/strict';
import test from 'node:test';

const { sendLinkNote, collectLinkNote } = await import('../../src/Vulpes.Plugins.Secret-Sharing/wwwroot/js/link-note.js');

test('link notes name a key fragment and a password separately', () => {
  assert.match(sendLinkNote(1, false, true), /# fragment/);
  assert.match(sendLinkNote(1, true, false), /password separately/);
  assert.match(sendLinkNote(2, true, true), /# fragment/);
  assert.match(sendLinkNote(2, true, true), /password separately/);

  assert.match(collectLinkNote(1, false, true), /private key/);
  assert.match(collectLinkNote(1, true, false), /not the private key/);
  assert.match(collectLinkNote(2, true, true), /private key/);
  assert.match(collectLinkNote(2, true, true), /password separately/);
});
