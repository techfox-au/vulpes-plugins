import assert from 'node:assert/strict';
import test from 'node:test';

const { presentBuckets, overviewDrill } = await import('../../src/Vulpes.Plugins.Microsoft-365-Audit/wwwroot/js/overview.js');

test('a remainder bucket is Other and not an equals filter', () => {
  const items = presentBuckets([
    { key: 'bob', count: 4 },
    { key: '', count: 9, remainder: true },
    { key: '(none)', count: 1 },
    { key: '\0other', count: 2 },
  ]);
  assert.deepEqual(items[0], { key: 'bob', count: 4 });
  assert.deepEqual(items[1], { key: 'Other', count: 9, remainder: true });
  assert.deepEqual(items[2], { key: '(none)', count: 1 });
  assert.equal(items[3].key, 'Other');
  assert.equal(items[3].remainder, true);

  assert.equal(overviewDrill('microsoft-365-audit', items[1], 'signins', 'user', { range: '24h', extra: 'outcome=failure' }), null);
  assert.equal(overviewDrill('microsoft-365-audit', { key: '\0other', count: 2 }, 'signins', 'user', { range: '24h' }), null);
  assert.equal(overviewDrill('microsoft-365-audit', { key: '', count: 9, remainder: true }, 'activity', 'user', { range: '7d' }), null);
  assert.equal(
    overviewDrill('microsoft-365-audit', items[0], 'signins', 'user', { range: '24h', extra: 'outcome=failure' }),
    '/p/microsoft-365-audit/signins?user=bob&outcome=failure&range=24h',
  );
  assert.equal(
    overviewDrill('microsoft-365-audit', items[2], 'signins', 'user', { range: '7d', tenant: 'contoso' }),
    '/p/microsoft-365-audit/signins?userMissing=1&range=7d&tenant=contoso',
  );
});
