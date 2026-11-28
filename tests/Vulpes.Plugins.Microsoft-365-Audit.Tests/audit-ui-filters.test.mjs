import assert from 'node:assert/strict';
import test from 'node:test';

const { carriedAlertFilters } = await import('../../src/Vulpes.Plugins.Microsoft-365-Audit/wwwroot/js/security-alerts.js');
const { carriedRiskFilters } = await import('../../src/Vulpes.Plugins.Microsoft-365-Audit/wwwroot/js/risk.js');
const { carriedDirectoryFilters } = await import('../../src/Vulpes.Plugins.Microsoft-365-Audit/wwwroot/js/directory.js');
const { lookbackDays } = await import('../../src/Vulpes.Plugins.Microsoft-365-Audit/wwwroot/js/clients.js');

test('incidents drop serviceSource and keep status', () => {
  const filters = [
    { field: 'labels.serviceSource', operator: 'equals', values: ['microsoftDefenderForEndpoint'] },
    { field: 'labels.status', operator: 'equals', values: ['new'] },
    { field: 'labels.classification', operator: 'equals', values: ['truePositive'] },
    { field: 'labels.assignedTo', operator: 'equals', values: ['sec'] },
    { field: 'user.name', operator: 'equals', values: ['ada'] },
    { field: 'vc.tenantName', operator: 'equals', values: ['Contoso'] },
  ];
  const incidents = carriedAlertFilters('incidents', filters);
  assert.deepEqual(incidents.map((filter) => filter.field), ['labels.status', 'labels.classification', 'labels.assignedTo', 'vc.tenantName']);
  assert.equal(incidents[0].values[0], 'new');
  assert.ok(!incidents.some((filter) => filter.field === 'labels.serviceSource'));
  assert.ok(incidents.some((filter) => filter.field === 'labels.status'));
  const alerts = carriedAlertFilters('security-alerts', filters);
  assert.deepEqual(alerts.map((filter) => filter.field), ['labels.serviceSource', 'labels.status', 'user.name', 'vc.tenantName']);
  assert.ok(alerts.some((filter) => filter.field === 'labels.serviceSource'));
  incidents[0].values.push('closed');
  assert.deepEqual(filters[1].values, ['new']);
});

test('service principals drop user.name and other risk tabs keep it', () => {
  const filters = [
    { field: 'labels.riskType', operator: 'equals', values: ['detection'] },
    { field: 'user.name', operator: 'equals', values: ['ada@contoso.com'] },
    { field: 'labels.riskState', operator: 'equals', values: ['atRisk'] },
    { field: 'client.appName', operator: 'equals', values: ['Graph'] },
  ];
  assert.deepEqual(carriedRiskFilters('servicePrincipal', filters).map((filter) => filter.field), ['labels.riskState', 'client.appName']);
  assert.deepEqual(carriedRiskFilters('detection', filters).map((filter) => filter.field), ['user.name', 'labels.riskState', 'client.appName']);
  assert.deepEqual(carriedRiskFilters('user', filters).map((filter) => filter.field), ['user.name', 'labels.riskState', 'client.appName']);
});

test('provisioning keeps a clicked user and drops activity and category without drill', () => {
  const filters = [
    { field: 'event.action', operator: 'equals', values: ['Add user'] },
    { field: 'labels.category', operator: 'equals', values: ['UserManagement'] },
    { field: 'user.name', operator: 'equals', values: ['ada'] },
  ];
  assert.deepEqual(carriedDirectoryFilters('provisioning', filters).map((filter) => filter.field), ['user.name']);
  assert.deepEqual(carriedDirectoryFilters('provisioning', filters)[0].values, ['ada']);
  assert.deepEqual(carriedDirectoryFilters('directory', filters).map((filter) => filter.field), ['event.action', 'labels.category', 'user.name']);
});

test('lookbackDays accepts only integers from 1 to 180', () => {
  assert.equal(lookbackDays(''), null);
  assert.equal(lookbackDays('7'), 7);
  assert.equal(lookbackDays('0'), null);
  assert.equal(lookbackDays('30'), 30);
  assert.equal(lookbackDays('181'), null);
  assert.equal(lookbackDays('1'), 1);
  assert.equal(lookbackDays('180'), 180);
});
