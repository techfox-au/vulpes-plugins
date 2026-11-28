import assert from 'node:assert/strict';
import test from 'node:test';

const { carriedAlertFilters, alertColumns } = await import('../../src/Vulpes.Plugins.Microsoft-365-Audit/wwwroot/js/security-alerts.js');
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
  assert.deepEqual(alerts.map((filter) => filter.field), ['labels.serviceSource', 'labels.status', 'labels.classification', 'labels.assignedTo', 'user.name', 'vc.tenantName']);
  assert.ok(alerts.some((filter) => filter.field === 'labels.serviceSource'));
  assert.ok(alerts.some((filter) => filter.field === 'labels.classification'));
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
  assert.deepEqual(carriedRiskFilters('detection', filters).map((filter) => filter.field), ['user.name', 'labels.riskState']);
  assert.deepEqual(carriedRiskFilters('user', filters).map((filter) => filter.field), ['user.name', 'labels.riskState']);
});

test('provisioning keeps a clicked user and drops activity and category without drill', () => {
  const filters = [
    { field: 'event.action', operator: 'equals', values: ['Add user'] },
    { field: 'labels.category', operator: 'equals', values: ['UserManagement'] },
    { field: 'user.name', operator: 'equals', values: ['ada'] },
  ];
  assert.deepEqual(carriedDirectoryFilters('provisioning', filters).map((filter) => filter.field), []);
  assert.deepEqual(carriedDirectoryFilters('directory', filters).map((filter) => filter.field), ['labels.category', 'user.name']);
  assert.ok(!carriedDirectoryFilters('directory', filters).some((filter) => filter.field === 'event.action'));
});

test('directory and provisioning drop fields the destination does not store', () => {
  const filters = [
    { field: 'event.action', operator: 'equals', values: ['Create'] },
    { field: 'labels.targetName', operator: 'equals', values: ['Ada'] },
    { field: 'labels.service', operator: 'equals', values: ['Core Directory'] },
    { field: 'source.address', operator: 'equals', values: ['203.0.113.10'] },
    { field: 'labels.category', operator: 'equals', values: ['UserManagement'] },
    { field: 'labels.resultReason', operator: 'equals', values: ['locked'] },
    { field: 'labels.sourceSystem', operator: 'equals', values: ['Azure AD'] },
    { field: 'labels.targetSystem', operator: 'equals', values: ['Salesforce'] },
    { field: 'user.name', operator: 'equals', values: ['ada'] },
    { field: 'client.appName', operator: 'equals', values: ['Graph'] },
    { field: 'vc.tenantName', operator: 'equals', values: ['Contoso'] },
  ];
  assert.deepEqual(carriedDirectoryFilters('provisioning', filters).map((filter) => filter.field), ['labels.sourceSystem', 'labels.targetSystem', 'client.appName', 'vc.tenantName']);
  assert.ok(!carriedDirectoryFilters('provisioning', filters).some((filter) => filter.field === 'user.name' || filter.field === 'user.id'));
  assert.ok(!carriedDirectoryFilters('provisioning', filters).some((filter) => filter.field === 'labels.targetName' || filter.field === 'labels.service' || filter.field === 'source.address' || filter.field === 'event.action'));
  assert.deepEqual(carriedDirectoryFilters('directory', filters).map((filter) => filter.field), ['labels.targetName', 'labels.service', 'source.address', 'labels.category', 'labels.resultReason', 'user.name', 'client.appName', 'vc.tenantName']);
  assert.ok(!carriedDirectoryFilters('directory', filters).some((filter) => filter.field === 'event.action' || filter.field === 'labels.sourceSystem'));
  const toDirectory = carriedDirectoryFilters('directory', carriedDirectoryFilters('provisioning', filters));
  assert.deepEqual(toDirectory.map((filter) => filter.field), ['client.appName', 'vc.tenantName']);
  const toProvisioning = carriedDirectoryFilters('provisioning', carriedDirectoryFilters('directory', filters));
  assert.ok(!toProvisioning.some((filter) => filter.field === 'user.name'));
  assert.ok(!toProvisioning.some((filter) => ['event.action', 'labels.targetName', 'labels.service', 'source.address'].includes(filter.field)));
});

test('risk tabs keep shared risk fields and drop fields the destination does not store', () => {
  const filters = [
    { field: 'labels.riskType', operator: 'equals', values: ['detection'] },
    { field: 'labels.riskLevel', operator: 'equals', values: ['high'] },
    { field: 'labels.riskState', operator: 'equals', values: ['atRisk'] },
    { field: 'labels.riskDetail', operator: 'equals', values: ['none'] },
    { field: 'source.address', operator: 'equals', values: ['203.0.113.8'] },
    { field: 'event.action', operator: 'equals', values: ['unfamiliarFeatures'] },
    { field: 'labels.servicePrincipalType', operator: 'equals', values: ['Application'] },
    { field: 'user.name', operator: 'equals', values: ['ada@contoso.com'] },
    { field: 'client.appName', operator: 'equals', values: ['Graph'] },
    { field: 'client.appId', operator: 'equals', values: ['app-1'] },
  ];
  assert.deepEqual(carriedRiskFilters('detection', filters).map((filter) => filter.field), ['labels.riskLevel', 'labels.riskState', 'labels.riskDetail', 'source.address', 'event.action', 'user.name']);
  assert.deepEqual(carriedRiskFilters('user', filters).map((filter) => filter.field), ['labels.riskLevel', 'labels.riskState', 'labels.riskDetail', 'user.name']);
  assert.deepEqual(carriedRiskFilters('servicePrincipal', filters).map((filter) => filter.field), ['labels.riskLevel', 'labels.riskState', 'labels.riskDetail', 'labels.servicePrincipalType', 'client.appName', 'client.appId']);
  assert.ok(!carriedRiskFilters('user', filters).some((filter) => filter.field === 'source.address' || filter.field === 'event.action' || filter.field === 'labels.servicePrincipalType'));
  assert.ok(!carriedRiskFilters('servicePrincipal', filters).some((filter) => filter.field === 'source.address' || filter.field === 'event.action' || filter.field === 'user.name'));
  assert.ok(carriedRiskFilters('servicePrincipal', filters).some((filter) => filter.field === 'labels.servicePrincipalType'));
});

test('severity and classification survive an incidents round trip and serviceSource does not', () => {
  const filters = [
    { field: 'event.severity', operator: 'equals', values: ['high'], drill: true },
    { field: 'labels.classification', operator: 'equals', values: ['truePositive'] },
    { field: 'labels.determination', operator: 'equals', values: ['malware'] },
    { field: 'labels.serviceSource', operator: 'equals', values: ['microsoftDefenderForEndpoint'] },
    { field: 'labels.status', operator: 'equals', values: ['new'] },
  ];
  const incidents = carriedAlertFilters('incidents', filters);
  assert.deepEqual(incidents.map((filter) => filter.field), ['event.severity', 'labels.classification', 'labels.determination', 'labels.status']);
  assert.equal(incidents[0].values[0], 'high');
  assert.equal(incidents[0].drill, true);
  assert.ok(!incidents.some((filter) => filter.field === 'labels.serviceSource'));
  const alerts = carriedAlertFilters('security-alerts', incidents);
  assert.deepEqual(alerts.map((filter) => filter.field), ['event.severity', 'labels.classification', 'labels.determination', 'labels.status']);
  assert.equal(alerts[0].values[0], 'high');
  assert.equal(alerts[0].drill, true);
  assert.ok(!alerts.some((filter) => filter.field === 'labels.serviceSource'));
  incidents[0].values.push('medium');
  assert.deepEqual(filters[0].values, ['high']);
});

test('incident assigned-to column filters by labels.assignedTo', () => {
  const columns = alertColumns('incidents', { ui: { h() {}, fmt: {} } });
  const assigned = columns.find((column) => column.title === 'Assigned to');
  assert.equal(assigned.path, 'labels.assignedTo');
  assert.equal(assigned.filterField, 'labels.assignedTo');
  const user = alertColumns('security-alerts', { ui: { h() {}, fmt: {} } }).find((column) => column.title === 'User');
  assert.equal(user.filterField, 'user.name');
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
