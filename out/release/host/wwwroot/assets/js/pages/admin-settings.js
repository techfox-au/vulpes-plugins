import { h, errorMessage, clear, setBusy, formValues, badge, kv, dropdown, panelNote } from '../ui.js?v=shell84';

let root;
let emailNotice = null;
export async function mount(el, ctx) { root = el; ctx.setTitle(['Settings']); await render(ctx); }
export function unmount() { root = null; }

function emailFieldName(message) {
  if (/graph directory/i.test(message)) return 'graphTenantId';
  if (/graph application/i.test(message)) return 'graphClientId';
  if (/graph client secret/i.test(message)) return 'graphClientSecret';
  if (/graph sender/i.test(message)) return 'graphSender';
  if (/mailgun from/i.test(message)) return 'mailgunFrom';
  if (/from address/i.test(message)) return 'fromAddress';
  if (/recipient/i.test(message)) return 'defaultRecipients';
  if (/domain/i.test(message)) return 'mailgunDomain';
  if (/host/i.test(message)) return 'host';
  if (/port/i.test(message)) return 'port';
  return null;
}

function showEmailError(card, form, message) {
  panelNote(card, message);
  form.querySelectorAll('.invalid').forEach((el) => el.classList.remove('invalid'));
  const name = emailFieldName(message);
  const field = name ? form.elements[name] : null;
  field?.classList.add('invalid');
  field?.focus();
}

async function render(ctx) {
  const notice = emailNotice;
  emailNotice = null;
  clear(root);
  // Graph, then SMTP, then Mailgun. See Notifications.cs.
  root.append(h('div', { class: 'page-header' }, h('h1', null, 'Settings')));
  const grid = h('div', { class: 'grid cols-2' });
  root.append(grid);

  // ---- SMTP
  const smtpCard = h('div', { class: 'card' }, h('div', { class: 'card-header' }, h('h2', null, 'Email')));
  grid.append(smtpCard);
  try {
    const smtp = await ctx.api.get('/api/admin/settings/smtp');
    const form = h('form', { class: 'col', novalidate: true });
    // Blank password, client secret, or API key keeps the stored secret. Order is Graph, SMTP, then Mailgun. See EmailTransports.
    const input = (name, label, value, type = 'text') => h('div', { class: 'field' }, h('label', null, label), h('input', { class: 'input', name, type, value: value ?? '', autocomplete: 'off', placeholder: (name === 'password' && smtp.passwordSet) || (name === 'graphClientSecret' && smtp.graphClientSecretSet) || (name === 'mailgunApiKey' && smtp.mailgunApiKeySet) ? 'Leave blank to keep' : '' }));
    form.append(
      h('h3', null, 'Microsoft Graph'),
      h('div', { class: 'form-row' }, input('graphTenantId', 'Directory id', smtp.graphTenantId), input('graphClientId', 'Application id', smtp.graphClientId)),
      h('div', { class: 'form-row' }, input('graphSender', 'Sender mailbox', smtp.graphSender, 'email'), input('graphClientSecret', 'Client secret', '', 'password')),
      h('label', { class: 'checkbox' }, h('input', { type: 'checkbox', name: 'graphEnabled', checked: smtp.graphEnabled === true }), h('span', null, 'Graph enabled')),
      h('h3', { class: 'mt' }, 'SMTP'),
      h('div', { class: 'form-row' }, input('host', 'SMTP host', smtp.host), input('port', 'Port', smtp.port ?? 587, 'number')),
      h('div', { class: 'field' }, h('label', null, 'Security'), dropdown(
        [['StartTls', 'STARTTLS'], ['SslOnConnect', 'Implicit TLS'], ['None', 'None']],
        { value: smtp.security || 'StartTls', name: 'security', ariaLabel: 'Security' })),
      h('div', { class: 'form-row' }, input('username', 'Username', smtp.username), input('password', 'Password', '', 'password')),
      h('div', { class: 'form-row' }, input('fromAddress', 'From address', smtp.fromAddress, 'email'), input('fromName', 'From name', smtp.fromName)),
      input('defaultRecipients', 'Default recipients', (smtp.defaultRecipients || []).join(', ')),
      h('label', { class: 'checkbox' }, h('input', { type: 'checkbox', name: 'enabled', checked: smtp.enabled === true }), h('span', null, 'SMTP enabled')),
      h('h3', { class: 'mt' }, 'Mailgun'),
      h('div', { class: 'form-row' }, input('mailgunDomain', 'Sending domain', smtp.mailgunDomain), input('mailgunFrom', 'From address', smtp.mailgunFrom, 'email')),
      h('div', { class: 'form-row' },
        h('div', { class: 'field' }, h('label', null, 'API region'), dropdown(
          [['https://api.mailgun.net', 'United States'], ['https://api.eu.mailgun.net', 'Europe']],
          { value: smtp.mailgunBaseUrl || 'https://api.mailgun.net', name: 'mailgunBaseUrl', ariaLabel: 'API region' })),
        input('mailgunApiKey', 'API key', '', 'password')),
      h('label', { class: 'checkbox' }, h('input', { type: 'checkbox', name: 'mailgunEnabled', checked: smtp.mailgunEnabled === true }), h('span', null, 'Mailgun enabled')),
    );
    const save = h('button', { class: 'btn primary', type: 'submit' }, 'Save');
    const test = h('button', { class: 'btn', type: 'button' }, 'Send test email');
    form.append(h('div', { class: 'form-actions' }, test, save));
    form.addEventListener('input', (e) => e.target.classList?.remove('invalid'));
    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      panelNote(smtpCard, '');
      form.querySelectorAll('.invalid').forEach((el) => el.classList.remove('invalid'));
      const v = formValues(form);
      setBusy(save, true, 'Saving…');
      try {
        await ctx.api.put('/api/admin/settings/smtp', { ...v, password: v.password || null, graphClientSecret: v.graphClientSecret || null, mailgunApiKey: v.mailgunApiKey || null, defaultRecipients: v.defaultRecipients.split(',').map((s) => s.trim()).filter(Boolean) });
        emailNotice = { message: 'Email settings saved.', kind: 'success' };
        await render(ctx);
      } catch (err) { showEmailError(smtpCard, form, errorMessage(err)); } finally { setBusy(save, false); }
    });
    test.addEventListener('click', async () => {
      const to = prompt('Send a test email to:', ctx.user.email || '');
      if (!to) return;
      setBusy(test, true, 'Sending…');
      try { await ctx.api.post('/api/admin/settings/smtp/test', { to }); panelNote(smtpCard, 'Test email queued and sent.', 'success'); }
      catch (err) { panelNote(smtpCard, errorMessage(err)); } finally { setBusy(test, false); }
    });
    smtpCard.append(form);
    if (notice) panelNote(smtpCard, notice.message, notice.kind);
  } catch (err) {
    smtpCard.append(h('div', { class: 'alert danger' }, errorMessage(err)));
  }

  // ---- proof of work (sign-in and secret sharing)
  const powCard = h('div', { class: 'card' }, h('div', { class: 'card-header' }, h('h2', null, 'Proof of work')));
  grid.append(powCard);
  try {
    const pow = await ctx.api.get('/api/admin/settings/pow');
    const form = h('form', { class: 'col', novalidate: true });
    const number = (name, label, value, min, max) => h('div', { class: 'field' },
      h('label', null, label),
      h('input', { class: 'input', name, type: 'number', min: String(min), max: String(max), step: '1', value: value ?? '', required: true, autocomplete: 'off' }));
    form.append(
      number('difficultyBits', 'Difficulty (bits)', pow.difficultyBits, 1, 28),
      number('challengeTtlSeconds', 'PoW ticket duration', pow.challengeTtlSeconds, 30, 600),
      number('scanBudgetWindowSeconds', 'Scan window (seconds)', pow.scanBudgetWindowSeconds, 30, 3600),
    );
    const save = h('button', { class: 'btn primary', type: 'submit' }, 'Save');
    form.append(h('div', { class: 'form-actions' }, save));
    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      panelNote(powCard, '');
      const v = formValues(form);
      setBusy(save, true, 'Saving…');
      try {
        await ctx.api.put('/api/admin/settings/pow', v);
        panelNote(powCard, 'Proof-of-work settings saved. The next challenge and the scan window use these values.', 'success');
      } catch (err) { panelNote(powCard, errorMessage(err)); }
      finally { setBusy(save, false); }
    });
    powCard.append(form);
  } catch (err) {
    powCard.append(h('div', { class: 'alert danger' }, errorMessage(err)));
  }

  // ---- values that the container otherwise takes from the environment
  const runtimeCard = h('div', { class: 'card' }, h('div', { class: 'card-header' }, h('h2', null, 'Server')));
  grid.append(runtimeCard);
  try {
    const [runtime, sqlite] = await Promise.all([
      ctx.api.get('/api/admin/settings/runtime'),
      ctx.api.get('/api/admin/settings/sqlite'),
    ]);
    const hours = Array.from({ length: 24 }, (_, hour) => [String(hour), String(hour).padStart(2, '0') + ':00 UTC']);
    const form = h('form', { class: 'col', novalidate: true });
    const input = (name, label, value, type = 'text', help) => h('div', { class: 'field' },
      h('label', null, label),
      h('input', { class: 'input', name, type, value: value ?? '', autocomplete: 'off', placeholder: type === 'password' ? 'Leave blank to keep' : '' }),
      help ? h('div', { class: 'help' }, help) : null);
    form.append(
      h('div', { class: 'field' }, h('label', null, 'SQLiteDB maintenance schedule'), dropdown(hours, { value: String(sqlite.hourUtc ?? 3), name: 'hourUtc', ariaLabel: 'SQLiteDB maintenance schedule' })),
      input('publicOrigin', 'Public origin', runtime.publicOrigin, 'url'),
      input('knownProxies', 'Known proxies', runtime.knownProxies),
      h('h3', { class: 'mt' }, 'Search'),
      input('retentionDays', 'Retention (days)', runtime.retentionDays, 'number'),
      input('elasticsearchUrl', 'Elasticsearch URL', runtime.elasticsearchUrl, 'url'),
      h('div', { class: 'form-row' }, input('elasticsearchUsername', 'Username', runtime.elasticsearchUsername), input('elasticsearchPassword', 'Password', '', 'password')),
      input('elasticsearchApiKey', 'API key', '', 'password', runtime.elasticsearchApiKeySet ? 'An API key is stored.' : null),
      input('certificateFingerprint', 'CA fingerprint', runtime.certificateFingerprint),
      h('label', { class: 'checkbox' }, h('input', { type: 'checkbox', name: 'allowInsecureHttp', checked: runtime.allowInsecureHttp === true }), h('span', null, 'Allow plain HTTP to Elasticsearch')),
    );
    const save = h('button', { class: 'btn primary', type: 'submit' }, 'Save');
    form.append(h('div', { class: 'form-actions' }, save));
    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      panelNote(runtimeCard, '');
      const v = formValues(form);
      setBusy(save, true, 'Saving…');
      try {
        await ctx.api.put('/api/admin/settings/sqlite', { hourUtc: Number(v.hourUtc) });
        const saved = await ctx.api.put('/api/admin/settings/runtime', {
          ...v,
          elasticsearchPassword: v.elasticsearchPassword || null,
          elasticsearchApiKey: v.elasticsearchApiKey || null,
        });
        const parts = ['Settings saved.'];
        if (saved.schemaWarning) parts.push(saved.schemaWarning);
        if (saved.restartRequired) parts.push('Restart the dashboard for origin, proxy, and search connection changes.');
        panelNote(runtimeCard, parts.join(' '), saved.schemaWarning ? '' : 'success');
      } catch (err) { panelNote(runtimeCard, errorMessage(err)); }
      finally { setBusy(save, false); }
    });
    runtimeCard.append(form);
  } catch (err) {
    runtimeCard.append(h('div', { class: 'alert danger' }, errorMessage(err)));
  }

  // ---- runtime info
  const infoCard = h('div', { class: 'card' }, h('div', { class: 'card-header' }, h('h2', null, 'Runtime')));
  grid.append(infoCard);
  try {
    const status = await ctx.api.get('/api/status');
    infoCard.append(kv([
      ['Version', status.version], ['Public origin', status.publicOrigin],
      ['Search backend', status.elasticsearch?.enabled ? h('span', null, status.elasticsearch.url || '', status.elasticsearch.version ? ` (v${status.elasticsearch.version}) ` : ' ', badge(status.elasticsearch.healthy ? 'healthy' : 'unreachable', status.elasticsearch.healthy ? 'success' : 'danger')) : badge('not configured', 'warning')],
      ['Retention', status.elasticsearch?.retentionDays ? `${status.elasticsearch.retentionDays} days` : null],
      ['Plugins', `${status.plugins?.loaded ?? 0} loaded, ${status.plugins?.failed ?? 0} failed`],
      ['Notification outbox', `${status.notifications?.pending ?? 0} pending, ${status.notifications?.failed ?? 0} failed`],
    ]));
    // The Server card above overrides the container environment. This block is the live view.
  } catch (err) {
    infoCard.append(h('div', { class: 'alert danger' }, errorMessage(err)));
  }
}
