import { confirmIdentity } from '../reauth.js?v=shell408';
import { h, icon, errorMessage, clear, setBusy, formValues, badge, kv, dropdown, panelNote, modal, fmt, table, copyToClipboard } from '../ui.js?v=shell380';
import { appendApplication } from './entra-application.js?v=shell426';

let root;
let pageCtx;
let emailNotice = null;
let generation = 0;
export async function mount(el, ctx) {
  const gen = ++generation;
  root = el;
  pageCtx = ctx;
  ctx.setTitle(['Settings']);
  await render(ctx);
  if (gen !== generation || root !== el) return gen;
  document.addEventListener('keydown', onPrivatePluginShortcut);
  return gen;
}
export function unmount(gen) {
  if (gen !== generation) return;
  generation += 1;
  document.removeEventListener('keydown', onPrivatePluginShortcut);
  root = null;
  pageCtx = null;
}

function onPrivatePluginShortcut(event) {
  if (!event.ctrlKey || event.metaKey || event.altKey || !event.shiftKey) return;
  if (event.key !== 'p' && event.key !== 'P') return;
  if (document.querySelector('.modal-card')) return;
  event.preventDefault();
  void openPrivatePlugins();
}

async function openPrivatePlugins() {
  if (!pageCtx) return;
  await modal.form('Private plugins', [
    { name: 'privateKey', label: 'SSH private key', type: 'textarea', required: true, help: 'Paste the ASCII armor, the same text that is in the key file.' },
    { name: 'passphrase', label: 'Passphrase', type: 'password', help: 'Leave this blank when the key has none.' },
  ], {
    submitLabel: 'Use key',
    wide: true,
    onSubmit: (values) => pageCtx.api.post('/api/admin/settings/private-plugins', { privateKey: values.privateKey, passphrase: values.passphrase || null }),
  });
}

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

function powError(v) {
  if (!Number.isInteger(v.difficultyBits) || v.difficultyBits < 1 || v.difficultyBits > 28) return 'Difficulty must be from 1 to 28 bits.';
  if (!Number.isInteger(v.challengeTtlSeconds) || v.challengeTtlSeconds < 30 || v.challengeTtlSeconds > 240) return 'Ticket duration must be from 30 to 240 seconds.';
  if (!Number.isInteger(v.scanBudgetWindowSeconds) || v.scanBudgetWindowSeconds < 30 || v.scanBudgetWindowSeconds > 3600) return 'Scan window must be from 30 to 3600 seconds.';
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
  const gen = generation;
  const host = root;
  if (!host || gen !== generation) return;
  const still = () => gen === generation && root === host;
  const notice = emailNotice;
  emailNotice = null;
  clear(host);
  // Graph, then SMTP, then Mailgun. See Notifications.cs.
  host.append(h('div', { class: 'page-header' }, h('h1', null, 'Settings')));
  await appendApplication(ctx, host, () => render(ctx));
  if (!still()) return;
  const grid = h('div', { class: 'grid cols-2' });
  host.append(grid);

  // ---- SMTP
  const smtpCard = h('div', { class: 'card' }, h('div', { class: 'card-header' }, h('h2', null, 'Email')));
  grid.append(smtpCard);
  try {
    const smtp = await ctx.api.get('/api/admin/settings/smtp');
    const form = h('form', { class: 'col', novalidate: true });
    // A stored secret stays masked. The eye asks for a fresh sign-in, then shows it. A blank field that was not revealed keeps the stored secret.
    const input = (name, label, value, type = 'text') => h('div', { class: 'field' }, h('label', null, label), h('input', { class: 'input', name, type, value: value ?? '', autocomplete: 'off' }));
    const mask = '••••••••';
    let revealedSecrets = null;
    const secretField = (key, configured) => {
      const field = h('input', {
        class: 'input',
        type: configured ? 'password' : 'text',
        value: configured ? mask : '',
        autocomplete: 'off',
        spellcheck: false,
        readOnly: configured,
      });
      const button = h('button', {
        class: 'secret-tool secret-eye',
        type: 'button',
        title: 'Show secret',
        'aria-label': 'Show secret',
      }, icon('eye'));
      button.hidden = !configured;
      let revealed = false;
      const label = (showing) => {
        const text = showing ? 'Hide secret' : 'Show secret';
        button.title = text;
        button.setAttribute('aria-label', text);
      };
      button.addEventListener('click', async () => {
        if (!revealed) {
          if (!revealedSecrets) {
            const me = await ctx.api.get('/api/account');
            if (!(await confirmIdentity(ctx, me))) return;
            try {
              revealedSecrets = await ctx.api.get('/api/admin/settings/smtp/secrets');
            } catch (err) {
              if (err.code !== 'reauth_required') {
                panelNote(smtpCard, errorMessage(err));
                return;
              }
              if (!(await confirmIdentity(ctx, me))) return;
              revealedSecrets = await ctx.api.get('/api/admin/settings/smtp/secrets');
            }
          }
          field.value = revealedSecrets[key] || '';
          field.readOnly = false;
          field.type = 'text';
          revealed = true;
          button.hidden = false;
          label(true);
          return;
        }
        const hidden = field.type === 'text';
        field.type = hidden ? 'password' : 'text';
        label(hidden);
      });
      const payload = () => {
        if (field.readOnly) return { secret: '', remove: false };
        const text = field.value.trim();
        if (text === mask) return { secret: '', remove: false };
        return { secret: text, remove: revealed && text.length === 0 };
      };
      return {
        line: h('div', { class: 'secret-box secret-line' }, field, h('div', { class: 'secret-box-tools' }, button)),
        payload,
      };
    };
    const graphSecret = secretField('graphClientSecret', smtp.graphClientSecretSet === true);
    const smtpPassword = secretField('password', smtp.passwordSet === true);
    const mailgunKey = secretField('mailgunApiKey', smtp.mailgunApiKeySet === true);
    form.append(
      h('h3', null, 'Microsoft Graph'),
      h('div', { class: 'form-row' }, input('graphTenantId', 'Directory id', smtp.graphTenantId), input('graphClientId', 'Application id', smtp.graphClientId)),
      h('div', { class: 'form-row' }, input('graphSender', 'Sender mailbox', smtp.graphSender, 'email'), h('div', { class: 'field' }, h('label', null, 'Client secret'), graphSecret.line)),
      h('label', { class: 'checkbox' }, h('input', { type: 'checkbox', name: 'graphEnabled', checked: smtp.graphEnabled === true }), h('span', null, 'Graph enabled')),
      h('label', { class: 'checkbox' }, h('input', { type: 'checkbox', name: 'graphSaveToSentItems', checked: smtp.graphSaveToSentItems === true }), h('span', null, 'Save a copy in Sent Items')),
      h('h3', { class: 'mt' }, 'SMTP'),
      h('div', { class: 'form-row' }, input('host', 'SMTP host', smtp.host), input('port', 'Port', smtp.port ?? 587, 'number')),
      h('div', { class: 'field' }, h('label', null, 'Security'), dropdown(
        [['StartTls', 'STARTTLS'], ['SslOnConnect', 'Implicit TLS'], ['None', 'None']],
        { value: smtp.security || 'StartTls', name: 'security', ariaLabel: 'Security' })),
      h('div', { class: 'form-row' }, input('username', 'Username', smtp.username), h('div', { class: 'field' }, h('label', null, 'Password'), smtpPassword.line)),
      h('div', { class: 'form-row' }, input('fromAddress', 'From address', smtp.fromAddress, 'email'), input('fromName', 'From name', smtp.fromName)),
      input('defaultRecipients', 'Default recipients', (smtp.defaultRecipients || []).join(', ')),
      h('label', { class: 'checkbox' }, h('input', { type: 'checkbox', name: 'enabled', checked: smtp.enabled === true }), h('span', null, 'SMTP enabled')),
      h('h3', { class: 'mt' }, 'Mailgun'),
      h('div', { class: 'form-row' }, input('mailgunDomain', 'Sending domain', smtp.mailgunDomain), input('mailgunFrom', 'From address', smtp.mailgunFrom, 'email'), input('mailgunFromName', 'From name', smtp.mailgunFromName)),
      h('div', { class: 'form-row' },
        h('div', { class: 'field' }, h('label', null, 'API region'), dropdown(
          [['https://api.mailgun.net', 'United States'], ['https://api.eu.mailgun.net', 'Europe']],
          { value: smtp.mailgunBaseUrl || 'https://api.mailgun.net', name: 'mailgunBaseUrl', ariaLabel: 'API region' })),
        h('div', { class: 'field' }, h('label', null, 'API key'), mailgunKey.line)),
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
      const password = smtpPassword.payload();
      const graph = graphSecret.payload();
      const mailgun = mailgunKey.payload();
      setBusy(save, true, 'Saving…');
      try {
        await ctx.api.put('/api/admin/settings/smtp', {
          ...v,
          password: password.secret || null,
          removePassword: password.remove,
          graphClientSecret: graph.secret || null,
          removeGraphClientSecret: graph.remove,
          mailgunApiKey: mailgun.secret || null,
          removeMailgunApiKey: mailgun.remove,
          defaultRecipients: v.defaultRecipients.split(',').map((s) => s.trim()).filter(Boolean),
        });
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
      number('challengeTtlSeconds', 'Ticket duration', pow.challengeTtlSeconds, 30, 240),
      number('scanBudgetWindowSeconds', 'Scan window (seconds)', pow.scanBudgetWindowSeconds, 30, 3600),
    );
    const save = h('button', { class: 'btn primary', type: 'submit' }, 'Save');
    form.append(h('div', { class: 'form-actions' }, save));
    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      panelNote(powCard, '');
      const v = formValues(form);
      const invalid = powError(v);
      if (invalid) { panelNote(powCard, invalid); return; }
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
    const zone = sqlite.timeZone || 'local';
    const hours = Array.from({ length: 24 }, (_, hour) => [String(hour), String(hour).padStart(2, '0') + ':00 ' + zone]);
    const levels = ['Trace', 'Debug', 'Information', 'Warning', 'Error', 'Critical', 'None'].map((name) => [name, name]);
    const form = h('form', { class: 'col', novalidate: true });
    const input = (name, label, value, type = 'text', help) => h('div', { class: 'field' },
      h('label', null, label),
      h('input', { class: 'input', name, type, value: value ?? '', autocomplete: 'off', placeholder: type === 'password' ? 'Leave blank to keep' : '' }),
      help ? h('div', { class: 'help' }, help) : null);
    form.append(
      h('div', { class: 'field' },
        h('label', null, 'Console log level'),
        dropdown(levels, { value: runtime.consoleLogLevel || 'Information', name: 'consoleLogLevel', ariaLabel: 'Console log level' }),
        h('div', { class: 'help' }, 'Lines after the Vulpes banner. The banner always prints.')),
      h('div', { class: 'field' }, h('label', null, 'SQLite daily maintenance schedule'), dropdown(hours, { value: String(sqlite.hourUtc ?? 3), name: 'hourUtc', ariaLabel: 'SQLite daily maintenance schedule' })),
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
  try {
    const themes = await ctx.api.get('/api/admin/settings/themes');
    const choices = (themes.themes || []).filter((t) => t.id === 'default' || t.id === 'gorelo' || t.id === 'silver-fox').map((t) => [t.id, t.name]);
    const control = dropdown(choices, { value: themes.active || 'gorelo', name: 'theme', ariaLabel: 'Theme' });
    infoCard.append(h('div', { class: 'field mt' }, h('label', null, 'Theme'), control));
    control.addEventListener('change', async () => {
      const id = control.querySelector('input[name="theme"]')?.value;
      if (!id || id === themes.active) return;
      try {
        await ctx.api.post(`/api/admin/settings/themes/${encodeURIComponent(id)}/use`, {});
        themes.active = id;
        const link = document.querySelector('link[rel="stylesheet"][href^="/theme.css"]');
        if (link) link.href = '/theme.css?' + Date.now();
        document.querySelectorAll('link[rel="icon"]').forEach((icon) => {
          const path = icon.getAttribute('href')?.split('?')[0];
          if (path) icon.setAttribute('href', path + '?v=' + Date.now());
        });
        panelNote(infoCard, 'Theme saved.', 'success');
      } catch (err) {
        panelNote(infoCard, errorMessage(err));
      }
    });
  } catch (err) {
    infoCard.append(h('div', { class: 'alert danger' }, errorMessage(err)));
  }

  if (!still()) return;
  await appendMcp(ctx, host);
}

async function appendMcp(ctx, parent) {
  const card = h('div', { class: 'card' });
  const list = h('div', { class: 'mt' });
  const revealed = h('div');
  const name = h('input', { class: 'input', placeholder: 'Grok Bot', 'aria-label': 'Token name', maxlength: '80' });
  let enabledBox;
  let origin = location.origin;
  try {
    const status = await ctx.api.get('/api/status');
    if (status?.publicOrigin) origin = String(status.publicOrigin).replace(/\/$/, '');
  } catch { /* the address bar origin is enough */ }
  try {
    const settings = await ctx.api.get('/api/mcp/settings');
    enabledBox = h('input', { type: 'checkbox', checked: settings.enabled === true, 'aria-label': 'MCP server enabled' });
  } catch (err) {
    card.append(h('div', { class: 'card-header' }, h('h2', null, 'MCP')), h('div', { class: 'alert danger' }, errorMessage(err)));
    parent.append(card);
    return;
  }
  enabledBox.addEventListener('change', () => setMcpEnabled(ctx, enabledBox, card));
  card.append(
    h('div', { class: 'card-header' }, h('h2', null, 'MCP')),
    h('label', { class: 'checkbox' }, enabledBox, h('span', null, 'MCP server enabled')),
    h('p', { class: 'muted' }, 'MCP endpoint: ' + origin + '/api/mcp'),
    h('div', { class: 'form-row' }, name, h('button', { class: 'btn', type: 'button', onClick: () => createMcpToken(ctx, name, revealed, card, list) }, 'Create token')),
    revealed,
    list);
  parent.append(card);
  await loadMcpTokens(ctx, list);
}

function mcpExpiry(row) {
  if (!row.expiresAt) return '—';
  const when = new Date(row.expiresAt);
  const label = fmt.date(row.expiresAt);
  if (Number.isNaN(when.getTime())) return label;
  const days = Math.ceil((when.getTime() - Date.now()) / 86400000);
  if (days < 0) return h('span', null, label, ' ', badge('Expired', 'danger'));
  if (days <= 10) return h('span', null, label, ' ', badge(days === 1 ? 'Expires in 1 day' : `Expires in ${days} days`, 'warning'));
  return label;
}

async function setMcpEnabled(ctx, box, card) {
  const enabled = box.checked;
  try {
    await ctx.api.put('/api/mcp/settings', { enabled });
  } catch (err) {
    if (err.code !== 'reauth_required') {
      box.checked = !enabled;
      panelNote(card, errorMessage(err));
      return;
    }
    const me = await ctx.api.get('/api/account');
    if (!(await confirmIdentity(ctx, me))) {
      box.checked = false;
      return;
    }
    try {
      await ctx.api.put('/api/mcp/settings', { enabled: true });
    } catch (again) {
      box.checked = false;
      panelNote(card, errorMessage(again));
    }
  }
}

async function loadMcpTokens(ctx, list) {
  let rows;
  try { rows = await ctx.api.get('/api/mcp/tokens'); }
  catch (err) { clear(list).append(h('div', { class: 'alert danger' }, errorMessage(err))); return; }
  clear(list).append(table({
    columns: [
      { title: 'Name', render: (r) => r.name },
      { title: 'Prefix', render: (r) => r.prefix },
      { title: 'Created', render: (r) => fmt.date(r.createdAt) },
      { title: 'Expires', render: mcpExpiry },
      { title: 'Last used', render: (r) => r.lastUsedAt ? fmt.relative(r.lastUsedAt) : 'never' },
      { title: '', render: (r) => h('div', { class: 'flex' }, r.revoked ? badge('Revoked', 'danger') : null, h('button', { class: 'btn sm danger', type: 'button', onClick: () => removeMcpToken(ctx, list, r) }, 'Delete')) },
    ],
    rows,
    emptyText: 'No tokens yet.',
  }));
}

async function createMcpToken(ctx, name, revealed, card, list) {
  clear(revealed);
  try {
    await storeMcpToken(ctx, name, revealed, card, list);
  } catch (err) {
    if (err.code !== 'reauth_required') {
      panelNote(card, errorMessage(err));
      return;
    }
    const me = await ctx.api.get('/api/account');
    if (!(await confirmIdentity(ctx, me))) return;
    try {
      await storeMcpToken(ctx, name, revealed, card, list);
    } catch (again) {
      panelNote(card, errorMessage(again));
    }
  }
}

async function storeMcpToken(ctx, name, revealed, card, list) {
  const created = await ctx.api.post('/api/mcp/tokens', { name: name.value.trim() || 'Grok Bot' });
  revealed.append(h('div', { class: 'alert success' },
    h('div', null, 'Copy this token now. It is not shown again.'),
    h('code', null, created.token),
    h('button', { class: 'btn ghost', type: 'button', onClick: () => copyToClipboard(created.token, card) }, 'Copy')));
  name.value = '';
  await loadMcpTokens(ctx, list);
}

async function removeMcpToken(ctx, list, row) {
  if (!(await modal.confirm('Delete token', `Delete ${row.name}? Its token stops working.`, { danger: true, confirmLabel: 'Delete' }))) return;
  try {
    await ctx.api.delete(`/api/mcp/tokens/${row.id}`);
    await loadMcpTokens(ctx, list);
  } catch (err) {
    panelNote(list, errorMessage(err));
  }
}
