import { h, errorMessage, clear, setBusy, formValues, badge, kv, dropdown, panelNote } from '../ui.js?v=shell84';

let root;
let emailNotice = null;
export async function mount(el, ctx) { root = el; ctx.setTitle(['Settings']); await render(ctx); }
export function unmount() { root = null; }

function emailFieldName(message) {
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
  // SMTP, Mailgun failover, and which settings stay in appsettings: README and Notifications.cs.
  root.append(h('div', { class: 'page-header' }, h('h1', null, 'Settings')));
  const grid = h('div', { class: 'grid cols-2' });
  root.append(grid);

  // ---- SMTP
  const smtpCard = h('div', { class: 'card' }, h('div', { class: 'card-header' }, h('h2', null, 'Email')));
  grid.append(smtpCard);
  try {
    const smtp = await ctx.api.get('/api/admin/settings/smtp');
    const form = h('form', { class: 'col', novalidate: true });
    // Blank password or API key keeps the stored secret. SMTP is tried first (7s), then Mailgun. See EmailTransports.
    const input = (name, label, value, type = 'text') => h('div', { class: 'field' }, h('label', null, label), h('input', { class: 'input', name, type, value: value ?? '', autocomplete: 'off', placeholder: (name === 'password' && smtp.passwordSet) || (name === 'mailgunApiKey' && smtp.mailgunApiKeySet) ? 'Leave blank to keep' : '' }));
    form.append(
      h('h3', null, 'SMTP'),
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
        await ctx.api.put('/api/admin/settings/smtp', { ...v, password: v.password || null, mailgunApiKey: v.mailgunApiKey || null, defaultRecipients: v.defaultRecipients.split(',').map((s) => s.trim()).filter(Boolean) });
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
    const number = (name, label, value, min, max, help) => h('div', { class: 'field' },
      h('label', null, label),
      h('input', { class: 'input', name, type: 'number', min: String(min), max: String(max), step: '1', value: value ?? '', required: true, autocomplete: 'off' }),
      h('div', { class: 'help' }, help));
    form.append(
      number('difficultyBits', 'Difficulty (bits)', pow.difficultyBits, 1, 28, 'Leading zero bits for every challenge. 12 is about four thousand tries. 1 is the minimum and cannot be turned off.'),
      number('challengeTtlSeconds', 'Sign-in and send lifetime (seconds)', pow.challengeTtlSeconds, 30, 600, 'How long a sign-in or send challenge stays valid. 30 to 600 seconds.'),
      number('collectChallengeTtlSeconds', 'Collect lifetime (seconds)', pow.collectChallengeTtlSeconds, 900, 3600, 'How long a collect upload or retrieve challenge stays valid. At least 15 minutes.'),
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
        panelNote(powCard, 'Proof-of-work settings saved. The next challenge uses these values.', 'success');
      } catch (err) { panelNote(powCard, errorMessage(err)); }
      finally { setBusy(save, false); }
    });
    powCard.append(form);
  } catch (err) {
    powCard.append(h('div', { class: 'alert danger' }, errorMessage(err)));
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
    // Elasticsearch and the master key come from environment variables or appsettings (README). Not editable here.
  } catch (err) {
    infoCard.append(h('div', { class: 'alert danger' }, errorMessage(err)));
  }
}
