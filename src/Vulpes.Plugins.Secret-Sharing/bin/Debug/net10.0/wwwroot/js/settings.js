export async function mount(el, ctx) {
  const root = el.querySelector('#settings-root');
  const { h, panelNote } = ctx.ui;
  const card = h('div', { class: 'card' });
  root.append(card);
  let prefs;
  try {
    prefs = await ctx.api.get(`${ctx.plugin.apiBase}/notifications`);
  } catch (err) {
    card.append(h('div', { class: 'alert danger' }, err.message || 'Could not load settings.'));
    return;
  }

  const canCollect = !!prefs.canCollect;
  const send = h('input', { type: 'checkbox', checked: !!prefs.notifySendOpened });
  const collect = canCollect ? h('input', { type: 'checkbox', checked: !!prefs.notifyCollectReady }) : null;
  const note = h('div');
  let savedCollect = !!prefs.notifyCollectReady;
  let savedSend = !!prefs.notifySendOpened;
  const noEmail = !prefs.email;
  if (noEmail) {
    if (collect) collect.disabled = true;
    send.disabled = true;
  }

  async function save() {
    if (collect) collect.disabled = true;
    send.disabled = true;
    try {
      const next = await ctx.api.put(`${ctx.plugin.apiBase}/notifications`, {
        notifyCollectReady: collect ? collect.checked : false,
        notifySendOpened: send.checked,
      });
      savedCollect = !!next.notifyCollectReady;
      savedSend = !!next.notifySendOpened;
      if (collect) collect.checked = savedCollect;
      send.checked = savedSend;
      panelNote(note, '');
    } catch (err) {
      if (collect) collect.checked = savedCollect;
      send.checked = savedSend;
      panelNote(note, err.message || 'Could not save settings.');
    } finally {
      if (!noEmail) {
        if (collect) collect.disabled = false;
        send.disabled = false;
      }
    }
  }

  if (collect) collect.addEventListener('change', save);
  send.addEventListener('change', save);
  const rows = [
    prefs.email ? h('p', { class: 'muted' }, `Messages go to ${prefs.email}.`) : h('p', { class: 'muted' }, 'An administrator must add an email address to this account before these emails can be turned on.'),
  ];
  if (collect) {
    rows.push(h('label', { class: 'checkbox' }, collect, h('span', null, 'Email me when a collect is ready to retrieve')));
  }
  rows.push(
    h('label', { class: 'checkbox' }, send, h('span', null, 'Email me when a send is opened for decryption')),
    note);
  card.append(
    h('div', { class: 'card-header' }, h('h2', null, 'Email')),
    h('div', { class: 'col' }, rows));

  if (ctx.hasRole('Admin')) await mountRetrieveIps(root, ctx);
}

async function mountRetrieveIps(root, ctx) {
  const { h, panelNote } = ctx.ui;
  const card = h('div', { class: 'card' });
  root.append(card);
  let current;
  try {
    current = await ctx.api.get(`${ctx.plugin.apiBase}/collect-retrieve-ips`);
  } catch (err) {
    card.append(h('div', { class: 'alert danger' }, err.message || 'Could not load collect retrieval addresses.'));
    return;
  }

  const list = h('textarea', { class: 'input', rows: '4', spellcheck: 'false', placeholder: 'Blank or * allows any address. Example: 203.0.113.10, 198.51.100.0/24' });
  list.value = current.allowedIps || '';
  const save = h('button', { class: 'btn primary', type: 'button' }, 'Save');
  const note = h('div');
  card.hidden = current.publicAddressVisible === false;
  card.append(
    h('div', { class: 'card-header' }, h('h2', null, 'Collect retrieval')),
    h('div', { class: 'col' },
      h('label', null, 'IPs allowed to retrieve collected secrets'),
      list,
      h('p', { class: 'muted small' }, 'Comma-separated IPv4, IPv6, or CIDR addresses. Leave blank or enter * to allow any address. Checked when a collected submission is opened, before the submission is removed.'),
      h('div', null, save),
      note));
  async function refreshIpRestrictions() {
    try {
      const cfg = await ctx.api.get('/api/client-ip/capability');
      card.hidden = cfg.ipRestrictionsEnabled === false;
    } catch { /* keep the card until the probe result is known */ }
  }
  await refreshIpRestrictions();
  setTimeout(refreshIpRestrictions, 3500);
  save.addEventListener('click', async () => {
    save.disabled = true;
    try {
      const next = await ctx.api.put(`${ctx.plugin.apiBase}/collect-retrieve-ips`, { allowedIps: list.value });
      list.value = next.allowedIps || '';
      panelNote(note, 'Saved.', 'success');
    } catch (err) {
      panelNote(note, err.message || 'Could not save the address list.');
    } finally {
      save.disabled = false;
    }
  });
}

export function unmount() {}
