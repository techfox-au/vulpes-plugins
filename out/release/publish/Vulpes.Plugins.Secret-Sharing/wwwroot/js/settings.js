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
    rows.push(
      h('label', { class: 'checkbox' }, collect, h('span', null, 'Email me when a collect is ready to retrieve')),
      h('p', { class: 'muted small' }, 'Sent when someone submits to one of your collect links.'));
  }
  rows.push(
    h('label', { class: 'checkbox' }, send, h('span', null, 'Email me when a send is opened for decryption')),
    h('p', { class: 'muted small' }, 'Sent when a recipient downloads the encrypted payload in their browser.'),
    note);
  card.append(
    h('div', { class: 'card-header' }, h('h2', null, 'Email')),
    h('div', { class: 'col' }, rows));
}

export function unmount() {}
