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

  const collect = h('input', { type: 'checkbox', checked: !!prefs.notifyCollectReady });
  const send = h('input', { type: 'checkbox', checked: !!prefs.notifySendOpened });
  const note = h('div');
  let savedCollect = !!prefs.notifyCollectReady;
  let savedSend = !!prefs.notifySendOpened;
  const noEmail = !prefs.email;
  if (noEmail) {
    collect.disabled = true;
    send.disabled = true;
  }

  async function save() {
    collect.disabled = true;
    send.disabled = true;
    try {
      const next = await ctx.api.put(`${ctx.plugin.apiBase}/notifications`, { notifyCollectReady: collect.checked, notifySendOpened: send.checked });
      savedCollect = !!next.notifyCollectReady;
      savedSend = !!next.notifySendOpened;
      panelNote(note, '');
    } catch (err) {
      collect.checked = savedCollect;
      send.checked = savedSend;
      panelNote(note, err.message || 'Could not save settings.');
    } finally {
      if (!noEmail) {
        collect.disabled = false;
        send.disabled = false;
      }
    }
  }

  collect.addEventListener('change', save);
  send.addEventListener('change', save);
  card.append(
    h('div', { class: 'card-header' }, h('h2', null, 'Email')),
    prefs.email ? h('p', { class: 'muted' }, `Messages go to ${prefs.email}.`) : h('p', { class: 'muted' }, 'An administrator must add an email address to this account before these emails can be turned on.'),
    h('label', { class: 'checkbox' }, collect, h('span', null, 'Email me when a collect is ready to retrieve')),
    h('p', { class: 'muted small' }, 'Sent when someone submits to one of your collect links.'),
    h('label', { class: 'checkbox' }, send, h('span', null, 'Email me when a send is opened for decryption')),
    h('p', { class: 'muted small' }, 'Sent when a recipient downloads the encrypted payload in their browser.'),
    note);
}

export function unmount() {}
