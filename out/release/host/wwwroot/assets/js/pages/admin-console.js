import { h } from '../ui.js?v=shell166';

let source;

export async function mount(el, ctx) {
  ctx.setTitle(['Console']);
  const log = h('div', { class: 'console-log', role: 'log', 'aria-live': 'polite' });
  const status = h('span', { class: 'badge success' }, 'Live');
  el.append(
    h('div', { class: 'page-header' }, h('h1', null, 'Console'), status),
    log);
  let stick = true;
  log.addEventListener('scroll', () => {
    stick = log.scrollHeight - log.scrollTop - log.clientHeight < 48;
  });
  source = new EventSource('/api/admin/console/stream');
  source.onmessage = (ev) => {
    let row;
    try { row = JSON.parse(ev.data); } catch { return; }
    log.append(h('div', { class: 'console-line' + (row.stream === 'err' ? ' err' : '') }, row.text ?? ''));
    if (stick) log.scrollTop = log.scrollHeight;
  };
  source.onerror = () => {
    status.className = 'badge danger';
    status.textContent = 'Disconnected';
  };
}

export function unmount() {
  if (source) {
    source.close();
    source = null;
  }
}
