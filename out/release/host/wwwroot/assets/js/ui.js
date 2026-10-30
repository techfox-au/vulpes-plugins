// DOM-building UI toolkit. Everything is created with createElement/textContent;
// untrusted data is never interpolated into HTML strings.

export function h(tag, props, ...children) {
  const el = document.createElement(tag);
  if (props) {
    for (const [key, value] of Object.entries(props)) {
      if (value === undefined || value === null) continue;
      if (value === false) {
        if (key in el && typeof el[key] === 'boolean') el[key] = false;
        continue;
      }
      if (key === 'class') el.className = value;
      else if (key === 'dataset') Object.assign(el.dataset, value);
      else if (key.startsWith('on') && typeof value === 'function') el.addEventListener(key.slice(2).toLowerCase(), value);
      else if (key === 'text') el.textContent = value;
      else if (key in el && typeof value !== 'object') { try { el[key] = value; } catch { el.setAttribute(key, value); } }
      else el.setAttribute(key, value === true ? '' : value);
    }
  }
  append(el, children);
  return el;
}

export function append(el, children) {
  for (const child of children.flat(Infinity)) {
    if (child === null || child === undefined || child === false) continue;
    el.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  return el;
}

export function clear(el) { while (el.firstChild) el.removeChild(el.firstChild); return el; }

const FILLED = new Set(['plug']);
const ICONS = new Set(['home', 'bell', 'user', 'users', 'puzzle', 'plug', 'settings', 'list', 'chart', 'login', 'directory', 'activity', 'shield', 'warning', 'building', 'pulse', 'lock', 'key', 'sparkles', 'sun', 'moon', 'logout', 'x', 'check', 'search', 'refresh', 'plus', 'trash', 'edit', 'copy', 'download', 'upload', 'external', 'info', 'dot', 'mail', 'play', 'eye']);

export function icon(name, cls = 'icon') {
  const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
  svg.setAttribute('class', cls + (FILLED.has(name) ? ' solid' : ''));
  svg.setAttribute('aria-hidden', 'true');
  const use = document.createElementNS('http://www.w3.org/2000/svg', 'use');
  use.setAttribute('href', '/assets/img/icons.svg?v=plug2#' + (ICONS.has(name) ? name : 'dot'));
  svg.append(use);
  return svg;
}

export function badge(text, kind = '', dot = false) {
  return h('span', { class: 'badge ' + kind }, dot ? h('span', { class: 'dot' }) : null, text);
}

export const fmt = {
  date(value) {
    if (!value) return '';
    const d = new Date(value);
    return Number.isNaN(d.getTime()) ? String(value) : d.toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' });
  },
  dateTime(value) {
    if (!value) return '';
    const d = new Date(value);
    return Number.isNaN(d.getTime()) ? String(value) : d.toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'medium' });
  },
  relative(value) {
    if (!value) return '';
    const diff = (Date.now() - new Date(value).getTime()) / 1000;
    if (!Number.isFinite(diff)) return String(value);
    const abs = Math.abs(diff);
    const units = [['year', 31536000], ['month', 2592000], ['day', 86400], ['hour', 3600], ['minute', 60], ['second', 1]];
    for (const [unit, secs] of units) {
      if (abs >= secs || unit === 'second') {
        const v = Math.round(diff / secs);
        return new Intl.RelativeTimeFormat(undefined, { numeric: 'auto' }).format(-v, unit);
      }
    }
    return '';
  },
  number(value) { return value === null || value === undefined ? '' : new Intl.NumberFormat().format(value); },
  bytes(n) {
    if (n === null || n === undefined) return '';
    const units = ['B', 'KB', 'MB', 'GB'];
    let i = 0; let v = n;
    while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
    return `${v.toFixed(i === 0 ? 0 : 1)} ${units[i]}`;
  },
  bool(v) { return v ? 'Yes' : 'No'; },
};

/** Renders a table. columns: [{ key, title, render?(row), class?, width? }] */
export function table({ columns, rows, onRowClick, emptyText = 'Nothing to show', rowKey, className = '' }) {
  const wrap = h('div', { class: 'table-wrap' });
  const tbl = h('table', { class: className ? `table ${className}` : 'table' });
  const thead = h('thead', null, h('tr', null, columns.map((c) => h('th', { class: c.class || '' }, c.title))));
  const tbody = h('tbody');
  if (!rows || rows.length === 0) {
    tbody.append(h('tr', null, h('td', { colspan: String(columns.length) }, h('div', { class: 'empty' }, emptyText))));
  } else {
    for (const row of rows) {
      const tr = h('tr', { class: onRowClick ? 'clickable' : '' });
      if (rowKey) tr.dataset.key = rowKey(row);
      for (const c of columns) {
        const value = c.render ? c.render(row) : (c.key ? valueAt(row, c.key) : '');
        tr.append(h('td', { class: c.class || '' }, value === null || value === undefined ? '' : value));
      }
      if (onRowClick) tr.addEventListener('click', (e) => { if (!e.target.closest('button, a, input')) onRowClick(row); });
      tbody.append(tr);
    }
  }
  tbl.append(thead, tbody);
  wrap.append(tbl);
  return wrap;
}

export function valueAt(obj, path) {
  return path.split('.').reduce((o, k) => (o === null || o === undefined ? undefined : o[k]), obj);
}

export function kv(pairs) {
  const dl = h('dl', { class: 'kv' });
  for (const [k, v] of pairs) {
    if (v === null || v === undefined || v === '') continue;
    dl.append(h('dt', null, k), h('dd', null, v));
  }
  return dl;
}

export function jsonView(value) {
  const text = typeof value === 'string' ? value : JSON.stringify(value, null, 2);
  return h('pre', { class: 'json-view mono' }, text);
}

export function empty(text, iconName = 'info') {
  return h('div', { class: 'empty' }, icon(iconName, 'icon'), h('div', null, text));
}

export function spinner() { return h('span', { class: 'spinner', role: 'status', 'aria-label': 'Loading' }); }

export function panelNote(panel, message, kind = 'danger') {
  if (!panel) return;
  panel.querySelector(':scope > .panel-note')?.remove();
  if (!message) return;
  const box = h('div', { class: `alert panel-note ${kind}`, role: 'alert' }, message);
  const header = panel.querySelector(':scope > .card-header');
  if (header) header.after(box);
  else panel.prepend(box);
}

// Sits under the page heading. A fixed banner covers the heading.
export function pageNote(root, message, kind = 'danger') {
  if (!root) return;
  root.querySelector(':scope > .page-note')?.remove();
  if (!message) return;
  const box = h('div', { class: `alert page-note ${kind}`, role: 'alert' }, message);
  const header = root.querySelector(':scope > .page-header');
  if (header) header.after(box);
  else root.prepend(box);
}

// ---------------------------------------------------------------- toasts
let toastHost = null;
export const toast = {
  show(message, kind = '', ms = 4000) {
    if (!toastHost) { toastHost = h('div', { class: 'toasts' }); document.body.append(toastHost); }
    const el = h('div', { class: 'toast ' + kind, role: 'status' }, message);
    toastHost.append(el);
    setTimeout(() => el.remove(), ms);
  },
  success(m) { toast.show(m, 'success'); },
  error(m) { toast.show(m, 'danger', 6000); },
};

// ---------------------------------------------------------------- drawer
let drawerEl = null;
export const drawer = {
  open({ title, content, width }) {
    drawer.close();
    const backdrop = h('div', { class: 'drawer-backdrop', onClick: () => drawer.close() });
    const panel = h('div', { class: 'drawer', role: 'dialog', 'aria-modal': 'true', 'aria-label': title },
      h('div', { class: 'drawer-header' }, h('h2', null, title), h('button', { class: 'btn ghost sm', 'aria-label': 'Close', onClick: () => drawer.close() }, icon('x'))),
      h('div', { class: 'drawer-body' }, content));
    if (width) panel.style.width = width;
    drawerEl = h('div', null, backdrop, panel);
    document.body.append(drawerEl);
    document.addEventListener('keydown', drawer._esc);
  },
  close() { if (drawerEl) { drawerEl.remove(); drawerEl = null; document.removeEventListener('keydown', drawer._esc); } },
  _esc(e) { if (e.key === 'Escape') drawer.close(); },
};

// ---------------------------------------------------------------- modal
export const modal = {
  /** Shows a modal; resolves with the value passed to close(value) (undefined on cancel). */
  show({ title, content, actions, wide }) {
    return new Promise((resolve) => {
      let root;
      const close = (value) => { root.remove(); document.removeEventListener('keydown', esc); resolve(value); };
      const esc = (e) => { if (e.key === 'Escape') close(undefined); };
      const footer = h('div', { class: 'modal-footer' });
      for (const a of actions || [{ label: 'Close' }]) {
        footer.append(h('button', { class: 'btn ' + (a.kind || ''), type: a.submit ? 'submit' : 'button', onClick: async () => {
          if (a.submit) return;
          if (a.onClick) { const r = await a.onClick(close); if (r === false) return; }
          close(a.value);
        } }, a.label));
      }
      const card = h('div', { class: 'modal-card' + (wide ? ' wide' : '') },
        h('div', { class: 'modal-header' }, h('h2', null, title), h('button', { class: 'btn ghost sm', 'aria-label': 'Close', onClick: () => close(undefined) }, icon('x'))),
        h('div', { class: 'modal-body' }, content), footer);
      root = h('div', null, h('div', { class: 'modal-backdrop', onClick: () => close(undefined) }), h('div', { class: 'modal' }, card));
      document.body.append(root);
      document.addEventListener('keydown', esc);
      card.closeModal = close;
    });
  },
  confirm(title, message, { danger = false, confirmLabel = 'Confirm' } = {}) {
    return modal.show({ title, content: h('p', null, message), actions: [{ label: 'Cancel', value: false }, { label: confirmLabel, kind: danger ? 'danger' : 'primary', value: true }] }).then((v) => v === true);
  },
  /** Prompt with a form; `fields` = [{ name, label, type, value, options, help, required }]. Resolves to values or undefined. */
  form(title, fields, { submitLabel = 'Save', wide = false, onSubmit } = {}) {
    return new Promise((resolve) => {
      const form = h('form', { class: 'col', novalidate: true });
      const inputs = {};
      for (const f of fields) {
        let input;
        if (f.type === 'select') {
          input = dropdown(f.options || [], { value: f.value ?? '', name: f.name, ariaLabel: f.label });
        } else if (f.type === 'checkbox') {
          input = h('input', { type: 'checkbox', name: f.name, checked: !!f.value });
        } else if (f.type === 'textarea') {
          input = h('textarea', { class: 'textarea', name: f.name, value: f.value ?? '' });
        } else {
          input = h('input', { class: 'input', type: f.type || 'text', name: f.name, value: f.value ?? '', placeholder: f.placeholder || '', autocomplete: f.autocomplete || 'off', required: !!f.required });
        }
        input.addEventListener('input', () => input.classList.remove('invalid'));
        inputs[f.name] = input;
        if (f.type === 'checkbox') form.append(h('label', { class: 'checkbox' }, input, h('span', null, f.label)));
        else form.append(h('div', { class: 'field' }, h('label', null, f.label), input, f.help ? h('div', { class: 'help' }, f.help) : null));
      }
      const error = h('div', { class: 'alert danger hidden' });
      form.prepend(error);
      const showFieldError = (name, message) => {
        error.textContent = message;
        error.classList.remove('hidden');
        const input = inputs[name];
        if (!input) return;
        input.classList.add('invalid');
        input.focus();
      };
      let closeFn;
      form.addEventListener('submit', async (e) => {
        e.preventDefault();
        for (const input of Object.values(inputs)) input.classList.remove('invalid');
        const values = {};
        for (const f of fields) values[f.name] = f.type === 'checkbox' ? inputs[f.name].checked : inputs[f.name].value;
        for (const f of fields) {
          if (f.required && !String(values[f.name] ?? '').trim()) {
            showFieldError(f.name, `${f.label} is required.`);
            return;
          }
        }
        for (const f of fields) {
          if (f.type !== 'email') continue;
          const value = String(values[f.name] ?? '').trim();
          values[f.name] = value;
          if (value && !inputs[f.name].checkValidity()) {
            showFieldError(f.name, 'Email is not a valid address.');
            return;
          }
        }
        if (onSubmit) {
          try {
            const result = await onSubmit(values);
            closeFn(result === undefined ? values : result);
          } catch (err) {
            const message = errorMessage(err);
            const emailField = fields.find((f) => f.type === 'email');
            if (emailField && /email/i.test(message)) showFieldError(emailField.name, message);
            else { error.textContent = message; error.classList.remove('hidden'); }
          }
          return;
        }
        closeFn(values);
      });
      modal.show({ title, content: form, wide, actions: [{ label: 'Cancel', value: undefined }, { label: submitLabel, kind: 'primary', onClick: () => { form.requestSubmit(); return false; } }] }).then(resolve);
      closeFn = (v) => { document.querySelector('.modal-card')?.closeModal(v); };
      setTimeout(() => form.querySelector('input:not([type="hidden"]), textarea, .dropdown-button')?.focus(), 30);
    });
  },
};

// ---------------------------------------------------------------- forms
export function formValues(form) {
  const data = {};
  for (const el of form.elements) {
    if (!el.name) continue;
    if (el.type === 'checkbox') data[el.name] = el.checked;
    else if (el.type === 'number') data[el.name] = el.value === '' ? null : Number(el.value);
    else data[el.name] = el.value;
  }
  return data;
}

export function setBusy(button, busy, label) {
  if (busy) { button.dataset.label = button.textContent; button.disabled = true; clear(button).append(spinner(), ' ', label || button.dataset.label); }
  else { button.disabled = false; button.textContent = button.dataset.label || button.textContent; }
}

export function errorMessage(err) {
  if (!err) return 'Something went wrong.';
  if (err.message) return err.message;
  return String(err);
}

export async function copyToClipboard(text, host) {
  const panel = host || document.activeElement?.closest('.col, .card, .drawer-body, .modal-body');
  try {
    await navigator.clipboard.writeText(text);
    panelNote(panel, 'Copied to clipboard.', 'success');
  } catch {
    panelNote(panel, 'Could not copy; select and copy manually.');
  }
}

// ---------------------------------------------------------------- charts (SVG, dependency-free)
const SVG = 'http://www.w3.org/2000/svg';
function svgEl(tag, attrs) { const el = document.createElementNS(SVG, tag); for (const [k, v] of Object.entries(attrs || {})) el.setAttribute(k, v); return el; }

/** Column chart: series = [{ label, values: number[], alt?: bool }], labels = string[] */
export function columnChart({ labels, series, height = 180, maxBars = 48, axis = null }) {
  const svg = svgEl('svg', { class: 'chart', role: 'img' });
  const plot = svgEl('g');
  svg.append(plot);
  let drawn = '';

  const draw = () => {
    const rect = svg.getBoundingClientRect();
    const width = rect.width;
    const hgt = rect.height || height;
    const key = `${width}x${hgt}`;
    if (width < 2 || key === drawn) return;
    drawn = key;
    // Match the element box so glyphs are not stretched. preserveAspectRatio "none" on a
    // fixed viewBox widens the time labels and clips the last one.
    svg.setAttribute('viewBox', `0 0 ${width} ${hgt}`);
    svg.setAttribute('preserveAspectRatio', 'xMinYMin meet');
    while (plot.firstChild) plot.removeChild(plot.firstChild);

    const n = Math.min(labels.length, maxBars);
    const shown = labels.slice(-n);
    const values = series.map((s) => s.values.slice(-n));
    const max = Math.max(1, ...values.flat());
    const measure = (content) => {
      const probe = svgEl('text', { class: 'label' });
      probe.textContent = content;
      plot.append(probe);
      const w = probe.getComputedTextLength() || String(content).length * 6.2;
      probe.remove();
      return w;
    };
    const yLabels = Array.from({ length: 5 }, (_, g) => fmt.number(Math.round((max * g) / 4)));
    const padL = Math.max(28, Math.ceil(Math.max(...yLabels.map(measure)) + 10));
    const padB = 26; const padT = 8; const padR = 4;
    const innerW = Math.max(1, width - padL - padR);
    const innerH = Math.max(1, hgt - padB - padT);
    const slot = innerW / Math.max(n, 1);
    const barW = Math.max(1, (slot - 2) / Math.max(series.length, 1));

    for (let g = 0; g <= 4; g++) {
      const y = padT + innerH - (innerH * g) / 4;
      plot.append(svgEl('line', { class: 'axis', x1: padL, x2: width - padR, y1: y, y2: y, 'stroke-dasharray': g === 0 ? '' : '2 4' }));
      const t = svgEl('text', { class: 'label', x: padL - 6, y, 'text-anchor': 'end', 'dominant-baseline': 'middle' });
      t.textContent = yLabels[g];
      plot.append(t);
    }

    shown.forEach((label, i) => {
      series.forEach((s, si) => {
        const v = values[si][i] || 0;
        const bh = (v / max) * innerH;
        const bar = svgEl('rect', { class: 'bar' + (s.alt ? ' alt' : ''), x: padL + i * slot + si * barW + 1, y: padT + innerH - bh, width: Math.max(barW - 1, 0.5), height: bh, rx: 1.5 });
        const title = svgEl('title'); title.textContent = `${label}: ${fmt.number(v)} ${s.label}`; bar.append(title);
        plot.append(bar);
      });
    });

    const axisShown = Array.isArray(axis) ? axis.slice(-n) : null;
    const marked = [];
    if (axisShown) shown.forEach((_, i) => { if (axisShown[i]) marked.push(i); });
    const idxs = [];
    if (marked.length) idxs.push(...marked);
    else {
      const step = Math.max(1, Math.ceil(n / 8));
      for (let i = 0; i < n; i += step) idxs.push(i);
    }
    const placed = [];
    const tryPlace = (i, edge) => {
      const label = shown[i];
      const tw = measure(label);
      let anchor = 'middle';
      let x = padL + i * slot + slot / 2;
      if (edge === 'start' || x - tw / 2 < padL) { anchor = 'start'; x = padL + i * slot; }
      if (edge === 'end' || x + tw / 2 > width - 2) { anchor = 'end'; x = Math.min(width - 2, padL + (i + 1) * slot); }
      const left = anchor === 'start' ? x : anchor === 'end' ? x - tw : x - tw / 2;
      const right = left + tw;
      if (right > width + 0.5 || left < -0.5) return;
      if (placed.some((p) => left < p.right + 8 && right > p.left - 8)) return;
      placed.push({ left, right });
      const t = svgEl('text', { class: 'label', x, y: hgt - 6, 'text-anchor': anchor });
      t.textContent = label;
      plot.append(t);
    };
    if (idxs.length) tryPlace(idxs[0], 'start');
    if (idxs.length > 1) tryPlace(idxs[idxs.length - 1], 'end');
    for (let k = 1; k < idxs.length - 1; k++) tryPlace(idxs[k]);
  };

  const ro = new ResizeObserver(() => {
    if (!svg.isConnected) { ro.disconnect(); return; }
    draw();
  });
  ro.observe(svg);
  return svg;
}

/** Horizontal bar list for "top N" data: items = [{ key, count }] */
export function barList(items, { alt = false, onClick } = {}) {
  const max = Math.max(1, ...items.map((i) => i.count));
  const root = h('div', { class: 'bars' });
  for (const item of items) {
    const fill = h('div', { class: 'fill' + (alt ? ' alt' : '') });
    fill.style.width = `${(100 * item.count) / max}%`;
    const row = h('div', { class: 'row' + (onClick ? ' clickable' : '') },
      h('div', null, h('div', { class: 'truncate', title: item.key }, item.key || '(empty)'), h('div', { class: 'track' }, fill)),
      h('div', { class: 'right mono' }, fmt.number(item.count)));
    if (onClick) row.addEventListener('click', () => onClick(item));
    root.append(row);
  }
  if (items.length === 0) root.append(h('div', { class: 'muted small' }, 'No data'));
  return root;
}

// ---------------------------------------------------------------- dropdown
// Themed listbox. Native <select> menus cannot be styled, and their arrow sits on the border.
function dropdownOptions(options) {
  return (options || []).map((o) => Array.isArray(o)
    ? { value: String(o[0]), label: String(o[1] ?? o[0]) }
    : { value: String(o.value ?? ''), label: String(o.label ?? o.value ?? '') });
}

let closeOpenDropdown = null;

export function dropdown(options, { value, ariaLabel, name, disabled = false } = {}) {
  const items = dropdownOptions(options);
  let current = value === undefined || value === null ? '' : String(value);
  if (!items.some((o) => o.value === current)) current = items[0]?.value ?? '';
  let activeIndex = 0;
  let raf = 0;
  let typeBuf = '';
  let typeTimer = 0;

  const label = h('span', { class: 'dropdown-label' });
  const button = h('button', {
    type: 'button',
    class: 'dropdown-button',
    'aria-haspopup': 'listbox',
    'aria-expanded': 'false',
    'aria-label': ariaLabel || undefined,
    disabled: !!disabled,
  }, label);
  const menu = h('div', { class: 'dropdown-menu', role: 'listbox', hidden: true });
  menu.id = 'dd-' + Math.random().toString(36).slice(2, 9);
  button.setAttribute('aria-controls', menu.id);
  const hidden = name ? h('input', { type: 'hidden', name, value: current }) : null;
  const root = h('div', { class: 'dropdown' }, button, hidden);

  const paint = () => {
    label.textContent = items.find((o) => o.value === current)?.label ?? '';
    if (hidden) hidden.value = current;
  };

  const renderMenu = () => {
    clear(menu);
    if (items.length === 0) {
      menu.append(h('div', { class: 'dropdown-empty' }, 'No options'));
      return;
    }
    items.forEach((o, i) => {
      menu.append(h('button', {
        type: 'button',
        class: 'dropdown-option' + (o.value === current ? ' selected' : ''),
        role: 'option',
        tabindex: '-1',
        'aria-selected': o.value === current ? 'true' : 'false',
        onClick: (e) => { e.preventDefault(); choose(i); },
        onMouseEnter: () => mark(i, false),
      }, o.label));
    });
  };

  const mark = (index, scroll) => {
    activeIndex = index;
    const opts = menu.querySelectorAll('.dropdown-option');
    opts.forEach((el, i) => el.classList.toggle('active', i === index));
    if (scroll) opts[index]?.scrollIntoView({ block: 'nearest' });
  };

  const place = () => {
    const rect = button.getBoundingClientRect();
    const vw = window.innerWidth;
    const vh = window.innerHeight;
    menu.style.maxWidth = Math.min(420, vw - 16) + 'px';
    menu.style.minWidth = rect.width + 'px';
    const width = Math.min(menu.offsetWidth, vw - 16);
    let left = rect.left;
    if (left + width > vw - 8) left = Math.max(8, vw - 8 - width);
    menu.style.left = left + 'px';
    const spaceBelow = vh - rect.bottom - 8;
    const spaceAbove = rect.top - 8;
    const natural = menu.scrollHeight;
    const openUp = spaceBelow < Math.min(natural, 160) && spaceAbove > spaceBelow;
    const maxH = Math.max(80, Math.min(320, openUp ? spaceAbove : spaceBelow));
    menu.style.maxHeight = maxH + 'px';
    const shown = Math.min(natural, maxH);
    menu.style.top = (openUp ? Math.max(8, rect.top - 4 - shown) : rect.bottom + 4) + 'px';
  };

  const close = () => {
    if (menu.hidden && !menu.isConnected) return;
    menu.hidden = true;
    menu.remove();
    button.setAttribute('aria-expanded', 'false');
    root.classList.remove('open');
    cancelAnimationFrame(raf);
    document.removeEventListener('pointerdown', onDoc, true);
    document.removeEventListener('keydown', onKey, true);
    if (closeOpenDropdown === close) closeOpenDropdown = null;
  };

  const watch = () => {
    if (!root.classList.contains('open')) return;
    if (!button.isConnected) { close(); return; }
    place();
    raf = requestAnimationFrame(watch);
  };

  const open = () => {
    if (button.disabled) return;
    if (closeOpenDropdown && closeOpenDropdown !== close) closeOpenDropdown();
    renderMenu();
    menu.hidden = false;
    document.body.append(menu);
    button.setAttribute('aria-expanded', 'true');
    root.classList.add('open');
    activeIndex = Math.max(0, items.findIndex((o) => o.value === current));
    mark(activeIndex, true);
    closeOpenDropdown = close;
    document.addEventListener('pointerdown', onDoc, true);
    document.addEventListener('keydown', onKey, true);
    watch();
  };

  const choose = (index) => {
    const next = items[index];
    const changed = next && next.value !== current;
    if (next) current = next.value;
    paint();
    close();
    button.focus();
    if (!changed) return;
    root.dispatchEvent(new Event('input', { bubbles: true }));
    root.dispatchEvent(new Event('change', { bubbles: true }));
  };

  function onDoc(e) {
    if (root.contains(e.target) || menu.contains(e.target)) return;
    close();
  }

  function onKey(e) {
    if (menu.hidden) return;
    if (e.key === 'Escape') { e.preventDefault(); e.stopPropagation(); close(); button.focus(); return; }
    if (e.key === 'Tab') { close(); return; }
    if (e.key === 'ArrowDown') { e.preventDefault(); e.stopPropagation(); mark(Math.min(items.length - 1, activeIndex + 1), true); return; }
    if (e.key === 'ArrowUp') { e.preventDefault(); e.stopPropagation(); mark(Math.max(0, activeIndex - 1), true); return; }
    if (e.key === 'Home') { e.preventDefault(); mark(0, true); return; }
    if (e.key === 'End') { e.preventDefault(); mark(Math.max(0, items.length - 1), true); return; }
    if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); e.stopPropagation(); choose(activeIndex); return; }
    if (e.key.length === 1 && !e.altKey && !e.ctrlKey && !e.metaKey) {
      typeBuf += e.key.toLowerCase();
      clearTimeout(typeTimer);
      typeTimer = setTimeout(() => { typeBuf = ''; }, 600);
      const start = (activeIndex + 1) % Math.max(items.length, 1);
      const order = items.map((_, i) => i).slice(start).concat(items.map((_, i) => i).slice(0, start));
      const hit = order.find((i) => items[i].label.toLowerCase().startsWith(typeBuf));
      if (hit !== undefined) mark(hit, true);
    }
  }

  button.addEventListener('click', () => { if (menu.hidden) open(); else close(); });
  button.addEventListener('keydown', (e) => {
    if (e.altKey || e.ctrlKey || e.metaKey || !menu.hidden) return;
    if (e.key === 'ArrowDown' || e.key === 'ArrowUp' || e.key === 'Enter' || e.key === ' ') {
      e.preventDefault();
      open();
    }
  });

  paint();

  Object.defineProperty(root, 'value', {
    get() { return current; },
    set(v) {
      const next = v === undefined || v === null ? '' : String(v);
      current = items.some((o) => o.value === next) ? next : (items[0]?.value ?? '');
      paint();
    },
  });
  Object.defineProperty(root, 'disabled', {
    get() { return button.disabled; },
    set(v) { button.disabled = !!v; if (v) close(); },
  });
  root.setOptions = (next, selected) => {
    const want = selected === undefined || selected === null ? current : String(selected);
    items.splice(0, items.length, ...dropdownOptions(next));
    current = items.some((o) => o.value === want) ? want : (items[0]?.value ?? '');
    paint();
    if (!menu.hidden) { renderMenu(); mark(Math.max(0, items.findIndex((o) => o.value === current)), false); }
  };
  root.focus = () => button.focus();
  return root;
}

export const ui = { h, append, clear, icon, badge, fmt, table, kv, jsonView, empty, spinner, toast, panelNote, pageNote, drawer, modal, dropdown, formValues, setBusy, errorMessage, copyToClipboard, columnChart, barList, valueAt };
export default ui;
