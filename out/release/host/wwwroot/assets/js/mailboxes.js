// A comma separates addresses. jane@example.com, bob@example.com is two addresses, with or without a space.
// Text outside <address> is not an address. Bob <bob@example.com>, Jane <jane@example.com> is those two addresses.
export function splitMailboxList(value) {
  const text = String(value ?? '');
  const addresses = [];
  let current = '';
  let quote = false;
  let angle = 0;
  const flush = () => {
    const token = current.trim();
    current = '';
    if (!token) return;
    const open = token.indexOf('<');
    const close = token.lastIndexOf('>');
    const candidate = open !== -1 && close > open ? token.slice(open + 1, close).trim() : token;
    if (isMailbox(candidate)) addresses.push(candidate);
  };
  for (const ch of text) {
    if (quote) {
      current += ch;
      if (ch === '"') quote = false;
      continue;
    }
    if (ch === '"') {
      quote = true;
      current += ch;
      continue;
    }
    if (ch === '<') {
      angle += 1;
      current += ch;
      continue;
    }
    if (ch === '>') {
      if (angle > 0) angle -= 1;
      current += ch;
      continue;
    }
    if (ch === ',' && angle === 0) {
      flush();
      continue;
    }
    current += ch;
  }
  flush();
  return addresses;
}

function domainLabels(domain) {
  const bare = domain.endsWith('.') ? domain.slice(0, -1) : domain;
  if (!bare || bare.startsWith('.') || bare.endsWith('.') || bare.includes('..')) return false;
  return bare.split('.').every((label) => /^[A-Za-z0-9_](?:[A-Za-z0-9_-]*[A-Za-z0-9_])?$/.test(label) || /^[A-Za-z0-9_]$/.test(label));
}

/** The same addresses MailAddress accepts for a single field: a trailing dot is kept, a semicolon is not. */
export function mailAddressShape(value) {
  const text = String(value ?? '').trim();
  if (!text || text.length > 254 || /\s/.test(text)) return false;
  const quoted = /^"(?:[^"\\]|\\.)+"@([^@]+)$/.exec(text);
  if (quoted) return domainLabels(quoted[1]);
  if (/[(),:;<>[\]\\]/.test(text)) return false;
  const at = text.indexOf('@');
  if (at <= 0 || at !== text.lastIndexOf('@') || at === text.length - 1) return false;
  const local = text.slice(0, at);
  if (local.startsWith('.') || local.includes('..')) return false;
  if (!/^[A-Za-z0-9!#$%&'*+/=?^_`{|}~.-]+$/.test(local)) return false;
  return domainLabels(text.slice(at + 1));
}

function rawMailboxTokens(value) {
  const tokens = [];
  let current = '';
  let quote = false;
  let angle = 0;
  const flush = () => {
    const token = current.trim();
    current = '';
    if (token) tokens.push(token);
  };
  for (const ch of String(value ?? '')) {
    if (quote) {
      current += ch;
      if (ch === '"') quote = false;
      continue;
    }
    if (ch === '"') { quote = true; current += ch; continue; }
    if (ch === '<') { angle += 1; current += ch; continue; }
    if (ch === '>') { if (angle > 0) angle -= 1; current += ch; continue; }
    if (ch === ',' && angle === 0) { flush(); continue; }
    current += ch;
  }
  flush();
  return tokens;
}

/** Blank means the default recipients. Typed text that is not an address is rejected. */
export function mailboxListError(value) {
  const text = String(value ?? '').trim();
  if (!text) return '';
  const tokens = rawMailboxTokens(text);
  const hasAngles = tokens.some((token) => token.includes('<'));
  let valid = 0;
  for (const token of tokens) {
    const open = token.indexOf('<');
    const close = token.lastIndexOf('>');
    if (open !== -1 && close > open) {
      if (!mailAddressShape(token.slice(open + 1, close).trim())) return 'Email is not a valid address.';
      valid += 1;
      continue;
    }
    if (!token.includes('@')) {
      if (!hasAngles) return 'Email is not a valid address.';
      continue;
    }
    if (!mailAddressShape(token)) return 'Email is not a valid address.';
    valid += 1;
  }
  return valid === 0 ? 'Email is not a valid address.' : '';
}

function isMailbox(value) {
  return mailAddressShape(value);
}

// A revealed secret is stored as typed. Spaces are part of it. Only an empty field removes it.
export function secretPayload(value, { readOnly = false, revealed = false, mask = '' } = {}) {
  if (readOnly) return { secret: '', remove: false };
  const text = value ?? '';
  if (text === mask) return { secret: '', remove: false };
  return { secret: text, remove: revealed === true && text.length === 0 };
}
