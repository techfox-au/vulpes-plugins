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
  return bare.split('.').every((label) => label.length > 0 && !/\s/.test(label));
}

function domainOrLiteral(domain) {
  if (domain.startsWith('[') && domain.endsWith(']')) {
    const inner = domain.slice(1, -1);
    if (/^IPv6:/i.test(inner)) return inner.slice(5).includes(':');
    return /^\d{1,3}(?:\.\d{1,3}){3}$/.test(inner);
  }
  return domainLabels(domain);
}

/** The same addresses MailAddress accepts for one field, including a domain literal, a quoted local part, and non-ASCII text. */
export function mailAddressShape(value) {
  const text = String(value ?? '').trim();
  if (!text || text.length > 254 || text.includes('\n') || text.includes('\r')) return false;
  const quoted = /^"((?:[^"\\]|\\.)*)"@(\[[^\]]+\]|\S+)$/.exec(text);
  if (quoted) return domainOrLiteral(quoted[2]);
  if (/\s/.test(text) || /[(),:;<>\\]/.test(text)) return false;
  const at = text.indexOf('@');
  if (at <= 0 || at !== text.lastIndexOf('@') || at === text.length - 1) return false;
  const local = text.slice(0, at);
  const domain = text.slice(at + 1);
  if (local.startsWith('.') || local.includes('..')) return false;
  if (!domain.startsWith('[') && !/^[\p{L}\p{N}!#$%&'*+/=?^_`{|}~.-]+$/u.test(local)) return false;
  return domainOrLiteral(domain);
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
