// Commas inside quotes or angle brackets belong to one mailbox. "Doe, Jane" <jane@example.com> is one address.
export function splitMailboxList(value) {
  const text = String(value ?? '');
  const parts = [];
  let current = '';
  let quote = '';
  let angle = 0;
  for (const ch of text) {
    if (quote) {
      current += ch;
      if (ch === quote) quote = '';
      continue;
    }
    if (ch === '"') {
      quote = ch;
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
      const item = current.trim();
      if (item) parts.push(item);
      current = '';
      continue;
    }
    current += ch;
  }
  const last = current.trim();
  if (last) parts.push(last);
  return parts;
}

// A revealed secret is stored as typed. Spaces are part of it. Only an empty field removes it.
export function secretPayload(value, { readOnly = false, revealed = false, mask = '' } = {}) {
  if (readOnly) return { secret: '', remove: false };
  const text = value ?? '';
  if (text === mask) return { secret: '', remove: false };
  return { secret: text, remove: revealed === true && text.length === 0 };
}
