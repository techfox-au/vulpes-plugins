// Which condition rows the alert editor draws after a source or plugin change.
export function nextConditions(existing, saved, touched, replace) {
  if (replace) return [];
  if (existing.length) return existing;
  return touched ? [] : (saved || []);
}
