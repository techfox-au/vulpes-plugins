// A return path stays on this host. Browsers drop tab, newline, and carriage return
// before parsing, so "/\\t/evil.com" would otherwise become https://evil.com/.
export function safeReturnUrl(url) {
  if (!url || !url.startsWith('/')) return '/';
  let parsed;
  try {
    parsed = new URL(url, 'https://return.invalid');
  } catch {
    return '/';
  }
  if (parsed.origin !== 'https://return.invalid' || parsed.username || parsed.password) return '/';
  const path = parsed.pathname + parsed.search + parsed.hash;
  // "/.//evil.com" parses as this host with pathname "//evil.com". Assigning that leaves the host.
  if (!path.startsWith('/') || path.startsWith('//') || path.startsWith('/\\')) return '/';
  let again;
  try {
    again = new URL(path, 'https://return.invalid');
  } catch {
    return '/';
  }
  if (again.origin !== 'https://return.invalid') return '/';
  return path;
}
