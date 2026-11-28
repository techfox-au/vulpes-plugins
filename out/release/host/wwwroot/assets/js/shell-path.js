import { safeReturnUrl } from './return-url.js';

const CORE_PATHS = new Set(['/', '/account', '/alerts', '/admin/users', '/admin/plugins', '/admin/settings', '/admin/audit', '/admin/console']);

// Core pages are exact paths. A bookmark such as /#/alerts/ must not become a missing /alerts/.
// The server matches /Alerts. The shell table is lowercase, so a core path is rewritten to that key.
export function canonicalShellPath(path) {
  if (typeof path !== 'string' || path === '' || path === '/') return '/';
  const trimmed = path.replace(/\/+$/, '');
  if (trimmed === '') return '/';
  const absolute = trimmed.startsWith('/') ? trimmed : `/${trimmed}`;
  const lower = absolute.toLowerCase();
  return CORE_PATHS.has(lower) ? lower : absolute;
}

// Old bookmarks used /#/alerts. #//host is another origin. A backslash is a slash here,
// so #/\host would also leave this origin and must stay on Home.
export function legacyHashPath(hash) {
  if (typeof hash !== 'string' || !hash.startsWith('#/')) return '';
  const next = hash.slice(1).replaceAll('\\', '/');
  if (!next.startsWith('/') || next.startsWith('//')) return '';
  // #/.//evil.com/ and #/foo/..//evil.com/ parse as another origin. Keep the same rules as a return URL.
  const safe = safeReturnUrl(next);
  if (!safe.startsWith('/') || safe.startsWith('//')) return '';
  try {
    if (new URL(safe, 'https://return.invalid').pathname.startsWith('//')) return '';
  } catch {
    return '';
  }
  return safe;
}

// Hash-only navigations never hit popstate. An empty result means do not route again.
export function hashChangeTarget(hash) {
  return legacyHashPath(hash);
}
