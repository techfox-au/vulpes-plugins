// Core pages are exact paths. A bookmark such as /#/alerts/ must not become a missing /alerts/.
export function canonicalShellPath(path) {
  if (typeof path !== 'string' || path === '' || path === '/') return '/';
  const trimmed = path.replace(/\/+$/, '');
  if (trimmed === '') return '/';
  return trimmed.startsWith('/') ? trimmed : `/${trimmed}`;
}

// Old bookmarks used /#/alerts. #//host is another origin. A backslash is a slash here,
// so #/\host would also leave this origin and must stay on Home.
export function legacyHashPath(hash) {
  if (typeof hash !== 'string' || !hash.startsWith('#/')) return '';
  const next = hash.slice(1).replaceAll('\\', '/');
  if (!next.startsWith('/') || next.startsWith('//')) return '';
  return next;
}

// Hash-only navigations never hit popstate. An empty result means do not route again.
export function hashChangeTarget(hash) {
  return legacyHashPath(hash);
}
