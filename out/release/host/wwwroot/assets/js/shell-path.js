// Core pages are exact paths. A bookmark such as /#/alerts/ must not become a missing /alerts/.
export function canonicalShellPath(path) {
  if (typeof path !== 'string' || path === '' || path === '/') return '/';
  const trimmed = path.replace(/\/+$/, '');
  if (trimmed === '') return '/';
  return trimmed.startsWith('/') ? trimmed : `/${trimmed}`;
}

// Old bookmarks used /#/alerts. #//host is another origin, so it must stay on Home.
export function legacyHashPath(hash) {
  if (typeof hash !== 'string' || !hash.startsWith('#/')) return '';
  const next = hash.slice(1);
  if (!next.startsWith('/') || next.startsWith('//')) return '';
  return next;
}
