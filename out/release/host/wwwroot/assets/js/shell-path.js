// Core pages are exact paths. A bookmark such as /#/alerts/ must not become a missing /alerts/.
export function canonicalShellPath(path) {
  if (typeof path !== 'string' || path === '' || path === '/') return '/';
  const trimmed = path.replace(/\/+$/, '');
  if (trimmed === '') return '/';
  return trimmed.startsWith('/') ? trimmed : `/${trimmed}`;
}
