export function isHomeLink(href, path) {
  return path === '/' && href === '/';
}

/** The secrets item opens the home panel. Replacing that history entry keeps Back on the page before it. */
export function secretsEntry(pluginId, page) {
  if (pluginId === 'secret-sharing' && page === 'secrets') return { path: '/?panel=secrets', replace: true };
  return null;
}

function lastQueryValue(search, name) {
  const values = new URLSearchParams(search || '').getAll(name);
  return values.length === 0 ? null : values[values.length - 1];
}

/** Secrets opens on the home page with ?panel=secrets. That item stays highlighted, and Home does not. */
export function navLinkActive(href, path, search) {
  const secretsHome = path === '/' && lastQueryValue(search, 'panel') === 'secrets';
  return secretsHome ? href === '/p/secret-sharing/secrets' : (isHomeLink(href, path) || href === path);
}
