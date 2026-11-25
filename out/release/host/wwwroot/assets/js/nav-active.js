export function isHomeLink(href, path) {
  return path === '/' && href === '/';
}

/** Secrets opens on the home page with ?panel=secrets. That item stays highlighted, and Home does not. */
export function navLinkActive(href, path, search) {
  const secretsHome = path === '/' && new URLSearchParams(search || '').get('panel') === 'secrets';
  return secretsHome ? href === '/p/secret-sharing/secrets' : (isHomeLink(href, path) || href === path);
}
