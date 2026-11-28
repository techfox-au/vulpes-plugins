// Dashboard installation only. Public invoice pages do not load this file.
const path = typeof location === 'undefined' ? '' : location.pathname;
const invoice = path.startsWith('/plugins/psa/public')
  || path.startsWith('/plugins/psa/card')
  || path.startsWith('/plugins/psa/preview')
  || path.startsWith('/plugins/psa/print');

if (!invoice && typeof navigator !== 'undefined' && 'serviceWorker' in navigator) {
  navigator.serviceWorker.register('/sw.js').catch(() => {});
}

// The bar colour is #000000 for every dark theme. The theme id keeps those cache keys apart.
export function manifestQuery(themeId, bar) {
  const id = String(themeId ?? '').trim();
  const colour = String(bar ?? '').replace(/^#/, '').toLowerCase();
  return 'v=' + id + '-' + colour;
}

function paintThemeColor() {
  if (invoice || typeof document === 'undefined') return;
  const bar = getComputedStyle(document.documentElement).colorScheme === 'light' ? '#ffffff' : '#000000';
  let meta = document.querySelector('meta[name="theme-color"]');
  if (!meta) {
    meta = document.createElement('meta');
    meta.setAttribute('name', 'theme-color');
    document.head.append(meta);
  }
  meta.setAttribute('content', bar);
  const themeId = getComputedStyle(document.documentElement).getPropertyValue('--theme-id').trim();
  const query = manifestQuery(themeId, bar);
  const manifest = document.querySelector('link[rel="manifest"]');
  if (manifest) manifest.href = '/manifest.webmanifest?' + query;
  document.querySelectorAll('link[rel="apple-touch-icon"]').forEach((icon) => {
    const iconPath = icon.getAttribute('href')?.split('?')[0];
    if (iconPath) icon.setAttribute('href', iconPath + '?' + query);
  });
}

if (typeof document !== 'undefined') {
  if (document.readyState === 'complete') paintThemeColor();
  else window.addEventListener('load', paintThemeColor);
  document.querySelector('link[rel="stylesheet"][href^="/theme.css"]')?.addEventListener('load', paintThemeColor);
}
