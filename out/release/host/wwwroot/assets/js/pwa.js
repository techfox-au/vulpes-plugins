// Dashboard installation only. Public invoice pages do not load this file.
const path = location.pathname;
const invoice = path.startsWith('/plugins/psa/public')
  || path.startsWith('/plugins/psa/card')
  || path.startsWith('/plugins/psa/preview')
  || path.startsWith('/plugins/psa/print');

if (!invoice && 'serviceWorker' in navigator) {
  navigator.serviceWorker.register('/sw.js').catch(() => {});
}

function paintThemeColor() {
  if (invoice) return;
  const bar = getComputedStyle(document.documentElement).colorScheme === 'light' ? '#ffffff' : '#000000';
  let meta = document.querySelector('meta[name="theme-color"]');
  if (!meta) {
    meta = document.createElement('meta');
    meta.setAttribute('name', 'theme-color');
    document.head.append(meta);
  }
  meta.setAttribute('content', bar);
  const manifest = document.querySelector('link[rel="manifest"]');
  if (manifest) manifest.href = '/manifest.webmanifest?v=' + bar.slice(1);
}

if (document.readyState === 'complete') paintThemeColor();
else window.addEventListener('load', paintThemeColor);
document.querySelector('link[rel="stylesheet"][href^="/theme.css"]')?.addEventListener('load', paintThemeColor);
