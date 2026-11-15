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
  const bg = getComputedStyle(document.documentElement).getPropertyValue('--bg').trim();
  if (!bg || invoice) return;
  let meta = document.querySelector('meta[name="theme-color"]');
  if (!meta) {
    meta = document.createElement('meta');
    meta.setAttribute('name', 'theme-color');
    document.head.append(meta);
  }
  meta.setAttribute('content', bg);
}

if (document.readyState === 'complete') paintThemeColor();
else window.addEventListener('load', paintThemeColor);
