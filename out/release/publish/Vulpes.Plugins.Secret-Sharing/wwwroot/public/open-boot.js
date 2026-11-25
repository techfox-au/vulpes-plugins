/**
 * Moves a secret link onto a document whose address never contained the fragment.
 * The navigation timing record keeps the URL that created the document, and
 * history.replaceState does not rewrite it. The key crosses that load only in
 * window.name, and this script clears that immediately.
 */
(function () {
  "use strict";
  var prefix = "vulpes-sk-handoff:";
  var hash = location.hash || "";
  if (hash.length > 1) {
    try { window.name = prefix + hash; } catch (err) { window.name = ""; }
    location.replace(location.pathname + location.search);
    return;
  }
  var handed = "";
  try { handed = window.name || ""; } catch (err) { handed = ""; }
  if (handed.indexOf(prefix) === 0) {
    window.__vulpesFragment = handed.slice(prefix.length);
    try { window.name = ""; } catch (err) { /* name can be blocked */ }
  }
})();
