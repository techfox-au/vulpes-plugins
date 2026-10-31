/** Same allow-list checks as Sendit app.js parseAllowedCidr. */
(function (global) {
  "use strict";
  var MAX_CIDR_INPUT = 5000000;
  var MAX_CIDR_ENTRIES = 250000;

  function parseAllowedCidr(input) {
    if (input == null) return { ok: true, value: null };
    var s = String(input).trim();
    if (!s) return { ok: true, value: null };
    if (s.length > MAX_CIDR_INPUT) return { ok: false, error: "Allowed IP/CIDR list is too long." };
    if (s.indexOf("%") >= 0) return { ok: false, error: "IPv6 zone identifiers are not allowed." };
    var rawParts = s.split(",");
    var parts = [];
    for (var r = 0; r < rawParts.length; r++) {
      var t = rawParts[r].trim();
      if (t) parts.push(t);
    }
    if (!parts.length) return { ok: true, value: null };
    for (var w = 0; w < parts.length; w++) if (parts[w] === "*") return { ok: true, value: "*" };
    if (parts.length > MAX_CIDR_ENTRIES) return { ok: false, error: "At most " + MAX_CIDR_ENTRIES + " IP/CIDR entries are allowed." };
    var normalized = [];
    var seen = Object.create(null);
    for (var i = 0; i < parts.length; i++) {
      var part = parts[i];
      if (/\s/.test(part)) return { ok: false, error: "Entry " + (i + 1) + ": IP/CIDR must not contain spaces." };
      var one = parseAllowedCidrOne(part);
      if (!one.ok) return { ok: false, error: "Entry " + (i + 1) + ": " + one.error };
      var key = one.value.toLowerCase();
      if (!seen[key]) { seen[key] = true; normalized.push(one.value); }
    }
    return { ok: true, value: normalized.join(",") };
  }

  function parseAllowedCidrOne(s) {
    var slash = s.indexOf("/");
    if (slash < 0) {
      var hostOnly = parseStrictIp(s);
      if (!hostOnly.ok) return hostOnly;
      return { ok: true, value: hostOnly.canonical };
    }
    if (s.split("/").length !== 2) return { ok: false, error: "CIDR must contain exactly one '/'." };
    var hostPart = s.slice(0, slash);
    var prefixPart = s.slice(slash + 1);
    if (!hostPart || !prefixPart) return { ok: false, error: "CIDR must be address/prefix (e.g. 192.168.0.0/24)." };
    if (!/^\d+$/.test(prefixPart)) return { ok: false, error: "CIDR prefix must be a decimal integer." };
    var prefix = parseInt(prefixPart, 10);
    var host = parseStrictIp(hostPart);
    if (!host.ok) return host;
    var maxPrefix = host.family === 4 ? 32 : 128;
    if (prefix < 0 || prefix > maxPrefix) {
      return { ok: false, error: host.family === 4 ? "IPv4 CIDR prefix must be between 0 and 32." : "IPv6 CIDR prefix must be between 0 and 128." };
    }
    return { ok: true, value: host.canonical + "/" + prefix };
  }

  function parseStrictIp(host) {
    if (host.indexOf(":") >= 0) return parseStrictIPv6(host);
    return parseStrictIPv4(host);
  }

  function parseStrictIPv4(host) {
    var parts = host.split(".");
    if (parts.length !== 4) return { ok: false, error: "Invalid IPv4 address." };
    var bytes = [];
    for (var i = 0; i < 4; i++) {
      if (!/^\d{1,3}$/.test(parts[i])) return { ok: false, error: "Invalid IPv4 address." };
      var n = parseInt(parts[i], 10);
      if (n > 255 || String(n) !== parts[i]) return { ok: false, error: "Invalid IPv4 address (use dotted decimal, e.g. 192.168.1.1)." };
      bytes.push(n);
    }
    return { ok: true, family: 4, bytes: bytes, canonical: bytes.join(".") };
  }

  function parseStrictIPv6(host) {
    if (host.indexOf(".") >= 0) return { ok: false, error: "Use a plain IPv4 address, not an IPv4-mapped IPv6 form." };
    if (!/^[0-9A-Fa-f:]+$/.test(host)) return { ok: false, error: "Invalid IPv6 address." };
    var dbl = host.indexOf("::");
    if (dbl !== host.lastIndexOf("::")) return { ok: false, error: "Invalid IPv6 address." };
    var head, tail;
    if (dbl >= 0) {
      head = host.slice(0, dbl) ? host.slice(0, dbl).split(":") : [];
      tail = host.slice(dbl + 2) ? host.slice(dbl + 2).split(":") : [];
    } else {
      head = host.split(":");
      tail = [];
    }
    if (head.length + tail.length > 8) return { ok: false, error: "Invalid IPv6 address." };
    if (dbl < 0 && head.length !== 8) return { ok: false, error: "Invalid IPv6 address." };
    var mid = dbl >= 0 ? 8 - head.length - tail.length : 0;
    if (dbl >= 0 && mid <= 0 && !(head.length + tail.length < 8)) return { ok: false, error: "Invalid IPv6 address." };
    var groups = [];
    function pushGroup(g) {
      if (!g || !/^[0-9A-Fa-f]{1,4}$/.test(g)) return false;
      groups.push(parseInt(g, 16));
      return true;
    }
    for (var i = 0; i < head.length; i++) if (!pushGroup(head[i])) return { ok: false, error: "Invalid IPv6 address." };
    for (var z = 0; z < mid; z++) groups.push(0);
    for (var j = 0; j < tail.length; j++) if (!pushGroup(tail[j])) return { ok: false, error: "Invalid IPv6 address." };
    if (groups.length !== 8) return { ok: false, error: "Invalid IPv6 address." };
    return { ok: true, family: 6, bytes: [], canonical: compressIPv6(groups) };
  }

  function compressIPv6(groups) {
    var bestStart = -1;
    var bestLen = 0;
    var i = 0;
    while (i < 8) {
      if (groups[i] !== 0) { i++; continue; }
      var j = i;
      while (j < 8 && groups[j] === 0) j++;
      var len = j - i;
      if (len > bestLen) { bestStart = i; bestLen = len; }
      i = j;
    }
    var parts = [];
    i = 0;
    while (i < 8) {
      if (bestLen >= 2 && i === bestStart) {
        parts.push("");
        if (i === 0) parts.push("");
        i += bestLen;
        if (i >= 8) parts.push("");
        continue;
      }
      parts.push(groups[i].toString(16));
      i++;
    }
    return parts.join(":").replace(/^:$/, "::");
  }

  global.SecretCidr = { parseAllowedCidr: parseAllowedCidr };
})(typeof window !== "undefined" ? window : globalThis);
