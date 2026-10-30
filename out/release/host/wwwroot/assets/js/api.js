// Fetch wrapper used by the shell and by module pages (through ctx.api).
// - same-origin, credentials: cookies
// - CSRF token from /api/session sent as X-CSRF-TOKEN on unsafe methods; refreshed once on a csrf failure
// - 401 on an authenticated page -> redirect to /login with a safe returnUrl

export class ApiError extends Error {
  constructor(status, code, message, body) {
    super(message || code || `HTTP ${status}`);
    this.status = status;
    this.code = code;
    this.body = body;
  }
}

let csrfToken = null;
let sessionCache = null;
let redirectOnUnauthorized = true;

export function setRedirectOnUnauthorized(value) { redirectOnUnauthorized = value; }

export async function session(force = false) {
  if (sessionCache && !force) return sessionCache;
  const res = await fetch('/api/session', { credentials: 'same-origin', headers: { Accept: 'application/json' } });
  const data = await res.json();
  csrfToken = data.csrfToken;
  sessionCache = data;
  return data;
}

export function invalidateSession() { sessionCache = null; csrfToken = null; }

async function ensureCsrf() {
  if (!csrfToken) await session(true);
  return csrfToken;
}

function safeReturnUrl() {
  const path = location.pathname + location.search + location.hash;
  return path.startsWith('/') && !path.startsWith('//') ? path : '/';
}

export function redirectToLogin() {
  location.assign('/login?returnUrl=' + encodeURIComponent(safeReturnUrl()));
}

async function request(method, url, body, opts = {}) {
  const unsafe = method !== 'GET' && method !== 'HEAD';
  const headers = { Accept: 'application/json', ...(opts.headers || {}) };
  let payload = body;
  if (body !== undefined && body !== null && !(body instanceof FormData)) {
    headers['Content-Type'] = 'application/json';
    payload = JSON.stringify(body);
  }
  if (unsafe) headers['X-CSRF-TOKEN'] = await ensureCsrf();

  let res = await fetch(url, { method, headers, body: payload, credentials: 'same-origin', signal: opts.signal });

  if (res.status === 400 && unsafe && !opts._retried) {
    const peek = await res.clone().json().catch(() => null);
    if (peek && peek.error === 'csrf') {
      await session(true);
      return request(method, url, body, { ...opts, _retried: true });
    }
  }

  if (res.status === 401 && redirectOnUnauthorized && !opts.noRedirect) {
    redirectToLogin();
    throw new ApiError(401, 'unauthorized', 'Session expired');
  }

  if (res.status === 204) return null;
  const text = await res.text();
  let data = null;
  if (text) {
    try { data = JSON.parse(text); } catch { data = text; }
  }
  if (!res.ok) {
    const code = data && typeof data === 'object' ? data.error : null;
    const message = data && typeof data === 'object' ? data.message : (typeof data === 'string' ? data : null);
    throw new ApiError(res.status, code || `http_${res.status}`, message || `Request failed (${res.status})`, data);
  }
  return data;
}

export const api = {
  get: (url, opts) => request('GET', url, undefined, opts),
  post: (url, body, opts) => request('POST', url, body ?? {}, opts),
  put: (url, body, opts) => request('PUT', url, body ?? {}, opts),
  patch: (url, body, opts) => request('PATCH', url, body ?? {}, opts),
  delete: (url, opts) => request('DELETE', url, undefined, opts),
  upload: (url, formData, opts) => request('POST', url, formData, opts),
  /** Builds a query string from an object, skipping empty values. */
  qs(params) {
    const usp = new URLSearchParams();
    for (const [k, v] of Object.entries(params || {})) {
      if (v === undefined || v === null || v === '') continue;
      if (Array.isArray(v)) v.forEach((x) => usp.append(k, x)); else usp.set(k, v);
    }
    const s = usp.toString();
    return s ? '?' + s : '';
  },
};

export default api;
