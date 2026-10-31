/**
 * Browser proof-of-work. HMAC-SHA256(serverKey, ascii(nonce)) must have difficultyBits leading zero bits.
 * Same check as Sendit and the secret-sharing pages. A challenge is one-time on the server.
 * Solving abandons work 5 seconds before expiresAt and fetches a fresh challenge.
 */

const ABANDON_BEFORE_MS = 5000;

// Page-load offset so ticket expiry uses the server clock. Zero means local time.
let clockOffsetMs = 0;

export function powNow() {
  return Date.now() + clockOffsetMs;
}

/** Extra milliseconds added so a ticket is treated as expired slightly before the server rejects it. */
export const CLOCK_MARGIN_MS = 2000;

/** Server time minus the midpoint of the request. Positive when the client clock is behind. */
export function clockOffset(serverUtcMs, clientBeforeMs, clientAfterMs) {
  return serverUtcMs - (clientBeforeMs + clientAfterMs) / 2;
}

export function powClockOffset(serverUtcMs, clientBeforeMs, clientAfterMs) {
  return clockOffset(serverUtcMs, clientBeforeMs, clientAfterMs) + CLOCK_MARGIN_MS;
}

function parseServerTime(value) {
  if (!value) return NaN;
  const text = String(value).replace(/(\.\d{3})\d+/, '$1');
  const parsed = Date.parse(text);
  return Number.isNaN(parsed) ? NaN : parsed;
}

/** Ask once. A failed request leaves the offset at zero so proof-of-work uses local time. */
export async function syncServerTime() {
  try {
    const before = Date.now();
    const res = await fetch('/api/time', { credentials: 'same-origin', cache: 'no-store', headers: { Accept: 'application/json' } });
    const after = Date.now();
    if (!res.ok) return false;
    const data = await res.json();
    const server = parseServerTime(data?.utc);
    if (Number.isNaN(server)) return false;
    clockOffsetMs = powClockOffset(server, before, after);
    return true;
  } catch {
    return false;
  }
}

function b64urlDecode(str) {
  const s = str.replace(/-/g, '+').replace(/_/g, '/');
  const pad = '='.repeat((4 - (s.length % 4)) % 4);
  const bin = atob(s + pad);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function b64urlEncode(bytes) {
  let bin = '';
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function hasLeadingZeroBits(hash, bits) {
  if (bits <= 0) return true;
  const full = (bits / 8) | 0;
  const rem = bits % 8;
  for (let i = 0; i < full; i++) {
    if (hash[i] !== 0) return false;
  }
  if (rem === 0) return true;
  const mask = 0xff << (8 - rem);
  return (hash[full] & mask) === 0;
}

function powExpiredError() {
  const err = new Error('Proof-of-work challenge nearing expiry.');
  err.powExpired = true;
  return err;
}

function abandonDeadlineMs(challenge) {
  if (!challenge || !challenge.expiresAt) return null;
  const exp = Date.parse(challenge.expiresAt);
  if (Number.isNaN(exp)) return null;
  return exp - ABANDON_BEFORE_MS;
}

function abortedError() {
  const err = new Error('Proof-of-work abandoned.');
  err.powAborted = true;
  return err;
}

async function solve(challenge, opts = {}) {
  const bits = Math.max(1, challenge.difficultyBits | 0);
  const subtle = globalThis.crypto && globalThis.crypto.subtle;
  if (!subtle) throw new Error('Web Crypto is unavailable for proof of work.');
  const deadline = abandonDeadlineMs(challenge);
  if (opts.shouldAbort?.()) throw abortedError();
  if (deadline != null && powNow() >= deadline) throw powExpiredError();

  const key = await subtle.importKey('raw', b64urlDecode(challenge.hmacKey), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const enc = new TextEncoder();
  let nonce = 0;
  let tries = 0;
  while (true) {
    if (opts.shouldAbort?.()) throw abortedError();
    if (deadline != null && powNow() >= deadline) throw powExpiredError();
    const nonceStr = String(nonce);
    const mac = new Uint8Array(await subtle.sign('HMAC', key, enc.encode(nonceStr)));
    tries++;
    if (hasLeadingZeroBits(mac, bits)) {
      return { challengeId: challenge.challengeId, nonce: nonceStr, hash: b64urlEncode(mac), tries };
    }
    nonce++;
    if (tries % 250 === 0) {
      await new Promise((r) => { setTimeout(r, 0); });
    }
  }
}

/** Fetch and solve until a challenge completes. Retries only when the current challenge is about to expire. */
export async function solvePow(fetchChallenge, opts = {}) {
  if (typeof fetchChallenge !== 'function') throw new Error('solvePow requires a function that fetches a challenge.');
  const maxAttempts = typeof opts.maxAttempts === 'number' && opts.maxAttempts > 0 ? opts.maxAttempts : 10000;
  let attempt = 0;
  while (attempt < maxAttempts) {
    attempt++;
    const challenge = await fetchChallenge();
    if (!challenge || !challenge.challengeId || !challenge.hmacKey) {
      throw new Error('Invalid proof-of-work challenge from server.');
    }
    try {
      const solution = await solve(challenge, opts);
      solution.attempts = attempt;
      return solution;
    } catch (err) {
      if (err && err.powExpired) continue;
      throw err;
    }
  }
  throw new Error('Proof-of-work could not complete.');
}

/**
 * Keeps a solved login ticket ready. Starts immediately, and when half the ticket's
 * life has passed it solves the next ticket. take() returns the newest finished solution.
 */
export function createPowKeeper(fetchChallenge, deps = {}) {
  const now = deps.now ?? powNow;
  const later = deps.setTimeout ?? setTimeout;
  const cancel = deps.clearTimeout ?? clearTimeout;
  const solveChallenge = deps.solve ?? ((challenge, opts) => solve(challenge, opts));
  let generation = 0;
  let solveId = 0;
  let held = null;
  let pending = null;
  let timer = 0;

  function clearTimer() {
    if (timer) { cancel(timer); timer = 0; }
  }

  function expiresMs(value) {
    if (!value) return NaN;
    const text = String(value).replace(/(\.\d{3})\d+/, '$1');
    const parsed = Date.parse(text);
    return Number.isNaN(parsed) ? NaN : parsed;
  }

  function usable(solution) {
    if (!solution) return false;
    const exp = expiresMs(solution.expiresAt);
    return !Number.isNaN(exp) && exp - now() > ABANDON_BEFORE_MS;
  }

  function schedule(receivedAt, challenge, gen) {
    const exp = expiresMs(challenge.expiresAt);
    if (Number.isNaN(exp)) return;
    const halfway = receivedAt + Math.max(0, (exp - receivedAt) / 2);
    clearTimer();
    timer = later(() => {
      if (gen !== generation) return;
      // A solve that is still running must be allowed to finish. Start the next ticket after it.
      if (pending) { refreshQueued = true; return; }
      begin(gen);
    }, Math.max(0, halfway - now()));
  }

  let refreshQueued = false;
  let lastError = null;

  function begin(gen) {
    if (gen !== generation || pending) return pending;
    const id = ++solveId;
    refreshQueued = false;
    const run = (async () => {
      const challenge = await fetchChallenge();
      const receivedAt = now();
      if (gen !== generation || id !== solveId) return;
      if (!challenge?.challengeId || !challenge.hmacKey) throw new Error('Invalid proof-of-work challenge from server.');
      schedule(receivedAt, challenge, gen);
      try {
        const solution = await solveChallenge(challenge, { shouldAbort: () => gen !== generation || id !== solveId });
        if (gen !== generation || id !== solveId) return;
        if (!held || receivedAt >= held.fetchedAt) {
          held = { ...solution, fetchedAt: receivedAt, expiresAt: challenge.expiresAt };
        }
      } catch (err) {
        if (err?.powAborted) return;
        if (err?.powExpired) { refreshQueued = true; return; }
        throw err;
      }
    })();
    let current;
    current = run.then(() => {}, (err) => { lastError = err; }).finally(() => {
      if (pending !== current) return;
      pending = null;
      if (gen === generation && refreshQueued) {
        refreshQueued = false;
        begin(gen);
      }
    });
    pending = current;
    return pending;
  }

  return {
    start() {
      generation++;
      held = null;
      pending = null;
      clearTimer();
      begin(generation);
    },
    stop() {
      generation++;
      held = null;
      pending = null;
      clearTimer();
      solveId++;
    },
    ready() {
      return usable(held);
    },
    async take() {
      for (let i = 0; i < 8; i++) {
        if (usable(held)) {
          const solution = held;
          held = null;
          if (!pending) begin(generation);
          return solution;
        }
        lastError = null;
        const wait = pending || begin(generation);
        await wait;
        if (lastError && !usable(held)) throw lastError;
      }
      throw new Error('Proof-of-work could not complete.');
    },
  };
}

export function powBody(pow) {
  if (!pow || !pow.challengeId) return {};
  return { powChallengeId: pow.challengeId, powNonce: pow.nonce, powHash: pow.hash || null };
}
