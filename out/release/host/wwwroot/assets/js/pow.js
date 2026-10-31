/**
 * Browser proof-of-work. HMAC-SHA256(serverKey, ascii(nonce)) must have difficultyBits leading zero bits.
 * Same check as Sendit and the secret-sharing pages. A challenge is one-time on the server.
 * Solving abandons work 5 seconds before expiresAt and fetches a fresh challenge.
 */

const ABANDON_BEFORE_MS = 5000;

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

async function solve(challenge, opts = {}) {
  const bits = Math.max(1, challenge.difficultyBits | 0);
  const subtle = globalThis.crypto && globalThis.crypto.subtle;
  if (!subtle) throw new Error('Web Crypto is unavailable for proof of work.');
  const deadline = abandonDeadlineMs(challenge);
  if (deadline != null && Date.now() >= deadline) throw powExpiredError();

  const key = await subtle.importKey('raw', b64urlDecode(challenge.hmacKey), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const enc = new TextEncoder();
  let nonce = 0;
  let tries = 0;
  while (true) {
    if (deadline != null && Date.now() >= deadline) throw powExpiredError();
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

export function powBody(pow) {
  if (!pow || !pow.challengeId) return {};
  return { powChallengeId: pow.challengeId, powNonce: pow.nonce, powHash: pow.hash || null };
}
