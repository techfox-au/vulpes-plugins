/**
 * HMAC-SHA256 proof-of-work search. Same digest as Web Crypto and the server:
 * HMAC-SHA256(key, ASCII decimal nonce), first difficultyBits bits zero.
 * The key schedule is done once. Each nonce is then one SHA-256 block plus the
 * outer block, in a tight loop, split across workers.
 */

const K = new Uint32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]);

const IV = new Uint32Array([
  0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
]);

function rotr(x, n) {
  return (x >>> n) | (x << (32 - n));
}

function compress(state, w) {
  for (let i = 16; i < 64; i++) {
    const w15 = w[i - 15];
    const w2 = w[i - 2];
    const s0 = rotr(w15, 7) ^ rotr(w15, 18) ^ (w15 >>> 3);
    const s1 = rotr(w2, 17) ^ rotr(w2, 19) ^ (w2 >>> 10);
    w[i] = (w[i - 16] + s0 + w[i - 7] + s1) | 0;
  }
  let a = state[0];
  let b = state[1];
  let c = state[2];
  let d = state[3];
  let e = state[4];
  let f = state[5];
  let g = state[6];
  let h = state[7];
  for (let i = 0; i < 64; i++) {
    const s1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
    const ch = (e & f) ^ (~e & g);
    const t1 = (h + s1 + ch + K[i] + w[i]) | 0;
    const s0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
    const maj = (a & b) ^ (a & c) ^ (b & c);
    const t2 = (s0 + maj) | 0;
    h = g;
    g = f;
    f = e;
    e = (d + t1) | 0;
    d = c;
    c = b;
    b = a;
    a = (t1 + t2) | 0;
  }
  state[0] = (state[0] + a) | 0;
  state[1] = (state[1] + b) | 0;
  state[2] = (state[2] + c) | 0;
  state[3] = (state[3] + d) | 0;
  state[4] = (state[4] + e) | 0;
  state[5] = (state[5] + f) | 0;
  state[6] = (state[6] + g) | 0;
  state[7] = (state[7] + h) | 0;
}

function loadWords(block) {
  const w = new Uint32Array(64);
  for (let i = 0; i < 16; i++) {
    const o = i * 4;
    w[i] = ((block[o] << 24) | (block[o + 1] << 16) | (block[o + 2] << 8) | block[o + 3]) >>> 0;
  }
  return w;
}

function prepare(keyBytes) {
  const block = new Uint8Array(64);
  if (keyBytes.length > 64) {
    const digest = sha256Bytes(keyBytes);
    block.set(digest);
  } else {
    block.set(keyBytes);
  }
  const ipad = loadWords(block.map((b) => b ^ 0x36));
  const opad = loadWords(block.map((b) => b ^ 0x5c));
  const inner = IV.slice();
  const outer = IV.slice();
  compress(inner, ipad);
  compress(outer, opad);
  return { inner, outer };
}

function sha256Bytes(bytes) {
  const state = IV.slice();
  const w = new Uint32Array(64);
  const len = bytes.length;
  let offset = 0;
  while (len - offset >= 64) {
    for (let i = 0; i < 16; i++) {
      const o = offset + i * 4;
      w[i] = ((bytes[o] << 24) | (bytes[o + 1] << 16) | (bytes[o + 2] << 8) | bytes[o + 3]) >>> 0;
    }
    for (let i = 16; i < 64; i++) w[i] = 0;
    compress(state, w);
    offset += 64;
  }
  w.fill(0);
  let wi = 0;
  let shift = 24;
  let word = 0;
  for (let i = offset; i < len; i++) {
    word |= bytes[i] << shift;
    if (shift === 0) {
      w[wi++] = word >>> 0;
      word = 0;
      shift = 24;
    } else {
      shift -= 8;
    }
  }
  word |= 0x80 << shift;
  w[wi] = word >>> 0;
  if (wi >= 14) {
    compress(state, w);
    w.fill(0);
  }
  const bits = len * 8;
  w[14] = (bits / 0x100000000) >>> 0;
  w[15] = bits >>> 0;
  compress(state, w);
  return stateToBytes(state);
}

function stateToBytes(state) {
  const out = new Uint8Array(32);
  for (let i = 0; i < 8; i++) {
    const v = state[i];
    const o = i * 4;
    out[o] = v >>> 24;
    out[o + 1] = v >>> 16;
    out[o + 2] = v >>> 8;
    out[o + 3] = v;
  }
  return out;
}

function writeNonceBlock(w, digits, nonce) {
  w[0] = 0;
  w[1] = 0;
  w[2] = 0;
  w[3] = 0;
  w[4] = 0;
  w[5] = 0;
  w[6] = 0;
  w[7] = 0;
  w[8] = 0;
  w[9] = 0;
  w[10] = 0;
  w[11] = 0;
  w[12] = 0;
  w[13] = 0;
  w[14] = 0;
  let len = 0;
  let value = nonce;
  do {
    digits[len++] = 0x30 + (value % 10);
    value = (value / 10) | 0;
  } while (value > 0);
  let word = 0;
  let shift = 24;
  let wi = 0;
  for (let i = len - 1; i >= 0; i--) {
    word |= digits[i] << shift;
    if (shift === 0) {
      w[wi++] = word >>> 0;
      word = 0;
      shift = 24;
    } else {
      shift -= 8;
    }
  }
  word |= 0x80 << shift;
  w[wi] = word >>> 0;
  // Inner message is the 64-byte ipad block plus these digits.
  w[15] = (64 + len) * 8;
}

function hmacNonce(engine, nonce) {
  const state = engine.state;
  state.set(engine.inner);
  const w = engine.w;
  writeNonceBlock(w, engine.digits, nonce);
  compress(state, w);
  const hi0 = state[0];
  const hi1 = state[1];
  const hi2 = state[2];
  const hi3 = state[3];
  const hi4 = state[4];
  const hi5 = state[5];
  const hi6 = state[6];
  const hi7 = state[7];
  w.fill(0);
  w[0] = hi0;
  w[1] = hi1;
  w[2] = hi2;
  w[3] = hi3;
  w[4] = hi4;
  w[5] = hi5;
  w[6] = hi6;
  w[7] = hi7;
  w[8] = 0x80000000;
  w[15] = 768;
  state.set(engine.outer);
  compress(state, w);
  return state[0] >>> 0;
}

function meets(firstWord, bits) {
  const shift = 32 - bits;
  return shift === 0 ? firstWord === 0 : (firstWord >>> shift) === 0;
}

export function createEngine(keyBytes) {
  const { inner, outer } = prepare(keyBytes);
  return { inner, outer, state: new Uint32Array(8), w: new Uint32Array(64), digits: new Uint8Array(24) };
}

/** Search start, start+step, start+2step, ... until a hit, a stop, or limit hashes. */
export function searchNonces(engine, start, step, bits, stopAt, shouldStop, limit) {
  let nonce = start;
  let tries = 0;
  while (true) {
    if ((tries & 8191) === 0) {
      if (shouldStop?.()) return { found: false, aborted: true, tries, next: nonce };
      if (stopAt && Date.now() >= stopAt) return { found: false, expired: true, tries, next: nonce };
      if (limit && tries >= limit) return { found: false, tries, next: nonce };
    }
    const first = hmacNonce(engine, nonce);
    tries++;
    if (meets(first, bits)) {
      return { found: true, nonce, hash: stateToBytes(engine.state), tries };
    }
    nonce += step;
  }
}

function logicalCores() {
  const reported = typeof navigator !== 'undefined' ? navigator.hardwareConcurrency : 0;
  return reported > 0 ? reported : 4;
}

/** Hashing threads. One logical core stays idle so the page can take clicks and paint. */
function workerCount(reported) {
  const cores = reported > 0 ? reported : logicalCores();
  if (cores < 2) return 1;
  return Math.min(cores - 1, 16);
}

function expiredError() {
  const err = new Error('Proof-of-work challenge nearing expiry.');
  err.powExpired = true;
  return err;
}

function abortedError() {
  const err = new Error('Proof-of-work abandoned.');
  err.powAborted = true;
  return err;
}

async function solveHere(keyBytes, bits, stopAt, shouldAbort) {
  const engine = createEngine(keyBytes);
  let nonce = 0;
  while (true) {
    if (shouldAbort?.()) throw abortedError();
    if (stopAt && Date.now() >= stopAt) throw expiredError();
    const result = searchNonces(engine, nonce, 1, bits, stopAt, shouldAbort, 20000);
    if (result.found) return result;
    if (result.expired) throw expiredError();
    if (result.aborted) throw abortedError();
    nonce = result.next;
    await new Promise((resolve) => setTimeout(resolve, 0));
  }
}

let workerUrlPromise;

// The worker must not fetch another https script. Private windows accept the page, then refuse that second fetch.
function workerUrl() {
  if (!workerUrlPromise) {
    workerUrlPromise = fetch(new URL('./pow-engine.js', import.meta.url)).then(async (res) => {
      if (!res.ok) throw new Error('Could not load the proof-of-work engine.');
      const engineUrl = URL.createObjectURL(new Blob([await res.text()], { type: 'text/javascript' }));
      const source = `import { createEngine, searchNonces } from ${JSON.stringify(engineUrl)};
let stop = false;
self.onmessage = async (event) => {
  const data = event.data;
  if (!data || data.type === 'stop') { stop = true; return; }
  if (data.type !== 'start') return;
  stop = false;
  const engine = createEngine(new Uint8Array(data.key));
  let nonce = data.start;
  while (!stop) {
    const result = searchNonces(engine, nonce, data.step, data.bits, data.stopAt, () => stop, 100000);
    if (result.found || result.expired || result.aborted) { self.postMessage(result); return; }
    nonce = result.next;
    await new Promise((resolve) => setTimeout(resolve, 0));
  }
  self.postMessage({ found: false, aborted: true });
};
`;
      return URL.createObjectURL(new Blob([source], { type: 'text/javascript' }));
    });
  }
  return workerUrlPromise;
}

/** Search on every core except one left for the page. Any valid decimal nonce is acceptable. */
export async function solveParallel(keyBytes, bits, stopAt, shouldAbort) {
  const available = logicalCores();
  if (available < 2 || typeof Worker === 'undefined') {
    return solveHere(keyBytes, bits, stopAt, shouldAbort);
  }
  const count = workerCount(available);
  let workers = [];
  try {
    const url = await workerUrl();
    workers = Array.from({ length: count }, () => new Worker(url, { type: 'module' }));
  } catch (err) {
    console.info('pow: workers unavailable', err?.message || 'could not start');
    return solveHere(keyBytes, bits, stopAt, shouldAbort);
  }
  return new Promise((resolve, reject) => {
    let open = count;
    let settled = false;
    const stop = () => {
      for (const worker of workers) {
        try { worker.postMessage({ type: 'stop' }); } catch { /* already gone */ }
        worker.terminate();
      }
    };
    const finish = (err, value) => {
      if (settled) return;
      settled = true;
      clearInterval(watch);
      stop();
      if (err) reject(err);
      else resolve(value);
    };
    const watch = setInterval(() => {
      if (shouldAbort?.()) finish(abortedError());
      else if (stopAt && Date.now() >= stopAt) finish(expiredError());
    }, 40);
    workers.forEach((worker, index) => {
      worker.onerror = (event) => {
        if (settled) return;
        settled = true;
        clearInterval(watch);
        stop();
        console.info('pow: worker failed', event?.message || 'worker error');
        solveHere(keyBytes, bits, stopAt, shouldAbort).then(resolve, reject);
      };
      worker.onmessage = (event) => {
        const message = event.data;
        if (message?.found) {
          finish(null, message);
          return;
        }
        open -= 1;
        if (open === 0) finish(message?.aborted ? abortedError() : expiredError());
      };
      worker.postMessage({ type: 'start', key: keyBytes, start: index, step: count, bits, stopAt });
    });
  });
}
