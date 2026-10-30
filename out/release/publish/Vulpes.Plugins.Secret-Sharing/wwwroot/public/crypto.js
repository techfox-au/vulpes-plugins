/**
 * Sendit! client-side cryptography
 * =================================
 *
 * This module is the ONLY place secret material is encrypted or decrypted.
 * The Sendit! server stores ciphertext and wrapped keys; it never sees plaintext
 * secrets or unwrapped AES keys.
 *
 * Protocol version: 1
 *
 * Layers
 * ------
 * 1. Payload encryption
 *    - Algorithm: AES-256-GCM
 *    - Key K: 32 random bytes (crypto.getRandomValues)
 *    - IV: 12 random bytes (unique per encryption)
 *    - Tag: 128-bit authentication tag (appended by Web Crypto)
 *    - Encrypt and decrypt (any size): Blob worker from aesWorkerBootstrap
 *      (CSP worker-src blob:). AES-256-GCM is crypto.subtle in the worker.
 *      2 MiB postMessage chunks in both directions — a single ~40 MiB+ worker
 *      message hangs Safari/WebKit. Decrypt plaintext returns as a chunk list;
 *      the page builds a Blob after the worker is torn down.
 *
 * 2. Key agreement (to transport K)
 *    - Algorithm: X25519 ECDH (via TweetNaCl nacl.scalarMult / box keyPair)
 *    - Ephemeral sender keypair (ephSk, ephPk) generated per wrap
 *    - shared = X25519(ephSk, recipientPk)
 *
 * 3. Key derivation
 *    - HKDF-SHA-256 (Web Crypto)
 *    - salt: 32 zero bytes (protocol-fixed; shared secret already high entropy)
 *    - info: UTF-8 "sendit-v1-wrap"
 *    - output: 32-byte wrap key
 *
 * 4. Key wrap (AES payload key K)
 *    - AES-256-GCM encrypt K under the HKDF wrap key
 *    - Separate 12-byte IV for the wrap (stored with wrapped key blob)
 *
 * Wire layout for wrappedKey field (binary, then base64url in JSON):
 *    wrapIv (12) || gcm(ciphertext||tag of K)
 *
 * 5. Optional link password (send and collect) — seals the fragment sk
 *    - PBKDF2-HMAC-SHA512(password, salt=16B, i from /api/v1/crypto/params) → 32B
 *    - AES-256-GCM(wrapKey, iv=12B, sk) → ct (ciphertext‖128-bit tag)
 *    - Compact package in fragment (alg fixed by protocol, not on wire):
 *         { i, s, iv, ct }  all b64url except i (integer)
 *    - Server stores only passwordProtected boolean; never sees password or sk
 *
 * URL fragment convention
 * -----------------------
 * Private keys travel only in the URL fragment (#...), which browsers do not
 * send to the server on HTTP requests:
 *    Unprotected:  /send?id=…#sk=<base64url 32-byte X25519 private key>
 *    Password:     /send?id=…#sk=<base64url(UTF-8 JSON {i,s,iv,ct})>
 * Collect link may use the password form. Dashboard stores UDK(raw sk) or, when password-
 * protected, UDK(password-wrap package) so re-opened links still require the link password.
 *
 * Dependencies
 * ------------
 * - window.nacl  (TweetNaCl nacl-fast.js) for X25519
 * - window.crypto.subtle for AES-GCM, HKDF, and PBKDF2
 * - Worker + blob: URLs for payload encrypt and decrypt (same path for every size)
 *
 * Auditors: prefer this file + docs/CRYPTO.md over minified public/js/crypto.min.js.
 */

(function (global) {
  "use strict";

  const PROTOCOL_VERSION = 1;
  const HKDF_INFO = new TextEncoder().encode("sendit-v1-wrap");
  const HKDF_SALT = new Uint8Array(32); // fixed zeros; documented in CRYPTO.md
  const AES_KEY_BITS = 256;
  const IV_LENGTH = 12;
  const X25519_LEN = 32;
  const GCM_TAG_LEN = 16;

  // Optional link-password wrap of fragment sk (params from /api/v1/crypto/params).
  const PW_WRAP_SALT_LEN = 16;
  const PW_WRAP_IV_LEN = 12; // AES-GCM standard nonce size
  let PW_WRAP_ITERATIONS = 893241; // same default as server password / UDK policy
  let PW_WRAP_HASH = "SHA-512";
  let pwWrapParamsLoaded = false;

  // ---------------------------------------------------------------------------
  // Encoding helpers (base64url, no padding)
  // ---------------------------------------------------------------------------

  /** Yield so a large encode/decode does not freeze the tab (Safari hang dialog). */
  function yieldUi() {
    return new Promise(function (r) {
      if (typeof requestAnimationFrame === "function") {
        requestAnimationFrame(function () {
          setTimeout(r, 0);
        });
      } else {
        setTimeout(r, 0);
      }
    });
  }

  /** Typed-array → binary string in 8 KiB pieces (apply() arg limits). */
  function bytesToBinaryString(arr) {
    var s = "";
    var i = 0;
    var CHUNK = 8192;
    for (; i + CHUNK <= arr.length; i += CHUNK) {
      s += String.fromCharCode.apply(
        null,
        Array.prototype.slice.call(arr.subarray(i, i + CHUNK))
      );
    }
    if (i < arr.length) {
      s += String.fromCharCode.apply(
        null,
        Array.prototype.slice.call(arr.subarray(i))
      );
    }
    return s;
  }

  function binaryStringToBytes(bin) {
    var out = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }

  /**
   * Encode bytes as base64url without '=' padding.
   * Large inputs are encoded in 96 KiB chunks (3-byte aligned) so `btoa` is never
   * given a large binary string.
   */
  function b64urlEncode(bytes) {
    const arr = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
    if (arr.length === 0) return "";
    const step = 96 * 1024;
    if (arr.length <= step) {
      return btoa(bytesToBinaryString(arr))
        .replace(/\+/g, "-")
        .replace(/\//g, "_")
        .replace(/=+$/g, "");
    }
    var out = "";
    for (var i = 0; i < arr.length; i += step) {
      out += btoa(bytesToBinaryString(arr.subarray(i, Math.min(i + step, arr.length))));
    }
    return out.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
  }

  /**
   * Decode base64url (with or without padding) to Uint8Array.
   * Large inputs are decoded in 128 KiB (4-char aligned) slices so `atob` + the
   * charCodeAt copy never run over a large string in one turn.
   */
  function b64urlDecode(str) {
    var s = str.replace(/-/g, "+").replace(/_/g, "/");
    while (s.length % 4) s += "=";
    const step = 128 * 1024;
    if (s.length <= step) {
      return binaryStringToBytes(atob(s));
    }
    var parts = [];
    var total = 0;
    for (var i = 0; i < s.length; i += step) {
      var u = binaryStringToBytes(atob(s.slice(i, i + step)));
      parts.push(u);
      total += u.length;
    }
    var out = new Uint8Array(total);
    var o = 0;
    for (var k = 0; k < parts.length; k++) {
      out.set(parts[k], o);
      o += parts[k].length;
    }
    return out;
  }

  function indexOfAscii(u8, ascii, from) {
    var n = ascii.length;
    var i = from || 0;
    var last = u8.length - n;
    outer: for (; i <= last; i++) {
      for (var j = 0; j < n; j++) {
        if (u8[i + j] !== ascii.charCodeAt(j)) continue outer;
      }
      return i;
    }
    return -1;
  }

  /**
   * Turn a payload GET ArrayBuffer into small JSON metadata + ciphertext bounds.
   * Does not JSON.parse or decode the ciphertext field (that would freeze Safari
   * on a max-size file). Ciphertext is the only field that can be huge; it is
   * base64url so it cannot include `","iv":"`. We find that marker in the last 1 MiB.
   * Same path for tiny text secrets and 40 MiB files.
   */
  async function ingestPayloadResponse(buf) {
    var raw = buf instanceof ArrayBuffer ? buf : buf.buffer;
    var u8 = buf instanceof Uint8Array ? buf : new Uint8Array(raw);
    var at = indexOfAscii(u8, '"ciphertext":"', 0);
    if (at < 0) {
      if (u8.length > 65536) throw new Error("Invalid payload.");
      return JSON.parse(new TextDecoder().decode(u8));
    }
    var start = at + 14;
    var tailFrom = Math.max(start, u8.length - 1024 * 1024);
    var ivAt = indexOfAscii(u8, '","iv":"', tailFrom);
    if (ivAt < start) throw new Error("Invalid payload.");
    var end = ivAt;
    var small = new Uint8Array(start + (u8.length - end));
    small.set(u8.subarray(0, start), 0);
    small.set(u8.subarray(end), start);
    var obj = JSON.parse(new TextDecoder().decode(small));
    obj.ciphertext = null;
    obj._raw = raw;
    obj._ctStart = start;
    obj._ctEnd = end;
    return obj;
  }

  /**
   * Decode base64url only if it is the canonical (unpadded) encoding of
   * exactly `expectedLen` bytes. Rejects non-canonical last-character
   * variants that base64 would otherwise accept as identical payloads
   * (32 bytes → 43 chars; the final char carries only 4 data bits).
   */
  function b64urlDecodeCanonical(str, expectedLen) {
    if (typeof str !== "string" || !str) return null;
    if (!/^[A-Za-z0-9_-]+$/.test(str)) return null;
    let decoded;
    try {
      decoded = b64urlDecode(str);
    } catch (_) {
      return null;
    }
    if (decoded.length !== expectedLen) return null;
    // Reject padding noise / alternate encodings of the same bytes.
    if (b64urlEncode(decoded) !== str) return null;
    return decoded;
  }

  function requireNacl() {
    if (!global.nacl || !global.nacl.box || !global.nacl.scalarMult) {
      throw new Error("TweetNaCl (nacl) is required for X25519.");
    }
  }

  /** AES-GCM / HKDF need crypto.subtle (HTTPS or localhost only). */
  function requireSubtle() {
    const subtle = global.crypto && global.crypto.subtle;
    if (subtle) return subtle;
    throw new Error(
      "Web Crypto is unavailable. Use HTTPS or http://localhost " +
        "(plain HTTP on a phone LAN IP blocks encryption)."
    );
  }

  // ---------------------------------------------------------------------------
  // Randomness and key generation
  // ---------------------------------------------------------------------------

  /** Cryptographically secure random bytes. */
  function randomBytes(n) {
    const b = new Uint8Array(n);
    global.crypto.getRandomValues(b);
    return b;
  }

  /**
   * Generate an X25519 keypair for hybrid encryption.
   * Returns { publicKey: Uint8Array(32), secretKey: Uint8Array(32) }.
   *
   * Uses nacl.box.keyPair which is X25519 (Curve25519 ECDH keys).
   */
  function generateKeyPair() {
    requireNacl();
    const kp = global.nacl.box.keyPair();
    return {
      publicKey: new Uint8Array(kp.publicKey),
      secretKey: new Uint8Array(kp.secretKey),
    };
  }

  /**
   * Derive a keypair from an existing 32-byte secret key.
   */
  function keyPairFromSecretKey(secretKey) {
    requireNacl();
    const sk = secretKey instanceof Uint8Array ? secretKey : new Uint8Array(secretKey);
    if (sk.length !== X25519_LEN) throw new Error("X25519 secret key must be 32 bytes.");
    const kp = global.nacl.box.keyPair.fromSecretKey(sk);
    return {
      publicKey: new Uint8Array(kp.publicKey),
      secretKey: new Uint8Array(kp.secretKey),
    };
  }

  // ---------------------------------------------------------------------------
  // AES-256-GCM payload encrypt / decrypt
  // ---------------------------------------------------------------------------

  /**
   * Import a raw 32-byte AES key for encrypt or decrypt.
   */
  async function importAesKey(rawKey, usages) {
    return requireSubtle().importKey("raw", rawKey, { name: "AES-GCM" }, false, usages);
  }

  /**
   * Decrypt AES-256-GCM. Always the Blob worker (same path for every size).
   * Ciphertext base64 in, plaintext out: 2 MiB postMessage chunks.
   * @returns {Uint8Array|ArrayBuffer[]} one buffer, or a chunk list for large files
   */
  async function decryptPayload(keyBytes, iv, rawBuf, ctStart, ctEnd, onStatus) {
    requireSubtle();
    var chunks = await withFreshAesWorker(function (w) {
      return decryptAesGcmInWorker(w, rawBuf, ctStart, ctEnd, keyBytes, iv, onStatus);
    });
    await yieldUi();
    if (!chunks || !chunks.length) return new Uint8Array(0);
    if (chunks.length === 1) return new Uint8Array(chunks[0]);
    return chunks;
  }

  var _aesJobTail = Promise.resolve();
  /** 2 MiB IPC chunks stay under Safari's ~40 MiB worker-message cliff. */
  var AES_CHUNK = 2 * 1024 * 1024;

  function enqueueAesJob(run) {
    var p = _aesJobTail.then(run, run);
    _aesJobTail = p.then(
      function () {},
      function () {}
    );
    return p;
  }

  function spawnAesWorker() {
    if (typeof Worker === "undefined") return null;
    try {
      var src = "(" + aesWorkerBootstrap.toString() + ")()";
      var blob = new Blob([src], { type: "text/javascript" });
      var url = URL.createObjectURL(blob);
      var w = new Worker(url);
      w._blobUrl = url;
      return w;
    } catch (_) {
      return null;
    }
  }

  function killAesWorker(w) {
    if (!w) return;
    try {
      w.terminate();
    } catch (_) {}
    try {
      if (w._blobUrl) URL.revokeObjectURL(w._blobUrl);
    } catch (_) {}
  }

  function withFreshAesWorker(fn) {
    return enqueueAesJob(function () {
      var w = spawnAesWorker();
      if (!w) {
        throw new Error(
          "Cannot run payload crypto in this browser (background worker unavailable)."
        );
      }
      return Promise.resolve(fn(w)).then(
        function (v) {
          killAesWorker(w);
          return v;
        },
        function (err) {
          killAesWorker(w);
          throw err;
        }
      );
    });
  }

  /** Runs inside a Blob worker (stringified). Must not close over page state. */
  function aesWorkerBootstrap() {
    var CHUNK = 2 * 1024 * 1024;
    var lut = new Int16Array(256);
    var encTbl = new Uint8Array(64);
    (function () {
      var i;
      var s = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
      for (i = 0; i < 256; i++) lut[i] = -1;
      for (i = 0; i < s.length; i++) lut[s.charCodeAt(i)] = i;
      lut[43] = 62;
      lut[47] = 63;
      for (i = 0; i < 64; i++) encTbl[i] = s.charCodeAt(i);
    })();
    function b64Val(ascii, idx) {
      var v = lut[ascii[idx]];
      if (v < 0) throw new Error("Invalid base64url.");
      return v;
    }
    function decodeQuartets(ascii, from, to, out, o) {
      var i = from;
      while (i + 4 <= to) {
        var t =
          (b64Val(ascii, i) << 18) |
          (b64Val(ascii, i + 1) << 12) |
          (b64Val(ascii, i + 2) << 6) |
          b64Val(ascii, i + 3);
        out[o++] = (t >> 16) & 255;
        out[o++] = (t >> 8) & 255;
        out[o++] = t & 255;
        i += 4;
      }
      return o;
    }
    function decodeTail(ascii, from, n, out, o) {
      var rem = n - from;
      if (rem === 1) throw new Error("Invalid base64url.");
      if (rem === 2) {
        var t2 = (b64Val(ascii, from) << 18) | (b64Val(ascii, from + 1) << 12);
        out[o++] = (t2 >> 16) & 255;
      } else if (rem === 3) {
        var t3 =
          (b64Val(ascii, from) << 18) |
          (b64Val(ascii, from + 1) << 12) |
          (b64Val(ascii, from + 2) << 6);
        out[o++] = (t3 >> 16) & 255;
        out[o++] = (t3 >> 8) & 255;
      }
      return o;
    }
    function encodeB64url(bytes) {
      var n = bytes.length;
      var full = Math.floor(n / 3);
      var rem = n - full * 3;
      var outLen = full * 4 + (rem === 0 ? 0 : rem === 1 ? 2 : 3);
      var out = new Uint8Array(outLen);
      var o = 0;
      var i = 0;
      var k;
      for (k = 0; k < full; k++) {
        var t = (bytes[i] << 16) | (bytes[i + 1] << 8) | bytes[i + 2];
        i += 3;
        out[o++] = encTbl[(t >> 18) & 63];
        out[o++] = encTbl[(t >> 12) & 63];
        out[o++] = encTbl[(t >> 6) & 63];
        out[o++] = encTbl[t & 63];
      }
      if (rem === 1) {
        var t1 = bytes[i] << 16;
        out[o++] = encTbl[(t1 >> 18) & 63];
        out[o++] = encTbl[(t1 >> 12) & 63];
      } else if (rem === 2) {
        var t2 = (bytes[i] << 16) | (bytes[i + 1] << 8);
        out[o++] = encTbl[(t2 >> 18) & 63];
        out[o++] = encTbl[(t2 >> 12) & 63];
        out[o++] = encTbl[(t2 >> 6) & 63];
      }
      return out;
    }
    var dec = null;
    var enc = null;
    var ret = null;
    self.onmessage = function (e) {
      var d = e.data || {};
      var op = d.op;
      try {
        if (op === "decrypt-start") {
          var asciiLen = d.asciiLen | 0;
          if (!d.key || !d.iv || asciiLen < 0 || asciiLen > 80 * 1024 * 1024) {
            self.postMessage({ ok: false, error: "Decrypt worker missing ciphertext." });
            return;
          }
          dec = {
            key: d.key,
            iv: d.iv,
            out: new Uint8Array(Math.floor((asciiLen * 3) / 4) + 3),
            o: 0,
            rem: new Uint8Array(3),
            remLen: 0,
            asciiLen: asciiLen,
            asciiSeen: 0,
          };
          self.postMessage({ more: true, progress: 0 });
          return;
        }
        if (op === "decrypt-ascii") {
          if (!dec || d.buf == null) {
            self.postMessage({ ok: false, error: "Decrypt worker missing ciphertext." });
            return;
          }
          var chunk = new Uint8Array(d.buf);
          d.buf = null;
          var bytes = chunk;
          if (dec.remLen) {
            var merged = new Uint8Array(dec.remLen + chunk.length);
            merged.set(dec.rem.subarray(0, dec.remLen), 0);
            merged.set(chunk, dec.remLen);
            bytes = merged;
          }
          var n = bytes.length;
          var complete = n - (n % 4);
          dec.o = decodeQuartets(bytes, 0, complete, dec.out, dec.o);
          dec.remLen = n - complete;
          if (dec.remLen) dec.rem.set(bytes.subarray(complete));
          dec.asciiSeen += chunk.length;
          var prog = dec.asciiLen ? dec.asciiSeen / dec.asciiLen : 1;
          self.postMessage({ more: true, progress: prog });
          return;
        }
        if (op === "decrypt-end") {
          if (!dec) {
            self.postMessage({ ok: false, error: "Decrypt worker missing ciphertext." });
            return;
          }
          if (dec.remLen === 1) throw new Error("Invalid base64url.");
          if (dec.remLen >= 2) {
            dec.o = decodeTail(dec.rem, 0, dec.remLen, dec.out, dec.o);
          }
          var packed = new Uint8Array(dec.o);
          packed.set(dec.out.subarray(0, dec.o));
          var key = dec.key;
          var iv = dec.iv;
          dec.out = null;
          dec.rem = null;
          dec = null;
          self.postMessage({ phase: "decrypting", progress: 0 });
          setTimeout(function () {
            crypto.subtle
              .importKey("raw", key, { name: "AES-GCM" }, false, ["decrypt"])
              .then(function (cryptoKey) {
                key = null;
                return crypto.subtle.decrypt({ name: "AES-GCM", iv: iv }, cryptoKey, packed);
              })
              .then(function (plainOut) {
                packed = null;
                iv = null;
                ret = { plain: new Uint8Array(plainOut), offset: 0 };
                self.postMessage({
                  phase: "returning",
                  plainLen: ret.plain.length,
                  progress: 1,
                });
              })
              .catch(function (err) {
                packed = null;
                key = null;
                iv = null;
                self.postMessage({
                  ok: false,
                  error: (err && err.message) || String(err || "Decrypt failed"),
                });
              });
          }, 0);
          return;
        }
        if (op === "plain-more") {
          if (!ret || !ret.plain) {
            self.postMessage({ ok: false, error: "Decrypt worker missing plaintext." });
            return;
          }
          if (ret.offset >= ret.plain.length) {
            ret.plain = null;
            ret = null;
            self.postMessage({ ok: true, done: true });
            return;
          }
          var pn = Math.min(CHUNK, ret.plain.length - ret.offset);
          var pcopy = new Uint8Array(pn);
          pcopy.set(ret.plain.subarray(ret.offset, ret.offset + pn));
          ret.offset += pn;
          self.postMessage({ plainChunk: pcopy.buffer }, [pcopy.buffer]);
          return;
        }
        if (op === "encrypt-start") {
          var plainLen = d.plainLen | 0;
          if (!d.key || !d.iv || plainLen < 0 || plainLen > 48 * 1024 * 1024) {
            self.postMessage({ ok: false, error: "Encrypt worker missing plaintext or key." });
            return;
          }
          enc = {
            key: d.key,
            iv: d.iv,
            plain: new Uint8Array(plainLen),
            o: 0,
          };
          self.postMessage({ more: true, progress: 0 });
          return;
        }
        if (op === "encrypt-plain") {
          if (!enc || d.buf == null) {
            self.postMessage({ ok: false, error: "Encrypt worker missing plaintext or key." });
            return;
          }
          var pchunk = new Uint8Array(d.buf);
          d.buf = null;
          enc.plain.set(pchunk, enc.o);
          enc.o += pchunk.length;
          self.postMessage({
            more: true,
            progress: enc.plain.length ? enc.o / enc.plain.length : 1,
          });
          return;
        }
        if (op === "encrypt-end") {
          if (!enc || enc.o !== enc.plain.length) {
            self.postMessage({ ok: false, error: "Encrypt worker missing plaintext or key." });
            return;
          }
          var eKey = enc.key;
          var eIv = enc.iv;
          var ePlain = enc.plain;
          enc = null;
          self.postMessage({ phase: "encrypting" });
          setTimeout(function () {
            crypto.subtle
              .importKey("raw", eKey, { name: "AES-GCM" }, false, ["encrypt"])
              .then(function (cryptoKey) {
                eKey = null;
                return crypto.subtle.encrypt({ name: "AES-GCM", iv: eIv }, cryptoKey, ePlain);
              })
              .then(function (ctAb) {
                ePlain = null;
                eIv = null;
                self.postMessage({ phase: "encoding", progress: 0 });
                setTimeout(function () {
                  var eCt = new Uint8Array(ctAb);
                  ctAb = null;
                  var ascii = encodeB64url(eCt);
                  eCt = null;
                  self.postMessage({ ok: true, ciphertext: ascii.buffer }, [ascii.buffer]);
                }, 0);
              })
              .catch(function (err) {
                ePlain = null;
                eKey = null;
                eIv = null;
                self.postMessage({
                  ok: false,
                  error: (err && err.message) || String(err || "Encrypt failed"),
                });
              });
          }, 0);
          return;
        }
        self.postMessage({ ok: false, error: "Unknown worker operation." });
      } catch (err) {
        dec = null;
        enc = null;
        ret = null;
        self.postMessage({
          ok: false,
          error: (err && err.message) || String(err || "Worker failed"),
        });
      }
    };
  }

  function listenAesWorker(worker, onStatus, okKey, resolve, reject) {
    var done = false;
    var to = setTimeout(function () {
      fail(new Error("Crypto worker timed out."));
    }, 180000);
    function cleanup() {
      if (done) return;
      done = true;
      clearTimeout(to);
      worker.removeEventListener("message", onMsg);
      worker.removeEventListener("error", onErr);
    }
    function fail(err) {
      cleanup();
      reject(err);
    }
    function onMsg(e) {
      var d = e.data || {};
      if (d.more) {
        if (typeof onStatus === "function") {
          onStatus(okKey === "plain" ? "Decoding…" : "Reading…", d.progress);
        }
        if (typeof onMsg._pump === "function") onMsg._pump();
        return;
      }
      if (d.phase === "decrypting") {
        if (typeof onStatus === "function") onStatus("Decrypting…", d.progress);
        return;
      }
      if (d.phase === "encrypting") {
        if (typeof onStatus === "function") onStatus("Encrypting…");
        return;
      }
      if (d.phase === "encoding") {
        if (typeof onStatus === "function") onStatus("Encoding…", d.progress);
        return;
      }
      if (d.phase === "returning") {
        if (typeof onStatus === "function") onStatus("Decrypting…", 1);
        if (typeof onMsg._beginReturn === "function") onMsg._beginReturn(d.plainLen | 0);
        worker.postMessage({ op: "plain-more" });
        return;
      }
      if (d.plainChunk) {
        if (typeof onMsg._gotChunk === "function") onMsg._gotChunk(d.plainChunk);
        worker.postMessage({ op: "plain-more" });
        return;
      }
      cleanup();
      if (d.ok && d.done && typeof onMsg._finish === "function") {
        resolve(onMsg._finish());
        return;
      }
      if (d.ok && d[okKey]) resolve(new Uint8Array(d[okKey]));
      else reject(new Error(d.error || "Decrypt failed"));
    }
    function onErr(ev) {
      fail(new Error((ev && ev.message) || "Decrypt worker failed"));
    }
    worker.addEventListener("message", onMsg);
    worker.addEventListener("error", onErr);
    return { onMsg: onMsg, fail: fail };
  }

  function decryptAesGcmInWorker(worker, rawBuf, start, end, keyBytes, iv, onStatus) {
    return new Promise(function (resolve, reject) {
      if (!(rawBuf instanceof ArrayBuffer) || start == null || end == null || end < start) {
        reject(new Error("Decrypt worker missing ciphertext."));
        return;
      }
      var asciiLen = end - start;
      var src = new Uint8Array(rawBuf, start, asciiLen);
      var offset = 0;
      var keyCopy = keyBytes.slice();
      var ivCopy = iv instanceof Uint8Array ? iv.slice() : new Uint8Array(iv);
      var chunks = [];
      var h = listenAesWorker(worker, onStatus, "plain", resolve, reject);
      h.onMsg._beginReturn = function () {
        chunks = [];
      };
      h.onMsg._gotChunk = function (buf) {
        chunks.push(buf);
      };
      h.onMsg._finish = function () {
        return chunks;
      };
      h.onMsg._pump = function () {
        if (offset >= asciiLen) {
          src = null;
          try {
            if (rawBuf && typeof rawBuf.transfer === "function") rawBuf.transfer(0);
          } catch (_) {}
          rawBuf = null;
          worker.postMessage({ op: "decrypt-end" });
          return;
        }
        var n = Math.min(AES_CHUNK, asciiLen - offset);
        var copy = new Uint8Array(n);
        copy.set(src.subarray(offset, offset + n));
        offset += n;
        worker.postMessage({ op: "decrypt-ascii", buf: copy.buffer }, [copy.buffer]);
      };
      worker.postMessage(
        {
          op: "decrypt-start",
          key: keyCopy.buffer,
          iv: ivCopy.buffer,
          asciiLen: asciiLen,
        },
        [keyCopy.buffer, ivCopy.buffer]
      );
    });
  }

  function transferablePlain(bytes) {
    var u8 = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
    if (
      u8.byteOffset === 0 &&
      u8.byteLength === u8.buffer.byteLength &&
      u8.buffer instanceof ArrayBuffer
    ) {
      return u8.buffer;
    }
    return u8.slice().buffer;
  }

  function encryptAesGcmInWorker(worker, plainBuf, keyBytes, iv, onStatus) {
    return new Promise(function (resolve, reject) {
      if (!(plainBuf instanceof ArrayBuffer)) {
        reject(new Error("Encrypt worker missing plaintext."));
        return;
      }
      var src = new Uint8Array(plainBuf);
      var offset = 0;
      var keyCopy = keyBytes instanceof Uint8Array ? keyBytes : new Uint8Array(keyBytes);
      var ivCopy = iv instanceof Uint8Array ? iv.slice() : new Uint8Array(iv);
      var keyAb =
        keyCopy.byteOffset === 0 && keyCopy.byteLength === keyCopy.buffer.byteLength
          ? keyCopy.buffer
          : keyCopy.slice().buffer;
      var h = listenAesWorker(worker, onStatus, "ciphertext", resolve, reject);
      h.onMsg._pump = function () {
        if (offset >= src.length) {
          src = null;
          try {
            if (plainBuf && typeof plainBuf.transfer === "function") plainBuf.transfer(0);
          } catch (_) {}
          plainBuf = null;
          worker.postMessage({ op: "encrypt-end" });
          return;
        }
        var n = Math.min(AES_CHUNK, src.length - offset);
        var copy = new Uint8Array(n);
        copy.set(src.subarray(offset, offset + n));
        offset += n;
        worker.postMessage({ op: "encrypt-plain", buf: copy.buffer }, [copy.buffer]);
      };
      worker.postMessage(
        {
          op: "encrypt-start",
          key: keyAb,
          iv: ivCopy.buffer,
          plainLen: src.length,
        },
        [keyAb, ivCopy.buffer]
      );
    });
  }

  // ---------------------------------------------------------------------------
  // ECDH + HKDF + AES-GCM key wrap
  // ---------------------------------------------------------------------------

  /**
   * X25519 ECDH shared secret: scalarMult(ourSecret, theirPublic).
   */
  function ecdhShared(secretKey, publicKey) {
    requireNacl();
    const shared = global.nacl.scalarMult(secretKey, publicKey);
    return new Uint8Array(shared);
  }

  /**
   * HKDF-SHA-256 → 32-byte AES key from ECDH shared secret.
   *
   * Steps:
   * 1. Import shared secret as HKDF IKM
   * 2. Derive bits with salt=zeros, info="sendit-v1-wrap", length=256
   */
  async function deriveWrapKey(sharedSecret) {
    const subtle = requireSubtle();
    const baseKey = await subtle.importKey(
      "raw",
      sharedSecret,
      "HKDF",
      false,
      ["deriveBits"]
    );
    const bits = await subtle.deriveBits(
      {
        name: "HKDF",
        hash: "SHA-256",
        salt: HKDF_SALT,
        info: HKDF_INFO,
      },
      baseKey,
      AES_KEY_BITS
    );
    return new Uint8Array(bits);
  }

  /**
   * Wrap AES payload key K for a recipient X25519 public key.
   *
   * Steps:
   * 1. Generate ephemeral X25519 keypair (ephSk, ephPk)
   * 2. shared = X25519(ephSk, recipientPublicKey)
   * 3. wrapKey = HKDF-SHA-256(shared, info="sendit-v1-wrap")
   * 4. Encrypt K with AES-GCM(wrapKey, wrapIv)
   * 5. Return { wrappedKey: wrapIv||ct, ephemeralPublicKey: ephPk }
   *
   * Recipient needs ephPk + their secret key to reverse this.
   */
  async function wrapKey(aesKeyBytes, recipientPublicKey) {
    if (aesKeyBytes.length !== 32) throw new Error("AES key must be 32 bytes.");
    if (recipientPublicKey.length !== X25519_LEN) {
      throw new Error("Recipient public key must be 32 bytes.");
    }

    const eph = generateKeyPair();
    const shared = ecdhShared(eph.secretKey, recipientPublicKey);
    // Best-effort wipe of ephemeral secret from our view (GC still applies).
    eph.secretKey.fill(0);

    const wrapKeyBytes = await deriveWrapKey(shared);
    shared.fill(0);

    const wrapIv = randomBytes(IV_LENGTH);
    const wk = await importAesKey(wrapKeyBytes, ["encrypt"]);
    wrapKeyBytes.fill(0);

    const wrapped = new Uint8Array(
      await requireSubtle().encrypt({ name: "AES-GCM", iv: wrapIv }, wk, aesKeyBytes)
    );

    // Layout: 12-byte IV || ciphertext+tag
    const packed = new Uint8Array(IV_LENGTH + wrapped.length);
    packed.set(wrapIv, 0);
    packed.set(wrapped, IV_LENGTH);

    return {
      wrappedKey: packed,
      ephemeralPublicKey: eph.publicKey,
    };
  }

  /**
   * Unwrap AES payload key using recipient secret key and sender ephemeral public key.
   *
   * Steps:
   * 1. shared = X25519(recipientSk, ephemeralPublicKey)
   * 2. wrapKey = HKDF-SHA-256(shared, ...)
   * 3. Split wrappedKey into wrapIv || ct
   * 4. AES-GCM decrypt → K
   */
  async function unwrapKey(wrappedKeyPacked, ephemeralPublicKey, recipientSecretKey) {
    if (wrappedKeyPacked.length < IV_LENGTH + 16) {
      throw new Error("wrappedKey too short.");
    }
    if (ephemeralPublicKey.length !== X25519_LEN) {
      throw new Error("ephemeralPublicKey must be 32 bytes.");
    }
    if (recipientSecretKey.length !== X25519_LEN) {
      throw new Error("recipient secret key must be 32 bytes.");
    }

    const wrapIv = wrappedKeyPacked.slice(0, IV_LENGTH);
    const ct = wrappedKeyPacked.slice(IV_LENGTH);

    const shared = ecdhShared(recipientSecretKey, ephemeralPublicKey);
    const wrapKeyBytes = await deriveWrapKey(shared);
    shared.fill(0);

    const wk = await importAesKey(wrapKeyBytes, ["decrypt"]);
    wrapKeyBytes.fill(0);

    const aesKey = new Uint8Array(
      await requireSubtle().decrypt({ name: "AES-GCM", iv: wrapIv }, wk, ct)
    );
    if (aesKey.length !== 32) throw new Error("Unwrapped key has unexpected length.");
    return aesKey;
  }

  // ---------------------------------------------------------------------------
  // High-level encrypt-for-recipient / decrypt-with-secret
  // ---------------------------------------------------------------------------

  /**
   * Encrypt a secret for a known recipient public key (send or collect-upload).
   * AES-GCM + base64url always run in the Blob worker (same path for every size).
   * Consumes `plaintextBytes` (buffer is transferred). `ciphertext` is unpadded
   * base64url as ASCII bytes (not a JS string) so the POST can Blob-assemble JSON
   * without JSON.stringify copying ~53 MiB.
   *
   * @param {Uint8Array} plaintextBytes
   * @param {Uint8Array} recipientPublicKey - 32-byte X25519 public key
   * @param {function(string, number=): void} [onStatus]
   * @returns wire object (ciphertext = Uint8Array of base64url ASCII)
   */
  async function encryptForRecipient(plaintextBytes, recipientPublicKey, onStatus) {
    requireSubtle();
    const keyBytes = randomBytes(32);
    const iv = randomBytes(IV_LENGTH);
    const keyCopy = keyBytes.slice();
    const ivCopy = iv.slice();
    const plainBuf = transferablePlain(plaintextBytes);
    try {
      const wrapped = await wrapKey(keyBytes, recipientPublicKey);
      const ascii = await withFreshAesWorker(function (w) {
        return encryptAesGcmInWorker(w, plainBuf, keyCopy, ivCopy, onStatus);
      });
      return {
        v: PROTOCOL_VERSION,
        ciphertext: ascii,
        iv: b64urlEncode(iv),
        wrappedKey: b64urlEncode(wrapped.wrappedKey),
        ephemeralPublicKey: b64urlEncode(wrapped.ephemeralPublicKey),
      };
    } finally {
      keyBytes.fill(0);
      try {
        keyCopy.fill(0);
      } catch (_) {
        /* transferred */
      }
    }
  }

  /**
   * Decrypt a wire payload using the recipient's X25519 secret key.
   * Ciphertext base64 is always decoded in the Blob worker (GET ingest bounds
   * or a UTF-8 view of the JSON `ciphertext` string — never on this thread).
   * @param {function(string): void} [onStatus] UI status ("Decoding…", "Decrypting…")
   */
  async function decryptWithSecretKey(payload, secretKey, onStatus) {
    await yieldUi();
    const iv = b64urlDecode(payload.iv);
    const wrappedKey = b64urlDecode(payload.wrappedKey);
    const ephPk = b64urlDecode(payload.ephemeralPublicKey);
    const aesKey = await unwrapKey(wrappedKey, ephPk, secretKey);

    var rawBuf = payload && payload._raw;
    var ctStart = payload && payload._ctStart;
    var ctEnd = payload && payload._ctEnd;
    if (!(rawBuf instanceof ArrayBuffer && ctStart != null && ctEnd != null)) {
      var raw = payload && payload.ciphertext;
      if (typeof raw !== "string" || !raw) {
        aesKey.fill(0);
        throw new Error("Invalid payload.");
      }
      var ascii = new TextEncoder().encode(raw);
      rawBuf = ascii.buffer;
      ctStart = ascii.byteOffset;
      ctEnd = ascii.byteOffset + ascii.byteLength;
    }
    if (payload) {
      payload.ciphertext = null;
      payload._raw = null;
    }
    if (typeof onStatus === "function") onStatus("Decoding…", 0);
    await yieldUi();
    try {
      const plain = await decryptPayload(aesKey, iv, rawBuf, ctStart, ctEnd, onStatus);
      await yieldUi();
      return plain;
    } finally {
      aesKey.fill(0);
    }
  }

  /**
   * Collect name dual-access encryption: AES-256-GCM key = SHA-256(publicKey).
   * Server stores ciphertext only. Upload decrypts with publicKey from meta (after PoW);
   * collect page derives publicKey from #sk=. Uses digest (not HKDF) for wide browser support.
   */
  async function deriveCollectNameKey(publicKey) {
    if (!(publicKey instanceof Uint8Array) || publicKey.length !== X25519_LEN) {
      throw new Error("Collect public key must be 32 bytes.");
    }
    // Domain-separate from other SHA-256 uses of the public key bytes.
    const input = new Uint8Array(16 + publicKey.length);
    input.set(new TextEncoder().encode("sendit-v1-cname"), 0);
    input.set(publicKey, 16);
    return new Uint8Array(await requireSubtle().digest("SHA-256", input));
  }

  /**
   * Encrypt collect name bound to the collect X25519 public key (not plaintext on server).
   * @returns wire { v, bound, ciphertext, iv } base64url fields
   */
  async function encryptCollectName(plaintextBytes, publicKey) {
    const keyBytes = await deriveCollectNameKey(publicKey);
    try {
      const iv = randomBytes(IV_LENGTH);
      const key = await importAesKey(keyBytes, ["encrypt"]);
      const ciphertext = new Uint8Array(
        await requireSubtle().encrypt({ name: "AES-GCM", iv: iv }, key, plaintextBytes)
      );
      return {
        v: PROTOCOL_VERSION,
        bound: "collect-pk-v2",
        ciphertext: b64urlEncode(ciphertext),
        iv: b64urlEncode(iv),
      };
    } finally {
      keyBytes.fill(0);
    }
  }

  /**
   * Decrypt collect name with the collect public key (from meta after PoW, or derived from #sk=).
   */
  async function decryptCollectName(wire, publicKey) {
    if (!wire) throw new Error("Invalid collect name ciphertext.");
    const ctB64 = wire.ciphertext || wire.Ciphertext;
    const ivB64 = wire.iv || wire.Iv;
    if (!ctB64 || !ivB64) throw new Error("Invalid collect name ciphertext.");
    const keyBytes = await deriveCollectNameKey(publicKey);
    try {
      const ivBytes = b64urlDecode(ivB64);
      const ciphertext = b64urlDecode(ctB64);
      if (ivBytes.length !== IV_LENGTH) throw new Error("Invalid collect name IV.");
      const key = await importAesKey(keyBytes, ["decrypt"]);
      return new Uint8Array(
        await requireSubtle().decrypt({ name: "AES-GCM", iv: ivBytes }, key, ciphertext)
      );
    } finally {
      keyBytes.fill(0);
    }
  }

  /**
   * Load PBKDF2 parameters for password-wrapping the fragment sk.
   * Same iteration count / hash as UDK wrap (bound to server password policy).
   */
  async function ensurePasswordWrapParams() {
    if (pwWrapParamsLoaded) return;
    try {
      const res = await fetch("/api/plugins/secret-sharing/crypto/params", { credentials: "same-origin" });
      if (res.ok) {
        const p = await res.json();
        // Prefer skWrap* when present; fall back to udkWrap* (same policy).
        const iters = p.skWrapIterations || p.udkWrapIterations;
        if (iters > 0) PW_WRAP_ITERATIONS = iters | 0;
        const hash = p.skWrapHash || p.udkWrapHash;
        if (hash) PW_WRAP_HASH = String(hash);
      }
    } catch {
      /* keep defaults */
    }
    pwWrapParamsLoaded = true;
  }

  /**
   * PBKDF2 → AES-256-GCM key (256 bits). Used only for password-wrapping fragment sk.
   */
  async function derivePasswordWrapKey(password, salt, iterations, hashName) {
    const subtle = requireSubtle();
    const enc = new TextEncoder();
    const hash = hashName || PW_WRAP_HASH || "SHA-512";
    const baseKey = await subtle.importKey(
      "raw",
      enc.encode(password),
      "PBKDF2",
      false,
      ["deriveBits"]
    );
    const bits = await subtle.deriveBits(
      { name: "PBKDF2", hash: hash, salt, iterations },
      baseKey,
      256
    );
    return subtle.importKey("raw", bits, { name: "AES-GCM" }, false, [
      "encrypt",
      "decrypt",
    ]);
  }

  /**
   * Wrap a 32-byte X25519 secret key with a password:
   *   wrapKey = PBKDF2-HMAC-SHA512(password, salt, i) → 32 bytes
   *   ct = AES-256-GCM(wrapKey, iv, sk)  // Web Crypto appends 128-bit tag to ct
   * Compact JSON for the fragment: { i, s, iv, ct } (no alg/v/purpose on wire).
   */
  async function wrapSecretKeyWithPassword(secretKey, password) {
    if (!(secretKey instanceof Uint8Array) || secretKey.length !== X25519_LEN) {
      throw new Error("Secret key must be 32 bytes.");
    }
    if (typeof password !== "string" || !password) {
      throw new Error("Password is required to wrap the decryption key.");
    }
    await ensurePasswordWrapParams();
    const salt = crypto.getRandomValues(new Uint8Array(PW_WRAP_SALT_LEN));
    const iv = crypto.getRandomValues(new Uint8Array(PW_WRAP_IV_LEN));
    const key = await derivePasswordWrapKey(
      password,
      salt,
      PW_WRAP_ITERATIONS,
      PW_WRAP_HASH
    );
    // AES-GCM: ciphertext || 16-byte auth tag (32+16 = 48 bytes for sk).
    const ct = new Uint8Array(
      await requireSubtle().encrypt({ name: "AES-GCM", iv }, key, secretKey)
    );
    if (ct.length < X25519_LEN + GCM_TAG_LEN) {
      throw new Error("AES-GCM wrap produced unexpected length.");
    }
    return JSON.stringify({
      i: PW_WRAP_ITERATIONS,
      s: b64urlEncode(salt),
      iv: b64urlEncode(iv),
      ct: b64urlEncode(ct),
    });
  }

  /**
   * Unwrap password-protected secret-key package → 32-byte X25519 sk.
   * Package: { i, s, iv, ct }. Algorithm fixed: PBKDF2-SHA512 + AES-256-GCM.
   */
  async function unwrapSecretKeyWithPassword(packageJson, password) {
    if (typeof password !== "string" || !password) {
      throw new Error("Password is required.");
    }
    const pkg =
      typeof packageJson === "string" ? JSON.parse(packageJson) : packageJson;
    if (!pkg || !pkg.s || !pkg.iv || !pkg.ct) {
      throw new Error("Invalid password-protected key package.");
    }
    const iterations = typeof pkg.i === "number" && pkg.i > 0 ? pkg.i : PW_WRAP_ITERATIONS;
    if (iterations !== 893241) throw new Error("Unsupported wrap parameters.");
    const salt = b64urlDecode(pkg.s);
    const iv = b64urlDecode(pkg.iv);
    const ct = b64urlDecode(pkg.ct);
    if (salt.length !== PW_WRAP_SALT_LEN) throw new Error("Invalid wrap salt length.");
    if (iv.length !== PW_WRAP_IV_LEN) throw new Error("Invalid wrap IV length.");
    // ct must include AES-GCM tag + plaintext (32-byte sk).
    if (ct.length < X25519_LEN + GCM_TAG_LEN) {
      throw new Error("Invalid wrap ciphertext length.");
    }
    const key = await derivePasswordWrapKey(
      password,
      salt,
      iterations,
      PW_WRAP_HASH || "SHA-512"
    );
    let plain;
    try {
      plain = new Uint8Array(
        await requireSubtle().decrypt({ name: "AES-GCM", iv }, key, ct)
      );
    } catch {
      throw new Error("Incorrect password or corrupted key package.");
    }
    if (plain.length !== X25519_LEN) {
      throw new Error("Unwrapped key has unexpected length.");
    }
    return plain;
  }

  /** Raw #sk= value from the fragment (string), or null. */
  function rawSkParamFromHash(hash) {
    const h = (hash || "").replace(/^#/, "");
    if (!h) return null;
    const params = new URLSearchParams(h);
    const sk = params.get("sk");
    if (sk) return sk;
    // Bare base64url fragment (legacy short form for raw 32-byte keys only).
    if (/^[A-Za-z0-9_-]+$/.test(h)) return h;
    return null;
  }

  /**
   * Parse #sk=... as a raw 32-byte X25519 key (unprotected sends).
   * Requires canonical base64url so last-character padding variants fail closed.
   */
  function secretKeyFromLocationHash(hash) {
    const sk = rawSkParamFromHash(hash);
    if (!sk) return null;
    return b64urlDecodeCanonical(sk, X25519_LEN);
  }

  /**
   * Parse #sk= as a password-wrap package JSON string (password-protected sends).
   * Package is UTF-8 JSON, base64url-encoded in the fragment.
   */
  function secretKeyPackageFromLocationHash(hash) {
    const sk = rawSkParamFromHash(hash);
    if (!sk || sk.length < 44) return null; // raw keys are exactly 43 chars
    try {
      const bytes = b64urlDecode(sk);
      const text = new TextDecoder().decode(bytes);
      const pkg = JSON.parse(text);
      if (!pkg || !pkg.s || !pkg.iv || !pkg.ct) return null;
      return text;
    } catch {
      return null;
    }
  }

  function buildFragment(secretKey) {
    return "#sk=" + b64urlEncode(secretKey);
  }

  /** Fragment for password-wrapped sk (package JSON → base64url). */
  function buildPasswordProtectedFragment(packageJson) {
    const bytes = new TextEncoder().encode(packageJson);
    return "#sk=" + b64urlEncode(bytes);
  }

  /** Decrypt result → one Uint8Array (joins a chunk list via Blob if needed). */
  async function plainToBytes(plain) {
    if (plain instanceof Uint8Array) return plain;
    if (plain instanceof ArrayBuffer) return new Uint8Array(plain);
    if (Array.isArray(plain)) {
      return new Uint8Array(await new Blob(plain).arrayBuffer());
    }
    if (plain && typeof plain.arrayBuffer === "function") {
      return new Uint8Array(await plain.arrayBuffer());
    }
    throw new Error("Decrypt failed");
  }

  /** Decrypt result → UTF-8 text (chunk list becomes a Blob, not one huge Uint8Array). */
  async function plainToText(plain) {
    if (typeof plain === "string") return plain;
    if (plain instanceof Uint8Array || plain instanceof ArrayBuffer) {
      return new TextDecoder().decode(plain);
    }
    if (Array.isArray(plain)) return await new Blob(plain).text();
    if (plain && typeof plain.text === "function") return await plain.text();
    return new TextDecoder().decode(await plainToBytes(plain));
  }

  /** Decrypt result → download Blob. An ArrayBuffer[] is passed through as Blob parts. */
  function plainToBlob(plain, type) {
    var t = type || "application/octet-stream";
    if (plain instanceof Blob) return plain;
    if (Array.isArray(plain)) return new Blob(plain, { type: t });
    return new Blob([plain], { type: t });
  }

  // Public API (page scripts + dashboard). Internal helpers stay private.
  global.SenditCrypto = {
    b64urlEncode,
    b64urlDecode,
    generateKeyPair,
    keyPairFromSecretKey,
    ingestPayloadResponse,
    encryptForRecipient,
    decryptWithSecretKey,
    plainToBytes,
    plainToText,
    plainToBlob,
    encryptCollectName,
    decryptCollectName,
    secretKeyFromLocationHash,
    secretKeyPackageFromLocationHash,
    buildFragment,
    buildPasswordProtectedFragment,
    wrapSecretKeyWithPassword,
    unwrapSecretKeyWithPassword,
  };
})(typeof window !== "undefined" ? window : globalThis);
