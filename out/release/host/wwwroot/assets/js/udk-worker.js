/**
 * Holds the user-data key for this tab. The page sends work in and receives
 * ciphertext or plaintext back. The raw key is not posted out.
 */
(function () {
  "use strict";
  const DB = "vulpes-udk";
  const STORE = "key";
  const UDK_BYTES = 32;
  const WRAP_ITERATIONS = 893241;

  let raw = null;
  let key = null;
  let userId = null;

  function b64urlEncode(bytes) {
    let bin = "";
    const arr = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
    for (let i = 0; i < arr.length; i++) bin += String.fromCharCode(arr[i]);
    return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
  }

  function b64urlDecode(str) {
    let s = String(str).replace(/-/g, "+").replace(/_/g, "/");
    while (s.length % 4) s += "=";
    const bin = atob(s);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }

  function subtle() {
    if (!crypto.subtle) throw new Error("Web Crypto is unavailable. Open this site with HTTPS or localhost.");
    return crypto.subtle;
  }

  async function importAes(bytes, usages) {
    return subtle().importKey("raw", bytes, { name: "AES-GCM" }, false, usages);
  }

  async function deriveWrapKey(password, salt) {
    const baseKey = await subtle().importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveBits"]);
    const bits = await subtle().deriveBits({ name: "PBKDF2", hash: "SHA-512", salt, iterations: WRAP_ITERATIONS }, baseKey, 256);
    return importAes(bits, ["encrypt", "decrypt"]);
  }

  function openDb() {
    return new Promise((resolve, reject) => {
      const req = indexedDB.open(DB, 1);
      req.onupgradeneeded = () => {
        const db = req.result;
        if (!db.objectStoreNames.contains(STORE)) db.createObjectStore(STORE);
      };
      req.onsuccess = () => {
        const db = req.result;
        db.onversionchange = () => {
          try { db.close(); } catch { /* already closed */ }
        };
        resolve(db);
      };
      req.onerror = () => reject(req.error || new Error("Could not open encryption storage."));
    });
  }

  function closeDb(db) {
    try { if (db) db.close(); } catch { /* already closed */ }
  }

  async function persist() {
    if (!key || !userId) return;
    let db = null;
    try {
      db = await openDb();
      await new Promise((resolve, reject) => {
        const tx = db.transaction(STORE, "readwrite");
        tx.objectStore(STORE).put({ userId, key }, "current");
        tx.oncomplete = () => resolve();
        tx.onerror = () => reject(tx.error || new Error("Could not store encryption."));
      });
    } catch {
      /* The key still works in this tab. A refresh asks again. */
    } finally {
      closeDb(db);
    }
  }

  async function hold(nextUser, bytes) {
    const copy = new Uint8Array(bytes);
    if (raw) raw.fill(0);
    raw = copy;
    key = await importAes(raw, ["encrypt", "decrypt"]);
    if (nextUser) userId = String(nextUser);
    await persist();
  }

  function forgetRaw() {
    if (raw) raw.fill(0);
    raw = null;
  }

  async function drop() {
    forgetRaw();
    key = null;
    userId = null;
    const db = await openDb();
    try {
      await new Promise((resolve, reject) => {
        const tx = db.transaction(STORE, "readwrite");
        tx.objectStore(STORE).delete("current");
        tx.oncomplete = () => resolve();
        tx.onerror = () => reject(tx.error || new Error("Could not clear encryption."));
      });
    } finally {
      closeDb(db);
    }
  }

  async function restore(nextUser) {
    const db = await openDb();
    let row;
    try {
      row = await new Promise((resolve, reject) => {
        const tx = db.transaction(STORE, "readonly");
        const req = tx.objectStore(STORE).get("current");
        req.onsuccess = () => resolve(req.result || null);
        req.onerror = () => reject(req.error || new Error("Could not read encryption."));
      });
    } finally {
      closeDb(db);
    }
    if (!row || !row.key || String(row.userId) !== String(nextUser)) {
      key = null;
      userId = null;
      forgetRaw();
      return false;
    }
    key = row.key;
    userId = String(nextUser);
    forgetRaw();
    return true;
  }

  async function encrypt(plain) {
    if (!key) throw new Error("Unlock encryption first.");
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = new Uint8Array(await subtle().encrypt({ name: "AES-GCM", iv }, key, plain));
    const packed = new Uint8Array(12 + ct.length);
    packed.set(iv, 0);
    packed.set(ct, 12);
    return b64urlEncode(packed);
  }

  async function decrypt(packedB64) {
    if (!key) throw new Error("Unlock encryption first.");
    const packed = b64urlDecode(packedB64);
    if (packed.length < 12 + 16) throw new Error("Ciphertext too short.");
    return new Uint8Array(await subtle().decrypt({ name: "AES-GCM", iv: packed.slice(0, 12) }, key, packed.slice(12)));
  }

  async function wrapPassword(password) {
    if (!raw) throw new Error("Unlock encryption again before wrapping it.");
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const wrapKey = await deriveWrapKey(password, salt);
    const ct = new Uint8Array(await subtle().encrypt({ name: "AES-GCM", iv }, wrapKey, raw));
    return JSON.stringify({ v: 1, alg: "PBKDF2-SHA512-AES-256-GCM", iterations: WRAP_ITERATIONS, salt: b64urlEncode(salt), iv: b64urlEncode(iv), ct: b64urlEncode(ct) });
  }

  async function wrapPrf(prfBytes) {
    if (!raw) throw new Error("Unlock encryption again before wrapping it.");
    if (!(prfBytes instanceof Uint8Array) || prfBytes.length !== UDK_BYTES) throw new Error("Passkey key material must be 32 bytes.");
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const wrapKey = await importAes(prfBytes, ["encrypt"]);
    const ct = new Uint8Array(await subtle().encrypt({ name: "AES-GCM", iv }, wrapKey, raw));
    return JSON.stringify({ v: 1, alg: "PRF-AES-256-GCM", iv: b64urlEncode(iv), ct: b64urlEncode(ct) });
  }

  async function unwrapPassword(packageJson, password, nextUser) {
    const pkg = typeof packageJson === "string" ? JSON.parse(packageJson) : packageJson;
    if (!pkg || pkg.v !== 1 || !pkg.salt || !pkg.iv || !pkg.ct) throw new Error("Invalid wrapped user data key package.");
    if (pkg.alg !== "PBKDF2-SHA512-AES-256-GCM" || pkg.iterations !== WRAP_ITERATIONS) throw new Error("Unsupported encryption package.");
    const salt = b64urlDecode(pkg.salt);
    const iv = b64urlDecode(pkg.iv);
    const ct = b64urlDecode(pkg.ct);
    if (salt.length !== 16 || iv.length !== 12 || ct.length !== UDK_BYTES + 16) throw new Error("Invalid wrapped user data key package.");
    const wrapKey = await deriveWrapKey(password, salt);
    const plain = new Uint8Array(await subtle().decrypt({ name: "AES-GCM", iv }, wrapKey, ct));
    if (plain.length !== UDK_BYTES) throw new Error("Unwrapped UDK has unexpected length.");
    try {
      await hold(nextUser, plain);
    } finally {
      plain.fill(0);
    }
  }

  async function unwrapPrf(packageJson, prfBytes, nextUser) {
    const pkg = typeof packageJson === "string" ? JSON.parse(packageJson) : packageJson;
    if (!pkg || pkg.v !== 1 || pkg.alg !== "PRF-AES-256-GCM" || !pkg.iv || !pkg.ct) throw new Error("Invalid passkey wrap.");
    if (!(prfBytes instanceof Uint8Array) || prfBytes.length !== UDK_BYTES) throw new Error("Passkey key material must be 32 bytes.");
    const iv = b64urlDecode(pkg.iv);
    const ct = b64urlDecode(pkg.ct);
    if (iv.length !== 12 || ct.length !== UDK_BYTES + 16) throw new Error("Invalid passkey wrap.");
    const wrapKey = await importAes(prfBytes, ["decrypt"]);
    const plain = new Uint8Array(await subtle().decrypt({ name: "AES-GCM", iv }, wrapKey, ct));
    if (plain.length !== UDK_BYTES) throw new Error("Unwrapped UDK has unexpected length.");
    try {
      await hold(nextUser, plain);
    } finally {
      plain.fill(0);
    }
  }

  self.onmessage = (ev) => {
    const msg = ev.data || {};
    Promise.resolve().then(async () => {
      if (msg.op === "generate") {
        const bytes = crypto.getRandomValues(new Uint8Array(UDK_BYTES));
        try {
          await hold(userId, bytes);
        } finally {
          bytes.fill(0);
        }
        return { raw: true };
      }
      if (msg.op === "importRaw") {
        const bytes = new Uint8Array(msg.raw);
        try {
          await hold(msg.userId || userId, bytes);
        } finally {
          bytes.fill(0);
        }
        return { raw: true };
      }
      if (msg.op === "adopt") {
        userId = String(msg.userId || "");
        await persist();
        return { raw: !!raw };
      }
      if (msg.op === "restore") return { unlocked: await restore(msg.userId) };
      if (msg.op === "status") return { unlocked: !!key, raw: !!raw, userId };
      if (msg.op === "clear") {
        await drop();
        return { unlocked: false };
      }
      if (msg.op === "encrypt") return { cipher: await encrypt(new Uint8Array(msg.plain)) };
      if (msg.op === "decrypt") return { plain: await decrypt(msg.cipher) };
      if (msg.op === "wrapPassword") return { wrapped: await wrapPassword(msg.password) };
      if (msg.op === "wrapPrf") return { wrapped: await wrapPrf(new Uint8Array(msg.prf)) };
      if (msg.op === "unwrapPassword") {
        await unwrapPassword(msg.package, msg.password, msg.userId);
        return { raw: true };
      }
      if (msg.op === "unwrapPrf") {
        await unwrapPrf(msg.package, new Uint8Array(msg.prf), msg.userId);
        return { raw: true };
      }
      throw new Error("Unknown encryption request.");
    }).then(
      (result) => self.postMessage({ id: msg.id, ok: true, result }),
      (err) => self.postMessage({ id: msg.id, ok: false, error: err && err.message ? err.message : "Encryption failed." })
    );
  };
})();
