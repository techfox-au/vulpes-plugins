/**
 * User data key. Wrapping matches Sendit: PBKDF2-SHA-512, 893241 iterations, AES-256-GCM.
 * The raw key stays in a same-origin worker. This page only keeps which account is unlocked.
 * A non-extractable copy is stored so a refresh in this tab does not ask again.
 * Idle time matches the account's session length. Activity in the tab keeps the key.
 */
(function (global) {
  "use strict";
  if (global.__vulpesUdkClient) {
    global.SecretUdk = global.__vulpesUdkClient;
    return;
  }

  const STORAGE_KEY = "vulpes_secret_sharing_udk";
  const DEFAULT_IDLE_MS = 8 * 60 * 60 * 1000;
  const DB = "vulpes-udk";
  let idleMs = null;
  let sessionUserId = "";
  let worker = null;
  let seq = 0;
  const pending = new Map();
  let gate = Promise.resolve();
  let readyPromise = null;
  let unlockedUser = null;
  let lastTouch = 0;

  function call(op, payload, transfer) {
    const id = ++seq;
    return new Promise((resolve, reject) => {
      pending.set(id, { resolve, reject });
      try {
        worker.postMessage(Object.assign({ id, op }, payload || {}), transfer || []);
      } catch (err) {
        pending.delete(id);
        reject(err);
      }
    });
  }

  function enqueue(op, payload, transfer) {
    const run = gate.then(() => call(op, payload, transfer));
    gate = run.then(() => {}, () => {});
    return run;
  }

  function startWorker() {
    if (worker) return;
    worker = new Worker("/assets/js/udk-worker.js?v=udk6");
    worker.onmessage = (ev) => {
      const msg = ev.data || {};
      const waiter = pending.get(msg.id);
      if (!waiter) return;
      pending.delete(msg.id);
      if (msg.ok) waiter.resolve(msg.result || {});
      else waiter.reject(new Error(msg.error || "Encryption failed."));
    };
    worker.onerror = () => {
      pending.forEach((waiter) => waiter.reject(new Error("Encryption failed.")));
      pending.clear();
    };
  }

  function readSession() {
    let raw;
    try { raw = sessionStorage.getItem(STORAGE_KEY); } catch { return null; }
    if (!raw) return null;
    try { return JSON.parse(raw); } catch { return null; }
  }

  function writeSession(userId) {
    const now = Date.now();
    lastTouch = now;
    try {
      sessionStorage.setItem(STORAGE_KEY, JSON.stringify({ v: 3, userId: String(userId), touched: now }));
    } catch { /* storage can be blocked */ }
  }

  function dropSession() {
    try { sessionStorage.removeItem(STORAGE_KEY); } catch { /* storage can be blocked */ }
  }

  function deleteStore() {
    return new Promise((resolve, reject) => {
      try {
        const request = indexedDB.deleteDatabase(DB);
        request.onsuccess = () => resolve();
        request.onerror = () => reject(request.error || new Error("Could not delete encryption storage."));
        request.onblocked = () => { /* Another tab still has the database. Wait until it closes. */ };
      } catch (err) {
        reject(err);
      }
    });
  }

  function sentinel(userId) {
    return { v: 3, userId: String(userId || unlockedUser || "") };
  }

  function noteActivity() {
    if (!unlockedUser) return;
    const now = Date.now();
    if (now - lastTouch < 60000) return;
    const rec = readSession();
    if (!rec || String(rec.userId) !== unlockedUser) return;
    writeSession(unlockedUser);
  }

  function clearUserDataKey() {
    unlockedUser = null;
    lastTouch = 0;
    dropSession();
    const wiping = (worker ? call("clear").catch(() => {}) : Promise.resolve()).then(() => deleteStore());
    gate = wiping.then(() => {}, () => {});
    return wiping;
  }

  async function loadIdleMs() {
    if (idleMs != null) return idleMs;
    try {
      const res = await fetch("/api/session", { credentials: "same-origin", headers: { Accept: "application/json" } });
      const data = await res.json();
      if (!data || data.authenticated !== true) {
        idleMs = 0;
        sessionUserId = "";
        return 0;
      }
      const seconds = Number(data.user && data.user.sessionLifetimeSeconds);
      idleMs = Number.isFinite(seconds) && seconds >= 60 ? seconds * 1000 : DEFAULT_IDLE_MS;
      sessionUserId = data.user && data.user.id ? String(data.user.id) : "";
    } catch {
      idleMs = DEFAULT_IDLE_MS;
      sessionUserId = "";
    }
    return idleMs;
  }

  async function ready() {
    if (!readyPromise) {
      startWorker();
      readyPromise = restore();
    }
    return readyPromise;
  }

  async function restore() {
    const rec = readSession();
    if (!rec || rec.v !== 3 || !rec.userId || rec.key) {
      await clearUserDataKey();
      return;
    }
    const limit = await loadIdleMs();
    if (limit === 0 || (sessionUserId && sessionUserId !== String(rec.userId)) || Date.now() - Number(rec.touched || 0) > limit) {
      await clearUserDataKey();
      return;
    }
    const status = await enqueue("restore", { userId: String(rec.userId) });
    if (!status.unlocked) {
      await clearUserDataKey();
      return;
    }
    unlockedUser = String(rec.userId);
    lastTouch = Number(rec.touched) || Date.now();
  }

  function loadUserDataKey(userId) {
    if (!userId || !unlockedUser || String(userId) !== unlockedUser) return null;
    noteActivity();
    return sentinel(userId);
  }

  function storeUserDataKey(_udk, userId) {
    if (!userId) throw new Error("User data key requires an account.");
    unlockedUser = String(userId);
    writeSession(userId);
    if (idleMs == null) loadIdleMs();
    return enqueue("adopt", { userId: unlockedUser });
  }

  async function generateUserDataKey() {
    await ready();
    await enqueue("generate");
    return sentinel(unlockedUser);
  }

  async function canRewrap() {
    await ready();
    const status = await enqueue("status");
    return !!status.raw;
  }

  async function wrapUserDataKey(_udk, password) {
    await ready();
    const result = await enqueue("wrapPassword", { password });
    return result.wrapped;
  }

  async function wrapUserDataKeyWithPrf(_udk, prfBytes) {
    await ready();
    const prf = prfBytes instanceof Uint8Array ? prfBytes : new Uint8Array(prfBytes);
    const result = await enqueue("wrapPrf", { prf }, [prf.buffer]);
    return result.wrapped;
  }

  async function unwrapUserDataKey(packageJson, password) {
    await ready();
    await enqueue("unwrapPassword", { package: packageJson, password, userId: unlockedUser });
    return sentinel(unlockedUser);
  }

  async function unwrapUserDataKeyWithPrf(packageJson, prfBytes) {
    await ready();
    const prf = prfBytes instanceof Uint8Array ? prfBytes : new Uint8Array(prfBytes);
    await enqueue("unwrapPrf", { package: packageJson, prf, userId: unlockedUser }, [prf.buffer]);
    return sentinel(unlockedUser);
  }

  async function encryptWithUserDataKey(plaintextBytes) {
    await ready();
    noteActivity();
    const plain = plaintextBytes instanceof Uint8Array ? plaintextBytes : new Uint8Array(plaintextBytes);
    const copy = plain.slice();
    const result = await enqueue("encrypt", { plain: copy }, [copy.buffer]);
    return result.cipher;
  }

  async function decryptWithUserDataKey(ciphertextB64) {
    await ready();
    noteActivity();
    const result = await enqueue("decrypt", { cipher: ciphertextB64 });
    return result.plain instanceof Uint8Array ? result.plain : new Uint8Array(result.plain);
  }

  if (global.document) {
    global.document.addEventListener("pointerdown", noteActivity, true);
    global.document.addEventListener("keydown", noteActivity, true);
  }
  global.setInterval(() => {
    if (!unlockedUser || idleMs == null) return;
    const rec = readSession();
    if (!rec || idleMs === 0 || Date.now() - Number(rec.touched || 0) > idleMs) {
      clearUserDataKey();
      return;
    }
    fetch("/api/session", { credentials: "same-origin", headers: { Accept: "application/json" } })
      .then((res) => res.json())
      .then((data) => {
        const id = data && data.authenticated === true && data.user && data.user.id ? String(data.user.id) : "";
        if (!data || data.authenticated !== true || (id && id !== unlockedUser)) clearUserDataKey();
      })
      .catch(() => {});
  }, 60000);

  const api = {
    ready,
    canRewrap,
    generateUserDataKey,
    wrapUserDataKey,
    unwrapUserDataKey,
    wrapUserDataKeyWithPrf,
    unwrapUserDataKeyWithPrf,
    storeUserDataKey,
    loadUserDataKey,
    clearUserDataKey,
    encryptWithUserDataKey,
    decryptWithUserDataKey,
  };
  global.__vulpesUdkClient = api;
  global.SecretUdk = api;
})(typeof window !== "undefined" ? window : globalThis);
