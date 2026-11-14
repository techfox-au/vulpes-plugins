/**
 * User data key wrap. Same package as Sendit: PBKDF2-SHA-512, 893241 iterations, AES-256-GCM.
 * Wire package: { v:1, alg:"PBKDF2-SHA512-AES-256-GCM", iterations, salt, iv, ct } base64url.
 * Encrypt of owner fields: base64url( iv(12) || ciphertext || tag ).
 */
(function (global) {
  "use strict";
  const STORAGE_KEY = "vulpes_secret_sharing_udk";
  const WRAP_ITERATIONS = 893241;
  const UDK_BYTES = 32;

  function requireSubtle() {
    const subtle = global.crypto && global.crypto.subtle;
    if (!subtle) throw new Error("Web Crypto is unavailable. Open this site with HTTPS or localhost.");
    return subtle;
  }
  function b64urlEncode(bytes) {
    let bin = "";
    const arr = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
    for (let i = 0; i < arr.length; i++) bin += String.fromCharCode(arr[i]);
    return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
  }
  function b64urlDecode(str) {
    let s = str.replace(/-/g, "+").replace(/_/g, "/");
    while (s.length % 4) s += "=";
    const bin = atob(s);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }
  async function deriveWrapKey(password, salt, iterations) {
    const subtle = requireSubtle();
    const baseKey = await subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveBits"]);
    const bits = await subtle.deriveBits({ name: "PBKDF2", hash: "SHA-512", salt, iterations }, baseKey, 256);
    return subtle.importKey("raw", bits, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
  }
  function generateUserDataKey() { return crypto.getRandomValues(new Uint8Array(UDK_BYTES)); }
  async function wrapUserDataKey(udkBytes, password) {
    if (!(udkBytes instanceof Uint8Array) || udkBytes.length !== UDK_BYTES) throw new Error("User data key must be 32 bytes.");
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const key = await deriveWrapKey(password, salt, WRAP_ITERATIONS);
    const ct = new Uint8Array(await requireSubtle().encrypt({ name: "AES-GCM", iv }, key, udkBytes));
    return JSON.stringify({ v: 1, alg: "PBKDF2-SHA512-AES-256-GCM", iterations: WRAP_ITERATIONS, salt: b64urlEncode(salt), iv: b64urlEncode(iv), ct: b64urlEncode(ct) });
  }
  async function unwrapUserDataKey(packageJson, password) {
    const pkg = typeof packageJson === "string" ? JSON.parse(packageJson) : packageJson;
    if (!pkg || pkg.v !== 1 || !pkg.salt || !pkg.iv || !pkg.ct) throw new Error("Invalid wrapped user data key package.");
    if (pkg.alg !== "PBKDF2-SHA512-AES-256-GCM" || pkg.iterations !== WRAP_ITERATIONS) throw new Error("Unsupported encryption package.");
    const salt = b64urlDecode(pkg.salt);
    const iv = b64urlDecode(pkg.iv);
    const ct = b64urlDecode(pkg.ct);
    if (salt.length !== 16 || iv.length !== 12 || ct.length !== UDK_BYTES + 16) throw new Error("Invalid wrapped user data key package.");
    const plain = new Uint8Array(await requireSubtle().decrypt({ name: "AES-GCM", iv }, await deriveWrapKey(password, salt, WRAP_ITERATIONS), ct));
    if (plain.length !== UDK_BYTES) throw new Error("Unwrapped UDK has unexpected length.");
    return plain;
  }
  async function wrapUserDataKeyWithPrf(udkBytes, prfBytes) {
    if (!(udkBytes instanceof Uint8Array) || udkBytes.length !== UDK_BYTES) throw new Error("User data key must be 32 bytes.");
    if (!(prfBytes instanceof Uint8Array) || prfBytes.length !== UDK_BYTES) throw new Error("Passkey key material must be 32 bytes.");
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const key = await requireSubtle().importKey("raw", prfBytes, { name: "AES-GCM" }, false, ["encrypt"]);
    const ct = new Uint8Array(await requireSubtle().encrypt({ name: "AES-GCM", iv }, key, udkBytes));
    return JSON.stringify({ v: 1, alg: "PRF-AES-256-GCM", iv: b64urlEncode(iv), ct: b64urlEncode(ct) });
  }
  async function unwrapUserDataKeyWithPrf(packageJson, prfBytes) {
    const pkg = typeof packageJson === "string" ? JSON.parse(packageJson) : packageJson;
    if (!pkg || pkg.v !== 1 || pkg.alg !== "PRF-AES-256-GCM" || !pkg.iv || !pkg.ct) throw new Error("Invalid passkey wrap.");
    const iv = b64urlDecode(pkg.iv);
    const ct = b64urlDecode(pkg.ct);
    if (iv.length !== 12 || ct.length !== UDK_BYTES + 16) throw new Error("Invalid passkey wrap.");
    const key = await requireSubtle().importKey("raw", prfBytes, { name: "AES-GCM" }, false, ["decrypt"]);
    const plain = new Uint8Array(await requireSubtle().decrypt({ name: "AES-GCM", iv }, key, ct));
    if (plain.length !== UDK_BYTES) throw new Error("Unwrapped UDK has unexpected length.");
    return plain;
  }
  function storeUserDataKey(udkBytes) { sessionStorage.setItem(STORAGE_KEY, b64urlEncode(udkBytes)); }
  function clearUserDataKey() { sessionStorage.removeItem(STORAGE_KEY); }
  function loadUserDataKey() {
    const s = sessionStorage.getItem(STORAGE_KEY);
    if (!s) return null;
    try { const b = b64urlDecode(s); return b.length === UDK_BYTES ? b : null; } catch { return null; }
  }
  async function encryptWithUserDataKey(plaintextBytes, udkBytes) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const key = await requireSubtle().importKey("raw", udkBytes, { name: "AES-GCM" }, false, ["encrypt"]);
    const ct = new Uint8Array(await requireSubtle().encrypt({ name: "AES-GCM", iv }, key, plaintextBytes));
    const packed = new Uint8Array(12 + ct.length);
    packed.set(iv, 0); packed.set(ct, 12);
    return b64urlEncode(packed);
  }
  async function decryptWithUserDataKey(ciphertextB64, udkBytes) {
    const packed = b64urlDecode(ciphertextB64);
    if (packed.length < 12 + 16) throw new Error("Ciphertext too short.");
    const key = await requireSubtle().importKey("raw", udkBytes, { name: "AES-GCM" }, false, ["decrypt"]);
    return new Uint8Array(await requireSubtle().decrypt({ name: "AES-GCM", iv: packed.slice(0, 12) }, key, packed.slice(12)));
  }
  global.SecretUdk = { generateUserDataKey, wrapUserDataKey, unwrapUserDataKey, wrapUserDataKeyWithPrf, unwrapUserDataKeyWithPrf, storeUserDataKey, loadUserDataKey, clearUserDataKey, encryptWithUserDataKey, decryptWithUserDataKey };
})(typeof window !== "undefined" ? window : globalThis);
