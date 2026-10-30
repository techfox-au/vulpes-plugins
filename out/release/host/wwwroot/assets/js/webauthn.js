// WebAuthn helpers: convert server options <-> browser credential objects, with graceful fallbacks
// for browsers lacking PublicKeyCredential.parseCreationOptionsFromJSON / toJSON.
import { api } from './api.js';

export function isSupported() {
  return typeof window.PublicKeyCredential !== 'undefined' && typeof navigator.credentials?.create === 'function';
}

export async function conditionalMediationAvailable() {
  try { return isSupported() && typeof PublicKeyCredential.isConditionalMediationAvailable === 'function' && await PublicKeyCredential.isConditionalMediationAvailable(); }
  catch { return false; }
}

function b64urlToBuf(s) {
  const pad = '='.repeat((4 - (s.length % 4)) % 4);
  const bin = atob((s + pad).replace(/-/g, '+').replace(/_/g, '/'));
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes.buffer;
}

function bufToB64url(buf) {
  const bytes = new Uint8Array(buf);
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function parseCreationOptions(json) {
  if (typeof PublicKeyCredential.parseCreationOptionsFromJSON === 'function') return PublicKeyCredential.parseCreationOptionsFromJSON(json);
  const o = structuredClone(json);
  o.challenge = b64urlToBuf(o.challenge);
  o.user.id = b64urlToBuf(o.user.id);
  for (const c of o.excludeCredentials || []) c.id = b64urlToBuf(c.id);
  return o;
}

function parseRequestOptions(json) {
  if (typeof PublicKeyCredential.parseRequestOptionsFromJSON === 'function') return PublicKeyCredential.parseRequestOptionsFromJSON(json);
  const o = structuredClone(json);
  o.challenge = b64urlToBuf(o.challenge);
  for (const c of o.allowCredentials || []) c.id = b64urlToBuf(c.id);
  return o;
}

function credentialToJSON(credential) {
  if (typeof credential.toJSON === 'function') return credential.toJSON();
  const r = credential.response;
  const response = { clientDataJSON: bufToB64url(r.clientDataJSON) };
  if (r.attestationObject) {
    response.attestationObject = bufToB64url(r.attestationObject);
    if (typeof r.getTransports === 'function') response.transports = r.getTransports();
  }
  if (r.authenticatorData) {
    response.authenticatorData = bufToB64url(r.authenticatorData);
    response.signature = bufToB64url(r.signature);
    response.userHandle = r.userHandle ? bufToB64url(r.userHandle) : null;
  }
  return {
    id: credential.id,
    rawId: bufToB64url(credential.rawId),
    type: credential.type,
    authenticatorAttachment: credential.authenticatorAttachment ?? null,
    clientExtensionResults: credential.getClientExtensionResults ? credential.getClientExtensionResults() : {},
    response,
  };
}

/**
 * Runs a registration ceremony.
 * optionsUrl: POST endpoint returning creation options JSON; finishUrl: POST endpoint receiving { credential, ...extra }.
 */
export async function register({ optionsUrl, finishUrl, optionsBody = {}, extra = {}, signal }) {
  if (!isSupported()) throw new Error('This browser does not support passkeys.');
  const options = await api.post(optionsUrl, optionsBody, { signal });
  const publicKey = parseCreationOptions(options);
  const credential = await navigator.credentials.create({ publicKey, signal });
  if (!credential) throw new Error('No credential was created.');
  return api.post(finishUrl, { credential: credentialToJSON(credential), ...extra }, { signal });
}

/**
 * Runs an authentication ceremony. With mediation 'conditional' the promise stays pending until the user picks a
 * passkey from the browser's autofill UI; pass an AbortController signal to cancel it (e.g. when switching to password).
 */
export async function authenticate({ optionsUrl, finishUrl, optionsBody = {}, extra = {}, mediation, signal }) {
  if (!isSupported()) throw new Error('This browser does not support passkeys.');
  const options = await api.post(optionsUrl, optionsBody, { signal });
  const publicKey = parseRequestOptions(options);
  const credential = await navigator.credentials.get({ publicKey, mediation, signal });
  if (!credential) throw new Error('No credential was provided.');
  return api.post(finishUrl, { credential: credentialToJSON(credential), ...extra }, { signal });
}

export function describeError(err) {
  if (!err) return 'Passkey operation failed.';
  if (err.name === 'NotAllowedError') return 'The passkey request was cancelled or timed out.';
  if (err.name === 'InvalidStateError') return 'This passkey is already registered.';
  if (err.name === 'AbortError') return '';
  if (err.name === 'SecurityError') return 'Passkeys require a secure (https) origin matching the configured public origin.';
  return err.message || 'Passkey operation failed.';
}
