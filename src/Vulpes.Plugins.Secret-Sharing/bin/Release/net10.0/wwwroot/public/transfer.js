/**
 * Same upload and download path as Sendit api.js.
 * Ciphertext stays a Uint8Array of base64url ASCII and is spliced into a Blob.
 * Downloads use XHR arraybuffer so WebKit does not stream a huge fetch body.
 */
(function (global) {
  "use strict";
  var CT_PLACEHOLDER = "__SENDIT_CT_PLACEHOLDER__";

  function serializeJsonBody(body) {
    if (body == null) return "{}";
    var ct = body.ciphertext;
    if (ct instanceof ArrayBuffer) ct = new Uint8Array(ct);
    if (!(ct instanceof Uint8Array)) return JSON.stringify(body);
    body.ciphertext = CT_PLACEHOLDER;
    var s = JSON.stringify(body);
    body.ciphertext = null;
    var prefix = '"ciphertext":"';
    var needle = prefix + CT_PLACEHOLDER + '"';
    var i = s.indexOf(needle);
    if (i < 0) throw new Error("Invalid payload.");
    var head = s.slice(0, i + prefix.length);
    var tail = s.slice(i + needle.length - 1);
    return new Blob([head, ct, tail], { type: "application/json" });
  }

  function parseJson(text) {
    if (!text) return null;
    try { return JSON.parse(text); } catch (_) { return { error: text }; }
  }

  async function csrf() {
    var res = await fetch("/api/session", { credentials: "same-origin" });
    var data = await res.json();
    return data && data.csrfToken ? data.csrfToken : "";
  }

  function postJson(path, body, onUploadProgress) {
    var payload = serializeJsonBody(body == null ? {} : body);
    return csrf().then(function (token) {
      return new Promise(function (resolve, reject) {
        var xhr = new XMLHttpRequest();
        xhr.open("POST", path);
        xhr.withCredentials = true;
        xhr.setRequestHeader("Accept", "application/json");
        xhr.setRequestHeader("Content-Type", "application/json");
        if (token) xhr.setRequestHeader("X-CSRF-TOKEN", token);
        if (body && body.challengeId && body.nonce) {
          xhr.setRequestHeader("X-Sendit-Pow-Challenge", body.challengeId);
          xhr.setRequestHeader("X-Sendit-Pow-Nonce", String(body.nonce));
          if (body.hash) xhr.setRequestHeader("X-Sendit-Pow-Hash", body.hash);
        }
        if (typeof onUploadProgress === "function") {
          xhr.upload.onprogress = function (ev) {
            if (!ev.lengthComputable || ev.total <= 0) return;
            onUploadProgress(ev.loaded / ev.total, ev.loaded, ev.total);
          };
        }
        xhr.onload = function () {
          var data = parseJson(xhr.responseText);
          if (xhr.status >= 200 && xhr.status < 300) { resolve(data); return; }
          var err = new Error((data && (data.message || data.error)) || "Upload was rejected.");
          err.status = xhr.status;
          reject(err);
        };
        xhr.onerror = function () { reject(new Error("Network error while uploading.")); };
        xhr.onabort = function () { reject(new Error("Upload cancelled.")); };
        xhr.send(payload);
      });
    });
  }

  function requestArrayBuffer(method, path, body) {
    return csrf().then(function (token) {
      return new Promise(function (resolve, reject) {
        var xhr = new XMLHttpRequest();
        xhr.open(method, path);
        xhr.withCredentials = true;
        xhr.responseType = "arraybuffer";
        xhr.setRequestHeader("Accept", "application/json");
        if (token) xhr.setRequestHeader("X-CSRF-TOKEN", token);
        if (body != null) xhr.setRequestHeader("Content-Type", "application/json");
        xhr.onload = function () {
          var buf = xhr.response instanceof ArrayBuffer ? xhr.response : new ArrayBuffer(0);
          if (xhr.status >= 200 && xhr.status < 300) { resolve(buf); return; }
          var data = parseJson(new TextDecoder().decode(buf));
          reject(new Error((data && (data.message || data.error)) || (xhr.status === 404 ? "This secret is no longer available." : "Download failed.")));
        };
        xhr.onerror = function () { reject(new Error("Network error while downloading.")); };
        xhr.send(body == null ? null : JSON.stringify(body));
      });
    });
  }

  global.SecretTransfer = { postJson: postJson, requestArrayBuffer: requestArrayBuffer, serializeJsonBody: serializeJsonBody };
})(typeof window !== "undefined" ? window : globalThis);
