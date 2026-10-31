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

  function requestArrayBuffer(method, path, body, onDownloadProgress) {
    return csrf().then(function (token) {
      return new Promise(function (resolve, reject) {
        var xhr = new XMLHttpRequest();
        xhr.open(method, path);
        xhr.withCredentials = true;
        xhr.responseType = "arraybuffer";
        xhr.setRequestHeader("Accept", "application/json");
        if (token) xhr.setRequestHeader("X-CSRF-TOKEN", token);
        if (body != null) xhr.setRequestHeader("Content-Type", "application/json");
        if (typeof onDownloadProgress === "function") {
          xhr.onprogress = function (ev) {
            if (!ev.lengthComputable || ev.total <= 0) return;
            onDownloadProgress(ev.loaded / ev.total, ev.loaded, ev.total);
          };
        }
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

  /**
   * Blocking encrypt/upload progress. setProgress(null) is indeterminate; 0..1 fills the bar.
   */
  function showProgress(title) {
    var prev = document.getElementById("vulpes-progress");
    if (prev) prev.remove();
    var overlay = document.createElement("div");
    overlay.id = "vulpes-progress";
    overlay.className = "progress-modal";
    overlay.setAttribute("role", "dialog");
    overlay.setAttribute("aria-modal", "true");
    overlay.setAttribute("aria-busy", "true");
    overlay.setAttribute("aria-label", title || "Working");
    var card = document.createElement("div");
    card.className = "progress-modal-card";
    var heading = document.createElement("h2");
    heading.textContent = title || "Working…";
    var status = document.createElement("p");
    status.className = "progress-modal-status";
    status.textContent = "Please wait…";
    var track = document.createElement("div");
    track.className = "progress-bar-track";
    track.setAttribute("role", "progressbar");
    track.setAttribute("aria-valuemin", "0");
    track.setAttribute("aria-valuemax", "100");
    var fill = document.createElement("div");
    fill.className = "progress-bar-fill progress-bar-indeterminate";
    var pct = document.createElement("p");
    pct.className = "progress-modal-pct";
    track.appendChild(fill);
    card.appendChild(heading);
    card.appendChild(status);
    card.appendChild(track);
    card.appendChild(pct);
    overlay.appendChild(card);
    document.body.appendChild(overlay);
    document.body.classList.add("progress-modal-open");
    return {
      setTitle: function (text) {
        heading.textContent = text || "Working…";
        overlay.setAttribute("aria-label", text || "Working");
      },
      setStatus: function (text) { status.textContent = text || ""; },
      setProgress: function (fraction) {
        if (fraction == null || !isFinite(fraction)) {
          fill.classList.add("progress-bar-indeterminate");
          fill.style.width = "40%";
          track.removeAttribute("aria-valuenow");
          pct.textContent = "";
          return;
        }
        var clamped = Math.max(0, Math.min(1, fraction));
        var shown = Math.round(clamped * 100);
        fill.classList.remove("progress-bar-indeterminate");
        fill.style.width = shown + "%";
        track.setAttribute("aria-valuenow", String(shown));
        pct.textContent = shown + "%";
      },
      close: function () {
        overlay.remove();
        document.body.classList.remove("progress-modal-open");
      },
    };
  }

  global.SecretTransfer = { postJson: postJson, requestArrayBuffer: requestArrayBuffer, serializeJsonBody: serializeJsonBody, showProgress: showProgress };
})(typeof window !== "undefined" ? window : globalThis);
