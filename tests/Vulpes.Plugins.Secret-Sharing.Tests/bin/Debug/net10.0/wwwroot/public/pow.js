/**
 * Browser proof-of-work for send/collect ID access and auth (login / email-OTP / TOTP / forgot).
 * HMAC-SHA256(serverKey, ascii(nonce)) must have `difficultyBits` leading zero bits.
 * Server always issues difficulty ≥ 1 (never disabled); default is 12 bits (~4k average tries).
 * Each challenge is one-time on the server — do not reuse challengeId after a successful request.
 *
 * Challenges include expiresAt (ISO). Solving abandons work 5s before expiry and, when used via
 * solveRefreshing / solvePow(fetcher), seamlessly fetches a new challenge until a solution is found.
 */
(function (global) {
  "use strict";

  /** Abandon the current challenge this many ms before server expiresAt. */
  var ABANDON_BEFORE_MS = 5000;
  var clockOffsetMs = 0;

  function powNow() {
    return Date.now() + clockOffsetMs;
  }

  var CLOCK_MARGIN_MS = 2000;

  function clockOffset(serverUtcMs, clientBeforeMs, clientAfterMs) {
    return serverUtcMs - (clientBeforeMs + clientAfterMs) / 2;
  }

  function powClockOffset(serverUtcMs, clientBeforeMs, clientAfterMs) {
    return clockOffset(serverUtcMs, clientBeforeMs, clientAfterMs) + CLOCK_MARGIN_MS;
  }

  function parseServerTime(value) {
    if (!value) return NaN;
    var parsed = Date.parse(String(value).replace(/(\.\d{3})\d+/, "$1"));
    return isNaN(parsed) ? NaN : parsed;
  }

  async function syncServerTime() {
    try {
      var before = Date.now();
      var res = await fetch("/api/time", { credentials: "same-origin", cache: "no-store", headers: { Accept: "application/json" } });
      var after = Date.now();
      if (!res.ok) return false;
      var data = await res.json();
      var server = parseServerTime(data && data.utc);
      if (isNaN(server)) return false;
      clockOffsetMs = powClockOffset(server, before, after);
      return true;
    } catch (err) {
      return false;
    }
  }

  function b64urlDecode(str) {
    var s = str.replace(/-/g, "+").replace(/_/g, "/");
    while (s.length % 4) s += "=";
    var bin = atob(s);
    var out = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }

  function b64urlEncode(bytes) {
    var bin = "";
    for (var i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
    return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
  }

  /** Pure check; bits ≤ 0 is vacuous (true). Production challenges always use ≥ 1. */
  function hasLeadingZeroBits(hash, bits) {
    if (bits <= 0) return true;
    var full = (bits / 8) | 0;
    var rem = bits % 8;
    for (var i = 0; i < full; i++) {
      if (hash[i] !== 0) return false;
    }
    if (rem === 0) return true;
    var mask = 0xff << (8 - rem);
    return (hash[full] & mask) === 0;
  }

  function powExpiredError() {
    var err = new Error("PoW challenge nearing expiry.");
    err.powExpired = true;
    return err;
  }

  /**
   * Deadline (epoch ms) to stop working on this challenge: expiresAt − 5s.
   * Null if expiresAt missing/invalid (no auto-abandon).
   * @param {{ expiresAt?: string }} challenge
   * @returns {number|null}
   */
  function abandonDeadlineMs(challenge) {
    if (!challenge || !challenge.expiresAt) return null;
    var exp = Date.parse(challenge.expiresAt);
    if (isNaN(exp)) return null;
    return exp - ABANDON_BEFORE_MS;
  }

  /**
   * Solve a single challenge. Abandons with err.powExpired when within 5s of expiresAt.
   * @param {{ hmacKey: string, difficultyBits: number, challengeId: string, expiresAt?: string }} challenge
   * @param {{ onProgress?: function(number, number=): void, attempt?: number }} [opts]
   *   onProgress(tries, attempt?) — attempt is optional (set by solveRefreshing)
   * @returns {Promise<{ challengeId: string, nonce: string, hash: string, tries: number }>}
   */
  async function solve(challenge, opts) {
    opts = opts || {};
    var attempt = opts.attempt | 0;
    // Defensive floor if a misconfigured peer sends 0; server clamps the same way.
    var bits = challenge.difficultyBits | 0;
    if (bits < 1) bits = 1;
    var keyBytes = b64urlDecode(challenge.hmacKey);
    var subtle = global.crypto && global.crypto.subtle;
    if (!subtle) throw new Error("Web Crypto unavailable for proof of work.");

    var deadline = abandonDeadlineMs(challenge);
    if (deadline != null && powNow() >= deadline) {
      throw powExpiredError();
    }

    var key = await subtle.importKey(
      "raw",
      keyBytes,
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign"]
    );

    var nonce = 0;
    var tries = 0;
    var enc = new TextEncoder();
    // Yield to UI every N iterations so the page stays responsive.
    var yieldEvery = 250;

    if (opts.onProgress) {
      try {
        opts.onProgress(0, attempt || undefined);
      } catch (_) {
        /* ignore UI errors */
      }
    }

    while (true) {
      if (opts.shouldAbort && opts.shouldAbort()) {
        var aborted = new Error("PoW abandoned.");
        aborted.powAborted = true;
        throw aborted;
      }
      if (deadline != null && powNow() >= deadline) {
        throw powExpiredError();
      }

      var nonceStr = String(nonce);
      var mac = new Uint8Array(
        await subtle.sign("HMAC", key, enc.encode(nonceStr))
      );
      tries++;
      if (hasLeadingZeroBits(mac, bits)) {
        return {
          challengeId: challenge.challengeId,
          nonce: nonceStr,
          hash: b64urlEncode(mac),
          tries: tries,
        };
      }
      nonce++;
      if (tries % yieldEvery === 0) {
        if (deadline != null && powNow() >= deadline) {
          throw powExpiredError();
        }
        if (opts.onProgress) {
          try {
            opts.onProgress(tries, attempt || undefined);
          } catch (_) {
            /* ignore */
          }
        }
        await new Promise(function (r) {
          setTimeout(r, 0);
        });
      }
    }
  }

  /**
   * Fetch challenges and solve until success. When a challenge is within 5s of
   * expiresAt, drop it and request a fresh one (no user-facing error).
   * Attempt counter: first challenge is attempt 1 (no UI counter expected);
   * attempt ≥ 2 is passed to onProgress for display.
   *
   * @param {function(): Promise<object>} fetchChallenge async () => challenge
   * @param {{ onProgress?: function(number, number): void, maxAttempts?: number }} [opts]
   *   onProgress(tries, attempt) — attempt is 1-based
   * @returns {Promise<{ challengeId: string, nonce: string, hash: string, tries: number, attempts: number }>}
   */
  async function solveRefreshing(fetchChallenge, opts) {
    opts = opts || {};
    if (typeof fetchChallenge !== "function") {
      throw new Error("solveRefreshing requires a fetchChallenge function.");
    }
    var maxAttempts =
      typeof opts.maxAttempts === "number" && opts.maxAttempts > 0
        ? opts.maxAttempts
        : 10000;
    var attempt = 0;

    while (attempt < maxAttempts) {
      attempt++;
      var challenge = await fetchChallenge();
      if (!challenge || !challenge.challengeId || !challenge.hmacKey) {
        throw new Error("Invalid proof-of-work challenge from server.");
      }
      try {
        var solution = await solve(challenge, {
          attempt: attempt,
          onProgress: opts.onProgress,
        });
        solution.attempts = attempt;
        return solution;
      } catch (err) {
        if (err && err.powExpired) {
          // Seamlessly continue with a new challenge.
          continue;
        }
        throw err;
      }
    }
    throw new Error(
      "Proof-of-work could not complete after " + maxAttempts + " challenges."
    );
  }

  /**
   * Status label helper: base text, plus " (N)" when attempt ≥ 2.
   * @param {string} base
   * @param {number} attempt
   */
  function statusLabel(base, attempt) {
    var b = base || "Performing proof-of-work…";
    if (attempt > 1) return b + " (" + attempt + ")";
    return b;
  }

  /**
   * Keep a solved ticket ready. Starts immediately. When half the ticket's life has passed,
   * solve the next one. take() returns the newest finished solution.
   */
  function createKeeper(fetchChallenge, deps) {
    deps = deps || {};
    var now = deps.now || powNow;
    var later = deps.setTimeout || setTimeout;
    var cancel = deps.clearTimeout || clearTimeout;
    var solveChallenge = deps.solve || solve;
    var generation = 0;
    var solveId = 0;
    var held = null;
    var pending = null;
    var timer = 0;

    function clearTimer() {
      if (timer) {
        cancel(timer);
        timer = 0;
      }
    }

    function usable(solution) {
      if (!solution || !solution.expiresAt) return false;
      var exp = expiresMs(solution.expiresAt);
      return !isNaN(exp) && exp - now() > ABANDON_BEFORE_MS;
    }

    var refreshQueued = false;
    var lastError = null;

    function expiresMs(value) {
      if (!value) return NaN;
      var parsed = Date.parse(String(value).replace(/(\.\d{3})\d+/, "$1"));
      return isNaN(parsed) ? NaN : parsed;
    }

    function schedule(receivedAt, challenge, gen) {
      var exp = expiresMs(challenge.expiresAt);
      if (isNaN(exp)) return;
      var halfway = receivedAt + Math.max(0, (exp - receivedAt) / 2);
      clearTimer();
      timer = later(function () {
        if (gen !== generation) return;
        if (pending) { refreshQueued = true; return; }
        begin(gen);
      }, Math.max(0, halfway - now()));
    }

    function begin(gen) {
      if (gen !== generation || pending) return pending;
      var id = ++solveId;
      refreshQueued = false;
      var run = (async function () {
        var challenge = await fetchChallenge();
        var receivedAt = now();
        if (gen !== generation || id !== solveId) return;
        if (!challenge || !challenge.challengeId || !challenge.hmacKey) {
          throw new Error("Invalid proof-of-work challenge from server.");
        }
        schedule(receivedAt, challenge, gen);
        try {
          var solution = await solveChallenge(challenge, {
            shouldAbort: function () {
              return gen !== generation || id !== solveId;
            },
          });
          if (gen !== generation || id !== solveId) return;
          if (!held || receivedAt >= held.fetchedAt) {
            solution.fetchedAt = receivedAt;
            solution.expiresAt = challenge.expiresAt;
            held = solution;
          }
        } catch (err) {
          if (err && err.powAborted) return;
          if (err && err.powExpired) { refreshQueued = true; return; }
          throw err;
        }
      })();
      var current;
      current = run.then(function () {}, function (err) { lastError = err; }).finally(function () {
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
      start: function () {
        generation++;
        held = null;
        pending = null;
        clearTimer();
        begin(generation);
      },
      stop: function () {
        generation++;
        held = null;
        pending = null;
        clearTimer();
        solveId++;
      },
      take: async function () {
        for (var i = 0; i < 8; i++) {
          if (usable(held)) {
            var solution = held;
            held = null;
            if (!pending) begin(generation);
            return solution;
          }
          lastError = null;
          var wait = pending || begin(generation);
          await wait;
          if (lastError && !usable(held)) throw lastError;
        }
        throw new Error("Proof-of-work could not complete.");
      },
    };
  }

  global.SenditPow = {
    solve: solve,
    solveRefreshing: solveRefreshing,
    createKeeper: createKeeper,
    syncServerTime: syncServerTime,
    statusLabel: statusLabel,
  };
})(typeof window !== "undefined" ? window : globalThis);
