/**
 * Shared browser crypto. Plugins call VulpesCrypto.ready() and then use window.SenditCrypto.
 * TweetNaCl is loaded first, then the cipher. A second call waits for the same load.
 */
(function (global) {
  "use strict";
  const version = "crypto1";
  const naclSrc = "/assets/js/crypto/nacl-fast.js?v=" + version;
  const cryptoSrc = "/assets/js/crypto/crypto.js?v=" + version;
  let loading = null;

  function loadScript(src) {
    return new Promise(function (resolve, reject) {
      const script = document.createElement("script");
      script.src = src;
      script.onload = function () { resolve(); };
      script.onerror = function () { reject(new Error("Could not load Vulpes crypto.")); };
      document.head.append(script);
    });
  }

  function ready() {
    if (global.nacl && global.nacl.box && global.SenditCrypto && global.SenditCrypto.generateKeyPair) {
      return Promise.resolve(global.SenditCrypto);
    }
    if (!loading) {
      loading = loadScript(naclSrc).then(function () {
        if (!global.nacl || !global.nacl.box) {
          throw new Error("TweetNaCl (nacl) is required for X25519.");
        }
        return loadScript(cryptoSrc);
      }).then(function () {
        if (!global.SenditCrypto || !global.SenditCrypto.generateKeyPair) {
          throw new Error("Vulpes crypto did not load.");
        }
        return global.SenditCrypto;
      });
    }
    return loading;
  }

  global.VulpesCrypto = { ready: ready };
})(window);
