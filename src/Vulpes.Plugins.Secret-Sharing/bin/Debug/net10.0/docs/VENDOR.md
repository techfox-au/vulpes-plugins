# Vendored library

This plugin does not vendor TweetNaCl or the payload cipher. Those files live on the host:

| File | Package | Version | Purpose |
|------|---------|---------|---------|
| `vulpes/src/Vulpes.Host/wwwroot/assets/js/crypto/nacl-fast.js` | tweetnacl | 1.0.3 | X25519 key agreement |

That host file is the TweetNaCl 1.0.3 library. A production host image minifies it with `vulpes/scripts/minify-frontend.py` (comments and whitespace only).

AES-256-GCM and HKDF-SHA-256 use the browser Web Crypto API. There is no third-party AES.
