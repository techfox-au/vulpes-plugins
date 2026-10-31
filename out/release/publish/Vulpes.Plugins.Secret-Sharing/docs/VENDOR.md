# Vendored library

Readable source. A production package minifies this file with the same script as the host
(`vulpes/scripts/minify-frontend.py`): comments and whitespace only.

| File | Package | Version | Purpose |
|------|---------|---------|---------|
| `wwwroot/public/nacl-fast.js` | tweetnacl | 1.0.3 | X25519 key agreement |

The file is byte-identical to `sendit/src/frontend/vendor/nacl-fast.js` and to tweetnacl@1.0.3 on npm.

AES-256-GCM and HKDF-SHA-256 use the browser Web Crypto API. There is no third-party AES.
