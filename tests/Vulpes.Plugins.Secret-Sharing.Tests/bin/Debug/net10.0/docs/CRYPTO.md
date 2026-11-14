# Secret Sharing cryptography

The browser encrypts. The plugin stores ciphertext and wrapped keys. It never decrypts a secret.

Read the host sources, not a minified copy served from an installed package. This plugin does not ship `crypto.js`, `nacl-fast.js`, or `pow.js`.

The cipher is the host framework. Pages call `VulpesCrypto.ready()` or load `/assets/js/crypto/nacl-fast.js` and `/assets/js/crypto/crypto.js`, then use `window.SenditCrypto`. That cipher still reads `GET /api/plugins/secret-sharing/crypto/params` and rejects a link-password package whose iteration count is not 893241.

Proof of work is the host client `VulpesPow` in `/assets/js/pow.js`, the same client sign-in uses. The worker is `/assets/js/pow-engine.js`. This plugin still stores its own challenges and checks them in `Services/PowService.cs` with the host `IPowPolicy` and `PowClock`.

The user data key script is the host file `/assets/js/udk.js`. Dashboard pages load it after `VulpesCrypto.ready()`. See [VENDOR.md](VENDOR.md).

The host user-data-key review is `vulpes/docs/CRYPTO.md`.

## Payload

| Purpose | Algorithm | Parameters |
|---------|-----------|------------|
| Payload | AES-256-GCM | 12-byte IV, 128-bit tag, Web Crypto, one shot inside the blob worker in the host `crypto.js` |
| Key agreement | X25519 | TweetNaCl `nacl.box.keyPair` / `nacl.scalarMult` |
| Wrap KDF | HKDF-SHA-256 | salt = 32 zero bytes, info = `sendit-v1-wrap`, length 32 |
| Key wrap | AES-256-GCM | 12-byte IV prepended to the wrap ciphertext |
| Link password | PBKDF2-HMAC-SHA512 | 893241 iterations, 16-byte salt, 12-byte IV, seals the 32-byte secret key |

A send or collect link puts the X25519 secret key in `#sk=`. The browser does not send the fragment. A link password replaces that fragment with base64url of `{ i, s, iv, ct }`. The server stores only `passwordProtected`.

All payload sizes use that one worker. There is no page-thread AES and no JavaScript AES. A large ciphertext is spliced into the JSON body by `wwwroot/public/transfer.js`. It is not passed through `JSON.stringify`.

UI caps: file 40 MiB, secret text 1,000,000 characters. The server accepts a base64url ciphertext up to 88,080,384 characters.

## Owner fields

Names, private notes, and the collect owner key are encrypted under the user data key before upload: `base64url(iv || AES-256-GCM ciphertext and tag)`. The raw user data key stays in the browser. This plugin stores that ciphertext. The collect owner key and the stored user-data-key wraps are then sealed again with the host `VULPES_DATA_KEY` (`vd1.` envelope). The seal is removed only when the value is returned to the signed-in owner. Payload ciphertext is not sealed again.

## Proof of work

HMAC-SHA256, ASCII decimal nonce, leading zero bits. The page uses `VulpesPow`. The difficulty and the lifetimes come from the host setting **Manage → Settings → Proof of work** (`IPowPolicy`). The default is 14 bits and 120 seconds for a send or collect challenge. The page uses the issued `expiresAt` and mints the next ticket when half of that life has passed. The server accepts the ticket for that duration plus 7 seconds of clock skew. A challenge is deleted when it is consumed. A one-time payload is burned only after that consume succeeds. Invoice links do not use this proof.

Public pages are `/send`, `/upload`, and `/collect`.
