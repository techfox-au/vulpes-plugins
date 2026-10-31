# Secret Sharing cryptography

The browser encrypts. The plugin stores ciphertext and wrapped keys. It never decrypts a secret.

Read the source, not a minified copy served from an installed package. `wwwroot/public/crypto.js` is the Sendit payload implementation with two edits: `GET /api/plugins/secret-sharing/crypto/params`, and rejection of a link-password package whose iteration count is not 893241. `wwwroot/public/nacl-fast.js` and `wwwroot/public/pow.js` are byte-identical to Sendit. The user data key script matches the host file `wwwroot/assets/js/udk.js`. See [VENDOR.md](VENDOR.md).

The host user-data-key review is `vulpes/docs/CRYPTO.md`.

## Payload

| Purpose | Algorithm | Parameters |
|---------|-----------|------------|
| Payload | AES-256-GCM | 12-byte IV, 128-bit tag, Web Crypto, one shot inside the blob worker in `crypto.js` |
| Key agreement | X25519 | TweetNaCl `nacl.box.keyPair` / `nacl.scalarMult` |
| Wrap KDF | HKDF-SHA-256 | salt = 32 zero bytes, info = `sendit-v1-wrap`, length 32 |
| Key wrap | AES-256-GCM | 12-byte IV prepended to the wrap ciphertext |
| Link password | PBKDF2-HMAC-SHA512 | 893241 iterations, 16-byte salt, 12-byte IV, seals the 32-byte secret key |

A send or collect link puts the X25519 secret key in `#sk=`. The browser does not send the fragment. A link password replaces that fragment with base64url of `{ i, s, iv, ct }`. The server stores only `passwordProtected`.

All payload sizes use that one worker. There is no page-thread AES and no JavaScript AES. A large ciphertext is spliced into the JSON body by `wwwroot/public/transfer.js`. It is not passed through `JSON.stringify`.

UI caps: file 40 MiB, secret text 1,000,000 characters. The server accepts a base64url ciphertext up to 88,080,384 characters.

## Owner fields

Names, private notes, and the collect owner key are encrypted under the user data key before upload: `base64url(iv || AES-256-GCM ciphertext and tag)`. The host holds that key. This plugin only stores the ciphertext.

## Proof of work

HMAC-SHA256, ASCII decimal nonce, leading zero bits. The difficulty and the lifetimes come from the host setting **Manage → Settings → Proof of work** (`IPowPolicy`). The default is 12 bits, 120 seconds for a send challenge, and 900 seconds for a collect challenge. A challenge is deleted when it is consumed. A one-time payload is burned only after that consume succeeds.

Public pages are `/send`, `/upload`, and `/collect`.
