# Secret Sharing cryptography

This plugin uses the Sendit protocol version 1 without changing the algorithms.
The browser encrypts. The plugin stores ciphertext, wrapped keys, and the user-data-key package.
It never decrypts a secret.

The implementation copied from Sendit is `wwwroot/public/crypto.js` and `wwwroot/public/nacl-fast.js` (TweetNaCl 1.0.3).
`wwwroot/public/udk.js` performs the same user-data-key wrap as Sendit `user-data-key.js`.

## Payload

| Purpose | Algorithm | Parameters |
|---------|-----------|------------|
| Payload | AES-256-GCM | 12-byte IV, 128-bit tag, Web Crypto inside a blob worker |
| Key agreement | X25519 | TweetNaCl `nacl.box.keyPair` |
| Wrap KDF | HKDF-SHA-256 | salt = 32 zero bytes, info = `sendit-v1-wrap`, length 32 |
| Key wrap | AES-256-GCM | 12-byte IV prepended to the wrap ciphertext |
| Link password | PBKDF2-HMAC-SHA512 | 893241 iterations, 16-byte salt, 12-byte IV, 32-byte `sk` |
| User data key, password wrap | PBKDF2-HMAC-SHA512 | 893241 iterations, 16-byte salt, 12-byte IV, 32-byte key |
| User data key, passkey wrap | AES-256-GCM | key = 32-byte WebAuthn PRF output, 12-byte IV |

A send link puts the X25519 secret key in the URL fragment (`#sk=`), which the browser does not send to the server.
A link password replaces that fragment with base64url of `{ i, s, iv, ct }`. The server stores only `passwordProtected`.

Owner names, private notes, and collect secret keys are encrypted with the user data key before they are uploaded:
`base64url(iv || AES-256-GCM ciphertext and tag)`.

## User data key

The browser generates one 32-byte user data key only while it wraps the first password or passkey. The raw key is kept only after that wrap is stored. Sign-in never creates a key.
Later credentials wrap that same key. A password wrap uses the sign-in password.
An administrator-issued temporary password deletes every passkey, every wrap, and every send and collect for that account. The next password the user chooses creates a new user data key and wraps it. Credentials added after that wrap the new key.
A passkey wrap uses AES-256-GCM under the 32-byte output of the WebAuthn PRF extension (`hmac-secret`) with the fixed salt SHA-256(`vulpes-secret-sharing-udk-v1`).
Changing the password replaces only the password wrap. Adding a passkey adds another wrap of the same key.
The server stores the wraps and never sees the key. Sign-in unwraps it into `sessionStorage` (`vulpes_secret_sharing_udk`).
An authenticator that does not return the PRF output can still sign in, but it cannot unwrap the key.

Passkey-only onboarding also stores a random password hash the user is never shown, with password sign-in left off.
That hash is not the user data key and cannot unwrap it. It exists so an empty password cannot sign in if password sign-in is turned on by mistake.

## Proof of work

Public send download and collect upload solve HMAC-SHA256 proof of work at 12 leading zero bits.
The challenge is deleted when it succeeds, and the one-time payload is burned only after that.

## What this plugin does not do

Sendit account passwords, email OTP, TOTP, IP allow-lists, and storage quotas are not part of this plugin.
Vulpes authenticates the owner. Recipients open `/plugins/secret-sharing/send` or `/plugins/secret-sharing/public/upload` without a Vulpes session. A collect is retrieved at `/plugins/secret-sharing/public/open?kind=collect`.
