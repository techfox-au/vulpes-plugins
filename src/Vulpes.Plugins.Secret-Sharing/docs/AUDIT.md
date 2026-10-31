# Secret Sharing audit

Review checklist for this plugin. The in-app trail is the Vulpes audit log. Filter the action prefix `secret.`. Cryptography is [CRYPTO.md](CRYPTO.md). The host user data key is `vulpes/docs/AUDIT.md`.

## Source of truth

| Area | Path |
|------|------|
| Payload crypto | `wwwroot/public/crypto.js` |
| X25519 | `wwwroot/public/nacl-fast.js` (TweetNaCl 1.0.3, [VENDOR.md](VENDOR.md)) |
| Proof of work, browser | `wwwroot/public/pow.js` |
| Proof of work, server | `Services/PowService.cs` (difficulty from host `IPowPolicy`) |
| Upload and download transport | `wwwroot/public/transfer.js` |
| Field limits and burn | `Services/ShareStore.cs` |
| IP allow-list | `Services/IpRestriction.cs` |
| SQL | `Data/ShareDatabase.cs`, `Services/ShareStore.cs` |
| Routes | `Endpoints/ShareEndpoints.cs` |
| Production pages | minified by `vulpes/scripts/minify-frontend.py` when a package is published. Audit these sources |

## Checklist

1. Confirm no server method decrypts `Ciphertext`, `WrappedKey`, a link-password package, or a user-data-key wrap.
2. Confirm `#sk=` is read only in the browser.
3. Confirm SQL uses parameters. Table names are the literals `secrets` and `collects`, not request data.
4. Confirm `crypto.js` still matches Sendit except the params URL and the 893241 iteration check. Confirm `nacl-fast.js` and `pow.js` are byte-identical to Sendit.
5. Confirm HKDF info remains `sendit-v1-wrap`.
6. Confirm proof of work is HMAC-SHA256, one-time, and uses the host difficulty on the next challenge. There is no path that sets difficulty to 0.
7. Confirm a missing, expired, or consumed secret returns the same "no longer available" response, and that the lookup happens only after the proof is burned.
8. Confirm an IP denial is `403` with "This send is not available from your IP address." and writes `secret.send.ip_denied` without burning the payload.
9. Confirm collect upload reads `X-Sendit-Pow-*`, burns the proof before the large body, and that `GET .../upload-permit` validates without burning.
10. Confirm anyone with the collect link can retrieve it after proof of work. The owner session is not required. A link password stays in the browser.
11. Confirm create and delete use the Vulpes session user id.
12. Confirm expired, consumed, and maxed-out rows are deleted on dashboard load and by the one-minute job.

## Events

| Action | When | Actor |
|--------|------|-------|
| `secret.send.created` / `secret.send.deleted` | Owner creates or deletes a send | Signed-in user |
| `secret.send.decrypted` | Proof of work succeeded and the ciphertext was released | `anonymous` |
| `secret.send.ip_denied` | The send is active and the client IP is outside the allow-list | `anonymous` |
| `secret.collect.created` / `secret.collect.deleted` | Owner creates or deletes a collect | Signed-in user |
| `secret.collect.uploaded` | Ciphertext stored on an open collect | `anonymous` |
| `secret.collect.retrieved` | Ciphertext released for a collect link | Signed-in user id, or `anonymous` |
| `secret.notify.changed` | Owner changes notification preferences | Signed-in user |
| `secret.notify.sent` | A notification email was accepted | Owner user id |
| `secret.reset` | A temporary password removed this user's sends and collects | `system:secret-sharing` |

Details never include plaintext, the URL fragment, the user data key, or a link password. A failed audit write does not fail the secret action.

The user data key itself is audited on the host as `account.data_key.created`, `account.data_key.wrapped`, and `account.data_key.removed`.
