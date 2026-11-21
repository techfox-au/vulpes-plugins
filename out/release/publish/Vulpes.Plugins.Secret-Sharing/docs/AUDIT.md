# Secret Sharing audit

Review checklist for this plugin. The in-app trail is the Vulpes audit log. Filter the action prefix `secret.`. Cryptography is [CRYPTO.md](CRYPTO.md). The host user data key is `vulpes/docs/AUDIT.md`.

## Source of truth

| Area | Path |
|------|------|
| Payload crypto | Host `/assets/js/crypto/crypto.js` via `VulpesCrypto.ready()` |
| X25519 | Host `/assets/js/crypto/nacl-fast.js` (TweetNaCl 1.0.3, [VENDOR.md](VENDOR.md)) |
| Proof of work, browser | Host `/assets/js/pow.js` (`VulpesPow`) and `/assets/js/pow-engine.js` |
| Proof of work, server | `Services/PowService.cs` (host `IPowPolicy` and `PowClock`) |
| Upload and download transport | `wwwroot/public/transfer.js` |
| Field limits and burn | `Services/ShareStore.cs` |
| IP allow-list | `Services/IpRestriction.cs` |
| SQL | `Data/ShareDatabase.cs`, `Services/ShareStore.cs` |
| Routes | `Endpoints/ShareEndpoints.cs` |
| Production pages | minified by `vulpes/scripts/minify-frontend.py` when a package is published. Audit these sources |

## Checklist

1. Confirm no server method decrypts `Ciphertext`, `WrappedKey`, a link-password package, or the inner user-data-key wrap. The server may remove the `vd1.` `VULPES_DATA_KEY` seal from a collect owner key or a stored wrap before returning it to the signed-in owner.
2. Confirm `#sk=` and `#pk=` are read only in the browser. The upload page encrypts to `#pk=` and stops when that key does not match the stored collect public key.
3. Confirm SQL uses parameters. Table names are the literals `secrets` and `collects`, not request data.
4. Confirm this plugin does not ship `crypto.js`, `nacl-fast.js`, or `pow.js`. Confirm the host cipher still calls `GET /api/plugins/secret-sharing/crypto/params` and rejects a wrap whose iteration count is not 893241. Confirm pages import `VulpesPow` from `/assets/js/pow.js`.
5. Confirm HKDF info remains `sendit-v1-wrap`.
6. Confirm proof of work is HMAC-SHA256, one-time, and uses the host difficulty on the next challenge. There is no path that sets difficulty to 0.
7. Confirm a missing, expired, or consumed secret returns the same "no longer available" response, and that the lookup happens only after the proof is burned. Collect retrieval burns the proof before the retrieval allow-list is checked, so a scan without a proof cannot learn that a collect exists. A valid proof from a blocked address is `403` and does not release the upload.
8. Confirm a send IP denial is `403` with "This send is not available from your IP address: " plus the server-seen address, and writes `secret.send.ip_denied` without releasing the payload. Confirm a collect retrieval denial is `403` with "Collecting this submission is not available from your IP address: " plus that address, and writes `secret.collect.ip_denied`.
9. Confirm collect upload reads `X-Sendit-Pow-*`, burns the proof before the large body, and that `GET .../upload-permit` validates without burning.
10. Confirm the collect owner session is not required to retrieve a collect. Retrieval still requires the link, proof of work, and the server collect-retrieval allow-list when that list is restrictive. When the server cannot see a public visitor address, a restrictive list denies retrieval, and the log says "Collect retrieval has an IP allow-list." A link password stays in the browser. A raw `#sk=` does not skip that password. A wrong link key does not call the open that burns a one-time or counted secret.
10a. Confirm a missing collect and a collect that is not open for upload return the same "no longer available" response, and that both count as scan failures. Confirm a collect public key that does not contribute is rejected. Confirm an omitted maximum open count stores no cap, and a count outside 1–100000 is rejected for a send, a collect, and the bot.
11. Confirm create and delete use the Vulpes session user id.
12. Confirm expired, consumed, and maxed-out rows are deleted on dashboard load and by the three-minute purge.
13. Confirm notification switches stay disabled, and cannot be turned on, unless the account has an email address and the dashboard has a Graph, SMTP, or Mailgun transport (`IHostEmail.IsConfiguredAsync`). Turning a switch off is still allowed.

## Events

| Action | When | Actor |
|--------|------|-------|
| `secret.send.created` / `secret.send.deleted` | Owner creates or deletes a send | Signed-in user |
| `secret.send.decrypted` | Proof of work succeeded and the ciphertext was released | `anonymous` |
| `secret.send.ip_denied` | The send is active and the client IP is outside the allow-list | `anonymous` |
| `secret.collect.created` / `secret.collect.deleted` | Owner creates or deletes a collect | Signed-in user |
| `secret.collect.uploaded` | Ciphertext stored on an open collect | `anonymous` |
| `secret.collect.retrieved` | Ciphertext released for a collect link | Signed-in user id, or `anonymous` |
| `secret.collect.ip_denied` | Collect retrieval denied because the client IP is outside the server allow-list | Signed-in user id, or `anonymous` |
| `secret.collect.retrieve_ips` | An administrator changes the collect-retrieval allow-list | Signed-in user |
| `secret.notify.changed` | Owner changes notification preferences | Signed-in user |
| `secret.notify.sent` | A notification email was accepted | Owner user id |
| `secret.reset` | A temporary password removed this user's sends and collects | `system:secret-sharing` |

Details never include plaintext, the URL fragment, the user data key, or a link password. A failed audit write does not fail the secret action.

The user data key itself is audited on the host as `account.data_key.created`, `account.data_key.wrapped`, and `account.data_key.removed`.
