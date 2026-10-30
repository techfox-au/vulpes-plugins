# Secret Sharing audit

Secret Sharing does not keep its own audit table. Every event is written to the Vulpes audit trail through `IHostAuditLog`.
Open **Manage → Audit trail** and filter the action prefix `secret.`.

The cryptographic review notes are in [CRYPTO.md](CRYPTO.md).

## Events

| Action | When | Target | Details |
|--------|------|--------|---------|
| `secret.udk.created` | The user stores the first user-data-key wrap | Vulpes user id | `kind` only |
| `secret.udk.wrapped` | Another credential wraps the same key, or a password wrap is replaced | Vulpes user id | `kind` only |
| `secret.udk.removed` | A passkey wrap is deleted | Vulpes user id | `kind=passkey` |
| `secret.notify.changed` | The owner changes email notification preferences | Vulpes user id | Which preferences are on |
| `secret.notify.sent` | An opted-in notification email was accepted by the mail transport | Send or collect id | `kind` only. The address is not recorded |
| `secret.reset` | A temporary password destroyed the user data key | Vulpes user id | Counts of sends and collects removed |
| `secret.send.created` | The owner creates a send | Send id | `oneTime` and `passwordProtected` only |
| `secret.send.deleted` | The owner deletes a send | Send id | |
| `secret.send.decrypted` | A recipient passes proof of work and the ciphertext is released | Send id | Actor is `anonymous` |
| `secret.collect.created` | The owner creates a collect | Collect id | `oneTime` and `passwordProtected` only |
| `secret.collect.deleted` | The owner deletes a collect | Collect id | |
| `secret.collect.uploaded` | Someone uploads a ciphertext to an open collect | Collect id | Actor is `anonymous` |
| `secret.collect.retrieved` | The owner downloads that ciphertext | Collect id | |

The actor for owner actions is the signed-in Vulpes user. Anonymous recipient actions are recorded as `anonymous`.
Messages never include plaintext, the URL fragment, the user data key, or a link password.

A failed audit write must not be treated as a failed send. The host logger records the failure and the secret action still completes.

## Review checks

1. No server method decrypts `Ciphertext`, `WrappedKey`, or the user-data-key package.
2. `#sk=` is read only in the browser.
3. SQL parameters are used for every value. The only interpolated identifier is the table name `secrets` or `collects`, chosen in code.
4. A password wrap is PBKDF2-HMAC-SHA512, 893241 iterations, 16-byte salt, AES-256-GCM. A passkey wrap is AES-256-GCM under the WebAuthn PRF output. The PRF output is not sent to the server.
5. Payload wrap info string remains `sendit-v1-wrap`.
6. Proof of work is consumed before a one-time send is marked consumed.
7. Create and delete use the Vulpes session user id, not a client-supplied owner id.
