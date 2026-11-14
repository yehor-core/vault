# Vault — Design

<!--
Rules for editing:
- Short as it can be while complete. Prefer tables and one-line statements. State each fact once, in the section that owns it.
- Every guarantee names one code location or test that enforces it (file:test name). No reference → write "not protected"; a "not tested" mark names its ticket (#NN) or says "not protected". `npm run check:refs` checks both.
- Self-contained: state each decision's outcome and rejected alternatives here, without links or decision IDs.
-->

Vault is a browser-native private-key store on IndexedDB. An application generates keys, lists their public information and gets signatures; private keys never leave Vault, and Vault does not know what its keys sign.

Test references: `<name> ›` cites `test/unit/<name>.test.ts`, `e2e ›` cites `test/e2e/`. Unit tests run in Chromium, Firefox and WebKit, except those needing a virtual authenticator (most `passkey ›` and `protection ›` tests): Chromium only.

## 1. Threat model

### 1.1 Assets

| Asset | Where it lives |
|---|---|
| Private keys of sealed keys (ed25519, secp256k1) | IndexedDB, sealed to the wrapping public key; no call returns them |
| Private keys of passkey keys and of the unlock passkey | The authenticator only |
| Wrapping private key: opens every sealed key | IndexedDB: a non-extractable CryptoKey (unprotected), or wrapped under a key derived from the unlock passkey's PRF result (protected) |
| The unlock passkey's PRF result | Memory only, during `protect()` or `unlock()`, as a non-extractable HKDF key |
| Public information | IndexedDB, in the clear; not secret |

### 1.2 Adversaries and guarantees

Trusted: the browser, its WebCrypto and IndexedDB, the OS, origin isolation. Out of scope: a compromised browser, OS or extension; preventing XSS (Vault limits what injected code reaches); physical and side-channel attacks (the secp256k1 JS code promises no constant time).

| Adversary or event | Mode | Guarantee | Not guaranteed | Enforced by |
|---|---|---|---|---|
| Profile or disk copy, read offline | Unprotected | Private keys are stored only sealed; the one stored secret, the wrapping private key, is a non-extractable CryptoKey. | **Not protected:** the browser keeps that key's bytes in the profile, so a copy opens every sealed key. | `storage › no private key bytes are stored: only ciphertext and a non-extractable root key` |
| | Protected | The wrapping private key is stored only wrapped under a key derived from the unlock passkey's PRF result, which the authenticator computes from a secret it never releases. | **A copy plus the unlock passkey, or the provider account that syncs it, opens every sealed key.** A copy taken before `protect()` still opens the keys sealed before it. | `protection › the protected header wraps the wrapping private key under a KEK from the PRF result, bound to every other field` |
| Storage writer (same-origin script, profile editor) adds, edits, swaps or deletes records | Both | Every read is validated and fails closed with `corrupted` (§2.4). With no secret, `list()` catches malformed fields and an edited id, type, scope or public key; `sign()` catches any other edit of a sealed key, as the AAD binds every field. | Adding a key needs no secret, so a complete added key can't be told from a real one. Deleted keys are not detected. **Labels can be spoofed**, and a passkey key's label and createdAt are never authenticated. A header replaced as a whole is not detected (§3.4). | `storage › tamper table › a bad record is corrupted at the operation the table names: <case>` |
| An older, consistent snapshot put back | Both | — | **Not detected:** deleted keys come back and newer keys vanish. IndexedDB is the only store, so nothing anchors a counter. | not protected |
| Same-origin script: calls the API, opens the database | Unprotected | No call returns private key bytes (§5.1), and a `Scope` has no path to its `Vault`. | **Not protected:** it signs with every key and can open every sealed key itself. Scopes don't separate same-origin code; consumers are separated by origin (§6). | `vault › a Scope has no path to its Vault…` |
| | Protected | In a locked context it can't sign with a sealed key. In an unlocked one, the wrapping private key is a non-extractable CryptoKey in a private field, never returned, stored or sent. | **Not protected while unlocked:** it signs with every sealed key until `lock()` or `close()`. It can also call `unlock()` and wait for the user, or replace the header. | `src/unlock.ts` `Unlock` |
| Lost, deleted or replaced unlock passkey | Protected | A failed `unlock()` writes nothing: a deleted unlock passkey ends as `cancelled`, another passkey as `not-found`. Everything but sealed `sign` keeps working. | **Every sealed key is lost for good**, keys sealed later too: no recovery; `wipe()` starts over. | `protection › unlock and lock › unlock with %s fails with %s; the vault stays protected and locked` |
| Lost, deleted or replaced passkey key | Both | The key stays listed; `sign` fails with `cancelled`. | A loss can't be told from a declined prompt (both are `NotAllowedError`). A replaced passkey: not protected. | `passkey › a failed prompt › a sign with a passkey removed from its authenticator is cancelled` |
| Secrets in memory | Both | secp256k1 seeds and scalars are zeroed once used, and the PRF result once imported; ed25519 private keys exist only as CryptoKeys; the unwrapped wrapping private key lives in one context until `lock()` or `close()`. | **Not protected:** JS can't zero memory reliably; secp256k1 scalars are JS bytes during `generate` and `sign`, and the curve library's copies stay; CryptoKeys live until garbage collection. | `storage › secp256k1 › generate erases the seed and the scalar it owns, also when the write fails`, `protection › the PRF result’s bytes are zeroed once imported, at protect and at unlock`, `src/unlock.ts` `Unlock` |
| Eviction: storage removed as a whole | Both | An empty database is an empty vault, also when deleted while open (§2.6). | Eviction can't be told from a wipe; an evicted protected vault becomes unprotected at the next `generate()`, and **every sealed key is lost.** | `vault › a database deleted while the vault is open is an empty vault: list returns no keys and generate creates a new vault` |
| Crash or closed tab: a transaction cut midway | Both | Every change that touches several records is one transaction: a cut leaves the old state or the new one (§4). | A browser or OS crash is not tested: not protected. | `e2e › a tab closed while the first generate writes leaves the old state or the new one, never a mix: <cut>` |

## 2. Storage layout and key protection

[To be written: 2.1 Records · 2.2 Key hierarchy · 2.3 Passkey keys · 2.4 Validation, fail closed · 2.5 Versioning and migration · 2.6 Eviction and persistent storage · 2.7 Primitives and dependencies]

## 3. Lifecycle and states

[To be written: 3.1 Diagram and operations · 3.2 Enabling protection, where the second prompt happens · 3.3 Unlock and lock · 3.4 No downgrade · 3.5 Wipe]

## 4. Concurrency

[To be written]

## 5. Public API

[To be written: 5.1 Surface · 5.2 Examples · 5.3 Errors · 5.4 Prompts, user gestures, up-front detection · 5.5 Adding a key type · 5.6 Where passkey features degrade]

## 6. Alternatives considered and rejected

[To be written]

## 7. Known limitations

[To be written]
