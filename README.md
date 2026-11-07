# Vault

A browser-native private-key store on top of IndexedDB. Design: [DESIGN.md](DESIGN.md).

> Status: S1. Unprotected vault with ed25519 keys: generate, list, sign, delete, wipe. Keys are encrypted at rest in a versioned storage format, and errors are classified. Not built yet: secp256k1, scopes and labels, multi-tab notifications, passkey keys, passkey protection.

## Setup

Requires Node.js ≥ 24 (developed on 26 LTS).

```sh
npm ci
npx playwright install --with-deps chromium firefox webkit   # --with-deps installs system libraries (sudo)
```

## Commands

| Command | What it does |
|---|---|
| `npm run build` | Compiles the library to `dist/` (ES modules and `.d.ts`) |
| `npm run demo` | Serves the demo page at http://localhost:5173: generate, list, sign (verified with WebCrypto outside Vault), delete, wipe |
| `npm run typecheck` | Type checks browser code (`tsconfig.json`, no Node globals) and Node-side config and e2e tests (`tsconfig.node.json`) |
| `npm run test:unit` | Vitest Browser Mode in real Chromium, Firefox and WebKit (`test/unit`) |
| `npm run test:e2e` | Playwright against the demo page in Chromium, Firefox and WebKit (`test/e2e`); starts its own server on :5174 |
| `npm test` | Both suites |

```ts
import { Vault } from 'vault';

const vault = await Vault.open();
const key = await vault.generate('ed25519');
const signature = await vault.sign(key.id, new TextEncoder().encode('hello'));
```

## Browser support

| Engine | Version tested (Playwright 1.64.1) | Unit + e2e suites | Vault (unprotected, ed25519) | Passkey features |
|---|---|---|---|---|
| Chromium | 156 | ✓ | ✓ | not built yet |
| Firefox | 157 | ✓ | ✓ | not built yet |
| WebKit | 27.2 | ✓ | ✓ | not built yet |

Needs WebCrypto Ed25519, ECDH P-256, HKDF and AES-GCM, IndexedDB and `Uint8Array.prototype.toBase64` (ES2026), in a secure context. WebKit (Playwright, Linux) has four quirks that shape the design; see DESIGN.md §8:
- It loses stored X25519 keys.
- Its point import accepts off-curve points.
- Its Ed25519 key generation fails about 0.7% of the time (Vault retries it).
- Its Ed25519 verify crashes the tab on degenerate public keys. That one is not protected: only a planted key can trigger it.

## Property → test

Unit tests: `test/unit/vault.test.ts` (vault ›), `test/unit/storage.test.ts` (storage ›) and `test/unit/records.test.ts` (records ›). Every unit test runs in all three engines, except one test skipped in WebKit, as noted in its row. Each row was break-checked: the guarding code was broken once and the test went red in every listed engine. Where two guards protect one property, both were broken together. Exception: breaking the SPKI guard turns its test red only in WebKit, the only engine whose `raw` import accepts off-curve points. Not break-checked: the two platform rows, "Keys persist" and "Opening and listing write nothing", which are functional checks.

| Property | Test | Engines |
|---|---|---|
| Tests run in real browser engines, not an emulation | `test/unit/platform.test.ts` › runs in the real browser engine it is configured for | Chromium, Firefox, WebKit |
| Playwright suite serves the demo from a secure context (needed by WebCrypto and WebAuthn) | `test/e2e/demo.spec.ts` › demo page runs its TypeScript module in a secure context | Chromium, Firefox, WebKit |
| No private key bytes are stored; the only stored secret is a non-extractable root key | storage › encryption at rest › no private key bytes are stored: only ciphertext and a non-extractable root key | Chromium, Firefox, WebKit |
| A key sealed by format v1 still opens: HKDF info, label, salt and key length can't change silently (round trips alone would miss it) | storage › encryption at rest › a value sealed by format v1 still opens: key derivation and cipher parameters are pinned | Chromium, Firefox, WebKit |
| Nothing decrypts without the root key (the sealing really uses ECDH) | storage › encryption at rest › decrypting needs the root key: with another private key in its place, sign fails closed | Chromium, Firefox, WebKit |
| Format v1 is pinned: key id and AAD of fixed inputs, and a key record written by the v1 code still lists and signs | records › format v1 regression › keyId of a fixed input is unchanged / keyAad of fixed fields is unchanged / a key record written by the v1 code still lists and signs | Chromium, Firefox, WebKit |
| Records are parsed strictly: an unexpected field on the header, its protection, a key record or its sealed part is `corrupted` | records › strict parsing › an unexpected extra field on … is corrupted (4 cases); › an extra field fails closed through the API too… | Chromium, Firefox, WebKit |
| Every malformed field is `corrupted`, and the error names the field | records › strict parsing › a malformed header field is corrupted and named: … (6 cases); › a malformed key record field is corrupted and named: … (14 cases) | Chromium, Firefox, WebKit |
| A signature verifies under the public key alone, without Vault | vault › keys › a signature verifies under the public key with WebCrypto alone, without Vault; `test/e2e/demo.spec.ts` › demo creates, lists, signs, deletes and wipes keys… (verified again in Node) | Chromium, Firefox, WebKit |
| An edited id, type, public key or version is caught by `list()`, without any secret | storage › integrity › editing id / type / publicKey / v of a key record fails closed | Chromium, Firefox, WebKit |
| Any edit to a stored key record fails closed (`corrupted`), and the cases cover every field | storage › integrity › editing \<field\> of a key record fails closed (8 cases); › the edit cases cover every stored field of a key record | Chromium, Firefox, WebKit |
| A field whose type changes but whose value doesn't (`"123"` for `123`, an `Array` or `Int8Array` for bytes) fails closed at `list()` | storage › integrity › changing a field type without changing its value fails closed at list: … (6 cases) | Chromium, Firefox, WebKit |
| The canonical encoding keeps types and boundaries (`123` ≠ `"123"`, only `Uint8Array` counts as bytes) | storage › canonical encoding › each value keeps its type… | Chromium, Firefox, WebKit |
| The encoding's exact v1 bytes are pinned (tags 1/2/3, 4-byte big-endian length, 8-byte big-endian integers), so a refactor can't silently change every stored id and AAD | storage › canonical encoding › encodes the exact v1 bytes… | Chromium, Firefox, WebKit |
| Key ids are base64url without padding: their stored text form can't change silently | storage › canonical encoding › key ids are base64url without padding (RFC 4648 §5) | Chromium, Firefox, WebKit |
| A negative `createdAt` fails closed at `list()` | storage › integrity › a negative createdAt is rejected at list… | Chromium, Firefox, WebKit |
| A planted key with a wrong-length public key fails closed at `list()` | storage › integrity › a planted key whose public key has the wrong length is rejected at list | Chromium, Firefox, WebKit |
| A planted key with a degenerate public key fails closed at `sign()` | storage › integrity › a planted key with a degenerate public key is listed like any added key, and sign fails closed | Chromium, Firefox (skipped in WebKit, where verify crashes the tab: not protected) |
| Ciphertexts swapped between records fail closed | storage › integrity › ciphertexts swapped between two key records fail closed | Chromium, Firefox, WebKit |
| A key an attacker sealed to the public wrapping key is rejected, not used | storage › integrity › a key an attacker sealed to the public wrapping key decrypts, but is rejected instead of used | Chromium, Firefox, WebKit |
| A record moved to another scope is rejected | storage › integrity › a key record moved to another scope is rejected there: its id binds the scope | Chromium, Firefox, WebKit |
| Off-curve ephemeral public keys are rejected on import | storage › integrity › an off-curve ephemeral public key is rejected on import, in every engine | Chromium, Firefox, WebKit (the guard matters in WebKit, the only engine that goes red without it) |
| Unknown format versions are rejected, not coerced | storage › format versioning › a header with format version 2 / 1 (string) / true / undefined is rejected, not coerced; storage › integrity › editing v…; › changing a field type…: v as the string '1' | Chromium, Firefox, WebKit |
| Storage written by a newer format is rejected with `incompatible` | storage › format versioning › a database written by a newer format is rejected with incompatible | Chromium, Firefox, WebKit |
| An open vault never blocks a newer format, and refuses to work afterwards | storage › format versioning › an open vault never blocks a newer format, and refuses to work afterwards | Chromium, Firefox, WebKit |
| A multi-record write is atomic: a failed first generate leaves no header | vault › errors › the first generate writes header and key atomically: if the key write fails, no header remains | Chromium, Firefox, WebKit |
| IndexedDB failures are classified as retryable `unavailable` | vault › errors › an IndexedDB failure is reported as retryable unavailable, and a retry succeeds | Chromium, Firefox, WebKit |
| A transient key generation failure is retried; a persistent one is retryable `unavailable` | vault › errors › a transient key generation failure is retried; a persistent one is retryable unavailable | Chromium, Firefox, WebKit |
| A missing key is `not-found` | vault › keys › signing with an unknown key id fails with not-found | Chromium, Firefox, WebKit |
| Key records without a vault header are `corrupted` in `list`, `generate` and `sign`, never a new vault; only `wipe` recovers | vault › errors › key records without a vault header are corrupted everywhere, never a new vault; only wipe recovers | Chromium, Firefox, WebKit |
| A header stored as `undefined` is `corrupted`, not absent and not retryable | vault › errors › a header stored as undefined is corrupted, not absent and not a retryable failure | Chromium, Firefox, WebKit |
| A database without Vault's stores is `corrupted`, not retryable | vault › errors › a database without Vault stores is corrupted, not a retryable failure | Chromium, Firefox, WebKit |
| A call in flight across `close()` gets `InvalidStateError`, not a retryable error | vault › lifecycle › a call in flight when the vault is closed fails with InvalidStateError, not a retryable error | Chromium, Firefox, WebKit |
| An unknown key type is a `TypeError` (programming error) | vault › lifecycle › an unknown key type is a programming error (TypeError), not a VaultError | Chromium, Firefox, WebKit |
| Wipe removes every key and the header; the next vault has a new wrapping key | vault › keys › wipe removes every key and the vault header; the next generate starts a new vault | Chromium, Firefox, WebKit |
| Delete removes exactly one key | vault › keys › delete removes only that key, and deleting a missing key is a no-op | Chromium, Firefox, WebKit |
| Keys persist across reopen and page reload | vault › keys › keys survive closing and reopening the vault; `test/e2e/demo.spec.ts` › demo creates… | Chromium, Firefox, WebKit |
| Opening and listing write nothing | vault › lifecycle › opening and listing write nothing; the first generate creates the vault | Chromium, Firefox, WebKit |
