# Vault

A browser-native private-key store on top of IndexedDB. Design: [DESIGN.md](DESIGN.md).

> Status: S2. Unprotected vault with ed25519 and secp256k1 keys in named scopes, with optional labels: generate, list, sign, delete, wipe. Keys are encrypted at rest in a versioned storage format, and errors are classified. Not built yet: persistent storage, multi-tab notifications, passkey keys, passkey protection.

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
| `npm run demo` | Serves the demo page at http://localhost:5173: pick a scope, generate ed25519 or secp256k1 keys with a label, list, sign (verified outside Vault), delete, wipe |
| `npm run typecheck` | Type checks browser code (`tsconfig.json`, no Node globals) and Node-side config and e2e tests (`tsconfig.node.json`) |
| `npm run test:unit` | Vitest Browser Mode in real Chromium, Firefox and WebKit (`test/unit`) |
| `npm run test:e2e` | Playwright against the demo page in Chromium, Firefox and WebKit (`test/e2e`); starts its own server on :5174 |
| `npm test` | Both suites |

```ts
import { Vault } from 'vault';

const vault = await Vault.open();
const keys = vault.scope('my-app');
const key = await keys.generate('secp256k1', { label: 'Main' });
const signature = await keys.sign(key, new TextEncoder().encode('hello'));
```

Runtime dependency: `@noble/curves` 2.3.0 (with `@noble/hashes` 2.3.0), for secp256k1 and for Ed25519 verification; why, in DESIGN.md §3.3.

## Browser support

| Engine | Version tested (Playwright 1.64.1) | Unit + e2e suites | Vault (unprotected; ed25519, secp256k1; scopes, labels) | Passkey features |
|---|---|---|---|---|
| Chromium | 156 | ✓ | ✓ | not built yet |
| Firefox | 157 | ✓ | ✓ | not built yet |
| WebKit | 27.2 | ✓ | ✓ | not built yet |

Needs WebCrypto Ed25519, ECDH P-256, HKDF and AES-GCM, IndexedDB, `Uint8Array.prototype.toBase64` (ES2026) and `String.prototype.isWellFormed` (ES2024), in a secure context. secp256k1 runs in JavaScript (`@noble/curves`), the same in every engine. WebKit (Playwright, Linux) has four quirks that shape the design; see DESIGN.md §8:
- It loses stored X25519 keys.
- Its point import accepts off-curve points.
- Its Ed25519 key generation fails about 0.7% of the time (Vault retries it).
- Its Ed25519 `crypto.subtle.verify` crashes the tab on degenerate public keys. Vault verifies Ed25519 with noble instead, so a planted key fails closed in WebKit too.

## Property → test

Unit tests: `test/unit/vault.test.ts` (vault ›), `test/unit/storage.test.ts` (storage ›), `test/unit/records.test.ts` (records ›) and `test/unit/key-types.test.ts` (key-types ›). Every unit test runs in all three engines; none is skipped. A test written "for each type" runs once per registered key type (ed25519, secp256k1).

Every row was break-checked: the guarding code was broken once and the test went red in every listed engine. S1 rows were checked in S1, and their tests kept their substance when they moved to the Scope API. For S2, 29 guards were broken one at a time, and each turned its test red in Chromium, Firefox and WebKit. Where several guards protect one property, the test pins Vault's own guard. For example, noble and the signature check would also stop a bad secp256k1 scalar, so the test checks that Vault rejects it first. Exceptions:
- Breaking the SPKI guard turns its test red only in WebKit, the only engine whose `raw` import accepts off-curve points.
- With Ed25519 verification moved back to `crypto.subtle.verify`, the noble-only test goes red everywhere. The degenerate-key tests then crash WebKit's page but pass in Chromium and Firefox; that crash is why the guard exists.

Not break-checked, because they are functional checks:
- the two platform rows
- "Keys persist"
- "Opening and listing write nothing"
- "A scope is its name"
- "Labels are stored and listed"

| Property | Test | Engines |
|---|---|---|
| Tests run in real browser engines, not an emulation | `test/unit/platform.test.ts` › runs in the real browser engine it is configured for | Chromium, Firefox, WebKit |
| Playwright suite serves the demo from a secure context (needed by WebCrypto and WebAuthn) | `test/e2e/demo.spec.ts` › demo page runs its TypeScript module in a secure context | Chromium, Firefox, WebKit |
| **Keys and key types** | | |
| Every key type generates, lists and signs through the same API | vault › keys of type \<type\> › a generated key is listed with its public information, in its scope (for each type); › keys of every type are listed together, oldest first | Chromium, Firefox, WebKit |
| A signature verifies under the public key alone, without Vault | vault › keys of type \<type\> › a signature verifies under the public key without Vault, and only for the signed data (WebCrypto for ed25519, noble for secp256k1); `test/e2e/demo.spec.ts` › demo creates, lists, signs, deletes and wipes keys of both types… (verified again in Node: WebCrypto for ed25519, OpenSSL for secp256k1, no noble) | Chromium, Firefox, WebKit |
| A new key type is a local change: no core file names a key type | key-types › the core never branches on key type names › no core file mentions a registered key type… | Chromium, Firefox, WebKit |
| secp256k1 is ECDSA over SHA-256(data) with RFC 6979 nonces, low-S, r ‖ s: every noble option is pinned | key-types › secp256k1 › signs the published RFC 6979 vector exactly…; `test/e2e/demo.spec.ts` › demo creates… (OpenSSL verifies) | Chromium, Firefox, WebKit |
| secp256k1 signatures are low-S, checked without noble | key-types › secp256k1 › every signature Vault returns is low-S, checked without noble | Chromium, Firefox, WebKit |
| A stored secp256k1 public key must be a 33-byte compressed point on the curve, checked by `list()` | key-types › secp256k1 › a public key is stored as a 33-byte compressed point; any other form or an off-curve point is rejected at list | Chromium, Firefox, WebKit |
| A decrypted secp256k1 value that is not a 32-byte scalar in [1, n−1] fails `sign()` closed | key-types › secp256k1 › a planted key whose sealed scalar is zero / the group order n / n + 1 / 31 bytes / 33 bytes fails sign closed | Chromium, Firefox, WebKit |
| Vault zeroes the secp256k1 secret buffers it owns (seed, generated scalar, decrypted scalar), on failure paths too | key-types › secp256k1 › Vault zeroes the secret buffers it owns…; › a generated key is disposed when generate fails after generating it, and when sign rejects the decrypted value | Chromium, Firefox, WebKit |
| Ed25519 signatures are verified with noble, never `crypto.subtle.verify` (which crashes WebKit on planted keys), in strict RFC 8032 mode | key-types › ed25519 › signatures are checked with noble, never with crypto.subtle.verify…; › strict RFC 8032 verification: a small-order public key verifies nothing… | Chromium, Firefox, WebKit |
| `generate` draws the key pair once, before any IndexedDB access; a write redone after a wipe seals that pair to the new header | vault › errors › generate draws the key pair once, before any IndexedDB access; a write redone after a wipe seals that same pair | Chromium, Firefox, WebKit |
| **Scopes and labels** | | |
| Scopes keep keys apart: each lists only its own; delete in one leaves the other | vault › scopes › scopes keep keys apart… | Chromium, Firefox, WebKit |
| A scope is its name: any Vault instance on the database sees the same keys | vault › scopes › the same name gives the same scope, from any Vault instance on the database | Chromium, Firefox, WebKit |
| A key of another scope is a `TypeError` in `sign` and `delete`, never that scope's key | vault › scopes › a key of another scope is a TypeError in sign and delete… | Chromium, Firefox, WebKit |
| Scope names are well-formed strings of 1–1024 characters | vault › scopes › scope names are well-formed strings of 1 to 1024 characters…; records › strict parsing › a malformed key record field…: scope … (4 cases) | Chromium, Firefox, WebKit |
| A Scope can't reach its Vault (code handed only a Scope can't wipe) | vault › scopes › a Scope exposes its name and key operations, and no way to reach its Vault | Chromium, Firefox, WebKit |
| A record moved to another scope with its id recomputed is listed there, but `sign()` fails closed (the AAD binds scope and id) | storage › integrity › \<type\> › a key record moved to another scope with its id recomputed is listed there, but sign fails closed (for each type) | Chromium, Firefox, WebKit |
| A record moved to another scope with its id kept is rejected by `list()` (the id binds the scope) | storage › integrity › \<type\> › a key record moved to another scope with its id kept is rejected by list() there (for each type) | Chromium, Firefox, WebKit |
| Labels are stored and listed without any secret | vault › labels › a label is stored with the key and listed without any secret | Chromium, Firefox, WebKit |
| Labels are well-formed strings of 1–256 characters, checked at `generate` and on every read | vault › labels › labels are well-formed strings of 1 to 256 characters…; records › strict parsing › a malformed key record field…: label … (5 cases) | Chromium, Firefox, WebKit |
| An edited, removed or added label fails `sign()` closed | storage › integrity › \<type\> › editing label of a key record fails closed; › a label removed from a key, or added to one stored without it… (for each type) | Chromium, Firefox, WebKit |
| A label enters the AAD only when present, as the tagged pair `'label'`, label; unlabelled records keep their v1 AAD | records › format v1 regression › keyAad of fixed labelled fields appends the tagged pair…; › keyAad of fixed fields is unchanged | Chromium, Firefox, WebKit |
| Strings with a lone surrogate never encode, so two names can't share an id or AAD | storage › canonical encoding › a string with a lone surrogate is rejected…; records › strict parsing › …: scope / id / label with a lone surrogate | Chromium, Firefox, WebKit |
| `sign` and `delete` take a KeyInfo: a bare id or a KeyInfo whose type was changed is a `TypeError` | vault › lifecycle › sign and delete take a KeyInfo… | Chromium, Firefox, WebKit |
| **Encryption at rest** | | |
| No private key bytes are stored, for any key type; the only stored secret is a non-extractable root key | storage › encryption at rest › no private key bytes are stored, for any key type… (raw key bytes), together with › decrypting needs the root key… (any form that opens without the secret) | Chromium, Firefox, WebKit |
| A key sealed by format v1 still opens: HKDF info, label, salt and key length can't change silently (round trips alone would miss it) | storage › encryption at rest › a value sealed by format v1 still opens: key derivation and cipher parameters are pinned | Chromium, Firefox, WebKit |
| Nothing decrypts without the root key (the sealing really uses ECDH) | storage › encryption at rest › decrypting needs the root key: with another private key in its place, sign fails closed (for each type) | Chromium, Firefox, WebKit |
| **Storage format** | | |
| Format v1 is pinned: key id and AAD of fixed inputs, a key record of each type written by the v1 code still lists and signs (the secp256k1 one with its exact signature), and the default database name is `vault` | records › format v1 regression › keyId of a fixed input is unchanged / keyAad of fixed fields is unchanged / a \<type\> key record written by the v1 code still lists and signs / the default database name is 'vault' | Chromium, Firefox, WebKit |
| A key of a well-formed type this build doesn't know is `incompatible`, not `corrupted`, even with unknown fields; keys of known types still sign | storage › format versioning › a key of a type this build does not know is incompatible…; records › strict parsing › a key of the unknown type … is incompatible… (4 cases) | Chromium, Firefox, WebKit |
| Records are parsed strictly: an unexpected field on the header, its protection, a key record or its sealed part is `corrupted` | records › strict parsing › an unexpected extra field on … is corrupted (4 cases); › an extra field fails closed through the API too… | Chromium, Firefox, WebKit |
| Every malformed field is `corrupted`, and the error names the field | records › strict parsing › a malformed header field is corrupted and named: … (6 cases); › a malformed key record field is corrupted and named: … (30 cases, including prototype-named types, non-canonical points and over-long values) | Chromium, Firefox, WebKit |
| Unknown format versions are rejected, not coerced | storage › format versioning › a header with format version 2 / '1' (a string) / true / missing is rejected, not coerced; storage › integrity › … › editing v…; › changing a field type…: v as the string '1' | Chromium, Firefox, WebKit |
| Storage written by a newer format is rejected with `incompatible` | storage › format versioning › a database written by a newer format is rejected with incompatible | Chromium, Firefox, WebKit |
| An open vault never blocks a newer format, and refuses to work afterwards | storage › format versioning › an open vault never blocks a newer format, and refuses to work afterwards | Chromium, Firefox, WebKit |
| **Integrity** | | |
| An edited id, type, public key or version is caught by `list()`, without any secret | storage › integrity › \<type\> › editing id / type / publicKey / v of a key record fails closed (for each type) | Chromium, Firefox, WebKit |
| Any edit to a stored key record fails closed (`corrupted`), and the cases cover every field | storage › integrity › \<type\> › editing \<field\> of a key record fails closed (9 cases, for each type); › the edit cases cover every stored field of a labelled key record | Chromium, Firefox, WebKit |
| A field whose type changes but whose value doesn't (`"123"` for `123`, an `Array` or `Int8Array` for bytes) fails closed at `list()` | storage › integrity › changing a field type without changing its value fails closed at list: … (6 cases) | Chromium, Firefox, WebKit |
| The canonical encoding keeps types and boundaries (`123` ≠ `"123"`, only `Uint8Array` counts as bytes, no unsafe integers: `2**64` would wrap to `0`) | storage › canonical encoding › each value keeps its type… | Chromium, Firefox, WebKit |
| The encoding's exact v1 bytes are pinned (tags 1/2/3, 4-byte big-endian length, 8-byte big-endian integers), so a refactor can't silently change every stored id and AAD | storage › canonical encoding › encodes the exact v1 bytes… | Chromium, Firefox, WebKit |
| Key ids are base64url without padding: their stored text form can't change silently | storage › canonical encoding › key ids are base64url without padding (RFC 4648 §5) | Chromium, Firefox, WebKit |
| A negative `createdAt` fails closed at `list()` | storage › integrity › a negative createdAt is rejected at list… | Chromium, Firefox, WebKit |
| A planted key with a wrong-length public key fails closed at `list()` | storage › integrity › a planted \<type\> key whose public key has the wrong length is rejected at list (for each type) | Chromium, Firefox, WebKit |
| A planted ed25519 key with a degenerate public key fails closed at `sign()`, in every engine | storage › integrity › a planted ed25519 key whose public key is the identity point / a point with a small y is listed like any added key, and sign fails closed | Chromium, Firefox, WebKit |
| Ciphertexts swapped between records fail closed | storage › integrity › \<type\> › ciphertexts swapped between two key records fail closed (for each type) | Chromium, Firefox, WebKit |
| A key an attacker sealed to the public wrapping key is rejected, not used | storage › integrity › \<type\> › a key an attacker sealed to the public wrapping key decrypts, but is rejected instead of used (for each type) | Chromium, Firefox, WebKit |
| Off-curve ephemeral public keys are rejected on import | storage › integrity › an off-curve ephemeral public key is rejected on import, in every engine | Chromium, Firefox, WebKit (the guard matters in WebKit, the only engine that goes red without it) |
| A tampered wrapping public key makes `generate` fail closed (`corrupted`), not with a raw `DataError` | storage › integrity › a tampered wrapping public key makes generate fail closed, not with a raw DataError | Chromium, Firefox, WebKit |
| Key records without a vault header are `corrupted` in `list`, `generate` and `sign`, in every scope, never a new vault; only `wipe` recovers | vault › errors › key records without a vault header are corrupted everywhere, never a new vault; only wipe recovers | Chromium, Firefox, WebKit |
| A header stored as `undefined` is `corrupted`, not absent and not retryable | vault › errors › a header stored as undefined is corrupted, not absent and not a retryable failure | Chromium, Firefox, WebKit |
| A database without Vault's stores is `corrupted`, not retryable | vault › errors › a database without Vault stores is corrupted, not a retryable failure | Chromium, Firefox, WebKit |
| **Atomicity and errors** | | |
| A multi-record write is atomic: a failed first generate leaves no header | vault › errors › the first generate writes header and key atomically: if the key write fails, no header remains | Chromium, Firefox, WebKit |
| A transaction that aborts at commit, after its body ran, fails as `unavailable` and stores nothing | vault › errors › a write that aborts at commit, after its body returned, fails as unavailable and stores nothing | Chromium, Firefox, WebKit |
| `wipe` is one transaction: aborted midway, it fails and leaves the header and keys | vault › errors › wipe is one transaction: aborted midway, it fails as unavailable and the header and keys remain | Chromium, Firefox, WebKit |
| IndexedDB failures are classified as retryable `unavailable` | vault › errors › an IndexedDB failure is reported as retryable unavailable, and a retry succeeds | Chromium, Firefox, WebKit |
| A transient key generation failure is retried; a persistent one is retryable `unavailable` | vault › errors › a transient key generation failure is retried; a persistent one is retryable unavailable | Chromium, Firefox, WebKit |
| Only `unavailable` is retryable: every other code is asserted non-retryable wherever a test expects it | `test/unit/helpers.ts` `expectVaultError` (used by every error test) | Chromium, Firefox, WebKit |
| A missing key is `not-found` | vault › keys › signing with an unknown key id fails with not-found; vault › keys of type \<type\> › delete removes only that key… | Chromium, Firefox, WebKit |
| **Lifecycle** | | |
| A call in flight across `close()` gets `InvalidStateError`, not a retryable error | vault › lifecycle › a call in flight when the vault is closed fails with InvalidStateError, not a retryable error | Chromium, Firefox, WebKit |
| A closed vault rejects every call, on the vault and on its scopes, and `scope()` throws | vault › lifecycle › a closed vault rejects every call, on the vault and on its scopes | Chromium, Firefox, WebKit |
| `sign` rejects `data` that is not a `Uint8Array` instead of signing something else (a string would coerce to the empty message) | vault › lifecycle › sign rejects data that is not a Uint8Array instead of signing something else | Chromium, Firefox, WebKit |
| An unknown key type is a `TypeError` (programming error) | vault › lifecycle › an unknown key type is a programming error (TypeError), not a VaultError | Chromium, Firefox, WebKit |
| Wipe removes every key in every scope and the header; the next vault has a new wrapping key | vault › keys › wipe removes every key in every scope and the vault header; the next generate starts a new vault | Chromium, Firefox, WebKit |
| Delete removes exactly one key | vault › keys of type \<type\> › delete removes only that key, and deleting a missing key is a no-op (for each type) | Chromium, Firefox, WebKit |
| Keys persist across reopen and page reload | vault › keys of type \<type\> › keys survive closing and reopening the vault (for each type); `test/e2e/demo.spec.ts` › demo creates… | Chromium, Firefox, WebKit |
| Opening and listing write nothing | vault › lifecycle › opening and listing write nothing; the first generate creates the vault | Chromium, Firefox, WebKit |
