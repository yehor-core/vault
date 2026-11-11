# Vault

A browser-native private-key store on top of IndexedDB. Design: [DESIGN.md](DESIGN.md).

> Status: S2 in progress. Unprotected vault with ed25519 keys in named scopes: generate, list, sign, delete per scope; wipe for the whole vault. Keys are encrypted at rest in a versioned storage format, and errors are classified. Not built yet: secp256k1, labels, multi-tab notifications, passkey keys, passkey protection.

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
| `npm run demo` | Serves the demo page at http://localhost:5173: generate, list, sign (verified with WebCrypto outside Vault), delete in one fixed scope, `demo`; wipe |
| `npm run typecheck` | Type checks browser code (`tsconfig.json`, no Node globals) and Node-side config, scripts and e2e tests (`tsconfig.node.json`) |
| `npm run lint` | oxlint: the coding-standards rules marked _(oxlint)_ (`.oxlintrc.json`) |
| `npm run check:refs` | Checks that every test cited in `DESIGN.md` and `README.md` (`storage › …`) still exists |
| `npm run test:unit` | Vitest Browser Mode in real Chromium, Firefox and WebKit (`test/unit`) |
| `npm run test:e2e` | Playwright against the demo page in Chromium, Firefox and WebKit (`test/e2e`); starts its own server on :5174 |
| `npm run test:scripts` | Node tests of the repo's own scripts (`scripts/*.test.ts`), e.g. that `check:refs` rejects a bad citation |
| `npm test` | Script tests, then both suites |
| `npx vitest run <file> -t '<name>' --project chromium` | One unit test in one engine (`chromium`, `firefox` or `webkit`): the fast TDD loop |
| `npm run break-check -- <file> <text> <replacement> <test file> '<name>' [engine]` | Breaks the code once, runs the test, restores the code; exit 0 only if the test went red |

```ts
import { Vault } from 'vault';

const vault = await Vault.open();
const keys = vault.scope('https://app.example');   // a named group of keys; synchronous, no I/O
const key = await keys.generate('ed25519');
const signature = await keys.sign(key, new TextEncoder().encode('hello')); // the KeyInfo itself, not its id
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

Test references: `<name> ›` cites `test/unit/<name>.test.ts`, `e2e ›` cites `test/e2e/`; a middle segment names the `describe` group. `npm run check:refs` checks that every cited test exists. Every unit test runs in all three engines, except one test skipped in WebKit, as noted in its row. Every test about keys runs once per registered key type. Each row was break-checked: the guarding code was broken once and the test went red in every listed engine. Where two guards protect one property, both were broken together. Exception: breaking the SPKI guard turns its test red only in WebKit, the only engine whose `raw` import accepts off-curve points. Not break-checked: the two platform rows, "Keys persist" and "Opening and listing write nothing", which are functional checks.

| Property | Test | Engines |
|---|---|---|
| Tests run in real browser engines, not an emulation | `platform › runs in the real browser engine it is configured for` | Chromium, Firefox, WebKit |
| Playwright suite serves the demo from a secure context (needed by WebCrypto and WebAuthn) | `e2e › demo page runs its TypeScript module in a secure context` | Chromium, Firefox, WebKit |
| No private key bytes are stored; the only stored secret is a non-extractable root key | `storage › encryption at rest › no private key bytes are stored: only ciphertext and a non-extractable root key` (raw key bytes), with `› decrypting needs the root key…` (any form that opens without the secret) | Chromium, Firefox, WebKit |
| A key sealed by format v1 still opens: HKDF info, label, salt and key length can't change silently (round trips alone would miss it) | `storage › encryption at rest › a value sealed by format v1 still opens: key derivation and cipher parameters are pinned` | Chromium, Firefox, WebKit |
| Nothing decrypts without the root key (the sealing really uses ECDH) | `storage › encryption at rest › decrypting needs the root key: with another private key in its place, sign fails closed` | Chromium, Firefox, WebKit |
| Format v1 is pinned: key id and AAD of fixed inputs, a key record written by the v1 code still lists and signs, and the default database name is `vault` | `records › format v1 regression › keyId of a fixed input is unchanged / keyAad of fixed fields is unchanged / a key record written by the v1 code still lists and signs / the default database name is 'vault'` | Chromium, Firefox, WebKit |
| Records are parsed strictly: an unexpected field on the header, its protection, a key record or its sealed part is `corrupted` | `records › strict parsing › an unexpected extra field on … is corrupted`, `› an extra field fails closed through the API too…` | Chromium, Firefox, WebKit |
| Every malformed field is `corrupted`, and the error names the field | `records › strict parsing › a malformed header field is corrupted and named: …`, `› a malformed key record field is corrupted and named: …` | Chromium, Firefox, WebKit |
| A signature verifies under the public key alone, without Vault | `vault › keys › a signature verifies under the public key without Vault`; `e2e › demo creates, lists, signs, deletes and wipes keys…` (verified again in Node) | Chromium, Firefox, WebKit |
| An edited id, type, public key or version is caught by `list()`, without any secret | `storage › integrity › editing <field> of a key record fails closed`: id, type, publicKey, v | Chromium, Firefox, WebKit |
| Any edit to a stored key record fails closed (`corrupted`), and the cases cover every field | `storage › integrity › editing <field> of a key record fails closed`, `› the edit cases cover every stored field of a key record` | Chromium, Firefox, WebKit |
| A field whose type changes but whose value doesn't (`"123"` for `123`, an `Array` or `Int8Array` for bytes) fails closed at `list()` | `storage › integrity › changing a field type without changing its value fails closed at list: …` | Chromium, Firefox, WebKit |
| The canonical encoding keeps types and boundaries (`123` ≠ `"123"`, only `Uint8Array` counts as bytes, no unsafe integers: `2**64` would wrap to `0`) | `storage › canonical encoding › each value keeps its type…` | Chromium, Firefox, WebKit |
| The encoding's exact v1 bytes are pinned (tags 1/2/3, 4-byte big-endian length, 8-byte big-endian integers), so a refactor can't silently change every stored id and AAD | `storage › canonical encoding › encodes the exact v1 bytes…` | Chromium, Firefox, WebKit |
| Key ids are base64url without padding: their stored text form can't change silently | `storage › canonical encoding › key ids are base64url without padding (RFC 4648 §5)` | Chromium, Firefox, WebKit |
| A negative `createdAt` fails closed at `list()` | `storage › integrity › a negative createdAt is rejected at list…` | Chromium, Firefox, WebKit |
| A planted key whose public key is not valid for its type (ed25519: not 32 bytes) fails closed at `list()` | `storage › integrity › a planted key whose public key is not valid for its type is rejected at list` | Chromium, Firefox, WebKit |
| A planted key with a degenerate public key fails closed at `sign()` | `storage › integrity › a planted key with a degenerate public key is listed like any added key, and sign fails closed` | Chromium, Firefox (skipped in WebKit, where verify crashes the tab: not protected) |
| Ciphertexts swapped between records fail closed | `storage › integrity › ciphertexts swapped between two key records fail closed` | Chromium, Firefox, WebKit |
| A key an attacker sealed to the public wrapping key is rejected, not used | `storage › integrity › a key an attacker sealed to the public wrapping key decrypts, but is rejected instead of used` | Chromium, Firefox, WebKit |
| A record moved to another scope fails closed: at `list()` if its id is kept, at `sign()` if its id is recomputed for the new scope | `storage › integrity › a key record moved to another scope fails closed: at list if its id is kept, at sign if it is recomputed` | Chromium, Firefox, WebKit |
| Off-curve ephemeral public keys are rejected on import | `storage › integrity › an off-curve ephemeral public key is rejected on import, in every engine` | Chromium, Firefox, WebKit (the guard matters in WebKit, the only engine that goes red without it) |
| Unknown format versions are rejected, not coerced | `storage › format versioning › a header with format version…` (2, '1' as a string, true, missing); `storage › integrity › editing <field> of a key record fails closed`: v; `› changing a field type…`: v as the string '1' | Chromium, Firefox, WebKit |
| Storage written by a newer format is rejected with `incompatible` | `storage › format versioning › a database written by a newer format is rejected with incompatible` | Chromium, Firefox, WebKit |
| An open vault never blocks a newer format, and refuses to work afterwards | `storage › format versioning › an open vault never blocks a newer format, and refuses to work afterwards` | Chromium, Firefox, WebKit |
| A multi-record write is atomic: a failed first generate leaves no header | `vault › errors › the first generate writes header and key atomically: if the key write fails, no header remains` | Chromium, Firefox, WebKit |
| IndexedDB failures are classified as retryable `unavailable` | `vault › errors › an IndexedDB failure is reported as retryable unavailable, and a retry succeeds` | Chromium, Firefox, WebKit |
| Only `unavailable` is retryable: every other code is asserted non-retryable wherever a test expects it | `test/unit/helpers.ts` `expectVaultError` (used by every error test) | Chromium, Firefox, WebKit |
| A transaction that aborts at commit, after its body ran, fails as `unavailable` and stores nothing | `vault › errors › a write that aborts at commit, after its body returned, fails as unavailable and stores nothing` | Chromium, Firefox, WebKit |
| `wipe` is one transaction: aborted midway, it fails and leaves the header and keys | `vault › errors › wipe is one transaction: aborted midway, it fails as unavailable and the header and keys remain` | Chromium, Firefox, WebKit |
| A tampered wrapping public key makes `generate` fail closed (`corrupted`), not with a raw `DataError` | `storage › integrity › a tampered wrapping public key makes generate fail closed, not with a raw DataError` | Chromium, Firefox, WebKit |
| A key generation that keeps failing is retryable `unavailable` and stores nothing, for every key type | `vault › errors › a key generation that keeps failing is retryable unavailable, and stores nothing` | Chromium, Firefox, WebKit |
| A transient key generation failure is retried; a persistent one is retryable `unavailable` | `vault › errors › a transient key generation failure is retried; a persistent one is retryable unavailable` | Chromium, Firefox, WebKit |
| A missing key is `not-found` | `vault › keys › signing with an unknown key id fails with not-found` | Chromium, Firefox, WebKit |
| Key records without a vault header are `corrupted` in `list`, `generate` and `sign`, never a new vault; only `wipe` recovers | `vault › errors › key records without a vault header are corrupted everywhere, never a new vault; only wipe recovers` | Chromium, Firefox, WebKit |
| A header stored as `undefined` is `corrupted`, not absent and not retryable | `vault › errors › a header stored as undefined is corrupted, not absent and not a retryable failure` | Chromium, Firefox, WebKit |
| A database without Vault's stores is `corrupted`, not retryable | `vault › errors › a database without Vault stores is corrupted, not a retryable failure` | Chromium, Firefox, WebKit |
| A call in flight across `close()` gets `InvalidStateError`, not a retryable error | `vault › lifecycle › a call in flight when the vault is closed fails with InvalidStateError, not a retryable error` | Chromium, Firefox, WebKit |
| A closed vault rejects every call of the vault and of its scopes | `vault › lifecycle › a closed vault rejects every call` | Chromium, Firefox, WebKit |
| `scope()` after `close()` throws `InvalidStateError`; closing ends every scope, calls in flight included | `vault › scopes › scope() after close() throws InvalidStateError, and closing ends every scope, calls in flight included` | Chromium, Firefox, WebKit |
| Keys of one scope are listed only there; an unused scope lists nothing | `vault › scopes › keys generated in one scope are listed only there, and an unused scope lists nothing` | Chromium, Firefox, WebKit |
| A malformed scope name (empty, over 1024 code units, not a string, a lone surrogate) is a `TypeError`; names are compared exactly | `vault › scopes › a malformed scope name is a TypeError; a name of 1 to 1024 code units is a scope of its own` | Chromium, Firefox, WebKit |
| The id of a key of another scope is `not-found` for `sign` and untouched by `delete` | `vault › scopes › the id of a key of another scope is not-found by sign and untouched by delete` | Chromium, Firefox, WebKit |
| A key passed to a scope it doesn't belong to is a `TypeError` in `sign` and `delete`: not signed with, not deleted | `vault › scopes › a key passed to another scope is a TypeError in sign and delete: not signed with, not deleted` | Chromium, Firefox, WebKit |
| `sign` and `delete` take a key's public information as returned, a structured clone included | `vault › keys › sign and delete take the public information as returned, a structured clone included` | Chromium, Firefox, WebKit |
| Only the id, scope and type of the argument count: an edited public key or creation time changes nothing, and the signature verifies under the stored public key | `vault › keys › only the id, scope and type of the argument count: edited public key and creation time change nothing` | Chromium, Firefox, WebKit |
| An argument whose type differs from the stored key is a `TypeError`, and the key is not deleted | `vault › keys › an argument whose type differs from the stored key is a TypeError, and the key is not deleted` | Chromium, Firefox, WebKit |
| `delete` removes a record whose stored type was tampered with, as before (only a different registered type is a `TypeError`) | `storage › integrity › delete removes a record whose stored type was tampered with` | Chromium, Firefox, WebKit |
| An argument that is not an object with a string id (an id string alone included) is a `TypeError` | `vault › keys › an argument that is not an object with a string id is a TypeError in sign and delete` | Chromium, Firefox, WebKit |
| A `Scope` has no path to its `Vault`: code holding only a `Scope` can't wipe or retarget it at another scope | `vault › scopes › a Scope has no path to its Vault: it can neither wipe nor be retargeted at another scope` | Chromium, Firefox, WebKit |
| `wipe` clears every scope and the header in one transaction | `vault › scopes › wipe removes the keys of every scope and the header in one transaction` | Chromium, Firefox, WebKit |
| S1's fixed scope is the ordinary scope `default`: an S1 record lists and signs there | `records › format v1 regression › a key record written by the v1 code still lists and signs` | Chromium, Firefox, WebKit |
| `sign` rejects `data` that is not a `Uint8Array` instead of signing something else (a string would coerce to the empty message) | `vault › lifecycle › sign rejects data that is not a Uint8Array instead of signing something else` | Chromium, Firefox, WebKit |
| An unknown key type is a `TypeError` (programming error) | `vault › lifecycle › an unknown key type is a programming error (TypeError), not a VaultError` | Chromium, Firefox, WebKit |
| Wipe removes every key and the header; the next vault has a new wrapping key | `vault › keys › wipe removes every key and the vault header; the next generate starts a new vault` | Chromium, Firefox, WebKit |
| Delete removes exactly one key | `vault › keys › delete removes only that key, and deleting a missing key is a no-op` | Chromium, Firefox, WebKit |
| Keys persist across reopen and page reload | `vault › keys › keys survive closing and reopening the vault`; `e2e › demo creates…` | Chromium, Firefox, WebKit |
| A generated key's secret buffers are erased once it is stored, and on every failure path of `generate` | `storage › encryption at rest › a generated key has its secrets erased once, after it is stored`, `› a generated key has its secrets erased when generate fails: <case>` | Chromium, Firefox, WebKit |
| The core never names a key type: a new sealed key type is one module and one registry entry | `key-types › no core file names a registered key type` | Chromium, Firefox, WebKit |
| Opening and listing write nothing | `vault › lifecycle › opening and listing write nothing; the first generate creates the vault` | Chromium, Firefox, WebKit |
