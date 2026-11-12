# Vault — Design

<!--
Template. Guidance lives in HTML comments; delete each comment once its section is written.
Rules for filling:
- Short as it can be while complete. Prefer tables and one-line statements over prose.
- Every guarantee names the code or test that enforces it (file:test name). No reference → write "not protected"; a test still to come → "not tested yet: #NN", naming its ticket in the same cell or sentence. `npm run check:refs` checks the code and test names and the ticket.
- Self-contained: state each decision's outcome and rejected alternatives here, without links or decision IDs, so the document reads on its own.
-->

Test references: `<name> ›` cites `test/unit/<name>.test.ts`, `e2e ›` cites `test/e2e/`. Unit tests run in Chromium, Firefox and WebKit.

## 1. Overview

Vault is a browser-native private-key store on IndexedDB. An application calls it to generate keys, list their public information and get signatures; private keys never leave it. Vault does not know or care what its keys sign.

| Goal | Status | Where |
|---|---|---|
| No plaintext keys at rest | Built (unprotected mode) | §3.1, §4.1 |
| Optional, upgradeable protection | Format ready; upgrade not built yet | §3.1, §5 |
| Cheap to add, gated to use | Adding needs only the public wrapping key | §3.1 |
| Many key types, one model | ed25519 and secp256k1; a new sealed key type is one module and one registry entry | §7.5 |
| Correct under concurrency and failure | Atomic writes, fail-closed reads; no lost updates, first-time setup and a stale context against a wipe tested across tabs | §4.2, §6 |
| A small, idiomatic domain API | Built for unprotected ed25519 and secp256k1 keys in named scopes | §7 |

## 2. Threat model

### 2.1 Assets

| Asset | Secret? |
|---|---|
| Private key material (ed25519, secp256k1) | Yes. Never leaves Vault through the API. |
| Wrapping private key: decrypts every private key | Yes. In unprotected mode it is the root secret. |
| Integrity of key records: Vault signs only with the key whose public key it lists | — |
| Protection state (unprotected or passkey-protected) | Not built yet |
| Public information: id, scope, type, public key, createdAt, label | No. Stored in the clear, readable by anyone who can read storage. |

### 2.2 Adversaries and events

| Adversary or event | Capability |
|---|---|
| Profile or disk copy | Reads every IndexedDB file, offline, at any later time |
| Storage writer: same-origin script, or someone editing the profile | Adds, edits, swaps, deletes any record; reads every public field |
| Snapshot restore | Puts back an older, internally consistent copy of the database |
| Same-origin script | Runs in the origin: calls the Vault API, opens the database itself, and uses the stored CryptoKeys |
| Eviction, crash, closed tab | Storage is removed as a whole; a transaction is cut off midway |

Trusted: the browser, its WebCrypto and IndexedDB implementations, the OS, and origin isolation.

### 2.3 Guarantees per case

| Adversary or event | Mode | Guarantee | Not guaranteed | Enforced by |
|---|---|---|---|---|
| Copy of the browser profile or disk | Unprotected | Private keys are stored only as AES-256-GCM ciphertext. The only stored secret is the wrapping private key, a non-extractable CryptoKey held by the browser, and without it nothing decrypts. | **Not protected against a profile copy.** The browser keeps the root key's bytes in the profile, so the copy, opened in the same browser or parsed, recovers every key. | `storage › no private key bytes are stored: only ciphertext and a non-extractable root key`, `› decrypting needs the root key…` |
| | Protected | Not built yet | | |
| Records added or replaced by anyone who can write to storage | Both | The tamper table names, for the header and for a key record that is modified, swapped, truncated or malformed, the operation that first detects it (`list()`, `generate()` or `sign()`), and shows that the operations before it don't. `list()`, with no secret, rejects a field of the wrong type or length, and an edited id, type, public key or version. A record moved to another scope fails closed: `list()` rejects it there if its id was kept, because the id binds the scope; if the id was recomputed for the new scope, `sign()` rejects it, because the AAD binds scope and id. `sign()` rejects an edit to any other field: a changed byte, a shortened ciphertext or ephemeral key, sealed parts exchanged between two records, an off-curve ephemeral key. Two key records whose contents are exchanged, ids kept, fail `list()`, because the id binds the public key. A key record or a header taken from another vault database of this origin passes `list()` and fails `sign()`: the key was sealed to another wrapping key, or the header holds another one. A header whose wrapping public key is shortened, off the curve or on another curve passes `list()` and fails `generate()`; Firefox imports a key of another curve as P-256, so Vault checks the curve of every imported public key (`src/seal.ts` `importPublicKey`); a missing, malformed or extra header field fails `list()`. It also rejects a key the attacker sealed to the public wrapping key: that ciphertext decrypts cleanly, so the signature check before returning catches it. A stored label that is edited, added or removed fails `sign()` too, for every key type, because the AAD binds it. A planted ed25519 public key that is not a canonical RFC 8032 point encoding, or is a point of small order (the identity among them), is rejected by `list()`, so no verify ever sees it. A sealed secp256k1 value that is not a valid 32-byte scalar is rejected by Vault's own check before it is used. Key records without a header are never treated as a new vault. A record planted in `meta` next to the header fails `list()`, `generate()` and `sign()`; `wipe()` recovers. All of these fail with `corrupted`. Object stores that are not Vault's are never read. | A complete new key record needs no secret, so an added key can't be told from a real one. Deleting records isn't detected. Edits to createdAt, the label and the ciphertext surface only when the key is used: until then `list()` shows an edited label. **Label spoofing is not prevented:** a writer can add a complete key with any label, a real key's label included, so callers that need assurance pin key ids. `list()` doesn't check the length of the header's wrapping public key or of a key's ephemeral public key, so a shortened one surfaces only at `generate()` or `sign()`. **Header replacement is not protected in unprotected mode.** A replaced header (another vault's, or one holding the writer's wrapping public key or another root key) is detected by neither `list()` nor `generate()`: new keys are sealed to it, and only existing keys fail at `sign()`. No check would stop anyone, because whoever can write the header can already use the root key; protected mode (not built), where a locked vault seals new keys to the stored wrapping public key, must detect it (§11). | `storage › tamper table › a bad record is corrupted at the operation the table names: <case>`, `storage › the edit cases cover every stored field…`, `› a stored label edited, added or removed makes sign fail with corrupted…`, `› changing a field type without changing its value…`, `› a planted key whose public key is not valid for its type…`, `› a planted ed25519 key whose public key is a small-order point is corrupted at list and sign: <case>`, `› a key an attacker sealed…`, `› an off-curve ephemeral public key…`, `› a key record moved to another scope fails closed…`, `storage › secp256k1 › a planted sealed value that is not a valid scalar is corrupted at sign: <case>`, `vault › key records without a vault header are corrupted everywhere…`, `records › foreign records › a record in meta other than the header makes list, generate and sign fail…`, `› wipe recovers a vault with a foreign record in meta…`, `› an object store that is not Vault’s is ignored…` |
| Older storage snapshot restored | Both | — | **Not detected.** A consistent older copy is a valid state: keys deleted since then reappear, keys added since then vanish. IndexedDB is the only store, so there is nowhere to anchor a counter. | not protected |
| Malicious script in the same origin while unlocked | Unprotected | The API never returns private key bytes. Vault keeps no secret in memory between calls. A `Scope` has no path to its `Vault`, so code handed only a `Scope` can't wipe the vault or open another scope. | **Not protected.** The script can sign with every key, and can open the database and use the root key to unwrap every key as extractable, which exfiltrates them. **Scopes group keys; they do not isolate same-origin code:** any same-origin code can call `vault.scope(name)` with any name, or read IndexedDB directly. Keeping other-origin consumers apart is the embedding layer's job (§9). | `src/scope.ts` (no export method), `vault › a Scope has no path to its Vault…` |
| Lost, deleted or replaced passkey (protection passkey) | Protected | Not built yet | | |
| Lost, deleted or replaced passkey (passkey key) | Both | Not built yet | | |
| Secrets in memory | Both | Ed25519 private keys exist only as CryptoKey objects: sealed with `wrapKey`, opened with `unwrapKey` into a non-extractable key, never as JS bytes. Per-key AES keys and the ECDH result stay inside `deriveKey`. A key type that holds secrets in JS buffers erases them once a generated key is stored or abandoned: `generate` calls the type's `erase` on success and on every failure path. secp256k1 zeroes every secret buffer Vault owns: the 48-byte key-generation seed as soon as the scalar is derived from it, the scalar when `erase` runs, and the decrypted scalar when `sign` returns or fails. | **The secp256k1 private key exists as JS bytes during `generate` and `sign`**, and the curve library's internal copies (bigints, hash state) are not zeroed: not protected. JS can't zero memory, and the browser may hold internal copies. A CryptoKey lives until garbage collection. | `src/key-types/ed25519.ts`, `src/key-types/secp256k1.ts`, `src/seal.ts`; `storage › a generated key has its secrets erased once, after it is stored`, `› a generated key has its secrets erased when generate fails: <case>`, `storage › secp256k1 › generate erases the seed and the scalar it owns, also when the write fails`, `› sign erases the decrypted scalar, also when it is rejected` |
| Storage evicted by the browser | Both | An empty database behaves as a new vault. A database deleted while a vault is open (site data cleared, eviction, another tab's `deleteDatabase`) is an empty vault on the next call: `list()` returns `[]` and `generate()` creates a new vault; the application need not reopen it. A key sealed before the deletion is never written next to a missing header: its write fails the header check and `generate` is redone against a new header. | Can't be told apart from a vault that was never used or was wiped; the caller is not told. An evicted protected vault (not built) becomes unprotected on the next `generate()` (§4.4). **Eviction is not protected against:** it loses every sealed key for good. Vault never requests persistent storage; the application decides when to ask (§4.4). | `vault › opening and listing write nothing; the first generate creates the vault`, `vault › a database deleted while the vault is open is an empty vault: list returns no keys and generate creates a new vault`, `› a generate whose key was sealed before the database was deleted is redone: one key, sealed to the new header`, `src/db.ts` `onversionchange`, `src/scope.ts` `#commitKeyRecord` |
| Crash or closed tab mid-operation | Both | Every multi-record change is one IndexedDB transaction, so a crash leaves the old state or the new one. A tab closed while the first `generate` writes its header and key (Chromium, Firefox, WebKit), or a renderer crash at that point (Chromium), cut before the commit leaves no vault, and a fresh page generates anew; cut right after the commit it leaves the header and the key together, and a fresh page lists and signs with the key. A transaction that aborts, even after its body has run, fails the call with `unavailable` and writes nothing. | A whole-browser or OS crash is not tested: not protected. A renderer crash is tested only in Chromium, the one engine Playwright can crash. | `e2e › a tab closed while the first generate writes leaves the old state or the new one, never a mix: <cut>`, `e2e › a renderer crash while the first generate writes… <cut>` (Chromium), `vault › the first generate writes header and key atomically…`, `› a write that aborts at commit…`, `› wipe is one transaction…`, `src/db.ts` `transact` |

### 2.4 Out of scope for the threat model

- A compromised browser or OS, and malicious browser extensions: they see everything the page sees.
- Preventing XSS. Vault limits what injected code gets (§2.3); it doesn't stop the injection.
- Physical and side-channel attacks on the machine or the authenticator.
- Timing side channels in JS. WebCrypto does the secret-dependent work, except for secp256k1, where `@noble/curves` and Vault's scalar check run in JS, which promises no constant time.

## 3. Key protection

### 3.1 Key hierarchy

```
vault wrapping key pair — ECDH P-256, one per vault, in the header record
├─ public half: SPKI, stored in the clear. Sealing a new key needs only this, so adding a key never needs an unlock.
└─ private half
   ├─ unprotected: stored as a non-extractable CryptoKey (usage deriveKey only)
   └─ passkey-protected: not built yet (wrapped under a passkey-derived key; never stored in the clear)

private key (one per key record), sealed by ECIES:
  ephemeral P-256 key pair → ECDH with the wrapping public key → HKDF-SHA-256 (info = both public keys)
  → AES-256-GCM (random 96-bit IV, AAD = every stored field of the record)
  → by key type: ed25519 wrapKey('pkcs8'); secp256k1 encrypt(the raw 32-byte scalar)
```

- **Unprotected mode is protected only by the browser.** The root is a CryptoKey that JS can use but not read. That stops a leaked record dump or log from revealing keys, but not a profile copy or same-origin code (§2.3).
- **Enabling protection (not built yet)** will generate a *fresh* wrapping key pair, re-seal every key to it and replace the header, all in one transaction. Rotating rather than rewrapping matters: a profile copy taken while unprotected, or leftover data the storage engine never overwrote, then can't decrypt keys added after protection is on.
- Exactly one passkey can unlock a vault.

### 3.2 Passkey keys

<!--
How a passkey is modelled as a key. User verification requirement.
Fresh device: how the user presents the passkey and Vault identifies which key it is.
What Vault stores about a passkey key and what it can do without that record.
-->

### 3.3 Primitives and dependencies

| Purpose | Primitive | Source | Why this source |
|---|---|---|---|
| Seal private keys | AES-256-GCM, random 96-bit IV, AAD | WebCrypto | Native in all engines |
| Key agreement for sealing | ECDH P-256, ephemeral–static | WebCrypto | Native. X25519 rejected: WebKit silently drops X25519 CryptoKeys stored in IndexedDB (they read back as `null`). |
| Key derivation | HKDF-SHA-256 over the ECDH output | WebCrypto | Native; done with `deriveKey`, so the shared secret never becomes JS bytes |
| Point validation | SPKI import | WebCrypto | WebKit accepts off-curve points in `raw` and `jwk` import, but every engine rejects them in `spki`: `storage › an off-curve ephemeral public key is rejected…` |
| ed25519 signing | Ed25519 (RFC 8032) | WebCrypto | Native in all three engines; the private key stays a CryptoKey |
| ed25519 verification and public-key check | Ed25519, strict RFC 8032 decoding (`zip215: false`: canonical encodings only, small-order points rejected) | `@noble/curves` 2.3.0 | WebKit's `crypto.subtle.verify` crashes the tab on degenerate public keys (§8); verification handles only public data: `vault › ed25519 › signing with an ed25519 key never calls WebCrypto verify` |
| secp256k1 keys and signatures | ECDSA over SHA-256, RFC 6979, low-S | `@noble/curves` 2.3.0 | No engine's WebCrypto has secp256k1 |
| Key ids | SHA-256 | WebCrypto | Native |
| Randomness | `getRandomValues` (also the secp256k1 seed), `generateKey` | WebCrypto | Native |

**The one third-party cryptographic dependency is `@noble/curves`, for secp256k1 and for ed25519 verification.** No engine's WebCrypto has secp256k1, WebKit's Ed25519 verify crashes on degenerate keys, and Vault does no hand-rolled crypto. It is pinned exactly to 2.3.0, its independently audited release (Trail of Bits, August 2026, full scope, as the Security section of the 2.4.0 README records; 2.3.0's own README predates the audit); the newer 2.4.0 has only AI-assisted self-audits, and its hardening concerns misuse that Vault's calls don't make. Its one dependency, `@noble/hashes`, arrives through its exact pin as 2.3.0. `package-lock.json` carries the integrity hash of both, and `npm audit signatures` verifies their registry signatures. Every option of every call is passed explicitly (`src/key-types/secp256k1.ts`, `src/key-types/ed25519.ts`), so a changed library default can't change what a signature is or which public keys verify.

The sealing construction (`src/seal.ts`) composes native primitives in the shape of HPKE base mode: a one-time key per seal, both public keys in the KDF context, and AEAD with associated data. It is not wire-compatible with HPKE. A value sealed by the v1 code is kept as a known-answer test, `storage › a value sealed by format v1 still opens…`. Any change to the derivation fails that test, even when it alters `seal` and `unseal` alike and every round trip still passes.

## 4. Storage layout

### 4.1 Records

One IndexedDB database (default name `vault`); schema version 1.

| Store / record | Key | Contents | Encrypted | Integrity-bound to |
|---|---|---|---|---|
| `meta` / header | `'header'` | `v`, `wrappingPublicKey` (SPKI), `protection: { kind: 'none', privateKey: CryptoKey }` | The private key is a non-extractable CryptoKey held by the browser | Not integrity-protected (§11) |
| `keys` / key | `[scope, id]` | `v`, `scope`, `id`, `type`, `publicKey`, `createdAt`, `label` (only when given), `sealed: { ephemeralPublicKey (SPKI), iv, ciphertext }` | `ciphertext` only | `id` = SHA-256(scope, type, public key), checked by `list()`. AAD = the domain separator `vault/v1/key`, then `v`, `scope`, `id`, `type`, `publicKey`, `createdAt`, then, only when a label is stored, the parts `'label'` and the label. HKDF binds the ephemeral key and the wrapping public key. |

Scopes are the first component of the key, so one scope is one key range, and a scope has no record of its own: it is there while it holds keys. A scope name is a well-formed string of 1 to 1024 UTF-16 code units, long enough for any origin, compared exactly, without normalisation: `vault › a malformed scope name is a TypeError…`. A label is a well-formed string of 1 to 256 UTF-16 code units, given at `generate` and never changed; labels need not be unique: `vault › labels › …`. A key generated without one has no `label` field at all, in its record or its public information, so its AAD is exactly the v1 bytes and the v1 known-answer tests pass unchanged; the AAD of a labelled record is pinned by `records › format v1 regression › keyAad of a labelled record…`. Records written before scopes existed are in the scope `default`, now an ordinary scope, and list and sign there unchanged: `records › a key record written by the v1 code still lists and signs`. Every hashed or authenticated value goes through one canonical encoding (`src/bytes.ts` `encode`): each part is a type tag, a 4-byte length and its bytes. Strings are UTF-8, bytes only `Uint8Array`, integers only safe non-negative values as 8 bytes big-endian. So field boundaries can't shift, and `123` and `"123"` never encode alike: `storage › each value keeps its type…`. The exact bytes are part of format v1 and pinned by a known-answer test, `storage › encodes the exact v1 bytes…`.

Code layout:
- `src/db.ts`: opening the database, and the transaction helper.
- `src/connection.ts`: the one connection a vault and its scopes share; closing it ends them all.
- `src/storage.ts`: record access inside a transaction, store names, scope ranges. No crypto.
- `src/records.ts`: the format, parsing and validation.
- `src/seal.ts`: sealing.
- `src/scope.ts`: the key operations of one scope (`generate`, `list`, `sign`, `delete`).
- `src/vault.ts`: the vault-wide operations (`open`, `scope`, `wipe`, `close`).

### 4.2 Validation and fail-closed behaviour

| Check | When | Failure |
|---|---|---|
| `v` is the number 1, never coerced (header and key records) | every read | `corrupted`: `storage › a header with format version 2 / '1' / true / undefined…`, `› a bad record is corrupted at the operation the table names: <case>` (v), `› changing a field type…: v as the string '1'` |
| Header fields have their exact types: wrapping public key bytes, a known protection kind, a CryptoKey root. A header key whose value is `undefined` (or `null`, which WebKit returns for an unreadable value) is malformed, not absent. | `list`, `generate`, `sign` | `corrupted`: `records › a malformed header field…`, `vault › a header stored as undefined…`, `storage › a tampered wrapping public key makes generate fail closed…`, `› a bad record is corrupted at the operation the table names: <case>` (header) |
| Key records without a header mean a deleted header, never a new vault: only `wipe()` works | `list`, `generate`, `sign` (`src/storage.ts` `readHeader`) | `corrupted`: `vault › key records without a vault header are corrupted everywhere…` |
| Key record fields have their exact types: a well-formed scope name of 1 to 1024 code units, an id string, a registered type (a malformed type name: empty, uppercase, over 32 characters, not a string), the public key a `Uint8Array` that passes its type's public-key check (ed25519: a canonical 32-byte RFC 8032 encoding of a point not of small order; secp256k1: a 33-byte compressed point on the curve), createdAt a safe non-negative integer, a label (if the field is present at all, even as `undefined`) a well-formed string of 1 to 256 code units, sealed fields `Uint8Array`, a 12-byte IV | `list`, `sign`, without any secret | `corrupted`: `records › a malformed key record field…`, `› a malformed stored label fails list closed…`, `storage › changing a field type…`, `› a negative createdAt…`, `› a planted key whose public key is not valid for its type…`, `› a planted ed25519 key whose public key is a small-order point…` |
| A key type that is a well-formed name (lowercase letters, digits and hyphens, 1 to 32 characters) but not registered was written by a newer build. It is checked right after `v`, before every other field, so a newer type with fields of its own still reads this way. Keys in other scopes, and `wipe()`, are unaffected | `list`, `sign` | `incompatible`: `records › a well-formed key type this build does not know is incompatible…`, `› an unknown key type is checked before the rest of the record…`, `› a key of an unknown type is incompatible at list and sign in its scope…` |
| Id matches the hash of scope, type and public key | `list`, `sign`, without any secret | `corrupted`: `storage › a bad record is corrupted at the operation the table names: <case>` (key record modified: id, type, publicKey; contents exchanged) |
| Ephemeral key imports as a P-256 SPKI, its curve checked (Firefox imports another curve's key) → AES-GCM decrypt with AAD → (secp256k1: the plaintext is exactly 32 bytes and 1 ≤ d < n) → sign → verify against the stored public key | `sign` | `corrupted`: `storage › an off-curve ephemeral public key…`, `› a bad record is corrupted at the operation the table names: <case>` (sign), `› a key an attacker sealed…`, `› decrypting needs the root key…`, `storage › secp256k1 › a planted sealed value that is not a valid scalar…` |
| Only the fields Vault writes: any other own field on the header, its protection, a key record or its sealed part is rejected | `list`, `generate`, `sign` | `corrupted` ("`<record>: unexpected field <name>`"): `records › an unexpected extra field on …`, `› an extra field fails closed through the API…` |
| Only the records Vault writes: `meta` holds the header and nothing else, so a record under any other key is rejected, with or without a header and key records. A later format that adds a `meta` record extends this allow-list, so it never trusts one planted before it. `wipe()` clears it | `list`, `generate`, `sign` (`src/storage.ts` `readHeader`) | `corrupted` ("`meta: unexpected record <key>`", the key written with its kind: `"7"` and `7` differ, bytes in hex): `records › foreign records › a record in meta other than the header makes list, generate and sign fail…`, `› a foreign record in meta is named by its key, with the key’s type: <case>`, `› wipe recovers a vault with a foreign record in meta…` |
| Object stores other than `meta` and `keys` are ignored, at `open` and later: Vault never reads them, so they can't mislead it, and rejecting one would leave a vault that `wipe()`, which clears only Vault's stores, can't recover | never checked | none: `records › foreign records › an object store that is not Vault’s is ignored…` |
| A version-1 database has Vault's stores | `open` | `corrupted`: `vault › a database without Vault stores…` |

Each field is read by a typed reader (`src/records.ts`), and the error names the field that failed, e.g. `Corrupted storage: key.sealed.iv`: `records › a malformed header field… / a malformed key record field…`. The parsers return new objects built from the read values, never the stored object. The typed encoding is a backstop, not a second classified check. If a reader check were ever missing, encoding the field for the id or the AAD throws a `TypeError` and the call fails instead of accepting the record; such a failure is not classified as `corrupted`. Vault never repairs: no code path writes back a record it failed to read. A failed check rejects the whole call, so `list()` fails if any key in the scope is bad. A stored scope name that `vault.scope()` would refuse lies outside every scope's key range, so no call reads it; the parser rejects it anyway (`key.scope`).

### 4.3 Versioning and migration

- One number is both the storage format version and the IndexedDB schema version. Every record also carries `v`.
- A database at a higher schema version fails `open()` with `incompatible`: `storage › a database written by a newer format is rejected with incompatible`. An older build never reads or writes a newer format.
- A record with `v ≠ 1` inside a version-1 database is `corrupted`, not `incompatible`: a legitimate newer format bumps the schema version first, so no Vault build writes such a record.
- Open connections close on `versionchange`, so a newer build is never blocked by an old tab. The old tab's next call then fails with `incompatible`: `storage › an open vault never blocks a newer format…`.
- Format v1 is pinned by regression tests produced by the v1 code: the id and AAD of fixed inputs, and a whole stored key record that must still list and sign (`records › format v1 regression`). The AAD of a labelled record, added before release, is pinned there too, its bytes derived by hand from the encoding.
- A new key type needs no version bump. A build that doesn't know the type reads its records as `incompatible` (reload a newer build), not `corrupted`, because the type is checked before the rest of the record (§4.2). The alternative, a version bump per key type, would make every older build fail `open()` on every vault. Only those records fail, and only in their scope.
- Records are parsed strictly (§4.2), so even an optional new field changes the format. It needs a version bump, or, before release, a change to the allow-list.
- **Migration (not built):** a v2 build opens with schema version 2 and changes structure in the upgrade callback, which is atomic. Re-encryption can't run there, because the callback can't await crypto. So it happens lazily per record, which per-record `v` allows: read a v1 record, re-seal it, write v2 in a normal transaction.

### 4.4 Eviction and persistent storage

An empty database (no header, no keys) behaves as a new vault: `list()` returns `[]` and the first `generate()` creates the vault. Key records without a header are not empty but `corrupted` (§4.2). Vault can't tell "never used", "wiped" and "evicted" apart. Browsers evict an origin's storage as a whole, and IndexedDB is its only store.

A database deleted while a vault is open (site data cleared, eviction, another tab's `deleteDatabase`) is the same empty vault. The open connection closes on `versionchange` so it never blocks the deletion (`src/db.ts`); the next call reopens, which recreates the database at version 1, so `list()` returns `[]` and `generate()` creates a new vault. A `generate` that sealed its key to the old header finds no header in its write transaction and is redone, so no key is ever written without a header (`src/scope.ts` `#commitKeyRecord`). Enforced by `vault › a database deleted while the vault is open is an empty vault: list returns no keys and generate creates a new vault` and `› a generate whose key was sealed before the database was deleted is redone: one key, sealed to the new header`. Rejected: treating the lost connection as terminal and closing the vault; one rule with `wipe()` was chosen instead. Given up: the caller is not told the vault was evicted.

**When protection exists (not built):** an evicted protected vault becomes an empty vault, and the next `generate()` silently creates an unprotected one. The vault will expose its state (empty, unprotected or protected), and an application that expects protection checks it before `generate()`.

**Persistent storage.** Storage is best-effort unless the origin is granted persistent mode, and eviction loses every sealed key for good: there is no backup. Vault never calls `navigator.storage.persist()` (no call in `src/`); the application decides when to ask. The call guarantees nothing in any engine, it sets the storage policy of the whole origin, and in Firefox it prompts, so it is a product and UX decision; an option on `Vault.open` would only wrap one line the application writes itself. Recommended: call it from a user gesture after the first key is generated, when there is something to lose. Rejected: Vault calling it after the first `generate()`, calling it only in engines without a prompt, an opt-in `Vault.open` option, and a `vault.persisted()` method. Given up: an application that never asks keeps best-effort storage.

| Engine | `persist()` |
|---|---|
| Chromium | No prompt; granted or denied silently by heuristics (site engagement, bookmark, installed app) |
| Firefox | Permission prompt |
| WebKit | No prompt; granted by heuristics, mostly to Home Screen web apps |

With tracking prevention on, Safari also deletes script-created data of an origin not visited in 7 days of browser use.

Sources (read 2026-11-11): web.dev/articles/persistent-storage, MDN "Storage quotas and eviction criteria", webkit.org/blog/14403. Unconfirmed: whether persistent mode lifts Safari's 7-day rule, and how Playwright's WebKit answers `persist()`. None of this is tested: not protected.

## 5. Lifecycle and state transitions

```mermaid
stateDiagram-v2
  [*] --> Empty
  Empty --> Unprotected: generate
  Unprotected --> Unprotected: generate, delete
  Unprotected --> Empty: wipe
  Empty --> Empty: list, wipe
  Unprotected --> Corrupted: header deleted or tampered (by a storage writer)
  Corrupted --> Empty: wipe
```

"Wiped" is the state Empty, and there is no separate state. Protected, locked and unlocked arrive with passkey protection. States belong to the vault as a whole, never to one scope. `close()` ends one instance and every scope taken from it (every later call throws `InvalidStateError`); the stored state doesn't change.

| From | Operation | To | Prompts | Atomic how | On failure |
|---|---|---|---|---|---|
| Empty | `generate` | Unprotected | none | Header and key added in one transaction; the header is added only if still absent and no key record exists. Two first `generate` calls converge on one header: `concurrency › concurrent first-time setup › a first generate held while another context runs its first generate…`; `e2e › concurrent first generates from two tabs converge on one vault…` (Chromium, Firefox, WebKit) | Nothing written: `vault › the first generate writes header and key atomically…` |
| Corrupted (key records without a header) | `list`, `generate`, `sign` | Corrupted | none | — | `corrupted`; only `wipe` leads out |
| Unprotected | `generate` | Unprotected | none | One transaction re-checks the header and adds the key; against a wiped header it adds nothing and redoes: `concurrency › a stale context against a wipe › a generate held while another context wipes…`; `e2e › a generate held in one tab while another tab wipes…` (Chromium, Firefox, WebKit) | Nothing written: `vault › a write that aborts at commit…` |
| Unprotected | `delete` | Unprotected | none | One request | Nothing deleted |
| Any | `wipe` | Empty | none | Both stores, every scope, cleared in one transaction: `vault › wipe removes the keys of every scope and the header in one transaction` | Nothing cleared: `vault › wipe is one transaction…` |

### 5.1 Enabling protection

<!-- Steps, the single commit point, where the second prompt happens and on which browsers, what is left after a cancel or crash. -->

### 5.2 Unlock and lock

<!-- At most one prompt. What lives in memory after unlock and for how long. What "closed" means. Unlocked state never persisted. -->

### 5.3 No downgrade

<!-- Why a protected vault can never become unprotected: after a failed unlock, a cancelled prompt, a deleted record, a tampered record. Link the tests. -->

### 5.4 Wipe

`wipe()` clears the header and every key of every scope in one transaction: `vault › wipe removes the keys of every scope…`, `vault › wipe removes every key and the vault header; the next generate starts a new vault`. The next `generate()` creates a new wrapping key pair, so nothing sealed before the wipe can be opened afterwards. `generate` re-reads the header inside its write transaction, so a key sealed to the wiped vault can't land: `concurrency › a stale context against a wipe › a generate held while another context wipes…`, `e2e › a generate held in one tab while another tab wipes…`. After a wipe, another context lists none of the old keys, and `sign` with an old `KeyInfo` fails with `not-found`: `concurrency › a stale context against a wipe › after a wipe in one context, the other lists none of the old keys…`. Wipe doesn't erase what the storage engine has not yet overwritten on disk.

## 6. Concurrency and crash safety

A transaction ends once control returns to the event loop with no request pending. Awaiting a request's promise continues in a microtask and keeps it alive. But in Firefox and WebKit, an await that settles in a later task, `crypto.subtle` included, ends it (Chromium happens to keep it). So all crypto runs **before** a transaction, and the transaction only checks and writes (`src/db.ts` `transact`; for a new key, `src/scope.ts` `#prepareKeyRecord` then `#commitKeyRecord`).

| Requirement | Mechanism | Verified by |
|---|---|---|
| Multi-record changes are atomic, also when the tab closes or crashes mid-write | One transaction per change; a throwing body aborts it, and a transaction cut off by a closed tab or a crashed renderer never commits | `vault › the first generate writes header and key atomically…`; `e2e › a tab closed while the first generate writes…` (Chromium, Firefox, WebKit), `e2e › a renderer crash while the first generate writes…` (Chromium) |
| No lost updates | Readwrite transactions on overlapping stores run one at a time across tabs. Each key is its own record: `generate` adds one and `delete` removes one, so writes from two tabs never overwrite each other. `generate` re-reads the header inside its write transaction and adds only if the header is the one it sealed to; otherwise it redoes the whole operation. It tries 3 times in total, then fails with `unavailable`. | `src/scope.ts` `#commitKeyRecord`, `untilUnchanged`; `concurrency › no lost updates › a generate held while another context generates in the same scope…`, `› a generate held while another context generates in another scope…`, `› a generate held while another context deletes a key of its scope…`; `e2e › concurrent generates from two tabs each store their key, which lists and signs in both tabs` (Chromium, Firefox, WebKit) |
| Concurrent first-time setup converges | The header is added only if absent, inside the write transaction; the loser redoes against the winner's header, without an error | `src/scope.ts` `#headerForWrite`, `#commitKeyRecord`; `concurrency › concurrent first-time setup › a first generate held while another context runs its first generate…`; `e2e › concurrent first generates from two tabs converge on one vault…` (Chromium, Firefox, WebKit) |
| A call in flight across `close()` | A vault and its scopes share one connection (`src/connection.ts`), taken right before each transaction, after re-checking `close()` | `vault › a call in flight when the vault is closed fails with InvalidStateError…`, `› scope() after close() throws InvalidStateError…` |
| A stale context can't undo a wipe | As above: a write sealed to a wiped header fails its check and is redone, so a `generate` that read its header before the wipe creates a new vault holding only its new key. No path puts a wiped key back. A `sign` that read its key before the wipe may still return its signature after `wipe()` has resolved in another context; it is ordered before the wipe, and a later `sign` with that key fails with `not-found`. Vault doesn't re-read the key after signing (one more transaction per sign, and still a race) and doesn't check and clear again after a wipe (that would delete keys another context wrote after the wipe, a lost update). | `src/scope.ts` `#commitKeyRecord`, `untilUnchanged`; `concurrency › a stale context against a wipe › a generate held while another context wipes…`, `› after a wipe in one context, the other lists none of the old keys…`; `e2e › a generate held in one tab while another tab wipes…` (Chromium, Firefox, WebKit) |
| Other contexts learn about changes | Not built yet | |

## 7. Public API

### 7.1 Surface

```ts
class Vault {
  static open(options?: { name?: string }): Promise<Vault>;
  scope(name: string): Scope;                          // synchronous, no I/O
  wipe(): Promise<void>;                               // every scope
  close(): void;                                       // ends every scope too
}
interface Scope {
  readonly name: string;
  generate(type: KeyTypeName, options?: { label?: string }): Promise<KeyInfo>;   // never prompts
  list(): Promise<KeyInfo[]>;                          // this scope only, oldest first, never prompts
  sign<K extends KeyInfo>(key: K, data: Uint8Array): Promise<Signature<K['type']>>;
  delete(key: KeyInfo): Promise<void>;                // missing key: no-op
}
type KeyTypeName = 'ed25519' | 'secp256k1';
// One member per key type, derived from the registry:
type KeyInfo = { id: string; scope: string; type: KeyTypeName; publicKey: Uint8Array; createdAt: Date; label?: string };
type Signature<T extends KeyTypeName = KeyTypeName> = { type: T; bytes: Uint8Array };   // the member for T
class VaultError extends Error { code: VaultErrorCode; retryable: boolean }
```

How the types prevent misuse: every key operation is a method of a `Scope`, so a key operation without a scope can't be written. A `Scope` exposes its name and the four key operations, nothing vault-wide, and its name can't be reassigned: `vault › a Scope has no path to its Vault…`. `generate` accepts only registered key type names. `sign` and `delete` take the key's public information as `generate` or `list` returned it, so an application never handles ids by hand, and `sign` returns the signature member of the key's type: `vault › the type of a signature follows the type of the key passed to sign`. Vault trusts nothing in that argument: it reads only the id, scope and type, and reads the key itself from storage, so an edited public key, creation time or label changes nothing: `vault › keys › only the id, scope and type of the argument count…`. No method changes a label: no `Scope` method but `generate` takes one (`src/scope.ts`), and `sign` and `delete` ignore the label of their argument. A malformed label or options argument is a `TypeError`, thrown before anything is generated or written: `vault › labels › a malformed label or options argument is a TypeError…`. At run time any object with these three fields works, a structured clone included: `vault › keys › sign and delete take the public information as returned…`. A key passed to a scope it doesn't belong to is a `TypeError`, and the key is neither signed with nor deleted: `vault › scopes › a key passed to another scope is a TypeError…`. `Signature` is a union discriminated by `type`, so a key type with a different signature shape (a passkey assertion) is another member, not a breaking change. There is no method that returns private key material.

### 7.2 Usage examples

```ts
import { Vault, VaultError } from 'vault';

const vault = await Vault.open();
const keys = vault.scope('https://app.example');       // a group of keys; no I/O
const key = await keys.generate('ed25519', { label: 'Payments' });   // { id, scope, type, publicKey, createdAt, label }
const list = await keys.list();                        // this scope's keys only

const data = new TextEncoder().encode('hello');
const signature = await keys.sign(key, data);          // pass the KeyInfo itself; signature.type is 'ed25519'

// Anyone with the public key verifies, without Vault:
const publicKey = await crypto.subtle.importKey('raw', key.publicKey, 'Ed25519', false, ['verify']);
await crypto.subtle.verify('Ed25519', publicKey, signature.bytes, data);   // true

const k1 = await keys.generate('secp256k1');           // publicKey: 33-byte compressed SEC1 point
const k1Signature = await keys.sign(k1, data);         // 64 bytes r ‖ s; verify with OpenSSL, `dgst -sha256`

// Kept only an id? Find its key first:
const saved = (await keys.list()).find((k) => k.id === savedId);
if (saved) await keys.delete(saved);
await vault.wipe();                                    // every scope

try {
  await keys.sign(key, data);
} catch (e) {
  if (e instanceof VaultError && e.code === 'not-found') { /* … */ }
}
```

### 7.3 Errors

All failures are `VaultError` with a `code`; `retryable` is true only for `unavailable`, and the underlying error is in `cause` (`src/errors.ts`).

| Situation | Error type | Retryable | Caller should |
|---|---|---|---|
| Infrastructure fault: IndexedDB, or a key generation WebCrypto rejected | `unavailable` | yes | Retry; check quota or storage access if it persists. A read that fails every time, from a database damaged at the engine level, is `unavailable` too; `wipe()` is the way out (§11). `vault › an IndexedDB failure is reported as retryable unavailable…`, `› a transient key generation failure is retried; a persistent one is retryable unavailable` |
| Corrupted or tampered storage | `corrupted` | no | Stop using the vault and tell the user; Vault doesn't repair. `wipe()` is the way back (for a database that isn't Vault's, delete it). §4.2 tests |
| Storage written by a newer build: a newer format, or a key type this build doesn't know | `incompatible` | no | Reload with the newer build. `storage › a database written by a newer format…`, `records › a key of an unknown type is incompatible at list and sign in its scope…` |
| Prompt declined or cancelled | Not built yet | | |
| Vault locked | Not built yet | | |
| Key not found, including the id of a key of another scope | `not-found` (`delete`: no-op) | no | Refresh the key list. `vault › signing with an unknown key id fails with not-found`, `› the id of a key of another scope is not-found by sign…`, `› delete removes only that key, and deleting a missing key is a no-op` |
| Passkey protection unsupported | Not built yet | | |

Programming errors are not `VaultError`. Use after `close()`, including a call still in flight when it closed, throws a `DOMException` `InvalidStateError`, as IndexedDB does: `vault › a closed vault rejects every call`, `› a call in flight when the vault is closed…`. So does `scope()` after `close()`: `vault › scope() after close() throws InvalidStateError…`. A malformed scope name (empty, longer than 1024 code units, not a string, a lone surrogate) throws `TypeError`, so a bug can't create a scope that nothing can address: `vault › a malformed scope name is a TypeError…`. An unknown key type name passed from JavaScript throws `TypeError`: `vault › an unknown key type is a programming error…`. So does `sign` with `data` that is not a `Uint8Array`. Coercing it would be worse, because `new Uint8Array('hello')` is empty and would be signed as the empty message: `vault › sign rejects data that is not a Uint8Array…`. `sign` and `delete` throw `TypeError` for an argument that is not an object with a string id (an id string alone, the S1 call, included): `vault › keys › an argument that is not an object with a string id…`; for a key of another scope: `vault › scopes › a key passed to another scope is a TypeError…`; and for a type that differs from the stored key's, and then nothing is deleted: `vault › keys › an argument whose type differs from the stored key…`. `delete` reads the stored type without parsing the record (parsing needs crypto, which would end its transaction), so a record whose type is not a registered name is deleted like any other: `storage › integrity › delete removes a record whose stored type was tampered with`.

### 7.4 Prompts and user gestures

<!-- Which operations may prompt. How each can be called directly from a gesture handler without earlier async work consuming the gesture. -->

### 7.5 Adding a key type

A new sealed key type is one module in `src/key-types/` that implements `KeyType`, and one entry in the `keyTypes` registry (`src/key-types.ts`). Nothing in the core changes: `KeyTypeName`, `KeyInfo` and `Signature` gain its member from the registry, and the core reaches type-specific behaviour only through the interface. A test reads the source of every other file in `src/` and fails if one names a registered key type: `key-types › no core file names a registered key type`. Every test about keys runs once per registered type, from one table of type-specific inputs in `test/unit/helpers.ts`.

```ts
interface KeyType {
  isPublicKey(bytes: Uint8Array): boolean;   // run by list() on every stored key, without any secret
  generate(): Promise<GeneratedKey>;
  sign(sealed: Uint8Array, cipher: Cipher, data: Uint8Array): Promise<Uint8Array>;
  verify(publicKey: Uint8Array, signature: Uint8Array, data: Uint8Array): Promise<boolean>;
}
interface GeneratedKey {
  publicKey: Uint8Array;
  seal(cipher: Cipher): Promise<ArrayBuffer>;
  erase(): void;   // called once the key is stored or abandoned, on every path of generate
}
```

| Key type | Public key | Signature |
|---|---|---|
| `ed25519` | 32 bytes, canonical RFC 8032 encoding of a point not of small order | 64 bytes, RFC 8032, over the exact bytes passed to `sign` |
| `secp256k1` | 33 bytes, compressed SEC1 point, checked to be on the curve | 64 bytes r ‖ s: ECDSA over SHA-256 of the bytes passed to `sign`, RFC 6979 nonces, low-S, no recovery id |

The core hands the type an AES-GCM key bound to the record (`Cipher`), and the type decides how its private key is sealed: ed25519 uses `wrapKey` (`src/key-types/ed25519.ts`), so it has no secret buffer to erase. secp256k1 encrypts its raw 32-byte scalar with `encrypt` and erases it (`src/key-types/secp256k1.ts`); the type name means exactly this scheme, and another scheme on the curve would be another type.

secp256k1 is pinned by known answers. A published deterministic-ECDSA vector (bitcoinjs-lib's `ecdsa.json`, private key 1) is reproduced exactly through the public API, from a record planted with that private key: `storage › secp256k1 › a published deterministic-ECDSA vector is reproduced exactly`. A stored secp256k1 record lists and gives a fixed signature: `records › format: secp256k1 known answer › a stored secp256k1 key record lists and gives the expected signature`. Every signature is low-S, checked with plain integer arithmetic, not the curve library: `vault › every secp256k1 signature is low-S, checked without the curve library`. OpenSSL verifies a demo signature in Node: `e2e › demo creates, lists, signs, deletes and wipes keys of each type…`.

The claim holds for sealed key types only: the core may assume that every key record has a sealed part and every signature is a type name with bytes. Passkey keys have neither, so adding them widens the interface and changes the core once. An older build reads a record of a type it doesn't know as `incompatible`, so adding a type needs no version bump (§4.3). Registered names are well-formed for this: `key-types › every registered key type name is well-formed…`.

## 8. Browser support and degradation

Storage and crypto facts this design depends on, measured in the engines Playwright 1.64.1 ships (Chromium 156, Firefox 157, WebKit 27.2):

| Fact | Chromium | Firefox | WebKit | Consequence |
|---|---|---|---|---|
| Ed25519, ECDH P-256, HKDF, AES-GCM `wrapKey`/`unwrapKey` | ✓ | ✓ | ✓ | All crypto is WebCrypto, except secp256k1 and ed25519 verification |
| secp256k1 in WebCrypto | ✗ | ✗ | ✗ | secp256k1 runs on `@noble/curves` (§3.3) |
| `Uint8Array.prototype.toBase64` with the `base64url` alphabet (ES2026) | ✓ | ✓ | ✓ | Key ids use it; older engines without it are not supported |
| X25519 CryptoKey survives IndexedDB | ✓ | ✓ | ✗ (reads back `null`) | P-256 for the wrapping key |
| Off-curve P-256 point rejected by `raw` / `jwk` import | ✓ | ✓ | ✗ | Points are imported only as SPKI |
| Transaction survives an await that settles in a later task (`crypto.subtle`) | yes | no | no | Crypto never runs inside a transaction |
| Transaction survives a microtask await (a request's promise) | yes | yes | yes | Transaction bodies await request promises |
| `generateKey('Ed25519')` always succeeds | ✓ | ✓ | ✗ (about 0.7% `OperationError`; no generated key has a leading zero byte) | Retried up to 5 times: `vault › a transient key generation failure is retried…`; a manual probe (not in the suite) ran 1000 generates in a row in every engine without failure |
| Ed25519 `verify` with a degenerate public key (identity point, small y) returns `false` | ✓ | ✓ | ✗ (the page's process crashes) | Vault never calls `crypto.subtle.verify`: ed25519 verifies on `@noble/curves` (§3.3), and `list()` rejects small-order and non-canonical keys before any verify; any other degenerate key reaches only noble's verify: `vault › ed25519 › signing with an ed25519 key never calls WebCrypto verify`, `storage › a planted ed25519 key whose public key is a small-order point…` |

These WebKit facts come from Playwright's WebKit on Linux. Safari on macOS was not checked.

<!-- Passkey features: where PRF at create vs get, UV and discoverable credentials degrade; what Vault detects up front and what only on failure. -->

## 9. Embedding for other origins (not built)

Scopes are what an embedding layer builds on: it chooses the scope from the sender's origin, which is why a scope name holds up to 1024 code units. The layer itself is not described yet.

<!-- Popup or iframe: the choice, why, and what we give up (storage partitioning, gesture/permission policy, messaging protocol). -->

## 10. Alternatives considered and rejected

| Topic | Chosen | Rejected | Why | Given up |
|---|---|---|---|---|
| Key hierarchy | ECIES (P-256) to a vault wrapping key pair; unprotected root = the non-extractable private half; protection rotates the key pair | X25519 with an AES "device key" wrapping the private half, protection rewraps only the header | A stable key pair means a profile copy taken while unprotected decrypts keys added after protection | A protection upgrade that re-seals every key and must redo on a concurrent add |
| | | RSA-OAEP-3072 with native `wrapKey` (OAEP label as AAD) | Key generation measured at 150–620 ms, 384 B per sealed key, padding-oracle class | A construction composed of several native calls instead of one |
| | | One symmetric vault key | Can't seal a new key while locked | — |
| Key id | SHA-256 of scope, type and public key | Random UUID | A derived id lets `list()` catch an edited public key, type or scope without any secret, and gives a passkey the same id on every device | One hash per key on `list()`; 43-character ids |
| Associated data | Every stored field of the key record, plus verifying each signature before returning it | Identity fields only, labels outside | Any edit fails closed; the verify catches a substituted key that decrypts cleanly | Labels are immutable after generate |
| Labels | An optional string label, fixed at generate, in the AAD only when present (after the v1 fields, tagged), so unlabelled records keep their v1 bytes | A label plus JSON metadata stored as its exact text; labels outside the AAD for every type (renamable later, never authenticated) | The task asks for a label or metadata; least code; an edit is detected wherever a secret exists | Structured metadata; renaming a key |
| Versioning | Schema version = format version, and `v` in every record | Version in the header only | Re-encrypting migrations can't run in the upgrade callback; per-record versions let them run lazily | One field per record |
| Concurrency | Crypto first, then one transaction that re-checks the header | Web Locks around read → crypto → write | IndexedDB alone gives atomicity and serialization; no lock is ever held across a passkey prompt | Crypto is wasted on a conflict |
| `sign` and `delete` argument | The key's public information (`KeyInfo`, carrying its scope); Vault reads id, scope and type and re-reads the record | `sign(id, data)`, `delete(id)` | With opaque hashed ids, `sign(id)` can't tell a passkey key without reading IndexedDB first, which spends the user gesture (S5); the signature type follows the key type; a key used through the wrong scope is a loud error | A caller who kept only an id calls `list()` first |
| secp256k1 scheme | ECDSA over SHA-256 of the data, RFC 6979 nonces, low-S, 64-byte r ‖ s; verify after sign | ECDSA over a caller-supplied 32-byte digest plus a recovery id; BIP-340 Schnorr; hedged nonces | Same shape as ed25519 (it signs the message); OpenSSL verifies it; determinism allows known answers, and verify-after-sign withholds a faulted signature, which is what hedged nonces defend against | Not directly usable where a protocol fixes another digest (Ethereum keccak, Bitcoin double SHA-256) or needs a recovery id |
| secp256k1 library | `@noble/curves` 2.3.0, pinned exactly | 2.4.0, the latest | 2.3.0 is the most recent independently audited release | 2.4.0's misuse hardening, which Vault's calls don't need |
| `sign` result | Union discriminated by `type` | Bare `Uint8Array`; key handles with methods | Passkey assertions need more than signature bytes; handles go stale across tabs | Callers narrow on `type` |
| Scopes | `vault.scope(name)` returns a `Scope` with the key operations; `Vault` keeps `open`, `scope`, `wipe`, `close`; all scopes share one connection and wrapping key pair | A `scope` option on every call, defaulting to `'default'` | A call that forgets its scope could be written, and would silently use the shared default; code handed a vault can always wipe it | Two classes instead of one |
| | | One scope per `Vault.open()` | Each instance would need its own unlock once protection exists, or a hidden global shared between instances | — |
| | | Scopes as isolation (a secret or a database per scope) | Same-origin code reads all of IndexedDB anyway; isolation between origins belongs to the embedding layer | Wipe and, later, protection are vault-wide |
| Errors | One `VaultError` with `code` | A subclass per category | Exhaustive `switch`; one export; `instanceof` fails across realms. A string code is easy to send in a message (structured clone keeps neither `code` nor a subclass, so an embedding layer sends `{ code, message }`). | No `instanceof` per category |
| Lifecycle | The vault is created by its first write; wipe empties it for every instance | Eager creation in `open()`; wipe closes every instance | Reads never write; one rule for wipe | "Wiped" and "never used" are the same state |
| Keys without a header | `corrupted` in `list`, `generate`, `sign`; only `wipe` recovers | Keep listing them; create a fresh header next to them | A fresh header would turn a deleted protected header into an unprotected vault | A writer who deletes only the header makes the vault unusable until `wipe` |
| Field types | Checked on every read, plus a typed canonical encoding | Leave type checks for later; numbers as `String()` | A type change with the same encoding (`"123"` for `123`, an `Array` for bytes) passed both the id and the AAD | — |
| Unknown fields | Rejected as `corrupted` (an allow-list per record part) | Ignore them | Vault writes the exact shape, so an extra field is tampering or a foreign format; a newer format already fails on `v`; an ignored field could carry data a later build would trust | No forward-compatible extra fields without a version bump |
| WebKit's failing Ed25519 key generation | Retry up to 5 times, then `unavailable` | Classify at once and let every caller retry | Generation has no side effects; 5 failures in a row ≈ 10⁻¹¹ | An engine workaround in the key type |
| WebKit's crashing Ed25519 verify | Verify with `@noble/curves` in strict RFC 8032 mode; sign stays in WebCrypto; `list()` applies the same strict decoding | Keep WebCrypto verify and document the tab crash; compare a public key derived via JWK export | noble's verify is pure JS and never reaches WebKit's crashing verify, so a planted degenerate key fails with `corrupted` in every engine; the dependency is already there for secp256k1; JWK export would put private key bytes in JS memory on every sign | Native-only ed25519; noble's ed25519 and SHA-512 code in the bundle |

## 11. Known limitations

- **Unprotected mode doesn't protect against a profile copy or same-origin code** (§2.3). That is what passkey protection is for.
- **A writer who deletes only the header makes the vault `corrupted` until `wipe()`**, by design (§4.2).
- **An evicted vault can't be told from one never used or wiped** (§4.4): a database deleted while open is an empty vault on the next call, and the caller is not told. Once protection exists, an evicted protected vault becomes empty and the next `generate()` creates an unprotected one, so an application that expects protection checks the vault's state first.
- **WebKit's Ed25519 key generation fails about 0.7% of the time**; Vault retries it. Not checked in Safari on macOS.
- **Adding a stored field is a format change** (strict parsing): a build that doesn't know the field reports such records as `corrupted`.
- **Header replacement is not protected in unprotected mode.** A writer who replaces the header with their own wrapping key pair makes existing keys fail at `sign()` (`corrupted`), and gets new keys sealed to their key. Neither `list()` nor `generate()` notices: `storage › tamper table › a bad record is corrupted at the operation the table names: <case>` (header modified, swapped). Vault adds no check (a wrapping key pair consistency check, a header fingerprint in key records, a header MAC), because none stops anyone: whoever can write the header can already use the root key, a fingerprint is rewritten along with the header, and a MAC needs a secret that exists only with protection. Constraint for protection (not built): a locked vault seals new keys to the stored wrapping public key without any secret, so the protected design must say how a replaced protected header is detected (for example at unlock) and which keys added after the replacement are exposed.
- **A database damaged at the engine level reads as retryable `unavailable`**, like every IndexedDB error, including a quota error and a read that fails every time: one error doesn't tell a transient fault from lost data, error names differ across engines, and no test can produce a genuinely damaged database file. The way out is `wipe()`, which loses every key (§7.3). A quota error and a damaged database are not tested: not protected.
- **Persistent storage is not requested** (§4.4): the application decides when to ask, and until it does, eviction can lose every sealed key.
- **One bad record fails all of `list()`** for its scope (fail closed).
- **A record planted with a made-up key type name reads as `incompatible`, not `corrupted`**: a well-formed name this build doesn't know can't be told from a newer build's type. It still fails closed (§4.2).
- **Other contexts are not notified of changes (#55).**
- **A `sign` in flight across a wipe in another context may still return its signature** after `wipe()` has resolved there (§6): the signature is ordered before the wipe.
- **Scopes group keys; they do not isolate same-origin code** (§2.3). Any same-origin code can open any scope.
- **The scopes of a vault can't be listed, and one scope can't be cleared on its own**: `wipe()` is vault-wide, and a scope's keys go one `delete` at a time.
- **`sign` and `delete` take a key's public information, not an id**: a caller who kept only an id calls `list()` first and passes the matching `KeyInfo`.
- **The secp256k1 private key exists as JS bytes during `generate` and `sign`.** Vault zeroes the buffers it owns; the curve library's internal copies are not zeroed (§2.3).
- **secp256k1 signs SHA-256 of the data and returns no recovery id**, so it is not directly usable where a protocol fixes another digest or needs a recovery id.
- **A label can't be renamed**: it is bound into the AAD, so a new label means a new key.
- **There is no metadata beyond the label.**
- **Label spoofing is not prevented** (§2.3): a storage writer can add a key with any label, and `list()` shows an edited label until the key is used. Callers that need assurance pin key ids.
