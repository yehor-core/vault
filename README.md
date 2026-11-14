# Vault

A browser-native private-key store on top of IndexedDB: ed25519, secp256k1 and passkey keys in named scopes, encrypted at rest, in a vault that is unprotected or passkey-protected. Design: [DESIGN.md](DESIGN.md).

> Status: S7 done.

## Demo

Live at https://yehor-core.github.io/vault/ (`.github/workflows/pages.yml` deploys it on every push to `main`); `npm run demo` serves the same page locally. In one fixed scope, `demo`, it generates keys of each type, adds an existing passkey, lists, signs and verifies each signature outside Vault, deletes, protects, unlocks, locks and wipes, and shows `vault.state()`. Passkeys made on the Pages demo and on localhost are different credentials (relying-party ids `yehor-core.github.io` and `localhost`).

### Signing with a passkey key in a fresh profile

1. Open the demo, pick Key type `passkey`, click Generate key, and create the passkey on an authenticator that carries across profiles (below).
2. Click the new row's Sign: Last signature shows the key's `public key` and ends with `verified   true`.
3. Open a fresh browser profile (Chrome: profile menu → Add; Firefox: `about:profiles` → Create a New Profile; Safari: Settings → Profiles → New Profile) or another browser, and open the demo there. State is `empty`.
4. Click Add existing passkey and pick the same passkey in both prompts: Vault needs two signatures to recover the public key. A `passkey` row appears with the id and credential id of step 1.
5. Click its Sign: the `public key` is the one of step 2, and `verified   true` is checked by the page with WebCrypto, without Vault (`demo/main.ts` `verifyAssertion`). The suite checks the same in all three engines: `e2e › a passkey moved to a new browser context with an empty vault is added there with the same id and public key, then signs`.

A passkey reaches a fresh profile only if its authenticator is there too: a security key works in every profile and browser it is plugged into; iCloud Keychain passkeys belong to the Mac, so every browser on it can use them; a passkey saved in one browser profile's own password manager may stay in that profile.

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
| `npm run demo` | Serves the demo at http://localhost:5173 |
| `npm run build:demo`, `npm run preview:demo` | Builds the published demo into `demo-dist/` under `/vault/`, and serves it at http://localhost:4173/vault/ |
| `npm test` | Script tests, then unit tests in Chromium, Firefox and WebKit, then e2e |
| `npm run test:unit`, `test:e2e`, `test:scripts` | One suite: Vitest Browser Mode in the three engines (`test/unit`); Playwright against the demo in the three engines, plus a smoke test of the production build (`test/e2e`); Node tests of the repository's scripts |
| `npx vitest run <file> -t '<name>' --project chromium` | One unit test in one engine |
| `npm run typecheck`, `lint`, `format:check`, `check:refs`, `check:casts`, `check:decisions` | The checks CI runs; `check:refs` fails if a test or code name cited in DESIGN.md or README.md doesn't exist |

## Browser support

Needs WebCrypto Ed25519, ECDH P-256, HKDF and AES-GCM, IndexedDB and `Uint8Array.prototype.toBase64`, in a secure context. Where passkey features degrade: [DESIGN.md §5.6](DESIGN.md#56-where-passkey-features-degrade).

| Engine (Playwright 1.64.1) | Unit + e2e suites | Passkey and protection paths |
|---|---|---|
| Chromium 156 | ✓ | ✓ unit + e2e, against the engine's own WebAuthn through a CDP virtual authenticator, the only one that returns PRF results |
| Firefox 157 | ✓ | Passkey keys: e2e on the stand-in. Protection, a declined prompt, no user verification: by hand |
| WebKit 27.2 | ✓ | As Firefox; Playwright's WebKit on Linux has no WebAuthn, so `protectionSupport()` is `unsupported` there |

The stand-in is Playwright's JavaScript replacement for `navigator.credentials` (`test/e2e/passkeys.ts`): it always answers ES256 with user verification, so it can't decline, drop user verification or return a PRF result, and checks no user activation.

**By hand:** Safari 18.6 and 27.2 and Firefox 160 on one Mac, with an iPhone over hybrid and a YubiKey, following [docs/manual-checks.md](docs/manual-checks.md). [DESIGN.md §3.2](DESIGN.md#32-enabling-protection) has the result per browser and authenticator, with its Runs. The three faults of Vault these runs found: #108, #110, #111. Not checked by hand: Windows, Linux, Android, iOS; Chromium with real authenticators; iCloud Keychain on the Mac itself; a security key with `prf` or `hmac-secret-mc`; several passkey keys in one scope; deleted or tampered records.

## Property → test

One row per property `docs/TASK.md` requires (Required properties, and the Evaluation table's hard properties, marked **Hard**), with the one or two tests that decide it and their engines. The threat-model cases are in [DESIGN.md §1.2](DESIGN.md#12-adversaries-and-guarantees), each with its test.

Test references: `<name> ›` cites `test/unit/<name>.test.ts`, `e2e ›` cites `test/e2e/`; a middle segment names the `describe` group. Unit tests run in Chromium, Firefox and WebKit, except `passkey ›` and `protection ›` tests that need a virtual authenticator: Chromium only. "All three" is Chromium, Firefox and WebKit; "Runs" are the Run log entries of `docs/manual-checks.md`. Each cited test was break-checked: the code it guards was broken once and the test went red in every engine its row lists. Exceptions: the user-handle break turns the several-passkey-keys e2e test red only in Chromium (the stand-in never overwrites a passkey); not break-checked, as functional checks: the "runs in" platform row, `vault › keys › keys survive closing and reopening the vault`, and the closed-tab row's "after commit" cut. Every error test asserts the `retryable` flag (`test/unit/helpers.ts` `expectVaultError`).

### Keys

| Property | Test | Engines | Code |
|---|---|---|---|
| Generate keys of a chosen type inside the vault | `vault › keys › a generated key is listed with its public information` (ed25519, secp256k1); `e2e › a passkey key generated in the page signs, and its assertion verifies outside Vault under the returned public key` | All three (passkey: stand-in in Firefox and WebKit) | [Test](test/unit/vault.test.ts#L36), [Test](test/e2e/passkey.spec.ts#L25) |
| List keys and read their public information (id, type, public key, label) without unlocking | `vault › labels › a label given at generate is stored and carried by the public information; without one there is no label field`; `protection › after protect › another instance is locked: sealed sign fails with locked; generate, list, add, passkey sign and wipe work` | All three; locked: Chromium | [Test](test/unit/vault.test.ts#L169), [Test](test/unit/protection.test.ts#L585) |
| Sign with a key; anyone verifies under its public key without Vault; private key material never leaves the vault | `vault › keys › a signature verifies under the public key without Vault`; `storage › encryption at rest › no private key bytes are stored: only ciphertext and a non-extractable root key` | All three | [Test](test/unit/vault.test.ts#L49), [Test](test/unit/storage.test.ts#L573) |
| Delete a single key, and wipe the whole vault | `vault › keys › delete removes only that key, and deleting a missing key is a no-op`; `vault › scopes › wipe removes the keys of every scope and the header in one transaction` | All three | [Test](test/unit/vault.test.ts#L84), [Test](test/unit/vault.test.ts#L285) |
| Named scopes serve independent consumers (the demo uses one scope, `demo`) | `vault › scopes › keys generated in one scope are listed only there, and an unused scope lists nothing`; `vault › scopes › the id of a key of another scope is not-found by sign and untouched by delete` | All three | [Test](test/unit/vault.test.ts#L212), [Test](test/unit/vault.test.ts#L251) |

### Passkey keys

| Property | Test | Engines | Code |
|---|---|---|---|
| Several passkeys as keys, each signing on its own | `e2e › several passkey keys in one scope list, and each signs on its own, verifying only under its own public key`; `passkey › generate › the user handle is the scope mark and 16 fresh random bytes, so a second key never overwrites the first` | Chromium; stand-in; no overwrite: Chromium. By hand: one passkey key per run (Runs 1–6b); several in one scope: not checked by hand | [Test](test/e2e/passkey.spec.ts#L37), [Test](test/unit/passkey.test.ts#L234) |
| **Hard:** a passkey key works in a vault that has never seen it, on a fresh device, and Vault tells which key it is | `e2e › a passkey moved to a new browser context with an empty vault is added there with the same id and public key, then signs`; `passkey › add › a passkey key added to a fresh vault is the key generate made…` | Chromium; stand-in. By hand, with real passkeys in a fresh profile, Safari 18.6 and 27.2, Firefox 160 (Runs 1–5, 4b, 6b) | [Test](test/e2e/passkey.spec.ts#L55), [Test](test/unit/passkey.test.ts#L587) |
| Using a passkey key requires user verification, not just presence | `passkey › generate › generate starts the passkey prompt before its first await, with the creation options Vault fixes` (`userVerification: 'required'`); `e2e › Chromium virtual authenticator › a passkey assertion without user verification is unsupported, and sign returns no signature` | Chromium (the stand-in always verifies). By hand: every assertion carried UV; an answer without UV there: not protected | [Test](test/unit/passkey.test.ts#L183), [Test](test/e2e/passkey.spec.ts#L91) |

### Protection

| Property | Test | Engines | Code |
|---|---|---|---|
| **Hard:** turning protection on for a populated vault is atomic: it completes fully or leaves the vault unchanged | `e2e › <how> while protect writes leaves the unprotected vault or the whole protected one, never a mix: <cut>`; `protection › after protect every key signs and verifies as before, under a new wrapping public key; passkey records are unchanged` | Chromium. By hand: a completed `protect()` kept every key (Runs 1, 4b, 5, 6b), a failed one left the vault unchanged (Runs 2, 3) | [Test](test/e2e/crash.spec.ts#L162), [Test](test/unit/protection.test.ts#L216) |
| A second prompt where the browser returns no PRF result at creation; where that happens: [DESIGN.md §3.2](DESIGN.md#32-enabling-protection) | `protection › protect, with no PRF result at creation › protect shows a second prompt for the new passkey only, user verification required, with the fixed PRF input; then every key signs`; `› a vault protected after two prompts unlocks in another instance with one prompt` | Chromium. By hand: one prompt with an iPhone (Runs 1, 1b, 5), two with a YubiKey in Firefox 160 and Safari 27.2 (Runs 4b, 6b) | [Test](test/unit/protection.test.ts#L347), [Test](test/unit/protection.test.ts#L454) |
| **Hard:** unlocking takes one passkey prompt; then every key is usable until the vault is closed, and only passkey keys prompt again | `protection › unlock and lock › after one unlock prompt, sealed keys of every scope sign without a prompt; a passkey key still prompts for itself`; `› lock() and close() lock this instance only: sealed sign fails with locked, after close() InvalidStateError; a new instance is locked` | Chromium. By hand (Runs 1, 1b, 4b, 5, 6b) | [Test](test/unit/protection.test.ts#L708), [Test](test/unit/protection.test.ts#L739) |
| Unlocked state is never persisted: a new instance of the same vault, as after a reload, is locked. A reload itself: not protected | `protection › unlock and lock › lock() and close() lock this instance only: sealed sign fails with locked, after close() InvalidStateError; a new instance is locked` | Chromium | [Test](test/unit/protection.test.ts#L739) |
| **Hard:** no downgrade: not after a failed unlock, a cancelled prompt, or a deleted or tampered record. A header replaced as a whole, or a vault reset to empty, is not detected ([DESIGN.md §3.4](DESIGN.md#34-no-downgrade)): not protected | `protection › unlock and lock › unlock with %s fails with %s; the vault stays protected and locked` (declined prompt, deleted unlock passkey, no user verification, no PRF result); `storage › tamper table, protected header › a bad protected header is corrupted at the operation the table names: <case>` | Chromium. By hand: a failed and a cancelled `unlock()` left the vault locked with every key (Runs 1, 1b, 4, 4b, 5, 6b) | [Test](test/unit/protection.test.ts#L944), [Test](test/unit/storage.test.ts#L760) |
| Browsers and authenticators that can't support protection: detected up front where possible, a clean failure with the vault unchanged on the rest | `protection › protection support › protectionSupport() with $name is $expected, with no prompt and no database opened`; `e2e › with an authenticator that returns no PRF result, protectionSupport is unknown, protect fails with unsupported, and the vault stays unprotected with every key signing` | All three (e2e: stand-in in Firefox and WebKit). By hand (Runs 2, 3) | [Test](test/unit/protection.test.ts#L1239), [Test](test/e2e/passkey.spec.ts#L106) |
| Whether more than one passkey can unlock a vault: one unlock passkey ([DESIGN.md §6](DESIGN.md#6-alternatives-considered-and-rejected)); any other passkey is refused | `protection › unlock and lock › unlock answered by %s fails with not-found and changes nothing, locked or unlocked` | Chromium | [Test](test/unit/protection.test.ts#L826) |
| **Hard:** adding keys without unlocking: a locked vault generates a sealed key with no prompt | `protection › after protect › another instance is locked: sealed sign fails with locked; generate, list, add, passkey sign and wipe work` | Chromium | [Test](test/unit/protection.test.ts#L585) |

### Storage, integrity and concurrency

| Property | Test | Engines | Code |
|---|---|---|---|
| IndexedDB is the only persistent store | `platform › the library stores nothing outside IndexedDB: no Web Storage, cookies, Cache Storage or origin private file system`; `vault › keys › keys survive closing and reopening the vault` | All three | [Test](test/unit/platform.test.ts#L56), [Test](test/unit/vault.test.ts#L60) |
| Everything read from IndexedDB is untrusted: modified, swapped, truncated or malformed records are detected, and Vault fails closed | `storage › tamper table › a bad record is corrupted at the operation the table names: <case>`; `vault › errors › key records without a vault header are corrupted everywhere, never a new vault; only wipe recovers` | All three | [Test](test/unit/storage.test.ts#L718), [Test](test/unit/vault.test.ts#L497) |
| Changes that touch several records are atomic: a crash or closed tab leaves the old state or the new one | `e2e › a tab closed while the first generate writes leaves the old state or the new one, never a mix: <cut>`; `vault › errors › wipe is one transaction: aborted midway, it fails as unavailable and the header and keys remain` | All three | [Test](test/e2e/crash.spec.ts#L189), [Test](test/unit/vault.test.ts#L481) |
| **Hard** (across tabs): no lost updates. No test runs in a frame: frames are not protected | `e2e › concurrent generates from two tabs each store their key, which lists and signs in both tabs`; `concurrency › no lost updates › a generate held while another context deletes a key of its scope…` | All three | [Test](test/e2e/tabs.spec.ts#L37), [Test](test/unit/concurrency.test.ts#L76) |
| **Hard** (across tabs): concurrent first-time setup converges | `e2e › concurrent first generates from two tabs converge on one vault: both keys list and sign in both tabs under the one header` | All three | [Test](test/e2e/tabs.spec.ts#L54) |
| **Hard** (across tabs): a stale context can't undo a wipe or a protection change | `e2e › a generate held in one tab while another tab wipes resolves in a new vault: only its new key lists and signs in both tabs, under a new header`; `protection › protection across instances › a generate held while another instance protects is redone against the protected header, and its key signs after unlock` | All three; protection: Chromium | [Test](test/e2e/tabs.spec.ts#L73), [Test](test/unit/protection.test.ts#L1133) |
| **Hard** (across tabs): other contexts learn about changes | `e2e › a listener in one tab is called after generate, delete and wipe in another tab`; `e2e › protect in one tab: the other tab is told, reports locked, unlocks with one prompt and signs` | All three; protect: Chromium | [Test](test/e2e/tabs.spec.ts#L121), [Test](test/e2e/tabs.spec.ts#L95) |
| Eviction: Vault never requests persistent storage ([DESIGN.md §2.6](DESIGN.md#26-eviction-and-persistent-storage)), and a vault found empty is a new vault | `platform › the library never requests persistent storage`; `vault › lifecycle › a database deleted while the vault is open is an empty vault: list returns no keys and generate creates a new vault` | All three | [Test](test/unit/platform.test.ts#L51), [Test](test/unit/vault.test.ts#L368) |
| The storage format is versioned, and unknown versions are rejected, not coerced; migration is described in [DESIGN.md §2.5](DESIGN.md#25-versioning-and-migration) | `storage › format versioning › a header with format version…`; `storage › format versioning › a database written by a newer format is rejected with incompatible` | All three | [Test](test/unit/storage.test.ts#L955), [Test](test/unit/storage.test.ts#L279) |

### API

| Property | Test | Engines | Code |
|---|---|---|---|
| Invalid states are hard to express in the types | `vault › add accepts only key types that can add an existing key, and returns that type’s KeyInfo`; `vault › the type of a signature follows the type of the key passed to sign` | `npm run typecheck` | [Test](test/unit/vault.test.ts#L606), [Test](test/unit/vault.test.ts#L531) |
| Errors: a retryable infrastructure fault is `unavailable` | `vault › errors › an IndexedDB failure is reported as retryable unavailable, and a retry succeeds` | All three | [Test](test/unit/vault.test.ts#L640) |
| Errors: corrupted storage is `corrupted` | `records › strict parsing › a malformed key record field is corrupted and named: …` | All three | [Test](test/unit/records.test.ts#L290) |
| Errors: a declined or cancelled prompt is `cancelled` | `passkey › a failed prompt › a sign whose prompt is declined or times out is cancelled…` | Chromium (the stand-in can't decline). By hand at `sign`, `unlock()` and `protect()` in Firefox 160, Safari 18.6 and 27.2 | [Test](test/unit/passkey.test.ts#L496) |
| Errors: a locked vault is `locked` | `protection › after protect › another instance is locked: sealed sign fails with locked; generate, list, add, passkey sign and wipe work` | Chromium | [Test](test/unit/protection.test.ts#L585) |
| Errors: a missing key is `not-found` | `vault › keys › signing with an unknown key id fails with not-found` | All three | [Test](test/unit/vault.test.ts#L144) |
| Any operation that may prompt can be started from a user gesture: it calls WebAuthn before its first await | `e2e › a passkey call started from a click handler calls WebAuthn before its first await: <call>` (generate, sign, add); `protection › unlock and lock › unlock starts a prompt for the stored unlock passkey only before its first await, user verification required, with the fixed PRF input` | Chromium; generate, sign and add on the stand-in, which checks no user activation. By hand: every operation started from a demo button (Runs 1–6b) | [Test](test/e2e/passkey.spec.ts#L221), [Test](test/unit/protection.test.ts#L682) |
| The core has no UI-framework dependency | `platform › the library imports only its own modules and the pinned @noble packages: no UI framework, no other third-party code` | All three | [Test](test/unit/platform.test.ts#L39) |

### Platform

| Property | Test | Engines | Code |
|---|---|---|---|
| TypeScript | `npm run typecheck` (strict); `npm run build` emits `.d.ts` | Node (`tsc`) | — |
| Runs in current Chromium, Firefox and WebKit; where passkey features degrade: [DESIGN.md §5.6](DESIGN.md#56-where-passkey-features-degrade) | `platform › runs in the real browser engine it is configured for`; `protection › protection support › protectionSupport() with the engine’s own WebAuthn is unknown in Chromium and Firefox, unsupported in Playwright’s WebKit, which has none` | All three; real passkeys by hand in Firefox 160 and Safari 18.6 and 27.2 | [Test](test/unit/platform.test.ts#L29), [Test](test/unit/protection.test.ts#L1249) |
| Native platform primitives preferred; every third-party cryptographic dependency justified ([DESIGN.md §2.7](DESIGN.md#27-primitives-and-dependencies)); none hand-rolled | `platform › the library imports only its own modules and the pinned @noble packages: no UI framework, no other third-party code`. No primitive hand-rolled is a review claim: not protected | All three | [Test](test/unit/platform.test.ts#L39) |
