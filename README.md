# Vault

A browser-native private-key store on top of IndexedDB. Design: [DESIGN.md](DESIGN.md).

> Status: S7 in progress. ed25519, secp256k1 and passkey keys in named scopes, encrypted at rest, in a vault that is unprotected or passkey-protected: generate, list, sign and delete per scope, add an existing passkey on a fresh device, wipe the whole vault. `protect()` turns protection on atomically, keeping every key; `unlock()` takes one prompt. Records are validated and fail closed, errors are classified, and several tabs share one vault safely.

## Demo

Live at https://yehor-core.github.io/vault/, over HTTPS: `.github/workflows/pages.yml` builds it with `npm run build:demo` and deploys it to GitHub Pages on every push to `main` (one-time setup: Settings → Pages → Source: GitHub Actions). Locally, `npm run demo` serves the same page.

The demo generates keys of each type, adds an existing passkey, lists, signs (and verifies each signature outside Vault), deletes and wipes in one fixed scope, `demo`; it protects, unlocks and locks, and shows `vault.state()`. Passkeys made on the Pages demo and on localhost are different credentials (relying-party ids `yehor-core.github.io` and `localhost`), so one can't be used on the other.

### Signing with a passkey key in a fresh profile

1. Open https://yehor-core.github.io/vault/.
2. Pick Key type `passkey`, click Generate key, and create the passkey on an authenticator that carries across profiles (below). A row of type `passkey` appears.
3. Click that row's Sign: Last signature shows the key's full `public key` line and ends with `verified   true`.
4. Open a fresh browser profile (Chrome: profile menu → Add; Firefox: `about:profiles` → Create a New Profile → Launch profile in new browser; Safari: Settings → Profiles → New Profile, then File → New Window in it) or another browser on the same machine, and open the demo there. State is `empty`: this profile has a vault of its own.
5. Click Add existing passkey and pick the passkey from step 2 in both prompts: Vault needs two signatures to recover the public key. A row of type `passkey` appears with the id and credential id of step 2.
6. Click that row's Sign: the `public key` line is the one of step 3 and the last line is `verified   true`, checked by the page under that public key with WebCrypto, without Vault (`demo/main.ts` `verifyAssertion`). So the added key is the key made in step 2, as `e2e › a passkey moved to a new browser context with an empty vault is added there with the same id and public key, then signs` checks in Chromium, Firefox and WebKit.

A passkey reaches a fresh profile only if its authenticator is there too. A security key (a YubiKey) works in every profile and browser it is plugged into. iCloud Keychain passkeys belong to the Mac, so Safari profiles, Firefox and Chrome on macOS can all use them. A passkey saved in one browser profile's own password manager (Google Password Manager in a Chrome profile, a password-manager extension) may stay in that profile, and then can't be added in another.

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
| `npm run build:demo` | Builds the published demo into `demo-dist/` under `/vault/`, without the dev-only console global `Vault`; `npm run preview:demo` serves it at http://localhost:4173/vault/ |
| `npm run typecheck` | Type checks browser code (`tsconfig.json`) and Node-side code (`tsconfig.node.json`) |
| `npm run lint` | oxlint (`.oxlintrc.json`) |
| `npm run format:check` | Prettier over the whole repo |
| `npm run check:casts` | Every type assertion in `src/` and `demo/` has a comment naming the check that makes it safe |
| `npm run check:refs` | Every test and code name cited in `DESIGN.md` and `README.md` exists |
| `npm run check:decisions` | No past decision in `docs/DECISIONS.md` was rewritten |
| `npm run test:unit` | Vitest Browser Mode in real Chromium, Firefox and WebKit (`test/unit`) |
| `npm run test:e2e` | Playwright against the demo in Chromium, Firefox and WebKit (`test/e2e`): the dev server, and the production build for a smoke test |
| `npm run test:scripts` | Node tests of the repo's scripts (`scripts/*.test.ts`) |
| `npm test` | Script tests, then both suites |
| `npx vitest run <file> -t '<name>' --project chromium` | One unit test in one engine |
| `npm run break-check -- <file> <text> <replacement> <test file> '<name>' [engine]` | Breaks the code once, runs the test, restores the code; exit 0 only if the test went red in every engine. `--typecheck` for type-level tests, `--batch <breaks.json>` for several |
| `npm run console-snippets -- <report.md> [engine]` | Runs a report's ```` ```js ```` blocks in the dev demo and prints their console output |

```ts
import { Vault } from 'vault';

const vault = await Vault.open();
const keys = vault.scope('https://app.example');   // a named group of keys; synchronous, no I/O
const key = await keys.generate('ed25519', { label: 'Payments' }); // the label is fixed: it can't be renamed
const signature = await keys.sign(key, new TextEncoder().encode('hello')); // the KeyInfo itself, not its id
const k1 = await keys.generate('secp256k1');      // ECDSA over SHA-256, low-S, 64-byte r ‖ s
const existing = await keys.add('passkey');        // a passkey made for this scope elsewhere: two prompts
```

## Browser support

| Engine | Version tested (Playwright 1.64.1) | Unit + e2e suites | Vault (unprotected, ed25519 and secp256k1) | Passkey features |
|---|---|---|---|---|
| Chromium | 156 | ✓ | ✓ | ✓ against the engine's WebAuthn (CDP virtual authenticator) |
| Firefox | 157 | ✓ | ✓ | e2e against Playwright's stand-in only; real passkeys checked by hand (below) |
| WebKit | 27.2 | ✓ | ✓ | e2e against Playwright's stand-in only; real passkeys checked by hand in Safari (below) |

Checked by hand, on one Mac with the Pages demo, following [docs/manual-checks.md](docs/manual-checks.md) (its Run log has every step). "iPhone" is an iPhone 15 Pro on iOS 26.6.2 whose iCloud Keychain holds the passkeys, reached over hybrid (QR code); "YubiKey" has firmware 5.4.3 (`hmac-secret`, no `hmac-secret-mc`). These are the browsers installed on that Mac, not Playwright's builds of the table above.

| macOS | Browser | Authenticator | Passkey key: generate, sign, add in a fresh profile | `protect()` prompts | `unlock()`, `lock()` | Runs |
|---|---|---|---|---|---|---|
| 15.8.3 | Safari 18.6 | iPhone | ✓ | 1 | ✓, 1 prompt | 1, 1b |
| 15.8.3 | Safari 18.6 | YubiKey | ✓ | 1, then `unsupported`, the vault unchanged | — | 2 |
| 15.8.3 | Firefox 160 | iPhone | ✓ (fresh context: a private window) | none possible: Firefox opens only its security-key dialog, cancelling it is `cancelled`, the vault unchanged | — | 3 |
| 15.8.3 | Firefox 160 | YubiKey | ✓ (a private window) | 2 | ✓, 1 prompt | 4, 4b |
| 27.2.1 | Safari 27.2 | iPhone | ✓ | 1 | ✓, 1 prompt | 5 |
| 27.2.1 | Safari 27.2 | YubiKey | ✓ (one `add` first failed with `cancelled` and passed after a reload; cause not established) | 2 | ✓, 1 prompt | 6, 6b |

Three faults of Vault these runs found were fixed and the runs repeated (4b, 1b, 6b): `unlock()` asked for a discoverable passkey, which Firefox 160 answers with no PRF result for the YubiKey (#108); `protect()` required a public key that Safari 27.2 doesn't return for a creation with an extension (#110); a chained second prompt ran before Safari 27.2 gave the page its focus back (#111).

Not checked by hand: Windows, Linux, Android and iOS; Chromium on real authenticators (only its virtual authenticator, in the suite); iCloud Keychain on the Mac itself (turned off by the Mac's management policy); a security key with `prf` or `hmac-secret-mc`; several passkey keys in one scope; deleted or tampered records.

Where the passkey and protection paths are tested:

| Path | Chromium | Firefox | WebKit |
|---|---|---|---|
| Passkey `generate`, `sign`, several keys in one scope, `add` on a fresh device, prompts started from a click | unit + e2e | e2e (stand-in); by hand | e2e (stand-in); by hand in Safari |
| A declined prompt is `cancelled`; no user verification is `unsupported` | unit + e2e | by hand (`cancelled` only) | by hand in Safari (`cancelled` only) |
| `Vault.protectionSupport()`; `protect()` without a PRF result fails with `unsupported`, the vault unchanged | unit + e2e | unit + e2e (stand-in) | unit + e2e (stand-in) |
| `protect()` with one or two prompts, `unlock()`, `lock()`, no downgrade | unit | by hand | by hand in Safari |
| Tampered protected headers; `protect()` across tabs and through a closed or crashed page | unit + e2e | not protected | not protected |

Chromium drives its own WebAuthn through a CDP virtual authenticator, the only one that returns PRF results. In Firefox and WebKit the e2e tests use Playwright's JavaScript stand-in for `navigator.credentials` ("stand-in"): it always answers ES256 with user verification, so it can't decline, drop user verification or return a PRF result, and checks no user activation. Playwright's WebKit on Linux has no WebAuthn at all, so the tests define empty WebAuthn classes for the stand-in (`test/e2e/passkeys.ts`), and `protectionSupport()` there is `unsupported`.

Needs WebCrypto Ed25519, ECDH P-256, HKDF and AES-GCM, IndexedDB and `Uint8Array.prototype.toBase64`, in a secure context. secp256k1 and verification run on `@noble/curves` 2.3.0 and `@noble/hashes` 2.3.0, pinned exactly. WebKit's quirks that shape the design (stored X25519 keys lost, off-curve points accepted, flaky Ed25519 key generation, a crashing Ed25519 verify) are in DESIGN.md §8.

## Property → test

One row per property `docs/TASK.md` requires (Required properties, Security expectations, and the Evaluation table's hard properties, marked **Hard**), with the one or two tests that decide it and their engines. A property no test decides says "not protected"; "by hand" cells name runs of the [docs/manual-checks.md](docs/manual-checks.md) Run log.

Test references: `<name> ›` cites `test/unit/<name>.test.ts`, `e2e ›` cites `test/e2e/`; a middle segment names the `describe` group. Unit tests run in Chromium, Firefox and WebKit, except `passkey ›` and `protection ›` tests that need a virtual authenticator: Chromium only. Each cited test was break-checked: the code it guards was broken once and the test went red in every engine its row lists. Exceptions: the user-handle break turns the several-passkey-keys e2e test red only in Chromium (the stand-in never overwrites a passkey); not break-checked, as functional checks: the "runs in" platform row, `vault › keys › keys survive closing and reopening the vault`, and the closed-tab row's "after commit" cut. Every error test asserts the `retryable` flag (`test/unit/helpers.ts` `expectVaultError`).

### Keys

| Property | Test | Engines |
|---|---|---|
| Generate keys of a chosen type inside the vault | `vault › keys › a generated key is listed with its public information` (ed25519, secp256k1); `e2e › a passkey key generated in the page signs, and its assertion verifies outside Vault under the returned public key` | Chromium, Firefox, WebKit (passkey: Firefox and WebKit on the stand-in) |
| List keys and read their public information (id, type, public key, label) without unlocking | `vault › labels › a label given at generate is stored and carried by the public information; without one there is no label field`; `protection › after protect › another instance is locked: sealed sign fails with locked; generate, list, add, passkey sign and wipe work` | Chromium, Firefox, WebKit; locked: Chromium |
| Sign with a key; anyone verifies under its public key without Vault; private key material never leaves the vault | `vault › keys › a signature verifies under the public key without Vault`; `storage › encryption at rest › no private key bytes are stored: only ciphertext and a non-extractable root key` | Chromium, Firefox, WebKit |
| Delete a single key, and wipe the whole vault | `vault › keys › delete removes only that key, and deleting a missing key is a no-op`; `vault › scopes › wipe removes the keys of every scope and the header in one transaction` | Chromium, Firefox, WebKit |
| Named scopes serve independent consumers. The demo stays on one fixed scope, `demo`; these tests prove scopes | `vault › scopes › keys generated in one scope are listed only there, and an unused scope lists nothing`; `vault › scopes › the id of a key of another scope is not-found by sign and untouched by delete` | Chromium, Firefox, WebKit |

### Passkey keys

| Property | Test | Engines |
|---|---|---|
| Several passkeys as keys, each signing on its own | `e2e › several passkey keys in one scope list, and each signs on its own, verifying only under its own public key`; `passkey › generate › the user handle is the scope mark and 16 fresh random bytes, so a second key never overwrites the first` | Chromium; Firefox and WebKit on the stand-in; no overwrite: Chromium. By hand, Firefox and Safari: one passkey key per run, on an iPhone over hybrid and on a YubiKey, signing beside the unlock passkey (Runs 1–6b); several passkey keys in one scope: not checked by hand |
| **Hard:** a passkey key works in a vault that has never seen it, on a fresh device, and Vault tells which key it is | `e2e › a passkey moved to a new browser context with an empty vault is added there with the same id and public key, then signs`; `passkey › add › a passkey key added to a fresh vault is the key generate made…` | Chromium; Firefox and WebKit on the stand-in; unit: Chromium. By hand, a fresh profile with real passkeys: same id, credential id and public key, then a signature, in Safari 18.6 and 27.2 (a new profile) and Firefox 160 (a private window), with an iPhone over hybrid and a YubiKey (Runs 1–5, 4b, 6b, steps 3–4) |
| Using a passkey key requires user verification, not just presence | `passkey › generate › generate starts the passkey prompt before its first await, with the creation options Vault fixes` (`userVerification: 'required'`); `e2e › Chromium virtual authenticator › a passkey assertion without user verification is unsupported, and sign returns no signature` | Chromium (the stand-in always verifies the user); by hand in Firefox and Safari, the assertion of step 2 of each run carried UV (flags `05` and `1d`); an answer without UV there: not protected |

### Protection

| Property | Test | Engines |
|---|---|---|
| **Hard:** turning protection on for a populated vault is atomic: it completes fully or leaves the vault unchanged | `e2e › <how> while protect writes leaves the unprotected vault or the whole protected one, never a mix: <cut>`; `protection › after protect every key signs and verifies as before, under a new wrapping public key; passkey records are unchanged` | Chromium; by hand in Firefox and Safari, a completed `protect()` kept every key (Runs 1, 4b, 5, 6b) and a failed one left the vault unchanged (Runs 2, 3); a cut during the write: Chromium only |
| A second prompt where the browser returns no PRF result at creation; where that happens: DESIGN.md §8 | `protection › protect, with no PRF result at creation › protect shows a second prompt for the new passkey only, user verification required, with the fixed PRF input; then every key signs`; `› a vault protected after two prompts unlocks in another instance with one prompt`; `› where the browser returns a PRF result only to a prompt restricted to a passkey, protect and then unlock in a new instance succeed (Firefox with a security key)` (a stand-in drops the PRF result of a discoverable prompt); `› where the page gets its focus back only after the creation, protect waits for it and succeeds with the second prompt, with no new gesture` (Safari 27.2 with a security key; a stand-in takes the focus away) | Chromium; prompt counts by hand: one in Safari 18.6 and 27.2 with an iPhone over hybrid (Runs 1, 1b, 5), two with a YubiKey in Firefox 160 and Safari 27.2 (Runs 4b, 6b) |
| **Hard:** unlocking takes one passkey prompt; then every key is usable until the vault is closed, and only passkey keys prompt again | `protection › unlock and lock › after one unlock prompt, sealed keys of every scope sign without a prompt; a passkey key still prompts for itself`; `› lock() and close() lock this instance only: sealed sign fails with locked, after close() InvalidStateError; a new instance is locked` | Chromium; by hand in Firefox and Safari: one prompt at `unlock()`, then the ed25519 key signs with none, and a sealed key is `locked` after `lock()` (Runs 1, 1b, 4b, 5, 6b, steps 7–10) |
| Unlocked state is never persisted: a new instance of the same vault, as after a reload, is locked. A reload itself is not tested: not protected | `protection › unlock and lock › lock() and close() lock this instance only: sealed sign fails with locked, after close() InvalidStateError; a new instance is locked` | Chromium |
| **Hard:** no downgrade: not after a failed unlock, a cancelled prompt, or a deleted or tampered record | `protection › unlock and lock › unlock with %s fails with %s; the vault stays protected and locked` (declined prompt, deleted unlock passkey, no user verification, no PRF result); `storage › tamper table, protected header › a bad protected header is corrupted at the operation the table names: <case>`. A header replaced as a whole, or a vault reset to empty, is not detected (DESIGN.md §5.3): not protected | Chromium; by hand in Firefox and Safari, a failed `unlock()` (Run 4) and a cancelled one (Run 1) left the vault locked with every key; a cancelled `unlock()` was `cancelled` in Runs 1b, 4, 4b, 5 and 6b too; deleted or tampered records: not checked by hand |
| Browsers and authenticators that can't support protection: detected up front where possible, a clean failure with the vault unchanged on the rest | `protection › protection support › protectionSupport() with $name is $expected, with no prompt and no database opened`; `e2e › with an authenticator that returns no PRF result, protectionSupport is unknown, protect fails with unsupported, and the vault stays unprotected with every key signing` | Chromium, Firefox, WebKit (e2e: Firefox and WebKit on the stand-in). By hand: Safari 18.6 with a YubiKey, `unsupported` after one prompt, the vault unchanged (Run 2); Firefox 160 with an iPhone, its security-key dialog cancelled, `cancelled`, the vault unchanged (Run 3) |
| Whether more than one passkey can unlock a vault: one unlock passkey (DESIGN.md §5.2); any other passkey is refused | `protection › unlock and lock › unlock answered by %s fails with not-found and changes nothing, locked or unlocked` | Chromium |
| **Hard:** adding keys without unlocking: a locked vault generates a sealed key without creating a passkey, sealed to the protected wrapping key | `protection › after protect › another instance is locked: sealed sign fails with locked; generate, list, add, passkey sign and wipe work` | Chromium |

### Storage, integrity and concurrency

| Property | Test | Engines |
|---|---|---|
| IndexedDB is the only persistent store | `platform › the library stores nothing outside IndexedDB: no Web Storage, cookies, Cache Storage or origin private file system`; `vault › keys › keys survive closing and reopening the vault` | Chromium, Firefox, WebKit |
| Everything read from IndexedDB is untrusted: modified, swapped, truncated or malformed records are detected, and Vault fails closed rather than returning a wrong key or repairing data | `storage › tamper table › a bad record is corrupted at the operation the table names: <case>`; `vault › errors › key records without a vault header are corrupted everywhere, never a new vault; only wipe recovers` | Chromium, Firefox, WebKit |
| Changes that touch several records are atomic: a crash or closed tab leaves the old state or the new one | `e2e › a tab closed while the first generate writes leaves the old state or the new one, never a mix: <cut>`; `vault › errors › wipe is one transaction: aborted midway, it fails as unavailable and the header and keys remain` | Chromium, Firefox, WebKit |
| **Hard** (across tabs): no lost updates. Frames share the tabs' IndexedDB and `BroadcastChannel`, but no test runs in a frame: frames are not protected | `e2e › concurrent generates from two tabs each store their key, which lists and signs in both tabs`; `concurrency › no lost updates › a generate held while another context deletes a key of its scope…` | Chromium, Firefox, WebKit |
| **Hard** (across tabs): concurrent first-time setup converges | `e2e › concurrent first generates from two tabs converge on one vault: both keys list and sign in both tabs under the one header` | Chromium, Firefox, WebKit |
| **Hard** (across tabs): a stale context can't undo a wipe or a protection change | `e2e › a generate held in one tab while another tab wipes resolves in a new vault: only its new key lists and signs in both tabs, under a new header`; `protection › protection across instances › a generate held while another instance protects is redone against the protected header, and its key signs after unlock` | Chromium, Firefox, WebKit; protection: Chromium |
| **Hard** (across tabs): other contexts learn about changes | `e2e › a listener in one tab is called after generate, delete and wipe in another tab`; `e2e › protect in one tab: the other tab is told, reports locked, unlocks with one prompt and signs` | Chromium, Firefox, WebKit; protect: Chromium |
| Eviction: Vault never requests persistent storage (DESIGN.md §4.4), and a vault found empty is a new vault | `platform › the library never requests persistent storage`; `vault › lifecycle › a database deleted while the vault is open is an empty vault: list returns no keys and generate creates a new vault` | Chromium, Firefox, WebKit |
| The storage format is versioned and unknown versions are rejected, not coerced; a future migration is described in DESIGN.md §4.3, with no migration code to test | `storage › format versioning › a header with format version…`; `storage › format versioning › a database written by a newer format is rejected with incompatible` | Chromium, Firefox, WebKit |

### API

| Property | Test | Engines |
|---|---|---|
| Invalid states are hard to express in the types | `vault › add accepts only key types that can add an existing key, and returns that type’s KeyInfo`; `vault › the type of a signature follows the type of the key passed to sign` | `npm run typecheck` |
| Errors: a retryable infrastructure fault is `unavailable` | `vault › errors › an IndexedDB failure is reported as retryable unavailable, and a retry succeeds` | Chromium, Firefox, WebKit |
| Errors: corrupted storage is `corrupted` | `records › strict parsing › a malformed key record field is corrupted and named: …` | Chromium, Firefox, WebKit |
| Errors: a declined or cancelled prompt is `cancelled` | `passkey › a failed prompt › a sign whose prompt is declined or times out is cancelled…` | Chromium (the stand-in can't decline); by hand, a cancelled prompt is `cancelled` in Firefox 160, Safari 18.6 and Safari 27.2, at `sign`, `unlock()` and `protect()` (step 11 of each run; Run 3, step 6) |
| Errors: a locked vault is `locked` | `protection › after protect › another instance is locked: sealed sign fails with locked; generate, list, add, passkey sign and wipe work` | Chromium |
| Errors: a missing key is `not-found` | `vault › keys › signing with an unknown key id fails with not-found` | Chromium, Firefox, WebKit |
| Any operation that may prompt can be started from a user gesture: it calls WebAuthn before its first await | `e2e › a passkey call started from a click handler calls WebAuthn before its first await: <call>` (generate, sign, add); `protection › unlock and lock › unlock starts a prompt for the stored unlock passkey only before its first await, user verification required, with the fixed PRF input`; `e2e › demo protects, signs, locks, fails a sealed sign with locked, unlocks and signs again, its state line following each step` (Protect and Unlock) | Chromium; generate, sign and add in Firefox and WebKit on the stand-in, which shows the call order but checks no user activation. By hand, each operation was started from a click on a demo button in Firefox 160, Safari 18.6 and Safari 27.2, and its first prompt opened (Runs 1–6b); Safari 27.2 with a security key also needs the page's focus back for a chained second prompt (DESIGN.md §8) |
| The core has no UI-framework dependency | `platform › the library imports only its own modules and the pinned @noble packages: no UI framework, no other third-party code` | Chromium, Firefox, WebKit |

### Platform

| Property | Test | Engines |
|---|---|---|
| TypeScript | `npm run typecheck` (strict); `npm run build` emits `.d.ts` | Node (`tsc`) |
| Runs in current Chromium, Firefox and WebKit; where passkey features degrade: Browser support above and DESIGN.md §8 | `platform › runs in the real browser engine it is configured for`; `protection › protection support › protectionSupport() with the engine’s own WebAuthn is unknown in Chromium and Firefox, unsupported in Playwright’s WebKit, which has none` | Chromium, Firefox, WebKit; real passkeys by hand in Firefox 160 and Safari 18.6 and 27.2 on macOS (Browser support above) |
| Native platform primitives preferred; every third-party cryptographic dependency justified (DESIGN.md §3.3); none hand-rolled | `platform › the library imports only its own modules and the pinned @noble packages: no UI framework, no other third-party code` (the third-party code is the two packages §3.3 justifies, pinned exactly). That no primitive is hand-rolled is a review claim: not protected | Chromium, Firefox, WebKit |

### Security expectations

DESIGN.md §2.3 states, per case, what Vault guarantees and what it doesn't.

| Case | Test | Engines |
|---|---|---|
| Copy of the browser profile, passkey mode: keys unrecoverable without the unlock passkey (or the account that syncs it) | `protection › protect, with the PRF result at creation › the protected header wraps the wrapping private key under a KEK from the PRF result, bound to every other field` | Chromium |
| Copy of the browser profile, unprotected mode: only the browser-held, non-extractable root key protects the keys, and a copy recovers every key: not protected | `storage › encryption at rest › no private key bytes are stored: only ciphertext and a non-extractable root key`; `› decrypting needs the root key: with another private key in its place, sign fails closed` | Chromium, Firefox, WebKit |
| Records added or replaced by anyone who can write to storage: what is detected, and at which operation. A complete added key needs no secret and is not detected: not protected | `storage › tamper table › a bad record is corrupted at the operation the table names: <case>`; `storage › integrity › the edit cases cover every stored field of a key record` | Chromium, Firefox, WebKit |
| An older storage snapshot: not detected, not protected | — | — |
| Malicious script in the same origin while unlocked: it signs with every key until `lock()` or `close()` (not protected); the API returns no private key bytes, and a `Scope` has no path to its `Vault` | `vault › scopes › a Scope has no path to its Vault: it can neither wipe nor be retargeted at another scope`; `protection › unlock and lock › lock() and close() lock this instance only: sealed sign fails with locked, after close() InvalidStateError; a new instance is locked` | Chromium, Firefox, WebKit; lock: Chromium |
| Lost, deleted or replaced passkey, for protection: the unlock fails and the vault is unchanged; the sealed keys are lost for good | `protection › unlock and lock › unlock with %s fails with %s; the vault stays protected and locked` (the unlock passkey deleted); `› unlock answered by %s fails with not-found and changes nothing, locked or unlocked` (another passkey) | Chromium |
| Lost, deleted or replaced passkey, for a passkey key: `sign` is `cancelled`, the key stays listed. A replaced passkey is not tested on its own: not protected | `passkey › a failed prompt › a sign with a passkey removed from its authenticator is cancelled` | Chromium |
| Secrets in memory: minimal lifetime. JS can't zero memory, and the secp256k1 scalar exists as JS bytes during `generate` and `sign`: not protected | `storage › encryption at rest › a generated key has its secrets erased once, after it is stored`; `protection › the PRF result’s bytes are zeroed once imported, at protect and at unlock` | Chromium, Firefox, WebKit; PRF: Chromium |
