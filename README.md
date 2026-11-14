# Vault

A browser-native private-key store on top of IndexedDB. Design: [DESIGN.md](DESIGN.md).

> Status: S7 in progress. A vault, unprotected or passkey-protected, with ed25519, secp256k1 and passkey keys in named scopes: generate, list, sign, delete per scope; wipe for the whole vault. Keys are encrypted at rest in a versioned storage format, records are validated and fail closed, and errors are classified. Keys can carry a label, fixed at generate. Several tabs can use one vault at once: concurrent writes lose no update, first-time setup converges, a stale tab can't undo a wipe, and `vault.onChange` tells every tab that the vault may have changed. A passkey key is created, listed, signed with and deleted through the same calls, each prompt started before any await; `scope.add('passkey')` adds an existing passkey on a fresh device, with the same key id as everywhere else. `vault.protect()` turns passkey protection on, keeping every key, with one passkey prompt where the browser returns the PRF result at creation and two where it doesn't; the protecting tab is unlocked, every other tab locked. `vault.unlock()` unlocks a tab with one passkey prompt, for every scope, until `lock()` or `close()`; an edited protected header fails it with `corrupted`. `protect()` is atomic across tabs and crashes. `Vault.protectionSupport()` reports `unsupported` up front where protection certainly can't work, else `unknown`; elsewhere `protect()` fails with `unsupported` and changes nothing. The demo protects, unlocks and locks, and shows the vault's state.

## Demo

Live at https://yehor-core.github.io/vault/, over HTTPS, without cloning the repository: `.github/workflows/pages.yml` builds it with `npm run build:demo` and deploys it to GitHub Pages on every push to `main` (one-time setup by the repository owner: Settings → Pages → Source: GitHub Actions). Locally, `npm run demo` serves the same page on localhost.

Passkeys made on the Pages demo and on localhost are different credentials: their relying-party ids differ (`yehor-core.github.io` and `localhost`), so a passkey from one can't be added or used on the other.

To sign with a passkey key in a fresh browser profile, follow the [walkthrough](#signing-with-a-passkey-key-in-a-fresh-profile) below. The passkey checks done by hand in Firefox and Safari follow the checklist in [docs/manual-checks.md](docs/manual-checks.md).

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
| `npm run demo` | Serves the demo page at http://localhost:5173: generate a key of any type (ed25519, secp256k1, passkey) with an optional label, add an existing passkey key, list (a passkey key with its credential id), sign (verified outside Vault: ed25519 with WebCrypto, secp256k1 with `@noble/curves`, a passkey assertion as a relying party checks it, with WebCrypto), delete in one fixed scope, `demo`; wipe. Protect with a passkey, Unlock and Lock; a state line shows `vault.state()` (`empty`, `unprotected`, `locked`, `unlocked`), refreshed after every action and when another tab changes the vault. A cancelled passkey prompt, a locked sign and a protect without PRF show their error code |
| `npm run build:demo` | Builds the published demo into `demo-dist/` under the GitHub Pages base path, `/vault/`, as the Pages workflow does; the dev-only console global `Vault` is left out. `npm run preview:demo` serves that build at http://localhost:4173/vault/ |
| `npm run typecheck` | Type checks browser code (`tsconfig.json`, no Node globals) and Node-side config, scripts and e2e tests (`tsconfig.node.json`) |
| `npm run lint` | oxlint: the coding-standards rules marked _(oxlint)_ (`.oxlintrc.json`) |
| `npm run format:check` | Prettier over the whole repo; the pre-commit hook formats only staged files, so CI runs this to catch drift elsewhere |
| `npm run check:casts` | Checks that every type assertion (`as`, not `as const`) in `src/` and `demo/` has a comment holding `` `as`: `` that names the check making it safe |
| `npm run check:refs` | Checks that every test (`storage › …`) and every code name (`src/scope.ts` `#commitKeyRecord`) cited in `DESIGN.md` and `README.md` still exists, and that every "not tested" mark names its ticket (`#NN`) or says "not protected" |
| `npm run check:decisions` | Checks that no past decision in `docs/DECISIONS.md` was rewritten since the merge-base with `origin/main`: it only gains notes naming a new decision |
| `npm run test:unit` | Vitest Browser Mode in real Chromium, Firefox and WebKit (`test/unit`) |
| `npm run test:e2e` | Playwright against the demo page in Chromium, Firefox and WebKit (`test/e2e`); starts its own servers: the dev demo on :5174, and the production build under `/vault/` on :5175 for the published-demo smoke test |
| `npm run test:scripts` | Node tests of the repo's own scripts (`scripts/*.test.ts`), e.g. that `check:refs` rejects a bad citation, `check:decisions` a rewritten decision, `check:casts` an unexplained cast, and that `break-check` reports red correctly (`--typecheck`, `--batch`, and the engines a vitest or Playwright break runs in) |
| `npm test` | Script tests, then both suites |
| `npx vitest run <file> -t '<name>' --project chromium` | One unit test in one engine (`chromium`, `firefox` or `webkit`): the fast TDD loop |
| `npm run break-check -- <file> <text> <replacement> <test file> '<name>' [engine]` | Breaks the code once, runs the test, restores the code; exit 0 only if the test went red. Without `engine`, the test runs in Chromium, Firefox and WebKit and must go red in each; name one engine for a fast loop. A test file under `test/e2e/` runs in Playwright, any other in vitest. `--typecheck <file> <text> <replacement> <test file>`: red when `npm run typecheck` fails in that test file. `--batch <breaks.json>`: a JSON array of `{ file, text, replacement, test, pattern?, engine?, typecheck? }`, each run alone |
| `npm run console-snippets -- <report.md> [engine]` | Runs the report's ```` ```js ```` blocks in the dev demo, in one scope as if pasted into DevTools in order, and prints their console output per engine (default: all three); exit 0 only if none threw. The demo sets `Vault` as a console global in dev |

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
| Firefox | 157 | ✓ | ✓ | e2e against Playwright's stand-in only; real passkeys checked by hand in S7 |
| WebKit | 27.2 | ✓ | ✓ | e2e against Playwright's stand-in only; real passkeys checked by hand in S7 |

Passkey keys, where each path is tested:

| Passkey path | Chromium | Firefox | WebKit |
|---|---|---|---|
| `generate`, `list`, `sign`; the assertion verifies outside Vault under the returned public key | unit + e2e | e2e (stand-in) | e2e (stand-in) |
| Several passkey keys in one scope, each signing on its own | unit + e2e | e2e (stand-in) | e2e (stand-in) |
| `add` on a fresh device (new browser context, empty vault): same id and public key, then `sign` | unit + e2e | e2e (stand-in) | e2e (stand-in) |
| Each prompt starts before the first await, from a click handler | unit + e2e | e2e (stand-in) | e2e (stand-in) |
| A declined prompt is `cancelled`; an answer without user verification is `unsupported` | unit + e2e | — | — |
| Assertion checks, `add` failures, records and tampering | unit | storage and recovery vectors only | storage and recovery vectors only |

Chromium drives its own WebAuthn stack through a CDP virtual authenticator. In Firefox and WebKit the e2e tests run against Playwright's JavaScript stand-in for `navigator.credentials` (`browserContext.credentials`), not the engine's WebAuthn: it always signs ES256 with user presence and user verification, so it can't decline a prompt or answer without user verification, and it checks no user activation. Playwright's WebKit on Linux has no WebAuthn at all (no `navigator.credentials`, and `PublicKeyCredential` is no constructor), so the tests also define empty `PublicKeyCredential` and `Authenticator…Response` classes for the stand-in to build its answers on (`test/e2e/passkeys.ts`). Real passkeys in Firefox and Safari are checked by hand in S7.

Protection, where each path is tested:

| Protection path | Chromium | Firefox | WebKit |
|---|---|---|---|
| `Vault.protectionSupport()`: `unsupported` without WebAuthn or with `extension:prf` reported false, otherwise `unknown`; no prompt, no database | unit | unit | unit |
| `protect()` with an authenticator that returns no PRF result fails with `unsupported`; the vault stays unprotected and every key signs | unit + e2e | e2e (stand-in) | e2e (stand-in) |
| `protect()` with one or two prompts, `unlock()`, `lock()`, no downgrade, tampered protected headers | unit | by hand (S7) | by hand (S7) |
| `protect()` across tabs and through a closed or crashed page | unit + e2e | by hand (S7) | by hand (S7) |

Only Chromium's virtual authenticator returns PRF results. Playwright's stand-in returns none, so protection's main paths in Firefox and WebKit are checked only by hand, with the demo, in S7. In Playwright's WebKit on Linux, `protectionSupport()` is `unsupported`: the engine has no WebAuthn (with the stand-in's classes installed it is `unknown`).

Needs WebCrypto Ed25519, ECDH P-256, HKDF and AES-GCM, IndexedDB and `Uint8Array.prototype.toBase64` (ES2026), in a secure context. secp256k1, ed25519 verification and passkey assertion checks run on `@noble/curves` 2.3.0, and the SHA-256 computed before a passkey prompt on `@noble/hashes` 2.3.0, both pinned exactly (DESIGN.md §3.3). WebKit (Playwright, Linux) has four quirks that shape the design; see DESIGN.md §8:
- It loses stored X25519 keys.
- Its point import accepts off-curve points.
- Its Ed25519 key generation fails about 0.7% of the time (Vault retries it).
- Its Ed25519 verify crashes the tab on degenerate public keys, so Vault verifies ed25519 on `@noble/curves` and never calls it.

## Property → test

One row per property `docs/TASK.md` requires: each line under Required properties, each case of Security expectations, and each hard property of the Evaluation table (marked **Hard**). Each row names the one or two tests that decide it and the engines they run in; DESIGN.md cites the other tests of each guarantee where it states it. A property no test decides says "not protected". The passkey paths that Firefox and Safari can show only with real passkeys, checked by hand with [docs/manual-checks.md](docs/manual-checks.md), say "not tested yet: #101".

Test references: `<name> ›` cites `test/unit/<name>.test.ts`, `e2e ›` cites `test/e2e/`; a middle segment names the `describe` group. `npm run check:refs` checks that every cited test exists. Unit tests run in Chromium, Firefox and WebKit, except the `passkey ›` and `protection ›` tests that need a virtual authenticator, which run in Chromium only. A test about sealed keys runs once per sealed key type (ed25519, secp256k1). "Stand-in" is Playwright's JavaScript `navigator.credentials` in Firefox and WebKit (see Browser support): it can't decline a prompt, drop user verification or return a PRF result. Each cited test was break-checked: the code it guards was broken once and the test went red in every engine its row lists; the type-level rows went red in `npm run typecheck`. Exception: breaking the fresh random bytes of a passkey's user handle turns the several-passkey-keys e2e test red only in Chromium, as the stand-in never overwrites a passkey. Not break-checked: the platform row "runs in Chromium, Firefox and WebKit", `vault › keys › keys survive closing and reopening the vault`, and the "after commit" cut of the closed-tab row, which are functional checks. Only `unavailable` is retryable: every error test asserts the `retryable` flag through `test/unit/helpers.ts` `expectVaultError`.

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
| Several passkeys as keys, each signing on its own | `e2e › several passkey keys in one scope list, and each signs on its own, verifying only under its own public key`; `passkey › generate › the user handle is the scope mark and 16 fresh random bytes, so a second key never overwrites the first` | Chromium; Firefox and WebKit on the stand-in; no overwrite: Chromium. A platform passkey and security keys by hand: not tested yet: #101 |
| **Hard:** a passkey key works in a vault that has never seen it, on a fresh device, and Vault tells which key it is | `e2e › a passkey moved to a new browser context with an empty vault is added there with the same id and public key, then signs`; `passkey › add › a passkey key added to a fresh vault is the key generate made…` | Chromium; Firefox and WebKit on the stand-in; unit: Chromium. A fresh profile with real passkeys: not tested yet: #101 |
| Using a passkey key requires user verification, not just presence | `passkey › generate › generate starts the passkey prompt before its first await, with the creation options Vault fixes` (`userVerification: 'required'`); `e2e › Chromium virtual authenticator › a passkey assertion without user verification is unsupported, and sign returns no signature` | Chromium (the stand-in always verifies the user); Firefox and Safari: not tested yet: #101 |

### Protection

| Property | Test | Engines |
|---|---|---|
| **Hard:** turning protection on for a populated vault is atomic: it completes fully or leaves the vault unchanged | `e2e › <how> while protect writes leaves the unprotected vault or the whole protected one, never a mix: <cut>`; `protection › after protect every key signs and verifies as before, under a new wrapping public key; passkey records are unchanged` | Chromium; Firefox and Safari: not tested yet: #101 |
| A second prompt where the browser returns no PRF result at creation; where that happens: DESIGN.md §8 | `protection › protect, with no PRF result at creation › protect shows a second prompt for the new passkey only, user verification required, with the fixed PRF input; then every key signs`; `› a vault protected after two prompts unlocks in another instance with one prompt`; `› where the browser returns a PRF result only to a prompt restricted to a passkey, protect and then unlock in a new instance succeed (Firefox with a security key)` (a stand-in drops the PRF result of a discoverable prompt); `› where the page gets its focus back only after the creation, protect waits for it and succeeds with the second prompt, with no new gesture` (Safari 27.2 with a security key; a stand-in takes the focus away) | Chromium; prompt counts in Firefox and Safari: not tested yet: #101 |
| **Hard:** unlocking takes one passkey prompt; then every key is usable until the vault is closed, and only passkey keys prompt again | `protection › unlock and lock › after one unlock prompt, sealed keys of every scope sign without a prompt; a passkey key still prompts for itself`; `› lock() and close() lock this instance only: sealed sign fails with locked, after close() InvalidStateError; a new instance is locked` | Chromium; Firefox and Safari: not tested yet: #101 |
| Unlocked state is never persisted: a new instance of the same vault, as after a reload, is locked. A reload itself is not tested: not protected | `protection › unlock and lock › lock() and close() lock this instance only: sealed sign fails with locked, after close() InvalidStateError; a new instance is locked` | Chromium |
| **Hard:** no downgrade: not after a failed unlock, a cancelled prompt, or a deleted or tampered record | `protection › unlock and lock › unlock with %s fails with %s; the vault stays protected and locked` (declined prompt, deleted unlock passkey, no user verification, no PRF result); `storage › tamper table, protected header › a bad protected header is corrupted at the operation the table names: <case>`. A header replaced as a whole, or a vault reset to empty, is not detected (DESIGN.md §5.3): not protected | Chromium; Firefox and Safari: not tested yet: #101 |
| Browsers and authenticators that can't support protection: detected up front where possible, a clean failure with the vault unchanged on the rest | `protection › protection support › protectionSupport() with $name is $expected, with no prompt and no database opened`; `e2e › with an authenticator that returns no PRF result, protectionSupport is unknown, protect fails with unsupported, and the vault stays unprotected with every key signing` | Chromium, Firefox, WebKit (e2e: Firefox and WebKit on the stand-in). Safari with a security key that has no PRF: not tested yet: #101 |
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
| Errors: a declined or cancelled prompt is `cancelled` | `passkey › a failed prompt › a sign whose prompt is declined or times out is cancelled…` | Chromium (the stand-in can't decline); Firefox and Safari: not tested yet: #101 |
| Errors: a locked vault is `locked` | `protection › after protect › another instance is locked: sealed sign fails with locked; generate, list, add, passkey sign and wipe work` | Chromium |
| Errors: a missing key is `not-found` | `vault › keys › signing with an unknown key id fails with not-found` | Chromium, Firefox, WebKit |
| Any operation that may prompt can be started from a user gesture: it calls WebAuthn before its first await | `e2e › a passkey call started from a click handler calls WebAuthn before its first await: <call>` (generate, sign, add); `protection › unlock and lock › unlock starts a prompt for the stored unlock passkey only before its first await, user verification required, with the fixed PRF input`; `e2e › demo protects, signs, locks, fails a sealed sign with locked, unlocks and signs again, its state line following each step` (Protect and Unlock) | Chromium; generate, sign and add in Firefox and WebKit on the stand-in, which shows the call order but checks no user activation. Real gestures in Firefox and Safari: not tested yet: #101 |
| The core has no UI-framework dependency | `platform › the library imports only its own modules and the pinned @noble packages: no UI framework, no other third-party code` | Chromium, Firefox, WebKit |

### Platform

| Property | Test | Engines |
|---|---|---|
| TypeScript | `npm run typecheck` (strict); `npm run build` emits `.d.ts` | Node (`tsc`) |
| Runs in current Chromium, Firefox and WebKit; where passkey features degrade: Browser support above and DESIGN.md §8 | `platform › runs in the real browser engine it is configured for`; `protection › protection support › protectionSupport() with the engine’s own WebAuthn is unknown in Chromium and Firefox, unsupported in Playwright’s WebKit, which has none` | Chromium, Firefox, WebKit; real passkeys in Firefox and Safari: not tested yet: #101 |
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
