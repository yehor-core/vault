# Manual passkey checks

Playwright can drive real WebAuthn only in Chromium, through its virtual authenticator. In Firefox and WebKit the e2e tests run against Playwright's stand-in for `navigator.credentials`, which can't decline a prompt, drop user verification or return a PRF result (README, "Browser support"). The passkey paths there are checked by hand, on the published demo, with the checklist below; each run is logged at the end of this file.

## What each run records

- Date.
- macOS version.
- Browser and version (Safari → About Safari; Firefox → About Firefox).
- Authenticator and firmware: the iPhone (model, iOS version) whose iCloud Keychain holds the passkeys, or the YubiKey and its firmware as Yubico Authenticator shows it.
- Vault commit: the commit of `main` the Pages demo was built from (the latest run of the Pages workflow).
- For each checklist step: the observed result, the number of prompts, and whether it matches the expected result.

A prompt is one passkey dialog the browser opens for one WebAuthn call. A YubiKey PIN and touch, or a QR code scanned and confirmed on the iPhone, asked inside that dialog are part of it.

## Pairs and order

All runs are on one Mac, on the Pages demo, https://yehor-core.github.io/vault/. Each pair runs the whole checklist.

The Mac is managed (MDM): iCloud Keychain can't be turned on, and Firefox's `about:profiles` is blocked. So the iCloud Keychain pairs keep their passkeys in an iPhone's iCloud Keychain, reached over hybrid: the browser's dialog shows a QR code, the iPhone scans it and asks for Face ID, and Bluetooth carries the rest. On the iPhone, Settings → General → AutoFill & Passwords has Passwords on and every other provider (Bitwarden) off, else the phone saves the passkey there. Firefox's fresh context is a private window, which has a storage of its own.

On macOS 15.8.3, with Safari 18.6 and Firefox 160:

1. Safari × iPhone (hybrid)
2. Safari × YubiKey
3. Firefox × iPhone (hybrid)
4. Firefox × YubiKey

Then macOS is updated to one that offers Safari 26.4 or later (27.2.1, with Safari 27.2):

5. Safari × iPhone (hybrid)
6. Safari × YubiKey

Firefox is 139 or later: 135–138 have no PRF on macOS. The Firefox pairs run before the macOS update: below macOS 26.4, Firefox reaches security keys through authenticator-rs, and that is the path these runs record.

The YubiKey has firmware 5.4.3 and a FIDO2 PIN set. Firmware 5.4.3 has `hmac-secret` but no `hmac-secret-mc`, so it returns no PRF result at creation in any browser.

A run that finds a fault of Vault is run again once the fix is on `main`, on the build with it; both runs stay in the log.

## Expected prompts per pair

| Step | Safari × iPhone (hybrid) | Safari 18.6 × YubiKey | Safari 26.4+ × YubiKey | Firefox × iPhone (hybrid) | Firefox × YubiKey |
|---|---|---|---|---|---|
| 1. Generate a passkey key | 1 | 1 | 1 | 1 | 1 |
| 2. Sign with it | 1 | 1 | 1 | 1 | 1 |
| 3. Add it in a fresh profile | 2 | 2 | 2 | 2 | 2 |
| 4. Sign there | 1 | 1 | 1 | 1 | 1 |
| 5. Generate an ed25519 key and sign | 0 | 0 | 0 | 0 | 0 |
| 6. Protect | 1 | 1, then `unsupported` | 2 | 1, Firefox's security-key dialog: cancel it | 2 |
| 7. Reload: locked | 0 | skipped | 0 | skipped | 0 |
| 8. Unlock | 1 | skipped | 1 | skipped | 1 |
| 9. Lock | 0 | skipped | 0 | skipped | 0 |
| 10. Sign with a sealed key while locked | 0 | skipped | 0 | skipped | 0 |
| 11. Cancelled prompt | 1 | 1 | 1 | 1 | 1 |
| 12. Wipe | 0 | 0 | 0 | 0 | 0 |

At `protect()`, one prompt means the creation returned the PRF result; two mean it returned only `prf.enabled: true` and Vault asked for the new passkey again at once. With the YubiKey it is two in every browser that has security-key PRF. The iPhone's iCloud Keychain returns the PRF result at creation in Safari 18.6 and 27.2 (Runs 1, 1b, 5), so one. Safari 18.6 has no PRF for security keys (it shipped in Safari 26.4), so `protect()` fails with `unsupported` after the creation and steps 7 to 10 are skipped. Firefox 160 on macOS 15.8.3 sends a creation that carries the PRF extension to its own "Touch your security key" dialog, which offers no iPhone, so with the iPhone `protect()` can only be cancelled (`cancelled`, the vault unchanged) and steps 7 to 10 are skipped.

At `unlock()`, one prompt in every pair: it asks for the stored unlock passkey by its credential id, the request `protect()`'s second prompt makes. Firefox × YubiKey: 2 prompts at `protect()`, 1 at `unlock()`. Before #108, `unlock()` made a discoverable request, which Firefox × YubiKey answers with no PRF result, so step 8 failed with `unsupported`.

## Checklist

Before the run:

0. Record the run's fields (above). With the YubiKey, open Yubico Authenticator → Passkeys and delete every credential for `yehor-core.github.io`; with the iPhone, delete the passkeys for `yehor-core.github.io` in its Passwords app. Open the demo in the browser's usual profile, the first profile, and reload it, so the page is the latest build. If State is not `empty`, click Wipe vault.

In each prompt, pick the pair's authenticator: the iPhone (the dialog's option for an iPhone or another device, then scan the QR code and confirm on the phone), or the security key (insert and touch the YubiKey, enter its PIN). Every result below is read from the page: the State line, the status line under it (`Ready`, or `VaultError <code>: …` on a failure), the key table, and `verified` under Last signature.

| Step | Do | Expected |
|---|---|---|
| 1. Generate a passkey key | Key type `passkey`, Label `run N key`, Generate key | A row of type `passkey` with a credential id; State `unprotected`; status `Ready` |
| 2. Sign with it | That row's Sign | The dialog lists `run N key`; Last signature shows the full `public key` line, `authenticator data`, `client data` and `verified   true` |
| 3. Add it in a fresh profile | Open a fresh profile (README, walkthrough step 4; Firefox here: a private window) and the demo in it; State is `empty`. Label `run N key`, Add existing passkey, pick `run N key` both times | A row of type `passkey` whose id and credential id are the ones of step 1; State `unprotected` |
| 4. Sign there | That row's Sign | `verified   true`; the `public key` line is the one of step 2 |
| 5. Generate an ed25519 key and sign | Back in the first profile: Key type `ed25519`, Generate key, then its row's Sign | No prompt; `verified   true` |
| 6. Protect | Protect with a passkey | State `unlocked`, status `Ready`, both keys still listed; Sign of the ed25519 key: no prompt, `verified   true`. Safari 18.6 × YubiKey: status `VaultError unsupported: …`, State `unprotected`, both keys listed, and the ed25519 key still signs. Firefox × iPhone: cancel Firefox's security-key dialog; status `VaultError cancelled: …`, State `unprotected`, both keys listed, and the ed25519 key still signs |
| 7. Reload: locked | Reload the page | State `locked`; both keys listed |
| 8. Unlock | Unlock; the dialog asks for the unlock passkey only (`Vault unlock`, if it names one) | State `unlocked`; Sign of the ed25519 key: no prompt, `verified   true` |
| 9. Lock | Lock | State `locked`, no prompt |
| 10. Sign with a sealed key while locked | The ed25519 row's Sign | No prompt; status `VaultError locked: …`; Last signature unchanged; State `locked` |
| 11. Cancelled prompt | Unlock, then cancel the dialog. Where the vault is not protected (Safari 18.6 × YubiKey, Firefox × iPhone): the passkey row's Sign, then cancel | Status `VaultError cancelled: …`; State as before (`locked`, or `unprotected` where the vault is not protected); both keys listed |
| 12. Wipe | Wipe vault, in the first profile and in the fresh one; then delete the fresh profile | No prompt; State `empty`; no keys |

After the run: clear the authenticator as in step 0. `wipe()` removes nothing at the authenticator: the passkey key and the unlock passkey stay on it, and a failed `protect()` leaves its unlock passkey there too. The YubiKey holds 25 discoverable credentials (firmware below 5.7) and each run adds two.

## On a failure

A step that does not match its expected result is logged as it went, with:

- Vault's error code, from the status line (`VaultError <code>: …`), or the browser's error if it is not a `VaultError`.
- Whether the vault changed: the key table and State compared with before the step.
- State afterwards.

A failure caused by the browser or the authenticator is not fixed: the README matrix and DESIGN.md's known limitations state what fails and with which error. It is Vault's fault, and a bug ticket with a test, when the error is misclassified, the vault changed, or a protected vault became unprotected, or when `protect()` succeeds where `unlock()` can't follow.

Known risk: Safari 26.4 returned a still-encrypted PRF output from security keys (WebKit bug 311099). It does not show in Safari 27.2: with the YubiKey, `protect()` and then `unlock()`, prompts of separate sessions, derive the same key (Run 6b).

## Run log

Steps marked "as expected" matched the expected result and prompt count of the tables above. ¹ = confirmed by the tester after the run, from memory, not noted during it.

### Run 1: Safari 18.6 × iPhone (hybrid)

2026-11-13 · macOS 15.8.3 (24H241) · Safari 18.6 (20621.3.11.11.3) · iPhone 15 Pro, iOS 26.6.2, iCloud Keychain · Vault `37dd635`

The first attempt saved the passkey in Bitwarden, the phone's default provider; it was deleted there, Passwords was made the provider (above) and the run started again from step 0.

| Step | Prompts | Observed | Match |
|---|---|---|---|
| 1 | 1 | Row of type `passkey`; `unprotected`, `Ready`¹ | yes |
| 2 | 1 | `verified   true`; authenticator data flags `1d` (UP, UV, BE, BS), sign count 0 | yes |
| 3 | 2 | New Safari profile; credential id `3f7674412c6f2a5a…`, the one of step 1; `passkey`, `unprotected`¹ | yes |
| 4 | 1 | `verified   true`; `key` and `public key` lines those of step 2 | yes |
| 5 | 0 | `verified   true` | yes |
| 6 | 1 | `unlocked`, `Ready`, both keys; ed25519 Sign: no prompt, `verified   true`. The PRF result came at creation | yes |
| 7 | 0 | `locked`, both keys | yes |
| 8 | 1 | `unlocked`; ed25519 Sign: no prompt, `verified   true` | yes |
| 9 | 0 | `locked` | yes |
| 10 | 0 | `VaultError locked: The vault is locked`; Last signature unchanged; `locked` | yes |
| 11 | 1 | Cancelled in the Mac's dialog, before the QR code: `VaultError cancelled: The passkey prompt ended with NotAllowedError`; `locked`, both keys | yes |
| 12 | 0 | `empty` in both profiles¹ | yes |

Each ed25519 Sign of the same key and message gave another signature, and each verified: Safari's WebCrypto Ed25519 signs non-deterministically (DESIGN.md §8).

### Run 2: Safari 18.6 × YubiKey

2026-11-13 · macOS 15.8.3 · Safari 18.6 · YubiKey firmware 5.4.3 · Vault `37dd635`

| Step | Prompts | Observed | Match |
|---|---|---|---|
| 1 | 1 | as expected | yes |
| 2 | 1 | `verified   true`; flags `05` (UP, UV), sign count 7 | yes |
| 3 | 2 | New Safari profile; the credential id of step 1 | yes |
| 4 | 1 | `verified   true`; `key` and `public key` those of step 2 | yes |
| 5 | 0 | `verified   true` | yes |
| 6 | 1 | `VaultError unsupported: The authenticator returned no PRF result`; `unprotected`, both keys; the ed25519 key still signs | yes |
| 7–10 | — | skipped | — |
| 11 | 1 | Passkey row's Sign, cancelled: `VaultError cancelled: The passkey prompt ended with NotAllowedError`; `unprotected`, both keys | yes |
| 12 | 0 | as expected | yes |

### Run 3: Firefox × iPhone (hybrid)

2026-11-13 · macOS 15.8.3 · Firefox 160.0 (aarch64) · iPhone 15 Pro, iOS 26.6.2 · Vault `37dd635`

| Step | Prompts | Observed | Match |
|---|---|---|---|
| 1 | 1 | `passkey`, `unprotected`, `Ready`; the macOS passkey dialog, with the iPhone option | yes |
| 2 | 1 | `verified   true`; flags `1d`, sign count 0 | yes |
| 3 | 2¹ | `about:profiles` blocked by policy ("Your organization has blocked access to this page"); in a private window: State `empty`, then credential id `441d89ef1c1c6664…`, the one of step 1 | yes |
| 4 | 1¹ | `verified   true`; `key` and `public key` those of step 2 | yes |
| 5 | 0 | ed25519 key generated; it signs after step 6 (not reported on its own) | yes |
| 6 | 1 | Firefox opened its own "Touch your security key…" dialog, with no iPhone or QR code; cancelled: `VaultError cancelled: The passkey prompt ended with NotAllowedError`; `unprotected`, both keys; the ed25519 key still signs | no: Firefox's routing, the vault unchanged |
| 7–10 | — | skipped | — |
| 11 | 1 | Passkey row's Sign, cancelled in the macOS dialog: `VaultError cancelled: The passkey prompt ended with NotAllowedError` | yes |
| 12 | 0 | as expected¹ | yes |

Vault's creation options for the unlock passkey are those of a passkey key plus the PRF extension, with no `authenticatorAttachment`, so the choice of dialog is Firefox's.

### Run 4: Firefox × YubiKey

2026-11-13 · macOS 15.8.3 · Firefox 160.0 · YubiKey firmware 5.4.3 · Vault `37dd635`

| Step | Prompts | Observed | Match |
|---|---|---|---|
| 1 | 1 | as expected | yes |
| 2 | 1 | `verified   true`; flags `05`, sign count 5 | yes |
| 3 | 2 | Private window; credential id `aa3a31af0f1acc46…` in both windows | yes |
| 4 | 1 | `verified   true`; `key` and `public key` those of step 2 | yes |
| 5 | 0 | as expected | yes |
| 6 | 2 | `unlocked`, `Ready` | yes |
| 7 | 0 | as expected | yes |
| 8 | 1 | `VaultError unsupported: The authenticator returned no PRF result`; `locked`, both keys | no: a fault of Vault, #108 |
| 9 | — | not applicable: the vault stayed `locked` | — |
| 10 | 0 | `VaultError locked: The vault is locked` | yes |
| 11 | 1 | Unlock, cancelled: `VaultError cancelled: The passkey prompt ended with NotAllowedError` | yes |
| 12 | 0 | as expected | yes |

Step 8, checked in the console with two page clicks, the same PRF input and the `Vault unlock` credential: a discoverable `get()` returned no PRF result, a `get()` restricted to the credential returned one. `protect()`'s second prompt was restricted, `unlock()`'s was discoverable, so `protect()` succeeded into a vault `unlock()` could not open. The fix (D-94) restricts `unlock()` to the stored credential id; Run 4b.

### Run 4b: Firefox × YubiKey, after #108

2026-11-14 · macOS 15.8.3 · Firefox 160.0 · YubiKey firmware 5.4.3 · Vault `77d9845`

| Step | Prompts | Observed | Match |
|---|---|---|---|
| 1 | 1 | as expected | yes |
| 2 | 1 | `verified   true`; flags `05`, sign count 6 | yes |
| 3 | 2 | Private window; credential id `b9cb0832126e2e51…` in both windows | yes |
| 4 | 1 | `verified   true`; `key` and `public key` those of step 2 | yes |
| 5 | 0 | `verified   true` | yes |
| 6 | 2 | `unlocked`, `Ready`, both keys; ed25519 Sign: no prompt | yes |
| 7 | 0 | `locked`, both keys | yes |
| 8 | 1 | `unlocked`; ed25519 Sign: no prompt, `verified   true` | yes |
| 9 | 0 | `locked` | yes |
| 10 | 0 | `VaultError locked: The vault is locked` | yes |
| 11 | 1 | `VaultError cancelled: The passkey prompt ended with NotAllowedError` | yes |
| 12 | 0 | `empty` | yes |

The YubiKey's credential ids begin with the bytes of the public key's x coordinate (seen in the authenticator data of a creation), so the credential id column and the public key line share a prefix.

### Run 1b: Safari 18.6 × iPhone (hybrid), steps 5–12 after #108

2026-11-14 · macOS 15.8.3 · Safari 18.6 · iPhone 15 Pro, iOS 26.6.2 · Vault `77d9845`. Steps 1–4 are not touched by the fix and were not repeated.

| Step | Prompts | Observed | Match |
|---|---|---|---|
| 5 | 0 | `verified   true` | yes |
| 6 | 1 | `unlocked`, `Ready`; ed25519 Sign: no prompt | yes |
| 7 | 0 | `locked` | yes |
| 8 | 1 | The phone offered `Vault unlock` at once, with no list to pick from; `unlocked`; ed25519 Sign: no prompt, `verified   true` | yes |
| 9 | 0 | `locked` | yes |
| 10 | 0 | `VaultError locked: The vault is locked` | yes |
| 11 | 1 | Cancelled in the Mac's dialog: `VaultError cancelled: The passkey prompt ended with NotAllowedError` | yes |
| 12 | 0 | `empty` | yes |

### Run 5: Safari 27.2 × iPhone (hybrid)

2026-11-14 · macOS 27.2.1 (26B131) · Safari 27.2 (22625.2.8.11.9) · iPhone 15 Pro, iOS 26.6.2 · Vault `77d9845`

| Step | Prompts | Observed | Match |
|---|---|---|---|
| 1 | 1 | `passkey`, `unprotected`, `Ready` | yes |
| 2 | 1 | `verified   true`; flags `1d`, sign count 0 | yes |
| 3 | 2 | New Safari profile; credential id `7ccdba6b9400aeef…` in both; `passkey`, `unprotected` | yes |
| 4 | 1 | `verified   true`; `key` and `public key` those of step 2 | yes |
| 5 | 0 | `verified   true` | yes |
| 6 | 1 | `unlocked`, `Ready`; ed25519 Sign: no prompt | yes |
| 7 | 0 | `locked`, both keys | yes |
| 8 | 1 | The phone offered `Vault unlock` at once; `unlocked`; ed25519 Sign: no prompt | yes |
| 9 | 0 | `locked` | yes |
| 10 | 0 | `VaultError locked: The vault is locked` | yes |
| 11 | 1 | `VaultError cancelled: The passkey prompt ended with NotAllowedError` | yes |
| 12 | 0 | `empty` | yes |

### Run 6: Safari 27.2 × YubiKey

2026-11-14 · macOS 27.2.1 · Safari 27.2 · YubiKey firmware 5.4.3 · Vault `77d9845`

| Step | Prompts | Observed | Match |
|---|---|---|---|
| 1 | 1 | as expected | yes |
| 2 | 1 | `verified   true`; flags `05`, sign count 12 | yes |
| 3 | 1 | The first prompt answered as usual (key, PIN, touch, `run 6 key`), no second dialog: `VaultError cancelled: The passkey prompt ended with NotAllowedError`; the fresh profile stayed `empty` | no: a fault of Vault, #111 |
| 4 | — | skipped: nothing was added | — |
| 5 | 0 | `verified   true` | yes |
| 6 | 1 | `VaultError unavailable: The new passkey has no ES256 public key` | no: a fault of Vault, #110 |
| 7–12 | — | not run; the run was repeated as Run 6b | — |

Step 3, in the console, from page clicks: a discoverable `get()` succeeded; the same-id `get()` chained right after it was refused with `NotAllowedError` "The document is not focused."; from a new click it succeeded. `document.hasFocus()` was false right after the first prompt, the `focus` event came 575 ms later, and a `get()` after it succeeded with no new click. Fix: D-96.

Step 6, in the console: a creation with Vault's options and the PRF extension had flags `c5` (ED set) and well-formed authenticator data (an ES256 COSE key, then `hmac-secret: true`), yet `getPublicKeyAlgorithm()` was `0` and `getPublicKey()` `null`; without the extension, flags `45`, algorithm `-7` and the SPKI. Vault never uses the unlock passkey's public key. Fix: D-95.

### Run 6b: Safari 27.2 × YubiKey, after #110 and #111

2026-11-14 · macOS 27.2.1 · Safari 27.2 · YubiKey firmware 5.4.3 · Vault `53ac6c7`

| Step | Prompts | Observed | Match |
|---|---|---|---|
| 1 | 1 | as expected | yes |
| 2 | 1 | `verified   true`; flags `05`, sign count 11 | yes |
| 3 | 2 | The first try failed with `VaultError cancelled: The passkey prompt ended with NotAllowedError` (prompt count not noted); after reloading the fresh profile's page, two prompts and the row as expected. The cause of the first failure was not established | yes, after a reload |
| 4 | 1 | `verified   true`; `key` and `public key` those of step 2 | yes |
| 5 | 0 | as expected | yes |
| 6 | 2 | `unlocked`, `Ready`, both keys; ed25519 Sign: no prompt | yes |
| 7 | 0 | as expected | yes |
| 8 | 1 | `unlocked`; ed25519 Sign: no prompt. WebKit bug 311099 does not show | yes |
| 9 | 0 | as expected | yes |
| 10 | 0 | `VaultError locked: The vault is locked` | yes |
| 11 | 1 | `VaultError cancelled: The passkey prompt ended with NotAllowedError` | yes |
| 12 | 0 | as expected | yes |
