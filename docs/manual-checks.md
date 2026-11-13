# Manual passkey checks

Playwright can drive real WebAuthn only in Chromium, through its virtual authenticator. In Firefox and WebKit the e2e tests run against Playwright's stand-in for `navigator.credentials`, which can't decline a prompt, drop user verification or return a PRF result (README, "Browser support"). The passkey paths there are checked by hand, on the published demo, with the checklist below; each run is logged at the end of this file.

## What each run records

- Date.
- macOS version.
- Browser and version (Safari → About Safari; Firefox → About Firefox).
- Authenticator and firmware: iCloud Keychain, or the YubiKey and its firmware as Yubico Authenticator shows it.
- Vault commit: the commit of `main` the Pages demo was built from (the latest run of the Pages workflow).
- For each checklist step: the observed result, the number of prompts, and whether it matches the expected result.

A prompt is one passkey dialog the browser opens for one WebAuthn call. A YubiKey PIN and touch asked inside that dialog are part of it.

## Pairs and order

All runs are on one Mac, on the Pages demo, https://yehor-core.github.io/vault/. Each pair runs the whole checklist.

On macOS 15.1, with Safari 18.6:

1. Safari × iCloud Keychain
2. Safari × YubiKey
3. Firefox × iCloud Keychain
4. Firefox × YubiKey

Then macOS is updated to a version that offers Safari 26.4 or later, and Safari is updated:

5. Safari × iCloud Keychain
6. Safari × YubiKey

Firefox is 139 or later: 135–138 have no PRF on macOS. The Firefox pairs run before the macOS update: below macOS 26.4, Firefox reaches security keys through authenticator-rs, and that is the path these runs record.

The YubiKey has firmware 5.4.3 and a FIDO2 PIN set. Firmware 5.4.3 has `hmac-secret` but no `hmac-secret-mc`, so it returns no PRF result at creation in any browser.

## Expected prompts per pair

| Step | Safari × iCloud Keychain | Safari 18.6 × YubiKey | Safari 26.4+ × YubiKey | Firefox × iCloud Keychain | Firefox × YubiKey |
|---|---|---|---|---|---|
| 1. Generate a passkey key | 1 | 1 | 1 | 1 | 1 |
| 2. Sign with it | 1 | 1 | 1 | 1 | 1 |
| 3. Add it in a fresh profile | 2 | 2 | 2 | 2 | 2 |
| 4. Sign there | 1 | 1 | 1 | 1 | 1 |
| 5. Generate an ed25519 key and sign | 0 | 0 | 0 | 0 | 0 |
| 6. Protect | 1 or 2: unconfirmed until run | 1, then `unsupported` | 2 | 1 or 2: unconfirmed until run | 2 |
| 7. Reload: locked | 0 | skipped | 0 | 0 | 0 |
| 8. Unlock | 1 | skipped | 1 | 1 | 1 |
| 9. Lock | 0 | skipped | 0 | 0 | 0 |
| 10. Sign with a sealed key while locked | 0 | skipped | 0 | 0 | 0 |
| 11. Cancelled prompt | 1 | 1 | 1 | 1 | 1 |
| 12. Wipe | 0 | 0 | 0 | 0 | 0 |

At `protect()`, one prompt means the creation returned the PRF result; two mean it returned only `prf.enabled: true` and Vault asked for the new passkey again at once. With the YubiKey it is two in every browser that has security-key PRF. Whether iCloud Keychain returns the PRF result at creation is unconfirmed; the iCloud Keychain runs answer it, and either count is a correct path. Safari 18.6 has no PRF for security keys (it shipped in Safari 26.4), so `protect()` fails with `unsupported` after the creation and steps 7 to 10 are skipped.

## Checklist

Before the run:

0. Record the run's fields (above). With the YubiKey, open Yubico Authenticator → Passkeys and delete every credential for `yehor-core.github.io`; with iCloud Keychain, delete the passkeys for `yehor-core.github.io` in the Passwords app. Open the demo in the browser's usual profile, the first profile. If State is not `empty`, click Wipe vault.

In each prompt, pick the pair's authenticator: iCloud Keychain, or the security key (insert and touch the YubiKey, enter its PIN). Every result below is read from the page: the State line, the status line under it (`Ready`, or `VaultError <code>: …` on a failure), the key table, and `verified` under Last signature.

| Step | Do | Expected |
|---|---|---|
| 1. Generate a passkey key | Key type `passkey`, Label `run N key`, Generate key | A row of type `passkey` with a credential id; State `unprotected`; status `Ready` |
| 2. Sign with it | That row's Sign | The dialog lists `run N key`; Last signature shows the full `public key` line, `authenticator data`, `client data` and `verified   true` |
| 3. Add it in a fresh profile | Open a fresh profile (README, walkthrough step 4) and the demo in it; State is `empty`. Label `run N key`, Add existing passkey, pick `run N key` both times | A row of type `passkey` whose id and credential id are the ones of step 1; State `unprotected` |
| 4. Sign there | That row's Sign | `verified   true`; the `public key` line is the one of step 2 |
| 5. Generate an ed25519 key and sign | Back in the first profile: Key type `ed25519`, Generate key, then its row's Sign | No prompt; `verified   true` |
| 6. Protect | Protect with a passkey | State `unlocked`, status `Ready`, both keys still listed; Sign of the ed25519 key: no prompt, `verified   true`. Safari 18.6 × YubiKey: status `VaultError unsupported: …`, State `unprotected`, both keys listed, and the ed25519 key still signs |
| 7. Reload: locked | Reload the page | State `locked`; both keys listed |
| 8. Unlock | Unlock, pick the unlock passkey (`Vault unlock` in the dialog) | State `unlocked`; Sign of the ed25519 key: no prompt, `verified   true` |
| 9. Lock | Lock | State `locked`, no prompt |
| 10. Sign with a sealed key while locked | The ed25519 row's Sign | No prompt; status `VaultError locked: …`; Last signature unchanged; State `locked` |
| 11. Cancelled prompt | Unlock, then cancel the dialog. Safari 18.6 × YubiKey (vault not protected): the passkey row's Sign, then cancel | Status `VaultError cancelled: …`; State as before (`locked`; `unprotected` for Safari 18.6 × YubiKey); both keys listed |
| 12. Wipe | Wipe vault, in the first profile and in the fresh one; then delete the fresh profile | No prompt; State `empty`; no keys |

After the run: clear the authenticator as in step 0. `wipe()` removes nothing at the authenticator: the passkey key and the unlock passkey stay on it, and a failed `protect()` leaves its unlock passkey there too. The YubiKey holds 25 discoverable credentials (firmware below 5.7) and each run adds two.

## On a failure

A step that does not match its expected result is logged as it went, with:

- Vault's error code, from the status line (`VaultError <code>: …`), or the browser's error if it is not a `VaultError`.
- Whether the vault changed: the key table and State compared with before the step.
- State afterwards.

A failure caused by the browser or the authenticator is not fixed: the README matrix and DESIGN.md's known limitations state what fails and with which error. It is Vault's fault, and a bug ticket with a test, when the error is misclassified, the vault changed, or a protected vault became unprotected.

Known risk: Safari 26.4 returned a still-encrypted PRF output from security keys (WebKit bug 311099); which shipping Safari has the fix is unconfirmed. In Safari 26.4+ × YubiKey, `protect()` succeeding and `unlock()` failing is this bug.

## Run log

No runs yet.
