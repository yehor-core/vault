# WebAuthn PRF: research notes

Facts gathered for slice planning: protecting a vault's wrapping private key with a secret derived from the PRF output of one unlock passkey.
All sources fetched on 2026-11-13. "Unconfirmed" means no primary source was found. "Derived" means a conclusion drawn from the cited code or spec text, not stated by the source itself.

Short source names used below:

- **Spec**: W3C WebAuthn Level 3, https://www.w3.org/TR/webauthn-3/ (§10.1.4 prf, §5.1.7 getClientCapabilities, §11 WebDriver)
- **CTAP**: FIDO CTAP 2.2 PS, https://fidoalliance.org/specs/fido-v2.2-ps-20250714/fido-client-to-authenticator-protocol-v2.2-ps-20250714.html (§12.7 hmac-secret, §12.8 hmac-secret-mc)
- **Blink**: https://chromium.googlesource.com/chromium/src/+/main/third_party/blink/renderer/modules/credentialmanagement/authentication_credentials_container.cc
- **Chromium browser**: https://chromium.googlesource.com/chromium/src/+/main/content/browser/webauth/authenticator_common_impl.cc
- **Chromium device**: https://chromium.googlesource.com/chromium/src/+/main/device/fido/ (`make_credential_request_handler.cc`, `get_assertion_request_handler.cc`, `virtual_ctap2_device.cc`, `mac/icloud_keychain.mm`, `win/authenticator.cc`, `win/type_conversions.cc`, `enclave/enclave_protocol_utils.cc`)
- **GPM**: https://chromium.googlesource.com/chromium/src/+/main/chrome/browser/webauthn/gpm_browser_authenticator.cc and https://chromium.googlesource.com/chromium/src/+/main/components/webauthn/core/browser/passkey_model_utils.cc
- **Gecko**: https://github.com/mozilla-firefox/firefox/tree/main/dom/webauthn (`WebAuthnHandler.cpp`, `WebAuthnService.cpp`, `PublicKeyCredential.cpp`, `authrs_bridge/src/`)
- **authenticator-rs**: https://github.com/mozilla/authenticator-rs (default branch `ctap2-2021`, `src/ctap2/commands/make_credentials.rs`)
- **WebKit**: https://github.com/WebKit/WebKit/blob/main/Source/WebKit/UIProcess/WebAuthentication/Cocoa/WebAuthenticatorCoordinatorProxy.mm
- **BCD**: MDN browser-compat-data 8.1.9 (2026-11-12), `api.CredentialsContainer.{create,get}.publicKey_option.extensions.prf`, `api.PublicKeyCredential.getClientCapabilities_static`
- **Win**: https://github.com/microsoft/webauthn/blob/master/webauthn.h

## 1. How PRF works

- Inputs: `extensions.prf.eval = { first, second? }` (any-length BufferSource) and, at `get()` only, `evalByCredential`, a record from base64url credential ID to `{ first, second? }`. Source: Spec §10.1.4.
- Output: "The PRFs provided by this extension map from BufferSources of any length to 32-byte BufferSources." `getClientExtensionResults().prf.results.first` (and `.second` if asked) are 32-byte ArrayBuffers. Source: Spec.
- Salt handling by the client: `salt = SHA-256(UTF8Encode("WebAuthn PRF") || 0x00 || input)`. The authenticator never sees the raw input. This keeps WebAuthn PRF values apart from other hmac-secret uses on the platform. Source: Spec. Chromium does this in `PRFInput::HashInputsIntoSalts()` (Chromium browser). Windows `webauthn.h` does the same conversion unless the caller sets `WEBAUTHN_AUTHENTICATOR_HMAC_SECRET_VALUES_FLAG` (Win l.~528).
- On CTAP authenticators PRF runs on `hmac-secret`: `output = HMAC-SHA-256(CredRandom, salt)`. The salts and outputs travel encrypted under the PIN/UV shared secret, and the client decrypts them. Source: CTAP §12.7.
- Determinism: one PRF is bound to the credential "for the lifetime of the credential", so the same credential and the same input always give the same output. Source: Spec (abstract authenticator procedure), CTAP (CredRandom is fixed at makeCredential).
- Two PRFs per CTAP credential: the authenticator holds `CredRandomWithUV` and `CredRandomWithoutUV`, and picks one by the UV bit of the response. Source: CTAP §12.7.
- The WebAuthn PRF is the UV one: "when implementing on top of hmac-secret, that PRF MUST be the one used for when user verification is performed. This overrides the UserVerificationRequirement if necessary." For non-CTAP authenticators: "The choice of PRF MUST be independent of the state of user verification." Source: Spec.
- Chromium:
  - When PRF is requested, it raises `userVerification` to at least `preferred` for the authenticator (`AtLeastUVPreferred`), at create and at get.
  - If the authenticator can do UV but this request does no UV (`kNoUVRequired`), it drops the PRF inputs: "we mustn't evaluate any PRF because it would be the wrong one."
  - If the authenticator cannot do UV at all (`kUVNotSupportedNorRequired`), it still evaluates hmac-secret, so the output comes from `CredRandomWithoutUV`.
  - Source: Chromium device (`get_assertion_request_handler.cc` l.~228, ~409; `make_credential_request_handler.cc` l.~1065).
- Implication of `userVerification: 'required'` (derived): every assertion that succeeds has UV=1, so a CTAP key always uses `CredRandomWithUV` and the output is stable. Keys without UV are excluded (see `webauthn-passkey-keys.md` §6). Without `required`, a UV-less key gives the non-UV PRF. If the user later sets a PIN on that key, the client starts to do UV and the output changes. That would lock the vault.
- `hmac-secret-mc` (CTAP 2.2 §12.8) is the creation-time variant: "This extension processing is the same as the hmac secret extension's getAssertion processing", during makeCredential. It requires `hmac-secret: true` in the same request. It has no client (JS) surface; browsers map `prf.eval` at create onto it. Source: CTAP, Yubico (below).

## 2. PRF at `create()`

- `prf: {}` at create asks the client to enable PRF. `results.enabled` is true "if, and only if, the PRF is available for use with the created credential", and it "is only reported during registration". Source: Spec.
- `prf: { eval }` at create: "Not all authenticators support evaluating the PRFs during credential creation so outputs may, or may not, be provided. If not, then an assertion is needed in order to obtain the outputs." `evalByCredential` at create → `NotSupportedError`. Source: Spec. Chromium: `NotSupportedError` "The 'evalByCredential' field cannot be set when creating a credential." (Blink l.~1022). Firefox: `NotSupportedError` (Gecko `WebAuthnHandler.cpp` l.~305).
- The TR text still says creation-time evaluation waits for "a future extension to [FIDO-CTAP]". The editor's draft fetched the same day does not name `hmac-secret-mc` either. Source: Spec, https://w3c.github.io/webauthn/.
- Who returns `results` at creation:
  - **Chromium + CTAP security key**: only if the key advertises `prf`, or `hmac-secret` plus `hmac-secret-mc`. Otherwise Chromium drops `prf_input` ("Evaluating the PRF at creation time is only supported with the 'prf' extension"), and you get `enabled` only. Source: Chromium device `make_credential_request_handler.cc` l.~1065–1085.
  - **YubiKey**: `hmac-secret` from firmware 5.2, `hmac-secret-mc` from 5.8. "`hmac-secret-mc` completes in one user interaction at registration, while `hmac-secret` takes two (registration, then assertion)." Source: https://developers.yubico.com/Passkeys/Passkey_concepts/Security_key_capabilities/Pseudo-Random_Function_PRF_Support.html, https://docs.yubico.com/yesdk/users-manual/application-fido2/hmac-secret.html
  - **Chromium + Google Password Manager**: yes. The GPM authenticator sets `supports_prf = true`. On create it makes a random `hmac_secret`, evaluates `prf_input`, and returns `prf_results`. The enclave protocol also parses a PRF result in the makeCredential response. Source: GPM (`gpm_browser_authenticator.cc` l.~56, ~174–187; `passkey_model_utils.cc` l.~186–200, ~279); Chromium device `enclave/enclave_protocol_utils.cc` l.~477–580.
  - **Chromium on macOS + iCloud Keychain**: `supports_prf = true` from macOS 15. At create Chromium reads `platform_result.prf.isSupported` and `prf.first/second`. So results at create are passed through **if** AuthenticationServices returns them. Source: Chromium device `mac/icloud_keychain.mm` l.~256, ~629. Whether iCloud Keychain itself fills `first` at registration: **unconfirmed** (Apple docs did not load; no Apple statement found).
  - **Chromium on Windows**: webauthn.dll handles hmac-secret in all versions. `supports_hmac_secret_mc` needs `WEBAUTHN_API_VERSION_8`, and results at create come from `pHmacSecret` (attestation struct v7). Source: Chromium device `win/authenticator.cc` l.~66–68, `win/type_conversions.cc` l.~181–188; Win. Which Windows build ships API v8: **unconfirmed** by a Microsoft document.
  - **Safari**: WebKit passes `prf.eval` at create to `ASAuthorizationPublicKeyCredentialPRFRegistrationInput` (passkeys and, when the selector exists, security keys), and maps `prf.first/second` back if present. Source: WebKit l.~345–385, ~769–781. Safari 26.4: PRF works "during both credential creation and authentication flows with security keys". Source: https://webkit.org/blog/17862/webkit-features-for-safari-26-4/ (2026-03-24). iCloud Keychain results at create: **unconfirmed**.
  - **Firefox + authenticator-rs (Linux; macOS < 26.4 security keys)**: create returns `{ enabled }` and never `results` in practice, because authenticator-rs sends plain `hmac-secret: true` and has no `hmac-secret-mc`. Source: authenticator-rs `make_credentials.rs` l.~421–460 (comment: "If a future version of hmac-secret permits calculating secrets in makeCredential…").
  - **Android (Chrome, Firefox)**: requests go to Play Services / Credential Manager as JSON. Whether a given provider returns results at create: **unconfirmed**.
- Practical rule (derived): code must handle `results` missing at create. When it is missing, it needs a second `get()` with the same `eval` (a second prompt) to obtain the secret.

## 3. Support matrix

BCD (2026-11-12):

| | create | get |
|---|---|---|
| Chrome / Edge desktop | 116 | 116 |
| Chrome Android | 116 | 116 |
| Firefox desktop | 139 (135–138 "Not supported on macOS") | 139 (same) |
| Firefox Android | 149 | not listed (`false`, bug 1958716) |
| Safari / iOS Safari | 18 | `false` (webkit.org/b/259934) |

BCD's `get: false` for Safari is contradicted by WebKit source and release notes (below). Treat that BCD entry as stale.

- **Chromium**:
  - The 2023 Intent to Ship says all six Blink platforms. Caveats: "Some passkey providers on Android 14 may not support it"; Windows needs a recent OS version; security keys need `hmac-secret`. Source: https://groups.google.com/a/chromium.org/g/blink-dev/c/iTNOgLwD2bI
  - Authenticators in code with PRF: CTAP security keys (`hmac-secret` / `prf` in getInfo), GPM (`supports_prf`), iCloud Keychain on macOS 15+, and Windows webauthn.dll (hmac-secret on all versions). Source: Chromium device, GPM.
  - Windows Hello (the platform authenticator) producing PRF: **unconfirmed** (only forum reports). Chrome profile-local passkeys on desktop: **unconfirmed**.
- **Safari / WebKit**:
  - Safari 18.0 added PRF for passkeys: it "lets a site retrieve a symmetric key from a passkey and use it to encrypt user data". Source: https://webkit.org/blog/15865/webkit-features-in-safari-18-0/
  - `get()` maps `eval` and `evalByCredential` to `ASAuthorizationPublicKeyCredentialPRFAssertionInput` (with `perCredentialInputValues`). Source: WebKit l.~476–526.
  - Security keys: PRF and hmac-secret landed in WebKit 2025-11-21 (b/259934), and shipped in Safari 26.4 (2026-03-24). Before that, PRF at create with a security key crashed in STP 234 (b/259934 comments, 2026-01-08). Safari 26.4 then returned the **still-encrypted** hmac-secret output, so outputs differed from Chrome. The reporter says this is fixed in STP 241 (2026-04-09), but the bug is still NEW. Which shipping Safari has the fix: **unconfirmed**. Source: https://bugs.webkit.org/show_bug.cgi?id=259934, https://bugs.webkit.org/show_bug.cgi?id=311099
- **Firefox**:
  - Windows: forwards PRF to webauthn.dll (`bEnablePrf`, `pPRFGlobalEval`). Source: Gecko `WinWebAuthnService.cpp` l.~331–649.
  - macOS: uses AuthenticationServices PRF. Below macOS 26.4, it sends PRF requests that look like security-key requests to authenticator-rs, because "the security key API cannot evaluate the PRF extension" there. Platform passkeys got PRF in macOS 15.0. Source: Gecko `WebAuthnService.cpp` l.~22–140, ~300–315.
  - Linux: authenticator-rs (USB CTAP2 keys) implements PRF over hmac-secret, with `enabled` only at create. Source: authenticator-rs.
  - Android: PRF since 149, through the JSON request passed to Play Services ("support would come for free" via bug 2008744). Source: https://bugzilla.mozilla.org/show_bug.cgi?id=1958716
- **Third-party providers**:
  - 1Password (2024-07-18): "PRF support is available now in the latest 1Password for Android beta (8.10.38) and browser extension beta (2.26.1)"; iOS 18 was planned. Source: https://1password.com/blog/encrypt-data-saved-passkeys
  - Bitwarden's post (2025-02-05) covers Bitwarden only as a PRF *relying party* (vault unlock). Bitwarden as a PRF *provider*: **unconfirmed**. Source: https://bitwarden.com/blog/prf-webauthn-and-its-role-in-passkeys/
  - A browser-extension provider intercepts `navigator.credentials` itself, so the browser's PRF code does not apply to it (derived).
- **Reported by Yubico's PRF developer guide** (quoted by the user during S6 planning, 2026-11-13; URL and wording not recorded here, so treat as **unconfirmed** until fetched): Windows Hello does not implement hmac-secret, and Safari on iOS does not pass PRF to YubiKeys. The same guide recommends treating the PRF output as input keying material (import it as a non-extractable HKDF key, derive the working key with `info` bound to its purpose), a random salt per credential stored next to the credential id, and a KEK/DEK scheme where the PRF-derived key wraps another key rather than the data.
- **Bitwarden "Log in with passkeys"** (same provenance): PRF output → HKDF → an encryption key and a MAC key; these encrypt the private key of an asymmetric key pair kept per passkey; that pair's public key encrypts the user's symmetric key.

## 4. Feature detection

- `getClientCapabilities()`: "The set of keys SHOULD also contain a key for each extension implemented by the client … prefixing the string `extension:`". A missing key means unknown. "Note that even if an extension is mapped to true, the authenticator used for any given operation may not support that extension, so Relying Parties MUST NOT assume that the authenticator processing steps for that extension will be performed on that basis." Source: Spec §5.1.7.
- Shipped: Chrome 133, Firefox 135 (desktop and Android), Safari 17.4. Source: BCD.
- Chromium reports `extension:prf: true` as a **constant** on every platform. Source: https://chromium.googlesource.com/chromium/src/+/main/third_party/blink/renderer/modules/credentialmanagement/public_key_credential.cc (l.~86)
- Firefox reports `extension:prf: true` as a constant on every platform, Android included. Source: Gecko `PublicKeyCredential.cpp` l.~215.
- Safari takes the capability map from a closed AuthenticationServices SPI (`getClientCapabilitiesForRelyingParty:`). Without that SPI it reports only `relatedOrigins`. Whether Safari reports `extension:prf`: **unconfirmed**. Source: WebKit l.~1435–1455.
- So `extension:prf` means only "this browser knows the extension". It does not mean the passkey the user picks will produce PRF. The only real test is a ceremony: `enabled`, then `results` (derived from the above).
- `isUserVerifyingPlatformAuthenticatorAvailable()` (Chrome 67, Firefox 60, Safari 13; BCD) and the `userVerifyingPlatformAuthenticator` capability say nothing about PRF (Spec §5.1.7 lists no PRF-related ClientCapability).

## 5. Failure shapes

- Authenticator without PRF, at **create**: no error. `prf: { enabled: false }` and no `results`:
  - Spec: "If not present, set enabled to false."
  - Chromium sets `enabled` from `prf_enabled` or the `hmac-secret: true` flag in authData (Chromium browser l.~3209–3245).
  - authenticator-rs returns `enabled: false` when authData has no hmac-secret.
  - Safari returns `prf.isSupported` (WebKit l.~779).
- Authenticator without PRF, at **get**: no error. The spec initializes "the prf extension output to an empty dictionary", so you get `prf: {}` with no `results`. Chromium always echoes `prf` when it was requested and sets `results` only if hmac-secret output came back (`credential_manager_type_converters.cc` l.~258–275). The same `{}` appears when Chromium drops the inputs because no UV happened (§1). Source: Spec, Blink.
- Other errors:
  - At get, `evalByCredential` with an empty `allowCredentials` → `NotSupportedError`.
  - A bad base64url key, an empty key, or a key not in `allowCredentials` → `SyntaxError` (Spec; Chromium messages "'prf' extension contains invalid base64url data in 'evalByCredential'" / "…key that doesn't match any in allowedCredentials").
  - Chromium also rejects inputs over `kMaxPRFInputSize` ("'prf' extension contains excessively large input"): `NotSupportedError` at create, `SyntaxError` at get. Source: Blink l.~1001–1070, ~1957, ~2356.
- Credential created **without** PRF, used with PRF later:
  - Spec allows it: the abstract authenticator does "initialize the association if uninitialized" at evaluation time.
  - CTAP: "Authenticator SHOULD generate CredRandomWithUV/CredRandomWithoutUV … even if hmac-secret extension is not present in authenticatorMakeCredential request." It is a SHOULD, so an older key may return nothing.
  - GPM: if no `hmac_secret` was stored at create, it derives one with `HKDF(private_key, info="derived PRF HMAC secret")`. A GPM passkey made without `prf` still gives PRF output at get. Source: GPM `passkey_model_utils.cc` l.~98–107, ~202–209.
  - iCloud Keychain / Windows Hello: **unconfirmed**.
- Synced passkeys:
  - GPM stores `hmac_secret` (or derives it from the private key) inside the encrypted, synced passkey entity, so every GPM device computes the same output (derived from GPM code).
  - iCloud Keychain sync giving the same output: **unconfirmed** (no Apple statement found).
  - Across browsers on one CTAP key, outputs match, except Safari 26.4's encrypted-output bug (§3).

## 6. Test automation

- **Chromium CDP `WebAuthn.addVirtualAuthenticator`**: `hasPrf`, `hasHmacSecret` and `hasHmacSecretMc`, all default false. Source: https://github.com/ChromeDevTools/devtools-protocol/blob/master/pdl/domains/WebAuthn.pdl
  - They need no special `ctap2Version`. Only largeBlob, credBlob and minPinLength need ctap2_1. Source: https://chromium.googlesource.com/chromium/src/+/main/content/browser/devtools/protocol/webauthn_handler.cc (l.~290–301)
  - Results at create: **yes** with `hasPrf: true` (virtual device evaluates `prf_input` at makeCredential) or with `hasHmacSecret` + `hasHmacSecretMc`. With `hasHmacSecret` alone: only `enabled`. Source: Chromium device `virtual_ctap2_device.cc` l.~1264–1300, ~1485–1493.
  - At get, the virtual device evaluates PRF **only if `user_verified`**, so use `hasUserVerification: true, isUserVerified: true`. The HMAC key is random per credential (`RAND_bytes`), so outputs are deterministic per created credential. Source: `virtual_ctap2_device.cc` l.~1270–1280, ~1834.
  - `addCredential` has no field for a PRF/hmac secret, so an injected credential cannot be given a known PRF key. Source: WebAuthn.pdl `Credential` type.
- **Playwright `browserContext.credentials` (1.61+, main is 1.66.0-next)**: **no PRF**. The shim hard-codes `getClientExtensionResults = () => ({})`, and neither the injected nor the server side mentions prf/hmac/extensions. Source: https://github.com/microsoft/playwright/blob/main/packages/injected/src/webAuthn.ts (l.~131), https://github.com/microsoft/playwright/blob/main/packages/playwright-core/src/server/credentials.ts
- **WebDriver (spec §11)**: Add Virtual Authenticator takes `extensions` ("An array containing extension identifiers"), and the capability `"webauthn:extension:prf"` says whether the implementation supports PRF. Source: Spec §11.1.1, §11.3.
  - Firefox's test token implements PRF with an identity function: "Not much point in using an actual PRF here, the identity function will work" (output = salt). Its `AddVirtualAuthenticator` has no `extensions` argument. Source: Gecko `authrs_bridge/src/test_token.rs` l.~458–475, `lib.rs` l.~1454.
  - Playwright exposes neither Firefox nor WebKit virtual authenticators (see `webauthn-passkey-keys.md` §9). WebKit virtual authenticator PRF: **unconfirmed**.
- Derived: in this repo's stack, PRF can only be tested end-to-end in Chromium through `cdp()` (Vitest Browser Mode) or Playwright CDP. Firefox and WebKit unit tests need a hand-written fake of `navigator.credentials`.

## 7. User activation

- PRF adds no activation rule. Spec §5.1.3/§5.1.4 require transient activation only for `create()` in a cross-origin iframe, and §10.1.4 adds nothing. Source: Spec.
- No PRF-specific activation or gesture check was found in Blink, Gecko or WebKit `AuthenticatorCoordinator.cpp`. Source: Blink, Gecko, WebKit (grep for activation/gesture).
- Safari: the gesture requirement for WebAuthn was removed in iOS 17.4 / macOS 14.4, with a rate limiter instead. PRF needs Safari 18+, so every PRF-capable Safari falls under the no-gesture rule. Source: `webauthn-passkey-keys.md` §8 (Apple forum thread 747036); derived for PRF.
- Chromium still requires page focus (`NOT_FOCUSED`) for any `get()`. Source: `webauthn-passkey-keys.md` §8.

## 8. Several credentials in one `get()`

- Allowed: `allowCredentials` with several ids, plus `evalByCredential` keyed by base64url id. The client uses the entry "whose key is the base64url encoding of the credential ID that will be returned", or else `eval`. Only one credential comes back per ceremony (the one the user picks), and with it the PRF results for that credential. Source: Spec §10.1.4.
- Implemented:
  - Chromium sorts and checks the keys against `allowCredentials` (Blink l.~1030–1070); the browser side keeps them sorted by id (Chromium browser l.~507–545).
  - WebKit uses `perCredentialInputValues` (WebKit l.~481–526).
  - Firefox passes the per-credential values to macOS (`ConstructPrfEvalByCredentialEntries`) and to Windows.
  - Windows has `WEBAUTHN_CRED_WITH_HMAC_SECRET_SALT` lists (Win l.~548–565).
- Chromium caps `allowCredentials` at 64 entries (see `webauthn-passkey-keys.md` §2).
- The project has decided on exactly one unlock passkey per vault. This section only records that the platform could do more.
