# WebAuthn passkey keys: research notes

Facts gathered for slice planning (passkey as a signing key; PRF is out of scope).
All sources fetched on 2026-11-12. "Unconfirmed" means no primary source was found.

Short source names used below:

- **Spec**: W3C WebAuthn Level 3, https://www.w3.org/TR/webauthn-3/
- **CTAP**: FIDO CTAP 2.2 PS, https://fidoalliance.org/specs/fido-v2.2-ps-20250714/fido-client-to-authenticator-protocol-v2.2-ps-20250714.html
- **Blink**: https://chromium.googlesource.com/chromium/src/+/main/third_party/blink/renderer/modules/credentialmanagement/authentication_credentials_container.cc
- **Gecko**: https://github.com/mozilla-firefox/firefox/blob/main/dom/webauthn/WebAuthnHandler.cpp
- **WebKit**: https://github.com/WebKit/WebKit/blob/main/Source/WebCore/Modules/webauthn/AuthenticatorCoordinator.cpp
- **BCD**: MDN browser-compat-data, https://github.com/mdn/browser-compat-data/tree/main/api (`AuthenticatorAttestationResponse.json`, `PublicKeyCredential.json`, `CredentialsContainer.json`)

## 1. Challenge length and encoding

- Spec sets no hard limit; it says challenges "SHOULD therefore be at least 16 bytes long" (§13.4.3). Source: Spec.
- Chromium enforces no minimum. The only maximum is the `wtf_size_t` overflow check (`IsArrayBufferOrViewBelowSizeLimit`), which throws `RangeError` "The `challenge` attribute exceeds the maximum allowed size". Source: Blink.
- Firefox enforces no minimum and no maximum. It copies the buffer, and a failed copy gives `SecurityError`. Source: Gecko (lines ~212, ~460).
- WebKit has no challenge-length check in WebCore. Source: WebKit.
- In `clientDataJSON`, `challenge` is "the base64url encoding of the challenge" (§5.8.1). Base64url means the RFC 4648 §5 alphabet "with all trailing '=' characters omitted" (§2 Terminology). Source: Spec.

## 2. `user.id`, overwriting, `excludeCredentials`

- `user.id` must be 1 to 64 bytes, otherwise `TypeError` (§5.1.3 step 5). Source: Spec. Chromium throws TypeError "User handle exceeds 64 bytes" (Blink). Firefox throws TypeError "user.id is too long" (Gecko l.158). WebKit has the same 1..64 check (WebKit l.180).
- Spec: `user.id` "is used to overwrite existing discoverable credentials that have the same rp.id and user.id on the same authenticator". The authenticator model stores `credentials[(rpId, userHandle)]`, so a second one replaces the first (§5.4.3, §6.3.2). Source: Spec.
- CTAP2 security keys: "If a credential for the same rp.id and account ID already exists on the authenticator: … Overwrite that credential." The old largeBlob data MAY be left orphaned (§6.1.2 authenticatorMakeCredential). Source: CTAP.
- Apple passkeys: an Apple Systems Engineer says "If you create a new passkey with the same `userID` as an existing one, the existing passkey gets updated." Source: https://developer.apple.com/forums/thread/730082. WebKit's own `LocalAuthenticator::deleteDuplicateCredential()` deletes the older keychain item that has the same user handle. Source: https://github.com/WebKit/WebKit/blob/main/Source/WebKit/UIProcess/WebAuthentication/Cocoa/LocalAuthenticator.mm
- Google Password Manager and Windows Hello: overwrite behaviour **unconfirmed** (no vendor doc found).
- Chromium's virtual CTAP2 device deletes an existing registration with the same RP and user ID. Source: https://github.com/chromium/chromium/blob/main/device/fido/virtual_ctap2_device.cc (l.~1448)
- `excludeCredentials`: if the authenticator holds a listed credential, the error is `InvalidStateError`, and only "after the user consented". Every other authenticator error stays hidden (§5.1.3, §5.1.3.1). Source: Spec. Chromium caps `excludeCredentials`/`allowCredentials` at 64 entries (`RangeError`). Source: Blink.
- A credential that is overwritten keeps nothing of the old key: the replaced public key is gone. The spec notes an RP may not know whether a second registration with the same user handle "will evict the first" (§5.4.6 note). Source: Spec.

## 3. `getPublicKey()`, `getPublicKeyAlgorithm()`, `getAuthenticatorData()`

- Shipped in Chrome 85, Firefox 119, Safari 16, all three methods. Source: BCD `AuthenticatorAttestationResponse.json`.
- `getPublicKey()` "returns the DER SubjectPublicKeyInfo of the new credential, or null if this is not available". UAs MUST return non-null for -7 (ES256, P-256, uncompressed), -257 (RS256) and -8 (Ed25519) (§5.2.1.1). Source: Spec.
- Safari returns `null` for EdDSA and RS256 (BCD note: "Returns `null`. See bug 312081", https://webkit.org/b/312081). ES256 works from Safari 16. Source: BCD.
- `getPublicKeyAlgorithm()` returns the COSEAlgorithmIdentifier. Spec recommends feature detection with `'getPublicKey' in AuthenticatorAttestationResponse.prototype`. Source: Spec.

## 4. Algorithms

- ES256 (-7): Apple passkeys support **only** ES256 ("Passkeys only support ES256 … -7 … not configurable", Apple Systems Engineer). Source: https://developer.apple.com/forums/thread/710784
- Chromium: "`RS256` is necessary for compatibility with Microsoft Windows platform authenticators"; ES256 "is compatible with most other platform authenticators and roaming authenticators". Leaving out either default (-7, -257) risks registration failures. Source: https://chromium.googlesource.com/chromium/src/+/main/content/browser/webauth/pub_key_cred_params.md
- Windows: "Starting in Windows 11, version 22H2, WebAuthn APIs support ECC algorithms." Source: https://learn.microsoft.com/en-us/windows/security/identity-protection/hello-for-business/webauthn-apis. Whether Windows Hello itself creates ES256 credentials on 22H2+ is **unconfirmed**.
- YubiKey 5: ECC P-256 on firmware 5.0+, EdDSA/Ed25519 on 5.3+, P-384 on 5.6+. Source: https://docs.yubico.com/hardware/yubikey/yk-tech-manual/yk5-apps-fido.html
- EdDSA on Apple: not supported (ES256 only, above). On Google Password Manager: **unconfirmed** (Google docs recommend only `[-7, -257]`: https://developers.google.com/identity/passkeys/developer-guides/server-registration). On Windows Hello: **unconfirmed**.
- Chromium virtual authenticator supports ES256, RS256 and EdDSA. Source: https://github.com/chromium/chromium/blob/main/device/fido/virtual_fido_device.cc

## 5. Discoverable credentials

- An empty `allowCredentials` can only find discoverable credentials. Only `residentKey: 'required'` guarantees one. With `'preferred'`, the client may skip discoverable storage, and the client "may not return a value for the rk property" (§5.4.6, §10.1.3). Source: Spec.
- `credProps.rk`: true means discoverable, false means server-side, absent means unknown. Spec says a missing `rk` "indicates that the created credential is most likely a non-discoverable credential" (§10.1.3). Support: Chrome 89, Firefox 119, Safari not supported. Source: Spec, BCD.
- `residentKey` option: BCD lists Chrome 89 and Firefox 114, and Safari as `false`. Real Safari behaviour is **unconfirmed** (Apple passkeys are always discoverable). Source: BCD.
- YubiKey 5 slots: 25 discoverable credentials before firmware 5.7. "FIDO2 has been increased to 100 discoverable credentials (aka Passkeys)" in 5.7. Sources: https://docs.yubico.com/hardware/yubikey/yk-tech-manual/yk5-firmware-5.7.html, https://docs.yubico.com/hardware/yubikey/yk-tech-manual/yk5-apps-fido.html (that page still says "up to 25").
- Firefox on Linux uses authenticator-rs, which supports CTAP2 security keys. "Firefox supports passkeys stored on USB security keys on Linux" is a Mozilla statement relayed on Mozilla Connect; I did not see a first-hand source, so the discoverable `get()` without `allowCredentials` on Linux + security key is **unconfirmed by primary source**.
- Hybrid (QR, cross-device):
  - Chrome: supported on Android, iOS 17+, macOS, Windows, Linux and ChromeOS. Source: https://developers.google.com/identity/passkeys/supported-environments
  - Firefox: on macOS and Windows hybrid comes from the OS. On Linux it is **not implemented**: Bugzilla 1543674 "Implement CTAP2 hybrid transport … for platforms that use authenticator-rs (e.g. Linux)" is ASSIGNED, not fixed. Sources: https://bugzilla.mozilla.org/show_bug.cgi?id=1543674, https://bugzilla.mozilla.org/show_bug.cgi?id=1895756
  - Safari: Apple says "you can even use your iPhone to sign in … on non-Apple devices". Versions and QR details are **unconfirmed**. Source: https://developer.apple.com/passkeys/

## 6. `userVerification: 'required'`

- At create, the client skips authenticators that cannot do UV ("set to required and the authenticator is not capable of performing user verification, continue"). If none is left, the documented error is `ConstraintError` (§5.1.3, §5.1.3.1). Source: Spec.
- Chromium can instead raise `NotSupportedError` "The specified `userVerification` requirement cannot be fulfilled by this device unless the device is secured with a screen lock" (`USER_VERIFICATION_UNSUPPORTED`). Source: Blink (l.~1341).
- Firefox (authenticator-rs) maps every error except `CredentialExcluded` to `NotAllowedError`. Source: https://github.com/mozilla-firefox/firefox/blob/main/dom/webauthn/authrs_bridge/src/lib.rs (`authrs_to_nserror`)
- UV is flags bit 2 (0x04) of authenticatorData (§6.1). RP step: "If user verification was determined to be required, verify that the UV bit of the flags in authData is set. Otherwise, ignore the value of the UV flag" (§7.2). The RP must still check it, because the client and authenticator are not trusted to enforce it. Source: Spec.

## 7. Error names

| Case | Spec | Chromium | Firefox | WebKit |
|---|---|---|---|---|
| User cancels | `NotAllowedError` (catch-all) | `NotAllowedError` "timed out or was not allowed" | `NotAllowedError` | `NotAllowedError` |
| Timeout | `NotAllowedError` | `NotAllowedError` (same message) | `NotAllowedError` | `NotAllowedError` (unconfirmed exact path) |
| No matching credential (get) | `NotAllowedError` | `NotAllowedError` | `NotAllowedError` | `NotAllowedError` "No matched credentials are found in the platform attached authenticator." |
| No transient activation (cross-origin iframe create) | `NotAllowedError` | `NotAllowedError` "A user activation is required to create a credential in a cross-origin iframe." | — | legacy: `NotAllowedError` "This request has been cancelled by the user." |
| `excludeCredentials` match | `InvalidStateError` | `InvalidStateError` | `InvalidStateError` | `InvalidStateError` |
| No supported algorithm | `NotSupportedError` (§5.1.3.1) | `NotSupportedError` (`ALGORITHM_UNSUPPORTED`) on some platforms; a security key's `CTAP2_ERR_UNSUPPORTED_ALGORITHM` may surface as `NotAllowedError` (unconfirmed) | `NotSupportedError` only if no entry has type `public-key`; otherwise `NotAllowedError` | `NotSupportedError` "doesn't support any provided PublicKeyCredentialParameters" |
| Page not focused | — | `NotAllowedError` (`NOT_FOCUSED`) | unconfirmed | `NotAllowedError` "The document is not focused." (get) |
| Aborted via signal | `AbortError` | `AbortError` | `AbortError` | `AbortError` |

Sources: Spec §5.1.3.1/§5.1.4.1; Blink `AuthenticatorStatusToDOMException` (l.~1305–1466); Gecko + authrs_bridge; WebKit `LocalAuthenticator.mm` (l.370, 389, 713) and `WebAuthenticatorCoordinatorProxy.cpp` (l.207). The WebKit `LocalAuthenticator` path is WebKit's open-source authenticator. Safari on current macOS/iOS goes through closed-source AuthenticationServices, so its exact error messages are **unconfirmed**. Treat `NotAllowedError` as covering cancel, timeout, no-credential and most failures in every engine.

## 8. User activation

- Spec: transient activation is required, and consumed, **only** for `create()` in a cross-origin iframe (`sameOriginWithAncestors` false) (§5.1.3 step 2). `get()` needs none. Source: Spec.
- Chromium follows the spec: `ConsumeTransientUserActivation` only for cross-origin-iframe `create()`. `get()` checks activation only for the experimental "immediate" mediation. Same-origin calls also need page focus (`NOT_FOCUSED`). Source: Blink (l.~1983, ~2280).
- Firefox: no activation check in `WebAuthnHandler.cpp` for `create()` or `get()`. Source: Gecko.
- Safari: "the user gesture requirement was removed as of iOS 17.4 and macOS 14.4 … there's a new rate limiting mechanism with a progressive backoff if too many requests come in close together" (Apple Systems Engineer). Source: https://developer.apple.com/forums/thread/747036. Current WebKit WebCore/WebProcess code has no gesture check (only a document-focus check for `get()`). Source: WebKit.
- Before 17.4, Safari used the media-gesture model. A gesture was lost across `fetch()` and other async boundaries, and calls without a gesture lost Touch ID / Face ID. Sources: https://bugs.webkit.org/show_bug.cgi?id=213595, https://bugs.webkit.org/show_bug.cgi?id=214380
- Awaiting IndexedDB or WebCrypto before the call: harmless in Chromium and Firefox (no activation needed). Harmless in Safari ≥ 17.4 / macOS 14.4 for top-level same-origin calls. On older Safari it could lose the gesture; that exact IDB/WebCrypto behaviour is **unconfirmed**. For a cross-origin iframe `create()`, the HTML transient-activation window (a few seconds) applies in all engines.
- Safari rate limiter thresholds: **unconfirmed** (not published).

## 9. Test automation

- **Playwright `browserContext.credentials` (1.61+)**, "works in all browsers": `install()`, `create(rpId, {id, userHandle, privateKey, publicKey, signCount})`, `get({id, rpId})`, `delete(id)`. Sources: https://playwright.dev/docs/api/class-credentials, https://playwright.dev/docs/release-notes
  - It is a **JS shim**, not the browser's WebAuthn stack. It overrides `navigator.credentials.create/get` and builds objects on the real prototypes. The server signs with Node `crypto.sign` (DER) using a P-256 key. Source: https://github.com/microsoft/playwright/blob/main/packages/injected/src/webAuthn.ts, https://github.com/microsoft/playwright/blob/main/packages/playwright-core/src/server/credentials.ts
  - Limits read from that source:
    - It always uses ES256 (`getPublicKeyAlgorithm() → -7`) and ignores `pubKeyCredParams`.
    - The flags are always UP|UV, so a UV failure cannot be simulated.
    - `getClientExtensionResults()` is `{}`, so there is no credProps, largeBlob or PRF.
    - There is no cancel or timeout simulation, and no user-activation or focus check.
    - `excludeCredentials` match → `InvalidStateError`. No match → `NotAllowedError`.
    - A discoverable `get()` returns the first resident credential for the rpId.
    - It does **not** overwrite on the same `user.id`.
- **Chromium CDP `WebAuthn` domain** (Chromium only). Source: https://github.com/ChromeDevTools/devtools-protocol/blob/master/pdl/domains/WebAuthn.pdl
  - `addVirtualAuthenticator` options:
    - `protocol` and `ctap2Version`
    - `transport`
    - `hasResidentKey` (default false)
    - `hasUserVerification` (default false)
    - `hasLargeBlob`, `hasCredBlob`, `hasMinPinLength`, `hasPrf`, `hasHmacSecret`
    - `automaticPresenceSimulation`: "If set to true, tests of user presence will succeed immediately. Otherwise, they will not be resolved. Defaults to true."
    - `isUserVerified` (default false)
    - `defaultBackupEligibility` and `defaultBackupState`
  - Other commands:
    - `enable({enableUI})`
    - `addCredential`, `getCredential(s)`, `removeCredential`, `clearCredentials`
    - `setUserVerified`, `setAutomaticPresenceSimulation`
    - `setResponseOverrideBits({isBogusSignature, isBadUV, isBadUP})`
    - `setCredentialProperties`
  - Events: `credentialAdded`, `credentialAsserted`, `credentialDeleted`, `credentialUpdated`.
  - To simulate a cancelled prompt: `setAutomaticPresenceSimulation(false)` plus a short `timeout` → `NotAllowedError`. When a virtual authenticator is enabled, Chromium uses the page's `timeout` **unclamped**. Normally it clamps to [3 min, 20 h]. Source: https://chromium.googlesource.com/chromium/src/+/main/content/browser/webauth/authenticator_common_impl.cc (`AdjustTimeout`), https://github.com/chromium/chromium/blob/main/device/fido/public/fido_constants.cc
  - Firefox's own timeout clamp is [15 s, 120 s], default 30 s. Source: https://github.com/mozilla-firefox/firefox/blob/main/dom/webauthn/WebAuthnUtil.cpp
  - To simulate a UV failure: `isUserVerified: false` (or `setUserVerified(false)`) with `userVerification: 'required'`. The resulting error name is **unconfirmed** (expected `NotAllowedError`). `isBadUV` instead returns a response with UV cleared, which tests the RP-side check.
- **Firefox / WebKit virtual authenticators**: the spec defines WebDriver extension commands (§11, `webauthn:virtualAuthenticators`). Playwright exposes none of them except through the 1.61 JS shim. Native support via Playwright in Firefox/WebKit: **unconfirmed / not available**.
- **Vitest Browser Mode**: `cdp()` from `vitest/browser` "returns the current Chrome DevTools Protocol session". It "works only with `playwright` provider and only when using `chromium` browser", and needs `api.allowWrite` and `api.allowExec`. Usage is `await cdp().send('WebAuthn.enable', …)` (CDPSession API; the page shows no example). Source: https://vitest.dev/api/browser/context (v5.1.0 docs)

## 10. P-256 public-key recovery from one assertion

- SEC1 §4.1.6 tries `x = r + j·n`. For P-256, `r + n < p` is possible but negligible (p − n ≈ 2^128 out of 2^256), so in practice one signature gives **2 candidate keys** (y even or odd), and in theory up to 4. noble's code comments describe the same. Source: https://www.secg.org/sec1-v2.pdf §4.1.6; `@noble/curves@2.3.0` `abstract/weierstrass.js` (l.~815–912)
- A single assertion cannot pin the key. Two ways to decide between the candidates:
  - keep a fingerprint of the key (for example a hash of the SPKI);
  - intersect the candidates from a second assertion over a different challenge, which also means a second prompt.
  Derived from the math above; no WebAuthn source covers it.
- `@noble/curves` 2.3.0 supports recovery. You can parse `p256.Signature.fromBytes(sig, 'der')`, then `.addRecoveryBit(0|1)`, then `.recoverPublicKey(msgHash)`, which returns a Point; message hash = SHA-256(authData ‖ SHA-256(clientDataJSON)). Recovery ids 2/3 cover `r + n`. Source: https://www.npmjs.com/package/@noble/curves/v/2.3.0 (`abstract/weierstrass.d.ts` `ECDSASignature.addRecoveryBit`, `recoverPublicKey`; formats `'compact' | 'recovered' | 'der'`)
- **Gotcha**: noble `verify` defaults to `lowS: true` and `prehash: true`. Authenticators may emit high-S signatures, so pass `{ lowS: false, format: 'der' }` (and `prehash: true` with the raw signed bytes). Source: same `.d.ts` (`ECDSAVerifyOpts`).

## 11. Carrying data with the credential (largeBlob, credBlob, credProps)

- **largeBlob**:
  - `support: 'required' | 'preferred'` is valid only at create. `read` and `write` are valid **only at `get()`**, and `read`+`write` together → `NotSupportedError` (§10.1.5). So writing a blob after registration needs a second ceremony (a second prompt). Source: Spec.
  - Chromium: `write` "can only be used with a single credential present on `allowCredentials`", and the max write is 2 KB (`kMaxLargeBlobSize = 2048`). Source: Blink.
  - BCD: create support in Chrome 113, Firefox 139 and Safari 17; get support in Chrome 113 and Firefox 139, with Safari listed `false`. WebKit's `LocalAuthenticator` does implement get-time read/write, so real Safari get support is **unconfirmed**. Source: BCD, WebKit LocalAuthenticator.mm l.437–510.
  - CTAP authenticators must store ≥ 1024 bytes in total (shared by all credentials). Overwriting a credential MAY leave its blob orphaned. Source: CTAP §6.10. YubiKey: 1 KB (fw 5.5–5.6), 4 KB (5.7+). Source: Yubico FIDO page above.
  - Google Password Manager and Windows Hello largeBlob: **unconfirmed**.
- **credBlob**: Chromium exposes `credBlob` (create) and `getCredBlob` (get) in its IDL. Authenticators "MUST support at least 32 bytes" (`maxCredBlobLength`). YubiKey 5.5+ has 32 bytes, unencrypted. Firefox and Safari support is **unconfirmed** (not in BCD). Sources: https://chromium.googlesource.com/chromium/src/+/main/third_party/blink/renderer/modules/credentialmanagement/authentication_extensions_client_inputs.idl, CTAP §12.2
- **credProps**: carries only `rk`, no user data. See §5.

## 12. `authenticatorAttachment` and `hints`

- `hints` (`security-key`, `client-device`, `hybrid`) are ordered by preference and "take precedence" over `authenticatorAttachment`. Spec advises also setting the matching `authenticatorAttachment` for older UAs (`security-key`/`hybrid` → `cross-platform`, `client-device` → `platform`) (§5.8.7). Source: Spec.
- `hints` support: Chrome 128 only. Firefox and Safari are listed `false`, so they ignore the member. Source: BCD.
- `PublicKeyCredential.authenticatorAttachment` (result): Chrome 98, Firefox 120, Safari 15.5. Source: BCD.
- Per-engine UI gotchas (for example whether `platform` on Chrome/macOS offers iCloud Keychain or GPM first): **unconfirmed**.

## 13. Signature format and what a verifier needs

- ES256 signatures are "encoded as an ASN.1 DER Ecdsa-Sig-Value, as defined in [RFC3279] section 2.2.3" (§6.5.5). Lengths vary, about 70–72 bytes. Source: Spec.
- The verifier checks `sig` over "the binary concatenation of authData and hash", where hash = SHA-256(clientDataJSON) (§7.2 step "Let hash be…"). With ES256 the signer hashes that concatenation again with SHA-256. Source: Spec.
- WebCrypto `verify({name:'ECDSA', hash:'SHA-256'})` expects raw r‖s (64 bytes) and not DER, so convert DER → raw first. The spec says "If signature does not have a length of n * 2 bytes, then return false. Let r be … the first n bytes …". Source: https://w3c.github.io/webcrypto/ (ECDSA Verify operation)
- The RP must also check:
  - `type`, `challenge` and `origin` in clientDataJSON;
  - rpIdHash;
  - the UP bit, and the UV bit if required;
  - signCount.
  (§7.2). Source: Spec.
