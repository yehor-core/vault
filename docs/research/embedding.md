# Embedding for other origins: popup or iframe

Collected 2026-11-13 for S7 (D-89, D-90). Engines current then: Chromium 156, Firefox 157, Safari 27. Marks: **confirmed** = a primary source says so; **unconfirmed** = no primary source found.

## 1. IndexedDB in a cross-site iframe is partitioned

- Chromium: IndexedDB is in partitioned storage, keyed by top-level site plus an ancestor bit; on for everyone since Chrome 115. Confirmed: https://privacysandbox.google.com/3pcd/storage-partitioning
- Firefox: IndexedDB is partitioned by top-level site (State Partitioning, Total Cookie Protection), on by default since Firefox 103. Confirmed: https://developer.mozilla.org/en-US/docs/Web/Privacy/Guides/State_Partitioning
- Safari: "Third-party LocalStorage and IndexedDB are partitioned per first-party website and also made ephemeral". Confirmed: https://webkit.org/tracking-prevention/, https://bugs.webkit.org/show_bug.cgi?id=231879. Since which version: unconfirmed.
- Safari also deletes script-writable storage, IndexedDB included, after 7 days of Safari use without user interaction with the site (since Safari 13.1). Confirmed: https://webkit.org/blog/10218/full-third-party-cookie-blocking-and-more/
- Derived: the vault's iframe on site A, its iframe on site B and the vault's origin opened top-level see three different databases, in every engine.

## 2. Storage Access API and IndexedDB

- Chromium: `document.requestStorageAccess({ indexedDB: true })` returns a `StorageAccessHandle` with `handle.indexedDB`; shipped in Chrome 125, the only engine per BCD. Confirmed: https://developer.mozilla.org/en-US/docs/Web/API/Document/requestStorageAccess, BCD `api/StorageAccessHandle.json`.
- Chromium's conditions: transient activation, a secure context, Permissions Policy `storage-access`, a prior top-level visit and interaction with the iframe's site (else auto-denied), then a prompt; the grant lasts 30 days and is requested on every page load. Confirmed: https://privacysandbox.google.com/cookies/storage-access-api
- Firefox and Safari: the Storage Access API unpartitions cookies only, not IndexedDB. Confirmed: MDN State_Partitioning (above); https://webkit.org/blog/8124/introducing-storage-access-api/

## 3. WebAuthn in a cross-origin iframe

- Off by default; enabled with `allow="publickey-credentials-get"` / `allow="publickey-credentials-create"`. The RP ID defaults to the iframe's origin; clientDataJSON carries `crossOrigin: true` and `topOrigin`. Confirmed: https://www.w3.org/TR/webauthn-3/#sctn-iframe-guidance, §5.1.3, §5.8.1
- `get()`: Chrome 84, Firefox 118, Safari 15.5. Confirmed: https://web.dev/articles/webauthn-within-iframe, https://bugzilla.mozilla.org/show_bug.cgi?id=1460986, https://bugs.webkit.org/show_bug.cgi?id=222240
- `create()`: Chrome 122, Firefox 123 (with transient activation, bug 1877332). Safari: not supported; status in Safari 27 unconfirmed. Confirmed: https://groups.google.com/a/chromium.org/g/blink-dev/c/Sq2WAVbPz6g, Bugzilla 1870863
- PRF: the spec sets no restriction for cross-origin callers (§10.1.4). Whether each engine evaluates it in an iframe: unconfirmed.

## 4. Popup

- A popup is a top-level document: its storage key is the vault's own site, the same database as the vault opened directly, in every engine. Derived from §1.
- `window.open` needs transient activation (popup blocker). Confirmed: https://html.spec.whatwg.org/multipage/browsers.html#popup-sandboxing-flag
- If the vault's origin sends `Cross-Origin-Opener-Policy: same-origin`, the opener link is cut and `postMessage` between the two windows is impossible; the consumer may use `same-origin-allow-popups`. Confirmed: https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Cross-Origin-Opener-Policy
- Chromium once proposed transient storage for popups with a live opener ("Opener Storage Partitioning"); not shipped in 2023, status now unconfirmed: https://groups.google.com/a/chromium.org/g/blink-dev/c/pWbFePTUnB4

## 5. WebAuthn on http://localhost

- The spec accepts `http://localhost` with RP ID `localhost`, and it is a potentially trustworthy origin. Confirmed: https://www.w3.org/TR/webauthn-3/#rp-id, https://developer.mozilla.org/en-US/docs/Web/Security/Secure_Contexts
- Safari: WebAuthn on localhost hangs or fails with `NotAllowedError` far more often than on a real domain; WebKit bug 273712 is open (Critical). Confirmed: https://bugs.webkit.org/show_bug.cgi?id=273712
