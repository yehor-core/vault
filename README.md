# Vault

A browser-native private-key store on top of IndexedDB. Design: [DESIGN.md](DESIGN.md).

> Status: S1. Unprotected vault with ed25519 keys: generate, list, sign, delete, wipe. Keys are encrypted at rest in a versioned storage format, and errors are classified. Not built yet: secp256k1, scopes and labels, multi-tab notifications, passkey keys, passkey protection.

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
| `npm run demo` | Serves the demo page at http://localhost:5173: generate, list, sign (verified with WebCrypto outside Vault), delete, wipe |
| `npm run typecheck` | Type checks browser code (`tsconfig.json`, no Node globals) and Node-side config and e2e tests (`tsconfig.node.json`) |
| `npm run test:unit` | Vitest Browser Mode in real Chromium, Firefox and WebKit (`test/unit`) |
| `npm run test:e2e` | Playwright against the demo page in Chromium, Firefox and WebKit (`test/e2e`); starts its own server on :5174 |
| `npm test` | Both suites |

```ts
import { Vault } from 'vault';

const vault = await Vault.open();
const key = await vault.generate('ed25519');
const signature = await vault.sign(key.id, new TextEncoder().encode('hello'));
```

## Browser support

| Engine | Version tested (Playwright 1.64.1) | Unit + e2e suites | Vault (unprotected, ed25519) | Passkey features |
|---|---|---|---|---|
| Chromium | 156 | ✓ | ✓ | not built yet |
| Firefox | 157 | ✓ | ✓ | not built yet |
| WebKit | 27.2 | ✓ | ✓ | not built yet |

Needs WebCrypto Ed25519, ECDH P-256, HKDF and AES-GCM, plus IndexedDB, in a secure context. WebKit drives two design choices; see DESIGN.md §8.

## Property → test

Unit tests: `test/unit/vault.test.ts` (vault ›) and `test/unit/storage.test.ts` (storage ›). Every unit test runs in all three engines. Each row was break-checked: the guarding code was broken once and the test went red in every listed engine. Where two guards protect one property, both were broken together. The exceptions are the two platform rows, "Keys persist" and "Opening and listing write nothing", which are functional checks.

| Property | Test | Engines |
|---|---|---|
| Tests run in real browser engines, not an emulation | `test/unit/platform.test.ts` › runs in the real browser engine it is configured for | Chromium, Firefox, WebKit |
| Playwright suite serves the demo from a secure context (needed by WebCrypto and WebAuthn) | `test/e2e/demo.spec.ts` › demo page runs its TypeScript module in a secure context | Chromium, Firefox, WebKit |
| No private key bytes are stored; the only stored secret is a non-extractable root key | storage › encryption at rest › no private key bytes are stored: only ciphertext and a non-extractable root key | Chromium, Firefox, WebKit |
| A signature verifies under the public key alone, without Vault | vault › keys › a signature verifies under the public key with WebCrypto alone, without Vault; `test/e2e/demo.spec.ts` › demo creates, lists, signs, deletes and wipes keys… (verified again in Node) | Chromium, Firefox, WebKit |
| An edited id, type, public key or version is caught by `list()`, without any secret | storage › integrity › editing id / type / publicKey / v of a key record fails closed | Chromium, Firefox, WebKit |
| Any edit to a stored key record fails closed (`corrupted`), and the cases cover every field | storage › integrity › editing \<field\> of a key record fails closed (8 cases); › the edit cases cover every stored field of a key record | Chromium, Firefox, WebKit |
| Ciphertexts swapped between records fail closed | storage › integrity › ciphertexts swapped between two key records fail closed | Chromium, Firefox, WebKit |
| A key an attacker sealed to the public wrapping key is rejected, not used | storage › integrity › a key an attacker sealed to the public wrapping key decrypts, but is rejected instead of used | Chromium, Firefox, WebKit |
| A record moved to another scope is rejected | storage › integrity › a key record moved to another scope is rejected there: its id binds the scope | Chromium, Firefox, WebKit |
| Off-curve ephemeral public keys are rejected on import | storage › integrity › an off-curve ephemeral public key is rejected on import, in every engine | Chromium, Firefox, WebKit (the guard matters in WebKit, the only engine that goes red without it) |
| Unknown format versions are rejected, not coerced | storage › format versioning › a header with an unknown format version is rejected, not coerced; storage › integrity › editing v… | Chromium, Firefox, WebKit |
| Storage written by a newer format is rejected with `incompatible` | storage › format versioning › a database written by a newer format is rejected with incompatible | Chromium, Firefox, WebKit |
| An open vault never blocks a newer format, and refuses to work afterwards | storage › format versioning › an open vault never blocks a newer format, and refuses to work afterwards | Chromium, Firefox, WebKit |
| A multi-record write is atomic: a failed first generate leaves no header | vault › errors › the first generate writes header and key atomically: if the key write fails, no header remains | Chromium, Firefox, WebKit |
| IndexedDB failures are classified as retryable `unavailable` | vault › errors › an IndexedDB failure is reported as retryable unavailable, and a retry succeeds | Chromium, Firefox, WebKit |
| A missing key is `not-found` | vault › keys › signing with an unknown key id fails with not-found | Chromium, Firefox, WebKit |
| A key record without a vault header is `corrupted`, never treated as a new vault | vault › errors › a key record without a vault header is corrupted, not unprotected | Chromium, Firefox, WebKit |
| Wipe removes every key and the header; the next vault has a new wrapping key | vault › keys › wipe removes every key and the vault header; the next generate starts a new vault | Chromium, Firefox, WebKit |
| Delete removes exactly one key | vault › keys › delete removes only that key, and deleting a missing key is a no-op | Chromium, Firefox, WebKit |
| Keys persist across reopen and page reload | vault › keys › keys survive closing and reopening the vault; `test/e2e/demo.spec.ts` › demo creates… | Chromium, Firefox, WebKit |
| Opening and listing write nothing | vault › lifecycle › opening and listing write nothing; the first generate creates the vault | Chromium, Firefox, WebKit |
