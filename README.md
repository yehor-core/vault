# Vault

A browser-native private-key store on top of IndexedDB. Design: [DESIGN.md](DESIGN.md).

> Status: S0 skeleton. Toolchain and test harness only; no library code yet.

## Setup

Requires Node.js ≥ 24 (developed on 26 LTS).

```sh
npm ci
npx playwright install --with-deps chromium firefox webkit   # --with-deps installs system libraries (sudo)
```

## Commands

| Command | What it does |
|---|---|
| `npm run demo` | Serves the demo page at http://localhost:5173 |
| `npm run typecheck` | Type checks browser code (`tsconfig.json`, no Node globals) and Node-side config and e2e tests (`tsconfig.node.json`) |
| `npm run test:unit` | Vitest Browser Mode in real Chromium, Firefox and WebKit (`test/unit`) |
| `npm run test:e2e` | Playwright against the demo page in Chromium, Firefox and WebKit (`test/e2e`); starts its own server on :5174 |
| `npm test` | Both suites |

There is no library build yet; it arrives with the first public API.

## Browser support

| Engine | Version tested (Playwright 1.64.1) | Unit + e2e suites | Passkey features |
|---|---|---|---|
| Chromium | 156 | ✓ | not built yet |
| Firefox | 157 | ✓ | not built yet |
| WebKit | 27.2 | ✓ | not built yet |

## Property → test

| Property | Test | Engines |
|---|---|---|
| Tests run in real browser engines, not an emulation | `test/unit/platform.test.ts` › runs in the real browser engine it is configured for | Chromium, Firefox, WebKit |
| Playwright suite serves the demo from a secure context (needed by WebCrypto and WebAuthn) | `test/e2e/demo.spec.ts` › demo page runs its TypeScript module in a secure context | Chromium, Firefox, WebKit |
