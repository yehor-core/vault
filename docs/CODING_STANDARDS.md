# Coding standards

Checked by `/code-review` against every diff. Rules marked _(oxlint)_ or _(tsc)_ are enforced by `npm run lint` or `npm run typecheck` in the pre-commit hook and CI; the reviewer skips them. Rules marked _(lint)_ are mechanical but have no tool yet.

## General

- Minimal code; nothing speculative. The task rewards simplicity.
- Comments explain only the non-obvious why, in one or two lines. No tutorials in code.
- In `src/` and `demo/`, name an awaited value before passing it on: no `await` inside function arguments or array literals. Tests may write `expect(await …)`. _(lint)_
- No non-null assertions (`!`). _(oxlint)_
- No unused imports, locals or parameters. _(tsc)_
- `as` only narrows a value already checked at runtime, or a generic type TypeScript can't follow. Never use it to skip a check.

## Untrusted input

- Everything read from IndexedDB is untrusted. Parse it with the typed readers in `src/records.ts` into new objects: check each field's type and length, never coerce, reject unknown fields, and name the failing field in the error.
- A failed check fails the whole call closed with `corrupted`. Vault never repairs: no code path writes back a record it failed to read.
- Caller input that could silently change meaning is checked, not coerced (e.g. `sign` data must be a `Uint8Array`). A malformed argument is a `TypeError`.

## Storage format

- Every hashed or authenticated value goes through `encode` (`src/bytes.ts`); no ad-hoc concatenation.
- Format constants (domain-separation labels, encoding tags, lengths, store names, the default database name) are each defined once, as a named constant.
- A new stored field of a key record is bound into its AAD, unless a decision in `docs/DECISIONS.md` says otherwise.
- A change to the bytes of an existing record, id or AAD needs a format version bump. The v1 known-answer tests (`records › format v1 regression`, `storage › encodes the exact v1 bytes…`, `storage › a value sealed by format v1 still opens…`) catch it; never edit them to make a change pass. Each known-answer literal carries `// prettier-ignore`, so a formatter run or a Prettier config change can't rewrite it.

## Transactions

- Transaction bodies await only IndexedDB requests. Crypto runs before the transaction, never inside it: Firefox and WebKit end a transaction at the first await that settles in a later task.
- A multi-record change is one transaction. A write re-checks, inside its transaction, the header it was prepared against.

## Crypto

- No hand-rolled crypto. WebCrypto first; `@noble/curves` only where a decision in `docs/DECISIONS.md` justifies it. A new dependency needs a decision; a crypto dependency is pinned to an exact version.
- Ed25519 private keys never exist as JS bytes. Secret buffers Vault owns (secp256k1 keys and seeds) are zeroed after use.
- A signature is verified against the stored public key before it is returned.

## Key types

- The core never branches on a key type name. Type-specific behaviour lives behind `KeyType` (`src/key-types.ts`) and its registry.

## Errors

- Runtime failures are `VaultError` with a `code`, and the original error in `cause`. Only `unavailable` is retryable.
- Programming errors are `TypeError`, or `DOMException` `InvalidStateError` after `close()`; never `VaultError`.

## Public API

- The public API speaks the domain (keys, signatures, scopes, protection), never records, ciphertext or transactions.
- No method returns private key material.

## Tests

- Name each test after the property it proves.
- Tests run on real IndexedDB and WebCrypto in Chromium, Firefox and WebKit; no emulation. A spy may observe a call or inject a failure, never replace the behaviour the test proves.
- A test skipped in an engine names the engine and the reason.

## Docs

- A guarantee stated in `DESIGN.md` or `README.md` names the test or code that enforces it. No reference → "not protected".
