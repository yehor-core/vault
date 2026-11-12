# Slices

Check every design option for a slice against all later slices. No migration code is planned (see "Not planned"), so a storage format chosen in one slice must serve every later slice without one.

When an attempt at a slice is abandoned, add one line under the slice: what stays in force (its decisions) and what is dead (its branch and PR).

## S0: Skeleton
Status: done · Spec: #- · Tickets: #-
- Vite + TS
- Vitest Browser Mode (Chromium, Firefox, WebKit), Playwright

## S1: Unprotected vault, ed25519
Status: done · Spec: #- · Tickets: #-
- generate, list, sign, delete, wipe
- keys encrypted at rest
- versioned storage format
- basic error classes
- demo: create, list, sign, wipe

## S2: Key types and scopes
Status: done · Spec: #9 · Tickets: #11, #13, #12, #14, #15, #16, #17
- key-type interface
- secp256k1
- scopes
- labels
- read-time validation of every field S2 adds

Not included: scopes in the demo, which stays on one fixed scope (S7 decides)

## S3: Storage integrity
Status: done · Spec: #35 · Tickets: #36, #39, #37, #38, #40
- record validation, fail closed on tampered or malformed records
- atomic multi-record writes
- empty vault, eviction, persistent storage

Not included: protection records (S6); validation of the fields S2 adds (S2)

## S4: Multi-tab
Status: done · Spec: #51 · Tickets: #52, #53, #54, #55
- concurrent writes without lost updates
- concurrent first-time setup
- stale tab can't undo a wipe
- change notifications

Not included: protection change across tabs (S6)

## S5: Passkey keys
Status: in progress · Spec: #64 · Tickets: #-
- several passkey keys, user verification required
- sign with a passkey key
- passkey key on a fresh device
- gesture-safe prompts
- cancelled prompt error
- demo: create, add and sign with a passkey key

Not included: passkey as vault unlock (S6)

## S6: Passkey protection
Status: planned · Spec: #- · Tickets: #-
- PRF support detection
- enable protection (atomic)
- unlock, lock
- generate while locked
- no downgrade
- protection records integrity
- protection change across tabs

## S7: Demo and docs
Status: planned · Spec: #- · Tickets: #-
- full demo, incl. passkey key in a fresh profile
- decide whether the demo shows scopes
- DESIGN.md
- README: browser matrix, property → test table
- manual passkey checks in Firefox and WebKit

## Not planned
- disabling protection, changing the unlock passkey
- migration code (described only)
- listing the scopes of a vault, clearing one scope, filtering `list()` by key type
- renaming a label; caller-supplied metadata beyond the label
