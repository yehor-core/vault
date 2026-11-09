# Slices

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
Status: in progress · Spec: #- · Tickets: #-
- key-type interface
- secp256k1
- scopes
- labels / metadata

## S3: Storage integrity
Status: planned · Spec: #- · Tickets: #-
- record validation, fail closed on tampered or malformed records
- atomic multi-record writes
- empty vault, eviction, persistent storage

Not included: protection records (S6)

## S4: Multi-tab
Status: planned · Spec: #- · Tickets: #-
- concurrent writes without lost updates
- concurrent first-time setup
- stale tab can't undo a wipe
- change notifications

Not included: protection change across tabs (S6)

## S5: Passkey keys
Status: planned · Spec: #- · Tickets: #-
- several passkey keys, user verification required
- sign with a passkey key
- passkey key on a fresh device
- gesture-safe prompts
- cancelled prompt error

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
- DESIGN.md
- README: browser matrix, property → test table
- manual passkey checks in Firefox and WebKit

## Not planned
- disabling protection, changing the unlock passkey
- migration code (described only)
