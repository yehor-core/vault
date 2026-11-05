# Vault — Design

<!--
Template. Guidance lives in HTML comments; delete each comment once its section is written.
Rules for filling:
- Short as it can be while complete. Prefer tables and one-line statements over prose.
- Every guarantee names the code or test that enforces it (file:test name). No reference → write "not protected".
- Self-contained: the decision log is not in the repository, so state each decision's outcome and rejected alternatives here, without links or decision IDs.
-->

## 1. Overview

<!--
One paragraph: what Vault is, who calls it, what it deliberately does not know (what keys sign).
One line per goal (the six outcomes in TASK.md), each pointing to the section that delivers it.
Scope cuts, if any: what and why (or link to §11).
-->

## 2. Threat model

### 2.1 Assets

<!-- What we protect: private key material, the vault key / wrapping keys, record integrity, protection state (unprotected vs protected), key metadata (is it secret? say so). -->

### 2.2 Adversaries and events

<!-- Who or what, with capabilities: disk/profile copy, storage writer, snapshot restore, same-origin script, passkey loss, memory inspection, eviction, crash. Plus what is assumed trusted (browser, OS, authenticator, origin isolation). -->

### 2.3 Guarantees per case

<!-- One row per required case and mode. "Enforced by" = code path or test. Fill "Not guaranteed" honestly. -->

| Adversary or event | Mode | Guarantee | Not guaranteed | Enforced by |
|---|---|---|---|---|
| Copy of the browser profile or disk | Unprotected | | | |
| | Protected | | | |
| Records added or replaced by anyone who can write to storage | Both | | | |
| Older storage snapshot restored | Both | | | |
| Malicious script in the same origin while unlocked | Both | | | |
| Lost, deleted or replaced passkey (protection passkey) | Protected | | | |
| Lost, deleted or replaced passkey (passkey key) | Both | | | |
| Secrets in memory | Both | | | |
| Storage evicted by the browser | Both | | | |
| Crash or closed tab mid-operation | Both | | | |

### 2.4 Out of scope for the threat model

<!-- Compromised browser/OS, malicious extensions, XSS prevention itself, physical attacks on authenticators, side channels. One line each. -->

## 3. Key protection

### 3.1 Key hierarchy

<!--
What encrypts what, in each mode. A small diagram or nested list:
  root secret → vault key → per-key wrapping → private key.
Unprotected mode: where the root comes from and exactly what protects it.
Protected mode: how the passkey secret (PRF) becomes the root; what is never stored.
How many passkeys can unlock a vault (decided: exactly one) and the consequence for passkey loss.
-->

### 3.2 Passkey keys

<!--
How a passkey is modelled as a key. User verification requirement.
Fresh device: how the user presents the passkey and Vault identifies which key it is.
What Vault stores about a passkey key and what it can do without that record.
-->

### 3.3 Primitives and dependencies

| Purpose | Primitive | Source | Why this source |
|---|---|---|---|
| | | | |

<!-- One row per primitive (encryption, key derivation, signing per key type, randomness). Every third-party crypto dependency justified here. -->

## 4. Storage layout

### 4.1 Records

| Store / record | Key | Contents | Encrypted | Integrity-bound to |
|---|---|---|---|---|
| | | | | |

<!-- Also: how scopes map onto storage. -->

### 4.2 Validation and fail-closed behaviour

<!-- How each read is checked (shape, version, authenticity, binding to its slot). What a failure returns. Why Vault never repairs. Which tampering is detected at read time and which is not. -->

### 4.3 Versioning and migration

<!-- Where the version lives, what "unknown version" does, and how a future format change migrates (who runs it, atomicity, multi-tab interaction with an older Vault build). -->

### 4.4 Eviction and persistent storage

<!-- Position on navigator.storage.persist(). What Vault does when it finds itself empty, and how it tells "never used" from "evicted" (or why it cannot). -->

## 5. Lifecycle and state transitions

<!-- States: empty, unprotected, protected+locked, protected+unlocked, wiped (and closed, if distinct). Diagram (mermaid stateDiagram-v2) plus the table below. -->

| From | Operation | To | Prompts | Atomic how | On failure |
|---|---|---|---|---|---|
| | | | | | |

### 5.1 Enabling protection

<!-- Steps, the single commit point, where the second prompt happens and on which browsers, what is left after a cancel or crash. -->

### 5.2 Unlock and lock

<!-- At most one prompt. What lives in memory after unlock and for how long. What "closed" means. Unlocked state never persisted. -->

### 5.3 No downgrade

<!-- Why a protected vault can never become unprotected: after a failed unlock, a cancelled prompt, a deleted record, a tampered record. Link the tests. -->

### 5.4 Wipe

<!-- What is removed, atomicity, what other contexts see, why a stale context cannot resurrect data. -->

## 6. Concurrency and crash safety

<!--
Cover each requirement explicitly:
- multi-record changes are atomic (crash → old or new state);
- no lost updates between tabs/frames;
- concurrent first-time setup converges;
- a stale context cannot undo a wipe or a protection change;
- other contexts learn about changes (mechanism, and what happens if a notification is missed).
-->

## 7. Public API

### 7.1 Surface

<!-- The types and methods, as a short TypeScript excerpt. Show how the types make invalid states hard to express (e.g. which operations exist on a locked vault). -->

### 7.2 Usage examples

<!-- Create, list, sign + verify outside Vault, enable protection, unlock, add passkey key, sign with passkey key on a fresh device, delete, wipe, scopes. -->

### 7.3 Errors

| Situation | Error type | Retryable | Caller should |
|---|---|---|---|
| Infrastructure fault (transient) | | | |
| Corrupted or tampered storage | | | |
| Prompt declined or cancelled | | | |
| Vault locked | | | |
| Key not found | | | |
| Passkey protection unsupported | | | |

### 7.4 Prompts and user gestures

<!-- Which operations may prompt. How each can be called directly from a gesture handler without earlier async work consuming the gesture. -->

### 7.5 Adding a key type

<!-- The interface a key type implements and where it is registered. Show that the core does not branch on type names. -->

## 8. Browser support and degradation

<!-- Reasoning only; the matrix lives in README. Where passkey features degrade (PRF at create vs get, UV, discoverable credentials), what Vault detects up front, and what it can only detect on failure. -->

## 9. Embedding for other origins (not built)

<!-- Popup or iframe: the choice, why, and what we give up (storage partitioning, gesture/permission policy, messaging protocol). -->

## 10. Alternatives considered and rejected

| Topic | Chosen | Rejected | Why | Given up |
|---|---|---|---|---|
| | | | | |

<!-- Only the decisions a reviewer would challenge. -->

## 11. Known limitations

<!-- Honest list: what is not protected, what is not tested in which engine, what was cut and why. -->
