# **Test Task: Browser Key Vault**

### **Context**

Design and build **Vault**: a browser-native private-key store on top of IndexedDB.

Applications use Vault to keep signing keys in the user's browser. In our product, Vault runs on one origin; other sites reach it through a popup or an iframe. Vault is a standalone library: it neither knows nor cares what its keys sign.

The task is deliberately open. It describes outcomes and constraints, not mechanisms. Where a requirement leaves a choice, make it, justify it, and name what you gave up.

# **Goals**

Vault succeeds when these six outcomes hold together:

- **No plaintext keys at rest.** Private keys are always stored encrypted.
- **Optional, upgradeable protection.** Vault works silently without a passkey. A user can turn passkey protection on later without losing keys.
- **Cheap to add, gated to use.** Generating a secp256k1 or ed25519 key never needs an unlock or a prompt, in either mode.
- **Many key types, one model.** secp256k1 keys, ed25519 keys and passkeys share one API. A new key type plugs in without the core branching on type names.
- **Correct under concurrency and failure.** Several tabs, crashes and corrupted storage are normal conditions, not edge cases.
- **A small, idiomatic domain API.** Callers think in keys, signatures and protection, never in databases, records or ciphertext.

### **Required properties**

Every item below is required. How you meet it is up to you.

#### **Keys**

- Generate keys of a chosen type inside the vault.
- List keys and read their public information (id, type, public key, caller-supplied label or metadata) without unlocking.
- Sign with a key. Anyone holding its public key can verify the signature without Vault. Private key material never leaves the vault.

- Delete a single key, and wipe the whole vault.
- Group keys into named scopes so one Vault can serve several independent consumers.

#### **Passkey keys**

- A user can add several passkeys as keys, for example a platform passkey and two hardware security keys.
- A passkey key works in a vault that has never seen it, including on a fresh device: the user presents the passkey, and Vault tells the caller which key it is.
- Using a passkey key requires user verification (PIN or biometric), not just presence.

### **Protection**

- Turning protection on for a populated vault is atomic: it completes fully or leaves the vault unchanged. It may take a second prompt where the browser does not return the passkey secret at creation; state where that happens.
- Unlocking takes at most one passkey prompt. After it, every key is usable until the vault is closed; only passkey keys may prompt again. Unlocked state is never persisted.
- A protected vault never falls back to unprotected: not after a failed unlock, a cancelled prompt, or a deleted or tampered record.
- Handle browsers and authenticators that cannot support passkey protection: detect what you can up front, and fail cleanly, with the vault unchanged, on the rest.
- Decide whether more than one passkey can unlock a vault.

### **Storage, integrity and concurrency**

- IndexedDB is the only persistent store, and everything read from it is untrusted. Modified, swapped, truncated or malformed records are detected; Vault fails closed rather than returning a wrong key or repairing data.
- Changes that touch several records are atomic. A crash or closed tab leaves the old state or the new one, never a mix.
- Several tabs and frames may use one vault at once. No lost updates; concurrent first-time setup converges; a stale context cannot undo a wipe or a protection change. Other contexts learn about changes.
- Browsers may evict storage. State your position on requesting persistent storage, and how Vault behaves when it finds itself empty.
- The storage format is versioned. Unknown versions are rejected, not coerced. Describe how a future format change would migrate.

### **API**

- Invalid states are hard to express, ideally impossible in the types.
- Errors are classified so a caller can tell apart: retryable infrastructure faults, corrupted storage, a declined or cancelled prompt, a locked vault, and a missing key.

- Any operation that may show a passkey prompt can be started directly from a user gesture, without earlier async work consuming that gesture.
- The core has no UI-framework dependency.

### **Platform**

- TypeScript, or Rust compiled to WebAssembly behind a TypeScript-facing API.
- Runs in current Chromium, Firefox and WebKit. State where passkey features degrade.
- Prefer native platform primitives. Justify every third-party cryptographic dependency; never hand-roll cryptographic primitives.

## **Security expectations**

Write an explicit threat model: assets, adversaries, what Vault guarantees against each, and what it does not. It must cover at least these cases:

|           | Adversary | or event        | Expectation                                                   |
|-----------|-----------|-----------------|---------------------------------------------------------------|
| Copy      | of the    | browser profile | or                                                            |
|           |           |                 | Passkey mode: keys unrecoverable without the passkey (or      |
|           |           |                 | the account that syncs it). Unprotected mode: state exactly   |
|           |           |                 | what protects them.                                           |
| Records   | added     | or replaced     | by                                                            |
| anyone    | who       | can write to    |                                                               |
|           |           |                 | Adding a key needs no secret. State what you can and          |
|           |           |                 | cannot detect, and when.                                      |
| An older  | storage   | snapshot        |                                                               |
|           |           |                 | State what you can and cannot detect.                         |
| Malicious | script    | in the same     |                                                               |
| origin    | while     | unlocked        |                                                               |
|           |           |                 | Vault is not a sandbox. State what such code can reach and    |
|           |           |                 | how the API limits exposure.                                  |
| Lost,     | deleted   | or replaced     |                                                               |
|           |           |                 | A defined, documented outcome, both for protection and for    |
|           |           |                 | passkey keys.                                                 |
| Secrets   | in        | memory          | Minimal lifetime and exposure; state the limits of what JS or |
|           |           |                 | WASM can promise.                                             |

Every guarantee you claim must be traceable to code or a test. An honest "not protected" beats an unsupported claim.

### **Out of scope**

- What the keys sign: transactions, messages, protocols, account models.
- Importing, exporting, backing up or recovering keys.
- Sync between devices, and any server component.
- Embedding Vault for other origins (popup or iframe): describe your choice in the design document; do not build it.
- Browser extensions, native apps, and hardware wallets other than passkeys.
- A polished UI.

# **Deliverables**

Submit a repository containing five things:

- 1. **Design document**, short as it can be while complete. Cover:
  - the threat model;
  - storage layout and how keys are protected;
  - lifecycle and state transitions: empty, unprotected, protected, locked, unlocked, wiped;
  - the concurrency approach;
  - the public API, with usage examples;
  - alternatives you considered and rejected;
  - known limitations.
- 2. **Library** implementing the design: secp256k1, ed25519 and passkey keys, in both protection modes.
- 3. **Tests**: unit tests, plus automated tests in at least two real browser engines. Automate the passkey paths where the engine's tooling allows (at least Chromium) and say how you checked the rest.
- 4. **Demo page** that exercises create, list, sign, enable protection, unlock and wipe, plus signing with a passkey key in a fresh browser profile.
- 5. **README** with build, run and test instructions, a browser support matrix, and for each hard property the test that proves it and the engines it runs in.

Budget about three working days of effort, delivered within seven calendar days. Any tools are allowed, LLMs and coding agents included; you own every line. A smaller, correct, well-argued subset beats a broad, shaky one. If you cut scope, say what and why.

# **Evaluation**

We review the repository first, then hold a call where you walk us through the design and defend its trade-offs. With AI tools allowed, we weigh judgment, not volume.

**Area What we look for**

|                 | A precise threat model; guarantees that match the code; trade-offs named, |
|-----------------|---------------------------------------------------------------------------|
|                 | not hidden.                                                               |
| Hard properties | Adding keys without unlocking, a single-prompt unlock, passkey keys on a  |
|                 | fresh device, an atomic protection upgrade, no downgrade, and             |
|                 | correctness across tabs.                                                  |
| API design      | Small, domain-driven, hard to misuse.                                     |
| Extensibility   | A new key type is a local change; the storage format can evolve.          |
| Robustness      | Fails closed on bad storage; classified errors; crash safety.             |
| Testing         | Tests aimed at the hard properties, run in real browsers, covering        |
| Simplicity      | Nothing speculative; the least code that meets the requirements.          |
| Communication   | A short, clear design document.                                           |