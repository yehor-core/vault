# Vault

A browser key vault: it generates signing keys, keeps them in the browser and signs with them. This glossary fixes the words that the design, the code and the issues use.

## Language

**Label**:
The name a caller gives a key when it is generated. Display text only: not unique, and never changed afterwards.
_Avoid_: name, tag, metadata; "label" for a constant of the storage format (say "domain separator")

**Public information**:
What can be read about a key without unlocking the vault: its id, scope, key type, public key, creation time and label.
_Avoid_: metadata, key metadata, public data

**Sealed key**:
A key whose private key the vault generates and keeps encrypted in its own storage. It exists only in the browser profile that generated it.
_Avoid_: local key, software key, stored key

**Passkey key**:
A key whose private key stays in a passkey authenticator; the vault holds only its public information. It belongs to the one scope it was created in and signs, like any other key. A vault that has never seen it, such as one on a fresh device, learns it by adding it.
_Avoid_: global key; "passkey" alone when the key is meant

**Adding a key**:
Recording in a scope a passkey key the vault has not seen: the user presents the passkey, and the vault learns its public information from it. Only a passkey key created in that scope can be added; adding one the scope already holds changes nothing.
_Avoid_: import, register, discover, recover

**Unlock passkey**:
The one passkey that unlocks a protected vault. It belongs to the vault as a whole, not to a scope, and it signs nothing.
_Avoid_: protection passkey, master passkey, global key

**Protection**:
The vault-wide setting under which keys with a sealed private key can sign only after the user presents the unlock passkey. A vault is unprotected or protected; once protected, it stays protected until it is wiped. Keys are encrypted in either mode.
_Avoid_: encryption (for the setting), password, lock (for the setting); "protected" for a single key

**Locked**, **Unlocked**:
How one context sees a protected vault. While locked, keys with a sealed private key can't sign; the user unlocks by presenting the unlock passkey, and then every key is usable in that context until it locks or closes the vault. Each context unlocks on its own, and the unlocked state is never stored.
_Avoid_: open, closed (they mean opening and closing the vault in a context); logged in

**Scope**:
A named group of keys inside one vault. It has no record of its own: it is there while it holds keys, and all scopes share the vault's protection and its wipe.
_Avoid_: namespace, account, wallet, tenant, consumer

**Consumer**:
An application that keeps its keys in a scope of its own; in the product, another site that reaches the vault through the embedding layer. The vault does not authenticate consumers.
_Avoid_: client, tenant, app

**Embedding layer**:
The part of the product, outside the vault library, that receives requests from other sites and chooses the scope from the sender's origin. It is what keeps consumers apart. Described, not built.
_Avoid_: bridge, host, wrapper

**Empty vault**:
A vault that holds no keys and no protection. A vault never used, wiped, or evicted by the browser is empty, and the three can't be told apart.
_Avoid_: new vault, wiped vault, evicted vault (as distinct states)

**Context**:
A tab or frame of the vault's origin that has the vault open. Several contexts may use one vault at once; each opened vault in a page counts as one.
_Avoid_: session, client, instance (for a tab)

**Change notification**:
A hint to a context that the vault may have changed, so it reads the vault again. It says only that something changed, not what. It can be lost or forged; the stored vault is the only truth.
_Avoid_: event (alone), sync, update message
