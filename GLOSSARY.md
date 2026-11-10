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
A key whose private key stays in a passkey authenticator; the vault holds only its public information. It lives in a scope and signs, like any other key.
_Avoid_: global key; "passkey" alone when the key is meant

**Unlock passkey**:
The one passkey that unlocks a protected vault. It belongs to the vault as a whole, not to a scope, and it signs nothing.
_Avoid_: protection passkey, master passkey, global key
