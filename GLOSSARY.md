# Vault

A browser key vault: it generates signing keys, keeps them in the browser and signs with them. This glossary fixes the words that the design, the code and the issues use.

## Language

**Label**:
The name a caller gives a key when it is generated. Display text only: not unique, and never changed afterwards.
_Avoid_: name, tag, metadata; "label" for a constant of the storage format (say "domain separator")

**Public information**:
What can be read about a key without unlocking the vault: its id, scope, key type, public key, creation time and label.
_Avoid_: metadata, key metadata, public data
