import type { Bytes } from './bytes.ts';
import { ed25519 } from './key-types/ed25519.ts';
import { passkey } from './key-types/passkey.ts';
import { secp256k1 } from './key-types/secp256k1.ts';
import type { Fields } from './readers.ts';
import type { HeaderRecord, KeyFields } from './records.ts';

/**
 * Everything the core needs from a key type; the core never names a type. A key type owns its part of the
 * key record, its public-key check and its member of `Signature`, so the core assumes neither a sealed private
 * key nor a signature shape. A new key type is one module in `key-types/` and one entry in `keyTypes`.
 */
export type KeyType<Part extends object = object, Sig extends object = object> = KeyTypeBase<Part, Sig> &
  (
    | { readonly canAdd: false }
    | {
        /** A key of this type can be added to a vault that has never seen it. */
        readonly canAdd: true;
        /**
         * Asks the user to present an existing key of `scope`, with a prompt started before any await; the core
         * calls it before its first await. A key not created in `scope` is `not-found`.
         */
        add(scope: string): Promise<PresentedKey<Part>>;
      }
  );

interface KeyTypeBase<Part extends object, Sig extends object> {
  /**
   * Whether generate and sign show a prompt. Such a type starts it in `generate` and `sign`, which the core calls
   * before its first await, so a user gesture still holds; and its new key's record doesn't depend on the vault
   * header, so the core writes it into the vault as it is and never generates it again, which would prompt again.
   */
  readonly prompts: boolean;
  /** The names of this type's own fields of a key record, beside `KeyFields`. */
  readonly fields: readonly string[];
  /** Reads this type's own fields of a stored key record into a new object; throws `corrupted`. Runs on every read, without any secret. */
  parse(record: Fields): Part;
  /** Whether stored bytes are a valid public key of this type. Runs on every read, without any secret. */
  isPublicKey(bytes: Bytes): boolean;
  /** The bytes the key id hashes beside scope and type (D-05): what names the key on every device. */
  identity(record: KeyFields & Part): Bytes;
  /** What this type adds to a key's public information, beside the fields every key has. */
  info(part: Part): object;
  /** A fresh key, not yet stored. */
  generate(request: NewKeyRequest): Promise<NewKey<Part>>;
  /**
   * Signs `data` with the key `key` names and checks the signature under its public key; a stored key that fails
   * is `corrupted`. `key` is the caller's argument, checked by the core only for its id, scope and type; `load`
   * reads the stored key, or fails as the core decides (`not-found`, a type mismatch).
   */
  sign(key: Fields, data: Bytes, load: () => Promise<StoredKey<Part>>): Promise<Sig>;
}

/** What `generate` was asked for. */
export interface NewKeyRequest {
  readonly scope: string;
  readonly label?: string;
}

export interface NewKey<Part extends object = object> {
  readonly publicKey: Bytes;
  /** The bytes the key id hashes, as `KeyType.identity` reads them from the stored record. */
  readonly identity: Bytes;
  /** This type's part of the record of `fields`, in the vault of `header`. */
  part(fields: KeyFields, header: HeaderRecord): Promise<Part>;
  /** Zeroes the secret buffers the type owns. The core calls it once the key is stored or abandoned. */
  erase(): void;
}

/** A key the user presented: its identity is known; the rest may take another prompt. */
export interface PresentedKey<Part extends object = object> {
  /** The bytes the key id hashes, so the core can tell whether the scope holds it already. */
  readonly identity: Bytes;
  /** The key as generate would have made it, checked; called only if the scope doesn't hold it. */
  complete(): Promise<NewKey<Part>>;
}

/** A stored key and the header of its vault, read in one transaction. */
export interface StoredKey<Part extends object = object> {
  readonly record: KeyFields & Part;
  readonly header: HeaderRecord;
}

export const keyTypes = { ed25519, secp256k1, passkey } satisfies Record<string, KeyType>;

export type KeyTypeName = keyof typeof keyTypes;

/** The key types that can add an existing key. */
export type AddableKeyTypeName = {
  [T in KeyTypeName]: (typeof keyTypes)[T]['canAdd'] extends true ? T : never;
}[KeyTypeName];

/** The member of `Signature` that key type `T` returns, besides its `type`. */
export type SignatureOf<T extends KeyTypeName> = Awaited<ReturnType<(typeof keyTypes)[T]['sign']>>;

/** What key type `T` adds to its member of `KeyInfo`. */
export type InfoOf<T extends KeyTypeName> = ReturnType<(typeof keyTypes)[T]['info']>;

/** Key type `name`, widened to `KeyType`: the core calls any type alike, its record part and signature opaque. */
export function keyType(name: KeyTypeName): KeyType {
  return keyTypes[name];
}

/**
 * Lowercase letters, digits and hyphens, 1 to 32 characters: the names a key type may take, registered or not.
 * A stored name of this form that this build doesn't know was written by a newer build (D-21).
 */
export function isWellFormedKeyTypeName(value: unknown): value is string {
  return typeof value === 'string' && /^[a-z0-9-]{1,32}$/.test(value);
}

export function isKeyTypeName(value: unknown): value is KeyTypeName {
  return typeof value === 'string' && Object.hasOwn(keyTypes, value);
}
