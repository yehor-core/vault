import type { Bytes } from './bytes.ts';
import { ed25519 } from './key-types/ed25519.ts';
import { secp256k1 } from './key-types/secp256k1.ts';
import type { Fields } from './readers.ts';
import type { HeaderRecord, KeyFields } from './records.ts';

/**
 * Everything the core needs from a key type; the core never names a type. A key type owns its part of the
 * key record, its public-key check and its member of `Signature`, so the core assumes neither a sealed private
 * key nor a signature shape. A new key type is one module in `key-types/` and one entry in `keyTypes`.
 */
export interface KeyType<Part extends object = object, Sig extends object = object> {
  /** Whether a key of this type can be added to a vault that has never seen it. */
  readonly canAdd: boolean;
  /** The names of this type's own fields of a key record, beside `KeyFields`. */
  readonly fields: readonly string[];
  /** Reads this type's own fields of a stored key record into a new object; throws `corrupted`. Runs on every read, without any secret. */
  parse(record: Fields): Part;
  /** Whether stored bytes are a valid public key of this type. Runs on every read, without any secret. */
  isPublicKey(bytes: Bytes): boolean;
  /** A fresh key, not yet stored. */
  generate(): Promise<NewKey<Part>>;
  /** Signs `data` with a stored key and checks the signature under its public key; a stored key that fails is `corrupted`. */
  sign(record: KeyFields & Part, header: HeaderRecord, data: Bytes): Promise<Sig>;
}

export interface NewKey<Part extends object = object> {
  readonly publicKey: Bytes;
  /** This type's part of the record of `fields`, in the vault of `header`. */
  part(fields: KeyFields, header: HeaderRecord): Promise<Part>;
  /** Zeroes the secret buffers the type owns. The core calls it once the key is stored or abandoned. */
  erase(): void;
}

export const keyTypes = { ed25519, secp256k1 } satisfies Record<string, KeyType>;

export type KeyTypeName = keyof typeof keyTypes;

/** The key types that can add an existing key. */
export type AddableKeyTypeName = {
  [T in KeyTypeName]: (typeof keyTypes)[T]['canAdd'] extends true ? T : never;
}[KeyTypeName];

/** The member of `Signature` that key type `T` returns, besides its `type`. */
export type SignatureOf<T extends KeyTypeName> = Awaited<ReturnType<(typeof keyTypes)[T]['sign']>>;

/** Key type `name`, as the core sees every type: its record part and its signature are its own. */
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
