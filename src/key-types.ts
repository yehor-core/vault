import type { Bytes } from './bytes.ts';
import { ed25519 } from './ed25519.ts';
import type { Cipher } from './seal.ts';
import { secp256k1 } from './secp256k1.ts';

/** A key pair generated for one `generate` call, not yet stored. */
export interface GeneratedKey {
  readonly publicKey: Bytes;
  /** Encrypts the private half with `cipher`. Called again with a new cipher when the write is redone. */
  seal(cipher: Cipher): Promise<ArrayBuffer>;
  /** Called once the key is stored or abandoned: erases whatever private material JS can erase. */
  dispose(): void;
}

/** Everything the core needs from a key type; the core never branches on type names. */
export interface KeyType {
  /** Whether bytes read from storage are a valid public key of this type. Checked by list(), without any secret. */
  isValidPublicKey(publicKey: Bytes): boolean;
  generate(): Promise<GeneratedKey>;
  /** Decrypts `sealed` with `cipher` and signs `data`. */
  sign(sealed: Bytes, cipher: Cipher, data: Bytes): Promise<Bytes>;
  verify(publicKey: Bytes, signature: Bytes, data: Bytes): Promise<boolean>;
}

/** Adding a key type: one module implementing KeyType, and one line here. */
export const keyTypes = { ed25519, secp256k1 } satisfies Record<string, KeyType>;

export type KeyTypeName = keyof typeof keyTypes;

export function isKeyTypeName(value: unknown): value is KeyTypeName {
  return typeof value === 'string' && Object.hasOwn(keyTypes, value);
}

// Storage format v1: every key type name has this form. A stored name of this form that this build doesn't know
// was written by a newer build; anything else is not a type name at all.
const TYPE_NAME = /^[a-z0-9]+(?:-[a-z0-9]+)*$/;
const MAX_TYPE_NAME_LENGTH = 32;

export function isTypeNameForm(value: unknown): value is string {
  return typeof value === 'string' && value.length <= MAX_TYPE_NAME_LENGTH && TYPE_NAME.test(value);
}
