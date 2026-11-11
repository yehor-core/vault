import type { Bytes } from './bytes.ts';
import { ed25519 } from './key-types/ed25519.ts';
import { secp256k1 } from './key-types/secp256k1.ts';
import type { Cipher } from './seal.ts';

/**
 * Everything the core needs from a sealed key type; the core never names a type. A new sealed key type is
 * one module in `key-types/` and one entry in `keyTypes`. Passkey keys, which have no sealed part, widen this.
 */
export interface KeyType {
  /** Whether stored bytes are a valid public key of this type. Runs on every read, without any secret. */
  isPublicKey(bytes: Bytes): boolean;
  /** A fresh key pair, not yet stored. */
  generate(): Promise<GeneratedKey>;
  /** Decrypts `sealed` with `cipher` and signs `data`. */
  sign(sealed: Bytes, cipher: Cipher, data: Bytes): Promise<Bytes>;
  verify(publicKey: Bytes, signature: Bytes, data: Bytes): Promise<boolean>;
}

export interface GeneratedKey {
  readonly publicKey: Bytes;
  /** Encrypts the private half with the given cipher. */
  seal(cipher: Cipher): Promise<ArrayBuffer>;
  /** Zeroes the secret buffers the type owns. The core calls it once the key is stored or abandoned. */
  erase(): void;
}

export const keyTypes = { ed25519, secp256k1 } satisfies Record<string, KeyType>;

export type KeyTypeName = keyof typeof keyTypes;

export function isKeyTypeName(value: unknown): value is KeyTypeName {
  return typeof value === 'string' && Object.hasOwn(keyTypes, value);
}
