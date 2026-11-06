import type { Bytes } from './bytes.ts';
import { ed25519 } from './ed25519.ts';
import type { Cipher } from './seal.ts';

/** Everything the core needs from a key type; the core never branches on type names. */
export interface KeyType {
  /** Exact length of the public key; a stored key of any other length is corrupted. */
  readonly publicKeyLength: number;
  /** A fresh key pair. `seal` encrypts its private half with the given cipher. */
  generate(): Promise<{ publicKey: Bytes; seal(cipher: Cipher): Promise<ArrayBuffer> }>;
  /** Decrypts `sealed` with `cipher` and signs `data`. */
  sign(sealed: Bytes, cipher: Cipher, data: Bytes): Promise<Bytes>;
  verify(publicKey: Bytes, signature: Bytes, data: Bytes): Promise<boolean>;
}

export const keyTypes = { ed25519 } satisfies Record<string, KeyType>;

export type KeyTypeName = keyof typeof keyTypes;

export function isKeyTypeName(value: unknown): value is KeyTypeName {
  return typeof value === 'string' && Object.hasOwn(keyTypes, value);
}
