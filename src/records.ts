import { base64url, encode, isBytes, isString, isUint, type Bytes } from './bytes.ts';
import { VaultError } from './errors.ts';
import { isKeyTypeName, keyTypes, type KeyTypeName } from './key-types.ts';
import type { Sealed } from './seal.ts';

/** Storage format version, and also the IndexedDB schema version: a newer format always bumps both. */
export const FORMAT_VERSION = 1;

/** The single `meta/header` record: the wrapping key pair every private key is sealed to. */
export interface HeaderRecord {
  readonly v: typeof FORMAT_VERSION;
  /** SPKI, P-256. */
  readonly wrappingPublicKey: Bytes;
  /** Unprotected: the wrapping private key itself, as a non-extractable CryptoKey. */
  readonly protection: { readonly kind: 'none'; readonly privateKey: CryptoKey };
}

/** A `keys` record, keyed by [scope, id]. */
export interface KeyRecord {
  readonly v: typeof FORMAT_VERSION;
  readonly scope: string;
  readonly id: string;
  readonly type: KeyTypeName;
  readonly publicKey: Bytes;
  /** Milliseconds since the epoch. */
  readonly createdAt: number;
  readonly sealed: Sealed;
}

export type KeyFields = Omit<KeyRecord, 'sealed'>;

// Everything read from IndexedDB is untrusted: each field's runtime type is checked, never coerced.

export function parseHeader(value: unknown): HeaderRecord {
  const header = value as Partial<HeaderRecord> | null | undefined;
  if (
    header?.v !== FORMAT_VERSION ||
    !isBytes(header.wrappingPublicKey) ||
    header.protection?.kind !== 'none' ||
    !(header.protection.privateKey instanceof CryptoKey)
  ) {
    throw corrupted('vault header');
  }
  return header as HeaderRecord;
}

export async function parseKeyRecord(value: unknown): Promise<KeyRecord> {
  const record = value as Partial<KeyRecord> | null | undefined;
  const sealed = record?.sealed as Partial<Sealed> | undefined;
  if (
    record?.v !== FORMAT_VERSION ||
    !isString(record.scope) ||
    !isString(record.id) ||
    !isKeyTypeName(record.type) ||
    !isBytes(record.publicKey) ||
    record.publicKey.length !== keyTypes[record.type].publicKeyLength ||
    !isUint(record.createdAt) ||
    !isBytes(sealed?.ephemeralPublicKey) ||
    !isBytes(sealed.iv) ||
    sealed.iv.length !== 12 ||
    !isBytes(sealed.ciphertext)
  ) {
    throw corrupted('key record');
  }
  if (record.id !== (await keyId(record.scope, record.type, record.publicKey))) {
    throw corrupted(`key ${record.id}: id does not match its public key`);
  }
  return record as KeyRecord;
}

/** Derived, so an edited public key, type or scope is caught without any secret. */
export async function keyId(scope: string, type: KeyTypeName, publicKey: Bytes): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', encode('vault/v1/key-id', scope, type, publicKey));
  return base64url(new Uint8Array(digest));
}

/** AES-GCM associated data: every stored field except the ciphertext itself, so any edit fails decryption. */
export function keyAad(fields: KeyFields): Bytes {
  const { v, scope, id, type, publicKey, createdAt } = fields;
  return encode('vault/v1/key', v, scope, id, type, publicKey, createdAt);
}

export function corrupted(what: string, cause?: unknown): VaultError {
  return new VaultError('corrupted', `Corrupted storage: ${what}`, { cause });
}
