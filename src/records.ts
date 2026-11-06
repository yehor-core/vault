import { base64url, encode, type Bytes } from './bytes.ts';
import { VaultError } from './errors.ts';
import { isKeyTypeName, type KeyTypeName } from './key-types.ts';
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

/** The header, or undefined if the vault has none yet. */
export function parseHeader(value: unknown): HeaderRecord | undefined {
  if (value === undefined) return undefined;
  const header = value as HeaderRecord | null;
  if (header?.v !== FORMAT_VERSION || header.protection?.kind !== 'none') throw corrupted('vault header');
  return header;
}

export async function parseKeyRecord(value: unknown): Promise<KeyRecord> {
  const record = value as KeyRecord | null;
  if (record?.v !== FORMAT_VERSION || !isKeyTypeName(record.type)) throw corrupted('key record');
  if (record.id !== (await keyId(record.scope, record.type, record.publicKey))) {
    throw corrupted(`key ${record.id}: id does not match its public key`);
  }
  return record;
}

/** Derived, so an edited public key, type or scope is caught without any secret. */
export async function keyId(scope: string, type: KeyTypeName, publicKey: Bytes): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', encode('vault/v1/key-id', scope, type, publicKey));
  return base64url(new Uint8Array(digest));
}

/** AES-GCM associated data: every stored field except the ciphertext itself, so any edit fails decryption. */
export function keyAad(fields: KeyFields): Bytes {
  const { v, scope, id, type, publicKey, createdAt } = fields;
  return encode('vault/v1/key', String(v), scope, id, type, publicKey, String(createdAt));
}

export function corrupted(what: string, cause?: unknown): VaultError {
  return new VaultError('corrupted', `Corrupted storage: ${what}`, { cause });
}
