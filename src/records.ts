import { base64url, encode, isBytes, isString, isUint, type Bytes } from './bytes.ts';
import { VaultError } from './errors.ts';
import { isKeyTypeName, isTypeNameForm, keyTypes, type KeyTypeName } from './key-types.ts';
import { IV_LENGTH, type Sealed } from './seal.ts';

/** Storage format version, and also the IndexedDB schema version: a newer format always bumps both. */
export const FORMAT_VERSION = 1;
const LABEL_KEY_ID = 'vault/v1/key-id';
const LABEL_KEY_AAD = 'vault/v1/key';
const MAX_SCOPE_LENGTH = 1024; // UTF-16 code units: room for any origin, which an embedding may use as a scope
const MAX_LABEL_LENGTH = 256;

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
  /** Absent, never undefined, when the caller gave none. */
  readonly label?: string;
  readonly sealed: Sealed;
}

export type KeyFields = Omit<KeyRecord, 'sealed'>;

// Field readers. Everything read from IndexedDB is untrusted: each reader checks one field, never coerces,
// and names the field when it fails.

type Fields = Record<string, unknown>;

function readObject(value: unknown, name: string): Fields {
  if (typeof value !== 'object' || value === null) throw corrupted(name);
  return value as Fields;
}

function readVersion(value: unknown, name: string): typeof FORMAT_VERSION {
  if (value !== FORMAT_VERSION) throw corrupted(name);
  return FORMAT_VERSION;
}

function readString(value: unknown, name: string): string {
  if (!isString(value)) throw corrupted(name);
  return value;
}

function readBytes(value: unknown, name: string, length?: number): Bytes {
  if (!isBytes(value)) throw corrupted(name);
  if (length !== undefined && value.length !== length) throw corrupted(name);
  return value;
}

function readUint(value: unknown, name: string): number {
  if (!isUint(value)) throw corrupted(name);
  return value;
}

function readKeyType(value: unknown, name: string): KeyTypeName {
  if (isKeyTypeName(value)) return value;
  if (isTypeNameForm(value)) {
    throw new VaultError('incompatible', `Storage holds a key of type ${value}, which this build does not know`);
  }
  throw corrupted(name);
}

function readScope(value: unknown, name: string): string {
  if (!isScopeName(value)) throw corrupted(name);
  return value;
}

function readLabel(value: unknown, name: string): string {
  if (!isLabel(value)) throw corrupted(name);
  return value;
}

function readPublicKey(value: unknown, type: KeyTypeName, name: string): Bytes {
  const publicKey = readBytes(value, name);
  if (!keyTypes[type].isValidPublicKey(publicKey)) throw corrupted(name);
  return publicKey;
}

function readCryptoKey(value: unknown, name: string): CryptoKey {
  if (!(value instanceof CryptoKey)) throw corrupted(name);
  return value;
}

// Vault writes the exact shape itself: an extra field is tampering or a foreign format (a newer one fails on `v`).
function assertOnlyFields(object: Fields, name: string, allowed: readonly string[]): void {
  for (const field of Object.keys(object)) {
    if (!allowed.includes(field)) throw corrupted(`${name}: unexpected field ${field}`);
  }
}

// Shape parsers: built only from the readers, and each returns a new object, never the stored one.

export function parseHeader(value: unknown): HeaderRecord {
  const header = readObject(value, 'header');
  const v = readVersion(header.v, 'header.v');
  assertOnlyFields(header, 'header', ['v', 'wrappingPublicKey', 'protection']);
  return {
    v,
    wrappingPublicKey: readBytes(header.wrappingPublicKey, 'header.wrappingPublicKey'),
    protection: parseProtection(header.protection),
  };
}

// Only unprotected so far; passkey protection adds its kind (and its fields) here.
function parseProtection(value: unknown): HeaderRecord['protection'] {
  const protection = readObject(value, 'header.protection');
  if (protection.kind !== 'none') throw corrupted('header.protection.kind');
  assertOnlyFields(protection, 'header.protection', ['kind', 'privateKey']);
  return { kind: 'none', privateKey: readCryptoKey(protection.privateKey, 'header.protection.privateKey') };
}

function parseSealed(value: unknown): Sealed {
  const sealed = readObject(value, 'key.sealed');
  assertOnlyFields(sealed, 'key.sealed', ['ephemeralPublicKey', 'iv', 'ciphertext']);
  return {
    ephemeralPublicKey: readBytes(sealed.ephemeralPublicKey, 'key.sealed.ephemeralPublicKey'),
    iv: readBytes(sealed.iv, 'key.sealed.iv', IV_LENGTH),
    ciphertext: readBytes(sealed.ciphertext, 'key.sealed.ciphertext'),
  };
}

function parseKeyShape(value: unknown): KeyRecord {
  const key = readObject(value, 'key');
  const v = readVersion(key.v, 'key.v');
  // Before the field list: a key type from a newer build may bring fields this build doesn't know.
  const type = readKeyType(key.type, 'key.type');
  assertOnlyFields(key, 'key', ['v', 'scope', 'id', 'type', 'publicKey', 'createdAt', 'label', 'sealed']);
  return {
    v,
    scope: readScope(key.scope, 'key.scope'),
    id: readString(key.id, 'key.id'),
    type,
    publicKey: readPublicKey(key.publicKey, type, 'key.publicKey'),
    createdAt: readUint(key.createdAt, 'key.createdAt'),
    // hasOwn, not `!== undefined`: Vault never stores `label: undefined`, so such a field is malformed.
    ...(Object.hasOwn(key, 'label') ? { label: readLabel(key.label, 'key.label') } : {}),
    sealed: parseSealed(key.sealed),
  };
}

/** The id is derived, so an edited public key, type or scope is caught without any secret. */
async function assertIdMatches(record: KeyRecord): Promise<void> {
  const expected = await keyId(record.scope, record.type, record.publicKey);
  if (record.id !== expected) throw corrupted('key.id does not match its public key');
}

export async function parseKeyRecord(value: unknown): Promise<KeyRecord> {
  const record = parseKeyShape(value);
  await assertIdMatches(record);
  return record;
}

export async function keyId(scope: string, type: KeyTypeName, publicKey: Bytes): Promise<string> {
  const input = encode(LABEL_KEY_ID, scope, type, publicKey);
  const digest = await crypto.subtle.digest('SHA-256', input);
  return base64url(new Uint8Array(digest));
}

/** AES-GCM associated data: every stored field except the ciphertext itself, so any edit fails decryption. */
export function keyAad(fields: KeyFields): Bytes {
  const { v, scope, id, type, publicKey, createdAt, label } = fields;
  // A tagged pair only when present, so records without a label keep their exact format-v1 AAD.
  const optional = label === undefined ? [] : ['label', label];
  return encode(LABEL_KEY_AAD, v, scope, id, type, publicKey, createdAt, ...optional);
}

/** A scope name, as the API accepts it and as storage must hold it. */
export function isScopeName(value: unknown): value is string {
  return isString(value) && value.length > 0 && value.length <= MAX_SCOPE_LENGTH;
}

/** A label, as the API accepts it and as storage must hold it. */
export function isLabel(value: unknown): value is string {
  return isString(value) && value.length > 0 && value.length <= MAX_LABEL_LENGTH;
}

export function corrupted(what: string, cause?: unknown): VaultError {
  return new VaultError('corrupted', `Corrupted storage: ${what}`, { cause });
}
