import { base64url, encode, isString, type Bytes } from './bytes.ts';
import { VaultError } from './errors.ts';
import { isKeyTypeName, isWellFormedKeyTypeName, keyType, type KeyTypeName } from './key-types.ts';
import {
  assertOnlyFields,
  corrupted,
  readBytes,
  readCryptoKey,
  readObject,
  readString,
  readUint,
  type Fields,
} from './readers.ts';

/** Storage format version, and also the IndexedDB schema version: a newer format always bumps both. */
export const FORMAT_VERSION = 1;
// Domain separators: the first part of every hashed or authenticated value, so no two uses can collide.
const DOMAIN_KEY_ID = 'vault/v1/key-id';
/** Long enough for any origin, so an embedding layer can name a scope after its sender. */
export const MAX_SCOPE_NAME_LENGTH = 1024;
/** In UTF-16 code units. */
export const MAX_LABEL_LENGTH = 256;

/** The single `meta/header` record: the wrapping key pair every private key is sealed to. */
export interface HeaderRecord {
  readonly v: typeof FORMAT_VERSION;
  /** SPKI, P-256. */
  readonly wrappingPublicKey: Bytes;
  /** Unprotected: the wrapping private key itself, as a non-extractable CryptoKey. */
  readonly protection: { readonly kind: 'none'; readonly privateKey: CryptoKey };
}

/** The fields every key record has, whatever its type. */
export interface KeyFields {
  readonly v: typeof FORMAT_VERSION;
  readonly scope: string;
  readonly id: string;
  readonly type: KeyTypeName;
  readonly publicKey: Bytes;
  /** Milliseconds since the epoch. */
  readonly createdAt: number;
  /** Stored only when given: a record without one keeps its v1 AAD. */
  readonly label?: string;
}

/** A `keys` record, keyed by [scope, id]: the common fields, then its key type's own part, opaque to the core. */
export type KeyRecord = KeyFields & Readonly<Fields>;

/** The fields of a key record that are not its type's own. */
const KEY_FIELDS = ['v', 'scope', 'id', 'type', 'publicKey', 'createdAt', 'label'];

/** A well-formed string of 1 to MAX_SCOPE_NAME_LENGTH UTF-16 code units, compared exactly (no normalisation). */
export function isScopeName(value: unknown): value is string {
  return isWellFormedString(value, MAX_SCOPE_NAME_LENGTH);
}

/** A well-formed string of 1 to MAX_LABEL_LENGTH UTF-16 code units. */
export function isLabel(value: unknown): value is string {
  return isWellFormedString(value, MAX_LABEL_LENGTH);
}

function isWellFormedString(value: unknown, maxLength: number): value is string {
  return isString(value) && value.length >= 1 && value.length <= maxLength && value.isWellFormed();
}

// Readers of the fields records have whatever their key type; the generic readers are in `readers.ts`.

function readVersion(value: unknown, name: string): typeof FORMAT_VERSION {
  if (value !== FORMAT_VERSION) throw corrupted(name);
  return FORMAT_VERSION;
}

function readScopeName(value: unknown, name: string): string {
  if (!isScopeName(value)) throw corrupted(name);
  return value;
}

function readLabel(value: unknown, name: string): string {
  if (!isLabel(value)) throw corrupted(name);
  return value;
}

function readPublicKey(value: unknown, name: string, type: KeyTypeName): Bytes {
  const bytes = readBytes(value, name);
  if (!keyType(type).isPublicKey(bytes)) throw corrupted(name);
  return bytes;
}

/** A well-formed name this build doesn't know is incompatible, not corrupted: most likely a newer build's type (D-21). */
function readKeyType(value: unknown, name: string): KeyTypeName {
  if (isKeyTypeName(value)) return value;
  if (isWellFormedKeyTypeName(value)) {
    throw new VaultError('incompatible', `Unknown key type: ${name} is ${value}`);
  }
  throw corrupted(name);
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

function parseKeyShape(value: unknown): KeyRecord {
  const key = readObject(value, 'key');
  const v = readVersion(key.v, 'key.v');
  // Before the rest: a newer key type may have fields of its own (D-21).
  const type = readKeyType(key.type, 'key.type');
  const { fields, parse } = keyType(type);
  assertOnlyFields(key, 'key', [...KEY_FIELDS, ...fields]);
  return {
    v,
    scope: readScopeName(key.scope, 'key.scope'),
    id: readString(key.id, 'key.id'),
    type,
    publicKey: readPublicKey(key.publicKey, 'key.publicKey', type),
    createdAt: readUint(key.createdAt, 'key.createdAt'),
    // Present means a label: a stored `label: undefined` is malformed, not absent.
    ...(Object.hasOwn(key, 'label') && { label: readLabel(key.label, 'key.label') }),
    ...parse(key),
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
  const input = encode(DOMAIN_KEY_ID, scope, type, publicKey);
  const digest = await crypto.subtle.digest('SHA-256', input);
  return base64url(new Uint8Array(digest));
}
