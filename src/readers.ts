import { isBytes, isString, isUint, type Bytes } from './bytes.ts';
import { VaultError } from './errors.ts';

// Field readers for everything read from IndexedDB, which is untrusted: each checks one field, never coerces,
// and names the field when it fails. The core and the key types build their parsers from them.

export type Fields = Record<string, unknown>;

export function readObject(value: unknown, name: string): Fields {
  if (typeof value !== 'object' || value === null) throw corrupted(name);
  return value as Fields; // `as`: a non-null object, checked above; its fields stay unknown
}

export function readString(value: unknown, name: string): string {
  if (!isString(value)) throw corrupted(name);
  return value;
}

export function readBytes(value: unknown, name: string, length?: number): Bytes {
  if (!isBytes(value)) throw corrupted(name);
  if (length !== undefined && value.length !== length) throw corrupted(name);
  return value;
}

export function readUint(value: unknown, name: string): number {
  if (!isUint(value)) throw corrupted(name);
  return value;
}

export function readCryptoKey(value: unknown, name: string): CryptoKey {
  if (!(value instanceof CryptoKey)) throw corrupted(name);
  return value;
}

// Vault writes the exact shape itself: an extra field is tampering or a foreign format (a newer one fails on `v`).
export function assertOnlyFields(object: Fields, name: string, allowed: readonly string[]): void {
  for (const field of Object.keys(object)) {
    if (!allowed.includes(field)) throw corrupted(`${name}: unexpected field ${field}`);
  }
}

export function corrupted(what: string, cause?: unknown): VaultError {
  return new VaultError('corrupted', `Corrupted storage: ${what}`, { cause });
}
