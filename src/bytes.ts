/** Bytes backed by a plain ArrayBuffer, as WebCrypto and IndexedDB hand them out. */
export type Bytes = Uint8Array<ArrayBuffer>;

// Storage format v1. Tags, the 4-byte length and the 8-byte integers are part of every stored key id
// and AAD: changing any of them needs a new format version.
const STRING = 1;
const BYTES = 2;
const INTEGER = 3;

const utf8 = new TextEncoder();

// Type guards: what is this value? They never throw.

/**
 * A well-formed string. UTF-8 can't carry a lone surrogate (TextEncoder writes U+FFFD instead), so 'x\uD800'
 * and 'x�' would encode alike and share a key id and AAD while IndexedDB keeps them apart.
 */
export function isString(value: unknown): value is string {
  return typeof value === 'string' && value.isWellFormed();
}

/** A byte field as Vault stores it; anything else read from storage is malformed. */
export function isBytes(value: unknown): value is Bytes {
  return value instanceof Uint8Array && value.buffer instanceof ArrayBuffer;
}

/** A safe, non-negative integer. */
export function isUint(value: unknown): value is number {
  return Number.isSafeInteger(value) && (value as number) >= 0;
}

// Converters: one value into raw bytes.

function utf8ToBytes(text: string): Bytes {
  return utf8.encode(text);
}

/** Exactly 8 bytes, big-endian. */
function uint64ToBytes(n: number): Bytes {
  const bytes = new Uint8Array(8);
  new DataView(bytes.buffer).setBigUint64(0, BigInt(n));
  return bytes;
}

/** Exactly 4 bytes, big-endian. */
function uint32ToBytes(n: number): Bytes {
  const bytes = new Uint8Array(4);
  new DataView(bytes.buffer).setUint32(0, n);
  return bytes;
}

/** One self-describing field: tag, then the data's length (4 bytes), then the data. */
function toField(part: unknown): Bytes {
  let tag: number;
  let data: Uint8Array;
  if (isString(part)) {
    tag = STRING;
    data = utf8ToBytes(part);
  } else if (isBytes(part)) {
    tag = BYTES;
    data = part;
  } else if (isUint(part)) {
    tag = INTEGER;
    data = uint64ToBytes(part);
  } else {
    throw new TypeError(`Cannot encode ${String(part)}`);
  }
  return concatBytes(Uint8Array.of(tag), uint32ToBytes(data.length), data);
}

function concatBytes(...arrays: Uint8Array[]): Bytes {
  const out = new Uint8Array(arrays.reduce((size, array) => size + array.length, 0));
  let offset = 0;
  for (const array of arrays) {
    out.set(array, offset);
    offset += array.length;
  }
  return out;
}

/**
 * Unambiguous, typed concatenation of fields. The tag keeps each value's type in the output,
 * so 123 and "123" never encode alike, and field boundaries can't shift.
 */
export function encode(...parts: (string | Bytes | number)[]): Bytes {
  return concatBytes(...parts.map(toField));
}

export function base64url(bytes: Uint8Array): string {
  return bytes.toBase64({ alphabet: 'base64url', omitPadding: true });
}

/** Not constant-time: for public values only. */
export function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && a.every((byte, i) => byte === b[i]);
}
