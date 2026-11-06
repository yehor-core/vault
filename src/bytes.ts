/** Bytes backed by a plain ArrayBuffer, as WebCrypto and IndexedDB hand them out. */
export type Bytes = Uint8Array<ArrayBuffer>;

const utf8 = new TextEncoder();

const STRING = 1;
const BYTES = 2;
const INTEGER = 3;

/**
 * Unambiguous, typed concatenation: each part is a type tag, a 4-byte big-endian length and its bytes.
 * The tag keeps a value's type in the output, so 123 and "123" never encode alike.
 */
export function encode(...parts: (string | Uint8Array | number)[]): Bytes {
  const chunks = parts.map((part): [number, Uint8Array] => {
    if (typeof part === 'string') return [STRING, utf8.encode(part)];
    if (part instanceof Uint8Array) return [BYTES, part];
    if (Number.isSafeInteger(part) && part >= 0) {
      const integer = new Uint8Array(8);
      new DataView(integer.buffer).setBigUint64(0, BigInt(part));
      return [INTEGER, integer];
    }
    throw new TypeError(`Cannot encode ${String(part)}`);
  });
  const out = new Uint8Array(chunks.reduce((size, [, chunk]) => size + 5 + chunk.length, 0));
  const view = new DataView(out.buffer);
  let offset = 0;
  for (const [tag, chunk] of chunks) {
    view.setUint8(offset, tag);
    view.setUint32(offset + 1, chunk.length);
    out.set(chunk, offset + 5);
    offset += 5 + chunk.length;
  }
  return out;
}

/** A byte field as Vault stores it; anything else read from storage is malformed. */
export function isBytes(value: unknown): value is Bytes {
  return value instanceof Uint8Array && value.buffer instanceof ArrayBuffer;
}

export function base64url(bytes: Uint8Array): string {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '');
}

/** Not constant-time: for public values only. */
export function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && a.every((byte, i) => byte === b[i]);
}
