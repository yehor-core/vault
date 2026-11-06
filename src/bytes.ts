/** Bytes backed by a plain ArrayBuffer, as WebCrypto and IndexedDB hand them out. */
export type Bytes = Uint8Array<ArrayBuffer>;

const utf8 = new TextEncoder();

/** Unambiguous concatenation: each part is prefixed with its 4-byte big-endian length. */
export function encode(...parts: (string | Uint8Array)[]): Bytes {
  const chunks = parts.map((part) => (typeof part === 'string' ? utf8.encode(part) : part));
  const out = new Uint8Array(chunks.reduce((size, chunk) => size + 4 + chunk.length, 0));
  const view = new DataView(out.buffer);
  let offset = 0;
  for (const chunk of chunks) {
    view.setUint32(offset, chunk.length);
    out.set(chunk, offset + 4);
    offset += 4 + chunk.length;
  }
  return out;
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
