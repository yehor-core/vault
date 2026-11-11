import { secp256k1 as curve } from '@noble/curves/secp256k1.js';
import type { Bytes } from '../bytes.ts';
import type { KeyType } from '../key-types.ts';

const SCALAR_LENGTH = 32;
// 48 bytes reduced mod n: the bias of the scalar is negligible (FIPS 186-5 A.2.1). noble requires this length.
const SEED_LENGTH = 48;
// The group order n, big-endian.
const ORDER = Uint8Array.fromHex('fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141');

// Every option explicit: a library default can't change what a 'secp256k1' signature is.
const SIGN_OPTIONS = { prehash: true, lowS: true, format: 'compact', extraEntropy: false } as const;
const VERIFY_OPTIONS = { prehash: true, lowS: true, format: 'compact' } as const;

/**
 * ECDSA on secp256k1 over SHA-256 of the data, RFC 6979 nonces, low-S, a 64-byte r ‖ s signature, on
 * @noble/curves. The public key is a 33-byte compressed SEC1 point; the sealed plaintext is the raw 32-byte
 * scalar. The scalar exists as JS bytes during generate and sign; Vault zeroes the buffers it owns.
 */
export const secp256k1: KeyType = {
  isPublicKey: (bytes) => curve.utils.isValidPublicKey(bytes, true),

  async generate() {
    const secretKey = randomScalar();
    try {
      const publicKey = new Uint8Array(curve.getPublicKey(secretKey, true));
      return {
        publicKey,
        seal: ({ key, params }) => crypto.subtle.encrypt(params, key, secretKey),
        erase: () => void secretKey.fill(0),
      };
    } catch (error) {
      secretKey.fill(0);
      throw error;
    }
  },

  async sign(sealed, { key, params }, data) {
    const plaintext = await crypto.subtle.decrypt(params, key, sealed);
    const secretKey = new Uint8Array(plaintext); // a view: zeroing it zeroes the decrypted buffer
    try {
      // Checked here, not left to noble: the sealed value is untrusted, and the scheme must not depend on its checks.
      if (!isScalar(secretKey)) throw new Error('The sealed secp256k1 key is not a valid scalar');
      const signature = curve.sign(data, secretKey, SIGN_OPTIONS);
      return new Uint8Array(signature);
    } finally {
      secretKey.fill(0);
    }
  },

  async verify(publicKey, signature, data) {
    return curve.verify(signature, data, publicKey, VERIFY_OPTIONS);
  },
};

function randomScalar() {
  const seed = crypto.getRandomValues(new Uint8Array(SEED_LENGTH));
  try {
    return curve.utils.randomSecretKey(seed);
  } finally {
    seed.fill(0);
  }
}

/** 1 ≤ d < n, compared byte by byte: the secret never becomes an immutable bigint of ours. */
function isScalar(bytes: Bytes): boolean {
  if (bytes.length !== SCALAR_LENGTH || bytes.every((byte) => byte === 0)) return false;
  for (let i = 0; i < SCALAR_LENGTH; i++) {
    const [byte = 0, limit = 0] = [bytes[i], ORDER[i]];
    if (byte !== limit) return byte < limit;
  }
  return false; // equal to n
}
