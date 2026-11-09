import { secp256k1 as curve } from '@noble/curves/secp256k1.js';
import type { Bytes } from './bytes.ts';
import type { KeyType } from './key-types.ts';

const SECRET_KEY_LENGTH = 32;
// noble reduces a seed 16 bytes longer than the key mod n, so the bias is negligible (FIPS 186-5 A.4.1); it checks the length.
const SEED_LENGTH = 48;

// Passed explicitly, never taken from noble's defaults: together they define what a 'secp256k1' signature is,
// and a default changing in a noble release must not change it silently.
const SIGN = { prehash: true, lowS: true, format: 'compact', extraEntropy: false } as const;
const VERIFY = { prehash: true, lowS: true, format: 'compact' } as const;

/**
 * ECDSA on secp256k1 over SHA-256(data), with RFC 6979 deterministic nonces. Public key: 33-byte compressed SEC1.
 * Signature: 64 bytes, r ‖ s (IEEE P1363), low-S. WebCrypto has no secp256k1, so @noble/curves does the curve
 * arithmetic, and the private key exists as JS bytes while a key is generated and while it signs.
 */
export const secp256k1: KeyType = {
  isValidPublicKey: (publicKey) => curve.utils.isValidPublicKey(publicKey, true),

  async generate() {
    const secretKey = newSecretKey();
    const publicKey: Bytes = new Uint8Array(curve.getPublicKey(secretKey, true));
    return {
      publicKey,
      // The raw 32-byte scalar is the sealed plaintext.
      seal: ({ key, params }) => crypto.subtle.encrypt(params, key, secretKey),
      dispose: () => secretKey.fill(0),
    };
  },

  async sign(sealed, { key, params }, data) {
    const secretKey = new Uint8Array(await crypto.subtle.decrypt(params, key, sealed));
    try {
      // A storage writer can seal any bytes to the public wrapping key: insist on a valid scalar.
      if (secretKey.length !== SECRET_KEY_LENGTH || !curve.utils.isValidSecretKey(secretKey)) {
        throw new Error('The sealed value is not a secp256k1 private key');
      }
      return new Uint8Array(curve.sign(data, secretKey, SIGN));
    } finally {
      secretKey.fill(0);
    }
  },

  async verify(publicKey, signature, data) {
    return curve.verify(signature, data, publicKey, VERIFY);
  },
};

/** A uniformly random valid scalar, from a seed Vault owns so it can erase it. */
function newSecretKey(): Bytes {
  const seed = crypto.getRandomValues(new Uint8Array(SEED_LENGTH));
  try {
    return curve.utils.randomSecretKey(seed) as Bytes;
  } finally {
    seed.fill(0);
  }
}
