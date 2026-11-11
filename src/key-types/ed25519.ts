import { ed25519 as curve } from '@noble/curves/ed25519.js';
import type { Bytes } from '../bytes.ts';
import type { KeyType } from '../key-types.ts';

// WebKit fails ~0.7% of generations, independently: all 5 attempts fail with p ≈ 0.007⁵ ≈ 2·10⁻¹¹ (3 would be
// ≈ 3·10⁻⁷, once per ~3 million keys), and a persistent failure still surfaces quickly as 'unavailable'.
const ATTEMPTS = 5;
const PUBLIC_KEY_LENGTH = 32;
// Strict RFC 8032 decoding, which also rejects small-order public keys. Explicit: noble's default is ZIP-215.
const VERIFY_OPTIONS = { zip215: false } as const;

/**
 * Ed25519 (RFC 8032), signed on WebCrypto and verified on @noble/curves. The public key is its 32-byte
 * encoding; a signature is 64 bytes, over the exact bytes passed to `sign`. The private key travels only as
 * a CryptoKey, never as JS bytes; verification handles only public data.
 */
export const ed25519: KeyType = {
  isPublicKey,

  async generate() {
    const { publicKey, privateKey } = await generateKeyPair();
    return {
      publicKey: new Uint8Array(await crypto.subtle.exportKey('raw', publicKey)),
      // wrapKey encrypts the private key inside WebCrypto, so its bytes never reach JS.
      seal: ({ key, params }) => crypto.subtle.wrapKey('pkcs8', privateKey, key, params),
      erase: () => {}, // the secret is a CryptoKey: no buffer of ours holds it
    };
  },

  async sign(sealed, { key, params }, data) {
    const privateKey = await crypto.subtle.unwrapKey('pkcs8', sealed, key, params, 'Ed25519', false, ['sign']);
    return new Uint8Array(await crypto.subtle.sign('Ed25519', privateKey, data));
  },

  // On the curve library, never crypto.subtle.verify: WebKit's crashes the tab on some public keys (D-20).
  async verify(publicKey, signature, data) {
    return curve.verify(signature, data, publicKey, VERIFY_OPTIONS);
  },
};

/**
 * A canonical RFC 8032 point encoding (y < p, no x = 0 with the sign bit set) of a point outside the
 * small-order subgroup: the same decoding strict verification applies.
 */
function isPublicKey(bytes: Bytes): boolean {
  if (bytes.length !== PUBLIC_KEY_LENGTH) return false;
  try {
    return !curve.Point.fromBytes(bytes, VERIFY_OPTIONS.zip215).isSmallOrder();
  } catch {
    return false; // not a point encoding
  }
}

// WebKit rejects about 0.7% of Ed25519 generations with OperationError (apparently keys with a leading
// zero byte). Generation has no side effects, so a retry simply draws another key.
async function generateKeyPair(): Promise<CryptoKeyPair> {
  for (let attempt = 1; ; attempt++) {
    try {
      // Extractable only so wrapKey can seal it.
      return await crypto.subtle.generateKey('Ed25519', true, ['sign', 'verify']);
    } catch (error) {
      if (attempt === ATTEMPTS || !(error instanceof DOMException && error.name === 'OperationError')) throw error;
    }
  }
}
