import { ed25519 as edwards } from '@noble/curves/ed25519.js';
import type { KeyType } from './key-types.ts';

// WebKit fails ~0.7% of generations, independently: all 5 attempts fail with p ≈ 0.007⁵ ≈ 2·10⁻¹¹ (3 would be
// ≈ 3·10⁻⁷, once per ~3 million keys), and a persistent failure still surfaces quickly as 'unavailable'.
const ATTEMPTS = 5;

// RFC 8032 strict decoding, not ZIP-215: rejects non-canonical encodings and small-order public keys.
const STRICT = { zip215: false };

/**
 * Ed25519 (RFC 8032). Public key: 32 bytes. Signature: 64 bytes over the exact bytes passed to `sign`.
 * The private key lives only in WebCrypto, as a CryptoKey, never as JS bytes.
 */
export const ed25519: KeyType = {
  isValidPublicKey: (publicKey) => edwards.utils.isValidPublicKey(publicKey, STRICT.zip215),

  async generate() {
    const { publicKey, privateKey } = await generateKeyPair();
    return {
      publicKey: new Uint8Array(await crypto.subtle.exportKey('raw', publicKey)),
      // wrapKey encrypts the private key inside WebCrypto, so its bytes never reach JS.
      seal: ({ key, params }) => crypto.subtle.wrapKey('pkcs8', privateKey, key, params),
      dispose() {}, // a CryptoKey can't be erased from JS; it goes when this object is collected
    };
  },

  async sign(sealed, { key, params }, data) {
    const privateKey = await crypto.subtle.unwrapKey('pkcs8', sealed, key, params, 'Ed25519', false, ['sign']);
    return new Uint8Array(await crypto.subtle.sign('Ed25519', privateKey, data));
  },

  // noble, not crypto.subtle.verify: WebKit's verify kills the page's process on some degenerate public keys,
  // which a storage writer can plant. Verification handles public data only.
  async verify(publicKey, signature, data) {
    return edwards.verify(signature, data, publicKey, STRICT);
  },
};

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
