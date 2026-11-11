import type { KeyType } from '../key-types.ts';

// WebKit fails ~0.7% of generations, independently: all 5 attempts fail with p ≈ 0.007⁵ ≈ 2·10⁻¹¹ (3 would be
// ≈ 3·10⁻⁷, once per ~3 million keys), and a persistent failure still surfaces quickly as 'unavailable'.
const ATTEMPTS = 5;
const PUBLIC_KEY_LENGTH = 32;

/**
 * Ed25519 (RFC 8032) on WebCrypto. The public key is its 32-byte encoding; a signature is 64 bytes, over the
 * exact bytes passed to `sign`. The private key travels only as a CryptoKey, never as JS bytes.
 */
export const ed25519: KeyType = {
  isPublicKey: (bytes) => bytes.length === PUBLIC_KEY_LENGTH,

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

  async verify(publicKey, signature, data) {
    const key = await crypto.subtle.importKey('raw', publicKey, 'Ed25519', false, ['verify']);
    return crypto.subtle.verify('Ed25519', key, signature, data);
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
