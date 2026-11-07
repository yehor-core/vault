import type { KeyType } from './key-types.ts';

// WebKit fails ~0.7% of generations, independently: all 5 attempts fail with p ≈ 0.007⁵ ≈ 2·10⁻¹¹ (3 would be
// ≈ 3·10⁻⁷, once per ~3 million keys), and a persistent failure still surfaces quickly as 'unavailable'.
const ATTEMPTS = 5;

/** Ed25519 (RFC 8032) on WebCrypto. The private key travels only as a CryptoKey, never as JS bytes. */
export const ed25519: KeyType = {
  publicKeyLength: 32,

  async generate() {
    const pair = await generateKeyPair();
    const publicKey = new Uint8Array(await crypto.subtle.exportKey('raw', pair.publicKey));
    return { publicKey, seal: (cipher) => crypto.subtle.wrapKey('pkcs8', pair.privateKey, cipher.key, cipher.params) };
  },

  async sign(sealed, cipher, data) {
    const key = await crypto.subtle.unwrapKey('pkcs8', sealed, cipher.key, cipher.params, 'Ed25519', false, ['sign']);
    return new Uint8Array(await crypto.subtle.sign('Ed25519', key, data));
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
