import type { KeyType } from './key-types.ts';

/** Ed25519 (RFC 8032) on WebCrypto. The private key travels only as a CryptoKey, never as JS bytes. */
export const ed25519: KeyType = {
  async generate() {
    // Extractable only so wrapKey can seal it.
    const pair = await crypto.subtle.generateKey('Ed25519', true, ['sign', 'verify']);
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
