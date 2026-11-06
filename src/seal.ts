import { encode, type Bytes } from './bytes.ts';

const P256: EcKeyImportParams = { name: 'ECDH', namedCurve: 'P-256' };

/** An AES-256-GCM key and parameters that seal exactly one private key. */
export interface Cipher {
  readonly key: CryptoKey;
  readonly params: AesGcmParams;
}

export interface Sealed {
  /** SPKI of the one-time ECDH key. */
  readonly ephemeralPublicKey: Bytes;
  readonly iv: Bytes;
  readonly ciphertext: Bytes;
}

/** A fresh wrapping key pair: SPKI public half, non-extractable private half that can only derive keys. */
export async function generateWrappingKey(): Promise<{ publicKey: Bytes; privateKey: CryptoKey }> {
  const pair = await crypto.subtle.generateKey(P256, false, ['deriveKey']);
  return { publicKey: new Uint8Array(await crypto.subtle.exportKey('spki', pair.publicKey)), privateKey: pair.privateKey };
}

// SPKI, not raw or JWK: WebKit accepts off-curve points in those formats, which opens an invalid-curve attack
// on the wrapping private key through records an attacker plants.
export function importPublicKey(spki: Bytes): Promise<CryptoKey> {
  return crypto.subtle.importKey('spki', spki, P256, false, []);
}

/**
 * ECIES: encrypts to the wrapping public key alone, so adding a key never needs a secret.
 * `encrypt` receives a cipher bound to `aad` and returns the ciphertext.
 */
export async function seal(
  recipient: Bytes,
  aad: Bytes,
  encrypt: (cipher: Cipher) => Promise<ArrayBuffer>,
): Promise<Sealed> {
  const ephemeral = await crypto.subtle.generateKey(P256, false, ['deriveKey']);
  const ephemeralPublicKey = new Uint8Array(await crypto.subtle.exportKey('spki', ephemeral.publicKey));
  const key = await deriveAesKey(ephemeral.privateKey, await importPublicKey(recipient), ephemeralPublicKey, recipient);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = new Uint8Array(await encrypt({ key, params: { name: 'AES-GCM', iv, additionalData: aad } }));
  return { ephemeralPublicKey, iv, ciphertext };
}

/** The cipher that opens `sealed`, given the wrapping private key and its SPKI public half. */
export async function unseal(privateKey: CryptoKey, recipient: Bytes, sealed: Sealed, aad: Bytes): Promise<Cipher> {
  const ephemeral = await importPublicKey(sealed.ephemeralPublicKey);
  const key = await deriveAesKey(privateKey, ephemeral, sealed.ephemeralPublicKey, recipient);
  return { key, params: { name: 'AES-GCM', iv: sealed.iv, additionalData: aad } };
}

async function deriveAesKey(privateKey: CryptoKey, publicKey: CryptoKey, ephemeral: Bytes, recipient: Bytes) {
  // Both public keys enter HKDF, so the AES key is bound to this exact ephemeral and wrapping key pair.
  const shared = await crypto.subtle.deriveKey({ name: 'ECDH', public: publicKey }, privateKey, 'HKDF', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(), info: encode('vault/v1/seal', ephemeral, recipient) },
    shared,
    { name: 'AES-GCM', length: 256 },
    false,
    ['wrapKey', 'unwrapKey', 'encrypt', 'decrypt'],
  );
}
