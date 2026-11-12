import { encode, type Bytes } from './bytes.ts';

// Storage format v1: the IV length and the HKDF domain separator decide whether a stored key opens.
export const IV_LENGTH = 12;
const SEAL_DOMAIN = 'vault/v1/seal';
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
  const publicKey = await crypto.subtle.exportKey('spki', pair.publicKey);
  return { publicKey: new Uint8Array(publicKey), privateKey: pair.privateKey };
}

// SPKI, not raw or JWK: WebKit accepts off-curve points in those formats, which opens an invalid-curve attack
// on the wrapping private key through records an attacker plants.
// Firefox imports an SPKI of another curve as asked and names its real curve in `algorithm`, so it is checked here.
export async function importPublicKey(spki: Bytes): Promise<CryptoKey> {
  const key = await crypto.subtle.importKey('spki', spki, P256, false, []);
  if (!('namedCurve' in key.algorithm) || key.algorithm.namedCurve !== P256.namedCurve) {
    throw new DOMException(`Not a ${P256.namedCurve} public key`, 'DataError');
  }
  return key;
}

/**
 * ECIES: encrypts to the wrapping public key alone, so adding a key never needs a secret.
 * `encrypt` receives a cipher bound to `aad` and returns the ciphertext.
 */
export async function seal(
  recipientPublicKey: Bytes,
  aad: Bytes,
  encrypt: (cipher: Cipher) => Promise<ArrayBuffer>,
): Promise<Sealed> {
  const { sharedKey, ephemeralPublicKey } = await encapsulate(recipientPublicKey);
  const iv = crypto.getRandomValues(new Uint8Array(IV_LENGTH));
  const ciphertext = await encrypt({ key: sharedKey, params: aesGcmParams(iv, aad) });
  return { ephemeralPublicKey, iv, ciphertext: new Uint8Array(ciphertext) };
}

/** The cipher that opens `sealed`, given the wrapping private key and its SPKI public half. */
export async function unseal(
  privateKey: CryptoKey,
  recipientPublicKey: Bytes,
  sealed: Sealed,
  aad: Bytes,
): Promise<Cipher> {
  const sharedKey = await decapsulate(privateKey, sealed.ephemeralPublicKey, recipientPublicKey);
  return { key: sharedKey, params: aesGcmParams(sealed.iv, aad) };
}

/** A fresh one-time key pair agrees a key with the recipient; only its public half is kept. */
async function encapsulate(recipientPublicKey: Bytes): Promise<{ sharedKey: CryptoKey; ephemeralPublicKey: Bytes }> {
  const ephemeral = await crypto.subtle.generateKey(P256, false, ['deriveKey']);
  const exported = await crypto.subtle.exportKey('spki', ephemeral.publicKey);
  const ephemeralPublicKey = new Uint8Array(exported);
  const recipient = await importPublicKey(recipientPublicKey);
  const sharedKey = await deriveSharedKey(ephemeral.privateKey, recipient, ephemeralPublicKey, recipientPublicKey);
  return { sharedKey, ephemeralPublicKey };
}

/** The recipient re-derives the same key from its private key and the stored one-time public key. */
async function decapsulate(
  privateKey: CryptoKey,
  ephemeralPublicKey: Bytes,
  recipientPublicKey: Bytes,
): Promise<CryptoKey> {
  const ephemeral = await importPublicKey(ephemeralPublicKey);
  return deriveSharedKey(privateKey, ephemeral, ephemeralPublicKey, recipientPublicKey);
}

// Both public keys enter HKDF, so the AES key is bound to this exact ephemeral and wrapping key pair.
async function deriveSharedKey(
  privateKey: CryptoKey,
  publicKey: CryptoKey,
  ephemeralSpki: Bytes,
  recipientSpki: Bytes,
) {
  const secret = await ecdhSecret(privateKey, publicKey);
  const info = encode(SEAL_DOMAIN, ephemeralSpki, recipientSpki);
  return hkdfToAes(secret, info);
}

/** ECDH, kept inside WebCrypto as an HKDF base key: the shared secret never becomes JS bytes. */
function ecdhSecret(privateKey: CryptoKey, publicKey: CryptoKey): Promise<CryptoKey> {
  return crypto.subtle.deriveKey({ name: 'ECDH', public: publicKey }, privateKey, 'HKDF', false, ['deriveKey']);
}

function hkdfToAes(secret: CryptoKey, info: Bytes): Promise<CryptoKey> {
  return crypto.subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(), info },
    secret,
    { name: 'AES-GCM', length: 256 },
    false,
    ['wrapKey', 'unwrapKey', 'encrypt', 'decrypt'],
  );
}

function aesGcmParams(iv: Bytes, aad: Bytes): AesGcmParams {
  return { name: 'AES-GCM', iv, additionalData: aad };
}
