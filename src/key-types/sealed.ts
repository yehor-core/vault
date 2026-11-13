import { encode, type Bytes } from '../bytes.ts';
import type { KeyType, StoredKey } from '../key-types.ts';
import { assertOnlyFields, corrupted, readBytes, readObject } from '../readers.ts';
import type { HeaderRecord, KeyFields } from '../records.ts';
import { IV_LENGTH, seal, unseal, type Cipher, type Sealed } from '../seal.ts';

// Storage format v1: the domain separator and the label tag are part of every sealed record's AAD.
const DOMAIN_KEY_AAD = 'vault/v1/key';
/** Tags a label in the AAD (D-18). */
const AAD_LABEL_TAG = 'label';

/** What a key type whose private key Vault generates and stores sealed implements; `sealedKeyType` does the rest. */
export interface SealedScheme {
  /** Whether stored bytes are a valid public key of this type. Runs on every read, without any secret. */
  isPublicKey(bytes: Bytes): boolean;
  /** A fresh key pair, not yet stored. */
  generate(): Promise<GeneratedKey>;
  /** Decrypts `sealed` with `cipher` and signs `data`. */
  sign(sealed: Bytes, cipher: Cipher, data: Bytes): Promise<Bytes>;
  verify(publicKey: Bytes, signature: Bytes, data: Bytes): Promise<boolean>;
}

export interface GeneratedKey {
  readonly publicKey: Bytes;
  /** Encrypts the private half with the given cipher. */
  seal(cipher: Cipher): Promise<ArrayBuffer>;
  /** Zeroes the secret buffers the type owns. The core calls it once the key is stored or abandoned. */
  erase(): void;
}

/** The part of a key record a sealed key type owns: its private key, sealed to the vault's wrapping key. */
export interface SealedPart {
  readonly sealed: Sealed;
}

/** A sealed key type's member of `Signature`, besides its `type`. */
export interface SealedSignature {
  readonly bytes: Bytes;
}

export type SealedKeyType = KeyType<SealedPart, SealedSignature> & {
  readonly canAdd: false;
  readonly prompts: false;
  /** Nothing: the public information of a sealed key is the fields every key has. */
  info(part: SealedPart): Record<never, never>;
  readonly scheme: SealedScheme;
};

/**
 * The key type of `scheme`: its record part is `sealed`, its signature is bytes. `scheme` is called through
 * the object at every use, never captured, so a test can spy on it.
 */
export function sealedKeyType(scheme: SealedScheme): SealedKeyType {
  return {
    scheme,
    canAdd: false,
    prompts: false,
    fields: ['sealed'],
    parse: (record) => ({ sealed: parseSealed(record.sealed) }),
    isPublicKey: (bytes) => scheme.isPublicKey(bytes),
    identity: (record) => record.publicKey,
    info: () => ({}),

    async generate() {
      const generated = await scheme.generate();
      return {
        publicKey: generated.publicKey,
        identity: generated.publicKey,
        part: async (fields, header) => ({ sealed: await sealFields(header, fields, generated) }),
        erase: () => generated.erase(),
      };
    },

    async sign(_key, data, load) {
      const stored = await load();
      const { record } = stored;
      const bytes = await signWithRecord(scheme, stored, data);
      // Anyone can seal a key of their own to the public wrapping key; it decrypts fine, and only this check catches it.
      const valid = await scheme.verify(record.publicKey, bytes, data).catch(() => false);
      if (!valid) throw corrupted(`key ${record.id} does not match its public key`);
      return { bytes };
    },
  };
}

/**
 * AES-GCM associated data: every stored field except the ciphertext itself, so any edit fails decryption.
 * A label is appended after the v1 fields, tagged, so an unlabelled record keeps its v1 bytes (D-18).
 */
export function keyAad(fields: KeyFields): Bytes {
  const { v, scope, id, type, publicKey, createdAt, label } = fields;
  const labelParts = label === undefined ? [] : [AAD_LABEL_TAG, label];
  return encode(DOMAIN_KEY_AAD, v, scope, id, type, publicKey, createdAt, ...labelParts);
}

function parseSealed(value: unknown): Sealed {
  const sealed = readObject(value, 'key.sealed');
  assertOnlyFields(sealed, 'key.sealed', ['ephemeralPublicKey', 'iv', 'ciphertext']);
  return {
    ephemeralPublicKey: readBytes(sealed.ephemeralPublicKey, 'key.sealed.ephemeralPublicKey'),
    iv: readBytes(sealed.iv, 'key.sealed.iv', IV_LENGTH),
    ciphertext: readBytes(sealed.ciphertext, 'key.sealed.ciphertext'),
  };
}

async function sealFields(header: HeaderRecord, fields: KeyFields, generated: GeneratedKey): Promise<Sealed> {
  return seal(header.wrappingPublicKey, keyAad(fields), (cipher) => generated.seal(cipher)).catch((cause: unknown) => {
    // The only stored input is the wrapping public key; a fresh one always imports.
    throw cause instanceof DOMException && cause.name === 'DataError' ? corrupted('wrapping public key', cause) : cause;
  });
}

/** Decrypts the key and signs; any failure means the stored key is not what Vault sealed. */
async function signWithRecord(scheme: SealedScheme, stored: StoredKey<SealedPart>, data: Bytes): Promise<Bytes> {
  const { record, header } = stored;
  const privateKey = stored.wrappingPrivateKey(); // outside the try: a failure to get it is not a corrupted key
  try {
    const cipher = await unseal(privateKey, header.wrappingPublicKey, record.sealed, keyAad(record));
    return await scheme.sign(record.sealed.ciphertext, cipher, data); // await: so catch sees it
  } catch (cause) {
    throw corrupted(`key ${record.id} does not decrypt`, cause);
  }
}
