import { sha256 } from '@noble/hashes/sha2.js';
import { encode, equalBytes, type Bytes } from './bytes.ts';
import { VaultError } from './errors.ts';
import {
  creationOptions,
  isUserVerified,
  noUserVerification,
  prompt,
  readCreatedId,
  secondPrompt,
  type StartPrompt,
} from './key-types/passkey.ts';
import { assertOnlyFields, corrupted, readBytes, type Fields } from './readers.ts';
import { IV_LENGTH, P256 } from './seal.ts';
import type { ProtectionSupport } from './vault.ts';

// Passkey protection (D-78, D-81). The one file besides the key types that names a passkey: the unlock passkey
// is no key type, and the core reaches it only through this module.

// Storage format v1: the domain separators, the kind and the lengths decide whether a protected vault unlocks.
/** The PRF input, the HKDF info and the mark of the unlock passkey's user handle. */
const DOMAIN_UNLOCK = 'vault/v1/unlock';
const DOMAIN_HEADER_AAD = 'vault/v1/header';
export const UNLOCK_KIND = 'passkey';
const SALT_LENGTH = 32;
const USER_MARK_LENGTH = 16;
const USER_ID_RANDOM_LENGTH = 16;
const UNLOCK_NAME = 'Vault unlock';
/** Nothing checks the unlock challenge: no public key of the unlock passkey is stored; it is random as the spec asks. */
const UNLOCK_CHALLENGE_LENGTH = 32;
const PRF_INPUT = encode(DOMAIN_UNLOCK);

/** A protected header's `protection`: the wrapping private key, wrapped under a key derived from the unlock passkey. */
export interface UnlockProtection {
  readonly kind: typeof UNLOCK_KIND;
  readonly credentialId: Bytes;
  readonly salt: Bytes;
  readonly iv: Bytes;
  /** PKCS #8, AES-256-GCM. */
  readonly wrappedPrivateKey: Bytes;
}

/** The unlock passkey's PRF result, as a non-extractable HKDF key, and its credential id. */
export interface UnlockSecret {
  readonly credentialId: Bytes;
  readonly secret: CryptoKey;
}

/** Reads a stored `protection` of kind UNLOCK_KIND into a new object; throws `corrupted`. */
export function parseUnlockProtection(protection: Fields): UnlockProtection {
  const name = 'header.protection';
  assertOnlyFields(protection, name, ['kind', 'credentialId', 'salt', 'iv', 'wrappedPrivateKey']);
  return {
    kind: UNLOCK_KIND,
    credentialId: readBytes(protection.credentialId, `${name}.credentialId`),
    salt: readBytes(protection.salt, `${name}.salt`, SALT_LENGTH),
    iv: readBytes(protection.iv, `${name}.iv`, IV_LENGTH),
    wrappedPrivateKey: readBytes(protection.wrappedPrivateKey, `${name}.wrappedPrivateKey`),
  };
}

/** `Vault.protectionSupport()` (D-75): `extension:prf` true says nothing of the authenticator the user will pick. */
export async function protectionSupport(): Promise<ProtectionSupport> {
  // Playwright's WebKit on Linux has a PublicKeyCredential that is no constructor, and no navigator.credentials
  if (typeof PublicKeyCredential !== 'function' || navigator.credentials === undefined) return 'unsupported';
  if (typeof PublicKeyCredential.getClientCapabilities !== 'function') return 'unknown';
  let capabilities: PublicKeyCredentialClientCapabilities;
  try {
    capabilities = await PublicKeyCredential.getClientCapabilities();
  } catch {
    return 'unknown'; // the browser didn't answer; protect() still tells
  }
  return capabilities['extension:prf'] === false ? 'unsupported' : 'unknown';
}

/** The passkey the user presented to unlock: its credential id, and its PRF result if the authenticator gave one. */
export interface PresentedUnlock {
  readonly credentialId: Bytes;
  readonly secret: CryptoKey | undefined;
}

/**
 * D-94: a prompt for the unlock passkey `credentialId`, started before any await, with user verification required and
 * the fixed PRF input: the request shape `protect()` checks (D-74). Which passkey answered is checked by the caller,
 * against the header it reads afterwards (D-77).
 */
export async function presentUnlockPasskey(credentialId: Bytes): Promise<PresentedUnlock> {
  const { credentialId: answeredBy, result } = await assertUnlock(credentialId);
  const secret = result === undefined ? undefined : await importSecret(result);
  return { credentialId: answeredBy, secret };
}

/**
 * Creates the unlock passkey, with its prompt started before any await, and returns its PRF result (D-74). The second
 * prompt follows the creation with no other await while the page has focus; without it, once focus is back (D-96).
 */
export async function createUnlockPasskey(): Promise<UnlockSecret> {
  const publicKey = {
    ...creationOptions(unlockUserId(), UNLOCK_NAME),
    extensions: { prf: { eval: { first: PRF_INPUT } } },
  };
  const pending = navigator.credentials.create({ publicKey }); // the prompt, before any await
  const credential = await prompt(pending);
  const credentialId = readCreatedId(credential); // D-95: its public key is never used, so none is required
  const prf = credential instanceof PublicKeyCredential ? credential.getClientExtensionResults().prf : undefined;
  let result = prf?.results?.first;
  if (result === undefined && prf?.enabled === true) {
    const second = await assertUnlock(credentialId, secondPrompt);
    if (!equalBytes(second.credentialId, credentialId))
      throw new VaultError('unavailable', 'The second prompt was answered by another passkey');
    result = second.result;
  }
  if (result === undefined) throw new VaultError('unsupported', 'The authenticator returned no PRF result');
  const secret = await importSecret(result);
  return { credentialId, secret };
}

/**
 * A prompt for the unlock passkey `credentialId`, started by `ask`: at once by default, before any await; once the
 * page has focus with `secondPrompt` (D-96). User verification is required and checked: without it, an `hmac-secret`
 * authenticator returns another PRF result.
 */
async function assertUnlock(
  credentialId: Bytes,
  ask: (start: StartPrompt) => Promise<Credential | null> = (start) => prompt(start()),
): Promise<{ credentialId: Bytes; result: BufferSource | undefined }> {
  const publicKey: PublicKeyCredentialRequestOptions = {
    challenge: crypto.getRandomValues(new Uint8Array(UNLOCK_CHALLENGE_LENGTH)),
    allowCredentials: [{ type: 'public-key', id: credentialId }],
    userVerification: 'required',
    extensions: { prf: { eval: { first: PRF_INPUT } } },
  };
  const credential = await ask(() => navigator.credentials.get({ publicKey }));
  if (!(credential instanceof PublicKeyCredential) || !(credential.response instanceof AuthenticatorAssertionResponse))
    throw new VaultError('unavailable', 'The browser returned no passkey assertion');
  if (!isUserVerified(new Uint8Array(credential.response.authenticatorData)))
    throw noUserVerification('The presented passkey');
  const result = credential.getClientExtensionResults().prf?.results?.first;
  return { credentialId: new Uint8Array(credential.rawId), result };
}

/**
 * The protection of a header whose wrapping key pair is `wrappingPublicKey` and the extractable `privateKey`, and
 * that private key again, unwrapped from it as a non-extractable key (D-81).
 */
export async function protectWrappingKey(
  unlock: UnlockSecret,
  v: number,
  wrappingPublicKey: Bytes,
  privateKey: CryptoKey,
): Promise<{ protection: UnlockProtection; privateKey: CryptoKey }> {
  const { credentialId } = unlock;
  const salt = crypto.getRandomValues(new Uint8Array(SALT_LENGTH));
  const iv = crypto.getRandomValues(new Uint8Array(IV_LENGTH));
  const kek = await deriveKek(unlock.secret, salt);
  const params: AesGcmParams = {
    name: 'AES-GCM',
    iv,
    additionalData: protectionAad(v, wrappingPublicKey, credentialId, salt),
  };
  const wrapped = await crypto.subtle.wrapKey('pkcs8', privateKey, kek, params);
  const wrappedPrivateKey = new Uint8Array(wrapped);
  const unwrapped = await unwrapPrivateKey(kek, params, wrappedPrivateKey);
  return { protection: { kind: UNLOCK_KIND, credentialId, salt, iv, wrappedPrivateKey }, privateKey: unwrapped };
}

/**
 * The wrapping private key of a protected header, unwrapped with the unlock passkey's PRF result as a non-extractable
 * key; `corrupted` if it doesn't open: the AAD binds every other field of the header (D-69, D-81).
 */
export async function unwrapWrappingKey(
  secret: CryptoKey,
  header: { readonly v: number; readonly wrappingPublicKey: Bytes; readonly protection: UnlockProtection },
): Promise<CryptoKey> {
  const { v, wrappingPublicKey, protection } = header;
  const { credentialId, salt, iv, wrappedPrivateKey } = protection;
  const kek = await deriveKek(secret, salt);
  const params: AesGcmParams = {
    name: 'AES-GCM',
    iv,
    additionalData: protectionAad(v, wrappingPublicKey, credentialId, salt),
  };
  try {
    return await unwrapPrivateKey(kek, params, wrappedPrivateKey); // await: so catch sees it
  } catch (cause) {
    throw corrupted('header.protection does not decrypt', cause);
  }
}

function unwrapPrivateKey(kek: CryptoKey, params: AesGcmParams, wrappedPrivateKey: Bytes): Promise<CryptoKey> {
  return crypto.subtle.unwrapKey('pkcs8', wrappedPrivateKey, kek, params, P256, false, ['deriveKey']);
}

/** AES-GCM associated data of the wrapped private key: every other field of the header (D-81). */
export function protectionAad(v: number, wrappingPublicKey: Bytes, credentialId: Bytes, salt: Bytes): Bytes {
  return encode(DOMAIN_HEADER_AAD, v, wrappingPublicKey, UNLOCK_KIND, credentialId, salt);
}

/** D-78: a mark no scope mark equals, then fresh random bytes, so no new passkey overwrites another. */
function unlockUserId(): Bytes {
  const id = new Uint8Array(USER_MARK_LENGTH + USER_ID_RANDOM_LENGTH);
  id.set(sha256(PRF_INPUT).subarray(0, USER_MARK_LENGTH));
  id.set(crypto.getRandomValues(new Uint8Array(USER_ID_RANDOM_LENGTH)), USER_MARK_LENGTH);
  return id;
}

/** Imports the PRF result as a non-extractable HKDF key, then zeroes its bytes. */
async function importSecret(result: BufferSource): Promise<CryptoKey> {
  const bytes = ArrayBuffer.isView(result)
    ? new Uint8Array(result.buffer, result.byteOffset, result.byteLength)
    : new Uint8Array(result);
  try {
    return await crypto.subtle.importKey('raw', bytes, 'HKDF', false, ['deriveKey']);
  } finally {
    bytes.fill(0);
  }
}

function deriveKek(secret: CryptoKey, salt: Bytes): Promise<CryptoKey> {
  return crypto.subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt, info: PRF_INPUT },
    secret,
    { name: 'AES-GCM', length: 256 },
    false,
    ['wrapKey', 'unwrapKey'],
  );
}
