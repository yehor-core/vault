import { p256 } from '@noble/curves/nist.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { base64url, encode, equalBytes, type Bytes } from '../bytes.ts';
import { VaultError } from '../errors.ts';
import type { KeyType, NewKeyRequest, StoredKey } from '../key-types.ts';
import { corrupted, readBytes } from '../readers.ts';

// Storage format v1: the scope mark's domain separator and length are part of every passkey's user handle.
const DOMAIN_SCOPE_MARK = 'vault/v1/passkey-scope';
const SCOPE_MARK_LENGTH = 16;
const USER_ID_RANDOM_LENGTH = 16;
/** Attestation is 'none', so nothing checks the creation challenge; it is random as the spec asks. */
const CREATE_CHALLENGE_LENGTH = 32;
const ES256 = -7;
const RP_NAME = 'Vault';
const DEFAULT_USER_NAME = 'Vault key';
// SPKI of a P-256 public key with an uncompressed point (RFC 5480), as getPublicKey() returns ES256 keys: this
// fixed DER prefix (id-ecPublicKey, prime256v1, a 66-byte bit string), then the 65-byte point.
const P256_SPKI_PREFIX = Uint8Array.fromHex('3059301306072a8648ce3d020106082a8648ce3d030107034200');
// authenticatorData: rpIdHash (32 bytes), then the flags byte; UV is bit 2 (WebAuthn §6.1).
const FLAGS_OFFSET = 32;
const FLAG_UV = 0x04;
// Authenticators may return high-S signatures; the signed bytes are hashed with SHA-256 by ES256 itself.
const VERIFY_OPTIONS = { prehash: true, lowS: false, format: 'der' } as const;

/** The part of a key record a passkey key owns: the id of its credential at the passkey provider. */
export interface PasskeyPart {
  readonly credentialId: Bytes;
}

/** A WebAuthn assertion over SHA-256 of the data, as the authenticator returned it; `signature` is DER (D-53). */
export interface PasskeySignature {
  readonly authenticatorData: Bytes;
  readonly clientDataJSON: Bytes;
  readonly signature: Bytes;
}

type PasskeyKeyType = KeyType<PasskeyPart, PasskeySignature> & {
  readonly canAdd: false;
  info(part: PasskeyPart): PasskeyPart;
};

/**
 * A passkey: an ES256 credential whose private key stays in its authenticator (D-50, D-51). Vault stores its
 * credential id and its public key in SPKI; generate and sign each show one prompt, started before any await,
 * with user verification required. The record has no sealed part, so it is written into the vault as it is (D-61).
 */
export const passkey: PasskeyKeyType = {
  canAdd: false,
  prompts: true,
  fields: ['credentialId'],
  parse: (record) => ({ credentialId: readBytes(record.credentialId, 'key.credentialId') }),
  isPublicKey,
  identity: (record) => record.credentialId,
  info: ({ credentialId }) => ({ credentialId }),

  async generate(request) {
    const pending = navigator.credentials.create({ publicKey: creationOptions(request) }); // the prompt, before any await
    const { credentialId, publicKey } = readCreated(await prompt(pending));
    return { publicKey, identity: credentialId, part: async () => ({ credentialId }), erase: () => {} };
  },

  async sign(key, data, load) {
    // From the argument, read once: the prompt can't wait for storage (D-60).
    const credentialId = readCredentialIdArgument(key.credentialId);
    const challenge = sha256(data); // D-58
    const pending = navigator.credentials.get({
      publicKey: {
        challenge,
        allowCredentials: [{ type: 'public-key', id: credentialId }],
        userVerification: 'required',
      },
    });
    const assertion = readAssertion(await prompt(pending));
    const { record } = await load();
    if (!equalBytes(record.credentialId, credentialId)) {
      throw new TypeError(`Key ${record.id} has another credential id than the one given`);
    }
    checkAssertion(assertion, record, challenge);
    const { authenticatorData, clientDataJSON, signature } = assertion;
    return { authenticatorData, clientDataJSON, signature };
  },
};

function creationOptions({ scope, label }: NewKeyRequest): PublicKeyCredentialCreationOptions {
  const name = label ?? DEFAULT_USER_NAME; // D-52: the picker shows it; the label leaves Vault
  return {
    rp: { id: location.hostname, name: RP_NAME },
    user: { id: userId(scope), name, displayName: name },
    challenge: crypto.getRandomValues(new Uint8Array(CREATE_CHALLENGE_LENGTH)),
    pubKeyCredParams: [{ type: 'public-key', alg: ES256 }],
    // requireResidentKey: what Level 1 browsers read instead of residentKey; the spec asks for both.
    authenticatorSelection: { residentKey: 'required', requireResidentKey: true, userVerification: 'required' },
    attestation: 'none',
  };
}

/** D-54: the scope mark, then fresh random bytes, so no new passkey overwrites another at its authenticator. */
function userId(scope: string): Bytes {
  const id = new Uint8Array(SCOPE_MARK_LENGTH + USER_ID_RANDOM_LENGTH);
  id.set(sha256(encode(DOMAIN_SCOPE_MARK, scope)).subarray(0, SCOPE_MARK_LENGTH));
  id.set(crypto.getRandomValues(new Uint8Array(USER_ID_RANDOM_LENGTH)), SCOPE_MARK_LENGTH);
  return id;
}

/** A WebAuthn call's result; any failure is a VaultError: a declined prompt `cancelled`, no user verification `unsupported` (D-59). */
async function prompt(pending: Promise<Credential | null>): Promise<Credential | null> {
  try {
    return await pending; // await: so catch sees it
  } catch (cause) {
    const name = cause instanceof DOMException ? cause.name : undefined;
    if (name === 'NotAllowedError')
      throw new VaultError('cancelled', 'The passkey prompt was declined, timed out or found no passkey', { cause });
    if (name === 'NotSupportedError' || name === 'ConstraintError')
      throw new VaultError('unsupported', 'The authenticator cannot verify the user for this passkey', { cause });
    throw new VaultError('unavailable', 'The passkey prompt failed', { cause });
  }
}

function readCreated(credential: Credential | null): { credentialId: Bytes; publicKey: Bytes } {
  if (
    !(credential instanceof PublicKeyCredential) ||
    !(credential.response instanceof AuthenticatorAttestationResponse)
  )
    throw new VaultError('unavailable', 'The browser returned no passkey credential');
  const { response } = credential;
  const spki = response.getPublicKey();
  const publicKey = spki === null ? undefined : new Uint8Array(spki);
  if (response.getPublicKeyAlgorithm() !== ES256 || publicKey === undefined || !isPublicKey(publicKey))
    throw new VaultError('unavailable', 'The new passkey has no ES256 public key');
  return { credentialId: new Uint8Array(credential.rawId), publicKey };
}

interface Assertion extends PasskeySignature {
  readonly credentialId: Bytes;
}

function readAssertion(credential: Credential | null): Assertion {
  if (!(credential instanceof PublicKeyCredential) || !(credential.response instanceof AuthenticatorAssertionResponse))
    throw new VaultError('unavailable', 'The browser returned no passkey assertion');
  const { response } = credential;
  return {
    credentialId: new Uint8Array(credential.rawId),
    authenticatorData: new Uint8Array(response.authenticatorData),
    clientDataJSON: new Uint8Array(response.clientDataJSON),
    signature: new Uint8Array(response.signature),
  };
}

/** D-53: the assertion is for this key, with the user verified (else `unsupported`, D-59), over our challenge, and verifies under the stored key. */
function checkAssertion(assertion: Assertion, record: StoredKey<PasskeyPart>['record'], challenge: Bytes): void {
  const { credentialId, authenticatorData, clientDataJSON, signature } = assertion;
  if (!equalBytes(credentialId, record.credentialId))
    throw corrupted(`key ${record.id}: the assertion is for another credential`);
  const flags = authenticatorData[FLAGS_OFFSET];
  if (flags === undefined) throw corrupted(`key ${record.id}: the assertion has no flags`);
  if ((flags & FLAG_UV) === 0)
    throw new VaultError('unsupported', `Key ${record.id}: the authenticator answered with no user verification`);
  const clientData = parseClientData(clientDataJSON);
  if (clientData?.type !== 'webauthn.get' || clientData.challenge !== base64url(challenge))
    throw corrupted(`key ${record.id}: the assertion's client data is not for this signature`);
  const clientDataHash = sha256(clientDataJSON);
  const signed = new Uint8Array(authenticatorData.length + clientDataHash.length); // what the authenticator signed
  signed.set(authenticatorData);
  signed.set(clientDataHash, authenticatorData.length);
  if (!verify(signature, signed, record.publicKey)) throw corrupted(`key ${record.id} does not match its public key`);
}

function parseClientData(json: Bytes): { type?: unknown; challenge?: unknown } | undefined {
  try {
    const value: unknown = JSON.parse(new TextDecoder().decode(json));
    return typeof value === 'object' && value !== null ? value : undefined;
  } catch {
    return undefined;
  }
}

function verify(signature: Bytes, signed: Bytes, publicKey: Bytes): boolean {
  try {
    return p256.verify(signature, signed, publicKey.subarray(P256_SPKI_PREFIX.length), VERIFY_OPTIONS);
  } catch {
    return false; // malformed DER
  }
}

/** SPKI of a P-256 point on the curve (D-60): WebKit's raw import accepts off-curve points, so Vault checks. */
function isPublicKey(bytes: Bytes): boolean {
  if (!equalBytes(bytes.subarray(0, P256_SPKI_PREFIX.length), P256_SPKI_PREFIX)) return false;
  return p256.utils.isValidPublicKey(bytes.subarray(P256_SPKI_PREFIX.length), false);
}

function readCredentialIdArgument(value: unknown): Bytes {
  if (!(value instanceof Uint8Array)) throw new TypeError('key.credentialId must be a Uint8Array');
  return new Uint8Array(value); // the caller may change it while we await
}
