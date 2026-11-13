import { p256 } from '@noble/curves/nist.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { base64url, encode, equalBytes, type Bytes } from '../bytes.ts';
import { VaultError } from '../errors.ts';
import type { KeyType, NewKeyRequest } from '../key-types.ts';
import { corrupted, readBytes } from '../readers.ts';

// Storage format v1: the scope mark's domain separator and length are part of every passkey's user handle.
const DOMAIN_SCOPE_MARK = 'vault/v1/passkey-scope';
const SCOPE_MARK_LENGTH = 16;
const USER_ID_RANDOM_LENGTH = 16;
/** Attestation is 'none', so nothing checks the creation challenge; it is random as the spec asks. */
const CREATE_CHALLENGE_LENGTH = 32;
/** The challenges of adding a key are random: nothing is signed but the proof of the key (D-55, D-56). */
const ADD_CHALLENGE_LENGTH = 32;
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
  readonly canAdd: true;
  info(part: PasskeyPart): PasskeyPart;
};

/**
 * A passkey: an ES256 credential whose private key stays in its authenticator (D-50, D-51). Vault stores its
 * credential id and its public key in SPKI; generate and sign each show one prompt, started before any await,
 * with user verification required. The record has no sealed part, so it is written into the vault as it is (D-61).
 */
export const passkey: PasskeyKeyType = {
  canAdd: true,
  prompts: true,
  fields: ['credentialId'],
  parse: (record) => ({ credentialId: readBytes(record.credentialId, 'key.credentialId') }),
  isPublicKey,
  identity: (record) => record.credentialId,
  info: ({ credentialId }) => ({ credentialId }),

  async generate(request) {
    const pending = navigator.credentials.create({ publicKey: keyCreationOptions(request) }); // the prompt, before any await
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
    const fault = checkAssertion(assertion, record.credentialId, challenge, `Key ${record.id}`);
    if (fault !== undefined) throw corrupted(`key ${record.id}: ${fault}`);
    if (!verifyAssertion(assertion, record.publicKey))
      throw corrupted(`key ${record.id} does not match its public key`);
    const { authenticatorData, clientDataJSON, signature } = assertion;
    return { authenticatorData, clientDataJSON, signature };
  },

  reseal: async () => undefined, // the private key is in its authenticator, sealed to nothing (D-61)

  // D-55, D-56: a discoverable prompt names the credential, a second one for it gives the public key.
  async add(scope) {
    const challenge = randomChallenge();
    const pending = navigator.credentials.get({ publicKey: { challenge, userVerification: 'required' } }); // before any await
    const presented = await prompt(pending);
    const first = readAssertion(presented);
    if (
      first.userHandle === undefined ||
      !equalBytes(first.userHandle.subarray(0, SCOPE_MARK_LENGTH), scopeMark(scope))
    )
      throw new VaultError('not-found', "The presented passkey's user handle has no mark of this scope"); // D-54
    failAdd(checkAssertion(first, first.credentialId, challenge, PRESENTED));
    const { credentialId } = first;
    return {
      identity: credentialId,
      async complete() {
        const again = randomChallenge();
        const allowCredentials = [{ type: 'public-key' as const, id: credentialId }];
        const pendingSecond = navigator.credentials.get({
          publicKey: { challenge: again, allowCredentials, userVerification: 'required' },
        });
        const answered = await prompt(pendingSecond);
        const second = readAssertion(answered);
        failAdd(checkAssertion(second, credentialId, again, PRESENTED));
        const publicKey = sharedPublicKey(signedBy(first), signedBy(second));
        // Recovered from both, so both verify under it; checked anyway, as every signature is before Vault uses it.
        if (publicKey === undefined || !verifyAssertion(first, publicKey) || !verifyAssertion(second, publicKey))
          throw addFailed('its two assertions share no public key');
        return { publicKey, identity: credentialId, part: async () => ({ credentialId }), erase: () => {} };
      },
    };
  },
};

const PRESENTED = 'The presented passkey';

/** An assertion that fails a check while adding a key: an answer of the authenticator, not stored data, is wrong. */
function failAdd(fault: string | undefined): void {
  if (fault !== undefined) throw addFailed(fault);
}

function addFailed(fault: string): VaultError {
  return new VaultError('unavailable', `Adding the presented passkey: ${fault}`);
}

function randomChallenge(): Bytes {
  return crypto.getRandomValues(new Uint8Array(ADD_CHALLENGE_LENGTH));
}

function keyCreationOptions({ scope, label }: NewKeyRequest): PublicKeyCredentialCreationOptions {
  return creationOptions(userId(scope), label ?? DEFAULT_USER_NAME); // D-52: the picker shows it; the label leaves Vault
}

/** The options of every passkey Vault creates (D-50, D-78): ES256 only, discoverable, user verification required. */
export function creationOptions(userId: Bytes, name: string): PublicKeyCredentialCreationOptions {
  return {
    rp: { id: location.hostname, name: RP_NAME },
    user: { id: userId, name, displayName: name },
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
  id.set(scopeMark(scope));
  id.set(crypto.getRandomValues(new Uint8Array(USER_ID_RANDOM_LENGTH)), SCOPE_MARK_LENGTH);
  return id;
}

function scopeMark(scope: string): Uint8Array {
  return sha256(encode(DOMAIN_SCOPE_MARK, scope)).subarray(0, SCOPE_MARK_LENGTH);
}

/** A WebAuthn call's result; any failure is a VaultError: a declined prompt `cancelled`, no user verification `unsupported` (D-59). */
export async function prompt(pending: Promise<Credential | null>): Promise<Credential | null> {
  try {
    return await pending; // await: so catch sees it
  } catch (cause) {
    const name = cause instanceof DOMException ? cause.name : undefined;
    if (name === 'NotAllowedError')
      throw new VaultError('cancelled', `The passkey prompt ended with ${name}`, { cause });
    if (name === 'NotSupportedError' || name === 'ConstraintError')
      throw new VaultError('unsupported', `The passkey prompt ended with ${name}`, { cause });
    throw new VaultError('unavailable', 'The passkey prompt failed', { cause });
  }
}

export function readCreated(credential: Credential | null): { credentialId: Bytes; publicKey: Bytes } {
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
  /** Absent when the authenticator returned none, as it may for a prompt restricted to one credential. */
  readonly userHandle: Bytes | undefined;
}

function readAssertion(credential: Credential | null): Assertion {
  if (!(credential instanceof PublicKeyCredential) || !(credential.response instanceof AuthenticatorAssertionResponse))
    throw new VaultError('unavailable', 'The browser returned no passkey assertion');
  const { response } = credential;
  return {
    credentialId: new Uint8Array(credential.rawId),
    userHandle: response.userHandle === null ? undefined : new Uint8Array(response.userHandle),
    authenticatorData: new Uint8Array(response.authenticatorData),
    clientDataJSON: new Uint8Array(response.clientDataJSON),
    signature: new Uint8Array(response.signature),
  };
}

/**
 * D-53: what is wrong with an assertion that should be for `credentialId`, over `challenge`, with the user verified;
 * undefined if nothing. No user verification is `unsupported` (D-59), thrown for `subject`. The signature is checked apart.
 */
function checkAssertion(
  assertion: Assertion,
  credentialId: Bytes,
  challenge: Bytes,
  subject: string,
): string | undefined {
  if (!equalBytes(assertion.credentialId, credentialId)) return 'the assertion is for another credential';
  const flags = assertion.authenticatorData[FLAGS_OFFSET];
  if (flags === undefined) return 'the assertion has no flags';
  if ((flags & FLAG_UV) === 0) throw noUserVerification(subject);
  const clientData = parseClientData(assertion.clientDataJSON);
  if (clientData?.type !== 'webauthn.get' || clientData.challenge !== base64url(challenge))
    return "the assertion's client data is not for this signature";
  return undefined;
}

/** D-59: an assertion answered without user verification, by the passkey `subject` names. */
export function noUserVerification(subject: string): VaultError {
  return new VaultError('unsupported', `${subject}: the authenticator answered with no user verification`);
}

/** Whether `authenticatorData` has its UV flag set; data too short to hold the flags has not. */
export function isUserVerified(authenticatorData: Bytes): boolean {
  const flags = authenticatorData[FLAGS_OFFSET];
  return flags !== undefined && (flags & FLAG_UV) !== 0;
}

/** What the authenticator signed: authenticatorData ‖ SHA-256(clientDataJSON), and the signature. */
function signedBy({ authenticatorData, clientDataJSON, signature }: Assertion): Signed {
  const clientDataHash = sha256(clientDataJSON);
  const signed = new Uint8Array(authenticatorData.length + clientDataHash.length);
  signed.set(authenticatorData);
  signed.set(clientDataHash, authenticatorData.length);
  return { signed, signature };
}

function verifyAssertion(assertion: Assertion, publicKey: Bytes): boolean {
  const { signed, signature } = signedBy(assertion);
  return verify(signature, signed, publicKey);
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

/** Bytes an authenticator signed with ES256, and its DER signature. */
export interface Signed {
  readonly signed: Bytes;
  readonly signature: Bytes;
}

/** The public keys, in SPKI, under which `signature` verifies over `signed`: two, but for a malformed signature (D-56). */
export function publicKeyCandidates({ signed, signature }: Signed): Bytes[] {
  const hash = sha256(signed);
  // Recovery ids 2 and 3 need r ≥ n, which a P-256 signature reaches with probability about 2^-128.
  return [0, 1].flatMap((recovery) => {
    try {
      const parsed = p256.Signature.fromBytes(signature, 'der').addRecoveryBit(recovery);
      return [spki(parsed.recoverPublicKey(hash).toBytes(false))];
    } catch {
      return []; // malformed DER, or no point for this recovery id
    }
  });
}

/** D-56: the one public key both signatures verify under, or undefined when they share none. */
export function sharedPublicKey(first: Signed, second: Signed): Bytes | undefined {
  const others = publicKeyCandidates(second);
  const shared = publicKeyCandidates(first).filter((candidate) => others.some((other) => equalBytes(candidate, other)));
  return shared.length === 1 ? shared[0] : undefined;
}

/** The SPKI of an uncompressed P-256 point. */
function spki(point: Uint8Array): Bytes {
  const bytes = new Uint8Array(P256_SPKI_PREFIX.length + point.length);
  bytes.set(P256_SPKI_PREFIX);
  bytes.set(point, P256_SPKI_PREFIX.length);
  return bytes;
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
