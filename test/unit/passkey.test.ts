import { p256 } from '@noble/curves/nist.js';
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';
import type { KeyInfo, Signature } from '../../src/index.ts';
import { addVirtualAuthenticator, hasVirtualAuthenticator, type VirtualAuthenticator } from './authenticator.ts';
import {
  cleanup,
  expectVaultError,
  openContexts,
  openVault,
  readHeader,
  readKey,
  replaceKey,
  TEST_SCOPE,
  tickingClock,
} from './helpers.ts';

const utf8 = new TextEncoder();
const message = utf8.encode('message to sign');
const sha256 = async (bytes: Uint8Array<ArrayBuffer>) => new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
const base64url = (bytes: Uint8Array) => bytes.toBase64({ alphabet: 'base64url', omitPadding: true });
const UV = 0x04;

/** Vault's length-prefixed encoding, written out by hand (format v1: tag, 4-byte big-endian length, data). */
function lengthPrefixed(...parts: (string | Uint8Array)[]): Uint8Array<ArrayBuffer> {
  const fields = parts.map((part) => {
    const [tag, data] = typeof part === 'string' ? [1, utf8.encode(part)] : [2, part];
    const field = new Uint8Array(5 + data.length);
    field[0] = tag;
    new DataView(field.buffer).setUint32(1, data.length);
    field.set(data, 5);
    return field;
  });
  return concat(...fields);
}

function concat(...arrays: Uint8Array[]): Uint8Array<ArrayBuffer> {
  const out = new Uint8Array(arrays.reduce((n, a) => n + a.length, 0));
  arrays.reduce((offset, a) => (out.set(a, offset), offset + a.length), 0);
  return out;
}

/** D-05: the id of a passkey key hashes its credential id. */
async function expectedKeyId(scope: string, credentialId: Uint8Array): Promise<string> {
  return base64url(await sha256(lengthPrefixed('vault/v1/key-id', scope, 'passkey', credentialId)));
}

/** D-54: the first 16 bytes of every passkey key's user handle in `scope`. */
async function scopeMark(scope: string): Promise<Uint8Array> {
  return (await sha256(lengthPrefixed('vault/v1/passkey-scope', scope))).slice(0, 16);
}

/**
 * Checks an assertion as a WebAuthn verifier does, without Vault: client data of type webauthn.get over
 * SHA-256(data), the UV flag, and the signature over authenticatorData ‖ SHA-256(clientDataJSON), in WebCrypto.
 */
async function verifyAssertion(
  publicKey: Uint8Array<ArrayBuffer>,
  { authenticatorData, clientDataJSON, signature }: Signature<'passkey'>,
  data: Uint8Array<ArrayBuffer>,
): Promise<boolean> {
  const clientData = JSON.parse(new TextDecoder().decode(clientDataJSON));
  if (clientData.type !== 'webauthn.get' || clientData.challenge !== base64url(await sha256(data))) return false;
  if (((authenticatorData[32] ?? 0) & UV) === 0) return false;
  const key = await crypto.subtle.importKey('spki', publicKey, { name: 'ECDSA', namedCurve: 'P-256' }, false, [
    'verify',
  ]);
  const raw = p256.Signature.fromBytes(signature, 'der').toBytes('compact'); // WebCrypto takes r ‖ s, not DER
  const signed = concat(authenticatorData, await sha256(clientDataJSON));
  return crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, key, raw, signed);
}

/** Holds the next passkey prompt once it is answered, until `release`; `reached` resolves once it is held. */
function holdPrompt(method: 'create' | 'get'): { reached: Promise<void>; release: () => void } {
  const original = navigator.credentials[method].bind(navigator.credentials);
  const reached = Promise.withResolvers<void>();
  const gate = Promise.withResolvers<void>();
  vi.spyOn(navigator.credentials, method).mockImplementationOnce(
    async (options?: CredentialCreationOptions & CredentialRequestOptions) => {
      const credential = await original(options);
      reached.resolve();
      await gate.promise;
      return credential;
    },
  );
  return { reached: reached.promise, release: gate.resolve };
}

/** Lets each answered `get()` be changed before Vault sees it: the injected faults of the check tests. */
function changeAssertions(change: (credential: PublicKeyCredential) => Promise<void>) {
  const original = navigator.credentials.get.bind(navigator.credentials);
  return vi.spyOn(navigator.credentials, 'get').mockImplementation(async (options) => {
    const credential = await original(options);
    if (!(credential instanceof PublicKeyCredential)) throw new Error('get() returned no PublicKeyCredential');
    await change(credential);
    return credential;
  });
}

/** Gives the next `method` prompt a short timeout: with presence off, it then ends as a declined prompt does. */
function shortTimeout(method: 'create' | 'get') {
  const original = navigator.credentials[method].bind(navigator.credentials);
  return vi
    .spyOn(navigator.credentials, method)
    .mockImplementationOnce(async (options?: CredentialCreationOptions & CredentialRequestOptions) =>
      original({ ...options, publicKey: { ...options?.publicKey, timeout: 100 } } as never),
    );
}

/** Replaces a field of a browser object with an own value; its getter stays on the prototype. */
const replaceField = (object: object, field: string, value: unknown) =>
  Object.defineProperty(object, field, { value, configurable: true });

let authenticator: VirtualAuthenticator;

// Chromium only: the CDP virtual authenticator exists nowhere else (D-62); e2e in Firefox and WebKit comes with #69.
describe.runIf(hasVirtualAuthenticator)('passkey keys', () => {
  beforeEach(async () => {
    authenticator = await addVirtualAuthenticator();
  });

  afterEach(async () => {
    vi.restoreAllMocks();
    await authenticator.remove();
    await cleanup();
  });

  describe('generate', () => {
    test('generate starts the passkey prompt before its first await, with the creation options Vault fixes', async () => {
      const { scope } = await openVault();
      const create = vi.spyOn(navigator.credentials, 'create');

      const pending = scope.generate('passkey', { label: 'Payments' });
      expect(create).toHaveBeenCalledTimes(1);
      await pending;

      const options = create.mock.calls[0]?.[0]?.publicKey;
      expect(options).toMatchObject({
        rp: { id: location.hostname },
        user: { name: 'Payments', displayName: 'Payments' },
        pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
        authenticatorSelection: { residentKey: 'required', userVerification: 'required' },
        attestation: 'none',
      });
      expect(options?.authenticatorSelection).not.toHaveProperty('authenticatorAttachment');
      expect(options).not.toHaveProperty('hints');
      expect(options).not.toHaveProperty('timeout');
    });

    test('a key without a label shows as Vault key in the passkey picker', async () => {
      const { scope } = await openVault();
      const create = vi.spyOn(navigator.credentials, 'create');
      await scope.generate('passkey');
      expect(create.mock.calls[0]?.[0]?.publicKey?.user).toMatchObject({ name: 'Vault key', displayName: 'Vault key' });
    });

    test('generate returns the public information of the new passkey key, its id derived from its credential id', async () => {
      const { scope } = await openVault();
      const before = Date.now();
      const key = await scope.generate('passkey', { label: 'Payments' });

      const [credential] = await authenticator.credentials();
      if (!credential) throw new Error('no credential was created');
      expect(key).toEqual({
        id: await expectedKeyId(TEST_SCOPE, credential.credentialId),
        scope: TEST_SCOPE,
        type: 'passkey',
        publicKey: expect.any(Uint8Array),
        credentialId: credential.credentialId,
        createdAt: expect.any(Date),
        label: 'Payments',
      });
      expect(key.createdAt.getTime()).toBeGreaterThanOrEqual(before);
      // The public key is the credential's P-256 key in SPKI: WebCrypto imports it as is.
      await expect(
        crypto.subtle.importKey('spki', key.publicKey, { name: 'ECDSA', namedCurve: 'P-256' }, true, ['verify']),
      ).resolves.toBeInstanceOf(CryptoKey);
    });

    test('the user handle is the scope mark and 16 fresh random bytes, so a second key never overwrites the first', async () => {
      const { scope } = await openVault();
      const [first, second] = [await scope.generate('passkey'), await scope.generate('passkey')];

      const credentials = await authenticator.credentials();
      expect(credentials.map((c) => c.credentialId)).toEqual(
        expect.arrayContaining([first.credentialId, second.credentialId]),
      );
      const mark = await scopeMark(TEST_SCOPE);
      for (const { userHandle, rpId } of credentials) {
        expect(userHandle.length).toBe(32);
        expect(userHandle.slice(0, 16)).toEqual(mark);
        expect(rpId).toBe(location.hostname);
      }
      expect(credentials[0]?.userHandle.slice(16)).not.toEqual(credentials[1]?.userHandle.slice(16));
      expect((await scope.list()).map((k) => k.id).sort()).toEqual([first.id, second.id].sort());
      for (const key of [first, second]) {
        expect(await verifyAssertion(key.publicKey, await scope.sign(key, message), message)).toBe(true);
      }
    });

    test('the stored record holds the public information and no sealed part', async () => {
      const { scope, name } = await openVault();
      const key = await scope.generate('passkey', { label: 'Payments' });
      const record = await readKey(name, scope.name, key.id);
      expect(record).toEqual({
        v: 1,
        scope: key.scope,
        id: key.id,
        type: 'passkey',
        publicKey: key.publicKey,
        credentialId: key.credentialId,
        createdAt: key.createdAt.getTime(),
        label: 'Payments',
      });
    });

    test('a passkey key can be the first key: its generate creates the vault', async () => {
      const { scope, name } = await openVault();
      const key = await scope.generate('passkey');
      expect(await readHeader(name)).toMatchObject({ v: 1 });
      expect(await scope.list()).toEqual([key]);
      await expect(scope.generate('ed25519')).resolves.toMatchObject({ type: 'ed25519' });
    });

    // D-61: the record has no sealed part, so it goes into the vault as it is, and the prompt is never repeated.
    test('a generate whose prompt is answered while another context wipes lands in the wiped vault, with one prompt', async () => {
      const [a, b] = await openContexts();
      const old = await a.scope.generate('ed25519');
      const held = holdPrompt('create');
      const create = vi.mocked(navigator.credentials.create);

      const pending = a.scope.generate('passkey');
      await held.reached;
      await b.vault.wipe();
      held.release();
      const key = await pending;

      expect(create).toHaveBeenCalledTimes(1);
      expect(await a.scope.list()).toEqual([key]);
      expect(await b.scope.list()).toEqual([key]);
      await expectVaultError(a.scope.sign(old, message), 'not-found');
    });
  });

  describe('list', () => {
    test('list returns passkey keys with sealed keys, oldest first, without a prompt', async () => {
      tickingClock();
      const { scope } = await openVault();
      const keys = [
        await scope.generate('ed25519'),
        await scope.generate('passkey'),
        await scope.generate('secp256k1'),
        await scope.generate('passkey'),
      ];
      const [create, get] = [vi.spyOn(navigator.credentials, 'create'), vi.spyOn(navigator.credentials, 'get')];

      expect(await scope.list()).toEqual(keys);
      expect(create).not.toHaveBeenCalled();
      expect(get).not.toHaveBeenCalled();
    });
  });

  describe('sign', () => {
    test('sign starts one prompt before its first await, for that key only, over SHA-256 of the data', async () => {
      const { scope } = await openVault();
      const [key] = [await scope.generate('passkey'), await scope.generate('passkey')];
      const get = vi.spyOn(navigator.credentials, 'get');

      const pending = scope.sign(key, message);
      expect(get).toHaveBeenCalledTimes(1);
      await pending;

      const options = get.mock.calls[0]?.[0]?.publicKey;
      expect(options).toMatchObject({
        challenge: await sha256(message),
        allowCredentials: [{ type: 'public-key', id: key.credentialId }],
        userVerification: 'required',
      });
    });

    test('a passkey signature is a WebAuthn assertion that a verifier checks with the public key alone', async () => {
      const { scope } = await openVault();
      const key = await scope.generate('passkey');
      const signature = await scope.sign(structuredClone(key), message);

      expect(Object.keys(signature).sort()).toEqual(['authenticatorData', 'clientDataJSON', 'signature', 'type']);
      expect(signature.type).toBe('passkey');
      expect(await verifyAssertion(key.publicKey, signature, message)).toBe(true);
      expect(await verifyAssertion(key.publicKey, signature, utf8.encode('other data'))).toBe(false);
    });

    test('a high-S signature from the authenticator is accepted and returned as it is', async () => {
      const { scope } = await openVault();
      const key = await scope.generate('passkey');
      changeAssertions(async (credential) => {
        const response = credential.response as AuthenticatorAssertionResponse;
        const { r, s } = p256.Signature.fromBytes(new Uint8Array(response.signature), 'der');
        const highS = s > p256.Point.CURVE().n / 2n ? s : p256.Point.CURVE().n - s;
        replaceField(response, 'signature', new p256.Signature(r, highS).toBytes('der').buffer);
      });

      const signature = await scope.sign(key, message);
      const { s } = p256.Signature.fromBytes(signature.signature, 'der');
      expect(s > p256.Point.CURVE().n / 2n).toBe(true);
      expect(await verifyAssertion(key.publicKey, signature, message)).toBe(true);
    });

    test('a signature that does not verify under the stored public key is corrupted', async () => {
      const { scope } = await openVault();
      const key = await scope.generate('passkey');
      await authenticator.overrideResponses({ isBogusSignature: true });
      await expectVaultError(scope.sign(key, message), 'corrupted');
    });

    describe('Vault checks each assertion before returning it', () => {
      // The test's own P-256 key replaces the stored public key, so it can sign assertions that differ in one
      // checked part only. The id binds the credential id, not the public key: list() still accepts the record.
      async function forgedSetup() {
        const { scope, name } = await openVault();
        const key = await scope.generate('passkey');
        const other = await scope.generate('passkey');
        const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']);
        const publicKey = new Uint8Array(await crypto.subtle.exportKey('spki', pair.publicKey));
        await replaceKey(name, scope.name, key.id, { ...(await readKey(name, scope.name, key.id)), publicKey });

        /** Answers every get() with an assertion the test signs, changed by `edit` first. */
        const forge = (edit: { flags?: number; type?: string; data?: Uint8Array<ArrayBuffer>; rawId?: Uint8Array }) =>
          changeAssertions(async (credential) => {
            const response = credential.response as AuthenticatorAssertionResponse;
            const authenticatorData = new Uint8Array(response.authenticatorData);
            authenticatorData[32] = edit.flags ?? authenticatorData[32] ?? 0;
            const clientData = JSON.parse(new TextDecoder().decode(response.clientDataJSON));
            if (edit.type) clientData.type = edit.type;
            if (edit.data) clientData.challenge = base64url(await sha256(edit.data));
            const clientDataJSON = utf8.encode(JSON.stringify(clientData));
            const signed = concat(authenticatorData, await sha256(clientDataJSON));
            const raw = new Uint8Array(
              await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, pair.privateKey, signed),
            );
            replaceField(response, 'authenticatorData', authenticatorData.buffer);
            replaceField(response, 'clientDataJSON', clientDataJSON.buffer);
            replaceField(response, 'signature', p256.Signature.fromBytes(raw, 'compact').toBytes('der').buffer);
            if (edit.rawId) replaceField(credential, 'rawId', edit.rawId.slice().buffer);
          });
        return { scope, key, other, publicKey, forge };
      }

      test('a forged assertion with every checked part right is accepted: the forgery itself is sound', async () => {
        const { scope, key, publicKey, forge } = await forgedSetup();
        forge({});
        expect(await verifyAssertion(publicKey, await scope.sign(key, message), message)).toBe(true);
      });

      test('an assertion without user verification is unsupported', async () => {
        const { scope, key, forge } = await forgedSetup();
        forge({ flags: 0x01 }); // UP only
        const error = await expectVaultError(scope.sign(key, message), 'unsupported');
        expect(error.message).toMatch(/no user verification/);
      });

      test('an assertion over another challenge, a replayed one, is rejected', async () => {
        const { scope, key, forge } = await forgedSetup();
        forge({ data: utf8.encode('other data') });
        const error = await expectVaultError(scope.sign(key, message), 'corrupted');
        expect(error.message).toMatch(/client data/);
      });

      test('an assertion whose client data is not of type webauthn.get is rejected', async () => {
        const { scope, key, forge } = await forgedSetup();
        forge({ type: 'webauthn.create' });
        const error = await expectVaultError(scope.sign(key, message), 'corrupted');
        expect(error.message).toMatch(/client data/);
      });

      test('an assertion for another credential is rejected', async () => {
        const { scope, key, other, forge } = await forgedSetup();
        forge({ rawId: other.credentialId });
        const error = await expectVaultError(scope.sign(key, message), 'corrupted');
        expect(error.message).toMatch(/another credential/);
      });
    });

    test('sign with a key no longer stored is not-found, after its prompt', async () => {
      const { scope } = await openVault();
      const key = await scope.generate('passkey');
      await scope.delete(key);
      const get = vi.spyOn(navigator.credentials, 'get');

      await expectVaultError(scope.sign(key, message), 'not-found');
      expect(get).toHaveBeenCalledTimes(1);
    });

    test('a key of another scope or another type is a TypeError, without a prompt', async () => {
      const { vault, scope } = await openVault();
      const key = await scope.generate('passkey');
      const get = vi.spyOn(navigator.credentials, 'get');

      await expect(vault.scope('other').sign(key, message)).rejects.toThrow(TypeError);
      await expect(scope.sign({ ...key, type: 'ed25519' } as KeyInfo, message)).rejects.toThrow(TypeError);
      await expect(scope.sign({ ...key, credentialId: 'x' } as never, message)).rejects.toThrow(
        new TypeError('key.credentialId must be a Uint8Array'),
      );
      expect(get).not.toHaveBeenCalled();
    });

    // D-60: sign prompts for the credential id of its argument, so it must be the stored key's, or one key would sign as another.
    test('a KeyInfo whose credential id is not the stored key’s is a TypeError, and returns no signature', async () => {
      const { scope } = await openVault();
      const [key, other] = [await scope.generate('passkey'), await scope.generate('passkey')];
      await expect(scope.sign({ ...key, credentialId: other.credentialId }, message)).rejects.toThrow(
        new TypeError(`Key ${key.id} has another credential id than the one given`),
      );
    });
  });

  // D-59: a declined, timed-out or unanswerable prompt is cancelled; it is the user's answer, so not retryable.
  describe('a failed prompt', () => {
    test('a generate whose prompt is declined is cancelled, with the browser error as cause, and writes nothing', async () => {
      const { scope, name } = await openVault();
      await authenticator.setPresence(false);
      shortTimeout('create');

      const error = await expectVaultError(scope.generate('passkey'), 'cancelled');
      expect(error.cause).toBeInstanceOf(DOMException);
      expect(error.cause).toMatchObject({ name: 'NotAllowedError' });
      expect(await readHeader(name)).toBeUndefined();
      expect(await scope.list()).toEqual([]);
    });

    test('a sign whose prompt is declined is cancelled, with the browser error as cause', async () => {
      const { scope } = await openVault();
      const key = await scope.generate('passkey');
      await authenticator.setPresence(false);
      shortTimeout('get');

      const error = await expectVaultError(scope.sign(key, message), 'cancelled');
      expect(error.cause).toMatchObject({ name: 'NotAllowedError' });
      expect(await scope.list()).toEqual([key]);
    });

    // The threat model's lost, deleted or replaced passkey: indistinguishable from a cancel (D-59).
    test('a sign with a passkey removed from its authenticator is cancelled', async () => {
      const { scope } = await openVault();
      const [key, kept] = [await scope.generate('passkey'), await scope.generate('passkey')];
      await authenticator.removeCredential(key.credentialId);
      shortTimeout('get');

      const error = await expectVaultError(scope.sign(key, message), 'cancelled');
      expect(error.cause).toMatchObject({ name: 'NotAllowedError' });
      expect(await verifyAssertion(kept.publicKey, await scope.sign(kept, message), message)).toBe(true);
    });
  });

  // D-59: TASK "Using a passkey key requires user verification (PIN or biometric), not just presence".
  describe('an authenticator without user verification', () => {
    test('a sign answered without user verification is unsupported, and returns no signature', async () => {
      const { scope } = await openVault();
      const key = await scope.generate('passkey');
      await authenticator.overrideResponses({ isBadUV: true });

      const error = await expectVaultError(scope.sign(key, message), 'unsupported');
      expect(error.message).toMatch(/no user verification/);
    });

    // No virtual authenticator raises these, so the browser's rejection is injected.
    describe.each(['NotSupportedError', 'ConstraintError'])('the browser error %s', (errorName) => {
      const rejectNext = (method: 'create' | 'get') => {
        const cause = new DOMException('injected', errorName);
        vi.spyOn(navigator.credentials, method).mockRejectedValueOnce(cause);
        return cause;
      };

      test('makes generate unsupported, with it as cause, and writes nothing', async () => {
        const { scope, name } = await openVault();
        const cause = rejectNext('create');
        const error = await expectVaultError(scope.generate('passkey'), 'unsupported');
        expect(error.cause).toBe(cause);
        expect(await readHeader(name)).toBeUndefined();
      });

      test('makes sign unsupported, with it as cause', async () => {
        const { scope } = await openVault();
        const key = await scope.generate('passkey');
        const cause = rejectNext('get');
        const error = await expectVaultError(scope.sign(key, message), 'unsupported');
        expect(error.cause).toBe(cause);
      });
    });

    test('any other browser error is unavailable, as before', async () => {
      const { scope } = await openVault();
      vi.spyOn(navigator.credentials, 'create').mockRejectedValueOnce(new DOMException('injected', 'UnknownError'));
      await expectVaultError(scope.generate('passkey'), 'unavailable');
    });
  });

  describe('delete', () => {
    test('delete removes the passkey key from the scope and leaves the passkey at its authenticator', async () => {
      const { scope } = await openVault();
      const [key, kept] = [await scope.generate('passkey'), await scope.generate('passkey')];

      await scope.delete(key);

      expect(await scope.list()).toEqual([kept]);
      expect((await authenticator.credentials()).map((c) => c.credentialId)).toEqual(
        expect.arrayContaining([key.credentialId, kept.credentialId]),
      );
    });
  });

  test('onChange listeners are called after a passkey generate and delete, in this context and the other', async () => {
    const [a, b] = await openContexts();
    const [inA, inB] = [vi.fn(), vi.fn()];
    a.vault.onChange(inA);
    b.vault.onChange(inB);

    const key = await a.scope.generate('passkey');
    await vi.waitFor(() => expect(inB).toHaveBeenCalledTimes(1));
    expect(inA).toHaveBeenCalledTimes(1);

    await a.scope.delete(key);
    await vi.waitFor(() => expect(inB).toHaveBeenCalledTimes(2));
    expect(inA).toHaveBeenCalledTimes(2);
  });
});
