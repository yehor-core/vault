import { p256 } from '@noble/curves/nist.js';
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';
import type { KeyInfo, Signature } from '../../src/index.ts';
import { publicKeyCandidates, sharedPublicKey } from '../../src/key-types/passkey.ts';
import { addVirtualAuthenticator, hasVirtualAuthenticator, type VirtualAuthenticator } from './authenticator.ts';
import {
  cleanup,
  expectVaultError,
  openContexts,
  openVault,
  readAll,
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

/** Makes the next `method` prompt fail with a DOMException of this name, which no virtual authenticator raises. */
function rejectNext(method: 'create' | 'get', errorName: string): DOMException {
  const cause = new DOMException('injected', errorName);
  vi.spyOn(navigator.credentials, method).mockRejectedValueOnce(cause);
  return cause;
}

/** Replaces a field of a browser object with an own value; its getter stays on the prototype. */
const replaceField = (object: object, field: string, value: unknown) =>
  Object.defineProperty(object, field, { value, configurable: true });

// D-56: known-answer vectors made with OpenSSL (Node's crypto), not noble: two P-256 keys, DER signatures over SHA-256.
// prettier-ignore
const RECOVERY = {
  keyA: Uint8Array.fromHex('3059301306072a8648ce3d020106082a8648ce3d03010703420004d893804a73974d09d1321c45304efac40f5d87eb92936fbed815f67450191b222bac9c0c16f8911e46fb2e492708701a90286794a36d9c118de7949388f63df9'),
  keyB: Uint8Array.fromHex('3059301306072a8648ce3d020106082a8648ce3d030107034200043f4147939a5eff347ec890594f63cc09898688db6126490416a6cf53b4beb14a5ec84226d3e146ce68795e4b659d9f4e35744ba640ff0cf02e654c56a283a9e3'),
  first: utf8.encode('first signed bytes'),
  second: utf8.encode('second signed bytes'),
  firstByA: Uint8Array.fromHex('30440220700e31aa62ab4505caa6f17e3da7d65c4bcc1abcaa3546400e57476f6174994402204950c1d06d4087472a073af440a0941230cf241dc88526047262a3f8dbdc41d6'),
  // firstByA with s replaced by n − s: as valid, and high-S.
  firstByAHighS: Uint8Array.fromHex('30450220700e31aa62ab4505caa6f17e3da7d65c4bcc1abcaa3546400e57476f61749944022100b6af3e2e92bf78b9d5f8c50bbf5f6bed8c17d68fde927880815726ca2086e37b'),
  secondByA: Uint8Array.fromHex('304502210085735fe03207594d9d2ba4a47f33f5547b03e71decfb466ec446c5edb59be85702206439d7091f0ebdf18c53fd2c8ed298e91121d1fe410005dd9eecd04f815b2b3e'),
  secondByB: Uint8Array.fromHex('3045022100a462541eebc42fcf74210436a54fbc82005f5f5f940da7e574f51b03686381e502202872b039cb13c3d449b3129bdaf5d0e0e2beb363ff1acdada93c685d91856ba8'),
};

// Pure computation: runs in every engine.
describe('public-key recovery', () => {
  const { keyA, keyB, first, second } = RECOVERY;

  test('one signature yields two candidate public keys, one of them the signer’s', () => {
    const candidates = publicKeyCandidates({ signed: first, signature: RECOVERY.firstByA });
    expect(candidates).toHaveLength(2);
    expect(candidates).toContainEqual(keyA);
  });

  test('two signatures by one key share exactly that key, high-S or not', () => {
    for (const signature of [RECOVERY.firstByA, RECOVERY.firstByAHighS]) {
      expect(sharedPublicKey({ signed: first, signature }, { signed: second, signature: RECOVERY.secondByA })).toEqual(
        keyA,
      );
    }
    expect(
      sharedPublicKey(
        { signed: second, signature: RECOVERY.secondByB },
        { signed: first, signature: RECOVERY.firstByA },
      ),
    ).toBeUndefined();
    expect(publicKeyCandidates({ signed: second, signature: RECOVERY.secondByB })).toContainEqual(keyB);
  });

  test('a malformed signature yields no candidate', () => {
    expect(publicKeyCandidates({ signed: first, signature: new Uint8Array(70) })).toEqual([]);
  });
});

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
    test('a generate whose prompt is declined or times out is cancelled, with the browser error as cause, and writes nothing', async () => {
      const { scope, name } = await openVault();
      await authenticator.setPresence(false);
      shortTimeout('create');

      const error = await expectVaultError(scope.generate('passkey'), 'cancelled');
      expect(error.cause).toBeInstanceOf(DOMException);
      expect(error.cause).toMatchObject({ name: 'NotAllowedError' });
      expect(await readHeader(name)).toBeUndefined();
      expect(await scope.list()).toEqual([]);
    });

    test('a sign whose prompt is declined or times out is cancelled, with the browser error as cause', async () => {
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

    test('a prompt that fails with any other browser error is unavailable, with it as cause', async () => {
      const { scope } = await openVault();
      const cause = rejectNext('create', 'UnknownError');
      const error = await expectVaultError(scope.generate('passkey'), 'unavailable');
      expect(error.cause).toBe(cause);
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
      test('makes generate unsupported, with it as cause, and writes nothing', async () => {
        const { scope, name } = await openVault();
        const cause = rejectNext('create', errorName);
        const error = await expectVaultError(scope.generate('passkey'), 'unsupported');
        expect(error.cause).toBe(cause);
        expect(await readHeader(name)).toBeUndefined();
      });

      test('makes sign unsupported, with it as cause', async () => {
        const { scope } = await openVault();
        const key = await scope.generate('passkey');
        const cause = rejectNext('get', errorName);
        const error = await expectVaultError(scope.sign(key, message), 'unsupported');
        expect(error.cause).toBe(cause);
      });
    });
  });

  // D-55, D-56, D-57: adding a key is how a vault that has never seen a passkey key learns it.
  describe('add', () => {
    /** A passkey key generated in another vault (another database: a fresh device, another profile), and a vault that never saw it. */
    async function elsewhere(label?: string) {
      const origin = await openVault();
      const key = await origin.scope.generate('passkey', label === undefined ? {} : { label });
      const fresh = await openVault();
      return { key, origin, fresh };
    }

    /** The calls of get() from now on, each answered as the authenticator answers. */
    const spyGet = () => vi.spyOn(navigator.credentials, 'get');

    test('add starts a discoverable prompt before its first await, over a fresh 32-byte challenge, user verification required', async () => {
      const { fresh } = await elsewhere();
      const get = spyGet();

      const pending = fresh.scope.add('passkey');
      expect(get).toHaveBeenCalledTimes(1);
      await pending;
      await fresh.scope.add('passkey'); // held now: one more prompt

      const [first, again] = [get.mock.calls[0]?.[0]?.publicKey, get.mock.calls[2]?.[0]?.publicKey];
      expect(first).toEqual({ challenge: expect.any(Uint8Array), userVerification: 'required' });
      expect(first?.challenge).toHaveProperty('length', 32);
      expect(again?.challenge).toHaveProperty('length', 32);
      expect(again?.challenge).not.toEqual(first?.challenge);
    });

    test('a passkey key added to a fresh vault is the key generate made: same id, public key and credential id, and it signs', async () => {
      const { key, origin, fresh } = await elsewhere('Payments');
      const get = spyGet();

      const added = await fresh.scope.add('passkey', { label: 'Payments' });

      expect(added).toEqual({ ...key, createdAt: expect.any(Date) });
      const stored = await readKey(origin.name, TEST_SCOPE, key.id);
      expect(await readKey(fresh.name, TEST_SCOPE, key.id)).toEqual({
        ...stored,
        createdAt: added.createdAt.getTime(),
      });
      expect(await fresh.scope.list()).toEqual([added]);
      // The second prompt is for that credential only, over another challenge.
      expect(get).toHaveBeenCalledTimes(2);
      const second = get.mock.calls[1]?.[0]?.publicKey;
      expect(second).toMatchObject({
        allowCredentials: [{ type: 'public-key', id: key.credentialId }],
        userVerification: 'required',
      });
      expect(second?.challenge).toHaveProperty('length', 32);
      expect(second?.challenge).not.toEqual(get.mock.calls[0]?.[0]?.publicKey?.challenge);
      expect(await verifyAssertion(key.publicKey, await fresh.scope.sign(added, message), message)).toBe(true);
    });

    test('a key added without a label has none, whatever generate was given', async () => {
      const { fresh } = await elsewhere('Payments');
      const added = await fresh.scope.add('passkey');
      expect(added).not.toHaveProperty('label');
    });

    test('a passkey created in another scope is not-found after the first prompt, and nothing is written', async () => {
      const { vault, scope, name } = await openVault();
      await vault.scope('other').generate('passkey');
      const get = spyGet();

      await expectVaultError(scope.add('passkey'), 'not-found');
      expect(get).toHaveBeenCalledTimes(1);
      expect(await scope.list()).toEqual([]);
      expect((await readAll(name)).keys).toHaveLength(1);
    });

    test('adding a key the scope holds returns the stored key after one prompt, writes nothing and ignores the label', async () => {
      const { vault, scope, name } = await openVault();
      const key = await scope.generate('passkey', { label: 'Payments' });
      const before = await readAll(name);
      const listener = vi.fn();
      vault.onChange(listener);
      const get = spyGet();

      expect(await scope.add('passkey', { label: 'Other' })).toEqual(key);
      expect(get).toHaveBeenCalledTimes(1);
      expect(await readAll(name)).toEqual(before);
      expect(listener).not.toHaveBeenCalled();
    });

    test('an add whose first or second prompt is declined is cancelled, and writes nothing', async () => {
      const { fresh } = await elsewhere();
      const original = navigator.credentials.get.bind(navigator.credentials); // before any spy wraps it
      await authenticator.setPresence(false);
      shortTimeout('get');
      const firstError = await expectVaultError(fresh.scope.add('passkey'), 'cancelled');
      expect(firstError.cause).toMatchObject({ name: 'NotAllowedError' });

      await authenticator.setPresence(true);
      vi.spyOn(navigator.credentials, 'get')
        .mockImplementationOnce(original)
        .mockRejectedValueOnce(new DOMException('declined', 'NotAllowedError'));
      await expectVaultError(fresh.scope.add('passkey'), 'cancelled');
      expect(await readHeader(fresh.name)).toBeUndefined();
    });

    test('an add whose second signature is by another key shares no public key, fails and writes nothing', async () => {
      const { fresh } = await elsewhere();
      const other = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']);
      let calls = 0;
      changeAssertions(async (credential) => {
        if (++calls !== 2) return;
        const response = credential.response as AuthenticatorAssertionResponse;
        const signed = concat(
          new Uint8Array(response.authenticatorData),
          await sha256(new Uint8Array(response.clientDataJSON)),
        );
        const raw = new Uint8Array(
          await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, other.privateKey, signed),
        );
        replaceField(response, 'signature', p256.Signature.fromBytes(raw, 'compact').toBytes('der').buffer);
      });
      const error = await expectVaultError(fresh.scope.add('passkey'), 'unavailable');
      expect(error.message).toMatch(/share no public key/);
      expect(await readHeader(fresh.name)).toBeUndefined();
    });

    test('an add whose signatures do not parse fails and writes nothing', async () => {
      const { fresh } = await elsewhere();
      await authenticator.overrideResponses({ isBogusSignature: true });
      await expectVaultError(fresh.scope.add('passkey'), 'unavailable');
      expect(await readHeader(fresh.name)).toBeUndefined();
    });

    test('an add answered without user verification is unsupported, and writes nothing', async () => {
      const { fresh } = await elsewhere();
      await authenticator.overrideResponses({ isBadUV: true });
      const error = await expectVaultError(fresh.scope.add('passkey'), 'unsupported');
      expect(error.message).toMatch(/no user verification/);
      expect(await readHeader(fresh.name)).toBeUndefined();
    });

    test('an add whose second assertion is over another challenge fails and writes nothing', async () => {
      const { fresh } = await elsewhere();
      let calls = 0;
      changeAssertions(async (credential) => {
        if (++calls !== 2) return;
        const response = credential.response as AuthenticatorAssertionResponse;
        const clientData = JSON.parse(new TextDecoder().decode(response.clientDataJSON));
        clientData.challenge = base64url(new Uint8Array(32));
        replaceField(response, 'clientDataJSON', utf8.encode(JSON.stringify(clientData)).buffer);
      });
      const error = await expectVaultError(fresh.scope.add('passkey'), 'unavailable');
      expect(error.message).toMatch(/client data/);
      expect(await readHeader(fresh.name)).toBeUndefined();
    });

    // D-61: the record has no sealed part, so it goes into the vault as it is, and no prompt is repeated.
    test('an add whose second prompt is answered while another context wipes lands in the wiped vault, with two prompts', async () => {
      const { key } = await elsewhere();
      const [a, b] = await openContexts();
      const old = await a.scope.generate('ed25519');
      const original = navigator.credentials.get.bind(navigator.credentials);
      const [reached, gate] = [Promise.withResolvers<void>(), Promise.withResolvers<void>()];
      const get = vi
        .spyOn(navigator.credentials, 'get')
        .mockImplementationOnce(original)
        .mockImplementationOnce(async (options) => {
          const credential = await original(options);
          reached.resolve();
          await gate.promise;
          return credential;
        });

      const pending = a.scope.add('passkey');
      await reached.promise;
      await b.vault.wipe();
      gate.resolve();
      const added = await pending;

      expect(added.id).toBe(key.id);
      expect(get).toHaveBeenCalledTimes(2);
      expect(await a.scope.list()).toEqual([added]);
      expect(await b.scope.list()).toEqual([added]);
      await expectVaultError(a.scope.sign(old, message), 'not-found');
    });

    test('onChange listeners are called after an add that wrote, in this context and the other', async () => {
      await elsewhere();
      const [a, b] = await openContexts();
      const [inA, inB] = [vi.fn(), vi.fn()];
      a.vault.onChange(inA);
      b.vault.onChange(inB);

      await a.scope.add('passkey');
      await vi.waitFor(() => expect(inB).toHaveBeenCalledTimes(1));
      expect(inA).toHaveBeenCalledTimes(1);
    });

    test('add of a key type that can’t add, of an unknown type or with a malformed label is a TypeError, without a prompt', async () => {
      const { scope } = await openVault();
      const get = spyGet();
      await expect(scope.add('ed25519' as never)).rejects.toThrow(
        new TypeError("A key of type ed25519 can't be added, only generated"),
      );
      await expect(scope.add('p256' as never)).rejects.toThrow(TypeError);
      await expect(scope.add('passkey', { label: '' })).rejects.toThrow(TypeError);
      await expect(scope.add('passkey', null as never)).rejects.toThrow(TypeError);
      expect(get).not.toHaveBeenCalled();
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
