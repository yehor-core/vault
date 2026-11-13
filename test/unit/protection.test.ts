import { afterEach, beforeEach, describe, expect, expectTypeOf, test, vi } from 'vitest';
import { server } from 'vitest/browser';
import { Vault, type KeyInfo, type Scope } from '../../src/index.ts';
import {
  addVirtualAuthenticator,
  hasVirtualAuthenticator,
  pickPasskey,
  type VirtualAuthenticator,
} from './authenticator.ts';
import {
  asSealed,
  cleanup,
  expectVaultError,
  holdGenerate,
  keyTypeCases,
  openVault,
  readAll,
  readHeader,
  readKey,
  openContexts,
  rawRun,
  TEST_SCOPE,
  writeHeader,
  tickingClock,
  type SealedKeyTypeName,
} from './helpers.ts';

const utf8 = new TextEncoder();
const sha256 = async (bytes: Uint8Array<ArrayBuffer>) => new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));

const message = utf8.encode('message to sign');

/** Vault's length-prefixed encoding, written out by hand (format v1: tag, 4-byte big-endian length, data). */
function lengthPrefixed(...parts: (string | number | Uint8Array)[]): Uint8Array<ArrayBuffer> {
  const fields = parts.map((part) => {
    const [tag, data] =
      typeof part === 'string'
        ? [1, utf8.encode(part)]
        : typeof part === 'number'
          ? [3, new Uint8Array(new BigUint64Array([BigInt(part)]).buffer).reverse()]
          : [2, part];
    const field = new Uint8Array(5 + data.length);
    field[0] = tag;
    new DataView(field.buffer).setUint32(1, data.length);
    field.set(data, 5);
    return field;
  });
  const out = new Uint8Array(fields.reduce((n, f) => n + f.length, 0));
  fields.reduce((offset, f) => (out.set(f, offset), offset + f.length), 0);
  return out;
}

/** D-73, D-78: the fixed PRF input of every unlock passkey prompt. */
const UNLOCK_PRF_INPUT = lengthPrefixed('vault/v1/unlock');

/**
 * Records the PRF results the browser hands Vault: `copies` as they were returned, `returned` the buffers Vault
 * received. An observer: the results themselves are the authenticator's.
 */
function recordPrfResults(): { copies: Uint8Array[]; returned: ArrayBuffer[] } {
  const original = PublicKeyCredential.prototype.getClientExtensionResults;
  const copies: Uint8Array[] = [];
  const returned: ArrayBuffer[] = [];
  vi.spyOn(PublicKeyCredential.prototype, 'getClientExtensionResults').mockImplementation(function (
    this: PublicKeyCredential,
  ) {
    const outputs = original.call(this);
    const first = outputs.prf?.results?.first;
    if (first instanceof ArrayBuffer) {
      copies.push(new Uint8Array(first.slice(0)));
      returned.push(first);
    }
    return outputs;
  });
  return { copies, returned };
}

/** The wrapping private key of a protected header, unwrapped with code that is not Vault's (D-81). */
async function unwrapByHand(header: any, prfResult: Uint8Array<ArrayBuffer>): Promise<CryptoKey> {
  const { v, wrappingPublicKey, protection } = header;
  const base = await crypto.subtle.importKey('raw', prfResult, 'HKDF', false, ['deriveKey']);
  const kek = await crypto.subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt: protection.salt, info: UNLOCK_PRF_INPUT },
    base,
    { name: 'AES-GCM', length: 256 },
    false,
    ['unwrapKey'],
  );
  const additionalData = lengthPrefixed(
    'vault/v1/header',
    v,
    wrappingPublicKey,
    'passkey',
    protection.credentialId,
    protection.salt,
  );
  return crypto.subtle.unwrapKey(
    'pkcs8',
    protection.wrappedPrivateKey,
    kek,
    { name: 'AES-GCM', iv: protection.iv, additionalData },
    { name: 'ECDH', namedCurve: 'P-256' },
    true,
    ['deriveKey'],
  );
}

/** The public point of a P-256 key, as JWK x and y. */
async function point(key: CryptoKey): Promise<{ x: string | undefined; y: string | undefined }> {
  const { x, y } = await crypto.subtle.exportKey('jwk', key);
  return { x, y };
}

let authenticator: VirtualAuthenticator;

// Chromium only: the CDP virtual authenticator with PRF exists nowhere else (D-80).
describe.runIf(hasVirtualAuthenticator)('protect, with the PRF result at creation', () => {
  beforeEach(async () => {
    authenticator = await addVirtualAuthenticator({ hasPrf: true });
  });

  afterEach(async () => {
    vi.restoreAllMocks();
    await authenticator.remove();
    await cleanup();
  });

  test('protect starts the unlock passkey prompt before its first await, with the options Vault fixes', async () => {
    const { vault } = await openVault();
    const create = vi.spyOn(navigator.credentials, 'create');

    const pending = vault.protect();
    expect(create).toHaveBeenCalledTimes(1);
    await pending;

    const options = create.mock.calls[0]?.[0]?.publicKey;
    expect(options).toMatchObject({
      rp: { id: location.hostname },
      user: { name: 'Vault unlock', displayName: 'Vault unlock' },
      pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
      authenticatorSelection: { residentKey: 'required', userVerification: 'required' },
      attestation: 'none',
      extensions: { prf: { eval: { first: UNLOCK_PRF_INPUT } } },
    });
    expect(options?.pubKeyCredParams).toHaveLength(1);
    const userId = new Uint8Array(options?.user.id as ArrayBuffer);
    expect(userId).toHaveLength(32);
    expect(userId.slice(0, 16)).toEqual((await sha256(UNLOCK_PRF_INPUT)).slice(0, 16));
    expect(create).toHaveBeenCalledTimes(1); // one prompt: the result came at creation
    expect(await authenticator.credentials()).toHaveLength(1);

    // The last 16 bytes are fresh for each unlock passkey, so a second one never overwrites the first.
    const { vault: another } = await openVault();
    await another.protect();
    const second = new Uint8Array(create.mock.calls[1]?.[0]?.publicKey?.user.id as ArrayBuffer);
    expect(second.slice(0, 16)).toEqual(userId.slice(0, 16));
    expect(second.slice(16)).not.toEqual(userId.slice(16));
    expect(await authenticator.credentials()).toHaveLength(2);
  });

  test('the protected header wraps the wrapping private key under a KEK from the PRF result, bound to every other field', async () => {
    const { vault, name } = await openVault();
    const prf = recordPrfResults();

    await vault.protect();

    const header = await readHeader(name);
    const [credential] = await authenticator.credentials();
    expect(Object.keys(header).sort()).toEqual(['protection', 'v', 'wrappingPublicKey']);
    expect(Object.keys(header.protection).sort()).toEqual(['credentialId', 'iv', 'kind', 'salt', 'wrappedPrivateKey']);
    expect(header.protection).toMatchObject({ kind: 'passkey', credentialId: credential?.credentialId });
    expect(header.protection.salt).toHaveLength(32);
    expect(header.protection.iv).toHaveLength(12);

    const [prfResult] = prf.copies;
    if (!prfResult) throw new Error('no PRF result was returned');
    const privateKey = await unwrapByHand(header, new Uint8Array(prfResult));
    const publicKey = await crypto.subtle.importKey(
      'spki',
      header.wrappingPublicKey,
      { name: 'ECDH', namedCurve: 'P-256' },
      true,
      [],
    );
    expect(await point(privateKey)).toEqual(await point(publicKey));

    // Each other field is in the AAD: the hand-made unwrap fails when one changes.
    for (const edited of [
      { ...header, v: 2 },
      { ...header, protection: { ...header.protection, salt: new Uint8Array(32) } },
      { ...header, protection: { ...header.protection, credentialId: new Uint8Array(16) } },
    ]) {
      await expect(unwrapByHand(edited, new Uint8Array(prfResult))).rejects.toThrow();
    }
  });

  test('the PRF result’s bytes are zeroed once imported, at protect and at unlock', async () => {
    const [first, second] = await openContexts();
    const prf = recordPrfResults();

    await first.vault.protect();
    await second.vault.state(); // an application shows Unlock after reading the state (D-94)
    await second.vault.unlock();

    expect(prf.copies).toHaveLength(2);
    for (const [i, copy] of prf.copies.entries()) {
      expect(copy.some((byte) => byte !== 0)).toBe(true);
      expect(new Uint8Array(prf.returned[i] ?? new ArrayBuffer(1))).toEqual(new Uint8Array(32));
    }
    expect(prf.copies[1]).toEqual(prf.copies[0]); // the same passkey, the same PRF input: the same result
  });

  describe.each(keyTypeCases)('$type', ({ type, verify }) => {
    test('after protect every key signs and verifies as before, under a new wrapping public key; passkey records are unchanged', async () => {
      tickingClock();
      const { vault, scope, name } = await openVault();
      const other = vault.scope('other');
      const keys = [await scope.generate(type), await other.generate(type, { label: 'Payments' })];
      const passkeyKey = await scope.generate('passkey');
      const before = await readHeader(name);
      const passkeyRecord = await readKey(name, TEST_SCOPE, passkeyKey.id);

      await vault.protect();

      expect((await readHeader(name)).wrappingPublicKey).not.toEqual(before.wrappingPublicKey);
      expect(await readKey(name, TEST_SCOPE, passkeyKey.id)).toEqual(passkeyRecord);
      for (const [key, owner] of [
        [keys[0], scope],
        [keys[1], other],
      ] as const) {
        if (!key) throw new Error('missing key');
        const { bytes } = await owner.sign(asSealed(key), message);
        expect(await verify(key.publicKey, bytes, message)).toBe(true);
      }
      expect((await scope.list()).map((k) => k.id)).toEqual([keys[0]?.id, passkeyKey.id]);
      expect(await other.list()).toEqual([keys[1]]);
      await expect(scope.sign(passkeyKey, message)).resolves.toMatchObject({ type: 'passkey' });
    });
  });

  test('protect on an empty vault writes a protected header and no keys', async () => {
    const { vault, name } = await openVault();

    await vault.protect();

    const { meta, keys } = await readAll(name);
    expect(meta).toEqual([expect.objectContaining({ protection: expect.objectContaining({ kind: 'passkey' }) })]);
    expect(keys).toEqual([]);
  });

  test('protect on a protected vault fails with protected, not retryable, and changes nothing, unlocked or locked; the locked instance then unlocks with one prompt', async () => {
    const [first, second] = await openContexts();
    await first.scope.generate('ed25519');
    await first.vault.protect();
    const before = await readAll(first.name);

    await expectVaultError(first.vault.protect(), 'protected');
    await expectVaultError(second.vault.protect(), 'protected');

    expect(await readAll(first.name)).toEqual(before);
    const get = vi.spyOn(navigator.credentials, 'get');
    await second.vault.unlock(); // protect's read of the protected header named the unlock passkey (D-94)
    expect(get).toHaveBeenCalledTimes(1);
  });
});

/** Gives the next `create` prompt a short timeout: with presence off, it then ends as a declined prompt does. */
function shortCreateTimeout() {
  const original = navigator.credentials.create.bind(navigator.credentials);
  vi.spyOn(navigator.credentials, 'create').mockImplementationOnce(async (options?: CredentialCreationOptions) =>
    original({ ...options, publicKey: { ...options?.publicKey, timeout: 100 } } as never),
  );
}

// Chromium only, as above (D-80): no PRF and a declined prompt need the virtual authenticator.
describe.runIf(hasVirtualAuthenticator)('protect, failing', () => {
  afterEach(async () => {
    vi.restoreAllMocks();
    await authenticator.remove();
    await cleanup();
  });

  test('an authenticator without PRF makes protect fail with unsupported after one prompt, and the vault is unchanged', async () => {
    authenticator = await addVirtualAuthenticator();
    const [first, second] = await openContexts();
    await first.scope.generate('ed25519');
    const before = await readAll(first.name);
    const notified = [vi.fn(), vi.fn()];
    first.vault.onChange(notified[0] ?? vi.fn());
    second.vault.onChange(notified[1] ?? vi.fn());
    const get = vi.spyOn(navigator.credentials, 'get');

    await expectVaultError(first.vault.protect(), 'unsupported');

    expect(get).not.toHaveBeenCalled(); // PRF not enabled at creation: no second prompt (D-74)
    expect(await readAll(first.name)).toEqual(before);
    expect(await first.vault.state()).toBe('unprotected');
    await new Promise((resolve) => setTimeout(resolve, 50)); // a notification would have crossed by now
    expect(notified.map((listener) => listener.mock.calls.length)).toEqual([0, 0]);
  });

  test('a declined prompt makes protect fail with cancelled, and the vault is unchanged', async () => {
    authenticator = await addVirtualAuthenticator({ hasPrf: true });
    const { vault, scope, name } = await openVault();
    await scope.generate('secp256k1');
    const before = await readAll(name);
    await authenticator.setPresence(false);
    shortCreateTimeout();

    await expectVaultError(vault.protect(), 'cancelled');

    expect(await readAll(name)).toEqual(before);
  });
});

// Chromium only, as above (D-80): `hasHmacSecret` without `hasHmacSecretMc` returns PRF results at assertion only,
// as Firefox does with every authenticator and Chromium with such security keys (docs/research/webauthn-prf.md §2, §6).
describe.runIf(hasVirtualAuthenticator)('protect, with no PRF result at creation', () => {
  beforeEach(async () => {
    authenticator = await addVirtualAuthenticator({ hasHmacSecret: true });
  });

  afterEach(async () => {
    vi.restoreAllMocks();
    await authenticator.remove();
    await cleanup();
  });

  describe.each(keyTypeCases)('$type', ({ type, verify }) => {
    test('protect shows a second prompt for the new passkey only, user verification required, with the fixed PRF input; then every key signs', async () => {
      const { vault, scope, name } = await openVault();
      const key = asSealed(await scope.generate(type));
      const passkeyKey = await scope.generate('passkey');
      const create = vi.spyOn(navigator.credentials, 'create');
      const get = vi.spyOn(navigator.credentials, 'get');

      await vault.protect();

      expect(create).toHaveBeenCalledTimes(1);
      expect(get).toHaveBeenCalledTimes(1);
      const credentialId = await unlockPasskeyId(name);
      const options = get.mock.calls[0]?.[0]?.publicKey;
      expect(options).toMatchObject({
        allowCredentials: [{ type: 'public-key', id: credentialId }],
        userVerification: 'required',
        extensions: { prf: { eval: { first: UNLOCK_PRF_INPUT } } },
      });
      expect(options?.challenge).toHaveProperty('byteLength', 32);
      expect(await vault.state()).toBe('unlocked');
      const { bytes } = await scope.sign(key, message);
      expect(await verify(key.publicKey, bytes, message)).toBe(true);
      expect(get).toHaveBeenCalledTimes(1); // sealed sign: no prompt
      await expect(scope.sign(passkeyKey, message)).resolves.toMatchObject({ type: 'passkey' });
    });
  });

  test('the second prompt starts before any task runs once the creation is answered', async () => {
    const { vault, scope } = await openVault();
    await scope.generate('ed25519'); // a header and a key: work protect could start before the second prompt
    const get = vi.spyOn(navigator.credentials, 'get');
    const startedBeforeAnyTask = Promise.withResolvers<boolean>();
    afterCreation(() => {
      // No task runs while microtasks are queued: this chain, re-queued until get() is called, holds back every
      // answer that comes in a task (IndexedDB, timers), so awaiting one before the second prompt ends it with false.
      let hops = 0;
      const spin = () => {
        if (get.mock.calls.length > 0) startedBeforeAnyTask.resolve(true);
        else if (++hops < 1000) queueMicrotask(spin);
        else startedBeforeAnyTask.resolve(false);
      };
      queueMicrotask(spin);
    });

    await vault.protect();

    expect(await startedBeforeAnyTask.promise).toBe(true);
  });

  test('a vault protected after two prompts unlocks in another instance with one prompt', async () => {
    const [first, second] = await openContexts();
    const key = asSealed(await first.scope.generate('secp256k1')); // any sealed type: it shows the unlock works
    await first.vault.protect();
    await second.vault.state(); // an application shows Unlock after reading the state (D-94)
    const get = vi.spyOn(navigator.credentials, 'get');

    await second.vault.unlock();

    expect(get).toHaveBeenCalledTimes(1);
    expect(await second.vault.state()).toBe('unlocked');
    await expect(second.scope.sign(key, message)).resolves.toMatchObject({ type: 'secp256k1' });
  });

  test('where the browser returns a PRF result only to a prompt restricted to a passkey, protect and then unlock in a new instance succeed (Firefox with a security key)', async () => {
    const { vault, scope, name } = await openVault();
    const key = asSealed(await scope.generate('ed25519')); // any sealed type: it shows the unlock works
    const get = prfOnlyWhenRestricted();
    await vault.protect();
    const reopened = await Vault.open({ name });
    try {
      const calls = get.mock.calls.length;

      await reopened.unlock();

      expect(get.mock.calls.length - calls).toBe(1);
      expect(await reopened.state()).toBe('unlocked');
      await expect(reopened.scope(TEST_SCOPE).sign(key, message)).resolves.toMatchObject({ type: 'ed25519' });
    } finally {
      reopened.close();
    }
  });

  /** Each failure of the second prompt, set up on a vault whose `scope` the test then protects. */
  const secondPromptFailures = [
    {
      failure: 'a declined second prompt',
      code: 'cancelled',
      setUp: async () => {
        afterCreation(() => authenticator.setPresence(false)); // the creation is answered, the second prompt not
        shortGetTimeout();
      },
    },
    {
      failure: 'a second assertion without a PRF result',
      code: 'unsupported',
      setUp: async () => {
        vi.spyOn(PublicKeyCredential.prototype, 'getClientExtensionResults').mockReturnValue({
          prf: { enabled: true },
        });
      },
    },
    {
      failure: 'a second assertion without UV',
      code: 'unsupported',
      setUp: () => authenticator.overrideResponses({ isBadUV: true }),
    },
    {
      failure: 'a second assertion by another passkey',
      code: 'unavailable',
      setUp: async (scope: Scope) => pickPasskey((await scope.generate('passkey')).credentialId),
    },
  ] as const;

  test.each(secondPromptFailures)(
    'protect with $failure fails with $code after two prompts, and the vault is unchanged',
    async ({ code, setUp }) => {
      const [first, second] = await openContexts();
      const key = asSealed(await first.scope.generate('ed25519')); // any sealed type: it shows the vault unchanged
      const create = vi.spyOn(navigator.credentials, 'create');
      const get = vi.spyOn(navigator.credentials, 'get');
      await setUp(first.scope);
      const calls = [create.mock.calls.length, get.mock.calls.length];
      const before = await readAll(first.name);
      const notified = [vi.fn(), vi.fn()];
      first.vault.onChange(notified[0] ?? vi.fn());
      second.vault.onChange(notified[1] ?? vi.fn());

      await expectVaultError(first.vault.protect(), code);

      expect([create.mock.calls.length, get.mock.calls.length]).toEqual([(calls[0] ?? 0) + 1, (calls[1] ?? 0) + 1]);
      expect(await readAll(first.name)).toEqual(before);
      expect(await first.vault.state()).toBe('unprotected');
      await expect(first.scope.sign(key, message)).resolves.toMatchObject({ type: 'ed25519' });
      await settle();
      expect(notified.map((listener) => listener.mock.calls.length)).toEqual([0, 0]);
    },
  );
});

// Chromium only, as above (D-80): protect needs the virtual authenticator's PRF result.
describe.runIf(hasVirtualAuthenticator)('after protect', () => {
  beforeEach(async () => {
    authenticator = await addVirtualAuthenticator({ hasPrf: true });
  });

  afterEach(async () => {
    vi.restoreAllMocks();
    await authenticator.remove();
    await cleanup();
  });

  test('onChange listeners are called after a protect that committed, in this and another instance; not after one that failed', async () => {
    const [first, second] = await openContexts();
    const calls = [vi.fn(), vi.fn()] as const;
    first.vault.onChange(calls[0]);
    const crossed = new Promise<void>((resolve) => second.vault.onChange(() => (calls[1](), resolve())));

    await first.vault.protect();
    expect(calls[0]).toHaveBeenCalledTimes(1);
    await crossed;

    await expectVaultError(first.vault.protect(), 'protected');
    await new Promise((resolve) => setTimeout(resolve, 50)); // a notification would have crossed by now
    expect([calls[0].mock.calls.length, calls[1].mock.calls.length]).toEqual([1, 1]);
  });

  describe.each(keyTypeCases)('$type', ({ type, verify }) => {
    test('the protecting instance is unlocked and signs with sealed keys without a prompt', async () => {
      const { vault, scope } = await openVault();
      const key = asSealed(await scope.generate(type));
      await vault.protect();
      const get = vi.spyOn(navigator.credentials, 'get');

      expect(await vault.state()).toBe('unlocked');
      const { bytes } = await scope.sign(key, message);

      expect(await verify(key.publicKey, bytes, message)).toBe(true);
      expect(get).not.toHaveBeenCalled();
    });

    test('another instance is locked: sealed sign fails with locked; generate, list, add, passkey sign and wipe work', async () => {
      tickingClock();
      const [first, second] = await openContexts();
      const sealed = asSealed(await first.scope.generate(type));
      const passkeyKey = await first.scope.generate('passkey');
      await first.vault.protect();
      const [unlockPasskey] = (await authenticator.credentials()).filter(
        (c) => !c.credentialId.every((byte, i) => byte === passkeyKey.credentialId[i]),
      );
      if (!unlockPasskey) throw new Error('no unlock passkey');
      await authenticator.removeCredential(unlockPasskey.credentialId); // so add's picker offers only the passkey key
      const create = vi.spyOn(navigator.credentials, 'create');

      expect(await second.vault.state()).toBe('locked');
      await expectVaultError(second.scope.sign(sealed, message), 'locked');
      const generated = asSealed(await second.scope.generate(type));
      expect(create).not.toHaveBeenCalled();
      expect((await second.scope.list()).map((k) => k.id)).toEqual([sealed.id, passkeyKey.id, generated.id]);
      await expect(second.scope.add('passkey')).resolves.toEqual(passkeyKey);
      await expect(second.scope.sign(passkeyKey, message)).resolves.toMatchObject({ type: 'passkey' });

      // Sealed to the protected wrapping public key: the unlocked instance opens it.
      const { bytes } = await first.scope.sign(generated, message);
      expect(await verify(generated.publicKey, bytes, message)).toBe(true);

      await second.vault.wipe();
      expect(await second.vault.state()).toBe('empty');
    });
  });
});

/** The unlock passkey's credential id, as the protected header of database `name` names it. */
async function unlockPasskeyId(name: string): Promise<Uint8Array<ArrayBuffer>> {
  return (await readHeader(name)).protection.credentialId;
}

/** Holds the next `get` prompt, already started, until `release`: the vault can change while it is open. */
function holdPrompt(): () => void {
  const original = CredentialsContainer.prototype.get;
  const gate = Promise.withResolvers<void>();
  vi.spyOn(navigator.credentials, 'get').mockImplementationOnce(async (options?: CredentialRequestOptions) => {
    await gate.promise;
    return original.call(navigator.credentials, options);
  });
  return gate.resolve;
}

/**
 * From here on, an assertion of a discoverable prompt (no `allowCredentials`) carries no PRF result, as Firefox with a
 * security key without `hmac-secret-mc` answers (#108). An injected failure: the result itself is the authenticator's.
 */
function prfOnlyWhenRestricted() {
  const original = CredentialsContainer.prototype.get;
  return vi.spyOn(navigator.credentials, 'get').mockImplementation(async (options?: CredentialRequestOptions) => {
    const credential = await original.call(navigator.credentials, options);
    if (credential && !options?.publicKey?.allowCredentials?.length)
      Object.defineProperty(credential, 'getClientExtensionResults', { value: () => ({ prf: {} }) });
    return credential;
  });
}

/** Gives the next `get` prompt a short timeout: with presence off, it then ends as a declined prompt does. */
function shortGetTimeout() {
  const original = CredentialsContainer.prototype.get;
  vi.spyOn(navigator.credentials, 'get').mockImplementationOnce(async (options?: CredentialRequestOptions) =>
    original.call(navigator.credentials, { ...options, publicKey: { ...options?.publicKey, timeout: 100 } } as never),
  );
}

/** What sign of a key sealed to the replaced header fails with, under each replacement. */
const SIGN_ERROR_UNDER = { locked: 'locked', unprotected: 'corrupted', empty: 'not-found' } as const;

/** Runs `hook` once the next `create` prompt is answered, before Vault sees the answer. */
function afterCreation(hook: () => unknown) {
  const original = CredentialsContainer.prototype.create;
  vi.spyOn(navigator.credentials, 'create').mockImplementationOnce(async (options?: CredentialCreationOptions) => {
    const credential = await original.call(navigator.credentials, options);
    await hook();
    return credential;
  });
}

/** Wait long enough for a notification to cross to another instance. */
const settle = () => new Promise((resolve) => setTimeout(resolve, 50));

// Chromium only, as above (D-80): unlock needs the virtual authenticator's PRF result.
describe.runIf(hasVirtualAuthenticator)('unlock and lock', () => {
  beforeEach(async () => {
    authenticator = await addVirtualAuthenticator({ hasPrf: true });
  });

  afterEach(async () => {
    vi.restoreAllMocks();
    await authenticator.remove();
    await cleanup();
  });

  test('unlock starts a prompt for the stored unlock passkey only before its first await, user verification required, with the fixed PRF input', async () => {
    const { vault, name } = await openVault();
    await vault.protect();
    const second = await Vault.open({ name }); // opened after protect: its header read names the unlock passkey
    try {
      const get = vi.spyOn(navigator.credentials, 'get');

      const pending = second.unlock();
      expect(get).toHaveBeenCalledTimes(1);
      await pending;

      const options = get.mock.calls[0]?.[0]?.publicKey;
      expect(options).toMatchObject({
        allowCredentials: [{ type: 'public-key', id: await unlockPasskeyId(name) }],
        userVerification: 'required',
        extensions: { prf: { eval: { first: UNLOCK_PRF_INPUT } } },
      });
      expect(options?.allowCredentials?.[0]).not.toHaveProperty('transports');
      expect(options?.challenge).toHaveProperty('byteLength', 32);
      expect(await second.state()).toBe('unlocked');
    } finally {
      second.close();
    }
  });

  describe.each(keyTypeCases)('$type', ({ type, verify }) => {
    test('after one unlock prompt, sealed keys of every scope sign without a prompt; a passkey key still prompts for itself', async () => {
      const [first, second] = await openContexts();
      const keys = [
        asSealed(await first.scope.generate(type)),
        asSealed(await first.vault.scope('other').generate(type)),
      ];
      const passkeyKey = await first.scope.generate('passkey');
      await first.vault.protect();
      await second.vault.state(); // an application shows Unlock after reading the state (D-94)
      const get = vi.spyOn(navigator.credentials, 'get');
      pickPasskey(await unlockPasskeyId(first.name));

      await second.vault.unlock();

      expect(get).toHaveBeenCalledTimes(1);
      for (const [key, scope] of [
        [keys[0], second.scope],
        [keys[1], second.vault.scope('other')],
      ] as const) {
        if (!key) throw new Error('missing key');
        const { bytes } = await scope.sign(key, message);
        expect(await verify(key.publicKey, bytes, message)).toBe(true);
      }
      expect(get).toHaveBeenCalledTimes(1);
      await second.scope.sign(passkeyKey, message);
      expect(get).toHaveBeenCalledTimes(2);
      expect(get.mock.calls[1]?.[0]?.publicKey?.allowCredentials).toEqual([
        { type: 'public-key', id: passkeyKey.credentialId },
      ]);
    });

    test('lock() and close() lock this instance only: sealed sign fails with locked, after close() InvalidStateError; a new instance is locked', async () => {
      const [first, second] = await openContexts();
      const key = asSealed(await first.scope.generate(type));
      await first.vault.protect();
      await second.vault.state(); // an application shows Unlock after reading the state (D-94)
      await second.vault.unlock();

      first.vault.lock();

      expect(await first.vault.state()).toBe('locked');
      await expectVaultError(first.scope.sign(key, message), 'locked');
      expect(await second.vault.state()).toBe('unlocked');
      await expect(second.scope.sign(key, message)).resolves.toMatchObject({ type });

      second.vault.close();
      await expect(second.scope.sign(key, message)).rejects.toMatchObject({ name: 'InvalidStateError' });
      const reopened = await Vault.open({ name: first.name });
      try {
        expect(await reopened.state()).toBe('locked');
        await expectVaultError(reopened.scope(TEST_SCOPE).sign(key, message), 'locked');
      } finally {
        reopened.close();
      }
    });

    test.each([
      ['another protected header', 'locked'],
      ['an unprotected header', 'unprotected'],
      ['no header and no keys', 'empty'],
    ] as const)(
      'an unlocked instance whose stored header is replaced by %s drops its key and reports %s, at state() and at sign',
      async (_, expected) => {
        const { vault, scope, name } = await openVault();
        const key = asSealed(await scope.generate(type));
        await vault.protect();
        const stored = await readAll(name);
        const { vault: another, scope: anotherScope, name: anotherName } = await openVault();
        await anotherScope.generate(type);
        if (expected === 'locked') await another.protect();
        const replacement = await readHeader(anotherName);
        const replace = async () => {
          if (expected === 'empty') await rawRun(name, ['meta', 'keys'], (tx) => void clearStores(tx));
          else await writeHeader(name, replacement);
        };
        const restore = () =>
          rawRun(name, ['meta', 'keys'], (tx) => {
            tx.objectStore('meta').put(stored.meta[0], 'header');
            for (const record of stored.keys) tx.objectStore('keys').put(record);
          });

        await replace();
        expect(await vault.state()).toBe(expected);
        await restore();
        expect(await vault.state()).toBe('locked'); // dropped, not only hidden while the header differed

        pickPasskey(await unlockPasskeyId(name)); // the other vault's unlock passkey is at the authenticator too
        await vault.unlock();
        await replace();
        await expectVaultError(scope.sign(key, message), SIGN_ERROR_UNDER[expected]);
        await restore();
        await expectVaultError(scope.sign(key, message), 'locked');
      },
    );
  });

  test('unlock on an unlocked instance unlocks again; unlock and lock call no onChange listener', async () => {
    const [first, second] = await openContexts();
    await first.vault.protect();
    await settle(); // protect's own notification has crossed
    const calls = [vi.fn(), vi.fn()] as const;
    first.vault.onChange(calls[0]);
    second.vault.onChange(calls[1]);
    const get = vi.spyOn(navigator.credentials, 'get');

    await first.vault.unlock();
    expect(get).toHaveBeenCalledTimes(1);
    expect(await first.vault.state()).toBe('unlocked');
    first.vault.lock();
    await second.vault.state(); // an application shows Unlock after reading the state (D-94)
    await second.vault.unlock();
    second.vault.lock();

    await settle();
    expect([calls[0].mock.calls.length, calls[1].mock.calls.length]).toEqual([0, 0]);
  });

  test.each(['a passkey key of the vault', "another vault's unlock passkey"] as const)(
    'unlock answered by %s fails with not-found and changes nothing, locked or unlocked',
    async (picked) => {
      const [first, second] = await openContexts();
      await first.scope.generate('ed25519');
      const passkeyKey = await first.scope.generate('passkey');
      await first.vault.protect();
      const { vault: another, name: anotherName } = await openVault();
      await another.protect();
      const id = picked === 'a passkey key of the vault' ? passkeyKey.credentialId : await unlockPasskeyId(anotherName);
      const before = await readAll(first.name);
      await second.vault.state(); // an application shows Unlock after reading the state (D-94)

      pickPasskey(id);
      await expectVaultError(second.vault.unlock(), 'not-found');
      pickPasskey(id);
      await expectVaultError(first.vault.unlock(), 'not-found');

      expect(await readAll(first.name)).toEqual(before);
      expect([await first.vault.state(), await second.vault.state()]).toEqual(['unlocked', 'locked']);
    },
  );

  test.each(['empty', 'unprotected'] as const)(
    'unlock on a vault that is %s when the prompt is answered fails with not-found and changes nothing',
    async (expected) => {
      const [first, second] = await openContexts();
      await first.vault.protect();
      await second.vault.state(); // an application shows Unlock after reading the state (D-94)
      const release = holdPrompt();

      const pending = second.vault.unlock();
      await first.vault.wipe();
      if (expected === 'unprotected') await first.scope.generate('ed25519');
      const before = await readAll(first.name);
      release();

      await expectVaultError(pending, 'not-found');
      expect(await readAll(first.name)).toEqual(before);
      expect(await second.vault.state()).toBe(expected);
    },
  );

  test.each(['empty', 'unprotected'] as const)(
    'unlock in an instance whose last read found the vault %s fails with not-found and no prompt; the next unlock prompts once and unlocks',
    async (seen) => {
      const [first, second] = await openContexts();
      if (seen === 'unprotected') await first.scope.generate('ed25519');
      expect(await second.vault.state()).toBe(seen);
      await first.vault.protect();
      const get = vi.spyOn(navigator.credentials, 'get');

      await expectVaultError(second.vault.unlock(), 'not-found');
      expect(get).not.toHaveBeenCalled();

      await second.vault.unlock();
      expect(get).toHaveBeenCalledTimes(1);
      expect(await second.vault.state()).toBe('unlocked');
    },
  );

  test('an instance whose last read was a sign that failed with locked unlocks with one prompt; after its own wipe, unlock is not-found with no prompt', async () => {
    const [first, second] = await openContexts();
    const key = asSealed(await first.scope.generate('ed25519')); // any sealed type: sign reads the header
    await first.vault.protect();
    await expectVaultError(second.scope.sign(key, message), 'locked');
    const get = vi.spyOn(navigator.credentials, 'get');

    await second.vault.unlock();
    expect(get).toHaveBeenCalledTimes(1);

    await second.vault.wipe();
    await expectVaultError(second.vault.unlock(), 'not-found');
    expect(get).toHaveBeenCalledTimes(1);
  });

  test('after another instance wipes and protects with a new unlock passkey, unlock with the old one fails with not-found and changes nothing; the next unlock asks for the new one and unlocks', async () => {
    const [first, second] = await openContexts();
    await first.vault.protect();
    const old = await unlockPasskeyId(first.name);
    expect(await second.vault.state()).toBe('locked');
    await first.vault.wipe();
    await first.vault.protect(); // the old unlock passkey stays at the authenticator (D-76)
    const current = await unlockPasskeyId(first.name);
    const before = await readAll(first.name);
    const get = vi.spyOn(navigator.credentials, 'get');

    await expectVaultError(second.vault.unlock(), 'not-found');
    expect(get.mock.calls[0]?.[0]?.publicKey?.allowCredentials).toEqual([{ type: 'public-key', id: old }]);
    expect(await readAll(first.name)).toEqual(before);

    await second.vault.unlock();
    expect(get.mock.calls[1]?.[0]?.publicKey?.allowCredentials).toEqual([{ type: 'public-key', id: current }]);
    expect(await second.vault.state()).toBe('unlocked');
  });

  test.each(['wiped', 'wiped and protected again'] as const)(
    'a declined prompt for an unlock passkey the vault no longer names, another instance having %s, fails with not-found, not cancelled',
    async (change) => {
      const [first, second] = await openContexts();
      await first.vault.protect();
      expect(await second.vault.state()).toBe('locked');
      await first.vault.wipe();
      if (change === 'wiped and protected again') await first.vault.protect();
      const before = await readAll(first.name);
      await authenticator.setPresence(false);
      shortGetTimeout();

      const error = await expectVaultError(second.vault.unlock(), 'not-found');
      expect(error.cause).toMatchObject({ code: 'cancelled' });
      expect(await readAll(first.name)).toEqual(before);
    },
  );

  test.each([
    ['a declined prompt', 'cancelled'],
    ['the unlock passkey deleted at its authenticator', 'cancelled'],
    ['an assertion without user verification', 'unsupported'],
    ['an assertion without a PRF result', 'unsupported'],
  ] as const)('unlock with %s fails with %s; the vault stays protected and locked', async (failure, code) => {
    const [first, second] = await openContexts();
    const key = asSealed(await first.scope.generate('ed25519'));
    await first.vault.protect();
    await second.vault.state(); // an application shows Unlock after reading the state (D-94)
    const before = await readAll(first.name);
    if (failure === 'a declined prompt') {
      await authenticator.setPresence(false);
      shortGetTimeout();
    } else if (failure === 'the unlock passkey deleted at its authenticator') {
      await authenticator.removeCredential(await unlockPasskeyId(first.name));
      shortGetTimeout();
    } else if (failure === 'an assertion without user verification') {
      await authenticator.overrideResponses({ isBadUV: true });
    } else {
      vi.spyOn(PublicKeyCredential.prototype, 'getClientExtensionResults').mockReturnValue({ prf: {} });
    }

    await expectVaultError(second.vault.unlock(), code);

    expect(await readAll(first.name)).toEqual(before);
    expect(await second.vault.state()).toBe('locked');
    await expectVaultError(second.scope.sign(key, message), 'locked');
  });
});

function clearStores(tx: IDBTransaction): void {
  tx.objectStore('meta').clear();
  tx.objectStore('keys').clear();
}

/**
 * Runs `write` each time protect, its prompts answered and the vault read, is about to wrap the new wrapping private
 * key: after its read, before its write transaction, so another instance's write falls in between. The only ECDH
 * key Vault wraps is that one; sealed keys are Ed25519 keys or bytes. Restored by vi.restoreAllMocks.
 */
function beforeProtectWrite(write: (attempt: number) => unknown): void {
  const wrapKey = crypto.subtle.wrapKey.bind(crypto.subtle);
  let attempt = 0;
  vi.spyOn(crypto.subtle, 'wrapKey').mockImplementation(async (format, key, wrappingKey, algorithm) => {
    if (key.algorithm.name === 'ECDH') await write(++attempt);
    return wrapKey(format, key, wrappingKey, algorithm);
  });
}

/** Counts the passkey prompts from here on, as [creations, assertions]. Restored by vi.restoreAllMocks. */
function countPrompts(): () => [number, number] {
  const create = vi.spyOn(navigator.credentials, 'create');
  const get = vi.spyOn(navigator.credentials, 'get');
  return () => [create.mock.calls.length, get.mock.calls.length];
}

// Chromium only, as above (D-80). Two instances of one database are two contexts (concurrency.test.ts).
describe.runIf(hasVirtualAuthenticator)('protection across instances', () => {
  beforeEach(async () => {
    authenticator = await addVirtualAuthenticator({ hasPrf: true });
  });

  afterEach(async () => {
    vi.restoreAllMocks();
    await authenticator.remove();
    await cleanup();
  });

  describe.each(keyTypeCases)('$type', ({ type, verify }) => {
    /** Every key signs in `scope`'s instance, unlocked, with a signature that verifies. */
    async function expectSigns(scope: Scope, keys: KeyInfo<SealedKeyTypeName>[]): Promise<void> {
      for (const key of keys) {
        const { bytes } = await scope.sign(key, message);
        expect(await verify(key.publicKey, bytes, message)).toBe(true);
      }
    }

    test('protect held after its prompt while another instance generates: it commits with no new prompt, and the new key is protected', async () => {
      tickingClock();
      const [first, second] = await openContexts();
      const existing = asSealed(await first.scope.generate(type));
      let generated: KeyInfo<SealedKeyTypeName> | undefined;
      beforeProtectWrite(async (attempt) => {
        if (attempt === 1) generated = asSealed(await second.scope.generate(type));
      });
      const prompts = countPrompts();

      await first.vault.protect();

      expect(prompts()).toEqual([1, 0]);
      if (!generated) throw new Error('no key generated');
      expect((await first.scope.list()).map((k) => k.id)).toEqual([existing.id, generated.id]);
      expect(await first.vault.state()).toBe('unlocked');
      await expectSigns(first.scope, [existing, generated]);
      expect(await second.vault.state()).toBe('locked');
      await expectVaultError(second.scope.sign(generated, message), 'locked');
      pickPasskey(await unlockPasskeyId(first.name));
      await second.vault.unlock();
      await expectSigns(second.scope, [existing, generated]);
    });

    test('protect held after its prompt while another instance deletes a key: it commits with no new prompt, and the key stays deleted', async () => {
      tickingClock();
      const [first, second] = await openContexts();
      const kept = asSealed(await first.scope.generate(type));
      const deleted = asSealed(await first.scope.generate(type));
      beforeProtectWrite(async (attempt) => {
        if (attempt === 1) await second.scope.delete(deleted);
      });
      const prompts = countPrompts();

      await first.vault.protect();

      expect(prompts()).toEqual([1, 0]);
      expect((await first.scope.list()).map((k) => k.id)).toEqual([kept.id]);
      expect((await readAll(first.name)).keys).toHaveLength(1);
      await expectSigns(first.scope, [kept]);
      await expectVaultError(first.scope.sign(deleted, message), 'not-found');
    });

    test('protect held after its prompt while another instance writes a passkey key: it commits with no new prompt, and both keys sign', async () => {
      tickingClock();
      const [first, second] = await openContexts();
      const sealed = asSealed(await first.scope.generate(type));
      let passkeyKey: KeyInfo<'passkey'> | undefined;
      beforeProtectWrite(async (attempt) => {
        if (attempt === 1) passkeyKey = await second.scope.generate('passkey');
      });
      const prompts = countPrompts();

      await first.vault.protect();

      expect(prompts()).toEqual([2, 0]); // the unlock passkey and the passkey key
      if (!passkeyKey) throw new Error('no passkey key generated');
      expect((await first.scope.list()).map((k) => k.id)).toEqual([sealed.id, passkeyKey.id]);
      await expectSigns(first.scope, [sealed]);
      await expect(first.scope.sign(passkeyKey, message)).resolves.toMatchObject({ type: 'passkey' });
    });

    test('protect held after its prompt while another instance wipes: it redoes against the empty vault, with no new prompt, and leaves a protected vault with no keys', async () => {
      const [first, second] = await openContexts();
      const wiped = asSealed(await first.scope.generate(type));
      beforeProtectWrite(async (attempt) => {
        if (attempt === 1) await second.vault.wipe();
      });
      const prompts = countPrompts();

      await first.vault.protect();

      expect(prompts()).toEqual([1, 0]);
      const { meta, keys } = await readAll(first.name);
      expect(meta).toEqual([expect.objectContaining({ protection: expect.objectContaining({ kind: 'passkey' }) })]);
      expect(keys).toEqual([]);
      expect([await first.vault.state(), await second.vault.state()]).toEqual(['unlocked', 'locked']);
      await expectVaultError(first.scope.sign(wiped, message), 'not-found');
    });

    test('protect whose every attempt meets another instance’s generate fails with unavailable, with no new prompt; the vault stays unprotected and every key signs', async () => {
      tickingClock();
      const [first, second] = await openContexts();
      const keys = [asSealed(await first.scope.generate(type))];
      beforeProtectWrite(async () => {
        keys.push(asSealed(await second.scope.generate(type)));
      });
      const prompts = countPrompts();

      await expectVaultError(first.vault.protect(), 'unavailable');

      expect(prompts()).toEqual([1, 0]);
      expect(keys).toHaveLength(1 + 3); // one write met by each of the 3 attempts
      expect([await first.vault.state(), await second.vault.state()]).toEqual(['unprotected', 'unprotected']);
      expect((await first.scope.list()).map((k) => k.id)).toEqual(keys.map((k) => k.id));
      await expectSigns(first.scope, keys);
    });

    test('protect whose read header a storage writer replaces before its write, the keys left, writes nothing: its redo finds keys the new header cannot open, corrupted', async () => {
      const { vault, scope, name } = await openVault();
      await scope.generate(type);
      const { scope: anotherScope, name: anotherName } = await openVault();
      await anotherScope.generate(type);
      const replacement = await readHeader(anotherName);
      beforeProtectWrite(async (attempt) => {
        if (attempt === 1) await writeHeader(name, replacement);
      });
      const prompts = countPrompts();

      await expectVaultError(vault.protect(), 'corrupted');

      expect(prompts()).toEqual([1, 0]);
      expect((await readAll(name)).meta).toEqual([replacement]);
      expect(await vault.state()).toBe('unprotected');
    });

    test('a generate held while another instance protects is redone against the protected header, and its key signs after unlock', async () => {
      tickingClock();
      const [first, second] = await openContexts();
      const existing = asSealed(await first.scope.generate(type));
      const unprotected = await readHeader(first.name);
      const held = holdGenerate(type); // first has read the unprotected header it would seal to

      const pending = first.scope.generate(type);
      await held.reached;
      await second.vault.protect();
      held.release();
      const key = asSealed(await pending);

      const header = await readHeader(first.name);
      expect(header.wrappingPublicKey).not.toEqual(unprotected.wrappingPublicKey);
      expect(header.protection.kind).toBe('passkey');
      await expectSigns(second.scope, [existing, key]); // the protecting instance is unlocked
      await expectVaultError(first.scope.sign(key, message), 'locked');
      pickPasskey(await unlockPasskeyId(first.name));
      await first.vault.unlock();
      await expectSigns(first.scope, [existing, key]);
    });

    test('an unlocked instance, after another wipes, reports empty and its old keys are not-found; after another wipes and protects again, it reports locked and sealed sign is locked', async () => {
      const [first, second] = await openContexts();
      const old = asSealed(await first.scope.generate(type));
      await first.vault.protect();

      await second.vault.wipe();

      expect(await first.vault.state()).toBe('empty');
      await expectVaultError(first.scope.sign(old, message), 'not-found');

      await first.vault.protect(); // unlocked again, under a vault of its own
      const key = asSealed(await first.scope.generate(type));
      await expectSigns(first.scope, [key]);
      await second.vault.wipe();
      const fresh = asSealed(await second.scope.generate(type));
      await second.vault.protect();

      expect(await first.vault.state()).toBe('locked');
      await expectVaultError(first.scope.sign(fresh, message), 'locked');
      await expectVaultError(first.scope.sign(key, message), 'not-found');
    });
  });
});

// Every engine: detection reads only the page's WebAuthn globals, so each case sets them by hand (D-75).
describe('protection support', () => {
  afterEach(() => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
    Reflect.deleteProperty(navigator, 'credentials'); // the case's own property; the engine's, if any, shows again
  });

  /** A PublicKeyCredential class whose getClientCapabilities() is `capabilities`. */
  const withCapabilities = (capabilities: () => Promise<Record<string, boolean>>) =>
    class {
      static getClientCapabilities = capabilities;
    };

  /**
   * Sets the page's WebAuthn: `PublicKeyCredential`, and a `navigator.credentials` whose prompting calls are counted,
   * or none. Opened databases are counted too.
   */
  function setWebAuthn(publicKeyCredential: unknown, credentials: boolean) {
    vi.stubGlobal('PublicKeyCredential', publicKeyCredential);
    const prompts = { create: vi.fn(), get: vi.fn() };
    const value = credentials ? prompts : undefined;
    Object.defineProperty(navigator, 'credentials', { value, configurable: true });
    const opened = vi.spyOn(indexedDB, 'open');
    return { prompts, opened };
  }

  const prfTrue = withCapabilities(async () => ({ 'extension:prf': true }));
  const supportCases = [
    { name: 'no PublicKeyCredential', publicKeyCredential: undefined, credentials: true, expected: 'unsupported' },
    {
      name: 'a PublicKeyCredential that is no constructor, as in Playwright’s WebKit on Linux',
      publicKeyCredential: { getClientCapabilities: async () => ({ 'extension:prf': true }) },
      credentials: true,
      expected: 'unsupported',
    },
    { name: 'no navigator.credentials', publicKeyCredential: prfTrue, credentials: false, expected: 'unsupported' },
    {
      name: 'extension:prf reported false',
      publicKeyCredential: withCapabilities(async () => ({ 'extension:prf': false })),
      credentials: true,
      expected: 'unsupported',
    },
    { name: 'extension:prf reported true', publicKeyCredential: prfTrue, credentials: true, expected: 'unknown' },
    {
      name: 'no extension:prf key',
      publicKeyCredential: withCapabilities(async () => ({ conditionalGet: true })),
      credentials: true,
      expected: 'unknown',
    },
    { name: 'no getClientCapabilities', publicKeyCredential: class {}, credentials: true, expected: 'unknown' },
    {
      name: 'getClientCapabilities rejecting',
      publicKeyCredential: withCapabilities(() => Promise.reject(new DOMException('Not allowed', 'NotAllowedError'))),
      credentials: true,
      expected: 'unknown',
    },
  ] as const;
  test.each(supportCases)(
    'protectionSupport() with $name is $expected, with no prompt and no database opened',
    async ({ publicKeyCredential, credentials, expected }) => {
      const { prompts, opened } = setWebAuthn(publicKeyCredential, credentials);
      expect(await Vault.protectionSupport()).toBe(expected);
      expect(prompts.create).not.toHaveBeenCalled();
      expect(prompts.get).not.toHaveBeenCalled();
      expect(opened).not.toHaveBeenCalled();
    },
  );

  test('protectionSupport() with the engine’s own WebAuthn is unknown in Chromium and Firefox, unsupported in Playwright’s WebKit, which has none', async () => {
    expect(await Vault.protectionSupport()).toBe(server.browser === 'webkit' ? 'unsupported' : 'unknown');
  });

  test('protectionSupport() takes no argument and returns exactly unsupported or unknown', () => {
    expectTypeOf(Vault.protectionSupport).parameters.toEqualTypeOf<[]>();
    expectTypeOf(Vault.protectionSupport).returns.toEqualTypeOf<Promise<'unsupported' | 'unknown'>>();
  });
});
