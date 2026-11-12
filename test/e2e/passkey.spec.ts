import { expect, test, type Page } from '@playwright/test';
import { DEMO_SCOPE, openDemo } from './contexts.ts';
import {
  addPasskey,
  addVirtualAuthenticator,
  expectVaultError,
  freshDevice,
  generatePasskey,
  listPasskeys,
  openWithAuthenticator,
  signWithPasskey,
  verifiesOutsideVault,
} from './passkeys.ts';

// Passkey keys end to end (D-62), from the dev demo's console. Chromium drives its own WebAuthn stack through a
// virtual authenticator; Firefox and WebKit run against Playwright's JavaScript stand-in for navigator.credentials,
// which always answers with the user verified, so the declined and unverified prompts are tested in Chromium only.

const message = 'message to sign';

const originOf = (page: Page) => new URL(page.url()).origin;

test('a passkey key generated in the page signs, and its assertion verifies outside Vault under the returned public key', async ({
  context,
  browserName,
}) => {
  const { page } = await openWithAuthenticator(context, browserName);
  const key = await generatePasskey(page);
  expect(await listPasskeys(page)).toEqual([key]);
  const assertion = await signWithPasskey(page, key, message);
  expect(verifiesOutsideVault(key.publicKey, assertion, message, originOf(page))).toBe(true);
  expect(verifiesOutsideVault(key.publicKey, assertion, 'another message', originOf(page))).toBe(false);
});

test('several passkey keys in one scope list, and each signs on its own, verifying only under its own public key', async ({
  context,
  browserName,
}) => {
  const { page, authenticator } = await openWithAuthenticator(context, browserName);
  const keys = [await generatePasskey(page), await generatePasskey(page), await generatePasskey(page)];
  expect(new Set(keys.map((key) => key.id)).size).toBe(3);
  expect(new Set(keys.map((key) => key.publicKey.join())).size).toBe(3);
  expect(await authenticator.passkeys()).toHaveLength(3); // no new passkey overwrote another
  expect(await listPasskeys(page)).toEqual(keys);
  for (const key of keys) {
    const assertion = await signWithPasskey(page, key, message);
    for (const other of keys) {
      expect(verifiesOutsideVault(other.publicKey, assertion, message, originOf(page))).toBe(other === key);
    }
  }
});

test('a passkey moved to a new browser context with an empty vault is added there with the same id and public key, then signs', async ({
  context,
  browser,
  browserName,
}) => {
  const { page, authenticator } = await openWithAuthenticator(context, browserName);
  const generated = await generatePasskey(page);
  const device = await freshDevice(browser, browserName, await authenticator.passkeys());
  try {
    expect(await listPasskeys(device.page)).toEqual([]);
    const added = await addPasskey(device.page);
    expect(added).toEqual(generated);
    expect(await listPasskeys(device.page)).toEqual([generated]);
    const assertion = await signWithPasskey(device.page, added, message);
    expect(verifiesOutsideVault(generated.publicKey, assertion, message, originOf(device.page))).toBe(true);
  } finally {
    await device.context.close();
  }
});

/** Gives every later passkey prompt of the page a 100 ms timeout: with presence off, it then ends as a declined one. */
async function shortenPromptTimeouts(page: Page): Promise<void> {
  await page.evaluate(() => {
    for (const method of ['create', 'get'] as const) {
      const original = navigator.credentials[method].bind(navigator.credentials);
      Object.assign(navigator.credentials, {
        [method]: (options: CredentialCreationOptions & CredentialRequestOptions) =>
          original({ ...options, publicKey: { ...options.publicKey, timeout: 100 } } as never),
      });
    }
  });
}

const CHROMIUM_ONLY =
  'Only Chromium’s virtual authenticator can decline a prompt or answer without user verification (D-62)';

test.describe('Chromium virtual authenticator', () => {
  test('a passkey prompt that is never answered is cancelled, for generate and sign, and generate stores nothing', async ({
    context,
    browserName,
  }, testInfo) => {
    testInfo.skip(browserName !== 'chromium', CHROMIUM_ONLY);
    const page = await openDemo(context);
    const authenticator = await addVirtualAuthenticator(page);
    const key = await generatePasskey(page);
    await authenticator.setPresence(false);
    await shortenPromptTimeouts(page);
    await expectVaultError(generatePasskey(page), 'cancelled');
    await expectVaultError(signWithPasskey(page, key, message), 'cancelled');
    expect(await listPasskeys(page)).toEqual([key]);
  });

  test('a passkey assertion without user verification is unsupported, and sign returns no signature', async ({
    context,
    browserName,
  }, testInfo) => {
    testInfo.skip(browserName !== 'chromium', CHROMIUM_ONLY);
    const page = await openDemo(context);
    const authenticator = await addVirtualAuthenticator(page);
    const key = await generatePasskey(page);
    await authenticator.answerWithoutUserVerification();
    await expectVaultError(signWithPasskey(page, key, message), 'unsupported');
  });
});

type PromptingCall = 'generate' | 'sign' | 'add';

/**
 * Adds a button to the page whose click handler starts `call` in the demo scope, and clicks it. True if
 * navigator.credentials had been called by the time `call` returned its promise, so before any await; the
 * call must then succeed. `sign` and `add` use the first passkey key the scope lists.
 */
async function promptStartsInClickHandler(page: Page, call: PromptingCall): Promise<boolean> {
  await page.evaluate(
    async ({ scope, call, message }) => {
      // `as`: the global the dev demo sets; undefined fails the call below
      const { Vault } = globalThis as unknown as typeof import('../../src/index.ts');
      const vault = await Vault.open();
      const keys = vault.scope(scope);
      const [key] = await keys.list();
      let prompts = 0;
      for (const method of ['create', 'get'] as const) {
        const original = navigator.credentials[method].bind(navigator.credentials);
        Object.assign(navigator.credentials, {
          [method]: (options: CredentialCreationOptions & CredentialRequestOptions) => {
            prompts++;
            return original(options);
          },
        });
      }
      const outcome = Promise.withResolvers<boolean>();
      const button = document.createElement('button');
      button.id = 'passkey-call';
      button.textContent = call;
      button.addEventListener(
        'click',
        () => {
          let pending: Promise<unknown>;
          if (call === 'generate') pending = keys.generate('passkey');
          else if (call === 'add') pending = keys.add('passkey');
          else if (key) pending = keys.sign(key, new TextEncoder().encode(message));
          else pending = Promise.reject(new Error('no key to sign with'));
          const started = prompts > 0;
          pending.then(() => outcome.resolve(started), outcome.reject).finally(() => vault.close());
        },
        { once: true },
      );
      document.body.append(button);
      Object.assign(globalThis, { passkeyCallOutcome: outcome.promise });
    },
    { scope: DEMO_SCOPE, call, message },
  );
  await page.click('#passkey-call');
  return page.evaluate(() => {
    const { passkeyCallOutcome } = globalThis as Record<string, unknown>;
    if (!(passkeyCallOutcome instanceof Promise)) throw new Error('passkeyCallOutcome missing');
    // `as`: checked to be a promise just above; promptStartsInClickHandler set it to one of a boolean
    return passkeyCallOutcome as Promise<boolean>;
  });
}

const promptingCalls: PromptingCall[] = ['generate', 'sign', 'add'];

for (const call of promptingCalls) {
  test(`a passkey call started from a click handler calls WebAuthn before its first await: ${call}`, async ({
    context,
    browserName,
  }) => {
    const { page } = await openWithAuthenticator(context, browserName);
    if (call !== 'generate') await generatePasskey(page);
    expect(await promptStartsInClickHandler(page, call)).toBe(true);
  });
}
