import { expect, test, type Page } from '@playwright/test';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  generate as generateInConsole,
  openDemo,
  protect as protectInConsole,
  wipe as wipeInConsole,
} from './contexts.ts';
import {
  addVirtualAuthenticator,
  CHROMIUM_ONLY,
  freshDevice,
  listPasskeys,
  openWithAuthenticator,
  PRF_CHROMIUM_ONLY,
  shortenPromptTimeouts,
  verifiesOutsideVault,
  type PageAssertion,
} from './passkeys.ts';

function fromHex(hex: string | null): Uint8Array<ArrayBuffer> {
  if (hex === null) throw new Error('attribute missing');
  return Uint8Array.from(hex.match(/../g) ?? [], (byte) => parseInt(byte, 16));
}

/** OpenSSL's verdict on a secp256k1 signature (64 bytes r ‖ s) of `message` under a compressed public key. */
function opensslVerifies(publicKey: Uint8Array, signature: Uint8Array, message: string): boolean {
  // SubjectPublicKeyInfo: id-ecPublicKey, secp256k1 (1.3.132.0.10), the 33-byte point as a BIT STRING.
  const spki = Uint8Array.of(...fromHex('3036301006072a8648ce3d020106052b8104000a032200'), ...publicKey);
  const dir = mkdtempSync(join(tmpdir(), 'vault-e2e-'));
  try {
    writeFileSync(join(dir, 'key.der'), spki);
    writeFileSync(join(dir, 'signature.der'), derSignature(signature));
    writeFileSync(join(dir, 'message'), message);
    const key = spawnSync('openssl', ['pkey', '-pubin', '-inform', 'DER', '-in', 'key.der', '-out', 'key.pem'], {
      cwd: dir,
    });
    if (key.status !== 0) throw new Error(`openssl pkey: ${key.stderr}`);
    const run = spawnSync(
      'openssl',
      ['dgst', '-sha256', '-verify', 'key.pem', '-signature', 'signature.der', 'message'],
      { cwd: dir, encoding: 'utf8' },
    );
    if (run.error) throw run.error;
    return run.status === 0 && run.stdout.trim() === 'Verified OK';
  } finally {
    rmSync(dir, { recursive: true });
  }
}

/** r ‖ s as the DER SEQUENCE of two INTEGERs that OpenSSL reads. */
function derSignature(signature: Uint8Array): Uint8Array {
  const integer = (bytes: Uint8Array) => {
    let i = 0;
    while (i < bytes.length - 1 && bytes[i] === 0) i++;
    const value = bytes.subarray(i);
    const padded = (value[0] ?? 0) >= 0x80 ? Uint8Array.of(0, ...value) : value; // keep it positive
    return [0x02, padded.length, ...padded];
  };
  const body = [...integer(signature.subarray(0, 32)), ...integer(signature.subarray(32))];
  return Uint8Array.of(0x30, body.length, ...body);
}

async function generate(page: Page, type: string) {
  await page.selectOption('#type', type);
  await page.click('#generate');
}

test('demo page runs its TypeScript module in a secure context', async ({ page }) => {
  await page.goto('/');
  await expect(page.locator('#status')).toHaveText('Ready');
  expect(await page.evaluate(() => isSecureContext)).toBe(true);
});

test('demo creates, lists, signs, deletes and wipes keys of each type, and its signatures verify outside the browser', async ({
  page,
}) => {
  await page.goto('/');
  await expect(page.locator('#status')).toHaveText('Ready');
  await expect(page.locator('#scope')).toHaveText('demo'); // one fixed scope, no scope input
  const rows = page.locator('#keys tr');

  await generate(page, 'ed25519');
  await expect(rows).toHaveCount(1);
  await generate(page, 'secp256k1');
  await expect(rows).toHaveCount(2);
  await generate(page, 'secp256k1');
  await expect(rows).toHaveCount(3);
  const ed = rows.and(page.locator('[data-type="ed25519"]'));
  const k1 = rows.and(page.locator('[data-type="secp256k1"]'));
  await expect(ed).toHaveCount(1);
  await expect(k1).toHaveCount(2);

  const output = page.locator('#output');
  const message = 'signed in an e2e test';
  await page.fill('#message', message);

  // Node's WebCrypto, the public key and the signature: no Vault, no browser.
  await ed.getByRole('button', { name: 'Sign' }).click();
  await expect(output).toHaveAttribute('data-verified', 'true');
  await expect(output).toHaveAttribute('data-type', 'ed25519');
  const edKey = await crypto.subtle.importKey(
    'raw',
    fromHex(await ed.getAttribute('data-public-key')),
    'Ed25519',
    false,
    ['verify'],
  );
  const edSignature = fromHex(await output.getAttribute('data-signature'));
  expect(await crypto.subtle.verify('Ed25519', edKey, edSignature, new TextEncoder().encode(message))).toBe(true);

  // OpenSSL, the public key and the signature: no Vault, no curve library.
  await k1.nth(0).getByRole('button', { name: 'Sign' }).click();
  await expect(output).toHaveAttribute('data-type', 'secp256k1');
  await expect(output).toHaveAttribute('data-verified', 'true');
  const k1Key = fromHex(await k1.nth(0).getAttribute('data-public-key'));
  const k1Signature = fromHex(await output.getAttribute('data-signature'));
  expect(k1Key).toHaveLength(33);
  expect(k1Signature).toHaveLength(64);
  expect(opensslVerifies(k1Key, k1Signature, message)).toBe(true);
  expect(opensslVerifies(k1Key, k1Signature, 'another message')).toBe(false);

  await k1.nth(1).getByRole('button', { name: 'Delete' }).click();
  await expect(rows).toHaveCount(2);
  await page.reload();
  await expect(page.locator('#status')).toHaveText('Ready');
  await expect(rows).toHaveCount(2);

  await page.click('#wipe');
  await expect(rows).toHaveCount(0);
  await page.reload();
  await expect(page.locator('#status')).toHaveText('Ready');
  await expect(rows).toHaveCount(0);
});

test('demo generates a labelled key and lists its label as text, never as markup', async ({ page }) => {
  await page.goto('/');
  await expect(page.locator('#status')).toHaveText('Ready');
  const rows = page.locator('#keys tr');
  const label = '<img src=x onerror="document.title=1">Payments';

  await page.fill('#label', label);
  await generate(page, 'ed25519');
  await expect(rows).toHaveCount(1);
  await page.fill('#label', '');
  await generate(page, 'secp256k1');
  await expect(rows).toHaveCount(2);

  await expect(rows.nth(0).getByRole('cell', { name: label, exact: true })).toHaveCount(1);
  await expect(rows.locator('img')).toHaveCount(0);
  await page.reload();
  await expect(page.locator('#status')).toHaveText('Ready');
  await expect(rows.nth(0).getByRole('cell', { name: label, exact: true })).toHaveCount(1);
  await page.click('#wipe');
  await expect(rows).toHaveCount(0);
});

// The wrap-up's console experiments (.claude/skills/wrap-up/console-prelude.md) start from this global.
test('the dev demo exposes Vault to the console: a key generated there is listed by the demo', async ({ page }) => {
  await page.goto('/');
  await expect(page.locator('#status')).toHaveText('Ready');
  await page.evaluate(async () => {
    // `as`: the global the dev demo sets; undefined fails the call below
    const { Vault } = globalThis as unknown as { Vault: typeof import('../../src/index.ts').Vault };
    const vault = await Vault.open();
    await vault.scope('demo').generate('ed25519', { label: 'from the console' });
    vault.close();
  });
  await page.reload();
  await expect(page.locator('#status')).toHaveText('Ready');
  await expect(page.getByRole('cell', { name: 'from the console', exact: true })).toHaveCount(1);
  await page.click('#wipe');
  await expect(page.locator('#keys tr')).toHaveCount(0);
});

/** The assertion the demo shows in #output after signing with a passkey key. */
async function shownAssertion(page: Page): Promise<PageAssertion> {
  const output = page.locator('#output');
  const bytes = async (name: string) => Array.from(fromHex(await output.getAttribute(name)));
  return {
    authenticatorData: await bytes('data-authenticator-data'),
    clientDataJSON: await bytes('data-client-data-json'),
    signature: await bytes('data-signature'),
  };
}

test('demo generates a labelled passkey key, lists it with its type, label and credential id, and signs with it', async ({
  context,
  browserName,
}) => {
  const { page } = await openWithAuthenticator(context, browserName);
  const rows = page.locator('#keys tr');
  await page.fill('#label', 'Laptop passkey');
  await generate(page, 'passkey');
  await expect(rows).toHaveCount(1);
  await expect(page.locator('#status')).toHaveText('Ready');
  const [key] = await listPasskeys(page);
  if (!key) throw new Error('no passkey key listed');
  const row = rows.nth(0);
  await expect(row).toHaveAttribute('data-type', 'passkey');
  await expect(row.getByRole('cell', { name: 'passkey', exact: true })).toHaveCount(1);
  await expect(row.getByRole('cell', { name: 'Laptop passkey', exact: true })).toHaveCount(1);
  const credentialId = await row.getAttribute('data-credential-id');
  expect(Array.from(fromHex(credentialId))).toEqual(key.credentialId);
  await expect(row.getByRole('cell').nth(3)).toHaveText(`${credentialId?.slice(0, 16)}…`); // the Credential id column

  const message = 'signed with a passkey in the demo';
  await page.fill('#message', message);
  await row.getByRole('button', { name: 'Sign' }).click();
  const output = page.locator('#output');
  await expect(output).toHaveAttribute('data-type', 'passkey');
  await expect(output).toHaveAttribute('data-verified', 'true');
  const assertion = await shownAssertion(page);
  const origin = new URL(page.url()).origin;
  expect(verifiesOutsideVault(key.publicKey, assertion, message, origin)).toBe(true);
  expect(verifiesOutsideVault(key.publicKey, assertion, 'another message', origin)).toBe(false);
});

test('demo adds an existing passkey key in a fresh browser context, with the id and credential id generate gave it, and signs with it', async ({
  context,
  browser,
  browserName,
}) => {
  const { page, authenticator } = await openWithAuthenticator(context, browserName);
  await page.fill('#label', 'made elsewhere');
  await generate(page, 'passkey');
  await expect(page.locator('#keys tr')).toHaveCount(1);
  const generated = page.locator('#keys tr').nth(0);
  const id = await generated.getAttribute('data-id');
  const credentialId = await generated.getAttribute('data-credential-id');

  const device = await freshDevice(browser, browserName, await authenticator.passkeys());
  try {
    const rows = device.page.locator('#keys tr');
    await expect(rows).toHaveCount(0);
    await device.page.fill('#label', 'added here');
    await device.page.click('#add');
    await expect(rows).toHaveCount(1);
    await expect(device.page.locator('#status')).toHaveText('Ready');
    const added = rows.nth(0);
    await expect(added).toHaveAttribute('data-type', 'passkey');
    await expect(added).toHaveAttribute('data-id', id ?? '');
    await expect(added).toHaveAttribute('data-credential-id', credentialId ?? '');
    await expect(added.getByRole('cell', { name: 'added here', exact: true })).toHaveCount(1);

    const [key] = await listPasskeys(device.page);
    if (!key) throw new Error('no passkey key listed');
    const message = 'signed on the fresh device';
    await device.page.fill('#message', message);
    await added.getByRole('button', { name: 'Sign' }).click();
    await expect(device.page.locator('#output')).toHaveAttribute('data-verified', 'true');
    const assertion = await shownAssertion(device.page);
    expect(verifiesOutsideVault(key.publicKey, assertion, message, new URL(device.page.url()).origin)).toBe(true);
  } finally {
    await device.context.close();
  }
});

/**
 * Per button click, how many WebAuthn calls its `onclick` started before returning. Wrapped by a capturing listener:
 * a later listener runs after the microtask checkpoint, when an `await` of a settled promise has already resumed.
 */
async function countPromptsAtClicks(page: Page): Promise<{ atClicks: () => Promise<number[]> }> {
  await page.evaluate(() => {
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
    const atClicks: number[] = [];
    document.addEventListener(
      'click',
      ({ target: button }) => {
        if (!(button instanceof HTMLButtonElement)) return;
        const handler = button.onclick;
        if (!handler) return;
        button.onclick = function (this: GlobalEventHandlers, event: PointerEvent) {
          button.onclick = handler;
          const before = prompts;
          const returned: unknown = handler.call(this, event);
          atClicks.push(prompts - before);
          return returned;
        };
      },
      { capture: true },
    );
    Object.assign(globalThis, { promptsAtClicks: atClicks });
  });
  return {
    atClicks: () =>
      page.evaluate(() => {
        const { promptsAtClicks } = globalThis as Record<string, unknown>;
        if (!Array.isArray(promptsAtClicks)) throw new Error('promptsAtClicks missing');
        return promptsAtClicks.map(Number);
      }),
  };
}

test('each demo passkey control calls Vault first in its click handler, so the prompt starts within the click', async ({
  context,
  browserName,
}) => {
  const { page } = await openWithAuthenticator(context, browserName);
  const status = page.locator('#status');
  const rows = page.locator('#keys tr');
  const prompts = await countPromptsAtClicks(page);
  await generate(page, 'passkey');
  await expect(rows).toHaveCount(1);
  await expect(status).toHaveText('Ready');
  await rows.nth(0).getByRole('button', { name: 'Sign' }).click();
  await expect(page.locator('#output')).toHaveAttribute('data-verified', 'true');
  await page.click('#add'); // the key this scope holds: one prompt, then returned as stored
  await expect(status).toHaveText('Ready');
  await expect(rows).toHaveCount(1);
  expect(await prompts.atClicks()).toEqual([1, 1, 1]); // generate, sign, add: each started its prompt synchronously
});

test('a cancelled passkey prompt in the demo shows its error code, and the demo goes on working', async ({
  context,
  browserName,
}, testInfo) => {
  testInfo.skip(browserName !== 'chromium', CHROMIUM_ONLY);
  const page = await openDemo(context);
  const authenticator = await addVirtualAuthenticator(page);
  const status = page.locator('#status');
  const rows = page.locator('#keys tr');
  await generate(page, 'passkey');
  await expect(rows).toHaveCount(1);
  await expect(status).toHaveText('Ready');

  await authenticator.setPresence(false);
  await shortenPromptTimeouts(page);
  for (const click of [
    () => page.click('#generate'),
    () => page.click('#add'),
    () => rows.nth(0).getByRole('button', { name: 'Sign' }).click(),
  ]) {
    await click();
    await expect(status).toHaveText(/^VaultError cancelled: /);
    await expect(status).toHaveClass('error');
    await status.evaluate((element) => (element.textContent = 'reset')); // so the next error is a new one
  }
  await expect(rows).toHaveCount(1); // the cancelled generate and add stored nothing

  await authenticator.setPresence(true);
  await rows.nth(0).getByRole('button', { name: 'Sign' }).click();
  await expect(page.locator('#output')).toHaveAttribute('data-verified', 'true');
  await expect(status).toHaveText('Ready');
});

test('demo protects, signs, locks, fails a sealed sign with locked, unlocks and signs again, its state line following each step', async ({
  context,
  browserName,
}, testInfo) => {
  testInfo.skip(browserName !== 'chromium', PRF_CHROMIUM_ONLY);
  const page = await openDemo(context);
  await addVirtualAuthenticator(page, [], { prf: true });
  const status = page.locator('#status');
  const state = page.locator('#state');
  const rows = page.locator('#keys tr');
  const output = page.locator('#output');
  const sign = () => rows.nth(0).getByRole('button', { name: 'Sign' }).click();
  await expect(state).toHaveText('empty');
  await generate(page, 'ed25519');
  await expect(rows).toHaveCount(1);
  await expect(state).toHaveText('unprotected');
  const prompts = await countPromptsAtClicks(page);

  await page.click('#protect');
  await expect(state).toHaveText('unlocked'); // the protecting tab is unlocked (D-83)
  await expect(status).toHaveText('Ready');
  await sign();
  await expect(output).toHaveAttribute('data-verified', 'true');

  await page.click('#lock');
  await expect(state).toHaveText('locked');
  await output.evaluate((element) => delete element.dataset.verified);
  await sign();
  await expect(status).toHaveText(/^VaultError locked: /);
  await expect(status).toHaveClass('error');
  await expect(output).not.toHaveAttribute('data-verified');

  await page.click('#unlock');
  await expect(state).toHaveText('unlocked');
  await expect(status).toHaveText('Ready');
  await sign();
  await expect(output).toHaveAttribute('data-verified', 'true');
  await expect(rows).toHaveCount(1);
  // protect, sign, lock, sign, unlock, sign: protect and unlock each started their one prompt within the click
  expect(await prompts.atClicks()).toEqual([1, 0, 0, 0, 1, 0]);

  await page.click('#wipe');
  await expect(state).toHaveText('empty');
  await expect(rows).toHaveCount(0);
});

test('the demo shows another tab’s generate and wipe on onChange, its state line and key list refreshed', async ({
  context,
}) => {
  const page = await openDemo(context);
  const other = await openDemo(context);
  const state = page.locator('#state');
  const rows = page.locator('#keys tr');
  await expect(state).toHaveText('empty');

  await generateInConsole(other);
  await expect(state).toHaveText('unprotected');
  await expect(rows).toHaveCount(1);
  await wipeInConsole(other);
  await expect(state).toHaveText('empty');
  await expect(rows).toHaveCount(0);
  await expect(page.locator('#status')).toHaveText('Ready');
});

test('the demo shows locked on onChange when another tab protects, and its sealed key fails Sign with locked', async ({
  context,
  browserName,
}, testInfo) => {
  testInfo.skip(browserName !== 'chromium', PRF_CHROMIUM_ONLY);
  const page = await openDemo(context);
  const other = await openDemo(context);
  await addVirtualAuthenticator(other, [], { prf: true });
  const state = page.locator('#state');
  const status = page.locator('#status');
  await generate(page, 'ed25519');
  await expect(state).toHaveText('unprotected');

  await protectInConsole(other);
  await expect(state).toHaveText('locked');
  await page.locator('#keys tr').nth(0).getByRole('button', { name: 'Sign' }).click();
  await expect(status).toHaveText(/^VaultError locked: /);
});

test('demo Protect without PRF results shows VaultError unsupported and leaves the vault and its key as they were', async ({
  context,
  browserName,
}, testInfo) => {
  testInfo.skip(browserName === 'chromium', 'Playwright’s credentials stand-in returns no PRF results (D-80)');
  const { page } = await openWithAuthenticator(context, browserName);
  const state = page.locator('#state');
  const status = page.locator('#status');
  const rows = page.locator('#keys tr');
  await generate(page, 'ed25519');
  await expect(state).toHaveText('unprotected');

  await page.click('#protect');
  await expect(status).toHaveText(/^VaultError unsupported: /);
  await expect(state).toHaveText('unprotected');
  await rows.nth(0).getByRole('button', { name: 'Sign' }).click();
  await expect(page.locator('#output')).toHaveAttribute('data-verified', 'true');
  await expect(status).toHaveText('Ready');
});
