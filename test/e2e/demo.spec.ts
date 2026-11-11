import { expect, test, type Page } from '@playwright/test';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

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
