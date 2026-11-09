import { expect, test, type Locator, type Page } from '@playwright/test';
import { createPublicKey, ECDH, verify } from 'node:crypto';

const fromHex = (hex: string) => Uint8Array.from(hex.match(/../g)!, (byte) => parseInt(byte, 16));

/** Verifies in Node, with no Vault and no noble: WebCrypto for ed25519, OpenSSL for secp256k1. */
async function verifyInNode(type: string, publicKeyHex: string, signatureHex: string, message: string): Promise<boolean> {
  const [publicKey, signature, data] = [fromHex(publicKeyHex), fromHex(signatureHex), new TextEncoder().encode(message)];
  if (type === 'ed25519') {
    const key = await crypto.subtle.importKey('raw', publicKey, 'Ed25519', false, ['verify']);
    return crypto.subtle.verify('Ed25519', key, signature, data);
  }
  // secp256k1: decompress the 33-byte SEC1 point for a JWK, then ECDSA-SHA256 with r ‖ s (IEEE P1363) encoding.
  const point = ECDH.convertKey(publicKey, 'secp256k1', undefined, undefined, 'uncompressed') as Buffer;
  const jwk = { kty: 'EC', crv: 'secp256k1', x: point.subarray(1, 33).toString('base64url'), y: point.subarray(33).toString('base64url') };
  return verify('sha256', data, { key: createPublicKey({ key: jwk, format: 'jwk' }), dsaEncoding: 'ieee-p1363' }, signature);
}

async function ready(page: Page) {
  await expect(page.locator('#status')).toHaveText('Ready');
}

async function generate(page: Page, type: string, label: string) {
  await page.selectOption('#type', type);
  await page.fill('#label', label);
  await page.click('#generate');
}

async function signAndVerifyOutside(page: Page, row: Locator, message: string) {
  await page.fill('#message', message);
  await row.getByRole('button', { name: 'Sign' }).click();
  const output = page.locator('#output');
  await expect(output).toHaveAttribute('data-verified', 'true');
  const [type, publicKey, signature] = [
    (await row.getAttribute('data-type'))!,
    (await row.getAttribute('data-public-key'))!,
    (await output.getAttribute('data-signature'))!,
  ];
  expect(await verifyInNode(type, publicKey, signature, message)).toBe(true);
  expect(await verifyInNode(type, publicKey, signature, `${message}!`)).toBe(false);
  return type;
}

test('demo page runs its TypeScript module in a secure context', async ({ page }) => {
  await page.goto('/');
  await ready(page);
  expect(await page.evaluate(() => isSecureContext)).toBe(true);
});

test('demo creates, lists, signs, deletes and wipes keys of both types, and its signatures verify outside the browser', async ({ page }) => {
  await page.goto('/');
  await ready(page);
  const rows = page.locator('#keys tr');

  await generate(page, 'ed25519', 'first');
  await expect(rows).toHaveCount(1);
  await generate(page, 'secp256k1', 'second');
  await expect(rows).toHaveCount(2);
  await expect(rows.nth(1).locator('td').first()).toHaveText('second');

  expect(await signAndVerifyOutside(page, rows.nth(0), 'signed in an e2e test')).toBe('ed25519');
  expect(await signAndVerifyOutside(page, rows.nth(1), 'signed in an e2e test')).toBe('secp256k1');

  await rows.nth(0).getByRole('button', { name: 'Delete' }).click();
  await expect(rows).toHaveCount(1);
  await page.reload();
  await ready(page);
  await expect(rows).toHaveCount(1);
  await expect(rows.nth(0)).toHaveAttribute('data-type', 'secp256k1');

  // Another scope sees none of these keys; wipe clears every scope.
  await page.fill('#scope', 'other');
  await page.locator('#scope').dispatchEvent('change');
  await ready(page);
  await expect(rows).toHaveCount(0);
  await generate(page, 'ed25519', 'elsewhere');
  await expect(rows).toHaveCount(1);

  await page.click('#wipe');
  await expect(rows).toHaveCount(0);
  await page.reload();
  await ready(page);
  await expect(rows).toHaveCount(0);
  await page.fill('#scope', 'other');
  await page.locator('#scope').dispatchEvent('change');
  await ready(page);
  await expect(rows).toHaveCount(0);
});
