import { expect, test } from '@playwright/test';

const fromHex = (hex: string) => Uint8Array.from(hex.match(/../g)!, (byte) => parseInt(byte, 16));

test('demo page runs its TypeScript module in a secure context', async ({ page }) => {
  await page.goto('/');
  await expect(page.locator('#status')).toHaveText('Ready');
  expect(await page.evaluate(() => isSecureContext)).toBe(true);
});

test('demo creates, lists, signs, deletes and wipes keys, and its signatures verify outside the browser', async ({ page }) => {
  await page.goto('/');
  await expect(page.locator('#status')).toHaveText('Ready');
  const rows = page.locator('#keys tr');

  await page.click('#generate');
  await expect(rows).toHaveCount(1);
  await page.click('#generate');
  await expect(rows).toHaveCount(2);

  await page.fill('#message', 'signed in an e2e test');
  await rows.nth(0).getByRole('button', { name: 'Sign' }).click();
  const output = page.locator('#output');
  await expect(output).toHaveAttribute('data-verified', 'true');

  // Node's WebCrypto, the public key and the signature: no Vault, no browser.
  const publicKey = await crypto.subtle.importKey('raw', fromHex((await rows.nth(0).getAttribute('data-public-key'))!), 'Ed25519', false, ['verify']);
  const signature = fromHex((await output.getAttribute('data-signature'))!);
  expect(await crypto.subtle.verify('Ed25519', publicKey, signature, new TextEncoder().encode('signed in an e2e test'))).toBe(true);

  await rows.nth(1).getByRole('button', { name: 'Delete' }).click();
  await expect(rows).toHaveCount(1);
  await page.reload();
  await expect(page.locator('#status')).toHaveText('Ready');
  await expect(rows).toHaveCount(1);

  await page.click('#wipe');
  await expect(rows).toHaveCount(0);
  await page.reload();
  await expect(page.locator('#status')).toHaveText('Ready');
  await expect(rows).toHaveCount(0);
});
