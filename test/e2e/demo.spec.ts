import { expect, test } from '@playwright/test';

function fromHex(hex: string | null): Uint8Array<ArrayBuffer> {
  if (hex === null) throw new Error('attribute missing');
  return Uint8Array.from(hex.match(/../g) ?? [], (byte) => parseInt(byte, 16));
}

test('demo page runs its TypeScript module in a secure context', async ({ page }) => {
  await page.goto('/');
  await expect(page.locator('#status')).toHaveText('Ready');
  expect(await page.evaluate(() => isSecureContext)).toBe(true);
});

test('demo creates, lists, signs, deletes and wipes keys, and its signatures verify outside the browser', async ({
  page,
}) => {
  await page.goto('/');
  await expect(page.locator('#status')).toHaveText('Ready');
  await expect(page.locator('#scope')).toHaveText('demo'); // one fixed scope, no scope input
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
  const publicKeyHex = await rows.nth(0).getAttribute('data-public-key');
  const publicKey = await crypto.subtle.importKey('raw', fromHex(publicKeyHex), 'Ed25519', false, ['verify']);
  const signatureHex = await output.getAttribute('data-signature');
  const signature = fromHex(signatureHex);
  expect(
    await crypto.subtle.verify('Ed25519', publicKey, signature, new TextEncoder().encode('signed in an e2e test')),
  ).toBe(true);

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
