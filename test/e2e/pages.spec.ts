import { expect, test, type Page } from '@playwright/test';
import { webcrypto } from 'node:crypto';
import { PUBLISHED_DEMO_URL } from './contexts.ts';
import { openWithAuthenticator, verifiesOutsideVault } from './passkeys.ts';

// The one smoke test of the published demo (D-93): the production build differs from the dev server only in
// bundling and asset paths under the base path, so the rest of the demo suite stays on the dev server.

const bytes = (hex: string | null): Uint8Array<ArrayBuffer> => {
  if (hex === null) throw new Error('attribute missing');
  return Uint8Array.from(Buffer.from(hex, 'hex'));
};

/** Generates a key of `type` in the page, signs `message` with it, and returns its listed row's public key. */
async function generateAndSign(page: Page, type: string, message: string): Promise<Uint8Array<ArrayBuffer>> {
  const rows = page.locator(`#keys tr[data-type="${type}"]`);
  await page.selectOption('#type', type);
  await page.click('#generate');
  await expect(rows).toHaveCount(1);
  await page.fill('#message', message);
  await rows.getByRole('button', { name: 'Sign' }).click();
  const output = page.locator('#output');
  await expect(output).toHaveAttribute('data-type', type);
  await expect(output).toHaveAttribute('data-verified', 'true');
  return bytes(await rows.getAttribute('data-public-key'));
}

test('the published demo build, under the Pages base path, signs with an ed25519 key and a passkey key, both verifying outside the browser, and exposes no Vault global', async ({
  browser,
  browserName,
}) => {
  // Its own context: the suite's baseURL is the dev demo.
  const context = await browser.newContext({ baseURL: PUBLISHED_DEMO_URL });
  try {
    const { page } = await openWithAuthenticator(context, browserName);
    expect(new URL(page.url()).pathname).toBe('/vault/');
    expect(await page.evaluate(() => 'Vault' in globalThis)).toBe(false);
    const output = page.locator('#output');

    // Node's WebCrypto, the listed public key and the shown signature: no Vault, no browser.
    const edMessage = 'signed on the published demo';
    const edPublicKey = await generateAndSign(page, 'ed25519', edMessage);
    const edKey = await webcrypto.subtle.importKey('raw', edPublicKey, 'Ed25519', false, ['verify']);
    const edSignature = bytes(await output.getAttribute('data-signature'));
    const edData = new TextEncoder().encode(edMessage);
    expect(await webcrypto.subtle.verify('Ed25519', edKey, edSignature, edData)).toBe(true);

    // A relying party's check in Node, under the listed SPKI public key.
    const passkeyMessage = 'signed with a passkey on the published demo';
    const passkeyKey = Array.from(await generateAndSign(page, 'passkey', passkeyMessage));
    const assertion = {
      authenticatorData: Array.from(bytes(await output.getAttribute('data-authenticator-data'))),
      clientDataJSON: Array.from(bytes(await output.getAttribute('data-client-data-json'))),
      signature: Array.from(bytes(await output.getAttribute('data-signature'))),
    };
    const origin = new URL(page.url()).origin;
    expect(verifiesOutsideVault(passkeyKey, assertion, passkeyMessage, origin)).toBe(true);
    expect(verifiesOutsideVault(passkeyKey, assertion, 'another message', origin)).toBe(false);
  } finally {
    await context.close();
  }
});
