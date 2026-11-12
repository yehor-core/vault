import { expect, type BrowserContext, type Page } from '@playwright/test';

// Helpers for tests that run two contexts (pages of one browser context) on the dev demo's vault.

/** The scope the dev demo uses. */
export const DEMO_SCOPE = 'demo';

/** A key as it crosses from a page to the test: plain numbers, no typed arrays. */
export interface PageKey {
  readonly id: string;
  readonly publicKey: number[];
}

/** A new page of `context` with the dev demo loaded, its `Vault` global ready on the demo's database. */
export async function openDemo(context: BrowserContext): Promise<Page> {
  const page = await context.newPage();
  await page.goto('/');
  await expect(page.locator('#status')).toHaveText('Ready');
  return page;
}

/**
 * Holds the page's next Ed25519 key generation, by wrapping `crypto.subtle.generateKey` in the page: a `generate`
 * started there has read the header and waits until `release`. `reached` resolves once a call is held. Only
 * the first Ed25519 call is held; the P-256 keys of the header and of sealing pass. Call once per page.
 */
export async function holdKeyGeneration(page: Page): Promise<{ reached: Promise<void>; release: () => Promise<void> }> {
  const reached = Promise.withResolvers<void>();
  await page.exposeFunction('keyGenerationHeld', reached.resolve);
  await page.evaluate(() => {
    const { keyGenerationHeld } = globalThis as Record<string, unknown>;
    if (typeof keyGenerationHeld !== 'function') throw new Error('keyGenerationHeld missing');
    const gate = Promise.withResolvers<void>();
    Object.assign(globalThis, { releaseKeyGeneration: gate.resolve });
    const generateKey = SubtleCrypto.prototype.generateKey;
    let held = false;
    // `as`: the wrapper passes every overload through unchanged
    SubtleCrypto.prototype.generateKey = async function (this: SubtleCrypto, ...args: unknown[]) {
      if (!held && args[0] === 'Ed25519') {
        held = true;
        keyGenerationHeld();
        await gate.promise;
      }
      return Reflect.apply(generateKey, this, args);
    } as SubtleCrypto['generateKey'];
  });
  return {
    reached: reached.promise,
    release: () =>
      page.evaluate(() => {
        const { releaseKeyGeneration } = globalThis as Record<string, unknown>;
        if (typeof releaseKeyGeneration !== 'function') throw new Error('releaseKeyGeneration missing');
        releaseKeyGeneration();
      }),
  };
}

/**
 * Starts an Ed25519 `generate` in the demo scope from the page's console and returns at once; `settled`
 * resolves with the key once the call does.
 */
export async function startGenerate(page: Page): Promise<{ settled: () => Promise<PageKey> }> {
  await page.evaluate((scope) => {
    // `as`: the global the dev demo sets; undefined fails the call below
    const { Vault } = globalThis as unknown as { Vault: typeof import('../../src/index.ts').Vault };
    const pending = Vault.open().then(async (vault) => {
      try {
        const key = await vault.scope(scope).generate('ed25519');
        return { id: key.id, publicKey: Array.from(key.publicKey) };
      } finally {
        vault.close();
      }
    });
    pending.catch(() => {}); // read by settled()
    Object.assign(globalThis, { pendingGenerate: pending });
  }, DEMO_SCOPE);
  return {
    settled: () =>
      page.evaluate(() => (globalThis as unknown as { pendingGenerate: Promise<PageKey> }).pendingGenerate),
  };
}

/** An Ed25519 key generated in the demo scope from the page's console. */
export async function generate(page: Page): Promise<PageKey> {
  const { settled } = await startGenerate(page);
  return settled();
}

/** Every key the page lists in the demo scope, each with its signature of `message` made in that page. */
export async function listAndSign(page: Page, message: string): Promise<(PageKey & { signature: number[] })[]> {
  return page.evaluate(
    async ({ scope, message }) => {
      // `as`: the global the dev demo sets; undefined fails the call below
      const { Vault } = globalThis as unknown as { Vault: typeof import('../../src/index.ts').Vault };
      const vault = await Vault.open();
      try {
        const keys = await vault.scope(scope).list();
        const data = new TextEncoder().encode(message);
        return await Promise.all(
          keys.map(async (key) => {
            const { bytes } = await vault.scope(scope).sign(key, data);
            return { id: key.id, publicKey: Array.from(key.publicKey), signature: Array.from(bytes) };
          }),
        );
      } finally {
        vault.close();
      }
    },
    { scope: DEMO_SCOPE, message },
  );
}
