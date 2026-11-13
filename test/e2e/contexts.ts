import { expect, type BrowserContext, type Page } from '@playwright/test';
import { webcrypto } from 'node:crypto';

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
      page.evaluate(() => {
        const { pendingGenerate } = globalThis as Record<string, unknown>;
        if (!(pendingGenerate instanceof Promise)) throw new Error('pendingGenerate missing');
        // `as`: checked to be a promise just above; startGenerate set it to one of a PageKey
        return pendingGenerate as Promise<PageKey>;
      }),
  };
}

/** An Ed25519 key generated in the demo scope from the page's console. */
export async function generate(page: Page): Promise<PageKey> {
  const { settled } = await startGenerate(page);
  return settled();
}

/** Deletes `key` from the demo scope from the page's console. */
export async function deleteKey(page: Page, key: PageKey): Promise<void> {
  await page.evaluate(
    async ({ scope, id }) => {
      // `as`: the global the dev demo sets; undefined fails the call below
      const { Vault } = globalThis as unknown as { Vault: typeof import('../../src/index.ts').Vault };
      const vault = await Vault.open();
      try {
        const stored = (await vault.scope(scope).list()).find((listed) => listed.id === id);
        if (!stored) throw new Error(`no key ${id} to delete`);
        await vault.scope(scope).delete(stored);
      } finally {
        vault.close();
      }
    },
    { scope: DEMO_SCOPE, id: key.id },
  );
}

/**
 * Opens the demo's vault in the page and keeps it open, with a listener on its change notifications.
 * `calls()` is how many times the listener has been called so far, each with no argument.
 */
export async function watchChanges(page: Page): Promise<{ calls: () => number }> {
  let calls = 0;
  await page.exposeFunction('vaultChanged', (argumentCount: number) => {
    expect(argumentCount).toBe(0);
    calls++;
  });
  await page.evaluate(async () => {
    // `as`: the global the dev demo sets, and the function exposed just above; undefined fails the calls below
    const { Vault, vaultChanged } = globalThis as unknown as {
      Vault: typeof import('../../src/index.ts').Vault;
      vaultChanged: (argumentCount: number) => void;
    };
    const vault = await Vault.open();
    vault.onChange((...args: unknown[]) => vaultChanged(args.length));
  });
  return { calls: () => calls };
}

/** Protects the demo's vault from the page's console; its prompts go to the page's authenticator. */
export async function protect(page: Page): Promise<void> {
  await page.evaluate(async () => {
    // `as`: the global the dev demo sets; undefined fails the call below
    const { Vault } = globalThis as unknown as { Vault: typeof import('../../src/index.ts').Vault };
    const vault = await Vault.open();
    try {
      await vault.protect();
    } finally {
      vault.close();
    }
  });
}

/** What a kept vault's `sign` step returns: each key's public key and signature, or the VaultError code. */
export type SignedKeys = { publicKey: number[]; signature: number[] }[] | { error: string };

/** A failed step of a kept vault: the code of its VaultError. */
type Failed = { error: string };

/**
 * Opens the demo's vault in `page` and keeps it open, as a tab does: every step runs on that one instance, so an
 * unlock lasts across steps (D-72). `changes()` counts its onChange calls. A VaultError comes back as its code.
 */
export async function keepVault(page: Page): Promise<{
  state: () => Promise<string | Failed>;
  unlock: () => Promise<undefined | Failed>;
  /** Every key of the demo scope, each with its signature of `message`. */
  sign: (message: string) => Promise<SignedKeys>;
  changes: () => number;
}> {
  let changes = 0;
  await page.exposeFunction('keptVaultChanged', () => void changes++);
  await page.evaluate(async () => {
    // `as`: the global the dev demo sets, and the function exposed just above; undefined fails the calls below
    const { Vault, keptVaultChanged } = globalThis as unknown as {
      Vault: typeof import('../../src/index.ts').Vault;
      keptVaultChanged: () => void;
    };
    const vault = await Vault.open();
    vault.onChange(keptVaultChanged);
    Object.assign(globalThis, { keptVault: vault });
  });
  const step = (step: 'state' | 'unlock' | 'sign', message = '') =>
    page.evaluate(
      async ({ step, scope, message }) => {
        // `as`: keepVault set it just above
        const { keptVault: vault } = globalThis as unknown as { keptVault: import('../../src/index.ts').Vault };
        try {
          if (step === 'state') return await vault.state();
          if (step === 'unlock') return await vault.unlock();
          const keys = await vault.scope(scope).list();
          return await Promise.all(
            keys.map(async (key) => {
              const signature = await vault.scope(scope).sign(key, new TextEncoder().encode(message));
              if (signature.type === 'passkey')
                throw new Error(`Key ${key.id} is a passkey key; these pages make none`);
              return { publicKey: Array.from(key.publicKey), signature: Array.from(signature.bytes) };
            }),
          );
        } catch (error) {
          if (error instanceof Error && error.name === 'VaultError' && 'code' in error)
            return { error: String(error.code) };
          throw error;
        }
      },
      { step, scope: DEMO_SCOPE, message },
    );
  return {
    // `as`: each step returns what its branch in the page returns
    state: () => step('state') as Promise<string | Failed>,
    unlock: () => step('unlock') as Promise<undefined | Failed>,
    sign: (message) => step('sign', message) as Promise<SignedKeys>,
    changes: () => changes,
  };
}

/** Ed25519 verification in Node, independent of Vault and of the page. */
export async function verifies(publicKey: number[], signature: number[], message: string): Promise<boolean> {
  const key = await webcrypto.subtle.importKey('raw', Uint8Array.from(publicKey), 'Ed25519', false, ['verify']);
  return webcrypto.subtle.verify('Ed25519', key, Uint8Array.from(signature), new TextEncoder().encode(message));
}

/** `signed` holds one signature of `message` per key of `keys`, each verifying under its public key. */
export async function expectKeysSigned(signed: SignedKeys, keys: PageKey[], message: string): Promise<void> {
  if (!Array.isArray(signed)) throw new Error(`sign failed with ${signed.error}`);
  expect(signed.map(({ publicKey }) => publicKey).toSorted()).toEqual(keys.map((k) => k.publicKey).toSorted());
  for (const { publicKey, signature } of signed) expect(await verifies(publicKey, signature, message)).toBe(true);
}

/** Wipes the demo's vault from the page's console. */
export async function wipe(page: Page): Promise<void> {
  await page.evaluate(async () => {
    // `as`: the global the dev demo sets; undefined fails the call below
    const { Vault } = globalThis as unknown as { Vault: typeof import('../../src/index.ts').Vault };
    const vault = await Vault.open();
    try {
      await vault.wipe();
    } finally {
      vault.close();
    }
  });
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
            const signature = await vault.scope(scope).sign(key, data);
            if (signature.type === 'passkey') throw new Error(`Key ${key.id} is a passkey key; these tabs make none`);
            const { bytes } = signature;
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

/**
 * Every record in the `meta` store of the demo's database, read in the page with raw IndexedDB, not with Vault:
 * the wrapping public key of each, as plain numbers.
 */
export async function metaRecords(page: Page): Promise<{ wrappingPublicKey: number[] }[]> {
  return page.evaluate(async () => {
    const db = await new Promise<IDBDatabase>((resolve, reject) => {
      const open = indexedDB.open('vault');
      open.onsuccess = () => resolve(open.result);
      open.onerror = () => reject(open.error);
    });
    try {
      const all = db.transaction('meta', 'readonly').objectStore('meta').getAll();
      const records = await new Promise<unknown[]>((resolve, reject) => {
        all.onsuccess = () => resolve(all.result);
        all.onerror = () => reject(all.error);
      });
      return records.map((record) => {
        // `as`: checked just below
        const { wrappingPublicKey } = (record ?? {}) as { wrappingPublicKey?: unknown };
        if (!(wrappingPublicKey instanceof Uint8Array)) throw new Error('a meta record without a wrapping public key');
        return { wrappingPublicKey: Array.from(wrappingPublicKey) };
      });
    } finally {
      db.close();
    }
  });
}
