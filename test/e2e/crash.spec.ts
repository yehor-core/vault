import { expect, test, type BrowserContext, type Page } from '@playwright/test';
import { expectKeysSigned, generate, keepVault, metaRecords, openDemo, type PageKey } from './contexts.ts';
import { addVirtualAuthenticator, answerPromptsFrom, PRF_CHROMIUM_ONLY } from './passkeys.ts';

// Crash safety (D-38): the page goes away while the first generate writes the header and the key. Atomicity
// is a property of the storage write, not of a key type: one type is enough.

/** Where the page is cut off: before the write's transaction commits, or right after it does. */
type CutPoint = 'before commit' | 'after commit';

/**
 * Opens the dev demo, starts the first generate from the console, and resolves at the cut point.
 * Before commit: the second add (header and key both written) has succeeded, and a chain of reads holds the
 * transaction open so it can't commit before the page goes. After commit: the transaction of the first add
 * has completed; a write split in two would finish before the page goes, so only "before commit" catches it.
 * The hooks observe Vault's requests and add reads; they replace none of them.
 */
async function startFirstGenerate(page: Page, cut: CutPoint): Promise<void> {
  await page.goto('/');
  await expect(page.locator('#status')).toHaveText('Ready');
  const reached = Promise.withResolvers<void>();
  await page.exposeFunction('cutPointReached', reached.resolve);
  await page.evaluate((cut) => {
    const { Vault, cutPointReached } = globalThis as Record<string, unknown>;
    if (typeof Vault !== 'function' || typeof cutPointReached !== 'function') throw new Error('globals missing');
    const add = IDBObjectStore.prototype.add;
    let adds = 0;
    IDBObjectStore.prototype.add = function (this: IDBObjectStore, ...args: Parameters<IDBObjectStore['add']>) {
      const request = add.apply(this, args);
      adds++;
      if (cut === 'after commit' && adds === 1) this.transaction.addEventListener('complete', () => cutPointReached());
      // On success, not on the call: a write split into a second transaction runs only once the first,
      // which spans both stores, has committed, so the cut then falls between the two.
      if (cut === 'before commit' && adds === 2) {
        request.addEventListener('success', () => {
          const hold = () => {
            this.count().onsuccess = hold;
          };
          hold();
          cutPointReached();
        });
      }
      return request;
    };
    // `as`: checked to be a function just above; the dev demo sets it to Vault
    const vault = Vault as typeof import('../../src/index.ts').Vault;
    void vault.open().then((opened) => opened.scope('demo').generate('ed25519'));
  }, cut);
  await reached.promise;
}

/**
 * A fresh page on the same context finds the state the cut point leaves: before commit no vault, and a
 * generate works; after commit the header and the key together, and the key lists and signs.
 */
async function expectWholeState(context: BrowserContext, cut: CutPoint): Promise<void> {
  const page = await context.newPage();
  await page.goto('/');
  const stored = await page.evaluate(
    () =>
      new Promise<{ headers: number; keys: number }>((resolve, reject) => {
        const open = indexedDB.open('vault');
        open.onerror = () => reject(open.error);
        open.onsuccess = () => {
          const tx = open.result.transaction(['meta', 'keys']);
          const headers = tx.objectStore('meta').count();
          const keys = tx.objectStore('keys').count();
          tx.oncomplete = () => {
            open.result.close();
            resolve({ headers: headers.result, keys: keys.result });
          };
        };
      }),
  );
  expect(stored).toEqual(cut === 'before commit' ? { headers: 0, keys: 0 } : { headers: 1, keys: 1 });
  await expect(page.locator('#status')).toHaveText('Ready');
  const rows = page.locator('#keys tr');
  if (cut === 'before commit') {
    await expect(rows).toHaveCount(0);
    await page.click('#generate');
  }
  await expect(rows).toHaveCount(1);
  await rows.getByRole('button', { name: 'Sign' }).click();
  await expect(page.locator('#output')).toHaveAttribute('data-verified', 'true');
}

const cutPoints: CutPoint[] = ['before commit', 'after commit'];

// Crash safety of protect (D-04, D-80): the page goes away while protect writes the protected header and re-seals
// every key in one transaction. Its prompts go to a keeper page's authenticator, which outlives it (passkeys.ts).

const SEALED_KEYS = 2;
const message = 'message to sign';

/** A page of the demo whose prompts the keeper's PRF authenticator answers. */
async function openAnswered(context: BrowserContext, keeper: Page): Promise<{ page: Page; prompts: () => number }> {
  const page = await openDemo(context);
  const { prompts } = await answerPromptsFrom(page, keeper);
  return { page, prompts };
}

/**
 * Starts protect from the page's console and resolves at the cut point. Its transaction puts the header and each
 * re-sealed key; before commit: the last put has succeeded and a chain of reads holds the transaction open; after
 * commit: the transaction of the first put has completed. The hooks observe Vault's requests and add reads only.
 */
async function startProtect(page: Page, cut: CutPoint): Promise<void> {
  const reached = Promise.withResolvers<void>();
  await page.exposeFunction('protectCutReached', reached.resolve);
  await page.evaluate(
    ({ cut, puts }) => {
      const { Vault, protectCutReached } = globalThis as Record<string, unknown>;
      if (typeof Vault !== 'function' || typeof protectCutReached !== 'function') throw new Error('globals missing');
      const put = IDBObjectStore.prototype.put;
      let count = 0;
      IDBObjectStore.prototype.put = function (this: IDBObjectStore, ...args: Parameters<IDBObjectStore['put']>) {
        const request = put.apply(this, args);
        count++;
        if (cut === 'after commit' && count === 1)
          this.transaction.addEventListener('complete', () => protectCutReached());
        if (cut === 'before commit' && count === puts) {
          request.addEventListener('success', () => {
            const hold = () => {
              this.count().onsuccess = hold;
            };
            hold();
            protectCutReached();
          });
        }
        return request;
      };
      // `as`: checked to be a function just above; the dev demo sets it to Vault
      const vault = Vault as typeof import('../../src/index.ts').Vault;
      void vault.open().then((opened) => opened.protect());
    },
    { cut, puts: 1 + SEALED_KEYS },
  );
  await reached.promise;
}

/**
 * A fresh page finds the whole old vault or the whole new one: before commit unprotected, every key signing; after
 * commit protected and locked, every key signing after one unlock prompt. Either way one header and every key.
 */
async function expectWholeProtection(context: BrowserContext, keeper: Page, cut: CutPoint, keys: PageKey[]) {
  const { page, prompts } = await openAnswered(context, keeper);
  const vault = await keepVault(page);
  expect((await metaRecords(page)).length).toBe(1);
  if (cut === 'before commit') {
    expect(await vault.state()).toBe('unprotected');
  } else {
    expect(await vault.state()).toBe('locked');
    expect(await vault.sign(message)).toEqual({ error: 'locked' });
    expect(await vault.unlock()).toBeUndefined();
    expect(prompts()).toBe(1);
  }
  await expectKeysSigned(await vault.sign(message), keys, message);
}

for (const cut of cutPoints) {
  for (const how of ['a tab closed', 'a renderer crash'] as const) {
    test(`${how} while protect writes leaves the unprotected vault or the whole protected one, never a mix: ${cut}`, async ({
      context,
      browserName,
    }, testInfo) => {
      testInfo.skip(browserName !== 'chromium', PRF_CHROMIUM_ONLY);
      const keeper = await openDemo(context);
      await addVirtualAuthenticator(keeper, [], { prf: true });
      const { page } = await openAnswered(context, keeper);
      const keys: PageKey[] = [];
      for (let i = 0; i < SEALED_KEYS; i++) keys.push(await generate(page));

      await startProtect(page, cut);
      if (how === 'a tab closed') {
        await page.close();
      } else {
        const crashed = page.waitForEvent('crash');
        const cdp = await context.newCDPSession(page);
        void cdp.send('Page.crash').catch(() => {}); // never answers: the renderer is gone
        await crashed;
      }

      await expectWholeProtection(context, keeper, cut, keys);
    });
  }
}

for (const cut of cutPoints) {
  test(`a tab closed while the first generate writes leaves the old state or the new one, never a mix: ${cut}`, async ({
    page,
    context,
  }) => {
    await startFirstGenerate(page, cut);
    await page.close();
    await expectWholeState(context, cut);
  });

  test(`a renderer crash while the first generate writes leaves the old state or the new one, never a mix: ${cut}`, async ({
    page,
    context,
    browserName,
  }, testInfo) => {
    testInfo.skip(
      browserName !== 'chromium',
      'Playwright crashes a renderer only through Chromium’s DevTools protocol (Page.crash)',
    );
    await startFirstGenerate(page, cut);
    const crashed = page.waitForEvent('crash');
    const cdp = await context.newCDPSession(page);
    void cdp.send('Page.crash').catch(() => {}); // never answers: the renderer is gone
    await crashed;
    await expectWholeState(context, cut);
  });
}
