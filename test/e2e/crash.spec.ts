import { expect, test, type BrowserContext, type Page } from '@playwright/test';

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
