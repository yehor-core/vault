import { expect, test, type BrowserContext, type Page } from '@playwright/test';

// Crash safety (D-38): the page goes away while the first generate's transaction, which adds the header and
// the key, is in flight. Atomicity is a property of the storage write, not of a key type: one type is enough.

/**
 * Opens the dev demo, starts the first generate from the console, and resolves once its write is underway:
 * the transaction's second add (header and key both issued) has succeeded, and the transaction is held open
 * by a chain of reads so it can't commit before the test ends the page. Nothing Vault does is replaced.
 */
async function startFirstGenerate(page: Page): Promise<void> {
  await page.goto('/');
  await expect(page.locator('#status')).toHaveText('Ready');
  const underway = Promise.withResolvers<void>();
  await page.exposeFunction('writeUnderway', underway.resolve);
  await page.evaluate(() => {
    // `as`: the globals the dev demo and exposeFunction set; undefined fails the calls below
    const { Vault, writeUnderway } = globalThis as unknown as {
      Vault: typeof import('../../src/index.ts').Vault;
      writeUnderway: () => void;
    };
    const add = IDBObjectStore.prototype.add;
    let adds = 0;
    IDBObjectStore.prototype.add = function (this: IDBObjectStore, ...args: Parameters<IDBObjectStore['add']>) {
      const request = add.apply(this, args);
      // On success, not on the call: a second transaction would only run after the first one committed.
      if (++adds === 2) {
        request.addEventListener('success', () => {
          const hold = () => {
            this.count().onsuccess = hold;
          };
          hold();
          writeUnderway();
        });
      }
      return request;
    };
    void Vault.open().then((vault) => vault.scope('demo').generate('ed25519'));
  });
  await underway.promise;
}

/** A fresh page on the same context finds no vault, or the header and the key together, and the key lists and signs. */
async function expectOldStateOrNew(context: BrowserContext): Promise<void> {
  const page = await context.newPage();
  await page.goto('/');
  const counts = await page.evaluate(
    () =>
      new Promise<number[]>((resolve, reject) => {
        const open = indexedDB.open('vault');
        open.onerror = () => reject(open.error);
        open.onsuccess = () => {
          const tx = open.result.transaction(['meta', 'keys']);
          const meta = tx.objectStore('meta').count();
          const keys = tx.objectStore('keys').count();
          tx.oncomplete = () => {
            open.result.close();
            resolve([meta.result, keys.result]);
          };
        };
      }),
  );
  expect([
    [0, 0],
    [1, 1],
  ]).toContainEqual(counts); // [header records, key records]
  await expect(page.locator('#status')).toHaveText('Ready');
  const rows = page.locator('#keys tr');
  if (counts[1] === 0) {
    await expect(rows).toHaveCount(0);
    await page.click('#generate');
  }
  await expect(rows).toHaveCount(1);
  await rows.getByRole('button', { name: 'Sign' }).click();
  await expect(page.locator('#output')).toHaveAttribute('data-verified', 'true');
}

test('a tab closed while the first generate writes leaves no vault, or the header and key together, and the key signs', async ({
  page,
  context,
}) => {
  await startFirstGenerate(page);
  await page.close();
  await expectOldStateOrNew(context);
});

test('a renderer crash while the first generate writes leaves no vault, or the header and key together, and the key signs', async ({
  page,
  context,
  browserName,
}, testInfo) => {
  testInfo.skip(
    browserName !== 'chromium',
    'Playwright crashes a renderer only through Chromium’s DevTools protocol (Page.crash)',
  );
  await startFirstGenerate(page);
  const crashed = page.waitForEvent('crash');
  const cdp = await context.newCDPSession(page);
  void cdp.send('Page.crash').catch(() => {}); // never answers: the renderer is gone
  await crashed;
  await expectOldStateOrNew(context);
});
