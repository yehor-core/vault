import { afterEach, describe, expect, expectTypeOf, test, vi, type Mock } from 'vitest';
import type { Scope, Vault } from '../../src/index.ts';
import { keyTypes } from '../../src/key-types.ts';
import { cleanup, expectVaultError, holdGenerate, keyRef, keyTypeCases, openContexts, openVault } from './helpers.ts';

// Change notifications (D-46): two Vault.open() of one database in one page stand for two contexts, and
// BroadcastChannel delivers between them as it does between tabs.

afterEach(async () => {
  vi.restoreAllMocks();
  await cleanup();
});

/**
 * `listener` has been called exactly `times` times, each with no argument, and stays so: delivery to another
 * context is a task of its own, so a call that should not come is waited for a little.
 */
async function expectCalls(listener: Mock, times: number): Promise<void> {
  await vi.waitFor(() => expect(listener).toHaveBeenCalledTimes(times));
  await new Promise((resolve) => setTimeout(resolve, 50));
  expect(listener).toHaveBeenCalledTimes(times);
  for (const args of listener.mock.calls) expect(args).toEqual([]);
}

describe.each(keyTypeCases)('$type', ({ type }) => {
  test('generate, delete and wipe each call the listener in the other context and in its own, also when nothing changed', async () => {
    const [a, b] = await openContexts();
    const [inA, inB] = [vi.fn(), vi.fn()];
    a.vault.onChange(inA);
    b.vault.onChange(inB);

    const key = await a.scope.generate(type);
    await expectCalls(inA, 1);
    await expectCalls(inB, 1);
    await b.scope.delete(key);
    await expectCalls(inA, 2);
    await expectCalls(inB, 2);
    await a.scope.delete(key); // already deleted: nothing changed
    await expectCalls(inA, 3);
    await expectCalls(inB, 3);
    await a.scope.generate(type);
    await b.vault.wipe();
    await expectCalls(inA, 5);
    await expectCalls(inB, 5);
  });

  test('a write that aborts or fails calls no listener', async () => {
    const [a, b] = await openContexts();
    // The same key pair twice gives the same id: the second add aborts the transaction at commit.
    const pair = await keyTypes[type].generate();
    vi.spyOn(keyTypes[type], 'generate').mockResolvedValue(pair);
    const [inA, inB] = [vi.fn(), vi.fn()];
    a.vault.onChange(inA);
    b.vault.onChange(inB);
    const key = await a.scope.generate(type);
    await expectCalls(inB, 1); // delivered: a later call is the failed writes' or the final wipe's
    const clear = IDBObjectStore.prototype.clear;
    const wipeAborts = vi.spyOn(IDBObjectStore.prototype, 'clear').mockImplementation(function (this: IDBObjectStore) {
      const request = clear.call(this);
      if (this.name === 'keys') this.transaction.abort();
      return request;
    });

    await expectVaultError(a.scope.generate(type), 'unavailable');
    await expectVaultError(a.vault.wipe(), 'unavailable');
    const otherType = keyTypeCases.find((other) => other.type !== type)?.type ?? type;
    await expect(a.scope.delete(keyRef(a.scope, key.id, otherType))).rejects.toThrow(TypeError);
    wipeAborts.mockRestore();
    await a.vault.wipe(); // the next notification either context gets

    await expectCalls(inA, 2);
    await expectCalls(inB, 2);
  });

  test('a generate that redoes, after a wipe in the other context, notifies once, after its final commit', async () => {
    const [a, b] = await openContexts();
    const [inA, inB] = [vi.fn(), vi.fn()];
    a.vault.onChange(inA);
    b.vault.onChange(inB);
    await a.scope.generate(type);
    await expectCalls(inB, 1);
    const held = holdGenerate(type);

    const pending = a.scope.generate(type);
    await held.reached;
    await b.vault.wipe();
    held.release();
    await pending; // its first attempt fails the header check; the redo commits

    await expectCalls(inA, 3);
    await expectCalls(inB, 3);
  });
});

describe('change notifications', () => {
  test('a wipe calls the listener in the other context and in its own, also when the vault was empty', async () => {
    const [a, b] = await openContexts();
    const [inA, inB] = [vi.fn(), vi.fn()];
    a.vault.onChange(inA);
    b.vault.onChange(inB);

    await b.vault.wipe(); // the vault is empty: nothing changed

    await expectCalls(inA, 1);
    await expectCalls(inB, 1);
  });

  test('the stop function stops that listener only, and calling it twice is harmless', async () => {
    const [a, b] = await openContexts();
    const [stopped, kept] = [vi.fn(), vi.fn()];
    const stop = a.vault.onChange(stopped);
    a.vault.onChange(kept);
    a.vault.onChange(stopped); // the same function again: a registration of its own

    stop();
    stop();
    await b.vault.wipe();
    await a.vault.wipe();

    await expectCalls(kept, 2);
    await expectCalls(stopped, 2); // by its second registration only
  });

  test('close() stops every listener of that vault; onChange after close() throws InvalidStateError', async () => {
    const [a, b] = await openContexts();
    const [inA, inB] = [vi.fn(), vi.fn()];
    a.vault.onChange(inA);
    a.vault.onChange(inA);
    b.vault.onChange(inB);

    a.vault.close();
    await b.vault.wipe();

    await expectCalls(inB, 1);
    await expectCalls(inA, 0);
    expect(() => a.vault.onChange(inA)).toThrow(expect.objectContaining({ name: 'InvalidStateError' }));
  });

  test('a listener that closes its vault stops the listeners after it', async () => {
    const [a, b] = await openContexts();
    const after = vi.fn();
    b.vault.onChange(() => b.vault.close());
    b.vault.onChange(after);

    await a.vault.wipe();
    await vi.waitFor(() => expect(() => b.vault.onChange(after)).toThrow()); // b's listeners have run

    await expectCalls(after, 0);
  });

  test('a write that commits while its vault is closed resolves; its notification is lost', async () => {
    const [a, b] = await openContexts();
    const inB = vi.fn();
    b.vault.onChange(inB);
    const transaction = IDBDatabase.prototype.transaction;
    vi.spyOn(IDBDatabase.prototype, 'transaction').mockImplementationOnce(function (this: IDBDatabase, ...args) {
      const tx = transaction.apply(this, args);
      a.vault.close(); // after the transaction started: it still commits
      return tx;
    });

    await expect(a.vault.wipe()).resolves.toBeUndefined();

    await expectCalls(inB, 0);
  });

  test('a listener that throws does not stop the others, and its error goes to reportError', async () => {
    const [a, b] = await openContexts();
    const reported = vi.spyOn(globalThis, 'reportError').mockImplementation(() => {}); // observed, not thrown at the page
    const failure = new Error('listener failed');
    const [before, after] = [vi.fn(), vi.fn()];
    b.vault.onChange(before);
    b.vault.onChange(() => {
      throw failure;
    });
    b.vault.onChange(after);

    await a.vault.wipe(); // a notification from the other context
    await b.vault.wipe(); // and one of its own

    await expectCalls(before, 2);
    await expectCalls(after, 2);
    expect(reported.mock.calls).toEqual([[failure], [failure]]);
  });

  test('a message of another shape on the channel is ignored', async () => {
    const [a, b] = await openContexts();
    const reported = vi.spyOn(globalThis, 'reportError');
    const inB = vi.fn();
    b.vault.onChange(inB);
    const forger = new BroadcastChannel(a.name); // the channel is named after the database
    for (const junk of [undefined, null, 0, '', 'change', {}, { type: 'changed' }, ['changed'], new Uint8Array(1)])
      forger.postMessage(junk);
    forger.close();

    await a.vault.wipe(); // posted after the junk: the first notification b gets

    await expectCalls(inB, 1);
    expect(reported).not.toHaveBeenCalled();
  });

  test('vaults with different database names do not notify each other', async () => {
    const [a, b] = await openContexts();
    const other = await openVault();
    const [inB, inOther] = [vi.fn(), vi.fn()];
    b.vault.onChange(inB);
    other.vault.onChange(inOther);

    await a.vault.wipe();
    await other.scope.list(); // a read: no notification

    await expectCalls(inB, 1);
    await expectCalls(inOther, 0);
  });
});

test('onChange is on Vault only; its listener takes no argument, and it returns a function that stops it', async () => {
  const { vault } = await openVault();

  expectTypeOf<Vault['onChange']>().parameters.toEqualTypeOf<[listener: () => void]>();
  expectTypeOf<Vault['onChange']>().returns.toEqualTypeOf<() => void>();
  expectTypeOf<Scope>().not.toHaveProperty('onChange');
  // @ts-expect-error a listener takes no argument: a later one can be added without breaking it
  vault.onChange((changed: string) => void changed);
  expect(typeof vault.onChange(() => {})).toBe('function');
});
