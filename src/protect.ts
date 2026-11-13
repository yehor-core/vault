import { equalBytes, type Bytes } from './bytes.ts';
import type { Connection } from './connection.ts';
import { VaultError } from './errors.ts';
import { keyType } from './key-types.ts';
import { protectWrappingKey, type UnlockSecret } from './protection.ts';
import { FORMAT_VERSION, parseKeyRecord, type HeaderRecord, type KeyRecord } from './records.ts';
import { MAX_ATTEMPTS, untilUnchanged } from './retry.ts';
import { generateWrappingKey } from './seal.ts';
import {
  KEYS_STORE,
  listAllKeyRecords,
  listAllKeys,
  META_STORE,
  putHeader,
  putKeyRecord,
  readHeader,
} from './storage.ts';
import type { Unlock } from './unlock.ts';

/**
 * Turns protection on, once the unlock credential's secret is in hand: a fresh wrapping key pair (D-04), every
 * sealed key re-sealed to it, its private half wrapped under the secret (D-81), all written in one transaction
 * that re-checks the header and the set of key records it was prepared against (D-44). When another context wrote
 * in between, only this crypto is redone, against the vault as it is then, with the secret kept in memory: no new
 * prompt (D-82). `unlock` then holds the key (D-83).
 */
export async function protectVault(connection: Connection, unlock: Unlock, secret: UnlockSecret): Promise<void> {
  const written = await untilUnchanged(MAX_ATTEMPTS, () => tryProtect(connection, unlock, secret));
  if (!written) throw new VaultError('unavailable', 'The vault kept changing during protect');
  unlock.hold(written.wrappingPublicKey, written.privateKey);
}

/**
 * One attempt: read, re-seal, write. The protected header's wrapping public key and its private key, unwrapped, once
 * written; undefined if the vault changed since it was read; `protected` if it is protected by then.
 */
async function tryProtect(
  connection: Connection,
  unlock: Unlock,
  secret: UnlockSecret,
): Promise<{ wrappingPublicKey: Bytes; privateKey: CryptoKey } | undefined> {
  const read = await connection.transact([META_STORE, KEYS_STORE], 'readonly', async (tx) => {
    const header = await readHeader(tx);
    const records = await listAllKeyRecords(tx);
    return { header, ...records };
  });
  if (read.header && read.header.protection.kind !== 'none') throw protectedError();
  const records = await Promise.all(read.values.map(parseKeyRecord));

  const wrapping = await generateWrappingKey(true);
  const resealed = await resealAll(records, read.header, unlock, wrapping.publicKey);
  const protectedKey = await protectWrappingKey(secret, FORMAT_VERSION, wrapping.publicKey, wrapping.privateKey);
  const header: HeaderRecord = {
    v: FORMAT_VERSION,
    wrappingPublicKey: wrapping.publicKey,
    protection: protectedKey.protection,
  };

  const outcome = await connection.transact([META_STORE, KEYS_STORE], 'readwrite', async (tx) => {
    const current = await readHeader(tx);
    if (current && current.protection.kind !== 'none') return 'protected';
    const keys = await listAllKeys(tx);
    if (!sameHeader(current, read.header) || !sameKeys(keys, read.keys)) return 'changed';
    putHeader(tx, header);
    for (const record of resealed) putKeyRecord(tx, record);
    return 'written';
  });
  if (outcome === 'protected') throw protectedError();
  if (outcome === 'changed') return undefined;
  return { wrappingPublicKey: header.wrappingPublicKey, privateKey: protectedKey.privateKey };
}

/** The records whose part depends on the header, sealed to `wrappingPublicKey`; the others stay as they are. */
async function resealAll(
  records: KeyRecord[],
  header: HeaderRecord | undefined,
  unlock: Unlock,
  wrappingPublicKey: Bytes,
): Promise<KeyRecord[]> {
  if (!header) return []; // no header, no key records: readHeader checked
  const resealed = await Promise.all(
    records.map(async (record) => {
      const stored = { record, header, wrappingPrivateKey: () => unlock.wrappingPrivateKey(header) };
      const part = await keyType(record.type).reseal(stored, wrappingPublicKey);
      return part === undefined ? undefined : { ...record, ...part };
    }),
  );
  return resealed.filter((record) => record !== undefined);
}

function sameHeader(a: HeaderRecord | undefined, b: HeaderRecord | undefined): boolean {
  return a === undefined || b === undefined ? a === b : equalBytes(a.wrappingPublicKey, b.wrappingPublicKey);
}

function sameKeys(a: IDBValidKey[], b: IDBValidKey[]): boolean {
  return a.length === b.length && a.every((key, i) => indexedDB.cmp(key, b[i]) === 0);
}

function protectedError(): VaultError {
  return new VaultError('protected', 'The vault is protected already');
}
