import { equalBytes, type Bytes } from './bytes.ts';
import { openDatabase, transact, type Store } from './db.ts';
import { VaultError } from './errors.ts';
import { isKeyTypeName, keyTypes, type KeyTypeName } from './key-types.ts';
import {
  corrupted,
  FORMAT_VERSION,
  keyAad,
  keyId,
  parseKeyRecord,
  type HeaderRecord,
  type KeyFields,
  type KeyRecord,
} from './records.ts';
import { generateWrappingKey, seal, unseal } from './seal.ts';
import {
  addHeader,
  addKeyRecord,
  clearAll,
  deleteKeyRecord,
  getKeyRecord,
  KEYS_STORE,
  listKeyRecords,
  META_STORE,
  readHeader,
} from './storage.ts';

const SCOPE = 'default';
const MAX_ATTEMPTS = 3;

/** Public information about a key; readable without unlocking. */
export interface KeyInfo {
  readonly id: string;
  readonly type: KeyTypeName;
  /** ed25519: the 32-byte RFC 8032 public key. */
  readonly publicKey: Uint8Array<ArrayBuffer>;
  readonly createdAt: Date;
}

/** One member per key type. ed25519: a 64-byte RFC 8032 signature over the exact bytes passed to `sign`. */
export type Signature = { [T in KeyTypeName]: { readonly type: T; readonly bytes: Uint8Array<ArrayBuffer> } }[KeyTypeName];

export interface OpenOptions {
  /** IndexedDB database name. Default: `vault`. */
  readonly name?: string;
}

/** A browser-native private-key store. Private keys never leave it; only signatures do. */
export class Vault {
  readonly #name: string;
  #db: Promise<IDBDatabase> | undefined;
  #closed = false;

  private constructor(name: string) {
    this.#name = name;
  }

  static async open(options: OpenOptions = {}): Promise<Vault> {
    const vault = new Vault(options.name ?? 'vault');
    await vault.#connection();
    return vault;
  }

  /** Generates a key inside the vault. Never prompts. */
  async generate(type: KeyTypeName): Promise<KeyInfo> {
    if (!isKeyTypeName(type)) throw new TypeError(`Unknown key type: ${String(type)}`);
    const record = await untilUnchanged(MAX_ATTEMPTS, async () => {
      const { header, isNew } = await this.#headerForWrite();
      const record = await this.#prepareKeyRecord(type, header);
      const written = await this.#commitKeyRecord(record, header, isNew);
      return written ? record : undefined;
    });
    if (!record) throw new VaultError('unavailable', 'The vault kept changing during generate');
    return keyInfo(record);
  }

  /** All keys, oldest first (keys created in the same millisecond: by id). Never prompts. */
  async list(): Promise<KeyInfo[]> {
    const values = await this.#transact([META_STORE, KEYS_STORE], 'readonly', async (tx) => {
      await readHeader(tx); // rejects a malformed header and keys without one
      return listKeyRecords(tx, SCOPE);
    });
    const records = await Promise.all(values.map(parseKeyRecord));
    return records.sort((a, b) => a.createdAt - b.createdAt).map(keyInfo);
  }

  /** Signs `data` with key `id`. The signature verifies under the key's public key, without Vault. */
  async sign(id: string, data: Uint8Array): Promise<Signature> {
    const message: Bytes = new Uint8Array(data); // the caller may change `data` while we await
    const { header, record } = await this.#loadKey(id);
    const signature = await signWithRecord(header, record, message);
    await assertSignatureMatches(record, signature, message);
    return { type: record.type, bytes: signature };
  }

  /** Deletes key `id`. Deleting a missing key is a no-op. */
  async delete(id: string): Promise<void> {
    await this.#transact([KEYS_STORE], 'readwrite', async (tx) => deleteKeyRecord(tx, SCOPE, id));
  }

  /** Deletes every key and the vault itself, atomically. The vault is then empty, as if never used. */
  async wipe(): Promise<void> {
    await this.#transact([META_STORE, KEYS_STORE], 'readwrite', async (tx) => clearAll(tx));
  }

  /** Releases the database connection. Every later call, and every call still in flight, throws. */
  close(): void {
    this.#closed = true;
    this.#db?.then((db) => db.close(), () => {});
    this.#db = undefined;
  }

  // The connection is taken right before each transaction, so a call in flight across close() sees the
  // documented InvalidStateError, and one across a versionchange reopens and gets 'incompatible'.
  async #transact<T>(stores: Store[], mode: IDBTransactionMode, body: (tx: IDBTransaction) => Promise<T>) {
    const db = await this.#connection();
    if (this.#closed) throw closedError(); // closed while we awaited; from here to db.transaction is synchronous
    return transact(db, stores, mode, body);
  }

  #connection(): Promise<IDBDatabase> {
    if (this.#closed) return Promise.reject(closedError());
    if (!this.#db) {
      const pending = openDatabase(this.#name, () => {
        if (this.#db === pending) this.#db = undefined;
      });
      this.#db = pending;
      pending.catch(() => {
        if (this.#db === pending) this.#db = undefined;
      });
    }
    return this.#db;
  }

  /** The header and the parsed record of key `id`, read in one transaction. */
  async #loadKey(id: string): Promise<{ header: HeaderRecord; record: KeyRecord }> {
    const { header, value } = await this.#transact([META_STORE, KEYS_STORE], 'readonly', async (tx) => {
      const header = await readHeader(tx);
      const value = await getKeyRecord(tx, SCOPE, id);
      return { header, value };
    });
    if (value === undefined || !header) throw new VaultError('not-found', `No key ${id}`);
    const record = await parseKeyRecord(value);
    return { header, record };
  }

  /**
   * The stored header, or a fresh one when the vault is empty. The vault is created by its first write,
   * in #commitKeyRecord; a concurrent first write elsewhere wins and we redo.
   */
  async #headerForWrite(): Promise<{ header: HeaderRecord; isNew: boolean }> {
    const stored = await this.#transact([META_STORE, KEYS_STORE], 'readonly', readHeader);
    if (stored) return { header: stored, isNew: false };
    const created = await createHeader();
    return { header: created, isNew: true };
  }

  /** All crypto for a new key: generate, derive the id, seal. Outside any transaction: crypto would end it. */
  async #prepareKeyRecord(type: KeyTypeName, header: HeaderRecord): Promise<KeyRecord> {
    const pair = await keyTypes[type].generate().catch((cause: unknown) => {
      throw new VaultError('unavailable', 'The browser failed to generate a key', { cause });
    });
    const id = await keyId(SCOPE, type, pair.publicKey);
    const fields: KeyFields = { v: FORMAT_VERSION, scope: SCOPE, id, type, publicKey: pair.publicKey, createdAt: Date.now() };
    const sealed = await this.#seal(header, fields, pair.seal);
    return { ...fields, sealed };
  }

  /**
   * Crypto is done; the transaction only checks that the header is still the one we sealed to, then
   * writes. False means the vault was wiped or its header replaced since we read it.
   */
  async #commitKeyRecord(record: KeyRecord, header: HeaderRecord, isNew: boolean): Promise<boolean> {
    return this.#transact([META_STORE, KEYS_STORE], 'readwrite', async (tx) => {
      const current = await readHeader(tx);
      if (!current) {
        if (!isNew) return false; // wiped since we read it
        addHeader(tx, header);
      } else if (!equalBytes(current.wrappingPublicKey, header.wrappingPublicKey)) {
        return false; // replaced since we read it (or another first write won)
      }
      addKeyRecord(tx, record);
      return true;
    });
  }

  async #seal(header: HeaderRecord, fields: KeyFields, encrypt: Parameters<typeof seal>[2]) {
    return seal(header.wrappingPublicKey, keyAad(fields), encrypt).catch((cause: unknown) => {
      // The only stored input is the wrapping public key; a fresh one always imports.
      throw cause instanceof DOMException && cause.name === 'DataError' ? corrupted('wrapping public key', cause) : cause;
    });
  }
}

/** Decrypts the key and signs; any failure means the stored key is not what Vault sealed. */
async function signWithRecord(header: HeaderRecord, record: KeyRecord, message: Bytes): Promise<Bytes> {
  try {
    const cipher = await unseal(header.protection.privateKey, header.wrappingPublicKey, record.sealed, keyAad(record));
    return await keyTypes[record.type].sign(record.sealed.ciphertext, cipher, message); // await: so catch sees it
  } catch (cause) {
    throw corrupted(`key ${record.id} does not decrypt`, cause);
  }
}

// Anyone can seal a key of their own to the public wrapping key; it decrypts fine, and only this check catches it.
async function assertSignatureMatches(record: KeyRecord, signature: Bytes, message: Bytes): Promise<void> {
  const valid = await keyTypes[record.type].verify(record.publicKey, signature, message).catch(() => false);
  if (!valid) throw corrupted(`key ${record.id} does not match its public key`);
}

/** Optimistic write: runs `attempt` up to `times` times until it returns a value (undefined = vault changed). */
async function untilUnchanged<T>(times: number, attempt: () => Promise<T | undefined>): Promise<T | undefined> {
  for (let i = 0; i < times; i++) {
    const result = await attempt();
    if (result !== undefined) return result;
  }
  return undefined;
}

function closedError(): DOMException {
  return new DOMException('The vault is closed', 'InvalidStateError');
}

async function createHeader(): Promise<HeaderRecord> {
  const { publicKey, privateKey } = await generateWrappingKey();
  return { v: FORMAT_VERSION, wrappingPublicKey: publicKey, protection: { kind: 'none', privateKey } };
}

function keyInfo(record: KeyRecord): KeyInfo {
  return { id: record.id, type: record.type, publicKey: record.publicKey, createdAt: new Date(record.createdAt) };
}
