import { equalBytes, type Bytes } from './bytes.ts';
import { openDatabase, request, transact, type Store } from './db.ts';
import { VaultError } from './errors.ts';
import { isKeyTypeName, keyTypes, type KeyTypeName } from './key-types.ts';
import {
  corrupted,
  FORMAT_VERSION,
  keyAad,
  keyId,
  parseHeader,
  parseKeyRecord,
  type HeaderRecord,
  type KeyFields,
  type KeyRecord,
} from './records.ts';
import { generateWrappingKey, seal, unseal } from './seal.ts';

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
    const keyType = keyTypes[type];
    for (let attempt = 0; attempt < MAX_ATTEMPTS; attempt++) {
      const stored = await this.#transact(['meta', 'keys'], 'readonly', readHeader);
      // The vault is created by its first write; a concurrent first write elsewhere wins and we redo.
      const created = stored ? undefined : await createHeader();
      const header = (stored ?? created)!;

      const pair = await keyType.generate().catch((cause: unknown) => {
        throw new VaultError('unavailable', 'The browser failed to generate a key', { cause });
      });
      const fields: KeyFields = {
        v: FORMAT_VERSION,
        scope: SCOPE,
        id: await keyId(SCOPE, type, pair.publicKey),
        type,
        publicKey: pair.publicKey,
        createdAt: Date.now(),
      };
      const record: KeyRecord = { ...fields, sealed: await this.#seal(header, fields, pair.seal) };

      // Crypto is done; the transaction only checks that the header is still the one we sealed to.
      const written = await this.#transact(['meta', 'keys'], 'readwrite', async (tx) => {
        const current = await readHeader(tx);
        if (!current) {
          if (!created) return false; // wiped since we read it
          tx.objectStore('meta').add(created, 'header');
        } else if (!equalBytes(current.wrappingPublicKey, header.wrappingPublicKey)) {
          return false; // replaced since we read it
        }
        tx.objectStore('keys').add(record);
        return true;
      });
      if (written) return keyInfo(record);
    }
    throw new VaultError('unavailable', 'The vault kept changing during generate');
  }

  /** All keys, oldest first (keys created in the same millisecond: by id). Never prompts. */
  async list(): Promise<KeyInfo[]> {
    const values = await this.#transact(['meta', 'keys'], 'readonly', async (tx) => {
      await readHeader(tx);
      return request(tx.objectStore('keys').getAll(IDBKeyRange.bound([SCOPE], [SCOPE, []])));
    });
    const records = await Promise.all(values.map(parseKeyRecord));
    return records.sort((a, b) => a.createdAt - b.createdAt).map(keyInfo);
  }

  /** Signs `data` with key `id`. The signature verifies under the key's public key, without Vault. */
  async sign(id: string, data: Uint8Array): Promise<Signature> {
    const message: Bytes = new Uint8Array(data); // the caller may change `data` while we await
    const [header, value] = await this.#transact(['meta', 'keys'], 'readonly', async (tx) => [
      await readHeader(tx),
      await request(tx.objectStore('keys').get([SCOPE, id])),
    ]);
    if (value === undefined || !header) throw new VaultError('not-found', `No key ${id}`);
    const record = await parseKeyRecord(value);

    const keyType = keyTypes[record.type];
    let signature: Bytes;
    try {
      const cipher = await unseal(header.protection.privateKey, header.wrappingPublicKey, record.sealed, keyAad(record));
      signature = await keyType.sign(record.sealed.ciphertext, cipher, message);
    } catch (cause) {
      throw corrupted(`key ${id} does not decrypt`, cause);
    }
    // Anyone can seal a key of their own to the public wrapping key; it decrypts fine, and only this check catches it.
    const valid = await keyType.verify(record.publicKey, signature, message).catch(() => false);
    if (!valid) throw corrupted(`key ${id} does not match its public key`);
    return { type: record.type, bytes: signature };
  }

  /** Deletes key `id`. Deleting a missing key is a no-op. */
  async delete(id: string): Promise<void> {
    await this.#transact(['keys'], 'readwrite', async (tx) => {
      tx.objectStore('keys').delete([SCOPE, id]);
    });
  }

  /** Deletes every key and the vault itself, atomically. The vault is then empty, as if never used. */
  async wipe(): Promise<void> {
    await this.#transact(['meta', 'keys'], 'readwrite', async (tx) => {
      tx.objectStore('meta').clear();
      tx.objectStore('keys').clear();
    });
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

  async #seal(header: HeaderRecord, fields: KeyFields, encrypt: Parameters<typeof seal>[2]) {
    return seal(header.wrappingPublicKey, keyAad(fields), encrypt).catch((cause: unknown) => {
      // The only stored input is the wrapping public key; a fresh one always imports.
      throw cause instanceof DOMException && cause.name === 'DataError' ? corrupted('wrapping public key', cause) : cause;
    });
  }
}

/**
 * The header, or undefined for an empty vault. Key records without a header mean the header was
 * deleted, never that the vault is new: no legitimate write leaves one without the other.
 */
async function readHeader(tx: IDBTransaction): Promise<HeaderRecord | undefined> {
  const meta = tx.objectStore('meta');
  // count, not get: a header stored as `undefined` is present and malformed, not absent.
  const [present, value] = await Promise.all([request(meta.count('header')), request(meta.get('header'))]);
  if (present) return parseHeader(value);
  if (await request(tx.objectStore('keys').count())) throw corrupted('key records exist without a vault header');
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
