import { equalBytes, type Bytes } from './bytes.ts';
import { openDatabase, request, transact } from './db.ts';
import { VaultError } from './errors.ts';
import { keyTypes, type KeyTypeName } from './key-types.ts';
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
  readonly publicKey: Uint8Array;
  readonly createdAt: Date;
}

/** ed25519: a 64-byte RFC 8032 signature over the exact bytes passed to `sign`. */
export type Signature = { readonly type: 'ed25519'; readonly bytes: Uint8Array };

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
    const keyType = keyTypes[type];
    for (let attempt = 0; attempt < MAX_ATTEMPTS; attempt++) {
      const db = await this.#connection();
      const stored = await transact(db, ['meta'], 'readonly', async (tx) =>
        parseHeader(await request(tx.objectStore('meta').get('header'))),
      );
      // The vault is created by its first write; a concurrent first write elsewhere wins and we redo.
      const created = stored ? undefined : await createHeader();
      const header = (stored ?? created)!;

      const pair = await keyType.generate();
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
      const written = await transact(db, ['meta', 'keys'], 'readwrite', async (tx) => {
        const meta = tx.objectStore('meta');
        const current = parseHeader(await request(meta.get('header')));
        if (!current) {
          if (!created) return false; // wiped since we read it
          meta.add(created, 'header');
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

  /** All keys, oldest first. Never prompts. */
  async list(): Promise<KeyInfo[]> {
    const db = await this.#connection();
    const values = await transact(db, ['keys'], 'readonly', (tx) =>
      request(tx.objectStore('keys').getAll(IDBKeyRange.bound([SCOPE], [SCOPE, []]))),
    );
    const records = await Promise.all(values.map(parseKeyRecord));
    return records.sort((a, b) => a.createdAt - b.createdAt).map(keyInfo);
  }

  /** Signs `data` with key `id`. The signature verifies under the key's public key, without Vault. */
  async sign(id: string, data: Uint8Array): Promise<Signature> {
    const message: Bytes = new Uint8Array(data); // the caller may change `data` while we await
    const db = await this.#connection();
    const [headerValue, keyValue] = await transact(db, ['meta', 'keys'], 'readonly', (tx) =>
      Promise.all([request(tx.objectStore('meta').get('header')), request(tx.objectStore('keys').get([SCOPE, id]))]),
    );
    if (keyValue === undefined) throw new VaultError('not-found', `No key ${id}`);
    const record = await parseKeyRecord(keyValue);
    const header = parseHeader(headerValue);
    if (!header) throw corrupted(`key ${id} exists without a vault header`);

    const keyType = keyTypes[record.type];
    let signature: Bytes;
    try {
      const cipher = await unseal(header.protection.privateKey, header.wrappingPublicKey, record.sealed, keyAad(record));
      signature = await keyType.sign(record.sealed.ciphertext, cipher, message);
    } catch (cause) {
      throw corrupted(`key ${id} does not decrypt`, cause);
    }
    // Anyone can seal a key of their own to the public wrapping key; it decrypts fine, and only this check catches it.
    if (!(await keyType.verify(record.publicKey, signature, message))) {
      throw corrupted(`key ${id} does not match its public key`);
    }
    return { type: record.type, bytes: signature };
  }

  /** Deletes key `id`. Deleting a missing key is a no-op. */
  async delete(id: string): Promise<void> {
    const db = await this.#connection();
    await transact(db, ['keys'], 'readwrite', async (tx) => {
      tx.objectStore('keys').delete([SCOPE, id]);
    });
  }

  /** Deletes every key and the vault itself, atomically. The vault is then empty, as if never used. */
  async wipe(): Promise<void> {
    const db = await this.#connection();
    await transact(db, ['meta', 'keys'], 'readwrite', async (tx) => {
      tx.objectStore('meta').clear();
      tx.objectStore('keys').clear();
    });
  }

  /** Releases the database connection. Every later call throws. */
  close(): void {
    this.#closed = true;
    this.#db?.then((db) => db.close(), () => {});
    this.#db = undefined;
  }

  #connection(): Promise<IDBDatabase> {
    if (this.#closed) return Promise.reject(new DOMException('The vault is closed', 'InvalidStateError'));
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

async function createHeader(): Promise<HeaderRecord> {
  const { publicKey, privateKey } = await generateWrappingKey();
  return { v: FORMAT_VERSION, wrappingPublicKey: publicKey, protection: { kind: 'none', privateKey } };
}

function keyInfo(record: KeyRecord): KeyInfo {
  return { id: record.id, type: record.type, publicKey: record.publicKey, createdAt: new Date(record.createdAt) };
}
