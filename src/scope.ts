import { equalBytes, type Bytes } from './bytes.ts';
import type { Connection } from './connection.ts';
import { VaultError } from './errors.ts';
import { isKeyTypeName, keyTypes, type GeneratedKey, type KeyTypeName } from './key-types.ts';
import {
  corrupted,
  FORMAT_VERSION,
  isLabel,
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
  deleteKeyRecord,
  getKeyRecord,
  KEYS_STORE,
  listKeyRecords,
  META_STORE,
  readHeader,
} from './storage.ts';

const MAX_ATTEMPTS = 3;

/**
 * Public information about a key; readable without unlocking. One member per key type, so narrowing on
 * `type` narrows what `sign` returns. The public key's format is defined by its key type (src/<type>.ts).
 */
export type KeyInfo<T extends KeyTypeName = KeyTypeName> = {
  [U in T]: {
    readonly id: string;
    readonly scope: string;
    readonly type: U;
    readonly publicKey: Uint8Array<ArrayBuffer>;
    readonly createdAt: Date;
    /** As given to `generate`; absent if none was. */
    readonly label?: string;
  };
}[T];

/** One member per key type; the bytes' format is defined by the key type. Verifiable with the public key alone. */
export type Signature<T extends KeyTypeName = KeyTypeName> = {
  [U in T]: { readonly type: U; readonly bytes: Uint8Array<ArrayBuffer> };
}[T];

export interface GenerateOptions {
  /** A well-formed string of 1 to 256 UTF-16 code units. Stored with the key, readable without unlocking, immutable. */
  readonly label?: string;
}

/**
 * The keys of one named scope. Scopes keep consumers' keys apart; they don't isolate code: anything that holds
 * the Vault, or runs in the origin, can open every scope. Get one with `vault.scope(name)`.
 */
export class Scope {
  readonly name: string;
  readonly #connection: Connection;

  /** @internal Use `vault.scope(name)`. */
  constructor(name: string, connection: Connection) {
    this.name = name;
    this.#connection = connection;
  }

  /** Generates a key inside the vault. Never prompts. */
  async generate<T extends KeyTypeName>(type: T, options: GenerateOptions = {}): Promise<KeyInfo<T>> {
    if (!isKeyTypeName(type)) throw new TypeError(`Unknown key type: ${String(type)}`);
    const { label } = options;
    if (label !== undefined && !isLabel(label)) throw new TypeError('A label is a well-formed string of 1 to 256 characters');
    // Once, before any IndexedDB access, and outside the retry: a type that prompts must prompt first, and once.
    const pair = await keyTypes[type].generate().catch((cause: unknown) => {
      throw new VaultError('unavailable', 'The browser failed to generate a key', { cause });
    });
    try {
      const fields = await this.#keyFields(type, pair.publicKey, label);
      const record = await untilUnchanged(MAX_ATTEMPTS, async () => {
        const { header, isNew } = await this.#headerForWrite();
        const record: KeyRecord = { ...fields, sealed: await sealTo(header, fields, pair) };
        return (await this.#commitKeyRecord(record, header, isNew)) ? record : undefined;
      });
      if (!record) throw new VaultError('unavailable', 'The vault kept changing during generate');
      return keyInfo(record) as KeyInfo<T>;
    } finally {
      pair.dispose();
    }
  }

  /** All keys of this scope, oldest first (keys created in the same millisecond: by id). Never prompts. */
  async list(): Promise<KeyInfo[]> {
    const values = await this.#connection.transact([META_STORE, KEYS_STORE], 'readonly', async (tx) => {
      await readHeader(tx); // rejects a malformed header and keys without one
      return listKeyRecords(tx, this.name);
    });
    const records = await Promise.all(values.map(parseKeyRecord));
    return records.sort((a, b) => a.createdAt - b.createdAt).map(keyInfo);
  }

  /** Signs `data` with `key`. The signature verifies under `key.publicKey`, without Vault. */
  async sign<K extends KeyInfo>(key: K, data: Uint8Array): Promise<Signature<K['type']>> {
    this.#assertOwnKey(key);
    // Checked, not coerced: new Uint8Array('hello') is empty, so a string would be signed as the empty message.
    if (!(data instanceof Uint8Array)) throw new TypeError('data must be a Uint8Array');
    const message: Bytes = new Uint8Array(data); // the caller may change `data` while we await
    const { header, record } = await this.#loadKey(key.id);
    // The stored id binds scope, type and public key, so a stored record of another type means an edited argument.
    if (record.type !== key.type) throw new TypeError(`Key ${key.id} is not of type ${String(key.type)}`);
    const signature = await signWithRecord(header, record, message);
    await assertSignatureMatches(record, signature, message);
    return { type: record.type, bytes: signature } as Signature<K['type']>;
  }

  /** Deletes `key`. Deleting a key that is already gone is a no-op. */
  async delete(key: KeyInfo): Promise<void> {
    this.#assertOwnKey(key);
    await this.#connection.transact([KEYS_STORE], 'readwrite', async (tx) => deleteKeyRecord(tx, this.name, key.id));
  }

  // A KeyInfo from another scope is a mix-up between consumers, not a missing key.
  #assertOwnKey(key: KeyInfo): void {
    if (typeof key !== 'object' || key === null || typeof key.id !== 'string') {
      throw new TypeError('key must be a KeyInfo returned by generate() or list()');
    }
    if (key.scope !== this.name) throw new TypeError(`Key ${key.id} belongs to scope ${String(key.scope)}, not ${this.name}`);
  }

  async #keyFields(type: KeyTypeName, publicKey: Bytes, label: string | undefined): Promise<KeyFields> {
    const id = await keyId(this.name, type, publicKey);
    const fields: KeyFields = { v: FORMAT_VERSION, scope: this.name, id, type, publicKey, createdAt: Date.now() };
    return label === undefined ? fields : { ...fields, label };
  }

  /** The header and the parsed record of key `id`, read in one transaction. */
  async #loadKey(id: string): Promise<{ header: HeaderRecord; record: KeyRecord }> {
    const { header, value } = await this.#connection.transact([META_STORE, KEYS_STORE], 'readonly', async (tx) => {
      const header = await readHeader(tx);
      const value = await getKeyRecord(tx, this.name, id);
      return { header, value };
    });
    if (value === undefined || !header) throw new VaultError('not-found', `No key ${id} in scope ${this.name}`);
    const record = await parseKeyRecord(value);
    return { header, record };
  }

  /**
   * The stored header, or a fresh one when the vault is empty. The vault is created by its first write,
   * in #commitKeyRecord; a concurrent first write elsewhere wins and we redo.
   */
  async #headerForWrite(): Promise<{ header: HeaderRecord; isNew: boolean }> {
    const stored = await this.#connection.transact([META_STORE, KEYS_STORE], 'readonly', readHeader);
    if (stored) return { header: stored, isNew: false };
    const created = await createHeader();
    return { header: created, isNew: true };
  }

  /**
   * Crypto is done; the transaction only checks that the header is still the one we sealed to, then
   * writes. False means the vault was wiped or its header replaced since we read it.
   */
  async #commitKeyRecord(record: KeyRecord, header: HeaderRecord, isNew: boolean): Promise<boolean> {
    return this.#connection.transact([META_STORE, KEYS_STORE], 'readwrite', async (tx) => {
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
}

/** Seals the key's private half to the header's wrapping public key, bound to the record's fields. */
async function sealTo(header: HeaderRecord, fields: KeyFields, pair: GeneratedKey) {
  return seal(header.wrappingPublicKey, keyAad(fields), pair.seal).catch((cause: unknown) => {
    // The only stored input is the wrapping public key; a fresh one always imports.
    throw cause instanceof DOMException && cause.name === 'DataError' ? corrupted('wrapping public key', cause) : cause;
  });
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

async function createHeader(): Promise<HeaderRecord> {
  const { publicKey, privateKey } = await generateWrappingKey();
  return { v: FORMAT_VERSION, wrappingPublicKey: publicKey, protection: { kind: 'none', privateKey } };
}

function keyInfo(record: KeyRecord): KeyInfo {
  const { id, scope, type, publicKey, createdAt, label } = record;
  const info = { id, scope, type, publicKey, createdAt: new Date(createdAt) };
  return label === undefined ? info : { ...info, label };
}
