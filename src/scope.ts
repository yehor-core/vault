import { equalBytes, type Bytes } from './bytes.ts';
import type { Changes } from './changes.ts';
import type { Connection } from './connection.ts';
import { VaultError } from './errors.ts';
import { isKeyTypeName, keyType, type KeyTypeName, type NewKey, type SignatureOf } from './key-types.ts';
import {
  FORMAT_VERSION,
  isLabel,
  keyId,
  MAX_LABEL_LENGTH,
  parseKeyRecord,
  type HeaderRecord,
  type KeyFields,
  type KeyRecord,
} from './records.ts';
import { generateWrappingKey } from './seal.ts';
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

/** Public information about a key; readable without unlocking. One member per key type. */
export type KeyInfo = {
  [T in KeyTypeName]: {
    readonly id: string;
    /** The name of the scope the key belongs to. */
    readonly scope: string;
    readonly type: T;
    /** In the encoding of its key type (DESIGN.md §7.5). */
    readonly publicKey: Uint8Array<ArrayBuffer>;
    readonly createdAt: Date;
    /** Given at generate, never changed; absent when none was given. */
    readonly label?: string;
  };
}[KeyTypeName];

export interface GenerateOptions {
  /** A well-formed string of 1 to MAX_LABEL_LENGTH (256) UTF-16 code units. Need not be unique; can't be changed later. */
  readonly label?: string;
}

/** One member per key type, in that type's signature encoding (DESIGN.md §7.5). */
export type Signature<T extends KeyTypeName = KeyTypeName> = {
  [U in T]: Simplify<{ readonly type: U } & SignatureOf<U>>;
}[T];

/** One object type instead of an intersection, so editors show a signature's fields. */
type Simplify<T> = { [K in keyof T]: T[K] };

/**
 * A named group of keys in a vault, from `vault.scope(name)`. It holds nothing but its name and has no
 * way back to its vault, so code handed only a Scope can't wipe the vault or open another scope.
 */
export class Scope {
  readonly #name: string;
  readonly #connection: Connection;
  readonly #changes: Changes;

  /** @internal Use `vault.scope(name)`. */
  constructor(name: string, connection: Connection, changes: Changes) {
    this.#name = name;
    this.#connection = connection;
    this.#changes = changes;
  }

  // A getter, not a field: a writable name would let code holding this Scope retarget it at another scope.
  get name(): string {
    return this.#name;
  }

  /** Generates a key inside the vault. Never prompts. */
  async generate(type: KeyTypeName, options: GenerateOptions = {}): Promise<KeyInfo> {
    if (!isKeyTypeName(type)) throw new TypeError(`Unknown key type: ${String(type)}`);
    if (typeof options !== 'object' || options === null) throw new TypeError('options must be an object');
    const { label } = options; // read once: a getter can't change between the check and the write
    if (label !== undefined && !isLabel(label))
      throw new TypeError(`A label is a well-formed string of 1 to ${MAX_LABEL_LENGTH} UTF-16 code units`);
    const record = await untilUnchanged(MAX_ATTEMPTS, async () => {
      const { header, isNew } = await this.#headerForWrite();
      const generated = await generateKey(type);
      try {
        const record = await this.#prepareKeyRecord(type, label, header, generated);
        const written = await this.#commitKeyRecord(record, header, isNew);
        return written ? record : undefined;
      } finally {
        generated.erase(); // stored, or abandoned: a retry generates a fresh key
      }
    });
    if (!record) throw new VaultError('unavailable', 'The vault kept changing during generate');
    this.#changes.notify(); // once, after the commit that stored the key: a redone attempt wrote nothing
    return keyInfo(record);
  }

  /** The keys of this scope, oldest first (keys created in the same millisecond: by id). Never prompts. */
  async list(): Promise<KeyInfo[]> {
    const values = await this.#connection.transact([META_STORE, KEYS_STORE], 'readonly', async (tx) => {
      await readHeader(tx); // rejects a malformed header and keys without one
      return listKeyRecords(tx, this.#name);
    });
    const records = await Promise.all(values.map(parseKeyRecord));
    return records.sort((a, b) => a.createdAt - b.createdAt).map(keyInfo);
  }

  /**
   * Signs `data` with `key`, as returned by `generate` or `list` (a structured clone will do). Only its id,
   * scope and type are read; the key itself is read from storage. The signature verifies under its public key.
   */
  async sign<K extends KeyInfo>(key: K, data: Uint8Array): Promise<Signature<K['type']>> {
    const { id, type } = this.#readKeyRef(key);
    // Checked, not coerced: new Uint8Array('hello') is empty, so a string would be signed as the empty message.
    if (!(data instanceof Uint8Array)) throw new TypeError('data must be a Uint8Array');
    const message: Bytes = new Uint8Array(data); // the caller may change `data` while we await
    const { header, record } = await this.#loadKey(id);
    if (record.type !== type) throw typeMismatch(id, record.type);
    const signature = await keyType(record.type).sign(record, header, message);
    // `as`: the runtime check above makes record.type K['type'], and its key type returned its own member.
    return { type: record.type, ...signature } as Signature<K['type']>;
  }

  /** Deletes `key`, read like `sign` reads it. Deleting a missing key is a no-op. */
  async delete(key: KeyInfo): Promise<void> {
    const { id, type } = this.#readKeyRef(key);
    const otherType = await this.#connection.transact([KEYS_STORE], 'readwrite', async (tx) => {
      const stored = storedKeyType(await getKeyRecord(tx, this.#name, id));
      if (stored !== undefined && stored !== type) return stored;
      deleteKeyRecord(tx, this.#name, id);
      return undefined;
    });
    if (otherType !== undefined) throw typeMismatch(id, otherType);
    this.#changes.notify();
  }

  /** The id and type of a `sign` or `delete` argument, which must name a key of this scope. */
  #readKeyRef(key: unknown): { id: string; type: unknown } {
    // Destructuring throws TypeError for undefined and null. Read once: a getter can't change between checks.
    // `as`: each field is read as unknown and checked below.
    const { id, scope, type } = key as Record<string, unknown>;
    if (typeof id !== 'string') throw new TypeError('key.id must be a string');
    if (scope !== this.#name) throw new TypeError(`Key ${id} is not of scope ${this.#name}`);
    return { id, type };
  }

  /** The header and the parsed record of key `id`, read in one transaction. */
  async #loadKey(id: string): Promise<{ header: HeaderRecord; record: KeyRecord }> {
    const { header, value } = await this.#connection.transact([META_STORE, KEYS_STORE], 'readonly', async (tx) => {
      const header = await readHeader(tx);
      const value = await getKeyRecord(tx, this.#name, id);
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
    const stored = await this.#connection.transact([META_STORE, KEYS_STORE], 'readonly', readHeader);
    if (stored) return { header: stored, isNew: false };
    const created = await createHeader();
    return { header: created, isNew: true };
  }

  /** The crypto after generation: derive the id, then the key type's part. Outside any transaction: crypto would end it. */
  async #prepareKeyRecord(
    type: KeyTypeName,
    label: string | undefined,
    header: HeaderRecord,
    generated: NewKey,
  ): Promise<KeyRecord> {
    const scope = this.#name;
    const id = await keyId(scope, type, generated.publicKey);
    const fields: KeyFields = {
      v: FORMAT_VERSION,
      scope,
      id,
      type,
      publicKey: generated.publicKey,
      createdAt: Date.now(),
      ...(label !== undefined && { label }), // never `label: undefined`: it would be stored
    };
    const part = await generated.part(fields, header);
    return { ...fields, ...part };
  }

  /**
   * Crypto is done; the transaction only checks that the header is still the one we sealed to, then
   * writes. False means the vault was wiped or deleted, or its header replaced, since we read it.
   */
  async #commitKeyRecord(record: KeyRecord, header: HeaderRecord, isNew: boolean): Promise<boolean> {
    return this.#connection.transact([META_STORE, KEYS_STORE], 'readwrite', async (tx) => {
      const current = await readHeader(tx);
      if (!current) {
        if (!isNew) return false; // wiped or deleted since we read it
        addHeader(tx, header);
      } else if (!equalBytes(current.wrappingPublicKey, header.wrappingPublicKey)) {
        return false; // replaced since we read it (or another first write won)
      }
      addKeyRecord(tx, record);
      return true;
    });
  }
}

async function generateKey(type: KeyTypeName): Promise<NewKey> {
  return keyType(type)
    .generate()
    .catch((cause: unknown) => {
      throw new VaultError('unavailable', 'The browser failed to generate a key', { cause });
    });
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
  const { id, scope, type, publicKey, label } = record;
  return { id, scope, type, publicKey, createdAt: new Date(record.createdAt), ...(label !== undefined && { label }) };
}

/**
 * The registered key type a stored record names, unparsed: parsing needs crypto, which would end the
 * transaction. Only compared; a record with no such type is deleted like any other.
 */
function storedKeyType(value: unknown): KeyTypeName | undefined {
  const type = typeof value === 'object' && value !== null && 'type' in value ? value.type : undefined;
  return isKeyTypeName(type) ? type : undefined;
}

function typeMismatch(id: string, stored: KeyTypeName): TypeError {
  return new TypeError(`Key ${id} is of type ${stored}, not the type given`);
}
