import { equalBytes, type Bytes } from './bytes.ts';
import type { Changes } from './changes.ts';
import type { Fields } from './readers.ts';
import type { Connection } from './connection.ts';
import { VaultError } from './errors.ts';
import {
  isKeyTypeName,
  keyType,
  type AddableKeyTypeName,
  type InfoOf,
  type KeyType,
  type KeyTypeName,
  type NewKey,
  type NewKeyRequest,
  type SignatureOf,
  type StoredKey,
} from './key-types.ts';
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
import type { Unlock } from './unlock.ts';
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
const ADD_FAILED = 'The browser failed to add the presented key';

/** Public information about a key; readable without unlocking. One member per key type. */
export type KeyInfo<T extends KeyTypeName = KeyTypeName> = {
  [U in T]: Simplify<
    {
      readonly id: string;
      /** The name of the scope the key belongs to. */
      readonly scope: string;
      readonly type: U;
      /** In the encoding of its key type (DESIGN.md §7.5). */
      readonly publicKey: Uint8Array<ArrayBuffer>;
      readonly createdAt: Date;
      /** Given at generate, never changed; absent when none was given. */
      readonly label?: string;
    } & InfoOf<U>
  >;
}[T];

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
  readonly #unlock: Unlock;

  /** @internal Use `vault.scope(name)`. */
  constructor(name: string, connection: Connection, changes: Changes, unlock: Unlock) {
    this.#name = name;
    this.#connection = connection;
    this.#changes = changes;
    this.#unlock = unlock;
  }

  // A getter, not a field: a writable name would let code holding this Scope retarget it at another scope.
  get name(): string {
    return this.#name;
  }

  /**
   * Generates a key. A key type whose private key Vault stores never prompts; one whose key stays in an
   * authenticator shows one prompt, started before any await, so it can be called from a user gesture.
   */
  async generate<T extends KeyTypeName>(type: T, options: GenerateOptions = {}): Promise<KeyInfo<T>> {
    if (!isKeyTypeName(type)) throw new TypeError(`Unknown key type: ${String(type)}`);
    const label = readLabelOption(options);
    const request: NewKeyRequest = { scope: this.#name, ...(label !== undefined && { label }) };
    const kind = keyType(type);
    const record = kind.prompts
      ? await this.#storeAsIs(type, label, generateKey(kind, request)) // generate is called here, before any await
      : await this.#storeUntilUnchanged(type, label, () => generateKey(kind, request));
    if (!record) throw new VaultError('unavailable', 'The vault kept changing during generate');
    this.#changes.notify(); // once, after the commit that stored the key: a redone attempt wrote nothing
    // `as`: the record was made for `type`, checked above to be a registered name; TypeScript can't follow T through it.
    return keyInfo(record) as KeyInfo<T>;
  }

  /**
   * Adds a key that exists outside this vault, which the user presents: on a fresh device, in another profile, or
   * after a wipe. Its prompt starts before any await. Returns the key with the id it has on every device; a key this
   * scope holds already is returned as stored, and `label` is then ignored. A key of another scope is `not-found`.
   */
  async add<T extends AddableKeyTypeName>(type: T, options: GenerateOptions = {}): Promise<KeyInfo<T>> {
    if (!isKeyTypeName(type)) throw new TypeError(`Unknown key type: ${String(type)}`);
    const kind = keyType(type);
    if (!kind.canAdd) throw new TypeError(`A key of type ${type} can't be added, only generated`);
    const label = readLabelOption(options);
    const pending = fromKeyType(kind.add(this.#name), ADD_FAILED); // the prompt, before any await
    const presented = await pending;
    const id = await keyId(this.#name, type, presented.identity);
    let record = await this.#findKey(id); // D-57: a key the scope holds takes no second prompt and no write
    if (!record) {
      const completed = fromKeyType(presented.complete(), ADD_FAILED);
      record = await this.#storeAsIs(type, label, completed);
      this.#changes.notify();
    }
    // `as`: the record is of `type`, checked above to be a registered name; TypeScript can't follow T through it.
    return keyInfo(record) as KeyInfo<T>;
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
    const { id, type, fields } = this.#readKeyRef(key);
    if (!isKeyTypeName(type)) throw new TypeError(`Unknown key type: ${String(type)}`);
    // Checked, not coerced: new Uint8Array('hello') is empty, so a string would be signed as the empty message.
    if (!(data instanceof Uint8Array)) throw new TypeError('data must be a Uint8Array');
    const message: Bytes = new Uint8Array(data); // the caller may change `data` while we await
    const load = async (): Promise<StoredKey> => {
      const stored = await this.#loadKey(id);
      if (stored.record.type !== type) throw typeMismatch(id, stored.record.type);
      return stored;
    };
    // Called before any await: a key type that prompts starts its prompt here.
    const signature = await keyType(type).sign(fields, message, load);
    // `type` last, so the member can't replace it. `load` checked that the stored key is of `type`, the argument's
    // K['type'], and that type returned its own member. `as`: TypeScript can't follow either through keyType().
    return { ...signature, type } as Signature<K['type']>;
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

  /** The id and type of a `sign` or `delete` argument, which must name a key of this scope, and the argument itself. */
  #readKeyRef(key: unknown): { id: string; type: unknown; fields: Fields } {
    // Destructuring throws TypeError for undefined and null. Read once: a getter can't change between checks.
    // `as`: each field is read as unknown and checked here or by the key type.
    const fields = key as Fields;
    const { id, scope, type } = fields;
    if (typeof id !== 'string') throw new TypeError('key.id must be a string');
    if (scope !== this.#name) throw new TypeError(`Key ${id} is not of scope ${this.#name}`);
    return { id, type, fields };
  }

  /** The parsed record of key `id`, or undefined if the vault has no such key. */
  async #findKey(id: string): Promise<KeyRecord | undefined> {
    const value = await this.#connection.transact([META_STORE, KEYS_STORE], 'readonly', async (tx) => {
      const header = await readHeader(tx); // rejects a malformed header and keys without one
      return header ? getKeyRecord(tx, this.#name, id) : undefined;
    });
    return value === undefined ? undefined : parseKeyRecord(value);
  }

  /** The header and the parsed record of key `id`, read in one transaction, and how this context opens it. */
  async #loadKey(id: string): Promise<StoredKey> {
    const { header, value } = await this.#connection.transact([META_STORE, KEYS_STORE], 'readonly', async (tx) => {
      const header = await readHeader(tx);
      const value = await getKeyRecord(tx, this.#name, id);
      return { header, value };
    });
    this.#unlock.dropIfStale(header); // also when the key is gone with the header
    if (value === undefined || !header) throw new VaultError('not-found', `No key ${id}`);
    const record = await parseKeyRecord(value);
    return { header, record, wrappingPrivateKey: () => this.#unlock.wrappingPrivateKey(header) };
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
   * A key whose record is sealed to the vault header: generated again, sealed to the header read anew, and written
   * only if that header is still the vault's, up to MAX_ATTEMPTS times.
   */
  async #storeUntilUnchanged(
    type: KeyTypeName,
    label: string | undefined,
    generate: () => Promise<NewKey>,
  ): Promise<KeyRecord | undefined> {
    return untilUnchanged(MAX_ATTEMPTS, async () => {
      const { header, isNew } = await this.#headerForWrite();
      const generated = await generate();
      try {
        const record = await this.#prepareKeyRecord(type, label, header, generated);
        const written = await this.#commitKeyRecord(record, header, isNew);
        return written ? record : undefined;
      } finally {
        generated.erase(); // stored, or abandoned: a retry generates a fresh key
      }
    });
  }

  /**
   * A key whose record doesn't depend on the header (D-61): generated once, behind a prompt, and added in one
   * transaction to the vault as it is then, never redone. A fresh header is made beforehand, used only if the
   * vault is empty by then. No wiped key comes back, as this one is new.
   */
  async #storeAsIs(type: KeyTypeName, label: string | undefined, pending: Promise<NewKey>): Promise<KeyRecord> {
    const generated = await pending;
    try {
      const header = await createHeader();
      const record = await this.#prepareKeyRecord(type, label, header, generated);
      await this.#connection.transact([META_STORE, KEYS_STORE], 'readwrite', async (tx) => {
        if (!(await readHeader(tx))) addHeader(tx, header);
        addKeyRecord(tx, record);
      });
      return record;
    } finally {
      generated.erase();
    }
  }

  /** The crypto after generation: derive the id, then the key type's part. Outside any transaction: crypto would end it. */
  async #prepareKeyRecord(
    type: KeyTypeName,
    label: string | undefined,
    header: HeaderRecord,
    generated: NewKey,
  ): Promise<KeyRecord> {
    const scope = this.#name;
    const id = await keyId(scope, type, generated.identity);
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

/** Calls the key type's generate at once. */
function generateKey(kind: KeyType, request: NewKeyRequest): Promise<NewKey> {
  return fromKeyType(kind.generate(request), 'The browser failed to generate a key');
}

/** A key type's result; a failure that is not a VaultError already is `unavailable`. */
async function fromKeyType<T>(pending: Promise<T>, message: string): Promise<T> {
  return pending.catch((cause: unknown) => {
    if (cause instanceof VaultError) throw cause;
    throw new VaultError('unavailable', message, { cause });
  });
}

/** The label of `options`, read once: a getter can't change between the check and the write. */
function readLabelOption(options: unknown): string | undefined {
  if (typeof options !== 'object' || options === null) throw new TypeError('options must be an object');
  const { label } = options as GenerateOptions; // `as`: checked to be an object; its label is checked next
  if (label !== undefined && !isLabel(label))
    throw new TypeError(`A label is a well-formed string of 1 to ${MAX_LABEL_LENGTH} UTF-16 code units`);
  return label;
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
  const info = keyType(type).info(record);
  const createdAt = new Date(record.createdAt);
  // `as`: the record was parsed by its type, whose info() returns that type's own fields of its KeyInfo member.
  return { id, scope, type, publicKey, ...info, createdAt, ...(label !== undefined && { label }) } as KeyInfo;
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
