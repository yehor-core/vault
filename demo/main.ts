import { secp256k1 } from '@noble/curves/secp256k1.js';
import { Vault, VaultError, type KeyInfo, type KeyTypeName } from '../src/index.ts';

// One fixed scope: whether the demo shows scopes is decided later.
const SCOPE = 'demo';

function element<T extends HTMLElement>(id: string, type: new () => T): T {
  const found = document.getElementById(id);
  if (!(found instanceof type)) throw new Error(`The demo page has no #${id} of type ${type.name}`);
  return found;
}

const status = element('status', HTMLElement);
const rows = element('keys', HTMLElement);
const output = element('output', HTMLElement);
const messageInput = element('message', HTMLInputElement);
const typeSelect = element('type', HTMLSelectElement);
const keyTypeNames: readonly string[] = ['ed25519', 'secp256k1'] satisfies KeyTypeName[];

const hex = (bytes: Uint8Array) => Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');

async function run(action: () => Promise<void>) {
  try {
    await action();
    await refresh();
    status.textContent = 'Ready';
    status.className = '';
  } catch (error) {
    show(error);
  }
}

function show(error: unknown) {
  status.textContent = error instanceof VaultError ? `VaultError ${error.code}: ${error.message}` : String(error);
  status.className = 'error';
}

async function refresh() {
  rows.replaceChildren(...(await keys.list()).map(row));
}

function row(key: KeyInfo): HTMLTableRowElement {
  const tr = document.createElement('tr');
  tr.dataset.id = key.id;
  tr.dataset.type = key.type;
  tr.dataset.publicKey = hex(key.publicKey);
  const cells = [
    key.id.slice(0, 12) + '…',
    key.type,
    hex(key.publicKey).slice(0, 16) + '…',
    key.createdAt.toLocaleTimeString(),
  ];
  for (const text of cells) tr.insertCell().textContent = text;
  const actions = tr.insertCell();
  actions.append(
    button('Sign', () => sign(key)),
    ' ',
    button('Delete', () => keys.delete(key)),
  );
  return tr;
}

function button(label: string, action: () => Promise<void>): HTMLButtonElement {
  const b = document.createElement('button');
  b.textContent = label;
  b.onclick = () => run(action);
  return b;
}

async function sign(key: KeyInfo) {
  const message = new TextEncoder().encode(messageInput.value);
  const signature = await keys.sign(key, message);
  const verified = await verify(key, signature.bytes, message);
  output.dataset.type = signature.type;
  output.dataset.signature = hex(signature.bytes);
  output.dataset.verified = String(verified);
  output.textContent = [
    `key        ${key.id}`,
    `public key ${hex(key.publicKey)}`,
    `message    ${JSON.stringify(messageInput.value)}`,
    `signature  ${hex(signature.bytes)}`,
    `verified   ${verified}`,
  ].join('\n');
}

// Verification needs only the public key: no Vault involved.
async function verify(key: KeyInfo, signature: Uint8Array<ArrayBuffer>, message: Uint8Array<ArrayBuffer>) {
  switch (key.type) {
    case 'ed25519': {
      const publicKey = await crypto.subtle.importKey('raw', key.publicKey, 'Ed25519', false, ['verify']);
      return crypto.subtle.verify('Ed25519', publicKey, signature, message);
    }
    case 'secp256k1':
      return secp256k1.verify(signature, message, key.publicKey, { prehash: true, lowS: true, format: 'compact' });
  }
}

function selectedType(): KeyTypeName {
  const type = typeSelect.value;
  if (!keyTypeNames.includes(type)) throw new Error(`The demo offers no key type ${type}`);
  return type as KeyTypeName; // `as`: checked against keyTypeNames above
}

const vault = await Vault.open().catch((error: unknown) => {
  show(error);
  throw error;
});
const keys = vault.scope(SCOPE);
element('scope', HTMLElement).textContent = SCOPE;
element('generate', HTMLElement).onclick = () => run(async () => void (await keys.generate(selectedType())));
element('wipe', HTMLElement).onclick = () =>
  run(async () => {
    await vault.wipe();
    output.textContent = '—';
  });
await run(async () => {});
