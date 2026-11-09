import { secp256k1 } from '@noble/curves/secp256k1.js';
import { Vault, VaultError, type KeyInfo, type KeyTypeName, type Scope, type Signature } from '../src/index.ts';

const status = document.getElementById('status')!;
const rows = document.getElementById('keys')!;
const output = document.getElementById('output')!;
const scopeInput = document.getElementById('scope') as HTMLInputElement;
const typeSelect = document.getElementById('type') as HTMLSelectElement;
const labelInput = document.getElementById('label') as HTMLInputElement;
const messageInput = document.getElementById('message') as HTMLInputElement;

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

function scope(): Scope {
  return vault.scope(scopeInput.value);
}

async function refresh() {
  rows.replaceChildren(...(await scope().list()).map(row));
}

function row(key: KeyInfo): HTMLTableRowElement {
  const tr = document.createElement('tr');
  tr.dataset.id = key.id;
  tr.dataset.type = key.type;
  tr.dataset.publicKey = hex(key.publicKey);
  const cells = [key.label ?? '—', key.id.slice(0, 12) + '…', key.type, hex(key.publicKey).slice(0, 16) + '…', key.createdAt.toLocaleTimeString()];
  for (const text of cells) tr.insertCell().textContent = text;
  const actions = tr.insertCell();
  actions.append(button('Sign', () => sign(key)), ' ', button('Delete', () => scope().delete(key)));
  return tr;
}

function button(label: string, action: () => Promise<void>): HTMLButtonElement {
  const b = document.createElement('button');
  b.textContent = label;
  b.onclick = () => run(action);
  return b;
}

/** Verification needs only the public key, no Vault: WebCrypto for ed25519, noble for secp256k1 (WebCrypto has none). */
async function verify(key: KeyInfo, signature: Signature, message: Uint8Array<ArrayBuffer>): Promise<[boolean, string]> {
  switch (key.type) {
    case 'ed25519': {
      const publicKey = await crypto.subtle.importKey('raw', key.publicKey, 'Ed25519', false, ['verify']);
      return [await crypto.subtle.verify('Ed25519', publicKey, signature.bytes, message), 'WebCrypto Ed25519'];
    }
    case 'secp256k1':
      return [secp256k1.verify(signature.bytes, message, key.publicKey), '@noble/curves ECDSA (SHA-256, low-S)'];
  }
}

async function sign(key: KeyInfo) {
  const message = new TextEncoder().encode(messageInput.value);
  const signature = await scope().sign(key, message);
  const [verified, verifier] = await verify(key, signature, message);
  output.dataset.key = key.id; // which key the attributes below belong to
  output.dataset.signature = hex(signature.bytes);
  output.dataset.verified = String(verified);
  output.textContent = [
    `key        ${key.id} (${key.type}${key.label ? `, "${key.label}"` : ''})`,
    `public key ${hex(key.publicKey)}`,
    `message    ${JSON.stringify(messageInput.value)}`,
    `signature  ${hex(signature.bytes)}`,
    `verified   ${verified} (${verifier})`,
  ].join('\n');
}

const vault = await Vault.open().catch((error: unknown) => {
  show(error);
  throw error;
});
document.getElementById('generate')!.onclick = () =>
  run(async () => {
    const label = labelInput.value.trim();
    await scope().generate(typeSelect.value as KeyTypeName, label ? { label } : {});
  });
document.getElementById('wipe')!.onclick = () =>
  run(async () => {
    await vault.wipe();
    output.textContent = '—';
  });
scopeInput.onchange = () => run(async () => {});
await run(async () => {});
