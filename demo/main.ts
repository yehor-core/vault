import { Vault, VaultError, type KeyInfo } from '../src/index.ts';

const status = document.getElementById('status')!;
const rows = document.getElementById('keys')!;
const output = document.getElementById('output')!;
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

async function refresh() {
  rows.replaceChildren(...(await vault.list()).map(row));
}

function row(key: KeyInfo): HTMLTableRowElement {
  const tr = document.createElement('tr');
  tr.dataset.id = key.id;
  tr.dataset.publicKey = hex(key.publicKey);
  const cells = [key.id.slice(0, 12) + '…', key.type, hex(key.publicKey).slice(0, 16) + '…', key.createdAt.toLocaleTimeString()];
  for (const text of cells) tr.insertCell().textContent = text;
  const actions = tr.insertCell();
  actions.append(button('Sign', () => sign(key)), ' ', button('Delete', () => vault.delete(key.id)));
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
  const signature = await vault.sign(key.id, message);
  // Verification needs only the public key: no Vault involved.
  const publicKey = await crypto.subtle.importKey('raw', new Uint8Array(key.publicKey), 'Ed25519', false, ['verify']);
  const verified = await crypto.subtle.verify('Ed25519', publicKey, new Uint8Array(signature.bytes), message);
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

const vault = await Vault.open().catch((error: unknown) => {
  show(error);
  throw error;
});
document.getElementById('generate')!.onclick = () => run(async () => void (await vault.generate('ed25519')));
document.getElementById('wipe')!.onclick = () =>
  run(async () => {
    await vault.wipe();
    output.textContent = '—';
  });
await run(async () => {});
