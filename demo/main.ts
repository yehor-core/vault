/// <reference types="vite/client" />
import { p256 } from '@noble/curves/nist.js';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { Vault, VaultError, type KeyInfo, type KeyTypeName, type Signature } from '../src/index.ts';

// One fixed scope: whether the demo shows scopes is decided later.
const SCOPE = 'demo';

// For experiments by hand in DevTools: Vite serves src/ only under /@fs/, so the console can't import it.
if (import.meta.env.DEV) Object.assign(globalThis, { Vault });

function element<T extends HTMLElement>(id: string, type: new () => T): T {
  const found = document.getElementById(id);
  if (!(found instanceof type)) throw new Error(`The demo page has no #${id} of type ${type.name}`);
  return found;
}

const status = element('status', HTMLElement);
const state = element('state', HTMLElement);
const rows = element('keys', HTMLElement);
const output = element('output', HTMLElement);
const messageInput = element('message', HTMLInputElement);
const typeSelect = element('type', HTMLSelectElement);
const labelInput = element('label', HTMLInputElement);
const keyTypeNames: readonly string[] = ['ed25519', 'secp256k1', 'passkey'] satisfies KeyTypeName[];

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
  const [listed, current] = await Promise.all([keys.list(), vault.state()]);
  rows.replaceChildren(...listed.map(row));
  state.textContent = current;
}

function row(key: KeyInfo): HTMLTableRowElement {
  const tr = document.createElement('tr');
  tr.dataset.id = key.id;
  tr.dataset.type = key.type;
  tr.dataset.publicKey = hex(key.publicKey);
  if (key.type === 'passkey') tr.dataset.credentialId = hex(key.credentialId);
  const cells = [
    key.id.slice(0, 12) + '…',
    key.label ?? '',
    key.type,
    key.type === 'passkey' ? hex(key.credentialId).slice(0, 16) + '…' : '',
    hex(key.publicKey).slice(0, 16) + '…',
    key.createdAt.toLocaleTimeString(),
  ];
  for (const text of cells) tr.insertCell().textContent = text; // text, never markup: a label is anyone's string
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
  const signature = await keys.sign(key, message); // first: a passkey prompt starts inside the click
  const verified = await verify(key.publicKey, signature, message);
  const lines = [
    `key        ${key.id}`,
    `public key ${hex(key.publicKey)}`,
    `message    ${JSON.stringify(messageInput.value)}`,
  ];
  delete output.dataset.authenticatorData;
  delete output.dataset.clientDataJson;
  if (signature.type === 'passkey') {
    output.dataset.authenticatorData = hex(signature.authenticatorData);
    output.dataset.clientDataJson = hex(signature.clientDataJSON);
    output.dataset.signature = hex(signature.signature);
    lines.push(
      `authenticator data ${hex(signature.authenticatorData)}`,
      `client data        ${new TextDecoder().decode(signature.clientDataJSON)}`,
      `signature (DER)    ${hex(signature.signature)}`,
    );
  } else {
    output.dataset.signature = hex(signature.bytes);
    lines.push(`signature  ${hex(signature.bytes)}`);
  }
  output.dataset.type = signature.type;
  output.dataset.verified = String(verified);
  output.textContent = [...lines, `verified   ${verified}`].join('\n');
}

// Verification needs only the public key: no Vault involved.
async function verify(publicKey: Uint8Array<ArrayBuffer>, signature: Signature, message: Uint8Array<ArrayBuffer>) {
  switch (signature.type) {
    case 'ed25519': {
      const key = await crypto.subtle.importKey('raw', publicKey, 'Ed25519', false, ['verify']);
      return crypto.subtle.verify('Ed25519', key, signature.bytes, message);
    }
    case 'secp256k1':
      return secp256k1.verify(signature.bytes, message, publicKey, { prehash: true, lowS: true, format: 'compact' });
    case 'passkey':
      return verifyAssertion(publicKey, signature, message);
  }
}

const FLAG_UP = 0x01;
const FLAG_UV = 0x04;

/**
 * Checks a passkey assertion as a WebAuthn relying party does: client data of type webauthn.get over
 * SHA-256(message) from this origin, the rpId hash, the UP and UV flags, and the ES256 signature over
 * authenticatorData ‖ SHA-256(clientDataJSON) under the SPKI public key.
 */
async function verifyAssertion(
  publicKey: Uint8Array<ArrayBuffer>,
  { authenticatorData, clientDataJSON, signature }: Signature<'passkey'>,
  message: Uint8Array<ArrayBuffer>,
): Promise<boolean> {
  const sha256 = async (bytes: Uint8Array<ArrayBuffer>) => {
    const digest = await crypto.subtle.digest('SHA-256', bytes);
    return new Uint8Array(digest);
  };
  const clientData: unknown = JSON.parse(new TextDecoder().decode(clientDataJSON));
  if (typeof clientData !== 'object' || clientData === null) return false;
  // Defaults first, so each field reads as unknown even when the client data lacks it.
  const { type, challenge, origin } = { type: undefined, challenge: undefined, origin: undefined, ...clientData };
  const messageHash = await sha256(message);
  if (type !== 'webauthn.get' || origin !== location.origin) return false;
  if (challenge !== messageHash.toBase64({ alphabet: 'base64url', omitPadding: true })) return false;
  const rpIdHash = await sha256(new TextEncoder().encode(location.hostname));
  if (hex(authenticatorData.subarray(0, 32)) !== hex(rpIdHash)) return false;
  const flags = authenticatorData[32] ?? 0;
  if ((flags & FLAG_UP) === 0 || (flags & FLAG_UV) === 0) return false;
  const clientDataHash = await sha256(clientDataJSON);
  const signed = new Uint8Array([...authenticatorData, ...clientDataHash]);
  // WebCrypto takes r ‖ s, the authenticator gives DER.
  const compact = new Uint8Array(p256.Signature.fromBytes(signature, 'der').toBytes('compact'));
  const key = await crypto.subtle.importKey('spki', publicKey, { name: 'ECDSA', namedCurve: 'P-256' }, false, [
    'verify',
  ]);
  return crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, key, compact, signed);
}

function selectedType(): KeyTypeName {
  const type = typeSelect.value;
  if (!keyTypeNames.includes(type)) throw new Error(`The demo offers no key type ${type}`);
  return type as KeyTypeName; // `as`: checked against keyTypeNames above
}

function labelOption(): { label?: string } {
  const label = labelInput.value;
  return label === '' ? {} : { label };
}

const vault = await Vault.open().catch((error: unknown) => {
  show(error);
  throw error;
});
const keys = vault.scope(SCOPE);
element('scope', HTMLElement).textContent = SCOPE;
element('generate', HTMLElement).onclick = () =>
  run(async () => {
    await keys.generate(selectedType(), labelOption()); // first: a passkey prompt starts inside the click
  });
element('add', HTMLElement).onclick = () =>
  run(async () => {
    await keys.add('passkey', labelOption()); // first: its prompt starts inside the click
  });
element('protect', HTMLElement).onclick = () =>
  run(async () => {
    await vault.protect(); // first: its prompt starts inside the click
  });
element('unlock', HTMLElement).onclick = () =>
  run(async () => {
    await vault.unlock(); // first: its prompt starts inside the click
  });
element('lock', HTMLElement).onclick = () =>
  run(async () => {
    vault.lock();
  });
element('wipe', HTMLElement).onclick = () =>
  run(async () => {
    await vault.wipe();
    output.textContent = '—';
  });
// Another tab wrote: show what is stored now. An error goes to the status line; a shown error stays.
vault.onChange(() => void refresh().catch(show));
await run(async () => {});
