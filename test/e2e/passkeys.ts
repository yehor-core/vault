import { expect, type Browser, type BrowserContext, type CDPSession, type Page } from '@playwright/test';
import { createHash, createPrivateKey, createPublicKey, verify } from 'node:crypto';
import type { VaultErrorCode } from '../../src/index.ts';
import { DEMO_SCOPE, openDemo, type PageKey } from './contexts.ts';

// Passkey authenticators for e2e tests (D-62): Chromium's own WebAuthn through a CDP virtual authenticator; in
// Firefox and WebKit, Playwright's JavaScript stand-in, which always signs ES256 with UP and UV.

/** The relying-party id of the dev demo's origin (`playwright.config.ts`). */
const RP_ID = 'localhost';

/** A passkey as it leaves one authenticator for another, base64url throughout: the private key is PKCS#8. */
export interface MovablePasskey {
  readonly id: string;
  readonly userHandle: string;
  readonly privateKey: string;
  readonly signCount: number;
}

export interface PasskeyAuthenticator {
  /** Every passkey it holds for the demo's origin, to put in another authenticator. */
  passkeys(): Promise<MovablePasskey[]>;
}

/** The Chromium authenticator, which also declines prompts and answers without user verification. */
export interface VirtualAuthenticator extends PasskeyAuthenticator {
  /** With presence off, a prompt is never answered: it ends at its timeout, as a declined prompt does. */
  setPresence(answers: boolean): Promise<void>;
  /** Makes every later assertion answer with the UV flag cleared. */
  answerWithoutUserVerification(): Promise<void>;
}

/** A browser context with an authenticator and a page of the dev demo, its `Vault` global ready. */
export interface PasskeyDevice {
  readonly page: Page;
  readonly authenticator: PasskeyAuthenticator;
}

/**
 * A new page of the dev demo in `context`, with an authenticator for the engine that holds `passkeys`. Once per
 * context: the Chromium authenticator belongs to this page, and the stand-in is installed into the context.
 */
export async function openWithAuthenticator(
  context: BrowserContext,
  browserName: string,
  passkeys: readonly MovablePasskey[] = [],
): Promise<PasskeyDevice> {
  if (browserName === 'chromium') {
    const page = await openDemo(context);
    return { page, authenticator: await addVirtualAuthenticator(page, passkeys) };
  }
  // Playwright's WebKit on Linux has no WebAuthn classes; the stand-in builds its answers on these, when present, so
  // Vault's `instanceof` checks pass. Registered before install(), so it runs before the stand-in.
  await context.addInitScript(() => {
    for (const name of ['PublicKeyCredential', 'AuthenticatorAttestationResponse', 'AuthenticatorAssertionResponse']) {
      if (typeof Reflect.get(globalThis, name) === 'function') continue;
      const emptyClass = { [name]: class {} }[name]; // a class with this name
      Object.defineProperty(globalThis, name, { value: emptyClass, writable: true, configurable: true });
    }
  });
  // Before the page first touches navigator.credentials, as `install()` asks.
  await context.credentials.install();
  for (const passkey of passkeys) {
    const publicKey = spkiOf(passkey.privateKey).toString('base64url');
    await context.credentials.create(RP_ID, { ...passkey, publicKey });
  }
  const page = await openDemo(context);
  return { page, authenticator: { passkeys: () => standInPasskeys(context) } };
}

/** A fresh device: a new browser context, so an empty vault, whose authenticator holds these passkeys. */
export async function freshDevice(
  browser: Browser,
  browserName: string,
  passkeys: readonly MovablePasskey[],
): Promise<PasskeyDevice & { context: BrowserContext }> {
  const context = await browser.newContext();
  return { context, ...(await openWithAuthenticator(context, browserName, passkeys)) };
}

/** A CTAP2 platform authenticator with resident keys, which answers every prompt at once with the user verified. */
export async function addVirtualAuthenticator(
  page: Page,
  passkeys: readonly MovablePasskey[] = [],
): Promise<VirtualAuthenticator> {
  const session = await page.context().newCDPSession(page);
  await session.send('WebAuthn.enable', { enableUI: false });
  const { authenticatorId } = await session.send('WebAuthn.addVirtualAuthenticator', {
    options: {
      protocol: 'ctap2',
      transport: 'internal',
      hasResidentKey: true,
      hasUserVerification: true,
      isUserVerified: true,
      automaticPresenceSimulation: true,
    },
  });
  for (const passkey of passkeys) await addCredential(session, authenticatorId, passkey);
  return {
    async passkeys() {
      const { credentials } = await session.send('WebAuthn.getCredentials', { authenticatorId });
      return credentials
        .filter((credential) => credential.rpId === RP_ID)
        .map(({ credentialId, userHandle, privateKey, signCount }) => ({
          id: reencode(credentialId, 'base64', 'base64url'),
          userHandle: reencode(userHandle ?? '', 'base64', 'base64url'),
          privateKey: reencode(privateKey, 'base64', 'base64url'),
          signCount,
        }));
    },
    async setPresence(answers) {
      await session.send('WebAuthn.setAutomaticPresenceSimulation', { authenticatorId, enabled: answers });
    },
    async answerWithoutUserVerification() {
      await session.send('WebAuthn.setResponseOverrideBits', { authenticatorId, isBadUV: true });
    },
  };
}

async function addCredential(session: CDPSession, authenticatorId: string, passkey: MovablePasskey): Promise<void> {
  await session.send('WebAuthn.addCredential', {
    authenticatorId,
    credential: {
      credentialId: reencode(passkey.id, 'base64url', 'base64'),
      isResidentCredential: true,
      rpId: RP_ID,
      privateKey: reencode(passkey.privateKey, 'base64url', 'base64'),
      userHandle: reencode(passkey.userHandle, 'base64url', 'base64'),
      signCount: passkey.signCount,
    },
  });
}

async function standInPasskeys(context: BrowserContext): Promise<MovablePasskey[]> {
  const credentials = await context.credentials.get({ rpId: RP_ID });
  return credentials.map(({ id, userHandle, privateKey, signCount }) => ({ id, userHandle, privateKey, signCount }));
}

function reencode(text: string, from: BufferEncoding, to: BufferEncoding): string {
  return Buffer.from(text, from).toString(to);
}

function spkiOf(privateKey: string): Buffer {
  const key = createPrivateKey({ key: Buffer.from(privateKey, 'base64url'), format: 'der', type: 'pkcs8' });
  return createPublicKey(key).export({ format: 'der', type: 'spki' });
}

/** A passkey key as it crosses from a page to the test: plain numbers, no typed arrays. */
export interface PagePasskey extends PageKey {
  readonly credentialId: number[];
}

/** A passkey assertion as it crosses from a page to the test. */
export interface PageAssertion {
  readonly authenticatorData: number[];
  readonly clientDataJSON: number[];
  readonly signature: number[];
}

// The page functions below rethrow a VaultError as `VaultError <code>: …`: page.evaluate keeps only the message.

/** A passkey key generated in the demo scope from the page's console. */
export const generatePasskey = (page: Page): Promise<PagePasskey> => newPasskey(page, 'generate');

/** A passkey the authenticator holds, added to the demo scope from the page's console. */
export const addPasskey = (page: Page): Promise<PagePasskey> => newPasskey(page, 'add');

async function newPasskey(page: Page, call: 'generate' | 'add'): Promise<PagePasskey> {
  return page.evaluate(
    async ({ scope, call }) => {
      // `as`: the global the dev demo sets; undefined fails the call below
      const { Vault } = globalThis as unknown as { Vault: typeof import('../../src/index.ts').Vault };
      const vault = await Vault.open();
      try {
        const key = await (call === 'generate'
          ? vault.scope(scope).generate('passkey')
          : vault.scope(scope).add('passkey'));
        return { id: key.id, publicKey: Array.from(key.publicKey), credentialId: Array.from(key.credentialId) };
      } catch (error) {
        throw error instanceof Error && error.name === 'VaultError' && 'code' in error
          ? new Error(`VaultError ${String(error.code)}: ${error.message}`)
          : error;
      } finally {
        vault.close();
      }
    },
    { scope: DEMO_SCOPE, call },
  );
}

/** Every passkey key the page lists in the demo scope. */
export async function listPasskeys(page: Page): Promise<PagePasskey[]> {
  return page.evaluate(async (scope) => {
    // `as`: the global the dev demo sets; undefined fails the call below
    const { Vault } = globalThis as unknown as { Vault: typeof import('../../src/index.ts').Vault };
    const vault = await Vault.open();
    try {
      return (await vault.scope(scope).list()).map((key) => {
        if (key.type !== 'passkey') throw new Error(`Key ${key.id} is not a passkey key`);
        return { id: key.id, publicKey: Array.from(key.publicKey), credentialId: Array.from(key.credentialId) };
      });
    } finally {
      vault.close();
    }
  }, DEMO_SCOPE);
}

/** The assertion over `message` that the page's `sign` returns for the stored passkey key `key`. */
export async function signWithPasskey(page: Page, key: PagePasskey, message: string): Promise<PageAssertion> {
  return page.evaluate(
    async ({ scope, id, message }) => {
      // `as`: the global the dev demo sets; undefined fails the call below
      const { Vault } = globalThis as unknown as { Vault: typeof import('../../src/index.ts').Vault };
      const vault = await Vault.open();
      try {
        const stored = (await vault.scope(scope).list()).find((listed) => listed.id === id);
        if (stored?.type !== 'passkey') throw new Error(`no passkey key ${id} to sign with`);
        const signature = await vault.scope(scope).sign(stored, new TextEncoder().encode(message));
        return {
          authenticatorData: Array.from(signature.authenticatorData),
          clientDataJSON: Array.from(signature.clientDataJSON),
          signature: Array.from(signature.signature),
        };
      } catch (error) {
        throw error instanceof Error && error.name === 'VaultError' && 'code' in error
          ? new Error(`VaultError ${String(error.code)}: ${error.message}`)
          : error;
      } finally {
        vault.close();
      }
    },
    { scope: DEMO_SCOPE, id: key.id, message },
  );
}

/** Expects a page call to fail with a VaultError of this code. */
export async function expectVaultError(call: Promise<unknown>, code: VaultErrorCode): Promise<void> {
  await expect(call).rejects.toThrow(`VaultError ${code}:`);
}

const FLAG_UP = 0x01;
const FLAG_UV = 0x04;

/**
 * Checks an assertion as a WebAuthn relying party does, in Node, without Vault or the page: client data of type
 * webauthn.get over SHA-256(message) from the demo's origin, the rpId hash, the UP and UV flags, and the ES256
 * signature over authenticatorData ‖ SHA-256(clientDataJSON) under the SPKI public key.
 */
export function verifiesOutsideVault(
  publicKey: number[],
  { authenticatorData, clientDataJSON, signature }: PageAssertion,
  message: string,
  origin: string,
): boolean {
  const sha256 = (bytes: Uint8Array | string) => createHash('sha256').update(bytes).digest();
  const clientData: unknown = JSON.parse(Buffer.from(clientDataJSON).toString('utf8'));
  if (typeof clientData !== 'object' || clientData === null) return false;
  const {
    type,
    challenge,
    origin: clientOrigin,
  } = { type: undefined, challenge: undefined, origin: undefined, ...clientData };
  if (type !== 'webauthn.get' || clientOrigin !== origin) return false;
  if (challenge !== sha256(message).toString('base64url')) return false;
  const data = Buffer.from(authenticatorData);
  if (!data.subarray(0, 32).equals(sha256(RP_ID))) return false;
  const flags = data[32] ?? 0;
  if ((flags & FLAG_UP) === 0 || (flags & FLAG_UV) === 0) return false;
  const key = createPublicKey({ key: Buffer.from(publicKey), format: 'der', type: 'spki' });
  const signed = Buffer.concat([data, sha256(Buffer.from(clientDataJSON))]);
  return verify('sha256', signed, { key, dsaEncoding: 'der' }, Buffer.from(signature));
}
