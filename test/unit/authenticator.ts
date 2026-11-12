/// <reference types="@vitest/browser-playwright" />
import { cdp, server } from 'vitest/browser';

/** Passkey unit tests need the CDP WebAuthn domain, which only Chromium has (D-62); Firefox and WebKit get e2e in #69. */
export const hasVirtualAuthenticator = server.browser === 'chromium';

/** A credential as the CDP WebAuthn domain reports it. */
export interface VirtualCredential {
  readonly credentialId: Uint8Array<ArrayBuffer>;
  readonly userHandle: Uint8Array<ArrayBuffer>;
  readonly rpId: string;
}

export interface VirtualAuthenticator {
  credentials(): Promise<VirtualCredential[]>;
  /** Makes every later assertion carry a signature that does not verify, or answer without user verification. */
  overrideResponses(bits: { isBogusSignature?: boolean; isBadUV?: boolean }): Promise<void>;
  remove(): Promise<void>;
}

/**
 * A CTAP2 platform authenticator with resident keys and user verification, which answers every prompt at once
 * with the user verified. Chromium only (`hasVirtualAuthenticator`). Remove it in afterEach.
 */
export async function addVirtualAuthenticator(): Promise<VirtualAuthenticator> {
  const session = cdp();
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
  return {
    async credentials() {
      const { credentials } = await session.send('WebAuthn.getCredentials', { authenticatorId });
      return credentials.map((c) => ({
        credentialId: Uint8Array.fromBase64(c.credentialId),
        userHandle: Uint8Array.fromBase64(c.userHandle ?? ''),
        rpId: c.rpId ?? '',
      }));
    },
    async overrideResponses(bits) {
      await session.send('WebAuthn.setResponseOverrideBits', { authenticatorId, ...bits });
    },
    async remove() {
      await session.send('WebAuthn.removeVirtualAuthenticator', { authenticatorId });
    },
  };
}
