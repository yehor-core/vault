import { expect, test } from 'vitest';
import { server } from 'vitest/browser';

const engineUserAgent: Record<string, RegExp> = {
  chromium: /Chrome\//,
  firefox: /Firefox\//,
  webkit: /AppleWebKit\/(?!.*Chrome)/,
};

test('runs in the real browser engine it is configured for', () => {
  expect(navigator.userAgent).toMatch(engineUserAgent[server.browser]!);
  expect(indexedDB).toBeInstanceOf(IDBFactory);
  expect(isSecureContext).toBe(true);
});
