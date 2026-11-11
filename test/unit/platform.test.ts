import { expect, test } from 'vitest';
import { server } from 'vitest/browser';

const engineUserAgent: Record<string, RegExp> = {
  chromium: /Chrome\//,
  firefox: /Firefox\//,
  webkit: /AppleWebKit\/(?!.*Chrome)/,
};

test('runs in the real browser engine it is configured for', () => {
  const expected = engineUserAgent[server.browser];
  if (!expected) throw new Error(`No user agent pattern for ${server.browser}`);
  expect(navigator.userAgent).toMatch(expected);
  expect(indexedDB).toBeInstanceOf(IDBFactory);
  expect(isSecureContext).toBe(true);
});
