import { playwright } from '@vitest/browser-playwright';
import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    include: ['test/unit/**/*.test.ts'],
    setupFiles: ['test/unit/setup.ts'],
    // cdp() needs both, for the passkey tests' virtual authenticator; the API listens on localhost only.
    api: { allowWrite: true, allowExec: true },
    browser: {
      enabled: true,
      headless: true,
      provider: playwright(),
      instances: [{ browser: 'chromium' }, { browser: 'firefox' }, { browser: 'webkit' }],
    },
  },
});
