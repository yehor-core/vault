import { defineConfig, devices } from '@playwright/test';
import { PUBLISHED_DEMO_URL } from './test/e2e/contexts.ts';

// localhost, not 127.0.0.1: WebAuthn rejects IP addresses as relying-party IDs.
const origin = 'http://localhost:5174';

export default defineConfig({
  testDir: 'test/e2e',
  webServer: [
    {
      command: 'npx vite demo --port 5174 --strictPort',
      url: origin,
    },
    // The production build under the GitHub Pages base path, for test/e2e/pages.spec.ts (D-93).
    {
      command: `npm run build:demo && npm run preview:demo -- --port ${new URL(PUBLISHED_DEMO_URL).port} --strictPort`,
      url: PUBLISHED_DEMO_URL,
    },
  ],
  use: { baseURL: origin },
  projects: [
    { name: 'chromium', use: { ...devices['Desktop Chrome'] } },
    { name: 'firefox', use: { ...devices['Desktop Firefox'] } },
    { name: 'webkit', use: { ...devices['Desktop Safari'] } },
  ],
});
