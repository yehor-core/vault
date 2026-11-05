import { defineConfig, devices } from '@playwright/test';

// localhost, not 127.0.0.1: WebAuthn rejects IP addresses as relying-party IDs.
const origin = 'http://localhost:5174';

export default defineConfig({
  testDir: 'test/e2e',
  webServer: {
    command: 'npx vite demo --port 5174 --strictPort',
    url: origin,
  },
  use: { baseURL: origin },
  projects: [
    { name: 'chromium', use: { ...devices['Desktop Chrome'] } },
    { name: 'firefox', use: { ...devices['Desktop Firefox'] } },
    { name: 'webkit', use: { ...devices['Desktop Safari'] } },
  ],
});
