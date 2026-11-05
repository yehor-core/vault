import { expect, test } from '@playwright/test';

test('demo page runs its TypeScript module in a secure context', async ({ page }) => {
  await page.goto('/');
  await expect(page.locator('#status')).toHaveText('Ready');
  expect(await page.evaluate(() => isSecureContext)).toBe(true);
});
