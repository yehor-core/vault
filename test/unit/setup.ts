import { beforeEach, vi } from 'vitest';

// Vitest runs each test page in an iframe that never has focus (`document.hasFocus()` is false in Chromium, Firefox
// and WebKit), while a page whose user just answered a passkey prompt has it. Vault waits for focus before a chained
// second prompt (D-96), so every test starts focused; `helpers.ts` `focusLostAtPrompt` takes it away. Re-applied
// before each test, as tests end with `vi.restoreAllMocks()`.
beforeEach(() => {
  vi.spyOn(Document.prototype, 'hasFocus').mockReturnValue(true);
});
