import { beforeEach, vi } from 'vitest';

// Vitest's test iframe never has focus, a page whose user answered a prompt has (D-96): every test starts focused.
// Before each test, as tests end with `vi.restoreAllMocks()`; `helpers.ts` `focusLostAtPrompt` takes focus away.
beforeEach(() => {
  vi.spyOn(Document.prototype, 'hasFocus').mockReturnValue(true);
});
