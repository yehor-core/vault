/** How many times an optimistic write is prepared and tried before it fails with `unavailable` (D-08, D-82). */
export const MAX_ATTEMPTS = 3;

/** Optimistic write: runs `attempt` up to `times` times until it returns a value (undefined = vault changed). */
export async function untilUnchanged<T>(times: number, attempt: () => Promise<T | undefined>): Promise<T | undefined> {
  for (let i = 0; i < times; i++) {
    const result = await attempt();
    if (result !== undefined) return result;
  }
  return undefined;
}
