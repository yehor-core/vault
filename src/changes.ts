// The one message Vault posts. It carries nothing: a notification only says "read the vault again" (D-46).
const CHANGED = 'changed';

/**
 * Change notifications of one vault: a BroadcastChannel named after its database, which reaches every other
 * context that has it open, and the listeners of this instance. Best effort: a message can be lost or forged (D-47).
 */
export class Changes {
  readonly #channel: BroadcastChannel;
  readonly #listeners = new Set<() => void>();
  #closed = false;

  constructor(name: string) {
    this.#channel = new BroadcastChannel(name);
    this.#channel.onmessage = (event: MessageEvent<unknown>) => {
      if (event.data === CHANGED) this.#call(); // anything else is not ours
    };
  }

  /** Calls `listener` with no argument on every change; the function returned stops it. */
  subscribe(listener: () => void): () => void {
    const entry = () => listener(); // one per call: stopping it leaves other registrations of the same function
    this.#listeners.add(entry);
    return () => void this.#listeners.delete(entry);
  }

  /** Tells every context, this one included, that the vault may have changed. Call after the write commits. */
  notify(): void {
    if (this.#closed) return; // closed after the commit: the notification is lost (D-47)
    this.#channel.postMessage(CHANGED);
    this.#call();
  }

  close(): void {
    this.#closed = true;
    this.#listeners.clear();
    this.#channel.close();
  }

  #call(): void {
    for (const listener of [...this.#listeners]) {
      if (!this.#listeners.has(listener)) continue; // stopped by a listener called before it, or by close()
      try {
        listener();
      } catch (error) {
        reportError(error); // one failing listener doesn't silence the others
      }
    }
  }
}
