/**
 * src/store.ts — Anti-Replay Storage Interface & Built-in Memory Store
 *
 * Provides the Inversion of Control (IoC) adapter pattern for preventing
 * OTP replay attacks. Users can inject their own storage backend (Redis,
 * Postgres, etc.) by implementing the IStore interface.
 */

// ---------------------------------------------------------------------------
// Interface
// ---------------------------------------------------------------------------

/**
 * Storage adapter interface for anti-replay protection.
 *
 * Implementations must track which (userId, timeBlock) combinations have
 * already been consumed and reject duplicates within the validity window.
 *
 * The method may be synchronous or asynchronous — both are accepted.
 */
export interface IStore {
  /**
   * Checks if the given time-block has already been used for this user.
   * If not, marks it as used and returns `true` (first use → valid).
   * If already used, returns `false` (replay → reject).
   *
   * @param userId     - The unique identifier for the user.
   * @param timeBlock  - The integer time block that was matched.
   * @param ttlSeconds - The OTP validity window in seconds (useful for
   *                     setting expiry on the stored key).
   * @returns `true` if the OTP is being used for the first time, `false`
   *          if it has already been consumed (replay attack).
   */
  checkAndStore(
    userId: string,
    timeBlock: number,
    ttlSeconds: number,
  ): boolean | Promise<boolean>;
}

// ---------------------------------------------------------------------------
// Built-in Memory Store
// ---------------------------------------------------------------------------

/**
 * A simple in-memory IStore implementation backed by a JavaScript Map.
 *
 * Suitable for single-process applications and development/testing.
 * For multi-server or production deployments, use a shared store like Redis.
 *
 * Includes lazy cleanup of expired entries to prevent unbounded memory growth.
 */
export class MemoryStore implements IStore {
  /**
   * Internal map: key = "userId:timeBlock", value = expiry timestamp (ms).
   */
  private readonly _used = new Map<string, number>();

  /**
   * Counter to throttle cleanup runs. Cleanup triggers every N calls.
   */
  private _opsSinceCleanup = 0;
  private static readonly CLEANUP_INTERVAL = 50;

  /**
   * Check if the (userId, timeBlock) pair has been used before.
   * If not, store it with an expiry and return true.
   * If it was already consumed, return false (replay).
   */
  checkAndStore(
    userId: string,
    timeBlock: number,
    ttlSeconds: number,
  ): boolean {
    // Lazy cleanup: periodically sweep expired keys
    this._opsSinceCleanup++;
    if (this._opsSinceCleanup >= MemoryStore.CLEANUP_INTERVAL) {
      this._cleanup();
      this._opsSinceCleanup = 0;
    }

    const key = `${userId}:${timeBlock}`;
    const now = Date.now();
    const existing = this._used.get(key);

    // If key exists and hasn't expired → replay attack
    if (existing !== undefined && existing > now) {
      return false;
    }

    // First use: store with expiry.
    // We use 3× ttlSeconds because the ±1 drift window means a time block
    // can be valid across up to 3 consecutive windows.
    const expiryMs = now + ttlSeconds * 3 * 1000;
    this._used.set(key, expiryMs);
    return true;
  }

  /**
   * Remove all entries whose expiry timestamp has passed.
   */
  private _cleanup(): void {
    const now = Date.now();
    for (const [key, expiry] of this._used) {
      if (expiry <= now) {
        this._used.delete(key);
      }
    }
  }

  /**
   * Returns the current number of tracked entries (useful for testing).
   */
  get size(): number {
    return this._used.size;
  }

  /**
   * Clears all stored entries (useful for testing).
   */
  clear(): void {
    this._used.clear();
    this._opsSinceCleanup = 0;
  }
}

// ---------------------------------------------------------------------------
// Default instance
// ---------------------------------------------------------------------------

/**
 * A pre-initialized MemoryStore instance used as the default store
 * when no custom store is provided to `validateOTP`.
 */
export const defaultMemoryStore = new MemoryStore();
