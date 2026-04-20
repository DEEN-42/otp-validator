import { timingSafeEqual } from 'crypto';
import {
  OTP_DIGITS,
  assertNonEmptyString,
  assertPositiveNumber,
  getTimeBlock,
  generateOTPForTimeBlock,
} from './core';
import { IStore, defaultMemoryStore } from './store';

// ---------------------------------------------------------------------------
// Options interface
// ---------------------------------------------------------------------------

/**
 * Options for the `validateOTP` function.
 */
export interface ValidateOTPOptions {
  /** A unique identifier for the user. */
  userId: string;

  /** The 6-digit OTP string provided by the client. */
  userProvidedOtp: string;

  /** The backend's private secret. */
  secretKey: string;

  /** The validity window in seconds. */
  ttlSeconds: number;

  /**
   * Anti-replay store instance.
   *
   * - Pass an `IStore` implementation to use custom storage (Redis, Postgres, etc.).
   * - Omit/`undefined` to use the built-in `defaultMemoryStore`.
   * - Pass `false` to bypass replay protection entirely (math-only validation).
   */
  store?: IStore | false;
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Validates a user-provided OTP against the expected TOTP value.
 *
 * To account for network latency and minor clock skew, the validation
 * checks the current time block as well as the immediately preceding (-1)
 * and following (+1) time blocks.
 *
 * All comparisons use `crypto.timingSafeEqual` to prevent timing attacks.
 *
 * If a matching time block is found, the store is consulted to prevent
 * replay attacks. The same OTP can only be used once.
 *
 * @param options - Validation parameters (see {@link ValidateOTPOptions}).
 * @returns A `Promise<boolean>` — `true` if valid and not replayed, `false` otherwise.
 *
 * @example
 * ```ts
 * // With default memory store (anti-replay enabled)
 * const isValid = await validateOTP({
 *   userId: 'user@example.com',
 *   userProvidedOtp: '482913',
 *   secretKey: 'my-super-secret',
 *   ttlSeconds: 300,
 * });
 *
 * // With replay protection disabled (math-only)
 * const isValid = await validateOTP({
 *   userId: 'user@example.com',
 *   userProvidedOtp: '482913',
 *   secretKey: 'my-super-secret',
 *   ttlSeconds: 300,
 *   store: false,
 * });
 * ```
 */
export async function validateOTP(
  options: ValidateOTPOptions,
): Promise<boolean> {
  const { userId, userProvidedOtp, secretKey, ttlSeconds, store } = options;

  // --- Input validation ---
  assertNonEmptyString(userId, 'userId');
  assertNonEmptyString(secretKey, 'secretKey');
  assertPositiveNumber(ttlSeconds, 'ttlSeconds');

  // The user-provided OTP must be a string of exactly 6 characters.
  if (typeof userProvidedOtp !== 'string' || userProvidedOtp.length !== OTP_DIGITS) {
    return false;
  }

  const userOtpBuffer = Buffer.from(userProvidedOtp, 'utf-8');
  if (userOtpBuffer.byteLength !== OTP_DIGITS) {
    return false;
  }

  // Check current, previous (-1), and next (+1) time blocks
  for (const offset of [-1, 0, 1]) {
    const timeBlock = getTimeBlock(ttlSeconds, offset);
    const expectedOtp = generateOTPForTimeBlock(userId, secretKey, timeBlock);
    const expectedBuffer = Buffer.from(expectedOtp, 'utf-8');

    // Timing-safe comparison to prevent side-channel attacks.
    // Both buffers are always exactly 6 bytes (UTF-8 digits), so lengths match.
    if (timingSafeEqual(userOtpBuffer, expectedBuffer)) {
      // --- Anti-replay check ---
      // If store is explicitly `false`, skip replay protection.
      if (store === false) {
        return true;
      }

      // Use provided store or fall back to the default memory store.
      const activeStore = store ?? defaultMemoryStore;
      return await activeStore.checkAndStore(userId, timeBlock, ttlSeconds);
    }
  }

  return false;
}
