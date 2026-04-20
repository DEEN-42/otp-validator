import { assertNonEmptyString, assertPositiveNumber, getTimeBlock, generateOTPForTimeBlock } from './core';

/**
 * Generates a 6-digit Time-Based One-Time Password (TOTP).
 *
 * The OTP is derived from the current time block, the user's identity,
 * and a shared secret key using HMAC-SHA256 + RFC 4226 dynamic truncation.
 *
 * @param userId     - A unique identifier for the user.
 * @param ttlSeconds - The validity window of the OTP in seconds.
 * @param secretKey  - The backend's private secret used for hashing.
 * @returns A 6-digit OTP string (zero-padded).
 *
 * @example
 * ```ts
 * const otp = generateOTP('user@example.com', 300, 'my-super-secret');
 * console.log(otp); // e.g. "482913"
 * ```
 */
export function generateOTP(
  userId: string,
  ttlSeconds: number,
  secretKey: string,
): string {
  // --- Input validation ---
  assertNonEmptyString(userId, 'userId');
  assertPositiveNumber(ttlSeconds, 'ttlSeconds');
  assertNonEmptyString(secretKey, 'secretKey');

  const timeBlock = getTimeBlock(ttlSeconds);
  return generateOTPForTimeBlock(userId, secretKey, timeBlock);
}
