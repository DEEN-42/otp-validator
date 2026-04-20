import { createHmac } from 'crypto';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** Number of digits in the generated OTP. */
export const OTP_DIGITS = 6;

/** Modulus used to extract the final N-digit code. */
export const OTP_MODULUS = 10 ** OTP_DIGITS;

// ---------------------------------------------------------------------------
// Input validation helpers
// ---------------------------------------------------------------------------

/**
 * Asserts that a value is a non-empty string.
 * @throws {TypeError} If the value is not a non-empty string.
 */
export function assertNonEmptyString(value: unknown, name: string): asserts value is string {
  if (typeof value !== 'string' || value.length === 0) {
    throw new TypeError(`${name} must be a non-empty string.`);
  }
}

/**
 * Asserts that a value is a positive finite number.
 * @throws {TypeError} If the value is not a positive finite number.
 */
export function assertPositiveNumber(value: unknown, name: string): asserts value is number {
  if (typeof value !== 'number' || !Number.isFinite(value) || value <= 0) {
    throw new TypeError(`${name} must be a positive number.`);
  }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/**
 * Computes the current time block for the given TTL.
 *
 * @param ttlSeconds - The validity window in seconds.
 * @param offset     - Optional offset applied to the time block (e.g. -1, 0, +1).
 * @returns The integer time block.
 */
export function getTimeBlock(ttlSeconds: number, offset: number = 0): number {
  return Math.floor(Date.now() / 1000 / ttlSeconds) + offset;
}

/**
 * Encodes a time block as an 8-byte (64-bit) Big Endian buffer.
 *
 * @param timeBlock - The integer time block to encode.
 * @returns A Buffer of length 8.
 */
export function timeBlockToBuffer(timeBlock: number): Buffer {
  const buf = Buffer.alloc(8);
  // Write as a 64-bit big-endian unsigned integer.
  // JavaScript bitwise operators work on 32 bits, so we split manually.
  const high = Math.floor(timeBlock / 0x100000000);
  const low = timeBlock >>> 0; // Ensure unsigned 32-bit
  buf.writeUInt32BE(high, 0);
  buf.writeUInt32BE(low, 4);
  return buf;
}

/**
 * Generates a 6-digit OTP for a specific time block.
 *
 * This is the core algorithm:
 *   1. Build the HMAC key from `secretKey + userId`.
 *   2. HMAC-SHA256(key, timeBuffer) → 32-byte hash.
 *   3. RFC 4226 Dynamic Truncation → 31-bit integer → mod 10^6 → zero-padded string.
 *
 * @param userId    - Unique user identifier.
 * @param ttlSeconds - Validity window (used only to calculate the time block when
 *                     `timeBlock` is not supplied directly by callers of this helper).
 * @param secretKey - Backend secret key.
 * @param timeBlock - The pre-computed time block.
 * @returns A 6-digit zero-padded OTP string.
 */
export function generateOTPForTimeBlock(
  userId: string,
  secretKey: string,
  timeBlock: number,
): string {
  // 1. Encode time block as 8-byte Big Endian buffer
  const timeBuffer = timeBlockToBuffer(timeBlock);

  // 2. Derive HMAC key by combining secretKey and userId
  const hmacKey = secretKey + userId;

  // 3. Compute HMAC-SHA256
  const hmac = createHmac('sha256', hmacKey);
  hmac.update(timeBuffer);
  const hash = hmac.digest(); // 32-byte Buffer

  // 4. RFC 4226 Dynamic Truncation
  //    - Take the last nibble (lower 4 bits of the last byte) as the offset.
  //    - Extract 4 bytes starting at that offset.
  //    - Mask the most-significant bit to get a 31-bit unsigned integer.
  const offset = hash[hash.length - 1] & 0x0f;
  const truncated =
    ((hash[offset] & 0x7f) << 24) |
    ((hash[offset + 1] & 0xff) << 16) |
    ((hash[offset + 2] & 0xff) << 8) |
    (hash[offset + 3] & 0xff);

  // 5. Reduce to 6 digits and zero-pad
  const code = truncated % OTP_MODULUS;
  return code.toString().padStart(OTP_DIGITS, '0');
}
