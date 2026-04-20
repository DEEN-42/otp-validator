/**
 * Test suite for otp-validator-totp
 *
 * Covers:
 *   - OTP generation (format, determinism, uniqueness)
 *   - OTP validation (happy path, wrong code, drift windows, edge cases)
 *   - Anti-replay protection via MemoryStore
 *   - Input validation / error handling
 */

import { generateOTP, validateOTP, MemoryStore } from './index';
import type { IStore } from './index';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Fix Date.now() to a specific timestamp for deterministic tests. */
function mockTime(epochMs: number): jest.SpyInstance {
  return jest.spyOn(Date, 'now').mockReturnValue(epochMs);
}

// A fixed timestamp: 2025-01-01T00:00:00Z = 1735689600000 ms
const FIXED_TIME_MS = 1735689600000;
const USER_ID = 'user@example.com';
const SECRET_KEY = 'super-secret-key-for-testing';
const TTL_SECONDS = 300; // 5-minute window

// ---------------------------------------------------------------------------
// generateOTP
// ---------------------------------------------------------------------------

describe('generateOTP', () => {
  afterEach(() => jest.restoreAllMocks());

  it('should return a string of exactly 6 digits', () => {
    mockTime(FIXED_TIME_MS);
    const otp = generateOTP(USER_ID, TTL_SECONDS, SECRET_KEY);
    expect(otp).toMatch(/^\d{6}$/);
  });

  it('should return the same OTP within the same time window', () => {
    const spy = mockTime(FIXED_TIME_MS);
    const otp1 = generateOTP(USER_ID, TTL_SECONDS, SECRET_KEY);

    spy.mockReturnValue(FIXED_TIME_MS + 10_000); // +10 s
    const otp2 = generateOTP(USER_ID, TTL_SECONDS, SECRET_KEY);

    expect(otp1).toBe(otp2);
  });

  it('should return a different OTP for a different time window', () => {
    const spy = mockTime(FIXED_TIME_MS);
    const otp1 = generateOTP(USER_ID, TTL_SECONDS, SECRET_KEY);

    // Jump ahead by more than one full TTL window (600 s = 2 windows)
    spy.mockReturnValue(FIXED_TIME_MS + TTL_SECONDS * 2 * 1000);
    const otp2 = generateOTP(USER_ID, TTL_SECONDS, SECRET_KEY);

    expect(otp1).not.toBe(otp2);
  });

  it('should return different OTPs for different userIds', () => {
    mockTime(FIXED_TIME_MS);
    const otp1 = generateOTP('alice@test.com', TTL_SECONDS, SECRET_KEY);
    const otp2 = generateOTP('bob@test.com', TTL_SECONDS, SECRET_KEY);
    expect(otp1).not.toBe(otp2);
  });

  it('should return different OTPs for different secret keys', () => {
    mockTime(FIXED_TIME_MS);
    const otp1 = generateOTP(USER_ID, TTL_SECONDS, 'secret-a');
    const otp2 = generateOTP(USER_ID, TTL_SECONDS, 'secret-b');
    expect(otp1).not.toBe(otp2);
  });

  it('should produce leading-zero-padded OTPs when needed', () => {
    mockTime(FIXED_TIME_MS);
    const otp = generateOTP(USER_ID, TTL_SECONDS, SECRET_KEY);
    expect(otp.length).toBe(6);
    expect(Number(otp)).not.toBeNaN();
  });

  // --- Input validation ---

  it('should throw TypeError for empty userId', () => {
    mockTime(FIXED_TIME_MS);
    expect(() => generateOTP('', TTL_SECONDS, SECRET_KEY)).toThrow(TypeError);
  });

  it('should throw TypeError for empty secretKey', () => {
    mockTime(FIXED_TIME_MS);
    expect(() => generateOTP(USER_ID, TTL_SECONDS, '')).toThrow(TypeError);
  });

  it('should throw TypeError for non-positive ttlSeconds', () => {
    mockTime(FIXED_TIME_MS);
    expect(() => generateOTP(USER_ID, 0, SECRET_KEY)).toThrow(TypeError);
    expect(() => generateOTP(USER_ID, -1, SECRET_KEY)).toThrow(TypeError);
  });

  it('should throw TypeError for non-string userId', () => {
    mockTime(FIXED_TIME_MS);
    expect(() => generateOTP(123 as any, TTL_SECONDS, SECRET_KEY)).toThrow(TypeError);
  });

  it('should throw TypeError for non-number ttlSeconds', () => {
    mockTime(FIXED_TIME_MS);
    expect(() => generateOTP(USER_ID, '300' as any, SECRET_KEY)).toThrow(TypeError);
  });
});

// ---------------------------------------------------------------------------
// validateOTP — Math Validation (store: false to isolate crypto logic)
// ---------------------------------------------------------------------------

describe('validateOTP — math validation', () => {
  afterEach(() => jest.restoreAllMocks());

  it('should return true for a valid OTP in the current window', async () => {
    mockTime(FIXED_TIME_MS);
    const otp = generateOTP(USER_ID, TTL_SECONDS, SECRET_KEY);
    const isValid = await validateOTP({
      userId: USER_ID,
      userProvidedOtp: otp,
      secretKey: SECRET_KEY,
      ttlSeconds: TTL_SECONDS,
      store: false,
    });
    expect(isValid).toBe(true);
  });

  it('should return false for an incorrect OTP', async () => {
    mockTime(FIXED_TIME_MS);
    const realOtp = generateOTP(USER_ID, TTL_SECONDS, SECRET_KEY);
    const wrongOtp = realOtp === '000000' ? '999999' : '000000';
    const isValid = await validateOTP({
      userId: USER_ID,
      userProvidedOtp: wrongOtp,
      secretKey: SECRET_KEY,
      ttlSeconds: TTL_SECONDS,
      store: false,
    });
    expect(isValid).toBe(false);
  });

  // --- Time-window drift ---

  it('should accept an OTP from the previous time block (-1 drift)', async () => {
    const spy = mockTime(FIXED_TIME_MS);
    const otp = generateOTP(USER_ID, TTL_SECONDS, SECRET_KEY);

    // Move time forward by exactly 1 full TTL window
    spy.mockReturnValue(FIXED_TIME_MS + TTL_SECONDS * 1000);

    const isValid = await validateOTP({
      userId: USER_ID,
      userProvidedOtp: otp,
      secretKey: SECRET_KEY,
      ttlSeconds: TTL_SECONDS,
      store: false,
    });
    expect(isValid).toBe(true);
  });

  it('should accept an OTP from the next time block (+1 drift)', async () => {
    const spy = mockTime(FIXED_TIME_MS + TTL_SECONDS * 1000);
    const futureOtp = generateOTP(USER_ID, TTL_SECONDS, SECRET_KEY);

    // Move time back to the previous window
    spy.mockReturnValue(FIXED_TIME_MS);

    const isValid = await validateOTP({
      userId: USER_ID,
      userProvidedOtp: futureOtp,
      secretKey: SECRET_KEY,
      ttlSeconds: TTL_SECONDS,
      store: false,
    });
    expect(isValid).toBe(true);
  });

  it('should reject an OTP from 2+ windows ago (fully expired)', async () => {
    const spy = mockTime(FIXED_TIME_MS);
    const otp = generateOTP(USER_ID, TTL_SECONDS, SECRET_KEY);

    // Move time forward by 3 full TTL windows (beyond the ±1 drift)
    spy.mockReturnValue(FIXED_TIME_MS + TTL_SECONDS * 3 * 1000);

    const isValid = await validateOTP({
      userId: USER_ID,
      userProvidedOtp: otp,
      secretKey: SECRET_KEY,
      ttlSeconds: TTL_SECONDS,
      store: false,
    });
    expect(isValid).toBe(false);
  });

  // --- Edge cases ---

  it('should return false for OTP with wrong length (too short)', async () => {
    mockTime(FIXED_TIME_MS);
    const result = await validateOTP({
      userId: USER_ID,
      userProvidedOtp: '12345',
      secretKey: SECRET_KEY,
      ttlSeconds: TTL_SECONDS,
      store: false,
    });
    expect(result).toBe(false);
  });

  it('should return false for OTP with wrong length (too long)', async () => {
    mockTime(FIXED_TIME_MS);
    const result = await validateOTP({
      userId: USER_ID,
      userProvidedOtp: '1234567',
      secretKey: SECRET_KEY,
      ttlSeconds: TTL_SECONDS,
      store: false,
    });
    expect(result).toBe(false);
  });

  it('should return false for empty OTP string', async () => {
    mockTime(FIXED_TIME_MS);
    const result = await validateOTP({
      userId: USER_ID,
      userProvidedOtp: '',
      secretKey: SECRET_KEY,
      ttlSeconds: TTL_SECONDS,
      store: false,
    });
    expect(result).toBe(false);
  });

  it('should return false for non-string OTP', async () => {
    mockTime(FIXED_TIME_MS);
    const result = await validateOTP({
      userId: USER_ID,
      userProvidedOtp: 123456 as any,
      secretKey: SECRET_KEY,
      ttlSeconds: TTL_SECONDS,
      store: false,
    });
    expect(result).toBe(false);
  });

  it('should throw TypeError for empty userId', async () => {
    mockTime(FIXED_TIME_MS);
    await expect(
      validateOTP({
        userId: '',
        userProvidedOtp: '123456',
        secretKey: SECRET_KEY,
        ttlSeconds: TTL_SECONDS,
        store: false,
      }),
    ).rejects.toThrow(TypeError);
  });

  it('should throw TypeError for empty secretKey', async () => {
    mockTime(FIXED_TIME_MS);
    await expect(
      validateOTP({
        userId: USER_ID,
        userProvidedOtp: '123456',
        secretKey: '',
        ttlSeconds: TTL_SECONDS,
        store: false,
      }),
    ).rejects.toThrow(TypeError);
  });

  it('should throw TypeError for non-positive ttlSeconds', async () => {
    mockTime(FIXED_TIME_MS);
    await expect(
      validateOTP({
        userId: USER_ID,
        userProvidedOtp: '123456',
        secretKey: SECRET_KEY,
        ttlSeconds: 0,
        store: false,
      }),
    ).rejects.toThrow(TypeError);
    await expect(
      validateOTP({
        userId: USER_ID,
        userProvidedOtp: '123456',
        secretKey: SECRET_KEY,
        ttlSeconds: -60,
        store: false,
      }),
    ).rejects.toThrow(TypeError);
  });

  it('should return false when OTP belongs to a different user', async () => {
    mockTime(FIXED_TIME_MS);
    const otp = generateOTP('alice@test.com', TTL_SECONDS, SECRET_KEY);
    const isValid = await validateOTP({
      userId: 'bob@test.com',
      userProvidedOtp: otp,
      secretKey: SECRET_KEY,
      ttlSeconds: TTL_SECONDS,
      store: false,
    });
    expect(isValid).toBe(false);
  });

  it('should return false when OTP was generated with a different secret', async () => {
    mockTime(FIXED_TIME_MS);
    const otp = generateOTP(USER_ID, TTL_SECONDS, 'secret-a');
    const isValid = await validateOTP({
      userId: USER_ID,
      userProvidedOtp: otp,
      secretKey: 'secret-b',
      ttlSeconds: TTL_SECONDS,
      store: false,
    });
    expect(isValid).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// validateOTP — Anti-Replay with MemoryStore
// ---------------------------------------------------------------------------

describe('validateOTP — anti-replay (MemoryStore)', () => {
  let store: MemoryStore;

  beforeEach(() => {
    store = new MemoryStore();
  });

  afterEach(() => {
    jest.restoreAllMocks();
    store.clear();
  });

  it('should accept an OTP on first use', async () => {
    mockTime(FIXED_TIME_MS);
    const otp = generateOTP(USER_ID, TTL_SECONDS, SECRET_KEY);

    const isValid = await validateOTP({
      userId: USER_ID,
      userProvidedOtp: otp,
      secretKey: SECRET_KEY,
      ttlSeconds: TTL_SECONDS,
      store,
    });
    expect(isValid).toBe(true);
  });

  it('should reject the same OTP on second use (replay attack)', async () => {
    mockTime(FIXED_TIME_MS);
    const otp = generateOTP(USER_ID, TTL_SECONDS, SECRET_KEY);

    // First use — should pass
    const first = await validateOTP({
      userId: USER_ID,
      userProvidedOtp: otp,
      secretKey: SECRET_KEY,
      ttlSeconds: TTL_SECONDS,
      store,
    });
    expect(first).toBe(true);

    // Second use — replay, should fail
    const second = await validateOTP({
      userId: USER_ID,
      userProvidedOtp: otp,
      secretKey: SECRET_KEY,
      ttlSeconds: TTL_SECONDS,
      store,
    });
    expect(second).toBe(false);
  });

  it('should allow a different user to use a valid OTP for their own account', async () => {
    mockTime(FIXED_TIME_MS);
    const otpAlice = generateOTP('alice@test.com', TTL_SECONDS, SECRET_KEY);
    const otpBob = generateOTP('bob@test.com', TTL_SECONDS, SECRET_KEY);

    const validAlice = await validateOTP({
      userId: 'alice@test.com',
      userProvidedOtp: otpAlice,
      secretKey: SECRET_KEY,
      ttlSeconds: TTL_SECONDS,
      store,
    });
    expect(validAlice).toBe(true);

    const validBob = await validateOTP({
      userId: 'bob@test.com',
      userProvidedOtp: otpBob,
      secretKey: SECRET_KEY,
      ttlSeconds: TTL_SECONDS,
      store,
    });
    expect(validBob).toBe(true);
  });

  it('should use the default memory store when store is omitted', async () => {
    mockTime(FIXED_TIME_MS);
    const otp = generateOTP(USER_ID, TTL_SECONDS, SECRET_KEY);

    // Omit store entirely → uses defaultMemoryStore
    const isValid = await validateOTP({
      userId: USER_ID,
      userProvidedOtp: otp,
      secretKey: SECRET_KEY,
      ttlSeconds: TTL_SECONDS,
    });
    expect(isValid).toBe(true);
  });

  it('should work with an async custom IStore', async () => {
    mockTime(FIXED_TIME_MS);
    const otp = generateOTP(USER_ID, TTL_SECONDS, SECRET_KEY);

    // A mock async store that always returns true (first use)
    const asyncStore: IStore = {
      checkAndStore: async () => true,
    };

    const isValid = await validateOTP({
      userId: USER_ID,
      userProvidedOtp: otp,
      secretKey: SECRET_KEY,
      ttlSeconds: TTL_SECONDS,
      store: asyncStore,
    });
    expect(isValid).toBe(true);
  });

  it('should reject when async custom IStore returns false', async () => {
    mockTime(FIXED_TIME_MS);
    const otp = generateOTP(USER_ID, TTL_SECONDS, SECRET_KEY);

    // A mock async store that always rejects (simulates replay)
    const asyncStore: IStore = {
      checkAndStore: async () => false,
    };

    const isValid = await validateOTP({
      userId: USER_ID,
      userProvidedOtp: otp,
      secretKey: SECRET_KEY,
      ttlSeconds: TTL_SECONDS,
      store: asyncStore,
    });
    expect(isValid).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// MemoryStore — unit tests
// ---------------------------------------------------------------------------

describe('MemoryStore', () => {
  let store: MemoryStore;

  beforeEach(() => {
    store = new MemoryStore();
  });

  afterEach(() => {
    jest.restoreAllMocks();
    store.clear();
  });

  it('should return true for first use of a (userId, timeBlock) pair', () => {
    mockTime(FIXED_TIME_MS);
    expect(store.checkAndStore(USER_ID, 100, TTL_SECONDS)).toBe(true);
  });

  it('should return false for duplicate (userId, timeBlock) pair', () => {
    mockTime(FIXED_TIME_MS);
    store.checkAndStore(USER_ID, 100, TTL_SECONDS);
    expect(store.checkAndStore(USER_ID, 100, TTL_SECONDS)).toBe(false);
  });

  it('should allow the same timeBlock for different users', () => {
    mockTime(FIXED_TIME_MS);
    expect(store.checkAndStore('alice', 100, TTL_SECONDS)).toBe(true);
    expect(store.checkAndStore('bob', 100, TTL_SECONDS)).toBe(true);
  });

  it('should allow the same user with a different timeBlock', () => {
    mockTime(FIXED_TIME_MS);
    expect(store.checkAndStore(USER_ID, 100, TTL_SECONDS)).toBe(true);
    expect(store.checkAndStore(USER_ID, 101, TTL_SECONDS)).toBe(true);
  });

  it('should re-allow a (userId, timeBlock) pair after expiry', () => {
    const spy = mockTime(FIXED_TIME_MS);
    store.checkAndStore(USER_ID, 100, TTL_SECONDS);

    // Fast-forward past expiry (3× TTL = 900s)
    spy.mockReturnValue(FIXED_TIME_MS + TTL_SECONDS * 3 * 1000 + 1);
    expect(store.checkAndStore(USER_ID, 100, TTL_SECONDS)).toBe(true);
  });

  it('should track the number of stored entries via size', () => {
    mockTime(FIXED_TIME_MS);
    expect(store.size).toBe(0);
    store.checkAndStore('a', 1, TTL_SECONDS);
    store.checkAndStore('b', 2, TTL_SECONDS);
    expect(store.size).toBe(2);
  });

  it('should clear all entries', () => {
    mockTime(FIXED_TIME_MS);
    store.checkAndStore('a', 1, TTL_SECONDS);
    store.checkAndStore('b', 2, TTL_SECONDS);
    store.clear();
    expect(store.size).toBe(0);
  });
});
