/**
 * otp-validator-totp — Public API
 *
 * Re-exports all public types and functions from submodules.
 */

// Core OTP functions
export { generateOTP } from './generator';
export { validateOTP } from './validator';
export type { ValidateOTPOptions } from './validator';

// Anti-replay store (IoC adapter pattern)
export { MemoryStore, defaultMemoryStore } from './store';
export type { IStore } from './store';
