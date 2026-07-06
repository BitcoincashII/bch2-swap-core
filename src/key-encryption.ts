/**
 * AES-256-GCM Encryption for Wallet Keys
 * Uses pure JavaScript implementations for HTTP compatibility
 */

import { gcm } from '@noble/ciphers/aes.js';
import { pbkdf2 } from '@noble/hashes/pbkdf2';
import { sha256 } from '@noble/hashes/sha256';
import { randomBytes } from '@noble/hashes/utils';

export interface EncryptedData {
  ciphertext: string;  // Base64 encoded
  iv: string;          // Base64 encoded 96-bit IV
  salt: string;        // Base64 encoded 256-bit salt
  iterations: number;  // PBKDF2 iterations
  // L4: forward-compat KDF identifier. Absent on legacy records => 'pbkdf2-sha256'.
  // Sealing still uses pbkdf2-sha256 today; 'scrypt' is reserved for a future
  // migration so adding it later is non-breaking.
  kdf?: 'pbkdf2-sha256' | 'scrypt';
}

export const PBKDF2_ITERATIONS = 600000; // OWASP 2023 recommendation (current seal-time default)

/**
 * FROZEN clamp bounds for a stored `iterations` field (M2).
 *
 * These are HISTORICAL constants that MUST NEVER change: resolveIterations clamps
 * a stored count against THESE, not the live PBKDF2_ITERATIONS default. If the live
 * default is later raised, an old record sealed at 600k (or any value >= this floor)
 * must still decrypt — clamping against the live default would wrongly push old
 * counts UP and brick those records. The floor is the lowest count we ever sealed
 * with; the cap is an absolute anti-DoS ceiling.
 */
export const MIN_PBKDF2_ITERATIONS = 600_000;   // historical floor — never changes
export const MAX_PBKDF2_ITERATIONS = 5_000_000; // absolute anti-DoS ceiling

/**
 * Resolve the PBKDF2 iteration count to use for decrypting a stored record.
 *
 * The count MUST match the one used at SEAL time so a valid record always
 * derives the same key. The floor/cap here only defends against a TAMPERED
 * `iterations` field (attacker with localStorage write):
 *   - R114-UNL-003: floor to MIN_PBKDF2_ITERATIONS to prevent a KDF downgrade
 *     (e.g. attacker sets iterations:1 to enable offline brute-force).
 *   - R121-CFG-001: cap to MAX_PBKDF2_ITERATIONS to prevent DoS — an attacker who
 *     can write localStorage could set iterations:999_999_999 and hang the browser.
 *
 * M2: clamps against the FROZEN MIN/MAX constants, NOT the live PBKDF2_ITERATIONS,
 * so a valid stored value (including 600k) always decrypts regardless of what
 * PBKDF2_ITERATIONS later becomes.
 */
export function resolveIterations(stored: number | undefined): number {
  return Math.min(
    Math.max(stored ?? MIN_PBKDF2_ITERATIONS, MIN_PBKDF2_ITERATIONS),
    MAX_PBKDF2_ITERATIONS,
  );
}

function toBase64(buffer: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < buffer.length; i++) {
    binary += String.fromCharCode(buffer[i]);
  }
  return btoa(binary);
}

function fromBase64(base64: string): Uint8Array {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

function deriveKey(password: string, salt: Uint8Array, iterations?: number): Uint8Array {
  const encoder = new TextEncoder();
  const passwordBytes = encoder.encode(password);

  // PBKDF2 with SHA-256, 32-byte output for AES-256
  const key = pbkdf2(sha256, passwordBytes, salt, {
    c: iterations ?? PBKDF2_ITERATIONS,
    dkLen: 32,
  });

  // Security: Zero password bytes after key derivation
  passwordBytes.fill(0);

  return key;
}

export async function encryptMnemonic(
  mnemonic: string,
  password: string
): Promise<EncryptedData> {
  const encoder = new TextEncoder();
  const salt = randomBytes(32);
  const iv = randomBytes(12);

  const key = deriveKey(password, salt);
  const aes = gcm(key, iv);
  // I3: hold the plaintext buffer so it can be zeroed after encryption.
  const plaintext = encoder.encode(mnemonic);
  const ciphertext = aes.encrypt(plaintext);
  plaintext.fill(0);

  // Security: Zero derived key after use
  key.fill(0);

  return {
    ciphertext: toBase64(ciphertext),
    iv: toBase64(iv),
    salt: toBase64(salt),
    iterations: PBKDF2_ITERATIONS,
    kdf: 'pbkdf2-sha256',
  };
}

export async function decryptMnemonic(
  encrypted: EncryptedData,
  password: string
): Promise<string> {
  const decoder = new TextDecoder();
  const iv = fromBase64(encrypted.iv);
  const salt = fromBase64(encrypted.salt);
  const ciphertext = fromBase64(encrypted.ciphertext);

  // L4: legacy records have no `kdf` field and are pbkdf2-sha256. When a future
  // scrypt migration lands, branch on this to select the derivation. For now only
  // pbkdf2-sha256 is implemented, so anything else is an unknown/tampered record.
  const kdf = encrypted.kdf ?? 'pbkdf2-sha256';
  if (kdf !== 'pbkdf2-sha256') {
    throw new Error('Invalid password');
  }

  // R114-UNL-003 (floor) + R121-CFG-001 (cap) — see resolveIterations().
  const iters = resolveIterations(encrypted.iterations);
  const key = deriveKey(password, salt, iters);
  const aes = gcm(key, iv);

  try {
    const decrypted = aes.decrypt(ciphertext);
    // Security: Zero derived key after use
    key.fill(0);
    // I3: decode COPIES the bytes into a JS string, so wiping the plaintext
    // buffer afterward is safe and clears the last decrypted-secret copy.
    const mnemonic = decoder.decode(decrypted);
    decrypted.fill(0);
    return mnemonic;
  } catch {
    // Security: Zero derived key even on failure
    key.fill(0);
    throw new Error('Invalid password');
  }
}

export function validatePassword(password: string): { valid: boolean; error?: string } {
  if (password.length < 12) {
    return { valid: false, error: 'Password must be at least 12 characters' };
  }
  // I4: a long passphrase (>=16 chars) is accepted with ANY characters, so
  // diceware/space-separated phrases pass without needing the 4 character classes.
  if (password.length >= 16) {
    return { valid: true };
  }
  if (!/[A-Z]/.test(password)) {
    return { valid: false, error: 'Password must contain an uppercase letter' };
  }
  if (!/[a-z]/.test(password)) {
    return { valid: false, error: 'Password must contain a lowercase letter' };
  }
  if (!/[0-9]/.test(password)) {
    return { valid: false, error: 'Password must contain a number' };
  }
  // I4: space added to the special-character class so passphrases with spaces qualify.
  if (!/[ !@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?`~]/.test(password)) {
    return { valid: false, error: 'Password must contain a special character (!@#$%^&*...)' };
  }
  return { valid: true };
}
