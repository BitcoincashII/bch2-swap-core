/**
 * AES-256-GCM Encryption for Wallet Keys
 * Uses pure JavaScript implementations for HTTP compatibility
 */
interface EncryptedData {
    ciphertext: string;
    iv: string;
    salt: string;
    iterations: number;
    kdf?: 'pbkdf2-sha256' | 'scrypt';
}
declare const PBKDF2_ITERATIONS = 600000;
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
declare const MIN_PBKDF2_ITERATIONS = 600000;
declare const MAX_PBKDF2_ITERATIONS = 5000000;
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
declare function resolveIterations(stored: number | undefined): number;
declare function encryptMnemonic(mnemonic: string, password: string): Promise<EncryptedData>;
declare function decryptMnemonic(encrypted: EncryptedData, password: string): Promise<string>;
declare function validatePassword(password: string): {
    valid: boolean;
    error?: string;
};

export { type EncryptedData, MAX_PBKDF2_ITERATIONS, MIN_PBKDF2_ITERATIONS, PBKDF2_ITERATIONS, decryptMnemonic, encryptMnemonic, resolveIterations, validatePassword };
