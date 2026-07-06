import { gcm } from '@noble/ciphers/aes.js';
import { pbkdf2 } from '@noble/hashes/pbkdf2';
import { sha256 } from '@noble/hashes/sha256';
import { randomBytes } from '@noble/hashes/utils';

// src/key-encryption.ts
var PBKDF2_ITERATIONS = 6e5;
var MIN_PBKDF2_ITERATIONS = 6e5;
var MAX_PBKDF2_ITERATIONS = 5e6;
function resolveIterations(stored) {
  return Math.min(
    Math.max(stored ?? MIN_PBKDF2_ITERATIONS, MIN_PBKDF2_ITERATIONS),
    MAX_PBKDF2_ITERATIONS
  );
}
function toBase64(buffer) {
  let binary = "";
  for (let i = 0; i < buffer.length; i++) {
    binary += String.fromCharCode(buffer[i]);
  }
  return btoa(binary);
}
function fromBase64(base64) {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}
function deriveKey(password, salt, iterations) {
  const encoder = new TextEncoder();
  const passwordBytes = encoder.encode(password);
  const key = pbkdf2(sha256, passwordBytes, salt, {
    c: iterations ?? PBKDF2_ITERATIONS,
    dkLen: 32
  });
  passwordBytes.fill(0);
  return key;
}
async function encryptMnemonic(mnemonic, password) {
  const encoder = new TextEncoder();
  const salt = randomBytes(32);
  const iv = randomBytes(12);
  const key = deriveKey(password, salt);
  const aes = gcm(key, iv);
  const plaintext = encoder.encode(mnemonic);
  const ciphertext = aes.encrypt(plaintext);
  plaintext.fill(0);
  key.fill(0);
  return {
    ciphertext: toBase64(ciphertext),
    iv: toBase64(iv),
    salt: toBase64(salt),
    iterations: PBKDF2_ITERATIONS,
    kdf: "pbkdf2-sha256"
  };
}
async function decryptMnemonic(encrypted, password) {
  const decoder = new TextDecoder();
  const iv = fromBase64(encrypted.iv);
  const salt = fromBase64(encrypted.salt);
  const ciphertext = fromBase64(encrypted.ciphertext);
  const kdf = encrypted.kdf ?? "pbkdf2-sha256";
  if (kdf !== "pbkdf2-sha256") {
    throw new Error("Invalid password");
  }
  const iters = resolveIterations(encrypted.iterations);
  const key = deriveKey(password, salt, iters);
  const aes = gcm(key, iv);
  try {
    const decrypted = aes.decrypt(ciphertext);
    key.fill(0);
    const mnemonic = decoder.decode(decrypted);
    decrypted.fill(0);
    return mnemonic;
  } catch {
    key.fill(0);
    throw new Error("Invalid password");
  }
}
function validatePassword(password) {
  if (password.length < 12) {
    return { valid: false, error: "Password must be at least 12 characters" };
  }
  if (password.length >= 16) {
    return { valid: true };
  }
  if (!/[A-Z]/.test(password)) {
    return { valid: false, error: "Password must contain an uppercase letter" };
  }
  if (!/[a-z]/.test(password)) {
    return { valid: false, error: "Password must contain a lowercase letter" };
  }
  if (!/[0-9]/.test(password)) {
    return { valid: false, error: "Password must contain a number" };
  }
  if (!/[ !@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?`~]/.test(password)) {
    return { valid: false, error: "Password must contain a special character (!@#$%^&*...)" };
  }
  return { valid: true };
}

export { MAX_PBKDF2_ITERATIONS, MIN_PBKDF2_ITERATIONS, PBKDF2_ITERATIONS, decryptMnemonic, encryptMnemonic, resolveIterations, validatePassword };
