/**
 * Address Encoding/Decoding for BCH2 (CashAddr) and BC2 (Legacy)
 */

import { sha256 } from '@noble/hashes/sha256';
import { ripemd160 } from '@noble/hashes/ripemd160';

// CashAddr character set
const CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
const CHARSET_MAP: Record<string, number> = {};
for (let i = 0; i < CHARSET.length; i++) {
  CHARSET_MAP[CHARSET[i]] = i;
}

// Base58 character set
const BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

export function hash160(data: Uint8Array): Uint8Array {
  return ripemd160(sha256(data));
}

function doubleHash(data: Uint8Array): Uint8Array {
  return sha256(sha256(data));
}

// CashAddr polymod for checksum
function cashAddrPolymod(values: number[]): bigint {
  const GENERATORS = [0x98f2bc8e61n, 0x79b76d99e2n, 0xf33e5fb3c4n, 0xae2eabe2a8n, 0x1e4f43e470n];
  let chk = 1n;
  for (const value of values) {
    const top = chk >> 35n;
    chk = ((chk & 0x07ffffffffn) << 5n) ^ BigInt(value);
    for (let i = 0; i < 5; i++) {
      if ((top >> BigInt(i)) & 1n) {
        chk ^= GENERATORS[i];
      }
    }
  }
  return chk;
}

function prefixToValues(prefix: string): number[] {
  const values: number[] = [];
  for (let i = 0; i < prefix.length; i++) {
    values.push(prefix.charCodeAt(i) & 0x1f);
  }
  values.push(0);
  return values;
}

function convert8to5(data: Uint8Array): number[] {
  const result: number[] = [];
  let buffer = 0;
  let bits = 0;

  for (let i = 0; i < data.length; i++) {
    buffer = (buffer << 8) | data[i];
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      result.push((buffer >> bits) & 0x1f);
    }
  }

  if (bits > 0) {
    result.push((buffer << (5 - bits)) & 0x1f);
  }

  return result;
}

function convert5to8(data: number[]): Uint8Array {
  const result: number[] = [];
  let buffer = 0;
  let bits = 0;

  for (let i = 0; i < data.length; i++) {
    buffer = (buffer << 5) | data[i];
    bits += 5;
    while (bits >= 8) {
      bits -= 8;
      result.push((buffer >> bits) & 0xff);
    }
  }

  return new Uint8Array(result);
}

/**
 * Pack an 8-bit version byte together with the hash into 5-bit groups.
 * This matches the CashAddr spec (and the BCH2 node's PackAddrData).
 *
 * version_byte = (type << 3) | encoded_size
 * For 20-byte hashes (P2PKH, P2SH): encoded_size = 0
 */
function packAddrData(hash: Uint8Array, type: number): number[] {
  let encodedSize = 0;
  switch (hash.length) {
    case 20: encodedSize = 0; break;
    case 24: encodedSize = 1; break;
    case 28: encodedSize = 2; break;
    case 32: encodedSize = 3; break;
    case 40: encodedSize = 4; break;
    case 48: encodedSize = 5; break;
    case 56: encodedSize = 6; break;
    case 64: encodedSize = 7; break;
    default: throw new Error('Invalid hash size for CashAddr: ' + hash.length);
  }

  const versionByte = (type << 3) | encodedSize;

  // Pack version byte (8 bits) + hash bytes into 5-bit groups
  const payload: number[] = [];
  let acc = versionByte;
  let bits = 8;

  for (let i = 0; i < hash.length; i++) {
    acc = (acc << 8) | hash[i];
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      payload.push((acc >> bits) & 0x1f);
    }
  }
  if (bits > 0) {
    payload.push((acc << (5 - bits)) & 0x1f);
  }

  return payload;
}

export function encodeCashAddr(prefix: string, type: number, hash: Uint8Array): string {
  const prefixValues = prefixToValues(prefix);
  const payload = packAddrData(hash, type);

  const checksumInput = [...prefixValues, ...payload, 0, 0, 0, 0, 0, 0, 0, 0];
  const polymod = cashAddrPolymod(checksumInput) ^ 1n;

  const checksumArray: number[] = [];
  for (let i = 0; i < 8; i++) {
    checksumArray.push(Number((polymod >> BigInt(5 * (7 - i))) & 0x1fn));
  }

  const combined = [...payload, ...checksumArray];
  let result = prefix + ':';
  for (const value of combined) {
    result += CHARSET[value];
  }

  return result;
}

export function decodeCashAddr(address: string): { prefix: string; type: number; hash: Uint8Array } | null {
  const lowered = address.toLowerCase();
  const colonIndex = lowered.indexOf(':');

  let prefix: string;
  let payload: string;

  if (colonIndex === -1) {
    prefix = 'bitcoincashii';
    payload = lowered;
  } else {
    prefix = lowered.slice(0, colonIndex);
    payload = lowered.slice(colonIndex + 1);
  }

  const values: number[] = [];
  for (let i = 0; i < payload.length; i++) {
    const value = CHARSET_MAP[payload[i]];
    if (value === undefined) return null;
    values.push(value);
  }

  const prefixValues = prefixToValues(prefix);
  const checksumInput = [...prefixValues, ...values];
  // cashAddrPolymod returns raw chk (without XOR). For a valid checksum,
  // the raw value must be 1 (since encode XORs with 1, verification yields 1).
  if (cashAddrPolymod(checksumInput) !== 1n) return null;

  const data = values.slice(0, -8);

  // Unpack: convert 5-bit groups back to 8-bit version byte + hash
  // The first 8 bits form the version byte, the rest is hash data
  let acc = 0;
  let bits = 0;
  let versionByte = 0;
  let versionExtracted = false;
  const hashBytes: number[] = [];

  for (let i = 0; i < data.length; i++) {
    acc = (acc << 5) | data[i];
    bits += 5;

    if (!versionExtracted && bits >= 8) {
      bits -= 8;
      versionByte = (acc >> bits) & 0xff;
      versionExtracted = true;
    }

    while (versionExtracted && bits >= 8) {
      bits -= 8;
      hashBytes.push((acc >> bits) & 0xff);
    }
  }

  // CashAddr spec: padding bits must be zero
  if (bits > 0 && (acc & ((1 << bits) - 1)) !== 0) return null;

  const type = versionByte >> 3;
  // Only P2PKH (type 0) and P2SH (type 1) are defined; reject reserved types
  if (type !== 0 && type !== 1) return null;
  const encodedSize = versionByte & 0x07;
  const expectedSizes = [20, 24, 28, 32, 40, 48, 56, 64];
  const expectedSize = expectedSizes[encodedSize];
  if (expectedSize === undefined) return null;
  if (hashBytes.length < expectedSize) return null;
  const hash = new Uint8Array(hashBytes.slice(0, expectedSize));

  return { prefix, type, hash };
}

export function encodeBase58(data: Uint8Array): string {
  let num = 0n;
  for (let i = 0; i < data.length; i++) {
    num = num * 256n + BigInt(data[i]);
  }

  let result = '';
  while (num > 0n) {
    const remainder = Number(num % 58n);
    num = num / 58n;
    result = BASE58_ALPHABET[remainder] + result;
  }

  // Add leading '1' for each leading zero byte
  for (let i = 0; i < data.length && data[i] === 0; i++) {
    result = '1' + result;
  }

  return result;
}

export function decodeBase58(str: string): Uint8Array | null {
  let num = 0n;
  for (let i = 0; i < str.length; i++) {
    const index = BASE58_ALPHABET.indexOf(str[i]);
    if (index === -1) return null;
    num = num * 58n + BigInt(index);
  }

  const bytes: number[] = [];
  while (num > 0n) {
    bytes.unshift(Number(num % 256n));
    num = num / 256n;
  }

  // Add leading zeros
  for (let i = 0; i < str.length && str[i] === '1'; i++) {
    bytes.unshift(0);
  }

  return new Uint8Array(bytes);
}

export function encodeLegacyAddress(pubkeyHash: Uint8Array): string {
  const versioned = new Uint8Array([0x00, ...pubkeyHash]);
  const checksum = doubleHash(versioned).slice(0, 4);
  const full = new Uint8Array([...versioned, ...checksum]);
  return encodeBase58(full);
}

export function decodeLegacyAddress(address: string): Uint8Array | null {
  const decoded = decodeBase58(address);
  if (!decoded || decoded.length !== 25) return null;

  // Validate version byte: 0x00 (P2PKH) or 0x05 (P2SH)
  if (decoded[0] !== 0x00 && decoded[0] !== 0x05) return null;

  const versioned = decoded.slice(0, 21);
  const checksum = decoded.slice(21);
  const expectedChecksum = doubleHash(versioned).slice(0, 4);

  for (let i = 0; i < 4; i++) {
    if (checksum[i] !== expectedChecksum[i]) return null;
  }

  return decoded.slice(1, 21);
}

export function pubkeyToBCH2Address(pubkey: Uint8Array): string {
  const pubkeyHash = hash160(pubkey);
  return encodeCashAddr('bitcoincashii', 0, pubkeyHash);
}

export function pubkeyToBC2Address(pubkey: Uint8Array): string {
  const pubkeyHash = hash160(pubkey);
  return encodeLegacyAddress(pubkeyHash);
}

// WIF (Wallet Import Format) decoding for BC2 private keys
export function decodeWIF(wif: string): { privateKey: Uint8Array; compressed: boolean } | null {
  const decoded = decodeBase58(wif);
  if (!decoded) return null;

  // Verify checksum
  const data = decoded.slice(0, -4);
  const checksum = decoded.slice(-4);
  const expectedChecksum = sha256(sha256(data)).slice(0, 4);

  for (let i = 0; i < 4; i++) {
    if (checksum[i] !== expectedChecksum[i]) return null;
  }

  // Check version byte (0x80 for mainnet)
  if (data[0] !== 0x80) return null;

  // Check if compressed (ends with 0x01)
  if (data.length === 34 && data[33] === 0x01) {
    return { privateKey: data.slice(1, 33), compressed: true };
  } else if (data.length === 33) {
    return { privateKey: data.slice(1, 33), compressed: false };
  }

  return null;
}

// Encode private key to WIF format
export function encodeWIF(privateKey: Uint8Array, compressed: boolean = true): string {
  const data = compressed
    ? new Uint8Array([0x80, ...privateKey, 0x01])
    : new Uint8Array([0x80, ...privateKey]);

  const checksum = sha256(sha256(data)).slice(0, 4);
  const full = new Uint8Array([...data, ...checksum]);
  return encodeBase58(full);
}

// ============================================================================
// Bech32 (SegWit bc1) Support
// ============================================================================

const BECH32_CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';

function bech32Polymod(values: number[]): number {
  const GENERATOR = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
  let chk = 1;

  for (const value of values) {
    const top = chk >> 25;
    chk = ((chk & 0x1ffffff) << 5) ^ value;
    for (let i = 0; i < 5; i++) {
      if ((top >> i) & 1) {
        chk ^= GENERATOR[i];
      }
    }
  }

  return chk;
}

function bech32HrpExpand(hrp: string): number[] {
  const result: number[] = [];
  for (const char of hrp) {
    result.push(char.charCodeAt(0) >> 5);
  }
  result.push(0);
  for (const char of hrp) {
    result.push(char.charCodeAt(0) & 31);
  }
  return result;
}

function bech32Checksum(hrp: string, data: number[]): number[] {
  const values = [...bech32HrpExpand(hrp), ...data, 0, 0, 0, 0, 0, 0];
  const polymod = bech32Polymod(values) ^ 1;

  const checksum: number[] = [];
  for (let i = 0; i < 6; i++) {
    checksum.push((polymod >> (5 * (5 - i))) & 31);
  }
  return checksum;
}

function verifyBech32Checksum(hrp: string, data: number[]): boolean {
  return bech32Polymod([...bech32HrpExpand(hrp), ...data]) === 1;
}

// Encode bech32 address (bc1...)
export function encodeBech32(hrp: string, version: number, data: Uint8Array): string {
  const converted: number[] = [version];
  let acc = 0;
  let bits = 0;

  for (const byte of data) {
    acc = (acc << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      converted.push((acc >> bits) & 0x1f);
    }
  }
  if (bits > 0) {
    converted.push((acc << (5 - bits)) & 0x1f);
  }

  const checksum = bech32Checksum(hrp, converted);

  let result = hrp + '1';
  for (const value of [...converted, ...checksum]) {
    result += BECH32_CHARSET[value];
  }

  return result;
}

// Decode bech32 address to get witness program
export function decodeBech32(address: string): { hrp: string; version: number; program: Uint8Array } | null {
  const lower = address.toLowerCase();
  const pos = lower.lastIndexOf('1');
  if (pos < 1 || pos + 7 > lower.length) return null;

  const hrp = lower.slice(0, pos);
  const dataStr = lower.slice(pos + 1);

  const data: number[] = [];
  for (const char of dataStr) {
    const idx = BECH32_CHARSET.indexOf(char);
    if (idx === -1) return null;
    data.push(idx);
  }

  if (!verifyBech32Checksum(hrp, data)) return null;

  const payload = data.slice(0, -6);
  if (payload.length < 1) return null;

  const version = payload[0];

  // Convert 5-bit to 8-bit
  const program: number[] = [];
  let acc = 0;
  let bits = 0;
  for (let i = 1; i < payload.length; i++) {
    acc = (acc << 5) | payload[i];
    bits += 5;
    while (bits >= 8) {
      bits -= 8;
      program.push((acc >> bits) & 0xff);
    }
  }

  // BIP173: padding bits must be zero
  if (bits > 0 && (acc & ((1 << bits) - 1)) !== 0) return null;

  return { hrp, version, program: new Uint8Array(program) };
}

// Convert pubkey to bc1 (Native SegWit P2WPKH) address
export function pubkeyToBech32Address(pubkey: Uint8Array): string {
  const pubkeyHash = hash160(pubkey);
  return encodeBech32('bc', 0, pubkeyHash);
}

// Convert pubkey to BCH CashAddr (bitcoincash: prefix) address
export function pubkeyToBCHAddress(pubkey: Uint8Array): string {
  const pubkeyHash = hash160(pubkey);
  return encodeCashAddr('bitcoincash', 0, pubkeyHash);
}

// Convert pubkey to BTC native SegWit (bc1q) address
// BTC uses bech32 P2WPKH with hrp 'bc', same encoding as BCH2 recovery addresses
export function pubkeyToBTCAddress(pubkey: Uint8Array): string {
  const pubkeyHash = hash160(pubkey);
  return encodeBech32('bc', 0, pubkeyHash);
}

// Check if address is bech32 (bc1...)
export function isBech32Address(address: string): boolean {
  return address.toLowerCase().startsWith('bc1');
}

// ============================================================================
// Bech32m (P2TR / Taproot bc1p...) Support — BIP350
// ============================================================================

// Bech32m encoding for P2TR (witness version >= 1)
export function encodeBech32m(hrp: string, version: number, data: Uint8Array): string {
  const converted: number[] = [version];
  let acc = 0;
  let bits = 0;
  for (const byte of data) {
    acc = (acc << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      converted.push((acc >> bits) & 0x1f);
    }
  }
  if (bits > 0) {
    converted.push((acc << (5 - bits)) & 0x1f);
  }
  const checksum = bech32mChecksum(hrp, converted);
  let result = hrp + '1';
  for (const value of [...converted, ...checksum]) {
    result += BECH32_CHARSET[value];
  }
  return result;
}

function bech32mChecksum(hrp: string, data: number[]): number[] {
  const values = [...bech32HrpExpand(hrp), ...data, 0, 0, 0, 0, 0, 0];
  const polymod = bech32Polymod(values) ^ 0x2bc830a3;
  const checksum: number[] = [];
  for (let i = 0; i < 6; i++) {
    checksum.push((polymod >> (5 * (5 - i))) & 31);
  }
  return checksum;
}

// Decode Bech32m (for P2TR bc1p... addresses)
export function decodeBech32m(address: string): { hrp: string; version: number; program: Uint8Array } | null {
  const lower = address.toLowerCase();
  const pos = lower.lastIndexOf('1');
  if (pos < 1 || pos + 7 > lower.length) return null;
  const hrp = lower.slice(0, pos);
  const dataStr = lower.slice(pos + 1);
  const data: number[] = [];
  for (const char of dataStr) {
    const idx = BECH32_CHARSET.indexOf(char);
    if (idx === -1) return null;
    data.push(idx);
  }
  // Bech32m checksum verification: polymod must equal 0x2bc830a3
  if (bech32Polymod([...bech32HrpExpand(hrp), ...data]) !== 0x2bc830a3) return null;
  const payload = data.slice(0, -6);
  if (payload.length < 1) return null;
  const version = payload[0];
  if (version < 1) return null; // Bech32m is for version >= 1
  const program: number[] = [];
  let acc2 = 0;
  let bits2 = 0;
  for (let i = 1; i < payload.length; i++) {
    acc2 = (acc2 << 5) | payload[i];
    bits2 += 5;
    while (bits2 >= 8) {
      bits2 -= 8;
      program.push((acc2 >> bits2) & 0xff);
    }
  }
  if (bits2 > 0 && (acc2 & ((1 << bits2) - 1)) !== 0) return null;
  return { hrp, version, program: new Uint8Array(program) };
}

// P2TR address from x-only pubkey (tweaked)
export function xonlyPubkeyToP2TRAddress(xonlyPubkey: Uint8Array): string {
  return encodeBech32m('bc', 1, xonlyPubkey);
}

// P2TR scripthash for Electrum queries
export function p2trScripthash(xonlyTweakedPubkey: Uint8Array): string {
  // P2TR scriptPubKey: OP_1 PUSH_32 <32-byte-tweaked-pubkey>
  const script = new Uint8Array([0x51, 0x20, ...xonlyTweakedPubkey]);
  const hash = sha256(script);
  const reversed = new Uint8Array(hash.length);
  for (let i = 0; i < hash.length; i++) {
    reversed[i] = hash[hash.length - 1 - i];
  }
  return Array.from(reversed).map(b => b.toString(16).padStart(2, '0')).join('');
}

// ============================================================================
// P2SH-P2WPKH (Wrapped SegWit 3xxx) Support
// ============================================================================

// Convert pubkey to P2SH-P2WPKH (3xxx) address
export function pubkeyToP2SHP2WPKHAddress(pubkey: Uint8Array): string {
  const pubkeyHash = hash160(pubkey);

  // redeemScript = OP_0 PUSH_20 <pubkeyhash>
  const redeemScript = new Uint8Array([0x00, 0x14, ...pubkeyHash]);

  // P2SH address = Base58Check(0x05 || HASH160(redeemScript))
  const scriptHash = hash160(redeemScript);
  const versioned = new Uint8Array([0x05, ...scriptHash]);
  const checksum = doubleHash(versioned).slice(0, 4);
  const full = new Uint8Array([...versioned, ...checksum]);
  return encodeBase58(full);
}

// ============================================================================
// Scripthash Calculations (for Electrum queries)
// ============================================================================

// Calculate scripthash for P2PK (raw public key) output
// Script: PUSH_33 <compressed-pubkey> OP_CHECKSIG
export function p2pkScripthash(publicKey: Uint8Array): string {
  const pushByte = publicKey.length === 33 ? 0x21 : 0x41;
  const script = new Uint8Array([pushByte, ...publicKey, 0xac]);
  const hash = sha256(script);
  const reversed = new Uint8Array(hash.length);
  for (let i = 0; i < hash.length; i++) {
    reversed[i] = hash[hash.length - 1 - i];
  }
  return Array.from(reversed).map(b => b.toString(16).padStart(2, '0')).join('');
}

// Calculate scripthash for P2PKH address
export function p2pkhScripthash(pubkeyHash: Uint8Array): string {
  const script = new Uint8Array([0x76, 0xa9, 0x14, ...pubkeyHash, 0x88, 0xac]);
  const hash = sha256(script);
  const reversed = new Uint8Array(hash.length);
  for (let i = 0; i < hash.length; i++) {
    reversed[i] = hash[hash.length - 1 - i];
  }
  return Array.from(reversed).map(b => b.toString(16).padStart(2, '0')).join('');
}

// Calculate scripthash for P2WPKH (bc1) address
export function p2wpkhScripthash(pubkeyHash: Uint8Array): string {
  // P2WPKH scriptPubKey: OP_0 PUSH_20 <20-byte-pubkeyhash>
  const script = new Uint8Array([0x00, 0x14, ...pubkeyHash]);
  const hash = sha256(script);
  const reversed = new Uint8Array(hash.length);
  for (let i = 0; i < hash.length; i++) {
    reversed[i] = hash[hash.length - 1 - i];
  }
  return Array.from(reversed).map(b => b.toString(16).padStart(2, '0')).join('');
}

// Calculate scripthash for P2SH-P2WPKH (3xxx) address
export function p2shP2wpkhScripthash(pubkeyHash: Uint8Array): string {
  // redeemScript = OP_0 PUSH_20 <pubkeyhash>
  const redeemScript = new Uint8Array([0x00, 0x14, ...pubkeyHash]);
  const scriptHash = hash160(redeemScript);

  // P2SH scriptPubKey = OP_HASH160 PUSH_20 <HASH160(redeemScript)> OP_EQUAL
  const script = new Uint8Array([0xa9, 0x14, ...scriptHash, 0x87]);
  const hash = sha256(script);
  const reversed = new Uint8Array(hash.length);
  for (let i = 0; i < hash.length; i++) {
    reversed[i] = hash[hash.length - 1 - i];
  }
  return Array.from(reversed).map(b => b.toString(16).padStart(2, '0')).join('');
}

// Get scripthash from bc1 address
export function bc1AddressToScripthash(address: string): string | null {
  const decoded = decodeBech32(address);
  if (!decoded || decoded.version !== 0 || decoded.program.length !== 20) {
    return null;
  }
  return p2wpkhScripthash(decoded.program);
}
