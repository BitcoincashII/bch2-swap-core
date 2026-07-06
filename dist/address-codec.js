import { sha256 } from '@noble/hashes/sha256';
import { ripemd160 } from '@noble/hashes/ripemd160';

// src/address-codec.ts
var CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
var CHARSET_MAP = {};
for (let i = 0; i < CHARSET.length; i++) {
  CHARSET_MAP[CHARSET[i]] = i;
}
var BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
function hash160(data) {
  return ripemd160(sha256(data));
}
function doubleHash(data) {
  return sha256(sha256(data));
}
function cashAddrPolymod(values) {
  const GENERATORS = [0x98f2bc8e61n, 0x79b76d99e2n, 0xf33e5fb3c4n, 0xae2eabe2a8n, 0x1e4f43e470n];
  let chk = 1n;
  for (const value of values) {
    const top = chk >> 35n;
    chk = (chk & 0x07ffffffffn) << 5n ^ BigInt(value);
    for (let i = 0; i < 5; i++) {
      if (top >> BigInt(i) & 1n) {
        chk ^= GENERATORS[i];
      }
    }
  }
  return chk;
}
function prefixToValues(prefix) {
  const values = [];
  for (let i = 0; i < prefix.length; i++) {
    values.push(prefix.charCodeAt(i) & 31);
  }
  values.push(0);
  return values;
}
function packAddrData(hash, type) {
  let encodedSize = 0;
  switch (hash.length) {
    case 20:
      encodedSize = 0;
      break;
    case 24:
      encodedSize = 1;
      break;
    case 28:
      encodedSize = 2;
      break;
    case 32:
      encodedSize = 3;
      break;
    case 40:
      encodedSize = 4;
      break;
    case 48:
      encodedSize = 5;
      break;
    case 56:
      encodedSize = 6;
      break;
    case 64:
      encodedSize = 7;
      break;
    default:
      throw new Error("Invalid hash size for CashAddr: " + hash.length);
  }
  const versionByte = type << 3 | encodedSize;
  const payload = [];
  let acc = versionByte;
  let bits = 8;
  for (let i = 0; i < hash.length; i++) {
    acc = acc << 8 | hash[i];
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      payload.push(acc >> bits & 31);
    }
  }
  if (bits > 0) {
    payload.push(acc << 5 - bits & 31);
  }
  return payload;
}
function encodeCashAddr(prefix, type, hash) {
  const prefixValues = prefixToValues(prefix);
  const payload = packAddrData(hash, type);
  const checksumInput = [...prefixValues, ...payload, 0, 0, 0, 0, 0, 0, 0, 0];
  const polymod = cashAddrPolymod(checksumInput) ^ 1n;
  const checksumArray = [];
  for (let i = 0; i < 8; i++) {
    checksumArray.push(Number(polymod >> BigInt(5 * (7 - i)) & 0x1fn));
  }
  const combined = [...payload, ...checksumArray];
  let result = prefix + ":";
  for (const value of combined) {
    result += CHARSET[value];
  }
  return result;
}
function decodeCashAddr(address) {
  const lowered = address.toLowerCase();
  const colonIndex = lowered.indexOf(":");
  let prefix;
  let payload;
  if (colonIndex === -1) {
    prefix = "bitcoincashii";
    payload = lowered;
  } else {
    prefix = lowered.slice(0, colonIndex);
    payload = lowered.slice(colonIndex + 1);
  }
  const values = [];
  for (let i = 0; i < payload.length; i++) {
    const value = CHARSET_MAP[payload[i]];
    if (value === void 0) return null;
    values.push(value);
  }
  const prefixValues = prefixToValues(prefix);
  const checksumInput = [...prefixValues, ...values];
  if (cashAddrPolymod(checksumInput) !== 1n) return null;
  const data = values.slice(0, -8);
  let acc = 0;
  let bits = 0;
  let versionByte = 0;
  let versionExtracted = false;
  const hashBytes = [];
  for (let i = 0; i < data.length; i++) {
    acc = acc << 5 | data[i];
    bits += 5;
    if (!versionExtracted && bits >= 8) {
      bits -= 8;
      versionByte = acc >> bits & 255;
      versionExtracted = true;
    }
    while (versionExtracted && bits >= 8) {
      bits -= 8;
      hashBytes.push(acc >> bits & 255);
    }
  }
  if (bits > 0 && (acc & (1 << bits) - 1) !== 0) return null;
  const type = versionByte >> 3;
  if (type !== 0 && type !== 1) return null;
  const encodedSize = versionByte & 7;
  const expectedSizes = [20, 24, 28, 32, 40, 48, 56, 64];
  const expectedSize = expectedSizes[encodedSize];
  if (expectedSize === void 0) return null;
  if (hashBytes.length < expectedSize) return null;
  const hash = new Uint8Array(hashBytes.slice(0, expectedSize));
  return { prefix, type, hash };
}
function encodeBase58(data) {
  let num = 0n;
  for (let i = 0; i < data.length; i++) {
    num = num * 256n + BigInt(data[i]);
  }
  let result = "";
  while (num > 0n) {
    const remainder = Number(num % 58n);
    num = num / 58n;
    result = BASE58_ALPHABET[remainder] + result;
  }
  for (let i = 0; i < data.length && data[i] === 0; i++) {
    result = "1" + result;
  }
  return result;
}
function decodeBase58(str) {
  let num = 0n;
  for (let i = 0; i < str.length; i++) {
    const index = BASE58_ALPHABET.indexOf(str[i]);
    if (index === -1) return null;
    num = num * 58n + BigInt(index);
  }
  const bytes = [];
  while (num > 0n) {
    bytes.unshift(Number(num % 256n));
    num = num / 256n;
  }
  for (let i = 0; i < str.length && str[i] === "1"; i++) {
    bytes.unshift(0);
  }
  return new Uint8Array(bytes);
}
function encodeLegacyAddress(pubkeyHash) {
  const versioned = new Uint8Array([0, ...pubkeyHash]);
  const checksum = doubleHash(versioned).slice(0, 4);
  const full = new Uint8Array([...versioned, ...checksum]);
  return encodeBase58(full);
}
function decodeLegacyAddress(address) {
  const decoded = decodeBase58(address);
  if (!decoded || decoded.length !== 25) return null;
  if (decoded[0] !== 0 && decoded[0] !== 5) return null;
  const versioned = decoded.slice(0, 21);
  const checksum = decoded.slice(21);
  const expectedChecksum = doubleHash(versioned).slice(0, 4);
  for (let i = 0; i < 4; i++) {
    if (checksum[i] !== expectedChecksum[i]) return null;
  }
  return decoded.slice(1, 21);
}
function pubkeyToBCH2Address(pubkey) {
  const pubkeyHash = hash160(pubkey);
  return encodeCashAddr("bitcoincashii", 0, pubkeyHash);
}
function pubkeyToBC2Address(pubkey) {
  const pubkeyHash = hash160(pubkey);
  return encodeLegacyAddress(pubkeyHash);
}
function decodeWIF(wif) {
  const decoded = decodeBase58(wif);
  if (!decoded) return null;
  const data = decoded.slice(0, -4);
  const checksum = decoded.slice(-4);
  const expectedChecksum = sha256(sha256(data)).slice(0, 4);
  for (let i = 0; i < 4; i++) {
    if (checksum[i] !== expectedChecksum[i]) return null;
  }
  if (data[0] !== 128) return null;
  if (data.length === 34 && data[33] === 1) {
    return { privateKey: data.slice(1, 33), compressed: true };
  } else if (data.length === 33) {
    return { privateKey: data.slice(1, 33), compressed: false };
  }
  return null;
}
function encodeWIF(privateKey, compressed = true) {
  const data = compressed ? new Uint8Array([128, ...privateKey, 1]) : new Uint8Array([128, ...privateKey]);
  const checksum = sha256(sha256(data)).slice(0, 4);
  const full = new Uint8Array([...data, ...checksum]);
  return encodeBase58(full);
}
var BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
function bech32Polymod(values) {
  const GENERATOR = [996825010, 642813549, 513874426, 1027748829, 705979059];
  let chk = 1;
  for (const value of values) {
    const top = chk >> 25;
    chk = (chk & 33554431) << 5 ^ value;
    for (let i = 0; i < 5; i++) {
      if (top >> i & 1) {
        chk ^= GENERATOR[i];
      }
    }
  }
  return chk;
}
function bech32HrpExpand(hrp) {
  const result = [];
  for (const char of hrp) {
    result.push(char.charCodeAt(0) >> 5);
  }
  result.push(0);
  for (const char of hrp) {
    result.push(char.charCodeAt(0) & 31);
  }
  return result;
}
function bech32Checksum(hrp, data) {
  const values = [...bech32HrpExpand(hrp), ...data, 0, 0, 0, 0, 0, 0];
  const polymod = bech32Polymod(values) ^ 1;
  const checksum = [];
  for (let i = 0; i < 6; i++) {
    checksum.push(polymod >> 5 * (5 - i) & 31);
  }
  return checksum;
}
function verifyBech32Checksum(hrp, data) {
  return bech32Polymod([...bech32HrpExpand(hrp), ...data]) === 1;
}
function encodeBech32(hrp, version, data) {
  const converted = [version];
  let acc = 0;
  let bits = 0;
  for (const byte of data) {
    acc = acc << 8 | byte;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      converted.push(acc >> bits & 31);
    }
  }
  if (bits > 0) {
    converted.push(acc << 5 - bits & 31);
  }
  const checksum = bech32Checksum(hrp, converted);
  let result = hrp + "1";
  for (const value of [...converted, ...checksum]) {
    result += BECH32_CHARSET[value];
  }
  return result;
}
function decodeBech32(address) {
  const lower = address.toLowerCase();
  const pos = lower.lastIndexOf("1");
  if (pos < 1 || pos + 7 > lower.length) return null;
  const hrp = lower.slice(0, pos);
  const dataStr = lower.slice(pos + 1);
  const data = [];
  for (const char of dataStr) {
    const idx = BECH32_CHARSET.indexOf(char);
    if (idx === -1) return null;
    data.push(idx);
  }
  if (!verifyBech32Checksum(hrp, data)) return null;
  const payload = data.slice(0, -6);
  if (payload.length < 1) return null;
  const version = payload[0];
  const program = [];
  let acc = 0;
  let bits = 0;
  for (let i = 1; i < payload.length; i++) {
    acc = acc << 5 | payload[i];
    bits += 5;
    while (bits >= 8) {
      bits -= 8;
      program.push(acc >> bits & 255);
    }
  }
  if (bits > 0 && (acc & (1 << bits) - 1) !== 0) return null;
  return { hrp, version, program: new Uint8Array(program) };
}
function pubkeyToBech32Address(pubkey) {
  const pubkeyHash = hash160(pubkey);
  return encodeBech32("bc", 0, pubkeyHash);
}
function pubkeyToBCHAddress(pubkey) {
  const pubkeyHash = hash160(pubkey);
  return encodeCashAddr("bitcoincash", 0, pubkeyHash);
}
function pubkeyToBTCAddress(pubkey) {
  const pubkeyHash = hash160(pubkey);
  return encodeBech32("bc", 0, pubkeyHash);
}
function isBech32Address(address) {
  return address.toLowerCase().startsWith("bc1");
}
function encodeBech32m(hrp, version, data) {
  const converted = [version];
  let acc = 0;
  let bits = 0;
  for (const byte of data) {
    acc = acc << 8 | byte;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      converted.push(acc >> bits & 31);
    }
  }
  if (bits > 0) {
    converted.push(acc << 5 - bits & 31);
  }
  const checksum = bech32mChecksum(hrp, converted);
  let result = hrp + "1";
  for (const value of [...converted, ...checksum]) {
    result += BECH32_CHARSET[value];
  }
  return result;
}
function bech32mChecksum(hrp, data) {
  const values = [...bech32HrpExpand(hrp), ...data, 0, 0, 0, 0, 0, 0];
  const polymod = bech32Polymod(values) ^ 734539939;
  const checksum = [];
  for (let i = 0; i < 6; i++) {
    checksum.push(polymod >> 5 * (5 - i) & 31);
  }
  return checksum;
}
function decodeBech32m(address) {
  const lower = address.toLowerCase();
  const pos = lower.lastIndexOf("1");
  if (pos < 1 || pos + 7 > lower.length) return null;
  const hrp = lower.slice(0, pos);
  const dataStr = lower.slice(pos + 1);
  const data = [];
  for (const char of dataStr) {
    const idx = BECH32_CHARSET.indexOf(char);
    if (idx === -1) return null;
    data.push(idx);
  }
  if (bech32Polymod([...bech32HrpExpand(hrp), ...data]) !== 734539939) return null;
  const payload = data.slice(0, -6);
  if (payload.length < 1) return null;
  const version = payload[0];
  if (version < 1) return null;
  const program = [];
  let acc2 = 0;
  let bits2 = 0;
  for (let i = 1; i < payload.length; i++) {
    acc2 = acc2 << 5 | payload[i];
    bits2 += 5;
    while (bits2 >= 8) {
      bits2 -= 8;
      program.push(acc2 >> bits2 & 255);
    }
  }
  if (bits2 > 0 && (acc2 & (1 << bits2) - 1) !== 0) return null;
  return { hrp, version, program: new Uint8Array(program) };
}
function xonlyPubkeyToP2TRAddress(xonlyPubkey) {
  return encodeBech32m("bc", 1, xonlyPubkey);
}
function p2trScripthash(xonlyTweakedPubkey) {
  const script = new Uint8Array([81, 32, ...xonlyTweakedPubkey]);
  const hash = sha256(script);
  const reversed = new Uint8Array(hash.length);
  for (let i = 0; i < hash.length; i++) {
    reversed[i] = hash[hash.length - 1 - i];
  }
  return Array.from(reversed).map((b) => b.toString(16).padStart(2, "0")).join("");
}
function pubkeyToP2SHP2WPKHAddress(pubkey) {
  const pubkeyHash = hash160(pubkey);
  const redeemScript = new Uint8Array([0, 20, ...pubkeyHash]);
  const scriptHash = hash160(redeemScript);
  const versioned = new Uint8Array([5, ...scriptHash]);
  const checksum = doubleHash(versioned).slice(0, 4);
  const full = new Uint8Array([...versioned, ...checksum]);
  return encodeBase58(full);
}
function p2pkScripthash(publicKey) {
  const pushByte = publicKey.length === 33 ? 33 : 65;
  const script = new Uint8Array([pushByte, ...publicKey, 172]);
  const hash = sha256(script);
  const reversed = new Uint8Array(hash.length);
  for (let i = 0; i < hash.length; i++) {
    reversed[i] = hash[hash.length - 1 - i];
  }
  return Array.from(reversed).map((b) => b.toString(16).padStart(2, "0")).join("");
}
function p2pkhScripthash(pubkeyHash) {
  const script = new Uint8Array([118, 169, 20, ...pubkeyHash, 136, 172]);
  const hash = sha256(script);
  const reversed = new Uint8Array(hash.length);
  for (let i = 0; i < hash.length; i++) {
    reversed[i] = hash[hash.length - 1 - i];
  }
  return Array.from(reversed).map((b) => b.toString(16).padStart(2, "0")).join("");
}
function p2wpkhScripthash(pubkeyHash) {
  const script = new Uint8Array([0, 20, ...pubkeyHash]);
  const hash = sha256(script);
  const reversed = new Uint8Array(hash.length);
  for (let i = 0; i < hash.length; i++) {
    reversed[i] = hash[hash.length - 1 - i];
  }
  return Array.from(reversed).map((b) => b.toString(16).padStart(2, "0")).join("");
}
function p2shP2wpkhScripthash(pubkeyHash) {
  const redeemScript = new Uint8Array([0, 20, ...pubkeyHash]);
  const scriptHash = hash160(redeemScript);
  const script = new Uint8Array([169, 20, ...scriptHash, 135]);
  const hash = sha256(script);
  const reversed = new Uint8Array(hash.length);
  for (let i = 0; i < hash.length; i++) {
    reversed[i] = hash[hash.length - 1 - i];
  }
  return Array.from(reversed).map((b) => b.toString(16).padStart(2, "0")).join("");
}
function bc1AddressToScripthash(address) {
  const decoded = decodeBech32(address);
  if (!decoded || decoded.version !== 0 || decoded.program.length !== 20) {
    return null;
  }
  return p2wpkhScripthash(decoded.program);
}

export { bc1AddressToScripthash, decodeBase58, decodeBech32, decodeBech32m, decodeCashAddr, decodeLegacyAddress, decodeWIF, encodeBase58, encodeBech32, encodeBech32m, encodeCashAddr, encodeLegacyAddress, encodeWIF, hash160, isBech32Address, p2pkScripthash, p2pkhScripthash, p2shP2wpkhScripthash, p2trScripthash, p2wpkhScripthash, pubkeyToBC2Address, pubkeyToBCH2Address, pubkeyToBCHAddress, pubkeyToBTCAddress, pubkeyToBech32Address, pubkeyToP2SHP2WPKHAddress, xonlyPubkeyToP2TRAddress };
