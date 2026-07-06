import * as bip39 from '@scure/bip39';
import { mnemonicToSeedSync } from '@scure/bip39';
import { wordlist } from '@scure/bip39/wordlists/english';
import { HDKey } from '@scure/bip32';
import { sha256 } from '@noble/hashes/sha256';
import { ripemd160 } from '@noble/hashes/ripemd160';
import * as secp256k12 from '@noble/secp256k1';
import { secp256k1 } from '@noble/curves/secp256k1';
import { keccak_256 } from '@noble/hashes/sha3';
import { bytesToHex } from '@noble/hashes/utils';
import { getAddress } from 'viem';

// src/wallet-core.ts
var CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
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
function pubkeyToP2SHP2WPKHAddress(pubkey) {
  const pubkeyHash = hash160(pubkey);
  const redeemScript = new Uint8Array([0, 20, ...pubkeyHash]);
  const scriptHash = hash160(redeemScript);
  const versioned = new Uint8Array([5, ...scriptHash]);
  const checksum = doubleHash(versioned).slice(0, 4);
  const full = new Uint8Array([...versioned, ...checksum]);
  return encodeBase58(full);
}
function evmAddressFromPubkey(publicKey) {
  const uncompressed = publicKey.length === 65 ? publicKey : secp256k1.ProjectivePoint.fromHex(publicKey).toRawBytes(false);
  const hash = keccak_256(uncompressed.subarray(1));
  return getAddress("0x" + bytesToHex(hash.subarray(hash.length - 20)));
}
function deriveEVMKey(mnemonic, index = 0, passphrase) {
  const seed = mnemonicToSeedSync(mnemonic, passphrase);
  let hdkey;
  try {
    hdkey = HDKey.fromMasterSeed(seed);
  } finally {
    seed.fill(0);
  }
  const node = hdkey.derive(`m/44'/60'/0'/0/${index}`);
  if (!node.privateKey || !node.publicKey) throw new Error("Failed to derive EVM key");
  return { privateKey: node.privateKey, publicKey: node.publicKey, address: evmAddressFromPubkey(node.publicKey) };
}

// src/wallet-core.ts
var BCH2_PATH = "m/44'/145'/0'/0/0";
var BCH_PATH = "m/44'/145'/0'/0/0";
var BC2_PATH = "m/44'/0'/0'/0/0";
var BTC_PATH = "m/84'/0'/0'/0/0";
var BC1_PATH = "m/84'/0'/0'/0/0";
var P2SH_SEGWIT_PATH = "m/49'/0'/0'/0/0";
function generateMnemonic2() {
  return bip39.generateMnemonic(wordlist, 128);
}
function validateMnemonic2(mnemonic) {
  return bip39.validateMnemonic(mnemonic, wordlist);
}
function mnemonicToSeed(mnemonic, passphrase) {
  return bip39.mnemonicToSeedSync(mnemonic, passphrase);
}
function deriveAddresses(mnemonic, passphrase) {
  const seed = mnemonicToSeed(mnemonic, passphrase);
  let hdkey;
  try {
    hdkey = HDKey.fromMasterSeed(seed);
  } finally {
    seed.fill(0);
  }
  const bch2Key = hdkey.derive(BCH2_PATH);
  if (!bch2Key.publicKey) throw new Error("Failed to derive BCH2 key");
  const bch2Address = pubkeyToBCH2Address(bch2Key.publicKey);
  const bchKey = hdkey.derive(BCH_PATH);
  if (!bchKey.publicKey) throw new Error("Failed to derive BCH key");
  const bchAddress = pubkeyToBCHAddress(bchKey.publicKey);
  const bc2Key = hdkey.derive(BC2_PATH);
  if (!bc2Key.publicKey) throw new Error("Failed to derive BC2 key");
  const bc2Address = pubkeyToBC2Address(bc2Key.publicKey);
  const btcKey = hdkey.derive(BTC_PATH);
  if (!btcKey.publicKey) throw new Error("Failed to derive BTC key");
  const btcAddress = pubkeyToBTCAddress(btcKey.publicKey);
  const bc1Key = hdkey.derive(BC1_PATH);
  if (!bc1Key.publicKey) throw new Error("Failed to derive BC1 key");
  const bc1Address = pubkeyToBech32Address(bc1Key.publicKey);
  const p2shKey = hdkey.derive(P2SH_SEGWIT_PATH);
  if (!p2shKey.publicKey) throw new Error("Failed to derive P2SH key");
  const p2shSegwitAddress = pubkeyToP2SHP2WPKHAddress(p2shKey.publicKey);
  const evmKey = deriveEVMKey(mnemonic, 0, passphrase);
  const evmAddress = evmKey.address;
  return {
    bch2: bch2Address,
    bch: bchAddress,
    bc2: bc2Address,
    btc: btcAddress,
    bc1: bc1Address,
    p2shSegwit: p2shSegwitAddress,
    evm: evmAddress
  };
}
function deriveKeyForSigning(mnemonic, chain, index = 0, passphrase) {
  const seed = mnemonicToSeed(mnemonic, passphrase);
  let hdkey;
  try {
    hdkey = HDKey.fromMasterSeed(seed);
  } finally {
    seed.fill(0);
  }
  let basePath;
  switch (chain) {
    case "bch2":
    case "bch":
      basePath = "m/44'/145'/0'";
      break;
    case "bc2":
      basePath = "m/44'/0'/0'";
      break;
    case "btc":
    case "bc1":
      basePath = "m/84'/0'/0'";
      break;
    case "p2sh-segwit":
      basePath = "m/49'/0'/0'";
      break;
    case "evm":
      basePath = "m/44'/60'/0'";
      break;
  }
  const fullPath = `${basePath}/0/${index}`;
  const derived = hdkey.derive(fullPath);
  if (!derived.privateKey || !derived.publicKey) {
    throw new Error("Failed to derive key");
  }
  let address;
  switch (chain) {
    case "bch2":
      address = pubkeyToBCH2Address(derived.publicKey);
      break;
    case "bch":
      address = pubkeyToBCHAddress(derived.publicKey);
      break;
    case "bc2":
      address = pubkeyToBC2Address(derived.publicKey);
      break;
    case "btc":
      address = pubkeyToBTCAddress(derived.publicKey);
      break;
    case "bc1":
      address = pubkeyToBech32Address(derived.publicKey);
      break;
    case "p2sh-segwit":
      address = pubkeyToP2SHP2WPKHAddress(derived.publicKey);
      break;
    case "evm":
      address = evmAddressFromPubkey(derived.publicKey);
      break;
  }
  return {
    privateKey: derived.privateKey,
    publicKey: derived.publicKey,
    address
  };
}
function deriveKeyForSigningByPath(mnemonic, path, passphrase) {
  const seed = mnemonicToSeed(mnemonic, passphrase);
  let hdkey;
  try {
    hdkey = HDKey.fromMasterSeed(seed);
  } finally {
    seed.fill(0);
  }
  const derived = hdkey.derive(path);
  if (!derived.privateKey || !derived.publicKey) {
    throw new Error("Failed to derive key for path: " + path);
  }
  let address;
  if (path.startsWith("m/84'")) {
    address = pubkeyToBech32Address(derived.publicKey);
  } else if (path.startsWith("m/49'")) {
    address = pubkeyToP2SHP2WPKHAddress(derived.publicKey);
  } else {
    address = pubkeyToBCH2Address(derived.publicKey);
  }
  return {
    privateKey: derived.privateKey,
    publicKey: derived.publicKey,
    address
  };
}
function deriveMultipleAddresses(mnemonic, chain, count = 20, passphrase) {
  const seed = mnemonicToSeed(mnemonic, passphrase);
  let hdkey;
  try {
    hdkey = HDKey.fromMasterSeed(seed);
  } finally {
    seed.fill(0);
  }
  let basePath;
  switch (chain) {
    case "bch2":
    case "bch":
      basePath = "m/44'/145'/0'";
      break;
    case "bc2":
      basePath = "m/44'/0'/0'";
      break;
    case "btc":
    case "bc1":
      basePath = "m/84'/0'/0'";
      break;
    case "p2sh-segwit":
      basePath = "m/49'/0'/0'";
      break;
  }
  const addresses = [];
  for (let i = 0; i < count; i++) {
    const derived = hdkey.derive(`${basePath}/0/${i}`);
    if (!derived.publicKey) continue;
    let address;
    switch (chain) {
      case "bch2":
        address = pubkeyToBCH2Address(derived.publicKey);
        break;
      case "bch":
        address = pubkeyToBCHAddress(derived.publicKey);
        break;
      case "bc2":
        address = pubkeyToBC2Address(derived.publicKey);
        break;
      case "btc":
        address = pubkeyToBTCAddress(derived.publicKey);
        break;
      case "bc1":
        address = pubkeyToBech32Address(derived.publicKey);
        break;
      case "p2sh-segwit":
        address = pubkeyToP2SHP2WPKHAddress(derived.publicKey);
        break;
    }
    addresses.push(address);
  }
  return addresses;
}
function formatMnemonicWords(mnemonic) {
  return mnemonic.trim().toLowerCase().split(/\s+/);
}
function sanitizeMnemonic(input) {
  return input.toLowerCase().replace(/[^a-z\s]/g, "").trim().replace(/\s+/g, " ");
}
function deriveFromWIF(wif) {
  const decoded = decodeWIF(wif);
  if (!decoded) return null;
  const { privateKey, compressed } = decoded;
  const publicKey = secp256k12.getPublicKey(privateKey, compressed);
  const pubkeyHash = hash160(publicKey);
  return {
    privateKey,
    publicKey,
    bch2Address: pubkeyToBCH2Address(publicKey),
    bc2Address: pubkeyToBC2Address(publicKey),
    bc1Address: pubkeyToBech32Address(publicKey),
    p2shSegwitAddress: pubkeyToP2SHP2WPKHAddress(publicKey),
    pubkeyHash,
    compressed
  };
}
function validateWIF(wif) {
  return decodeWIF(wif) !== null;
}

export { deriveAddresses, deriveFromWIF, deriveKeyForSigning, deriveKeyForSigningByPath, deriveMultipleAddresses, formatMnemonicWords, generateMnemonic2 as generateMnemonic, mnemonicToSeed, sanitizeMnemonic, validateMnemonic2 as validateMnemonic, validateWIF };
