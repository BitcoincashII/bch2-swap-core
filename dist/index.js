import { sha256 } from '@noble/hashes/sha256';
import { ripemd160 } from '@noble/hashes/ripemd160';
import * as secp256k1 from '@noble/secp256k1';
import { gcm } from '@noble/ciphers/aes.js';
import { pbkdf2 } from '@noble/hashes/pbkdf2';
import { randomBytes } from '@noble/hashes/utils';

// src/swap-engine/state.ts
var State = /* @__PURE__ */ ((State2) => {
  State2[State2["Created"] = 0] = "Created";
  State2[State2["Prepared"] = 1] = "Prepared";
  State2[State2["Funded"] = 2] = "Funded";
  State2[State2["CounterpartyFunded"] = 3] = "CounterpartyFunded";
  State2[State2["Verified"] = 4] = "Verified";
  State2[State2["Revealed"] = 5] = "Revealed";
  State2[State2["Complete"] = 6] = "Complete";
  State2[State2["TimedOut"] = 7] = "TimedOut";
  State2[State2["Refunding"] = 8] = "Refunding";
  State2[State2["Refunded"] = 9] = "Refunded";
  State2[State2["Failed"] = 10] = "Failed";
  return State2;
})(State || {});
var Role = /* @__PURE__ */ ((Role2) => {
  Role2[Role2["Initiator"] = 0] = "Initiator";
  Role2[Role2["Responder"] = 1] = "Responder";
  return Role2;
})(Role || {});
function stateToString(s) {
  return State[s] ?? `State(${s})`;
}
function roleToString(r) {
  return Role[r] ?? `Role(${r})`;
}
function isTerminal(s) {
  return s === 6 /* Complete */ || s === 9 /* Refunded */ || s === 10 /* Failed */;
}
var ErrVerificationRequired = class extends Error {
  constructor(msg) {
    super(msg ?? "swapengine: verification gate must pass before this action");
    this.name = "ErrVerificationRequired";
  }
};
var ErrWrongState = class extends Error {
  constructor(msg) {
    super(msg ?? "swapengine: action not valid in current state");
    this.name = "ErrWrongState";
  }
};
var ErrWrongRole = class extends Error {
  constructor(msg) {
    super(msg ?? "swapengine: action not valid for this role");
    this.name = "ErrWrongRole";
  }
};
var ErrNoSecret = class extends Error {
  constructor(msg) {
    super(msg ?? "swapengine: secret not available");
    this.name = "ErrNoSecret";
  }
};
var ErrHashMismatch = class extends Error {
  constructor(msg) {
    super(msg ?? "swapengine: SHA256(secret) does not match agreed hashLock");
    this.name = "ErrHashMismatch";
  }
};
var ErrOutputNotFound = class extends Error {
  constructor(msg) {
    super(msg ?? "swapengine: P2SH output not found");
    this.name = "ErrOutputNotFound";
  }
};
var ErrTimelockOrdering = class extends Error {
  constructor(msg) {
    super(msg ?? "swapengine: timelock ordering violated: initiator CSV must be < responder CSV");
    this.name = "ErrTimelockOrdering";
  }
};
var ErrInsufficientConfirmations = class extends Error {
  constructor(msg) {
    super(msg ?? "swapengine: counterparty HTLC has insufficient confirmations");
    this.name = "ErrInsufficientConfirmations";
  }
};
var ErrAmountTooLow = class extends Error {
  constructor(msg) {
    super(msg ?? "swapengine: counterparty HTLC amount is below agreed minimum");
    this.name = "ErrAmountTooLow";
  }
};
var validTransitions = {
  [0 /* Initiator */]: {
    [0 /* Created */]: [1 /* Prepared */, 10 /* Failed */],
    [1 /* Prepared */]: [3 /* CounterpartyFunded */, 10 /* Failed */],
    [3 /* CounterpartyFunded */]: [4 /* Verified */, 10 /* Failed */],
    [4 /* Verified */]: [2 /* Funded */, 10 /* Failed */],
    [2 /* Funded */]: [6 /* Complete */, 7 /* TimedOut */, 10 /* Failed */],
    [7 /* TimedOut */]: [8 /* Refunding */, 10 /* Failed */],
    [8 /* Refunding */]: [9 /* Refunded */, 10 /* Failed */]
  },
  [1 /* Responder */]: {
    [0 /* Created */]: [1 /* Prepared */, 10 /* Failed */],
    [1 /* Prepared */]: [2 /* Funded */, 10 /* Failed */],
    [2 /* Funded */]: [3 /* CounterpartyFunded */, 7 /* TimedOut */, 10 /* Failed */],
    [3 /* CounterpartyFunded */]: [4 /* Verified */, 10 /* Failed */],
    [4 /* Verified */]: [5 /* Revealed */, 10 /* Failed */],
    [5 /* Revealed */]: [6 /* Complete */, 10 /* Failed */],
    [7 /* TimedOut */]: [8 /* Refunding */, 10 /* Failed */],
    [8 /* Refunding */]: [9 /* Refunded */, 10 /* Failed */]
  }
};
function isValidTransition(role, from, to) {
  const allowed = validTransitions[role][from];
  return allowed !== void 0 && allowed.includes(to);
}
function validateParams(p, role, requireCounterPubKey = true) {
  if (requireCounterPubKey && p.counterPubKey.length === 0) {
    throw new Error("swapengine: counterPubKey is required");
  }
  if (role === 0 /* Initiator */) {
    if (p.ourCSVNSequence >= p.counterCSVNSequence) {
      throw new ErrTimelockOrdering(
        `swapengine: timelock ordering violated: initiator nSequence ${p.ourCSVNSequence} must be < responder nSequence ${p.counterCSVNSequence}`
      );
    }
  }
}
function validateTimelockOrdering(p, role) {
  validateParams(p, role, false);
}
function swapIDFromHashLock(hashLock) {
  const h = sha256(hashLock);
  return Array.from(h.slice(0, 16)).map((b) => b.toString(16).padStart(2, "0")).join("");
}

// src/swap-engine/chains.ts
function toHex(b) {
  return Array.from(b).map((v) => v.toString(16).padStart(2, "0")).join("");
}
var MockUTXOChain = class {
  constructor() {
    this.outputs = /* @__PURE__ */ new Map();
    this.scanError = null;
  }
  /** Add a P2SH output keyed by txid + script hash. */
  addOutput(txid, scriptHash, satoshis, confs) {
    this.outputs.set(`${txid}|${toHex(scriptHash)}`, { satoshis, confs });
  }
  /** Update the confirmation count on an existing output. */
  setConfirmations(txid, scriptHash, confs) {
    const key = `${txid}|${toHex(scriptHash)}`;
    const out = this.outputs.get(key);
    if (!out) throw new Error(`MockUTXOChain: no output for key ${key}`);
    this.outputs.set(key, { ...out, confs });
  }
  /** Force scanForHTLC to return an error (simulates a probe failure). */
  setScanError(err) {
    this.scanError = err;
  }
  async getP2SHOutput(txid, scriptHash) {
    const key = `${txid}|${toHex(scriptHash)}`;
    const out = this.outputs.get(key);
    if (!out) throw new ErrOutputNotFound(`txid=${txid} scriptHash=${toHex(scriptHash)}`);
    return { satoshis: out.satoshis, confs: out.confs };
  }
  async scanForHTLC(scriptHash, expectedSat) {
    if (this.scanError) throw this.scanError;
    const shHex = toHex(scriptHash);
    for (const [key, out] of this.outputs.entries()) {
      const [txid, sh] = key.split("|");
      if (sh === shHex && out.satoshis === expectedSat) return txid;
    }
    return "";
  }
};
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
var HTLC_CSV_BLOCKS = 288;
var SIGHASH_ALL_FORKID = 65;
var SIGHASH_ALL = 1;
var DUST_SATOSHIS = 546;
var DEFAULT_FEE_SATOSHIS = 500;
var SEQ_LOCKTIME_TYPE_FLAG = 4194304;
var SEQ_LOCKTIME_GRANULARITY = 9;
var BCH_SWAP_BCH2_CSV_NSEQUENCE = (SEQ_LOCKTIME_TYPE_FLAG | 1) >>> 0;
var BCH_SWAP_BCH_CSV_NSEQUENCE = (SEQ_LOCKTIME_TYPE_FLAG | 2) >>> 0;
var MAINNET_BCH_SWAP_BCH2_CSV = (SEQ_LOCKTIME_TYPE_FLAG | 338) >>> 0;
var MAINNET_BCH_SWAP_BCH_CSV = (SEQ_LOCKTIME_TYPE_FLAG | 1182) >>> 0;
var MAINNET_BTC_SWAP_BCH2_CSV = (SEQ_LOCKTIME_TYPE_FLAG | 337) >>> 0;
var MAINNET_BTC_SWAP_BTC_CSV = (SEQ_LOCKTIME_TYPE_FLAG | 1687) >>> 0;
var MAINNET_BC2_SWAP_BCH2_CSV = (SEQ_LOCKTIME_TYPE_FLAG | 337) >>> 0;
var MAINNET_BC2_SWAP_BC2_CSV = (SEQ_LOCKTIME_TYPE_FLAG | 1687) >>> 0;
function buildRedeemScript(buyerPubKey, sellerPubKey, csvNSequence, hashLock) {
  return concat([
    new Uint8Array([99]),
    // OP_IF
    new Uint8Array([168]),
    // OP_SHA256
    pushData(hashLock),
    // push 32-byte hashLock
    new Uint8Array([136]),
    // OP_EQUALVERIFY
    pushData(buyerPubKey),
    // push buyerPubKey (33 bytes)
    new Uint8Array([172]),
    // OP_CHECKSIG
    new Uint8Array([103]),
    // OP_ELSE
    encodeCSV(csvNSequence),
    // minimal CSV push
    new Uint8Array([178]),
    // OP_CSV
    new Uint8Array([117]),
    // OP_DROP
    pushData(sellerPubKey),
    // push sellerPubKey (33 bytes)
    new Uint8Array([172]),
    // OP_CHECKSIG
    new Uint8Array([104])
    // OP_ENDIF
  ]);
}
function p2shScriptPubKey(redeemScript) {
  const h = hash160(redeemScript);
  return new Uint8Array([169, 20, ...h, 135]);
}
function p2pkhScriptPubKey(pubKey) {
  const h = hash160(pubKey);
  return new Uint8Array([118, 169, 20, ...h, 136, 172]);
}
async function buildClaimTx(prevTxID, prevVout, htlcSatoshis, redeemScript, buyerPrivKey, buyerPubKey, secret, sighashType) {
  if (secret.length === 0) throw new Error("secret must not be empty");
  const net = htlcSatoshis - DEFAULT_FEE_SATOSHIS;
  if (net < DUST_SATOSHIS) {
    throw new Error(`net output ${net} after fee is below dust threshold ${DUST_SATOSHIS}`);
  }
  const outputScript = p2pkhScriptPubKey(buyerPubKey);
  const sequence = 4294967295;
  const locktime = 0;
  const sighash = sighashType === SIGHASH_ALL ? legacySighashSingle(prevTxID, prevVout, sequence, redeemScript, net, outputScript, locktime, sighashType) : bip143Sighash(prevTxID, prevVout, sequence, redeemScript, htlcSatoshis, outputScript, net, locktime, sighashType);
  const sig = await ecdsaSign(sighash, buyerPrivKey, sighashType);
  const scriptSig = buildP2SHScriptSig(sig, secret, redeemScript);
  return buildRawTx(prevTxID, prevVout, scriptSig, sequence, outputScript, net, locktime);
}
async function buildRefundTx(prevTxID, prevVout, htlcSatoshis, redeemScript, sellerPrivKey, sellerPubKey, csvNSequence, sighashType) {
  const net = htlcSatoshis - DEFAULT_FEE_SATOSHIS;
  if (net < DUST_SATOSHIS) {
    throw new Error(`net output ${net} after fee is below dust threshold ${DUST_SATOSHIS}`);
  }
  const outputScript = p2pkhScriptPubKey(sellerPubKey);
  const sequence = csvNSequence >>> 0;
  const locktime = 0;
  const sighash = sighashType === SIGHASH_ALL ? legacySighashSingle(prevTxID, prevVout, sequence, redeemScript, net, outputScript, locktime, sighashType) : bip143Sighash(prevTxID, prevVout, sequence, redeemScript, htlcSatoshis, outputScript, net, locktime, sighashType);
  const sig = await ecdsaSign(sighash, sellerPrivKey, sighashType);
  const scriptSig = buildP2SHScriptSig(sig, null, redeemScript);
  return buildRawTx(prevTxID, prevVout, scriptSig, sequence, outputScript, net, locktime);
}
async function buildFundingTx(prevTxID, prevVout, inputSatoshis, funderPrivKey, funderPubKey, htlcRedeemScript, htlcSatoshis, feeSatoshis, sighashType) {
  const change = inputSatoshis - htlcSatoshis - feeSatoshis;
  if (change < DUST_SATOSHIS) {
    throw new Error(`change ${change} sat is below dust threshold ${DUST_SATOSHIS}`);
  }
  const outputs = [
    { amount: htlcSatoshis, script: p2shScriptPubKey(htlcRedeemScript) },
    { amount: change, script: p2pkhScriptPubKey(funderPubKey) }
  ];
  const sequence = 4294967295;
  const locktime = 0;
  const scriptCode = p2pkhScriptPubKey(funderPubKey);
  const sighash = sighashType === SIGHASH_ALL ? legacySighashOutputs(prevTxID, prevVout, sequence, scriptCode, outputs, locktime, sighashType) : bip143SighashOutputs(prevTxID, prevVout, sequence, scriptCode, inputSatoshis, outputs, locktime, sighashType);
  const sig = await ecdsaSign(sighash, funderPrivKey, sighashType);
  const scriptSig = buildP2PKHScriptSig(sig, funderPubKey);
  return buildRawTxOutputs(prevTxID, prevVout, scriptSig, sequence, outputs, locktime);
}
function extractSecretFromScriptSig(scriptSig) {
  let pos = 0;
  if (pos >= scriptSig.length) throw new Error("scriptSig too short: no sig push");
  const op0 = scriptSig[pos++];
  let sigLen;
  if (op0 >= 1 && op0 <= 75) {
    sigLen = op0;
  } else if (op0 === 76) {
    if (pos >= scriptSig.length) throw new Error("scriptSig truncated after OP_PUSHDATA1");
    sigLen = scriptSig[pos++];
  } else if (op0 === 77) {
    if (pos + 2 > scriptSig.length) throw new Error("scriptSig truncated after OP_PUSHDATA2");
    sigLen = scriptSig[pos] | scriptSig[pos + 1] << 8;
    pos += 2;
  } else {
    throw new Error(`unexpected scriptSig opcode 0x${op0.toString(16).padStart(2, "0")} at pos 0`);
  }
  if (pos + sigLen > scriptSig.length) throw new Error("scriptSig: sig data overflows buffer");
  pos += sigLen;
  if (pos >= scriptSig.length) throw new Error("scriptSig too short: no secret push");
  const op1 = scriptSig[pos++];
  let secretLen;
  if (op1 >= 1 && op1 <= 75) {
    secretLen = op1;
  } else if (op1 === 76) {
    if (pos >= scriptSig.length) throw new Error("scriptSig truncated in secret OP_PUSHDATA1");
    secretLen = scriptSig[pos++];
  } else {
    throw new Error(`unexpected secret push opcode 0x${op1.toString(16).padStart(2, "0")}`);
  }
  if (secretLen !== 32) throw new Error(`expected 32-byte secret, got ${secretLen} bytes`);
  if (pos + 32 > scriptSig.length) throw new Error("scriptSig: secret data overflows buffer");
  return scriptSig.slice(pos, pos + 32);
}
function pushData(data) {
  const n = data.length;
  if (n === 0) return new Uint8Array([0]);
  if (n <= 75) return concat([new Uint8Array([n]), data]);
  if (n <= 255) return concat([new Uint8Array([76, n]), data]);
  if (n <= 65535) return concat([new Uint8Array([77, n & 255, n >> 8 & 255]), data]);
  return concat([new Uint8Array([78, n & 255, n >> 8 & 255, n >> 16 & 255, n >> 24 & 255]), data]);
}
function encodeCSV(nSequence) {
  const n = nSequence >>> 0;
  if (n === 0) return new Uint8Array([0]);
  if (n <= 16) return new Uint8Array([80 + n]);
  return pushScriptInt(n);
}
function pushScriptInt(v) {
  if (v === 0) return new Uint8Array([0]);
  const bytes = [];
  let rem = v >>> 0;
  while (rem > 0) {
    bytes.push(rem & 255);
    rem = rem >>> 8;
  }
  if (bytes[bytes.length - 1] & 128) bytes.push(0);
  return pushData(new Uint8Array(bytes));
}
function legacySighashSingle(prevTxID, prevVout, sequence, scriptCode, outputAmount, outputScript, locktime, sighashType) {
  return dsha256(concat([
    le32(2),
    new Uint8Array([1]),
    prevTxID,
    le32(prevVout),
    varint(scriptCode.length),
    scriptCode,
    le32(sequence >>> 0),
    new Uint8Array([1]),
    le64(outputAmount),
    varint(outputScript.length),
    outputScript,
    le32(locktime),
    le32(sighashType)
  ]));
}
function legacySighashOutputs(prevTxID, prevVout, sequence, scriptCode, outputs, locktime, sighashType) {
  const outParts = outputs.flatMap((o) => [le64(o.amount), varint(o.script.length), o.script]);
  return dsha256(concat([
    le32(2),
    new Uint8Array([1]),
    prevTxID,
    le32(prevVout),
    varint(scriptCode.length),
    scriptCode,
    le32(sequence >>> 0),
    varint(outputs.length),
    concat(outParts),
    le32(locktime),
    le32(sighashType)
  ]));
}
function bip143Sighash(prevTxID, prevVout, sequence, scriptCode, inputAmount, outputScript, outputAmount, locktime, sighashType) {
  const hashPrevouts = dsha256(concat([prevTxID, le32(prevVout)]));
  const hashSequence = dsha256(le32(sequence >>> 0));
  const hashOutputs = dsha256(concat([le64(outputAmount), varint(outputScript.length), outputScript]));
  return dsha256(concat([
    le32(2),
    hashPrevouts,
    hashSequence,
    prevTxID,
    le32(prevVout),
    varint(scriptCode.length),
    scriptCode,
    le64(inputAmount),
    le32(sequence >>> 0),
    hashOutputs,
    le32(locktime),
    le32(sighashType)
  ]));
}
function bip143SighashOutputs(prevTxID, prevVout, sequence, scriptCode, inputAmount, outputs, locktime, sighashType) {
  const hashPrevouts = dsha256(concat([prevTxID, le32(prevVout)]));
  const hashSequence = dsha256(le32(sequence >>> 0));
  const hashOutputs = dsha256(concat(outputs.flatMap((o) => [le64(o.amount), varint(o.script.length), o.script])));
  return dsha256(concat([
    le32(2),
    hashPrevouts,
    hashSequence,
    prevTxID,
    le32(prevVout),
    varint(scriptCode.length),
    scriptCode,
    le64(inputAmount),
    le32(sequence >>> 0),
    hashOutputs,
    le32(locktime),
    le32(sighashType)
  ]));
}
function buildRawTx(prevTxID, prevVout, scriptSig, sequence, outputScript, outputAmount, locktime) {
  return concat([
    le32(2),
    new Uint8Array([1]),
    prevTxID,
    le32(prevVout),
    varint(scriptSig.length),
    scriptSig,
    le32(sequence >>> 0),
    new Uint8Array([1]),
    le64(outputAmount),
    varint(outputScript.length),
    outputScript,
    le32(locktime)
  ]);
}
function buildRawTxOutputs(prevTxID, prevVout, scriptSig, sequence, outputs, locktime) {
  return concat([
    le32(2),
    new Uint8Array([1]),
    prevTxID,
    le32(prevVout),
    varint(scriptSig.length),
    scriptSig,
    le32(sequence >>> 0),
    varint(outputs.length),
    concat(outputs.flatMap((o) => [le64(o.amount), varint(o.script.length), o.script])),
    le32(locktime)
  ]);
}
function buildP2SHScriptSig(sig, secret, redeemScript) {
  const parts = [pushData(sig)];
  if (secret !== null) {
    parts.push(pushData(secret));
    parts.push(new Uint8Array([81]));
  } else {
    parts.push(new Uint8Array([0]));
  }
  parts.push(pushData(redeemScript));
  return concat(parts);
}
function buildP2PKHScriptSig(sig, pubKey) {
  return concat([pushData(sig), pushData(pubKey)]);
}
async function ecdsaSign(sighash, privKey, sighashType) {
  try {
    const signature = await secp256k1.signAsync(sighash, privKey);
    const sigCompact = signature.toCompactRawBytes();
    const sigDer = compactToDER(sigCompact);
    return new Uint8Array([...sigDer, sighashType]);
  } finally {
    zeroBytes(privKey);
  }
}
function compactToDER(compact) {
  const r = compact.slice(0, 32);
  const s = compact.slice(32, 64);
  function encodeInt(b) {
    let start = 0;
    while (start < b.length - 1 && b[start] === 0) start++;
    const trimmed = b.slice(start);
    return trimmed[0] & 128 ? new Uint8Array([0, ...trimmed]) : trimmed;
  }
  const rEnc = encodeInt(r);
  const sEnc = encodeInt(s);
  const totalLen = 2 + rEnc.length + 2 + sEnc.length;
  const der = new Uint8Array(2 + totalLen);
  let pos = 0;
  der[pos++] = 48;
  der[pos++] = totalLen;
  der[pos++] = 2;
  der[pos++] = rEnc.length;
  der.set(rEnc, pos);
  pos += rEnc.length;
  der[pos++] = 2;
  der[pos++] = sEnc.length;
  der.set(sEnc, pos);
  return der;
}
function zeroBytes(arr) {
  crypto.getRandomValues(arr);
  arr.fill(0);
}
function le32(v) {
  const n = v >>> 0;
  return new Uint8Array([n & 255, n >> 8 & 255, n >> 16 & 255, n >> 24 & 255]);
}
function le64(v) {
  const lo = v >>> 0;
  const hi = Math.floor(v / 4294967296) >>> 0;
  return new Uint8Array([
    lo & 255,
    lo >> 8 & 255,
    lo >> 16 & 255,
    lo >> 24 & 255,
    hi & 255,
    hi >> 8 & 255,
    hi >> 16 & 255,
    hi >> 24 & 255
  ]);
}
function varint(n) {
  if (n < 253) return new Uint8Array([n]);
  if (n <= 65535) return new Uint8Array([253, n & 255, n >> 8 & 255]);
  if (n <= 4294967295) return new Uint8Array([254, n & 255, n >> 8 & 255, n >> 16 & 255, n >> 24 & 255]);
  throw new Error(`varint value too large: ${n}`);
}
function dsha256(data) {
  return sha256(sha256(data));
}
function concat(parts) {
  const total = parts.reduce((s, p) => s + p.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

// src/swap-engine/verify.ts
var VerificationGate = class {
  constructor(params, role, counterFundTxid, counterChain) {
    this.params = params;
    this.role = role;
    this.counterFundTxid = counterFundTxid;
    this.counterChain = counterChain;
  }
  /**
   * Runs all five checks in order:
   *   1. Timelock ordering
   *   2. Build expected P2SH hash from agreed params (H-derived, not counterparty-supplied)
   *   3. Query chain for the output — throws ErrOutputNotFound if absent or wrong structure
   *   4. Confirmation depth — throws ErrInsufficientConfirmations
   *   5. Amount — throws ErrAmountTooLow
   */
  async run() {
    validateTimelockOrdering(this.params, this.role);
    const redeemScript = buildRedeemScript(
      this.params.ourPubKey,
      this.params.counterPubKey,
      this.params.counterCSVNSequence,
      this.params.hashLock
    );
    const expectedHash = hash160(redeemScript);
    const { satoshis, confs } = await this.counterChain.getP2SHOutput(
      this.counterFundTxid,
      expectedHash
    );
    const minConfs = this.params.minConfirmations;
    if (confs < minConfs) {
      throw new ErrInsufficientConfirmations(
        `swapengine: counterparty HTLC has ${confs} confirmations, need ${minConfs}`
      );
    }
    if (satoshis < this.params.counterAmountSat) {
      throw new ErrAmountTooLow(
        `swapengine: counterparty HTLC has ${satoshis} sat, expected >= ${this.params.counterAmountSat}`
      );
    }
  }
};

// src/swap-engine/persist.ts
var LocalSwapStorage = class {
  constructor() {
    this.prefix = "bch2swap:";
  }
  save(swapID, record) {
    localStorage.setItem(this.prefix + swapID, JSON.stringify(record));
  }
  load(swapID) {
    const raw = localStorage.getItem(this.prefix + swapID);
    if (raw == null) return null;
    return parseRecord(raw);
  }
  loadAll() {
    const records = [];
    for (let i = 0; i < localStorage.length; i++) {
      const key = localStorage.key(i);
      if (!key?.startsWith(this.prefix)) continue;
      const raw = localStorage.getItem(key);
      if (!raw) continue;
      const rec = parseRecord(raw);
      if (rec) records.push(rec);
    }
    return records;
  }
  delete(swapID) {
    localStorage.removeItem(this.prefix + swapID);
  }
};
var MemorySwapStorage = class {
  constructor() {
    this.store = /* @__PURE__ */ new Map();
  }
  save(swapID, record) {
    this.store.set(swapID, JSON.parse(JSON.stringify(record)));
  }
  load(swapID) {
    const rec = this.store.get(swapID);
    if (!rec) return null;
    return JSON.parse(JSON.stringify(rec));
  }
  loadAll() {
    return Array.from(this.store.values()).map((r) => JSON.parse(JSON.stringify(r))).filter(isValidRecord);
  }
  delete(swapID) {
    this.store.delete(swapID);
  }
  /** Expose underlying map size for test assertions. */
  size() {
    return this.store.size;
  }
};
function loadSwapRecords(storage) {
  return storage.loadAll();
}
function deleteSwapRecord(storage, swapID) {
  storage.delete(swapID);
}
function parseRecord(raw) {
  try {
    const rec = JSON.parse(raw);
    if (!isValidRecord(rec)) return null;
    return rec;
  } catch {
    return null;
  }
}
function isValidRecord(r) {
  return typeof r.swapID === "string" && r.swapID !== "" && typeof r.ourPrivKey === "string" && r.ourPrivKey !== "" && typeof r.ourPubKey === "string" && r.ourPubKey !== "" && typeof r.hashLock === "string" && r.hashLock !== "" && typeof r.role === "number" && typeof r.state === "number";
}

// src/swap-engine/recover.ts
var RecoveryAction = /* @__PURE__ */ ((RecoveryAction2) => {
  RecoveryAction2[RecoveryAction2["None"] = 0] = "None";
  RecoveryAction2[RecoveryAction2["WaitForCounterparty"] = 1] = "WaitForCounterparty";
  RecoveryAction2[RecoveryAction2["VerifyAndFund"] = 2] = "VerifyAndFund";
  RecoveryAction2[RecoveryAction2["ClaimOrTimeout"] = 3] = "ClaimOrTimeout";
  RecoveryAction2[RecoveryAction2["Refund"] = 4] = "Refund";
  RecoveryAction2[RecoveryAction2["ConfirmRefund"] = 5] = "ConfirmRefund";
  return RecoveryAction2;
})(RecoveryAction || {});
function newFromRecord(rec, chain, storage, engineFactory) {
  return engineFactory(rec, chain, storage);
}
function determineRecoveryAction(role, state) {
  if (isTerminal(state)) return 0 /* None */;
  if (role === 0 /* Initiator */) {
    switch (state) {
      case 0 /* Created */:
      case 1 /* Prepared */:
        return 1 /* WaitForCounterparty */;
      case 3 /* CounterpartyFunded */:
        return 2 /* VerifyAndFund */;
      case 4 /* Verified */:
        return 2 /* VerifyAndFund */;
      case 2 /* Funded */:
        return 3 /* ClaimOrTimeout */;
      case 7 /* TimedOut */:
      case 8 /* Refunding */:
        return 4 /* Refund */;
      default:
        return 0 /* None */;
    }
  } else {
    switch (state) {
      case 0 /* Created */:
      case 1 /* Prepared */:
        return 1 /* WaitForCounterparty */;
      case 2 /* Funded */:
        return 1 /* WaitForCounterparty */;
      case 3 /* CounterpartyFunded */:
        return 2 /* VerifyAndFund */;
      case 4 /* Verified */:
        return 3 /* ClaimOrTimeout */;
      case 5 /* Revealed */:
        return 3 /* ClaimOrTimeout */;
      case 7 /* TimedOut */:
      case 8 /* Refunding */:
        return 4 /* Refund */;
      default:
        return 0 /* None */;
    }
  }
}
async function recoverAndResume(storage, chainFactory, resumeFn, engineFactory) {
  const records = storage.loadAll();
  const errors = [];
  for (const rec of records) {
    if (isTerminal(rec.state)) continue;
    const chain = chainFactory(rec.role, rec.swapID);
    if (!chain) continue;
    const engine = engineFactory(rec, chain, storage);
    const action = determineRecoveryAction(rec.role, rec.state);
    try {
      await resumeFn(engine, action);
    } catch (err) {
      errors.push(err instanceof Error ? err : new Error(String(err)));
    }
  }
  return errors;
}
function toHex2(b) {
  return Array.from(b).map((v) => v.toString(16).padStart(2, "0")).join("");
}
function fromHex(h) {
  if (h.length % 2 !== 0) throw new Error("fromHex: odd-length hex string");
  const buf = new Uint8Array(h.length / 2);
  for (let i = 0; i < buf.length; i++) {
    buf[i] = parseInt(h.slice(i * 2, i * 2 + 2), 16);
  }
  return buf;
}
function generateKeyPair() {
  while (true) {
    const privKey = new Uint8Array(32);
    crypto.getRandomValues(privKey);
    try {
      const pubKey = secp256k1.getPublicKey(privKey, true);
      return { privKey, pubKey };
    } catch {
    }
  }
}
var Engine = class _Engine {
  constructor(role, params, ourChain, storage) {
    this.role = role;
    this.params = { ...params };
    this.state = 0 /* Created */;
    this.swapID = "";
    this.ourPrivKey = new Uint8Array(0);
    this.secret = null;
    this.counterFundTxid = "";
    this.ourFundTxid = "";
    this.htlcScriptHash = new Uint8Array(20);
    this.verified = false;
    this.ourChain = ourChain ?? null;
    this.storage = storage ?? null;
  }
  // ── Getters ───────────────────────────────────────────────────────────────
  getState() {
    return this.state;
  }
  getRole() {
    return this.role;
  }
  getSwapID() {
    return this.swapID;
  }
  getOurFundTxid() {
    return this.ourFundTxid;
  }
  getHashLock() {
    return this.params.hashLock.slice();
  }
  getOurPubKey() {
    return this.params.ourPubKey.slice();
  }
  getHTLCScriptHash() {
    return this.htlcScriptHash.slice();
  }
  /**
   * Returns the private key. Throws ErrNoSecret if Prepare has not been called.
   * Caller receives a copy — the engine's copy is retained.
   */
  getPrivKey() {
    if (this.ourPrivKey.length === 0) throw new ErrNoSecret("swapengine: getPrivKey: prepare not called");
    return this.ourPrivKey.slice();
  }
  /**
   * Returns the revealed preimage. Throws ErrNoSecret if not yet known.
   */
  getSecret() {
    if (!this.secret) throw new ErrNoSecret("swapengine: secret not available");
    return this.secret.slice();
  }
  // ── Setters ───────────────────────────────────────────────────────────────
  setStorage(s) {
    this.storage = s;
  }
  setOurChain(c) {
    this.ourChain = c;
  }
  setCounterPubKey(pub) {
    this.params = { ...this.params, counterPubKey: pub };
  }
  // ── Core lifecycle ────────────────────────────────────────────────────────
  /**
   * Transitions Created → Prepared.
   * Generates an ephemeral secp256k1 key pair and (for initiator) a random
   * hashLock. Persists the new state.
   *
   * Returns a SwapProposal (initiator) or SwapResponse (responder) for the
   * peer. Caller is responsible for transmitting it.
   */
  async prepare() {
    this.transition(1 /* Prepared */);
    if (this.params.ourPubKey.length === 0) {
      const { privKey, pubKey } = generateKeyPair();
      this.ourPrivKey = privKey;
      this.params = { ...this.params, ourPubKey: pubKey };
    }
    if (this.role === 0 /* Initiator */) {
      const secret = new Uint8Array(32);
      crypto.getRandomValues(secret);
      this.secret = secret;
      const hashLock = sha256(secret);
      this.params = { ...this.params, hashLock };
      this.swapID = swapIDFromHashLock(hashLock);
      await this.persist();
      return {
        swapID: this.swapID,
        hashLock: toHex2(hashLock),
        initiatorPubKey: toHex2(this.params.ourPubKey),
        initiatorCSV: this.params.ourCSVNSequence,
        initiatorAmountSat: this.params.ourAmountSat,
        responderAmountSat: this.params.counterAmountSat,
        minConfirmations: this.params.minConfirmations,
        feeSatoshis: this.params.feeSatoshis
      };
    } else {
      this.swapID = swapIDFromHashLock(this.params.hashLock);
      await this.persist();
      return {
        swapID: this.swapID,
        responderPubKey: toHex2(this.params.ourPubKey),
        responderCSV: this.params.ourCSVNSequence
      };
    }
  }
  /**
   * Records that the counterparty has funded their HTLC.
   * Transitions Prepared → CounterpartyFunded (initiator) or
   *             Funded   → CounterpartyFunded (responder).
   */
  async notifyCounterpartyFunded(counterFundTxid) {
    if (this.role === 0 /* Initiator */ && this.state !== 1 /* Prepared */ || this.role === 1 /* Responder */ && this.state !== 2 /* Funded */) {
      throw new ErrWrongState(
        `swapengine: notifyCounterpartyFunded called in state ${State[this.state]}`
      );
    }
    this.counterFundTxid = counterFundTxid;
    this.transition(3 /* CounterpartyFunded */);
    await this.persist();
  }
  /**
   * Runs the verification gate against the counterparty's HTLC.
   * Transitions CounterpartyFunded → Verified.
   *
   * This is the unskippable gate before Fund().
   * Passing here is the only way to reach StateVerified.
   */
  async verify(counterChain) {
    if (this.state !== 3 /* CounterpartyFunded */) {
      throw new ErrWrongState(
        `swapengine: verify requires StateCounterpartyFunded, have ${State[this.state]}`
      );
    }
    if (this.counterFundTxid === "") {
      throw new ErrWrongState("swapengine: verify: counterFundTxid not set");
    }
    const gate = new VerificationGate(
      this.params,
      this.role,
      this.counterFundTxid,
      counterChain
    );
    await gate.run();
    this.verified = true;
    this.transition(4 /* Verified */);
    await this.persist();
  }
  /**
   * Funds our own HTLC.
   *
   * Initiator: requires StateVerified (gate is unskippable — no direct path from
   *            StateCounterpartyFunded or earlier).
   * Responder: requires StatePrepared.
   *
   * Double-fund probe (SEP-3): if ourChain is set, scanForHTLC is called first:
   *   - probe error   → return error; do NOT broadcast (safe = blocked)
   *   - HTLC found    → call recordFunded (idempotent); do NOT re-broadcast
   *   - HTLC absent   → call fundFn once, then transition to StateFunded
   *
   * scanForHTLC is passed ourAmountSat so the probe matches THIS swap's UTXO
   * and ignores any concurrent swap that shares the same P2SH script.
   *
   * @param htlcScriptHash 20-byte hash of our HTLC's redeemScript.
   * @param fundFn         Async callback that broadcasts the funding tx and
   *                       returns the txid.
   */
  async fund(htlcScriptHash, fundFn) {
    if (this.role === 0 /* Initiator */) {
      if (this.state !== 4 /* Verified */) {
        throw new ErrVerificationRequired(
          `swapengine: fund: initiator must pass verification gate first (state=${State[this.state]})`
        );
      }
    } else {
      if (this.state !== 1 /* Prepared */) {
        throw new ErrWrongState(
          `swapengine: fund: responder must be in StatePrepared (state=${State[this.state]})`
        );
      }
    }
    this.htlcScriptHash = htlcScriptHash;
    await this.persist();
    if (this.ourChain) {
      let existingTxid;
      try {
        existingTxid = await this.ourChain.scanForHTLC(htlcScriptHash, this.params.ourAmountSat);
      } catch (err) {
        return Promise.reject(err);
      }
      if (existingTxid !== "") {
        await this.recordFunded(existingTxid);
        return;
      }
    }
    const txid = await fundFn();
    await this.recordFunded(txid);
  }
  /**
   * Records a confirmed funding txid without re-broadcasting.
   * Idempotent: safe to call when the HTLC already exists on-chain.
   */
  async recordFunded(txid) {
    this.ourFundTxid = txid;
    this.transition(2 /* Funded */);
    await this.persist();
  }
  /**
   * Records the revealed preimage (responder learns it when initiator claims).
   * Validates SHA256(secret) == hashLock.
   * Responder transitions Verified → Revealed.
   */
  async setRevealedSecret(secret) {
    if (this.role !== 1 /* Responder */) {
      throw new ErrWrongRole("swapengine: setRevealedSecret is only valid for the responder role");
    }
    const h = sha256(secret);
    const hl = this.params.hashLock;
    if (h.length !== hl.length || !h.every((b, i) => b === hl[i])) {
      throw new ErrHashMismatch();
    }
    this.secret = secret;
    this.transition(5 /* Revealed */);
    await this.persist();
  }
  /** Marks the swap as Complete. */
  async claim() {
    this.transition(6 /* Complete */);
    await this.persist();
  }
  /** Initiator: claims the responder's HTLC using the preimage. */
  async claimAsInitiator() {
    if (this.role !== 0 /* Initiator */) {
      throw new ErrWrongRole("swapengine: claimAsInitiator is only valid for the initiator role");
    }
    if (!this.secret) throw new ErrNoSecret();
    await this.claim();
    return this.secret.slice();
  }
  /** Records that the counterparty's HTLC has timed out. */
  async timeout() {
    this.transition(7 /* TimedOut */);
    await this.persist();
  }
  /** Initiates the refund sequence. */
  async refund() {
    this.transition(8 /* Refunding */);
    await this.persist();
  }
  /** Confirms the refund transaction was mined. */
  async confirmRefund() {
    this.transition(9 /* Refunded */);
    await this.persist();
  }
  /**
   * Moves to StateFailed. No-op if already in a terminal state (mirrors Go
   * `Fail` which is a no-op on terminal states rather than returning an error).
   */
  async fail() {
    if (isTerminal(this.state)) return;
    this.transition(10 /* Failed */);
    await this.persist();
  }
  // ── Internal helpers ───────────────────────────────────────────────────────
  /**
   * Enforces the validTransitions table.
   * Throws ErrWrongState if the transition is not allowed.
   */
  transition(to) {
    if (!isValidTransition(this.role, this.state, to)) {
      throw new ErrWrongState(
        `swapengine: invalid transition ${State[this.state]} \u2192 ${State[to]} for role ${Role[this.role]}`
      );
    }
    this.state = to;
  }
  /**
   * Saves the current engine state to storage.
   * No-op when storage is null.
   */
  async persist() {
    if (!this.storage) return;
    const rec = {
      swapID: this.swapID,
      role: this.role,
      state: this.state,
      hashLock: toHex2(this.params.hashLock),
      ourPrivKey: toHex2(this.ourPrivKey),
      ourPubKey: toHex2(this.params.ourPubKey),
      counterPubKey: toHex2(this.params.counterPubKey),
      ourCSVNSequence: this.params.ourCSVNSequence,
      counterCSVNSequence: this.params.counterCSVNSequence,
      ourAmountSat: this.params.ourAmountSat,
      counterAmountSat: this.params.counterAmountSat,
      minConfirmations: this.params.minConfirmations,
      feeSatoshis: this.params.feeSatoshis,
      ourFundTxid: this.ourFundTxid,
      counterFundTxid: this.counterFundTxid,
      secret: this.secret ? toHex2(this.secret) : "",
      htlcScriptHash: toHex2(this.htlcScriptHash)
    };
    this.storage.save(this.swapID !== "" ? this.swapID : "_pending", rec);
  }
  // ── Record reconstruction (used by newFromRecord in recover.ts) ───────────
  static fromRecord(rec, chain, storage) {
    const hashLock = fromHex(rec.hashLock);
    const params = {
      hashLock,
      ourPubKey: fromHex(rec.ourPubKey),
      counterPubKey: rec.counterPubKey ? fromHex(rec.counterPubKey) : new Uint8Array(0),
      ourCSVNSequence: rec.ourCSVNSequence,
      counterCSVNSequence: rec.counterCSVNSequence,
      ourAmountSat: rec.ourAmountSat,
      counterAmountSat: rec.counterAmountSat,
      minConfirmations: rec.minConfirmations,
      feeSatoshis: rec.feeSatoshis
    };
    const e = new _Engine(rec.role, params, chain, storage);
    e.state = rec.state;
    e.swapID = rec.swapID;
    e.ourPrivKey = fromHex(rec.ourPrivKey);
    e.ourFundTxid = rec.ourFundTxid ?? "";
    e.counterFundTxid = rec.counterFundTxid ?? "";
    e.htlcScriptHash = rec.htlcScriptHash ? fromHex(rec.htlcScriptHash) : new Uint8Array(20);
    e.secret = rec.secret ? fromHex(rec.secret) : null;
    e.verified = rec.state >= 4 /* Verified */;
    return e;
  }
};

// src/order-book/mock.ts
var _nextId = 1;
function nextId() {
  return `mock-order-${(_nextId++).toString().padStart(4, "0")}`;
}
function matches(order, filter) {
  if (filter.offerChain && order.offerChain !== filter.offerChain) return false;
  if (filter.wantChain && order.wantChain !== filter.wantChain) return false;
  if (filter.status && order.status !== filter.status) return false;
  return true;
}
var MockOrderBook = class {
  constructor() {
    this.orders = /* @__PURE__ */ new Map();
    this.subs = [];
  }
  notify() {
    for (const { filter, cb } of this.subs) {
      cb(this._query(filter));
    }
  }
  _query(filter) {
    return Array.from(this.orders.values()).filter((o) => matches(o, filter));
  }
  async postOrder(req) {
    const id = nextId();
    const now = Date.now();
    const order = {
      id,
      proposal: req.proposal,
      offerChain: req.offerChain,
      wantChain: req.wantChain,
      status: "open",
      createdAt: now,
      expiresAt: now + (req.ttlSeconds ?? 3600) * 1e3
    };
    this.orders.set(id, order);
    this.notify();
    return id;
  }
  async queryOrders(filter) {
    return this._query(filter);
  }
  subscribeToOrders(filter, callback) {
    const entry = { filter, cb: callback };
    this.subs.push(entry);
    callback(this._query(filter));
    return () => {
      this.subs = this.subs.filter((s) => s !== entry);
    };
  }
  async cancelOrder(orderId, makerPubKey) {
    const order = this.orders.get(orderId);
    if (!order) throw new Error(`order-book: order not found: ${orderId}`);
    if (order.proposal.initiatorPubKey !== makerPubKey) {
      throw new Error("order-book: cancelOrder: pubKey does not match order maker");
    }
    if (order.status !== "open") {
      throw new Error(`order-book: cancelOrder: order is not open (status=${order.status})`);
    }
    this.orders.set(orderId, { ...order, status: "cancelled" });
    this.notify();
  }
  async takeOrder(orderId, takerPubKey) {
    const order = this.orders.get(orderId);
    if (!order) throw new Error(`order-book: order not found: ${orderId}`);
    if (order.status !== "open") {
      throw new Error(`order-book: takeOrder: order is not open (status=${order.status})`);
    }
    const now = Date.now();
    if (now > order.expiresAt) {
      this.orders.set(orderId, { ...order, status: "expired" });
      this.notify();
      throw new Error(`order-book: takeOrder: order has expired`);
    }
    this.orders.set(orderId, {
      ...order,
      status: "taken",
      takerPubKey,
      takenAt: now
    });
    this.notify();
    return {
      orderId,
      proposal: order.proposal,
      takerPubKey,
      offerChain: order.offerChain,
      wantChain: order.wantChain
    };
  }
  /** Test helper — get order by id. */
  getOrder(id) {
    return this.orders.get(id);
  }
  /** Test helper — number of orders in the book. */
  size() {
    return this.orders.size;
  }
};

// src/order-book/centralized.ts
var ORDER_BOOK_PATH = "/api/orders";
var POLL_INTERVAL_MS = 3e3;
function filterToParams(filter) {
  const p = new URLSearchParams();
  if (filter.offerChain) p.set("offerChain", filter.offerChain);
  if (filter.wantChain) p.set("wantChain", filter.wantChain);
  if (filter.status) p.set("status", filter.status);
  const s = p.toString();
  return s ? `?${s}` : "";
}
async function apiFetch(path, init) {
  const res = await fetch(path, {
    ...init,
    headers: {
      "Content-Type": "application/json",
      ...init?.headers ?? {}
    }
  });
  const body = await res.json();
  if (!res.ok || !body.success) {
    throw new Error(body.error ?? `order-book: HTTP ${res.status}`);
  }
  return body.data;
}
var CentralizedOrderBook = class {
  /**
   * @param opts.baseUrl Absolute origin of the proxy (e.g. "https://swap.bch2.org") — REQUIRED for Node /
   *   bot use, where a relative fetch has no origin. Omit in the browser to hit the same-origin path.
   */
  constructor(opts) {
    this.base = (opts?.baseUrl?.replace(/\/+$/, "") ?? "") + ORDER_BOOK_PATH;
  }
  async postOrder(req) {
    return apiFetch(this.base, {
      method: "POST",
      body: JSON.stringify(req)
    });
  }
  async queryOrders(filter) {
    return apiFetch(this.base + filterToParams(filter));
  }
  subscribeToOrders(filter, callback) {
    let alive = true;
    const poll = async () => {
      try {
        const orders = await this.queryOrders(filter);
        if (alive) callback(orders);
      } catch {
      }
    };
    poll();
    const timer = setInterval(() => {
      if (alive) poll();
    }, POLL_INTERVAL_MS);
    return () => {
      alive = false;
      clearInterval(timer);
    };
  }
  async cancelOrder(orderId, makerPubKey) {
    await apiFetch(`${this.base}/${encodeURIComponent(orderId)}`, {
      method: "DELETE",
      body: JSON.stringify({ makerPubKey })
    });
  }
  async takeOrder(orderId, takerPubKey) {
    return apiFetch(
      `${this.base}/${encodeURIComponent(orderId)}/take`,
      {
        method: "POST",
        body: JSON.stringify({ takerPubKey })
      }
    );
  }
};
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

export { BCH_SWAP_BCH2_CSV_NSEQUENCE, BCH_SWAP_BCH_CSV_NSEQUENCE, CentralizedOrderBook, DEFAULT_FEE_SATOSHIS, DUST_SATOSHIS, Engine, ErrAmountTooLow, ErrHashMismatch, ErrInsufficientConfirmations, ErrNoSecret, ErrOutputNotFound, ErrTimelockOrdering, ErrVerificationRequired, ErrWrongRole, ErrWrongState, HTLC_CSV_BLOCKS, LocalSwapStorage, MAINNET_BC2_SWAP_BC2_CSV, MAINNET_BC2_SWAP_BCH2_CSV, MAINNET_BCH_SWAP_BCH2_CSV, MAINNET_BCH_SWAP_BCH_CSV, MAINNET_BTC_SWAP_BCH2_CSV, MAINNET_BTC_SWAP_BTC_CSV, MAX_PBKDF2_ITERATIONS, MIN_PBKDF2_ITERATIONS, MemorySwapStorage, MockOrderBook, MockUTXOChain, PBKDF2_ITERATIONS, RecoveryAction, Role, SEQ_LOCKTIME_GRANULARITY, SEQ_LOCKTIME_TYPE_FLAG, SIGHASH_ALL, SIGHASH_ALL_FORKID, State, VerificationGate, bc1AddressToScripthash, bip143Sighash, bip143SighashOutputs, buildClaimTx, buildFundingTx, buildRedeemScript, buildRefundTx, decodeBase58, decodeBech32, decodeBech32m, decodeCashAddr, decodeLegacyAddress, decodeWIF, decryptMnemonic, deleteSwapRecord, determineRecoveryAction, encodeBase58, encodeBech32, encodeBech32m, encodeCSV, encodeCashAddr, encodeLegacyAddress, encodeWIF, encryptMnemonic, extractSecretFromScriptSig, hash160, isBech32Address, isTerminal, isValidTransition, legacySighashOutputs, legacySighashSingle, loadSwapRecords, newFromRecord, p2pkScripthash, p2pkhScriptPubKey, p2pkhScripthash, p2shP2wpkhScripthash, p2shScriptPubKey, p2trScripthash, p2wpkhScripthash, pubkeyToBC2Address, pubkeyToBCH2Address, pubkeyToBCHAddress, pubkeyToBTCAddress, pubkeyToBech32Address, pubkeyToP2SHP2WPKHAddress, pushData, recoverAndResume, resolveIterations, roleToString, stateToString, swapIDFromHashLock, validTransitions, validateParams, validatePassword, validateTimelockOrdering, xonlyPubkeyToP2TRAddress };
