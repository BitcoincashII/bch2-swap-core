import { HDKey } from '@scure/bip32';
import { validateMnemonic, mnemonicToSeedSync } from '@scure/bip39';
import { wordlist } from '@scure/bip39/wordlists/english';
import { hmac } from '@noble/hashes/hmac';
import { sha256 } from '@noble/hashes/sha256';
import * as secp256k12 from '@noble/secp256k1';
import { ripemd160 } from '@noble/hashes/ripemd160';
import { ethers, Contract } from 'ethers';
import { gcm } from '@noble/ciphers/aes.js';
import { pbkdf2 } from '@noble/hashes/pbkdf2';
import { randomBytes } from '@noble/hashes/utils';

// src/seed-secret.ts
var HARDENED = 2147483648;
var SWAP_SECRET_PATH = [HARDENED + 83, HARDENED + 0, HARDENED + 0];
var SECRET_DOMAIN = new TextEncoder().encode("BCH2SWAP/secret/v1");
new TextEncoder().encode("BCH2SWAP/maker/v1");
var SWAP_SECRET_SCHEME = "hmac-v1";
var SWAP_NONCE_BYTES = 16;
function wipeNode(n) {
  try {
    n?.wipePrivateData?.();
  } catch {
  }
  try {
    if (n && "chainCode" in n && n.chainCode instanceof Uint8Array) n.chainCode.fill(0);
  } catch {
  }
}
function deriveSwapKss(mnemonic) {
  const normalized = mnemonic.trim().toLowerCase();
  if (!validateMnemonic(normalized, wordlist)) return null;
  let seed;
  let root = null;
  let kss = null;
  try {
    seed = mnemonicToSeedSync(normalized);
    root = HDKey.fromMasterSeed(seed);
    let l1 = null, l2 = null, l3 = null;
    try {
      l1 = root.deriveChild(SWAP_SECRET_PATH[0]);
      l2 = l1.deriveChild(SWAP_SECRET_PATH[1]);
      l3 = l2.deriveChild(SWAP_SECRET_PATH[2]);
      if (l3.privateKey) kss = new Uint8Array(l3.privateKey);
    } finally {
      wipeNode(l1);
      wipeNode(l2);
      wipeNode(l3);
    }
    return kss;
  } catch {
    if (kss) kss.fill(0);
    return null;
  } finally {
    try {
      root?.wipePrivateData?.();
    } catch {
    }
    if (seed) seed.fill(0);
  }
}
function swapSecretFromKss(kss, nonce) {
  if (!(kss instanceof Uint8Array) || kss.length !== 32) return null;
  if (!(nonce instanceof Uint8Array) || nonce.length !== SWAP_NONCE_BYTES) return null;
  const msg = new Uint8Array(SECRET_DOMAIN.length + nonce.length);
  msg.set(SECRET_DOMAIN, 0);
  msg.set(nonce, SECRET_DOMAIN.length);
  return hmac(sha256, kss, msg);
}

// src/chain-config.ts
var REGTEST = globalThis.process?.env?.BCH2_SWAP_NETWORK === "regtest";
var chainConfigs = {
  bch2: {
    name: "Bitcoin Cash II",
    ticker: "BCH2",
    addressPrefix: "bitcoincashii",
    p2shVersionByte: 5,
    sighashType: 65,
    // SIGHASH_ALL | SIGHASH_FORKID
    useBip143: true,
    electrumServers: [
      { host: "electrum.bch2.org", port: 50002, ssl: true },
      { host: "144.202.73.66", port: 50002, ssl: true }
    ],
    avgBlockTimeSec: 600,
    dustThreshold: 182,
    // 1000 sat/kvB relay rate: 1000/1000*(34+148)=182 sat for P2PKH
    feePerByte: 1,
    bip44CoinType: 20145,
    // BCH2-specific; differs from BCH (145) to prevent key reuse. BREAKING: existing wallets derived under 145 must re-derive.
    // R117-CHAIN-001: raised from 3 to 6 — BCH2 is a minority-hashrate chain; 51%-attack cost
    // on 3 BCH2 blocks is extremely low. 6 confs ≈ 1 hour at 10-min blocks. Re-assess at mainnet launch.
    requiredConfirmations: 6
  },
  bch: {
    name: "Bitcoin Cash",
    ticker: "BCH",
    addressPrefix: REGTEST ? "bchreg" : "bitcoincash",
    p2shVersionByte: 5,
    sighashType: 65,
    // SIGHASH_ALL | SIGHASH_FORKID
    useBip143: true,
    electrumServers: [
      { host: "bch0.kister.net", port: 50002, ssl: true },
      { host: "blackie.c3-soft.com", port: 50002, ssl: true }
    ],
    avgBlockTimeSec: 600,
    dustThreshold: 182,
    // 1000 sat/kvB relay rate: same as BCH2
    feePerByte: 1,
    bip44CoinType: 145,
    // R116-CHAIN-001: raised from 3 to 6 — BCH hashrate is orders of magnitude below BTC's,
    // making a 51% attack on 3 BCH blocks much cheaper than 2 BTC blocks. 6 confs ≈ 1 hour.
    requiredConfirmations: 6
  },
  btc: {
    name: "Bitcoin",
    ticker: "BTC",
    p2shVersionByte: REGTEST ? 196 : 5,
    p2pkhVersionByte: REGTEST ? 111 : 0,
    sighashType: 1,
    // SIGHASH_ALL
    useBip143: false,
    electrumServers: [
      { host: "electrum.blockstream.info", port: 50002, ssl: true },
      { host: "electrum.emzy.de", port: 50002, ssl: true }
    ],
    avgBlockTimeSec: 600,
    dustThreshold: 546,
    feePerByte: 10,
    bip44CoinType: 0,
    requiredConfirmations: 2
  },
  bc2: {
    name: "Bitcoin II",
    ticker: "BC2",
    p2shVersionByte: REGTEST ? 196 : 5,
    p2pkhVersionByte: REGTEST ? 111 : 0,
    sighashType: 1,
    // SIGHASH_ALL
    useBip143: false,
    electrumServers: [
      { host: "infra1.bitcoin-ii.org", port: 50009, ssl: true },
      { host: "50.6.6.41", port: 50009, ssl: true }
    ],
    avgBlockTimeSec: 600,
    dustThreshold: 546,
    feePerByte: 1,
    bip44CoinType: 1,
    // SLIP-0044 testnet reserved. WARNING: key reuse risk with any BTC/LTC testnet wallet using same mnemonic. TODO: register a custom coin type (e.g. 20002) before BC2 mainnet.
    requiredConfirmations: 3
  },
  // R21-HTLC-001: EVM responder minLockBlocks must be ~12h (not ~24h).
  // The UTXO initiator locks for LOCKTIME_BLOCKS.initiator (216 blocks, ~36h). The EVM responder must lock for
  // strictly less time so the initiator cannot simultaneously claim EVM and refund UTXO.
  // Rule: EVM minLockBlocks ≈ LOCKTIME_BLOCKS.responder * avgBlockTimeSec / evmAvgBlockTimeSec
  eth: {
    name: "Ethereum Sepolia",
    ticker: "ETH",
    isEvm: true,
    evmChainId: 11155111,
    avgBlockTimeSec: 12,
    // NOTE: minLockBlocks/maxLockBlocks for EVM chains in this file are DEAD CODE.
    // The swap engine reads lock parameters from evm-config.ts (EVM_CHAINS).
    // These values are intentionally different (production vs testnet scales).
    // Do NOT rely on chain-config.ts for EVM timing parameters. See R38-CFG-002.
    minLockBlocks: 3600,
    // ~12h at 12s/block (half of UTXO initiator locktime)
    maxLockBlocks: 86400
    // ~12 days at 12s/block
  },
  base: {
    name: "Base Sepolia",
    ticker: "BASE",
    isEvm: true,
    evmChainId: 84532,
    avgBlockTimeSec: 2,
    // NOTE: minLockBlocks/maxLockBlocks for EVM chains in this file are DEAD CODE.
    // The swap engine reads lock parameters from evm-config.ts (EVM_CHAINS).
    // These values are intentionally different (production vs testnet scales).
    // Do NOT rely on chain-config.ts for EVM timing parameters. See R38-CFG-002.
    minLockBlocks: 21600,
    // ~12h at 2s/block (half of UTXO initiator locktime)
    maxLockBlocks: 518400
    // ~12 days at 2s/block
  },
  arb: {
    name: "Arbitrum",
    ticker: "ARB",
    isEvm: true,
    evmChainId: 42161,
    avgBlockTimeSec: 1,
    // NOTE: minLockBlocks/maxLockBlocks for EVM chains in this file are DEAD CODE.
    // The swap engine reads lock parameters from evm-config.ts (EVM_CHAINS).
    // These values are intentionally different (production vs testnet scales).
    // Do NOT rely on chain-config.ts for EVM timing parameters. See R38-CFG-002.
    minLockBlocks: 43200,
    // ~12h at 1s/block (half of UTXO initiator locktime)
    maxLockBlocks: 1036800
    // ~12 days at 1s/block
  },
  poly: {
    name: "Polygon",
    ticker: "POL",
    isEvm: true,
    evmChainId: 137,
    avgBlockTimeSec: 2,
    // Dead code for EVM chains (lock params come from evm-config.ts EVM_CHAINS). See R38-CFG-002.
    minLockBlocks: 10800,
    // ~6h at 2s/block
    maxLockBlocks: 86400
    // ~48h at 2s/block
  }
};
var LOCKTIME_BLOCKS = {
  initiator: 216,
  // ~36 hours (R-TIMELOCK-K: raised from 144 so the ÷K responder fund gate still leaves a funding window)
  responder: 72
  // ~12 hours (R-TIMELOCK-K: kept at 12h — the initiator's claim window on this leg needs K*margin + confs)
};
var TIMELOCK_SAFETY_K = 2;
var CLAIM_MARGIN_BLOCKS = 24;
function minSecondsUntilRefund(blocksRemaining, chainBlockSec) {
  return blocksRemaining * chainBlockSec / TIMELOCK_SAFETY_K;
}
var SUSPENDED_SWAP_CHAINS = /* @__PURE__ */ new Set(["bc2"]);
function isSwapSuspended(chain) {
  return SUSPENDED_SWAP_CHAINS.has(chain);
}
function isSwapPairSuspended(chainA, chainB) {
  return isSwapSuspended(chainA) || isSwapSuspended(chainB);
}
var MAX_FEE_RATE_SAT_PER_BYTE = {
  bch2: 20,
  bch: 20,
  btc: 100,
  bc2: 20,
  eth: 0,
  base: 0,
  arb: 0,
  poly: 0
};
function maxFeeRate(chain) {
  return MAX_FEE_RATE_SAT_PER_BYTE[chain] || 1;
}
function getChainConfig(chain) {
  const cfg = chainConfigs[chain];
  if (!cfg) throw new Error(`getChainConfig: unknown chain '${chain}'`);
  return cfg;
}

// src/htlc-builder.ts
function hexToBytes(hex) {
  if (hex.length % 2 !== 0) throw new Error("Invalid hex: odd length");
  if (!/^[0-9a-fA-F]*$/.test(hex)) throw new Error("Invalid hex: non-hex characters");
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
  }
  return bytes;
}
function bytesToHex(bytes) {
  return Array.from(bytes).map((b) => b.toString(16).padStart(2, "0")).join("");
}
function reverseBytes(bytes) {
  const r = new Uint8Array(bytes.length);
  for (let i = 0; i < bytes.length; i++) r[i] = bytes[bytes.length - 1 - i];
  return r;
}
function hash256(data) {
  return sha256(sha256(data));
}
function hash160(data) {
  return ripemd160(sha256(data));
}
function writeVarInt(n) {
  if (n < 253) return new Uint8Array([n]);
  if (n <= 65535) return new Uint8Array([253, n & 255, n >> 8 & 255]);
  return new Uint8Array([254, n & 255, n >> 8 & 255, n >> 16 & 255, n >> 24 & 255]);
}
function readVarInt(data, offset) {
  if (offset >= data.length) return null;
  const first = data[offset];
  if (first < 253) return { value: first, bytesRead: 1 };
  if (first === 253) {
    if (offset + 2 >= data.length) return null;
    return { value: data[offset + 1] | data[offset + 2] << 8, bytesRead: 3 };
  }
  if (first === 254) {
    if (offset + 4 >= data.length) return null;
    return { value: (data[offset + 1] | data[offset + 2] << 8 | data[offset + 3] << 16 | data[offset + 4] << 24) >>> 0, bytesRead: 5 };
  }
  return null;
}
function writeUInt32LE(n) {
  return new Uint8Array([n & 255, n >> 8 & 255, n >> 16 & 255, n >> 24 & 255]);
}
function writeUInt64LE(n) {
  if (n < 0 || n > Number.MAX_SAFE_INTEGER) {
    throw new Error(`writeUInt64LE: value out of safe range: ${n}`);
  }
  const low = n >>> 0;
  const high = Number(BigInt(n) >> 32n) >>> 0;
  return new Uint8Array([
    low & 255,
    low >> 8 & 255,
    low >> 16 & 255,
    low >> 24 & 255,
    high & 255,
    high >> 8 & 255,
    high >> 16 & 255,
    high >> 24 & 255
  ]);
}
function concat(...arrays) {
  const totalLen = arrays.reduce((s, a) => s + a.length, 0);
  const result = new Uint8Array(totalLen);
  let offset = 0;
  for (const arr of arrays) {
    result.set(arr, offset);
    offset += arr.length;
  }
  return result;
}
function pushData(data) {
  if (data.length < 76) {
    return concat(new Uint8Array([data.length]), data);
  } else if (data.length < 256) {
    return concat(new Uint8Array([76, data.length]), data);
  } else {
    return concat(new Uint8Array([77, data.length & 255, data.length >> 8 & 255]), data);
  }
}
function encodeScriptNum(n) {
  if (n === 0) return new Uint8Array(0);
  const neg = n < 0;
  let abs = Math.abs(n);
  const bytes = [];
  while (abs > 0) {
    bytes.push(abs & 255);
    abs = Math.floor(abs / 256);
  }
  if (bytes[bytes.length - 1] & 128) {
    bytes.push(neg ? 128 : 0);
  } else if (neg) {
    bytes[bytes.length - 1] |= 128;
  }
  return new Uint8Array(bytes);
}
function compactToDER(compact) {
  const r = compact.slice(0, 32);
  const s = compact.slice(32, 64);
  function encodeInt(bytes) {
    let start = 0;
    while (start < bytes.length - 1 && bytes[start] === 0) start++;
    const trimmed = bytes.slice(start);
    if (trimmed[0] & 128) return new Uint8Array([0, ...trimmed]);
    return trimmed;
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
var CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
function cashAddrPolymod(values) {
  const GENERATORS = [0x98f2bc8e61n, 0x79b76d99e2n, 0xf33e5fb3c4n, 0xae2eabe2a8n, 0x1e4f43e470n];
  let chk = 1n;
  for (const value of values) {
    const top = chk >> 35n;
    chk = (chk & 0x07ffffffffn) << 5n ^ BigInt(value);
    for (let i = 0; i < 5; i++) {
      if (top >> BigInt(i) & 1n) chk ^= GENERATORS[i];
    }
  }
  return chk;
}
function packAddrData(hash, type) {
  const encodedSize = hash.length === 20 ? 0 : 3;
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
  if (bits > 0) payload.push(acc << 5 - bits & 31);
  return payload;
}
function encodeCashAddr(prefix, type, hash) {
  const prefixValues = [];
  for (let i = 0; i < prefix.length; i++) prefixValues.push(prefix.charCodeAt(i) & 31);
  prefixValues.push(0);
  const payload = packAddrData(hash, type);
  const checksumInput = [...prefixValues, ...payload, 0, 0, 0, 0, 0, 0, 0, 0];
  const polymod = cashAddrPolymod(checksumInput) ^ 1n;
  const checksumArray = [];
  for (let i = 0; i < 8; i++) checksumArray.push(Number(polymod >> BigInt(5 * (7 - i)) & 0x1fn));
  const combined = [...payload, ...checksumArray];
  let result = prefix + ":";
  for (const value of combined) result += CHARSET[value];
  return result;
}
var BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
function encodeBase58(data) {
  let num = 0n;
  for (let i = 0; i < data.length; i++) num = num * 256n + BigInt(data[i]);
  let result = "";
  while (num > 0n) {
    result = BASE58_ALPHABET[Number(num % 58n)] + result;
    num = num / 58n;
  }
  for (let i = 0; i < data.length && data[i] === 0; i++) result = "1" + result;
  return result;
}
var LOCKTIME_HEIGHT_MAX = 5e8;
var LOCKTIME_TS_MIN = 15e8;
var LOCKTIME_TS_MAX = 2147483648;
function isValidLocktime(locktime) {
  if (!Number.isInteger(locktime)) return false;
  if (locktime > 0 && locktime < LOCKTIME_HEIGHT_MAX) return true;
  if (locktime >= LOCKTIME_TS_MIN && locktime < LOCKTIME_TS_MAX) return true;
  return false;
}
var BITCOIN_GENESIS_SEC = 1231006505;
var MIN_PLAUSIBLE_BLOCK_INTERVAL_SEC = 30;
function maxPlausibleBlockHeight(nowSec = Math.floor(Date.now() / 1e3)) {
  return Math.floor((nowSec - BITCOIN_GENESIS_SEC) / MIN_PLAUSIBLE_BLOCK_INTERVAL_SEC);
}
function createHTLCRedeemScript(params) {
  const { secretHash, recipientPubkeyHash, refundPubkeyHash, locktime } = params;
  if (secretHash.length !== 32) throw new Error("secretHash must be 32 bytes");
  if (recipientPubkeyHash.length !== 20) throw new Error("recipientPubkeyHash must be 20 bytes");
  if (refundPubkeyHash.length !== 20) throw new Error("refundPubkeyHash must be 20 bytes");
  if (recipientPubkeyHash.every((b, i) => b === refundPubkeyHash[i])) {
    throw new Error("recipientPubkeyHash and refundPubkeyHash must differ \u2014 same key used for both parties?");
  }
  if (!isValidLocktime(locktime)) {
    throw new Error(`locktime must be a block height in (0, ${LOCKTIME_HEIGHT_MAX}) or a Unix timestamp in [${LOCKTIME_TS_MIN}, ${LOCKTIME_TS_MAX}) (got ${locktime})`);
  }
  const locktimeBytes = encodeScriptNum(locktime);
  return new Uint8Array([
    99,
    // OP_IF
    168,
    // OP_SHA256
    32,
    ...secretHash,
    // push 32 bytes: secret hash
    136,
    // OP_EQUALVERIFY
    118,
    // OP_DUP
    169,
    // OP_HASH160
    20,
    ...recipientPubkeyHash,
    // push 20 bytes: recipient pubkey hash
    103,
    // OP_ELSE
    // R30-HTLC-002: use pushData() instead of raw length byte — raw byte would be misinterpreted
    // as OP_PUSHDATA1 by script interpreter if locktimeBytes.length >= 76 (0x4c). Block heights
    // up to ~134M fit in 4 bytes (safe today), but pushData() is correct for all future values.
    ...pushData(locktimeBytes),
    // push N bytes: locktime (safe for all possible encoded lengths)
    177,
    // OP_CHECKLOCKTIMEVERIFY
    117,
    // OP_DROP
    118,
    // OP_DUP
    169,
    // OP_HASH160
    20,
    ...refundPubkeyHash,
    // push 20 bytes: refund pubkey hash
    104,
    // OP_ENDIF
    136,
    // OP_EQUALVERIFY
    172
    // OP_CHECKSIG
  ]);
}
function htlcToP2SHAddress(redeemScript, chain) {
  const scriptHash = hash160(redeemScript);
  const config = getChainConfig(chain);
  if (config.addressPrefix) {
    return encodeCashAddr(config.addressPrefix, 1, scriptHash);
  } else {
    const versioned = new Uint8Array([config.p2shVersionByte ?? 5, ...scriptHash]);
    const checksum = hash256(versioned).slice(0, 4);
    return encodeBase58(new Uint8Array([...versioned, ...checksum]));
  }
}
function createHTLC(params, chain) {
  const redeemScript = createHTLCRedeemScript(params);
  if (redeemScript.length > 520) {
    throw new Error(`createHTLC: redeemScript is ${redeemScript.length} bytes \u2014 exceeds BIP16 P2SH limit of 520`);
  }
  const scriptHash = hash160(redeemScript);
  const p2shScriptPubKey = new Uint8Array([169, 20, ...scriptHash, 135]);
  const p2shAddress = htlcToP2SHAddress(redeemScript, chain);
  return { redeemScript, p2shAddress, p2shScriptPubKey, params };
}
function htlcScripthash(redeemScript) {
  const scriptHash = hash160(redeemScript);
  const p2shScript = new Uint8Array([169, 20, ...scriptHash, 135]);
  const hash = sha256(p2shScript);
  return bytesToHex(reverseBytes(hash));
}
function minClaimableHtlcAmount(chain) {
  const config = getChainConfig(chain);
  const dustThreshold = config.dustThreshold ?? 546;
  const feePerByte = maxFeeRate(chain);
  const useBip143 = config.useBip143 ?? false;
  const RS_LEN = 110;
  const rsPushOverhead = 2 ;
  const scriptSigEstimate = 74 + 34 + 33 + 1 + rsPushOverhead + RS_LEN;
  const outputSize = 8 + 1 + 25;
  const claimTxSize = 90 - 34 + outputSize + scriptSigEstimate + (useBip143 ? 0 : 50);
  const estClaimFee = claimTxSize * feePerByte;
  return Math.max(dustThreshold * 5, estClaimFee + dustThreshold);
}
function resolveClampedFeeRate(feeRate, configRate, chain) {
  const r = configRate ?? 1;
  return Number.isFinite(r) ? Math.min(r, maxFeeRate(chain)) : r;
}
async function buildHTLCFundingTx(inputs, htlcScriptPubKey, amount, changeScriptPubKey, chain, feeRate) {
  if (inputs.length === 0) {
    throw new Error("buildHTLCFundingTx: no inputs provided \u2014 wallet has no spendable UTXOs");
  }
  if (!Number.isInteger(amount) || !Number.isFinite(amount) || amount <= 0) {
    throw new Error(`buildHTLCFundingTx: amount must be a positive integer (satoshis); got ${amount}`);
  }
  const config = getChainConfig(chain);
  const hashType = config.sighashType ?? 1;
  if ((config.useBip143 ?? false) && !(hashType & 64)) {
    throw new Error(`SIGHASH_FORKID (0x40) required for ${chain} but hashType is 0x${hashType.toString(16)}`);
  }
  const feePerByte = resolveClampedFeeRate(feeRate, config.feePerByte, chain);
  if (!feePerByte || !Number.isFinite(feePerByte) || feePerByte <= 0) {
    throw new Error(`feePerByte must be a finite positive number, got ${feePerByte}`);
  }
  const dustThreshold = config.dustThreshold ?? 546;
  const p2shDustFloor = minClaimableHtlcAmount(chain);
  if (amount < p2shDustFloor) {
    throw new Error(
      `HTLC amount ${amount} sat is below the minimum claimable amount (${p2shDustFloor} sat) on ${chain} after fees. Increase the swap amount.`
    );
  }
  const totalIn = inputs.reduce((s, i) => s + i.utxo.value, 0);
  let numOutputs = changeScriptPubKey ? 2 : 1;
  let estimatedSize = inputs.length * 148 + numOutputs * 34 + 10;
  let fee = estimatedSize * feePerByte;
  let change = totalIn - amount - fee;
  if (change <= dustThreshold && changeScriptPubKey) {
    if (change > 0) console.warn(`[htlc-builder] Sub-dust change (${change} sat) absorbed into miner fee`);
    numOutputs = 1;
    estimatedSize = inputs.length * 148 + numOutputs * 34 + 10;
    fee = estimatedSize * feePerByte;
    change = totalIn - amount - fee;
    if (change > dustThreshold) {
      numOutputs = 2;
      estimatedSize = inputs.length * 148 + 2 * 34 + 10;
      fee = estimatedSize * feePerByte;
      change = totalIn - amount - fee;
    }
    if (change > 0 && change <= dustThreshold) {
      console.warn(`[htlc-builder] Second sub-dust change (${change} sat) absorbed into fee`);
      numOutputs = 1;
      const estimatedSize2 = inputs.length * 148 + 1 * 34 + 10;
      fee = estimatedSize2 * feePerByte;
      change = totalIn - amount - fee;
    }
  }
  if (change >= dustThreshold && numOutputs === 1 && changeScriptPubKey) {
    const sizeWith2 = inputs.length * 148 + 2 * 34 + 10;
    fee = sizeWith2 * feePerByte;
    change = totalIn - amount - fee;
    numOutputs = change >= dustThreshold ? 2 : 1;
    if (change < 0) throw new Error("Insufficient funds after fee reconciliation");
  }
  const sp = htlcScriptPubKey;
  const isP2SH = sp.length === 23 && sp[0] === 169 && sp[1] === 20 && sp[22] === 135;
  const isP2PKH = sp.length === 25 && sp[0] === 118 && sp[1] === 169 && sp[2] === 20 && sp[23] === 136 && sp[24] === 172;
  if (!isP2SH && !isP2PKH) {
    throw new Error(`buildHTLCFundingTx: recipient scriptPubKey must be a standard P2SH (23B) or P2PKH (25B); got ${sp.length} bytes`);
  }
  const outputs = [
    { scriptPubKey: htlcScriptPubKey, value: amount }
    // vout=0 — REQUIRED for claim/refund
  ];
  if (change >= dustThreshold && changeScriptPubKey) {
    if (changeScriptPubKey.length < 1 || changeScriptPubKey.length > 520) {
      throw new Error(`buildHTLCFundingTx: changeScriptPubKey invalid length (${changeScriptPubKey.length})`);
    }
    outputs.push({ scriptPubKey: changeScriptPubKey, value: change });
  } else if (change < 0) {
    throw new Error("Insufficient funds");
  }
  return buildSignedTx(inputs, outputs, hashType, config.useBip143 ?? false);
}
async function buildHTLCClaimTx(utxo, redeemScript, secret, recipientPrivateKey, recipientPublicKey, destinationScriptPubKey, chain, feeRate) {
  if (secret.length !== 32) throw new Error(`HTLC secret must be exactly 32 bytes; got ${secret.length}`);
  if (redeemScript.length === 0 || redeemScript.length > 520) {
    throw new Error(`redeemScript invalid length (${redeemScript.length}; must be 1\u2013520 bytes)`);
  }
  const config = getChainConfig(chain);
  const hashType = config.sighashType ?? 1;
  if ((config.useBip143 ?? false) && !(hashType & 64)) {
    throw new Error(`SIGHASH_FORKID (0x40) required for ${chain} claim but hashType is 0x${hashType.toString(16)}`);
  }
  const useBip143 = config.useBip143 ?? false;
  const feePerByte = resolveClampedFeeRate(feeRate, config.feePerByte, chain);
  if (!feePerByte || !Number.isFinite(feePerByte) || feePerByte <= 0) {
    throw new Error(`feePerByte must be a finite positive number, got ${feePerByte}`);
  }
  const dustThreshold = config.dustThreshold ?? 546;
  if (!destinationScriptPubKey || destinationScriptPubKey.length < 1 || destinationScriptPubKey.length > 520) {
    throw new Error(`destinationScriptPubKey invalid length (${destinationScriptPubKey?.length ?? 0}); must be 1\u2013520 bytes`);
  }
  const rsLen = redeemScript.length;
  const rsPushOverhead = rsLen < 76 ? 1 : rsLen < 256 ? 2 : 3;
  const scriptSigEstimate = 74 + 34 + 33 + 1 + rsPushOverhead + rsLen;
  const destScriptLen = destinationScriptPubKey.length;
  const destScriptVarIntLen = destScriptLen < 253 ? 1 : 3;
  const outputSize = 8 + destScriptVarIntLen + destScriptLen;
  const claimTxSize = 90 - 34 + outputSize + scriptSigEstimate + (useBip143 ? 0 : 50);
  const affordableClaimRate = Math.floor((utxo.value - dustThreshold) / claimTxSize);
  const effectiveClaimFeePerByte = Math.max(1, Math.min(feePerByte, affordableClaimRate));
  const fee = claimTxSize * effectiveClaimFeePerByte;
  if (!Number.isInteger(utxo.value) || utxo.value <= 0) {
    throw new Error(`claimUtxo.value must be a positive integer; got ${utxo.value}. Refresh UTXO from Electrum.`);
  }
  if (fee >= utxo.value) {
    throw new Error(`Claim fee (${fee} sat) would exceed UTXO value (${utxo.value} sat). Swap amount is too small.`);
  }
  const outputValue = utxo.value - fee;
  if (outputValue < dustThreshold) {
    throw new Error("HTLC value too small to claim after fees");
  }
  const outputs = [{ scriptPubKey: destinationScriptPubKey, value: outputValue }];
  const claimNSequence = 4294967295;
  const sighash = computeSighash(
    [{ utxo, scriptCode: redeemScript }],
    outputs,
    0,
    hashType,
    useBip143,
    0,
    // nLockTime = 0 for claim
    claimNSequence
  );
  const signature = await secp256k12.signAsync(sighash, recipientPrivateKey, { lowS: true });
  const sigDer = compactToDER(signature.toCompactRawBytes());
  const sigWithType = concat(sigDer, new Uint8Array([hashType]));
  const scriptSig = concat(
    pushData(sigWithType),
    pushData(recipientPublicKey),
    pushData(secret),
    new Uint8Array([81]),
    // OP_1 — MINIMALDATA-compliant encoding of integer 1 for BCH2 (R103-HTLC-001)
    pushData(redeemScript)
  );
  return serializeTx(
    [{ utxo, scriptSig, nSequence: claimNSequence }],
    outputs,
    0
    // nLockTime
  );
}
async function buildHTLCRefundTx(utxo, redeemScript, locktime, refundPrivateKey, refundPublicKey, destinationScriptPubKey, chain, feeRate) {
  if (!isValidLocktime(locktime)) {
    throw new Error(`locktime must be a block height in (0, ${LOCKTIME_HEIGHT_MAX}) or a Unix timestamp in [${LOCKTIME_TS_MIN}, ${LOCKTIME_TS_MAX}); got ${locktime}`);
  }
  if (redeemScript.length === 0 || redeemScript.length > 520) {
    throw new Error(`redeemScript invalid length (${redeemScript.length}; must be 1\u2013520 bytes)`);
  }
  if (!Number.isInteger(utxo.value) || utxo.value <= 0) {
    throw new Error(`refundUtxo.value must be a positive integer; got ${utxo.value}. Refresh UTXO from Electrum.`);
  }
  const config = getChainConfig(chain);
  const hashType = config.sighashType ?? 1;
  if ((config.useBip143 ?? false) && !(hashType & 64)) {
    throw new Error(`SIGHASH_FORKID (0x40) required for ${chain} refund but hashType is 0x${hashType.toString(16)}`);
  }
  const useBip143 = config.useBip143 ?? false;
  const feePerByte = resolveClampedFeeRate(feeRate, config.feePerByte, chain);
  if (!feePerByte || !Number.isFinite(feePerByte) || feePerByte <= 0) {
    throw new Error(`feePerByte must be a finite positive number, got ${feePerByte}`);
  }
  const dustThreshold = config.dustThreshold ?? 546;
  if (!destinationScriptPubKey || destinationScriptPubKey.length < 1 || destinationScriptPubKey.length > 520) {
    throw new Error(`destinationScriptPubKey invalid length (${destinationScriptPubKey?.length ?? 0}); must be 1\u2013520 bytes`);
  }
  const rsLen = redeemScript.length;
  const rsPushOverhead = rsLen < 76 ? 1 : rsLen < 256 ? 2 : 3;
  const refundScriptSig = 74 + 34 + 1 + rsPushOverhead + rsLen;
  const refundDestScriptLen = destinationScriptPubKey.length;
  const refundDestScriptVarIntLen = refundDestScriptLen < 253 ? 1 : 3;
  const refundOutputSize = 8 + refundDestScriptVarIntLen + refundDestScriptLen;
  const refundTxSize = useBip143 ? 10 + 41 + refundScriptSig + refundOutputSize : 10 + 41 + refundScriptSig + refundOutputSize + 50;
  const affordableRefundRate = Math.floor((utxo.value - dustThreshold) / refundTxSize);
  const effectiveRefundFeePerByte = Math.max(1, Math.min(feePerByte, affordableRefundRate));
  const fee = refundTxSize * effectiveRefundFeePerByte;
  if (fee >= utxo.value) {
    throw new Error(`Refund fee (${fee} sat) would exceed UTXO value (${utxo.value} sat). Swap amount is too small.`);
  }
  const outputValue = utxo.value - fee;
  if (outputValue < dustThreshold) {
    throw new Error("HTLC value too small to refund after fees");
  }
  const outputs = [{ scriptPubKey: destinationScriptPubKey, value: outputValue }];
  const nSequence = 4294967294;
  const sighash = computeSighash(
    [{ utxo, scriptCode: redeemScript }],
    outputs,
    0,
    hashType,
    useBip143,
    locktime,
    // nLockTime must be >= HTLC locktime
    nSequence
  );
  const signature = await secp256k12.signAsync(sighash, refundPrivateKey, { lowS: true });
  const sigDer = compactToDER(signature.toCompactRawBytes());
  const sigWithType = concat(sigDer, new Uint8Array([hashType]));
  const scriptSig = concat(
    pushData(sigWithType),
    pushData(refundPublicKey),
    new Uint8Array([0]),
    // OP_FALSE (empty push for OP_ELSE branch)
    pushData(redeemScript)
  );
  return serializeTx(
    [{ utxo, scriptSig, nSequence }],
    outputs,
    locktime
  );
}
function extractSecretFromClaimTx(rawTxHex, expectedSecretHash) {
  if (!rawTxHex || rawTxHex.length < 20) return null;
  let tx;
  try {
    tx = hexToBytes(rawTxHex);
  } catch {
    return null;
  }
  if (tx.length < 52) return null;
  let offset = 4;
  if (tx[offset] === 0) {
    if (tx[offset + 1] !== 1) return null;
    offset += 2;
  }
  const inputCountV = readVarInt(tx, offset);
  if (!inputCountV || inputCountV.value === 0) return null;
  const inputCount = Math.min(inputCountV.value, 100);
  offset += inputCountV.bytesRead;
  for (let inputIdx = 0; inputIdx < inputCount; inputIdx++) {
    let readPushLen2 = function() {
      if (pos >= scriptSig.length) return null;
      const b = scriptSig[pos++];
      if (b === 0) return null;
      if (b === 76) {
        if (pos >= scriptSig.length) return null;
        return scriptSig[pos++];
      }
      if (b === 77) {
        if (pos + 1 >= scriptSig.length) return null;
        const len = (scriptSig[pos] | scriptSig[pos + 1] << 8) >>> 0;
        pos += 2;
        return len;
      }
      if (b === 78) {
        if (pos + 3 >= scriptSig.length) return null;
        const len = scriptSig[pos] | scriptSig[pos + 1] << 8 | scriptSig[pos + 2] << 16 | scriptSig[pos + 3] << 24;
        pos += 4;
        const ulen = len >>> 0;
        if (ulen > 520) return null;
        return ulen;
      }
      if (b >= 79) return null;
      return b;
    };
    offset += 32 + 4;
    if (offset >= tx.length) return null;
    const scriptSigLenV = readVarInt(tx, offset);
    if (!scriptSigLenV) return null;
    offset += scriptSigLenV.bytesRead;
    const scriptSigLen = scriptSigLenV.value;
    if (offset + scriptSigLen > tx.length) return null;
    const scriptSig = tx.slice(offset, offset + scriptSigLen);
    offset += scriptSigLen;
    offset += 4;
    if (scriptSigLen < 100) continue;
    let pos = 0;
    const sigLen = readPushLen2();
    if (sigLen === null || sigLen < 8 || sigLen > 80) continue;
    if (pos + sigLen > scriptSig.length) continue;
    pos += sigLen;
    const pubkeyLen = readPushLen2();
    if (pubkeyLen === null || pubkeyLen !== 33) continue;
    if (pos + pubkeyLen > scriptSig.length) continue;
    pos += pubkeyLen;
    if (pos >= scriptSig.length) continue;
    if (scriptSig[pos] === 0) continue;
    const secretLen = readPushLen2();
    if (secretLen !== 32) continue;
    if (pos + 32 > scriptSig.length) continue;
    const secret = scriptSig.slice(pos, pos + 32);
    if (expectedSecretHash) {
      let expectedBytes;
      if (typeof expectedSecretHash === "string") {
        try {
          expectedBytes = hexToBytes(expectedSecretHash.replace(/^0x/, ""));
        } catch {
          expectedBytes = null;
        }
      } else {
        expectedBytes = expectedSecretHash;
      }
      if (!expectedBytes) continue;
      const actualHash = sha256(secret);
      if (actualHash.length !== expectedBytes.length) continue;
      let hashMatch = true;
      for (let k = 0; k < actualHash.length; k++) {
        if (actualHash[k] !== expectedBytes[k]) {
          hashMatch = false;
          break;
        }
      }
      if (!hashMatch) continue;
    }
    return secret;
  }
  return null;
}
function parseAuthenticatedOutput(rawTxHex, expectedTxid, voutIndex) {
  if (!rawTxHex || typeof rawTxHex !== "string") {
    throw new Error("parseAuthenticatedOutput: empty raw transaction");
  }
  if (!/^[0-9a-fA-F]{64}$/.test(expectedTxid)) {
    throw new Error(`parseAuthenticatedOutput: invalid expectedTxid: ${expectedTxid}`);
  }
  if (!Number.isInteger(voutIndex) || voutIndex < 0) {
    throw new Error(`parseAuthenticatedOutput: invalid voutIndex: ${voutIndex}`);
  }
  let tx;
  try {
    tx = hexToBytes(rawTxHex);
  } catch {
    throw new Error("parseAuthenticatedOutput: raw transaction is not valid hex");
  }
  if (tx.length < 10) throw new Error("parseAuthenticatedOutput: raw transaction too short");
  const segwit = tx[4] === 0;
  if (segwit && tx[5] !== 1) {
    throw new Error("parseAuthenticatedOutput: SegWit marker (0x00) without a valid flag (0x01) \u2014 malformed tx");
  }
  const inputsStart = segwit ? 6 : 4;
  let offset = inputsStart;
  const inCountV = readVarInt(tx, offset);
  if (!inCountV) throw new Error("parseAuthenticatedOutput: truncated input count");
  const inCount = inCountV.value;
  if (inCount === 0) throw new Error("parseAuthenticatedOutput: zero inputs (malformed tx)");
  if (inCount > 1e5) throw new Error("parseAuthenticatedOutput: implausible input count");
  offset += inCountV.bytesRead;
  for (let i = 0; i < inCount; i++) {
    offset += 36;
    const ssLenV = readVarInt(tx, offset);
    if (!ssLenV) throw new Error("parseAuthenticatedOutput: truncated scriptSig length");
    offset += ssLenV.bytesRead + ssLenV.value + 4;
    if (offset > tx.length) throw new Error("parseAuthenticatedOutput: input overruns tx");
  }
  const outCountV = readVarInt(tx, offset);
  if (!outCountV) throw new Error("parseAuthenticatedOutput: truncated output count");
  const outCount = outCountV.value;
  offset += outCountV.bytesRead;
  if (voutIndex >= outCount) {
    throw new Error(`parseAuthenticatedOutput: voutIndex ${voutIndex} out of range (tx has ${outCount} outputs)`);
  }
  let value = 0;
  let scriptPubKey = new Uint8Array(0);
  for (let i = 0; i < outCount; i++) {
    if (offset + 8 > tx.length) throw new Error("parseAuthenticatedOutput: truncated output value");
    let v = 0n;
    for (let b = 0; b < 8; b++) v |= BigInt(tx[offset + b]) << BigInt(8 * b);
    offset += 8;
    if (v > BigInt(Number.MAX_SAFE_INTEGER)) {
      throw new Error("parseAuthenticatedOutput: output value exceeds MAX_SAFE_INTEGER");
    }
    const spkLenV = readVarInt(tx, offset);
    if (!spkLenV) throw new Error("parseAuthenticatedOutput: truncated scriptPubKey length");
    offset += spkLenV.bytesRead;
    if (offset + spkLenV.value > tx.length) {
      throw new Error("parseAuthenticatedOutput: scriptPubKey overruns tx");
    }
    if (i === voutIndex) {
      value = Number(v);
      scriptPubKey = tx.slice(offset, offset + spkLenV.value);
    }
    offset += spkLenV.value;
  }
  const outputsEnd = offset;
  if (tx.length < outputsEnd + 4) throw new Error("parseAuthenticatedOutput: tx too short for nLockTime");
  let stripped;
  if (segwit) {
    const ver = tx.slice(0, 4), body = tx.slice(inputsStart, outputsEnd), lt = tx.slice(tx.length - 4);
    stripped = new Uint8Array(ver.length + body.length + lt.length);
    stripped.set(ver, 0);
    stripped.set(body, ver.length);
    stripped.set(lt, ver.length + body.length);
  } else {
    stripped = tx;
  }
  const computedTxid = bytesToHex(reverseBytes(hash256(stripped)));
  if (computedTxid !== expectedTxid.toLowerCase()) {
    throw new Error(
      `parseAuthenticatedOutput: txid mismatch \u2014 proxy returned bytes for ${computedTxid} but expected ${expectedTxid.toLowerCase()} (possible malicious/compromised proxy)`
    );
  }
  if (!Number.isInteger(value) || value <= 0) {
    throw new Error(`parseAuthenticatedOutput: output ${voutIndex} has non-positive value ${value}`);
  }
  return { value, scriptPubKey };
}
function computeSighash(inputs, outputs, inputIndex, hashType, useBip143, nLockTime, nSequence) {
  if (inputIndex < 0 || inputIndex >= inputs.length) {
    throw new Error(`computeSighash: inputIndex ${inputIndex} out of range (inputs.length=${inputs.length})`);
  }
  if (!Number.isInteger(nLockTime) || nLockTime < 0 || nLockTime > 4294967295) {
    throw new Error(`computeSighash: nLockTime must be a uint32 [0, 0xFFFFFFFF]; got ${nLockTime}`);
  }
  const version = writeUInt32LE(2);
  const locktime = writeUInt32LE(nLockTime);
  if (useBip143) {
    const anyoneCanPay = (hashType & 128) !== 0;
    const prevoutsData = [];
    for (const { utxo } of inputs) {
      prevoutsData.push(reverseBytes(hexToBytes(utxo.tx_hash)));
      prevoutsData.push(writeUInt32LE(utxo.tx_pos));
    }
    const hashPrevouts = anyoneCanPay ? new Uint8Array(32) : hash256(concat(...prevoutsData));
    const sequenceData = [];
    for (let i = 0; i < inputs.length; i++) {
      sequenceData.push(writeUInt32LE(nSequence));
    }
    const baseHashType = hashType & 31;
    const hashSequence = anyoneCanPay || baseHashType === 2 || baseHashType === 3 ? new Uint8Array(32) : hash256(concat(...sequenceData));
    let hashOutputs;
    if (baseHashType === 3) {
      if (inputIndex < outputs.length) {
        const o = outputs[inputIndex];
        hashOutputs = hash256(concat(
          writeUInt64LE(o.value),
          writeVarInt(o.scriptPubKey.length),
          o.scriptPubKey
        ));
      } else {
        hashOutputs = new Uint8Array(32);
      }
    } else if (baseHashType === 2) {
      hashOutputs = new Uint8Array(32);
    } else {
      const outputsData = [];
      for (const output of outputs) {
        outputsData.push(
          writeUInt64LE(output.value),
          writeVarInt(output.scriptPubKey.length),
          output.scriptPubKey
        );
      }
      hashOutputs = hash256(concat(...outputsData));
    }
    const input = inputs[inputIndex];
    const preimage = concat(
      version,
      hashPrevouts,
      hashSequence,
      reverseBytes(hexToBytes(input.utxo.tx_hash)),
      writeUInt32LE(input.utxo.tx_pos),
      writeVarInt(input.scriptCode.length),
      input.scriptCode,
      writeUInt64LE(input.utxo.value),
      writeUInt32LE(nSequence),
      hashOutputs,
      locktime,
      writeUInt32LE(hashType)
    );
    return hash256(preimage);
  } else {
    const parts = [version, writeVarInt(inputs.length)];
    const baseHashType = hashType & 31;
    if (baseHashType === 2 || baseHashType === 3) {
      throw new Error(`legacy SIGHASH_NONE/SINGLE (0x${baseHashType.toString(16)}) not supported \u2014 only SIGHASH_ALL`);
    }
    for (let i = 0; i < inputs.length; i++) {
      const { utxo } = inputs[i];
      parts.push(reverseBytes(hexToBytes(utxo.tx_hash)));
      parts.push(writeUInt32LE(utxo.tx_pos));
      if (i === inputIndex) {
        parts.push(writeVarInt(inputs[i].scriptCode.length));
        parts.push(inputs[i].scriptCode);
      } else {
        parts.push(new Uint8Array([0]));
      }
      const seqForInput = i === inputIndex || baseHashType === 1 ? nSequence : 0;
      parts.push(writeUInt32LE(seqForInput));
    }
    if (baseHashType === 2) {
      parts.push(writeVarInt(0));
    } else if (baseHashType === 3) {
      if (inputIndex < outputs.length) {
        parts.push(writeVarInt(inputIndex + 1));
        for (let i = 0; i < inputIndex; i++) {
          parts.push(new Uint8Array([255, 255, 255, 255, 255, 255, 255, 255]));
          parts.push(writeVarInt(0));
        }
        parts.push(writeUInt64LE(outputs[inputIndex].value));
        parts.push(writeVarInt(outputs[inputIndex].scriptPubKey.length));
        parts.push(outputs[inputIndex].scriptPubKey);
      } else {
        parts.push(writeVarInt(0));
      }
    } else {
      parts.push(writeVarInt(outputs.length));
      for (const output of outputs) {
        parts.push(writeUInt64LE(output.value));
        parts.push(writeVarInt(output.scriptPubKey.length));
        parts.push(output.scriptPubKey);
      }
    }
    parts.push(locktime);
    parts.push(writeUInt32LE(hashType));
    return hash256(concat(...parts));
  }
}
async function buildSignedTx(inputs, outputs, hashType, useBip143, chain) {
  const scriptCodeInputs = inputs.map((i) => ({ utxo: i.utxo, scriptCode: i.scriptPubKey }));
  const signatures = [];
  for (let i = 0; i < inputs.length; i++) {
    const sighash = computeSighash(scriptCodeInputs, outputs, i, hashType, useBip143, 0, 4294967295);
    const sig = await secp256k12.signAsync(sighash, inputs[i].privateKey, { lowS: true });
    const sigDer = compactToDER(sig.toCompactRawBytes());
    signatures.push(concat(sigDer, new Uint8Array([hashType])));
  }
  const txInputs = inputs.map((inp, i) => {
    const scriptSig = concat(
      pushData(signatures[i]),
      pushData(inp.publicKey)
    );
    return { utxo: inp.utxo, scriptSig, nSequence: 4294967295 };
  });
  const { txid, rawTx } = serializeTx(txInputs, outputs, 0);
  const totalIn = inputs.reduce((s, i) => s + i.utxo.value, 0);
  const totalOut = outputs.reduce((s, o) => s + o.value, 0);
  return { txid, rawTx, fee: totalIn - totalOut };
}
function serializeTx(inputs, outputs, nLockTime) {
  if (!Number.isInteger(nLockTime) || nLockTime < 0 || nLockTime > 4294967295) {
    throw new Error(`serializeTx: nLockTime must be a uint32 [0, 0xFFFFFFFF]; got ${nLockTime}`);
  }
  const parts = [
    writeUInt32LE(2),
    // version
    writeVarInt(inputs.length)
  ];
  for (const { utxo, scriptSig, nSequence } of inputs) {
    parts.push(reverseBytes(hexToBytes(utxo.tx_hash)));
    parts.push(writeUInt32LE(utxo.tx_pos));
    parts.push(writeVarInt(scriptSig.length));
    parts.push(scriptSig);
    parts.push(writeUInt32LE(nSequence));
  }
  parts.push(writeVarInt(outputs.length));
  for (const { scriptPubKey, value } of outputs) {
    parts.push(writeUInt64LE(value));
    parts.push(writeVarInt(scriptPubKey.length));
    parts.push(scriptPubKey);
  }
  parts.push(writeUInt32LE(nLockTime));
  const rawTxBytes = concat(...parts);
  const txid = bytesToHex(reverseBytes(hash256(rawTxBytes)));
  return { txid, rawTx: bytesToHex(rawTxBytes) };
}

// src/swap-flow.ts
async function verifyAndAuthenticateUtxo(proxyUtxo, redeemScript, fetchRawTx) {
  if (!proxyUtxo || typeof proxyUtxo.tx_hash !== "string" || !/^[0-9a-f]{64}$/.test(proxyUtxo.tx_hash)) {
    throw new Error("verifyAndAuthenticateUtxo: malformed UTXO tx_hash from proxy");
  }
  if (!Number.isInteger(proxyUtxo.tx_pos) || proxyUtxo.tx_pos < 0) {
    throw new Error("verifyAndAuthenticateUtxo: malformed UTXO tx_pos from proxy");
  }
  const rawTx = await fetchRawTx(proxyUtxo.tx_hash);
  const { value, scriptPubKey } = parseAuthenticatedOutput(rawTx, proxyUtxo.tx_hash, proxyUtxo.tx_pos);
  const expectedSpk = new Uint8Array([169, 20, ...hash160(redeemScript), 135]);
  if (scriptPubKey.length !== expectedSpk.length || !scriptPubKey.every((b, i) => b === expectedSpk[i])) {
    throw new Error(
      "verifyAndAuthenticateUtxo: funded output scriptPubKey does not match the HTLC P2SH \u2014 the proxy pointed at the wrong output (possible malicious/compromised proxy)"
    );
  }
  if (Number.isFinite(proxyUtxo.value) && proxyUtxo.value !== value) {
    console.warn(
      `[swap-flow] proxy listunspent value ${proxyUtxo.value} != authenticated value ${value} for ${proxyUtxo.tx_hash}:${proxyUtxo.tx_pos} \u2014 using authenticated value`
    );
  }
  return { ...proxyUtxo, value };
}
async function verifyAndAuthenticateP2pkhInput(proxyUtxo, expectedPubkeyHash, fetchRawTx) {
  if (!proxyUtxo || typeof proxyUtxo.tx_hash !== "string" || !/^[0-9a-f]{64}$/.test(proxyUtxo.tx_hash)) {
    throw new Error("verifyAndAuthenticateP2pkhInput: malformed UTXO tx_hash from proxy");
  }
  if (!Number.isInteger(proxyUtxo.tx_pos) || proxyUtxo.tx_pos < 0) {
    throw new Error("verifyAndAuthenticateP2pkhInput: malformed UTXO tx_pos from proxy");
  }
  if (!(expectedPubkeyHash instanceof Uint8Array) || expectedPubkeyHash.length !== 20) {
    throw new Error("verifyAndAuthenticateP2pkhInput: expectedPubkeyHash must be 20 bytes");
  }
  const rawTx = await fetchRawTx(proxyUtxo.tx_hash);
  const { value, scriptPubKey } = parseAuthenticatedOutput(rawTx, proxyUtxo.tx_hash, proxyUtxo.tx_pos);
  const expectedSpk = new Uint8Array([118, 169, 20, ...expectedPubkeyHash, 136, 172]);
  if (scriptPubKey.length !== expectedSpk.length || !scriptPubKey.every((b, i) => b === expectedSpk[i])) {
    throw new Error(
      "verifyAndAuthenticateP2pkhInput: input scriptPubKey does not match the expected own-address P2PKH \u2014 the proxy supplied a wrong/foreign input value (possible malicious/compromised proxy)"
    );
  }
  return { ...proxyUtxo, value };
}
function assertUtxoChain(chain) {
  if (chainConfigs[chain].isEvm) {
    throw new Error(`HTLC UTXO construction not supported for EVM chain '${chain}' \u2014 use evm-client.ts`);
  }
}
function createInitiatorHTLC(state, currentHeight, recipientPubkeyHash, refundPubkeyHash) {
  assertUtxoChain(state.offer.sendChain);
  const locktime = currentHeight + LOCKTIME_BLOCKS.initiator;
  const params = {
    secretHash: state.secretHash,
    recipientPubkeyHash,
    refundPubkeyHash,
    locktime
  };
  return createHTLC(params, state.offer.sendChain);
}
function createResponderHTLC(state, currentHeight, initiatorPubkeyHash, refundPubkeyHash, explicitLocktime) {
  assertUtxoChain(state.offer.receiveChain);
  const locktime = currentHeight + LOCKTIME_BLOCKS.responder;
  const params = {
    secretHash: state.secretHash,
    recipientPubkeyHash: initiatorPubkeyHash,
    refundPubkeyHash,
    locktime
  };
  return createHTLC(params, state.offer.receiveChain);
}
function getHTLCScripthash(redeemScript) {
  return htlcScripthash(redeemScript);
}
async function fundHTLC(htlc, utxos, privateKey, publicKey, p2pkhScript, amount, chain, feeRate) {
  assertUtxoChain(chain);
  const inputs = utxos.map((utxo) => ({
    utxo,
    privateKey,
    publicKey,
    scriptPubKey: p2pkhScript
  }));
  return buildHTLCFundingTx(
    inputs,
    htlc.p2shScriptPubKey,
    amount,
    p2pkhScript,
    // change back to same address
    chain,
    feeRate
  );
}
async function claimHTLC(utxo, redeemScript, secret, privateKey, publicKey, destPubkeyHash, chain, feeRate) {
  assertUtxoChain(chain);
  if (secret.length !== 32) throw new Error(`HTLC secret must be exactly 32 bytes; got ${secret.length}`);
  if (destPubkeyHash.length !== 20) throw new Error("destPubkeyHash must be exactly 20 bytes");
  const destP2PKH = new Uint8Array([118, 169, 20, ...destPubkeyHash, 136, 172]);
  return buildHTLCClaimTx(utxo, redeemScript, secret, privateKey, publicKey, destP2PKH, chain, feeRate);
}
function extractSecret(rawTxHex, expectedSecretHash) {
  return extractSecretFromClaimTx(rawTxHex, expectedSecretHash);
}
var CHARSET2 = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
var CHARSET_MAP = {};
for (let i = 0; i < CHARSET2.length; i++) {
  CHARSET_MAP[CHARSET2[i]] = i;
}
var BASE58_ALPHABET2 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
function hash1602(data) {
  return ripemd160(sha256(data));
}
function doubleHash(data) {
  return sha256(sha256(data));
}
function cashAddrPolymod2(values) {
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
function packAddrData2(hash, type) {
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
function encodeCashAddr2(prefix, type, hash) {
  const prefixValues = prefixToValues(prefix);
  const payload = packAddrData2(hash, type);
  const checksumInput = [...prefixValues, ...payload, 0, 0, 0, 0, 0, 0, 0, 0];
  const polymod = cashAddrPolymod2(checksumInput) ^ 1n;
  const checksumArray = [];
  for (let i = 0; i < 8; i++) {
    checksumArray.push(Number(polymod >> BigInt(5 * (7 - i)) & 0x1fn));
  }
  const combined = [...payload, ...checksumArray];
  let result = prefix + ":";
  for (const value of combined) {
    result += CHARSET2[value];
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
  if (cashAddrPolymod2(checksumInput) !== 1n) return null;
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
function encodeBase582(data) {
  let num = 0n;
  for (let i = 0; i < data.length; i++) {
    num = num * 256n + BigInt(data[i]);
  }
  let result = "";
  while (num > 0n) {
    const remainder = Number(num % 58n);
    num = num / 58n;
    result = BASE58_ALPHABET2[remainder] + result;
  }
  for (let i = 0; i < data.length && data[i] === 0; i++) {
    result = "1" + result;
  }
  return result;
}
function decodeBase58(str) {
  let num = 0n;
  for (let i = 0; i < str.length; i++) {
    const index = BASE58_ALPHABET2.indexOf(str[i]);
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
  return encodeBase582(full);
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
  const pubkeyHash = hash1602(pubkey);
  return encodeCashAddr2("bitcoincashii", 0, pubkeyHash);
}
function pubkeyToBC2Address(pubkey) {
  const pubkeyHash = hash1602(pubkey);
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
  return encodeBase582(full);
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
  const pubkeyHash = hash1602(pubkey);
  return encodeBech32("bc", 0, pubkeyHash);
}
function pubkeyToBCHAddress(pubkey) {
  const pubkeyHash = hash1602(pubkey);
  return encodeCashAddr2("bitcoincash", 0, pubkeyHash);
}
function pubkeyToBTCAddress(pubkey) {
  const pubkeyHash = hash1602(pubkey);
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
  const pubkeyHash = hash1602(pubkey);
  const redeemScript = new Uint8Array([0, 20, ...pubkeyHash]);
  const scriptHash = hash1602(redeemScript);
  const versioned = new Uint8Array([5, ...scriptHash]);
  const checksum = doubleHash(versioned).slice(0, 4);
  const full = new Uint8Array([...versioned, ...checksum]);
  return encodeBase582(full);
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
  const scriptHash = hash1602(redeemScript);
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
function hash2562(d) {
  return sha256(sha256(d));
}
function concat2(...arrs) {
  let n = 0;
  for (const a of arrs) n += a.length;
  const out = new Uint8Array(n);
  let o = 0;
  for (const a of arrs) {
    out.set(a, o);
    o += a.length;
  }
  return out;
}
function reverse(a) {
  const b = new Uint8Array(a.length);
  for (let i = 0; i < a.length; i++) b[i] = a[a.length - 1 - i];
  return b;
}
function equalBytes(a, b) {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i];
  return d === 0;
}
function hexToBytes2(h) {
  const s = h.startsWith("0x") ? h.slice(2) : h;
  if (s.length % 2) throw new Error("odd hex");
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) {
    const b = parseInt(s.substr(i * 2, 2), 16);
    if (Number.isNaN(b)) throw new Error("bad hex");
    out[i] = b;
  }
  return out;
}
function leBytesToBigInt(a) {
  let n = 0n;
  for (let i = a.length - 1; i >= 0; i--) n = n << 8n | BigInt(a[i]);
  return n;
}
function bitLength(n) {
  return n <= 0n ? 0 : n.toString(2).length;
}
function targetFromCompact(nCompact) {
  const nSize = nCompact >>> 24;
  const nWordRaw = nCompact & 8388607;
  let nWord = BigInt(nWordRaw);
  let target;
  if (nSize <= 3) {
    nWord >>= BigInt(8 * (3 - nSize));
    target = nWord;
  } else {
    target = BigInt(nWordRaw) << BigInt(8 * (nSize - 3));
  }
  const negative = nWord !== 0n && (nCompact & 8388608) !== 0;
  const overflow = nWord !== 0n && (nSize > 34 || nWord > 0xffn && nSize > 33 || nWord > 0xffffn && nSize > 32);
  return { target, negative, overflow };
}
function compactFromTarget(target) {
  let nSize = Math.floor((bitLength(target) + 7) / 8);
  let low;
  if (nSize <= 3) low = (target & 0xffffffffffffffffn) << BigInt(8 * (3 - nSize));
  else low = target >> BigInt(8 * (nSize - 3)) & 0xffffffffffffffffn;
  let nCompact = Number(low & 0xffffffffn) >>> 0;
  if (nCompact & 8388608) {
    nCompact >>>= 8;
    nSize++;
  }
  nCompact = (nCompact | nSize << 24) >>> 0;
  return nCompact;
}
function calculateASERT(refTarget, spacing, timeDiff, heightDiff, powLimit, halfLife) {
  if (heightDiff < 0n) throw new Error("ASERT: negative heightDiff");
  if (refTarget <= 0n || refTarget > powLimit) throw new Error("ASERT: refTarget out of range");
  const exponent = (timeDiff - spacing * (heightDiff + 1n)) * 65536n / halfLife;
  const shifts0 = exponent >> 16n;
  const frac = exponent & 0xFFFFn;
  const factor = 65536n + (195766423245049n * frac + 971821376n * frac * frac + 5127n * frac * frac * frac + (1n << 47n) >> 48n);
  let nextTarget = refTarget * factor;
  const shifts = shifts0 - 16n;
  if (shifts <= 0n) nextTarget >>= -shifts;
  else nextTarget <<= shifts;
  if (nextTarget === 0n) return 1n;
  if (nextTarget > powLimit) return powLimit;
  return nextTarget;
}
var BCH2_MAINNET_ASERT = {
  anchorHeight: 53201,
  anchorBits: 419668748,
  anchorParentTime: 1772649180,
  spacing: 600n,
  powLimit: 0x00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffn,
  halfLife: (h) => h >= 92736 ? 172800n : 3600n
};
var BCH_MAINNET_ASERT = {
  anchorHeight: 661647,
  anchorBits: 402971390,
  anchorParentTime: 1605447844,
  spacing: 600n,
  powLimit: 0x00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffn,
  halfLife: () => 172800n
};
var BTC_MAINNET_LEGACY = { powLimit: 0x00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffn, targetTimespan: 1209600n, interval: 2016 };
var BC2_MAINNET_LEGACY = { powLimit: 0x00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffn, targetTimespan: 1209600n, interval: 2016 };
function getNextWorkRequiredLegacy(height, prevBits, prevTime, firstTime, p) {
  if (height % p.interval !== 0) return prevBits;
  let actual = BigInt(prevTime - firstTime);
  if (actual < p.targetTimespan / 4n) actual = p.targetTimespan / 4n;
  if (actual > p.targetTimespan * 4n) actual = p.targetTimespan * 4n;
  const { target } = targetFromCompact(prevBits);
  let next = target * actual / p.targetTimespan;
  if (next > p.powLimit) next = p.powLimit;
  return compactFromTarget(next);
}
var BTC_MAINNET_CHECKPOINT = {
  height: 955584,
  hashDisplay: "00000000000000000001e265c627e0a27ad347deb4d6b921f249eddfbf78e011",
  time: 1782525607,
  bits: 386013762
};
var BC2_MAINNET_CHECKPOINT = {
  height: 56448,
  hashDisplay: "0000000000000000303afa22bcc2736d86b5142a6c8d313f45df822ef44ae907",
  time: 1779492169,
  bits: 406751414
};
var BCH2_MAINNET_CHECKPOINT = {
  height: 71e3,
  hashDisplay: "0000000000000009271d1b0554f651d7102b8f7622f74c50eb20963f62910117",
  time: 1783333735
};
var BCH_MAINNET_CHECKPOINT = {
  height: 958521,
  hashDisplay: "000000000000000001d83f6025669747451cc3d676f9577044f87f6b66410b00",
  time: 1783373746
};
function getNextWorkRequiredASERT(prevHeight, prevTime, p) {
  const nextHeight = prevHeight + 1;
  if (nextHeight < p.anchorHeight) throw new Error(`SPV: height ${nextHeight} is at/below the fork block (pre-fork BC2, not ASERT)`);
  if (nextHeight === p.anchorHeight) return p.anchorBits;
  const { target: refTarget, negative, overflow } = targetFromCompact(p.anchorBits);
  if (negative || overflow || refTarget === 0n) throw new Error("ASERT: bad anchor bits");
  const timeDiff = BigInt(prevTime - p.anchorParentTime);
  const heightDiff = BigInt(prevHeight - p.anchorHeight);
  return compactFromTarget(calculateASERT(refTarget, p.spacing, timeDiff, heightDiff, p.powLimit, p.halfLife(nextHeight)));
}
function parseHeader(raw) {
  if (raw.length !== 80) throw new Error("header must be exactly 80 bytes");
  const dv = new DataView(raw.buffer, raw.byteOffset, 80);
  return {
    version: dv.getInt32(0, true),
    prevHash: raw.slice(4, 36),
    merkleRoot: raw.slice(36, 68),
    time: dv.getUint32(68, true),
    bits: dv.getUint32(72, true),
    nonce: dv.getUint32(76, true),
    raw: raw.slice(0, 80)
  };
}
function blockHashInternal(raw) {
  return hash2562(raw);
}
function checkPoW(raw, bits, powLimit) {
  const { target, negative, overflow } = targetFromCompact(bits);
  if (negative || overflow || target === 0n || target > powLimit) return false;
  return leBytesToBigInt(hash2562(raw)) <= target;
}
function merkleRootFromBranch(txidInternal, branchInternal, pos) {
  let h = txidInternal;
  let index = pos >>> 0;
  for (const sib of branchInternal) {
    h = index & 1 ? hash2562(concat2(sib, h)) : hash2562(concat2(h, sib));
    index >>>= 1;
  }
  return h;
}
function readVarIntAt(tx, off) {
  const b = tx[off];
  if (b === void 0) throw new Error("SPV: varint out of range");
  if (b < 253) return [b, 1];
  if (b === 253) return [tx[off + 1] | tx[off + 2] << 8, 3];
  if (b === 254) return [(tx[off + 1] | tx[off + 2] << 8 | tx[off + 3] << 16 | tx[off + 4] << 24) >>> 0, 5];
  let v = 0;
  for (let i = 0; i < 6; i++) v += tx[off + 1 + i] * 2 ** (8 * i);
  return [v, 9];
}
function legacySerialization(tx) {
  if (tx.length < 10 || tx[4] !== 0) return tx;
  if (tx[5] !== 1) throw new Error("SPV: SegWit marker (0x00) without a valid flag (0x01)");
  const inputsStart = 6;
  let o = inputsStart;
  const [nIn, nInLen] = readVarIntAt(tx, o);
  o += nInLen;
  if (nIn === 0 || nIn > 1e5) throw new Error("SPV: implausible input count in SegWit tx");
  for (let i = 0; i < nIn; i++) {
    o += 36;
    const [ssLen, ssLenLen] = readVarIntAt(tx, o);
    o += ssLenLen + ssLen + 4;
    if (o > tx.length) throw new Error("SPV: input overruns SegWit tx");
  }
  const [nOut, nOutLen] = readVarIntAt(tx, o);
  o += nOutLen;
  if (nOut > 1e5) throw new Error("SPV: implausible output count in SegWit tx");
  for (let i = 0; i < nOut; i++) {
    o += 8;
    const [spkLen, spkLenLen] = readVarIntAt(tx, o);
    o += spkLenLen + spkLen;
    if (o > tx.length) throw new Error("SPV: output overruns SegWit tx");
  }
  const outputsEnd = o;
  if (tx.length < outputsEnd + 4) throw new Error("SPV: SegWit tx too short for nLockTime");
  return concat2(tx.slice(0, 4), tx.slice(inputsStart, outputsEnd), tx.slice(tx.length - 4));
}
function verifyMerkleInclusion(rawTxHex, merkleHexReversed, pos, merkleRootInternal) {
  const rawTx = legacySerialization(hexToBytes2(rawTxHex));
  const txidInternal = hash2562(rawTx);
  const branchInternal = merkleHexReversed.map((h) => reverse(hexToBytes2(h)));
  const root = merkleRootFromBranch(txidInternal, branchInternal, pos);
  if (!equalBytes(root, merkleRootInternal)) throw new Error("Merkle inclusion proof does not match the block header merkle root");
  return bytesToHex2(reverse(txidInternal));
}
function bytesToHex2(a) {
  let s = "";
  for (const b of a) s += b.toString(16).padStart(2, "0");
  return s;
}
var MAX_HEADER_FUTURE_SEC = 7200;
function medianTimePast(window2) {
  const w = window2.slice(-11).slice().sort((a, b) => a - b);
  return w[Math.floor(w.length / 2)];
}
function verifyHeaderChain(headers, startHeight, prevHashOfStart, p, prevTimeOfStart, trustedNowSec, priorTimes = []) {
  const out = /* @__PURE__ */ new Map();
  let expectedPrevHash = prevHashOfStart;
  let prevTime = prevTimeOfStart;
  let prevHeight = startHeight - 1;
  const times = priorTimes.slice(-11);
  for (let i = 0; i < headers.length; i++) {
    const height = startHeight + i;
    const h = parseHeader(headers[i]);
    if (!equalBytes(h.prevHash, expectedPrevHash)) throw new Error(`header ${height}: prevHash does not link to ${prevHeight}`);
    if (!checkPoW(h.raw, h.bits, p.powLimit)) throw new Error(`header ${height}: proof-of-work below target`);
    if (h.time > trustedNowSec + MAX_HEADER_FUTURE_SEC) throw new Error(`header ${height}: timestamp ${h.time} exceeds trusted now + 2h`);
    if (times.length >= 11 && h.time <= medianTimePast(times)) throw new Error(`header ${height}: timestamp ${h.time} not above median-time-past`);
    const expectedBits = getNextWorkRequiredASERT(prevHeight, prevTime, p);
    if (h.bits !== expectedBits) throw new Error(`header ${height}: nBits 0x${h.bits.toString(16)} != expected ASERT 0x${expectedBits.toString(16)}`);
    out.set(height, h);
    expectedPrevHash = blockHashInternal(h.raw);
    prevTime = h.time;
    prevHeight = height;
    times.push(h.time);
  }
  return out;
}
function verifyLegacyChunk(headers, startHeight, prevHashOfStart, prevBitsOfStart, prevTimeOfStart, p, getPriorTime, trustedNowSec, priorTimes = []) {
  const out = /* @__PURE__ */ new Map();
  let expectedPrevHash = prevHashOfStart;
  let prevBits = prevBitsOfStart;
  let prevTime = prevTimeOfStart;
  let prevHeight = startHeight - 1;
  const times = priorTimes.slice(-11);
  for (let i = 0; i < headers.length; i++) {
    const height = startHeight + i;
    const h = parseHeader(headers[i]);
    if (!equalBytes(h.prevHash, expectedPrevHash)) throw new Error(`legacy header ${height}: prevHash does not link to ${prevHeight}`);
    if (!checkPoW(h.raw, h.bits, p.powLimit)) throw new Error(`legacy header ${height}: proof-of-work below target`);
    if (h.time > trustedNowSec + MAX_HEADER_FUTURE_SEC) throw new Error(`legacy header ${height}: timestamp ${h.time} exceeds trusted now + 2h`);
    if (times.length >= 11 && h.time <= medianTimePast(times)) throw new Error(`legacy header ${height}: timestamp ${h.time} not above median-time-past`);
    let expected;
    if (height % p.interval !== 0) {
      expected = prevBits;
    } else {
      const firstTime = getPriorTime(height - p.interval);
      expected = getNextWorkRequiredLegacy(height, prevBits, prevTime, firstTime, p);
    }
    if (h.bits !== expected) throw new Error(`legacy header ${height}: nBits 0x${h.bits.toString(16)} != expected 0x${expected.toString(16)}`);
    out.set(height, h);
    expectedPrevHash = blockHashInternal(h.raw);
    prevBits = h.bits;
    prevTime = h.time;
    prevHeight = height;
    times.push(h.time);
  }
  return out;
}

// src/spv-verifier.ts
var REGTEST2 = globalThis.process?.env?.BCH2_SWAP_NETWORK === "regtest";
function legacy(params, cp) {
  if (cp.bits === void 0) throw new Error("legacy checkpoint missing bits");
  if (cp.height % params.interval !== 0) throw new Error("legacy checkpoint not on a retarget boundary");
  return { mode: "legacy", params, checkpoint: { ...cp, bits: cp.bits } };
}
var SPV = REGTEST2 ? {} : {
  bch2: { mode: "asert", params: BCH2_MAINNET_ASERT, checkpoint: BCH2_MAINNET_CHECKPOINT },
  bch: { mode: "asert", params: BCH_MAINNET_ASERT, checkpoint: BCH_MAINNET_CHECKPOINT },
  btc: legacy(BTC_MAINNET_LEGACY, BTC_MAINNET_CHECKPOINT),
  bc2: legacy(BC2_MAINNET_LEGACY, BC2_MAINNET_CHECKPOINT)
};
function spvSupported(chain) {
  return chain in SPV;
}
var HEADERS_PER_CALL = 500;
var cache = /* @__PURE__ */ new Map();
var locks = /* @__PURE__ */ new Map();
function reverseHexToInternal(displayHex) {
  const s = displayHex.startsWith("0x") ? displayHex.slice(2) : displayHex;
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(s.substr(i * 2, 2), 16);
  return out.reverse();
}
function splitHeaders(hex, count) {
  const out = [];
  for (let i = 0; i < count; i++) {
    const chunk = hex.slice(i * 160, (i + 1) * 160);
    if (chunk.length !== 160) throw new Error("SPV: short header in batch");
    const b = new Uint8Array(80);
    for (let j = 0; j < 80; j++) b[j] = parseInt(chunk.substr(j * 2, 2), 16);
    out.push(b);
  }
  return out;
}
async function withLock(chain, fn) {
  const prev = locks.get(chain) ?? Promise.resolve();
  let release;
  const p = new Promise((r) => {
    release = r;
  });
  locks.set(chain, prev.then(() => p));
  await prev.catch(() => {
  });
  try {
    return await fn();
  } finally {
    release();
  }
}
async function extendVerifiedChain(client, chain, tipHeight) {
  const cfg = SPV[chain];
  if (!cfg) throw new Error(`SPV not supported for ${chain}`);
  if (tipHeight <= cfg.checkpoint.height) throw new Error(`SPV: tip ${tipHeight} is at/below checkpoint ${cfg.checkpoint.height}`);
  return withLock(chain, async () => {
    let v = cache.get(chain);
    if (!v) v = {
      tipHeight: cfg.checkpoint.height,
      lastHashInternal: reverseHexToInternal(cfg.checkpoint.hashDisplay),
      lastTime: cfg.checkpoint.time,
      lastBits: cfg.mode === "legacy" ? cfg.checkpoint.bits : 0,
      headers: /* @__PURE__ */ new Map()
    };
    const trustedNowSec = Math.floor(Date.now() / 1e3);
    while (v.tipHeight < tipHeight) {
      const start = v.tipHeight + 1;
      const want = Math.min(HEADERS_PER_CALL, tipHeight - v.tipHeight);
      const res = await client.getBlockHeaders(start, want);
      const raws = splitHeaders(res.hex, res.count);
      if (raws.length === 0) throw new Error("SPV: proxy returned no headers");
      const priorTimes = [];
      for (let hh = start - 11; hh < start; hh++) {
        if (hh === cfg.checkpoint.height) priorTimes.push(cfg.checkpoint.time);
        else {
          const hd = v.headers.get(hh);
          if (hd) priorTimes.push(hd.time);
        }
      }
      let map;
      if (cfg.mode === "asert") {
        map = verifyHeaderChain(raws, start, v.lastHashInternal, cfg.params, v.lastTime, trustedNowSec, priorTimes);
      } else {
        const vv = v;
        const cp = cfg.checkpoint;
        const getPriorTime = (height) => {
          if (height === cp.height) return cp.time;
          const hd = vv.headers.get(height);
          if (!hd) throw new Error(`SPV: missing retarget lookback header ${height}`);
          return hd.time;
        };
        map = verifyLegacyChunk(raws, start, v.lastHashInternal, v.lastBits, v.lastTime, cfg.params, getPriorTime, trustedNowSec, priorTimes);
      }
      for (const [h, hdr] of map) v.headers.set(h, hdr);
      const lastHeight = start + raws.length - 1;
      const last = map.get(lastHeight);
      v.lastHashInternal = blockHashInternal(last.raw);
      v.lastTime = last.time;
      v.lastBits = last.bits;
      v.tipHeight = lastHeight;
    }
    cache.set(chain, v);
    return v;
  });
}
async function verifyConfirmations(client, chain, txid, claimedHeight, rawTxHex, tipHeight) {
  const cfg = SPV[chain];
  if (!cfg) throw new Error(`SPV not supported for ${chain}`);
  if (cfg.mode === "asert" && claimedHeight < cfg.params.anchorHeight) throw new Error(`SPV: funding height ${claimedHeight} is pre-fork (< ${cfg.params.anchorHeight})`);
  if (!Number.isInteger(claimedHeight) || claimedHeight <= cfg.checkpoint.height) throw new Error(`SPV: funding height ${claimedHeight} at/below checkpoint`);
  if (claimedHeight > tipHeight) throw new Error(`SPV: funding height ${claimedHeight} above tip ${tipHeight}`);
  const v = await extendVerifiedChain(client, chain, tipHeight);
  const header = v.headers.get(claimedHeight);
  if (!header) throw new Error(`SPV: no verified header at height ${claimedHeight}`);
  const proof = await client.getMerkleProof(txid, claimedHeight);
  if (proof.block_height !== claimedHeight) throw new Error(`SPV: proof height ${proof.block_height} != ${claimedHeight}`);
  const provenTxid = verifyMerkleInclusion(rawTxHex, proof.merkle, proof.pos, header.merkleRoot);
  if (provenTxid.toLowerCase() !== txid.toLowerCase()) throw new Error(`SPV: proven txid ${provenTxid} != requested ${txid}`);
  return Math.min(v.tipHeight, tipHeight) - claimedHeight + 1;
}
async function verifyFundingHeight(client, chain, claimedHeight) {
  const cfg = SPV[chain];
  if (!cfg) throw new Error(`SPV not supported for ${chain}`);
  if (!Number.isInteger(claimedHeight) || claimedHeight <= cfg.checkpoint.height) {
    throw new Error(`SPV: claimed funding height ${claimedHeight} at/below checkpoint ${cfg.checkpoint.height}`);
  }
  const v = await extendVerifiedChain(client, chain, claimedHeight);
  if (v.tipHeight < claimedHeight) throw new Error(`SPV: verified tip ${v.tipHeight} below claimed height ${claimedHeight}`);
  return v.tipHeight;
}
var MAX_TIMING_TIP_STALENESS_SEC = 2 * 60 * 60;
async function spvVerifiedTipFresh(client, chain, claimedTip, maxStalenessSec = MAX_TIMING_TIP_STALENESS_SEC) {
  const cfg = SPV[chain];
  if (!cfg) throw new Error(`SPV not supported for ${chain}`);
  if (!Number.isInteger(claimedTip) || claimedTip <= cfg.checkpoint.height) {
    throw new Error(`SPV: claimed tip ${claimedTip} at/below checkpoint ${cfg.checkpoint.height}`);
  }
  const v = await extendVerifiedChain(client, chain, claimedTip);
  if (v.tipHeight < claimedTip) throw new Error(`SPV: verified tip ${v.tipHeight} below claimed ${claimedTip}`);
  const stalenessSec = Math.floor(Date.now() / 1e3) - v.lastTime;
  if (stalenessSec > maxStalenessSec) {
    throw new Error(`SPV: verified tip is stale (${Math.floor(stalenessSec / 60)}min > ${Math.floor(maxStalenessSec / 60)}min) \u2014 possible proxy height under-reporting`);
  }
  return v.tipHeight;
}
function parseHeaderTimeSec(headerHex) {
  if (typeof headerHex !== "string" || headerHex.length < 144) return null;
  const be = headerHex.slice(136, 144).match(/../g)?.reverse().join("");
  if (!be) return null;
  const t = parseInt(be, 16);
  return Number.isInteger(t) && t >= 1e9 && t <= 1e11 ? t : null;
}
async function getChainTimeSec(client) {
  try {
    const hdr = await Promise.race([
      client.request("blockchain.headers.subscribe", []),
      new Promise((res) => setTimeout(() => res(null), 15e3))
    ]);
    return hdr && typeof hdr.hex === "string" ? parseHeaderTimeSec(hdr.hex) : null;
  } catch {
    return null;
  }
}

// src/timelock-gates.ts
var CLAIM_MARGIN_SEC = CLAIM_MARGIN_BLOCKS * 600;
function marginTooTight(remainingBlocks, blockSec, requiredSec) {
  return minSecondsUntilRefund(remainingBlocks, blockSec) < requiredSec;
}
var NATIVE_ETH_ADDRESS = "0x0000000000000000000000000000000000000000";
var EVM_CHAINS = {
  // R114-CFG-002: Ethereum Sepolia (11155111) — in EvmChainId type but no contract deployed.
  // Included here so getEvmConfig(11155111) returns a config (not null → crash) and so
  // validateEvmConfigs() can check it. DO NOT add to SUPPORTED_EVM_CHAINS until deployed.
  11155111: {
    chainId: 11155111,
    name: "Ethereum Sepolia",
    shortName: "eth",
    nativeSymbol: "ETH",
    avgBlockTimeSec: 12,
    requiredConfirmations: 4,
    // R143: ~48s; Ethereum Sepolia (not deployed/used yet)
    htlcAddress: "0x0000000000000000000000000000000000000000",
    // TODO: deploy contract
    minLockSeconds: 300,
    maxLockSeconds: 86400,
    minLockBlocks: 300,
    maxLockBlocks: 86400,
    rpcUrl: "https://ethereum-sepolia-rpc.publicnode.com",
    tokens: {}
  },
  // R266-ARB-ENABLE: HTLC DEPLOYED on Arbitrum Sepolia + added to SUPPORTED_EVM_CHAINS. Lock params are identical
  // to the proven-safe Base Sepolia (300/86400, on-chain-verified), and Arbitrum supports the 'safe'/'finalized'
  // block tags so the R148/R206 reorg-safe finality reads work. USDT/USDC already deployed on Arbitrum Sepolia.
  421614: {
    chainId: 421614,
    name: "Arbitrum Sepolia",
    shortName: "arb",
    nativeSymbol: "ETH",
    avgBlockTimeSec: 1,
    requiredConfirmations: 30,
    // R143: ~30s at 1s/block (≈ Base Sepolia's 15×2s reorg-safe window)
    htlcAddress: "0x405A6dD5b51a00C5F789C9D215e4986ba1Dc9963",
    // R266: deployed TokenHTLCTestnet (MIN/MAX_LOCK_SECONDS 300/86400, verified on-chain)
    // WARNING: minLockBlocks here overrides chain-config.ts values (mainnet=43200/86400).
    // Swap engine reads from evm-config.ts for EVM-chain config. Keep these consistent with chain-config.ts
    // when deploying to mainnet.
    // R31-EVM-003: 300 blocks = ~5 min on Arb Sepolia (1s/block). Mainnet should use 2160+ (72 min at 1s/block).
    minLockSeconds: 300,
    maxLockSeconds: 86400,
    minLockBlocks: 300,
    maxLockBlocks: 86400,
    rpcUrl: "https://sepolia-rollup.arbitrum.io/rpc",
    tokens: {
      USDT: {
        symbol: "USDT",
        address: "0x1F6A3cEE99F04A306FE99E0E783be4C07DEd2525",
        decimals: 6,
        name: "Tether USD"
      },
      USDC: {
        symbol: "USDC",
        address: "0x77a07183922417C381262723fFe548dBF1afa838",
        decimals: 6,
        name: "USD Coin"
      },
      ETH: { symbol: "ETH", address: NATIVE_ETH_ADDRESS, decimals: 18, name: "Ether" }
      // R266: native ETH swappable (HTLC address(0) path)
    }
  },
  84532: {
    chainId: 84532,
    name: "Base Sepolia",
    shortName: "base",
    nativeSymbol: "ETH",
    avgBlockTimeSec: 2,
    requiredConfirmations: 15,
    // R143: ~30s, past Base Sepolia OP-stack tip-reorg horizon (2s blocks)
    // R138b-XCHAIN-001: canonical TokenHTLCTestnet (UNIX-TIMESTAMP based, MIN_LOCK_SECONDS=300,
    // MAX_LOCK_SECONDS=86400, verified on-chain). Reconciled with packages/swap-core
    // (TOKEN_HTLC_ADDRESS.baseSepoliaTestnet) + prover/e2e/config-base-sepolia.json (htlc_test_address).
    // PREVIOUS value 0xe0ED04861A00FC1f2656AEbde11590CDcBA767a2 was the ZK-DEX BCH2SwapEscrow
    // (no lock/claim/getSwap selectors) — every EVM lock reverted. See AUDIT_LOG R138 / R138b.
    htlcAddress: "0x9A7D64F9dF98112A16E56B1eD9F2Bb8D9986a4cF",
    // R138b-XCHAIN-001: authoritative lock bounds in SECONDS, matching the deployed contract's
    // MIN_LOCK_SECONDS/MAX_LOCK_SECONDS read on-chain. minLockBlocks/maxLockBlocks below are a
    // coarse block-window hint for event scanning only (Base Sepolia ~2s/block → 86400 blocks ≈ 48h).
    minLockSeconds: 300,
    maxLockSeconds: 86400,
    minLockBlocks: 300,
    maxLockBlocks: 86400,
    rpcUrl: "https://sepolia.base.org",
    tokens: {
      USDC: {
        symbol: "USDC",
        // R138b-XCHAIN-001: canonical MockUSDC shared with packages/swap-core + web-wallet
        // (prover/e2e/config-base-sepolia.json usdc_address). PREVIOUS 0x94F6567f… was a divergent
        // bch2-swap-only MockUSDC deployment, breaking interop with canonical-ecosystem counterparties.
        address: "0x5cAd6F5A4eC28Ec42e3953A728a5Eea35719BB0D",
        decimals: 6,
        name: "USD Coin"
      },
      // NOTE: no canonical testnet USDT exists in packages/swap-core. This MockUSDT is bch2-swap-internal
      // (offers are takeable only between bch2-swap users, not canonical-ecosystem wallets). Verified deployed.
      USDT: {
        symbol: "USDT",
        address: "0x0F697BB2f8eAdb75C868CfD58e6096Ab726B3E49",
        decimals: 6,
        name: "Tether USD"
      },
      ETH: { symbol: "ETH", address: NATIVE_ETH_ADDRESS, decimals: 18, name: "Ether" }
      // R266: native ETH swappable (HTLC address(0) path)
    }
  },
  // ── Polygon MAINNET (137) — TokenHTLCSwap deployed 0x405A6dD5b51a00C5F789C9D215e4986ba1Dc9963 (MIN 6h / MAX 48h,
  //    verified on-chain). Token addresses match the KDF/NonKYC PLG20 contracts. minLock/maxLockSeconds MUST equal
  //    the deployed contract's MIN_LOCK_SECONDS/MAX_LOCK_SECONDS. ───────────────────────────────────────────────
  137: {
    chainId: 137,
    name: "Polygon",
    shortName: "poly",
    nativeSymbol: "POL",
    avgBlockTimeSec: 2,
    requiredConfirmations: 128,
    // Polygon reorg safety — well beyond ~16-block milestone finality
    htlcAddress: "0x405A6dD5b51a00C5F789C9D215e4986ba1Dc9963",
    minLockSeconds: 21600,
    // 6h — MUST match contract MIN_LOCK_SECONDS
    maxLockSeconds: 172800,
    // 48h — MUST match contract MAX_LOCK_SECONDS
    minLockBlocks: 10800,
    // ~6h at 2s (event-scan hint only)
    maxLockBlocks: 86400,
    // ~48h at 2s (event-scan hint only)
    // R-POLYHIST: primary must be tenderly (NOT publicnode) — getPublicProvider prepends rpcUrl, and ethers'
    // FallbackProvider uses the FIRST leaf for getLogs; publicnode 403s on getLogs+historical and poisons the
    // read, so it's dropped from Polygon entirely. tenderly serves latest+historical+getLogs; drpc backs it.
    rpcUrl: "https://polygon.gateway.tenderly.co",
    tokens: {
      USDC: { symbol: "USDC", address: "0x3c499c542cEF5E3811e1192ce70d8cC03d5c3359", decimals: 6, name: "USD Coin" },
      // native Circle USDC (KDF/NonKYC USDC-PLG20)
      USDT: { symbol: "USDT", address: "0xc2132D05D31c914a87C6611C10748AEb04B58e8F", decimals: 6, name: "Tether USD" },
      // USDT-PLG20
      POL: { symbol: "POL", address: NATIVE_ETH_ADDRESS, decimals: 18, name: "Polygon" }
      // native gas token (HTLC address(0) path)
    }
  },
  // ── Arbitrum One MAINNET (42161) — TokenHTLCSwap 0x141F8f62F92c6486a7EfE8D0891A6800d7ED1186 (MIN 6h / MAX 48h,
  //    verified on-chain). Native Circle USDC + USDT + native ETH. ───────────────────────────────────────────────
  42161: {
    chainId: 42161,
    name: "Arbitrum",
    shortName: "arb",
    nativeSymbol: "ETH",
    avgBlockTimeSec: 1,
    requiredConfirmations: 30,
    // Arbitrum soft finality is fast (sequencer); reorgs are rare
    htlcAddress: "0x141F8f62F92c6486a7EfE8D0891A6800d7ED1186",
    minLockSeconds: 21600,
    // 6h — MUST match contract MIN_LOCK_SECONDS
    maxLockSeconds: 172800,
    // 48h — MUST match contract MAX_LOCK_SECONDS
    minLockBlocks: 21600,
    maxLockBlocks: 172800,
    // R-POLYHIST: primary must be arb1 (NOT publicnode) — getPublicProvider prepends rpcUrl and ethers uses the FIRST
    // leaf for getLogs; publicnode 403s getLogs beyond ~100 blocks and would poison the secret-read. See FALLBACK_RPCS.
    rpcUrl: "https://arb1.arbitrum.io/rpc",
    tokens: {
      USDC: { symbol: "USDC", address: "0xaf88d065e77c8cC2239327C5EDb3A432268e5831", decimals: 6, name: "USD Coin" },
      // native Circle USDC
      USDT: { symbol: "USDT", address: "0xFd086bC7CD5C481DCC9C85ebE478A1C0b69FCbb9", decimals: 6, name: "Tether USD" },
      // USDT (Arbitrum)
      ETH: { symbol: "ETH", address: NATIVE_ETH_ADDRESS, decimals: 18, name: "Ether" }
      // native gas token
    }
  }
};
function getEvmConfig(chainId) {
  return EVM_CHAINS[chainId] ?? null;
}
var UTXO_REF_BLOCK_SEC = chainConfigs.bch2.avgBlockTimeSec;
var INITIATOR_LOCK_SEC = LOCKTIME_BLOCKS.initiator * UTXO_REF_BLOCK_SEC;
var RESPONDER_LOCK_SEC = LOCKTIME_BLOCKS.responder * UTXO_REF_BLOCK_SEC;
var EVM_CLAIM_MARGIN_SEC = 24 * UTXO_REF_BLOCK_SEC;
function evmLockSecondsForRole(cfg, role) {
  const sec = role === "initiator" ? INITIATOR_LOCK_SEC : RESPONDER_LOCK_SEC;
  return Math.min(Math.max(sec, cfg.minLockSeconds), cfg.maxLockSeconds);
}
function isNativeToken(tokenAddress) {
  return tokenAddress === NATIVE_ETH_ADDRESS;
}
var HTLC_ABI = [
  "function lock(address recipient, address token, uint256 amount, bytes32 hashLock, uint256 timeLock) payable returns (bytes32)",
  "function claim(bytes32 id, bytes32 secret)",
  "function refund(bytes32 id)",
  "function getSwap(bytes32 id) view returns (address initiator, address recipient, address token, uint256 amount, bytes32 hashLock, uint256 timeLock, bool claimed, bool refunded)",
  "event Locked(bytes32 indexed id, address indexed initiator, address recipient, address token, uint256 amount, bytes32 hashLock, uint256 timeLock)",
  "event Claimed(bytes32 indexed id, bytes32 secret)",
  "event Refunded(bytes32 indexed id)"
];
var ERC20_ABI = [
  "function balanceOf(address owner) view returns (uint256)",
  "function allowance(address owner, address spender) view returns (uint256)",
  "function approve(address spender, uint256 amount) returns (bool)"
];
var _activeLocks = /* @__PURE__ */ new Set();
async function bumpedTxFees(signer) {
  try {
    const fd = await Promise.race([
      signer.provider.getFeeData(),
      new Promise((_, rej) => setTimeout(() => rej(new Error("getFeeData timed out")), 15e3))
    ]);
    const prioBase = fd.maxPriorityFeePerGas ?? 1000000n;
    const feeBase = fd.maxFeePerGas ?? fd.gasPrice ?? 2000000n;
    const maxPriorityFeePerGas = prioBase * 3n;
    let maxFeePerGas = feeBase * 3n;
    if (maxFeePerGas < maxPriorityFeePerGas) maxFeePerGas = maxPriorityFeePerGas * 2n;
    return { maxFeePerGas, maxPriorityFeePerGas };
  } catch {
    return {};
  }
}
async function recoverLockFromTx(htlcAddr, txHash, provider, scan) {
  const leaves = (() => {
    const ls = provider.__leafProviders;
    return Array.isArray(ls) && ls.length > 0 ? ls : [provider];
  })();
  const checkOneLeaf = async (p) => {
    const htlc = new Contract(htlcAddr, HTLC_ABI, p);
    let receipt;
    try {
      receipt = await p.getTransactionReceipt(txHash);
    } catch {
      return { kind: "blocked" };
    }
    if (receipt) {
      if (receipt.status !== 1) return { kind: "safe" };
      for (const log of receipt.logs) {
        if (htlcAddr && String(log.address).toLowerCase() !== htlcAddr.toLowerCase()) continue;
        try {
          const parsed = htlc.interface.parseLog(log);
          if (parsed && parsed.name === "Locked") {
            const a = parsed.args;
            const okHash = !scan?.hashLock || String(a.hashLock).toLowerCase() === scan.hashLock.toLowerCase();
            const okRcpt = !scan?.recipient || String(a.recipient).toLowerCase() === scan.recipient.toLowerCase();
            const okAmt = scan?.minAmount === void 0 || a.amount >= scan.minAmount;
            if (okHash && okRcpt && okAmt) return { kind: "locked", swapId: parsed.args[0] };
          }
        } catch {
        }
      }
      return { kind: "blocked" };
    }
    let tx;
    try {
      tx = await p.getTransaction(txHash);
    } catch {
      return { kind: "blocked" };
    }
    if (tx) return { kind: "blocked" };
    if (scan?.sender && scan.hashLock) {
      try {
        const tip = await p.getBlockNumber();
        const start = Math.max(0, scan.fromBlock && scan.fromBlock > 0 ? scan.fromBlock : tip - 5e4);
        const CHUNK = 1800;
        for (let to = tip; to >= start; to -= CHUNK) {
          const from = Math.max(start, to - CHUNK + 1);
          const evs = await htlc.queryFilter(htlc.filters.Locked(null, scan.sender), from, to);
          for (const ev of evs) {
            const a = ev.args;
            if (!a) continue;
            const okHash = String(a.hashLock).toLowerCase() === scan.hashLock.toLowerCase();
            const okRcpt = !scan.recipient || String(a.recipient).toLowerCase() === scan.recipient.toLowerCase();
            const okAmt = scan.minAmount === void 0 || a.amount >= scan.minAmount;
            if (okHash && okRcpt && okAmt) return { kind: "locked", swapId: String(a.id) };
          }
          if (from <= start) break;
        }
      } catch {
        return { kind: "blocked" };
      }
    }
    return { kind: "safe" };
  };
  const results = await Promise.all(leaves.map((p) => checkOneLeaf(p).catch(() => ({ kind: "blocked" }))));
  const found = results.find((r) => r.kind === "locked");
  if (found) return found;
  if (results.some((r) => r.kind === "blocked")) return { kind: "blocked" };
  return { kind: "safe" };
}
function authenticatedLockedSwapId(htlc, htlcAddr, hashLock, logs) {
  for (const log of logs) {
    if (htlcAddr && String(log.address).toLowerCase() !== htlcAddr.toLowerCase()) continue;
    try {
      const parsed = htlc.interface.parseLog(log);
      if (parsed && parsed.name === "Locked" && String(parsed.args.hashLock).toLowerCase() === hashLock.toLowerCase()) {
        return parsed.args[0];
      }
    } catch {
    }
  }
  return null;
}
async function lockTokens(htlcAddr, recipient, tokenAddr, amount, hashLock, timeLock, signer, expectedChainId, onBroadcast) {
  const lockKey = `${hashLock.toLowerCase()}:${htlcAddr.toLowerCase()}`;
  if (_activeLocks.has(lockKey)) throw new Error(`lockTokens: a lock for hashLock ${hashLock} on ${htlcAddr} is already in progress`);
  _activeLocks.add(lockKey);
  try {
    if (amount <= 0n) throw new Error("lockTokens: amount must be greater than 0");
    if (timeLock === 0n) throw new Error("lockTokens: timeLock must not be zero");
    if (!hashLock || hashLock.replace(/^0x/, "") === "0".repeat(64)) throw new Error("lockTokens: hashLock must not be all zeros");
    if (ethers.getAddress(recipient) === ethers.ZeroAddress) throw new Error("lockTokens: recipient must not be the zero address");
    if (expectedChainId !== void 0) {
      let _ltNetTimer;
      const network = await Promise.race([
        signer.provider.getNetwork(),
        new Promise((_, rej) => {
          _ltNetTimer = setTimeout(() => rej(new Error("getNetwork timed out")), 15e3);
        })
      ]).finally(() => clearTimeout(_ltNetTimer));
      if (network.chainId !== BigInt(expectedChainId)) {
        throw new Error(`Chain mismatch: wallet is on chainId ${network.chainId}, expected ${expectedChainId}. Switch networks in MetaMask.`);
      }
    }
    class _HtlcNotDeployedError extends Error {
      constructor() {
        super(...arguments);
        this.isHtlcNotDeployed = true;
      }
    }
    try {
      const code = await Promise.race([
        signer.provider.getCode(htlcAddr),
        new Promise((_, rej) => setTimeout(() => rej(new Error("getCode timed out")), 15e3))
      ]);
      if (!code || code === "0x") throw new _HtlcNotDeployedError(`HTLC contract not deployed at ${htlcAddr} on this network`);
    } catch (codeErr) {
      if (codeErr.isHtlcNotDeployed) throw codeErr;
      const msg = codeErr instanceof Error ? codeErr.message : String(codeErr);
      throw new Error(`HTLC contract check failed (network/RPC error \u2014 check MetaMask): ${msg}`);
    }
    const htlc = new Contract(htlcAddr, HTLC_ABI, signer);
    let receipt = null;
    let _broadcastTxHash;
    try {
      const lockTx = await htlc.lock(recipient, tokenAddr, amount, hashLock, timeLock, { gasLimit: 300000n, ...await bumpedTxFees(signer) });
      _broadcastTxHash = lockTx.hash;
      try {
        onBroadcast?.(lockTx.hash);
      } catch {
      }
      let lockWaitId;
      const lockTimeoutReject = new Promise((_, reject) => {
        lockWaitId = setTimeout(() => reject(new Error("lockTokens: tx.wait() timed out after 120s \u2014 tx may still confirm")), 12e4);
      });
      try {
        receipt = await Promise.race([lockTx.wait(), lockTimeoutReject]);
      } finally {
        clearTimeout(lockWaitId);
      }
    } catch (lockErr) {
      {
        const _re = lockErr;
        if (_re.code === "TRANSACTION_REPLACED" && _re.reason !== "cancelled" && !_re.cancelled) {
          if (_re.replacement?.hash) {
            try {
              onBroadcast?.(_re.replacement.hash);
            } catch {
            }
          }
          if (_re.receipt && _re.receipt.status === 1) {
            const _sid = authenticatedLockedSwapId(htlc, htlcAddr, hashLock, _re.receipt.logs);
            if (_sid) return _sid;
          }
          throw Object.assign(
            new Error("lockTokens: lock tx was sped up; the replacement is on-chain \u2014 reload to adopt the lock"),
            { broadcasted: true, txHash: _re.replacement?.hash ?? _broadcastTxHash }
          );
        }
      }
      try {
        const tokenContract = new Contract(tokenAddr, ERC20_ABI, signer);
        const revokeTx = await Promise.race([
          tokenContract.approve(htlcAddr, 0n),
          new Promise((_, rej) => setTimeout(() => rej(new Error("revoke approve() timed out")), 3e4))
        ]);
        let revokeWaitId;
        await Promise.race([
          revokeTx.wait(),
          new Promise((_, rej) => {
            revokeWaitId = setTimeout(() => rej(new Error("revoke timed out")), 3e4);
          })
        ]).catch(() => {
        }).finally(() => clearTimeout(revokeWaitId));
      } catch {
      }
      {
        const _reCancel = lockErr;
        if (_reCancel.code === "TRANSACTION_REPLACED" && (_reCancel.reason === "cancelled" || _reCancel.cancelled)) {
          throw new Error("lockTokens: lock transaction was cancelled in the wallet \u2014 no tokens were locked; retry the swap.");
        }
      }
      const rawMsg = lockErr instanceof Error ? lockErr.message : String(lockErr);
      const isAllowanceIssue = rawMsg.toLowerCase().includes("allowance") || rawMsg.toLowerCase().includes("insufficient") || rawMsg.includes("CALL_EXCEPTION");
      if (isAllowanceIssue) {
        throw new Error(
          `lockTokens: lock() reverted \u2014 likely an allowance race with a concurrent wallet operation. Wait for any pending transactions to confirm and retry the swap.`
        );
      }
      if (lockErr instanceof Error && _broadcastTxHash) Object.assign(lockErr, { broadcasted: true, txHash: _broadcastTxHash });
      throw lockErr;
    }
    if (!receipt) throw Object.assign(new Error("Transaction was dropped or replaced before confirmation"), _broadcastTxHash ? { broadcasted: true, txHash: _broadcastTxHash } : {});
    if (receipt.status !== 1) throw new Error("Transaction reverted on-chain");
    {
      const _sid = authenticatedLockedSwapId(htlc, htlcAddr, hashLock, receipt.logs);
      if (_sid) return _sid;
    }
    throw Object.assign(new Error("Locked event not found in transaction receipt"), _broadcastTxHash ? { broadcasted: true, txHash: _broadcastTxHash } : {});
  } finally {
    _activeLocks.delete(lockKey);
  }
}
async function lockETH(htlcAddr, recipient, amount, hashLock, timeLock, signer, expectedChainId, onBroadcast) {
  const lockKey = `${hashLock.toLowerCase()}:${htlcAddr.toLowerCase()}`;
  if (_activeLocks.has(lockKey)) throw new Error(`lockETH: a lock for hashLock ${hashLock} on ${htlcAddr} is already in progress`);
  _activeLocks.add(lockKey);
  try {
    if (amount <= 0n) throw new Error("lockETH: amount must be greater than 0");
    if (timeLock === 0n) throw new Error("lockETH: timeLock must not be zero");
    if (!hashLock || hashLock.replace(/^0x/, "") === "0".repeat(64)) throw new Error("lockETH: hashLock must not be all zeros");
    if (ethers.getAddress(recipient) === ethers.ZeroAddress) throw new Error("lockETH: recipient must not be the zero address");
    if (expectedChainId !== void 0) {
      let _leNetTimer2;
      const network = await Promise.race([
        signer.provider.getNetwork(),
        new Promise((_, rej) => {
          _leNetTimer2 = setTimeout(() => rej(new Error("getNetwork timed out")), 15e3);
        })
      ]).finally(() => clearTimeout(_leNetTimer2));
      if (network.chainId !== BigInt(expectedChainId)) {
        throw new Error(`Chain mismatch: wallet is on chainId ${network.chainId}, expected ${expectedChainId}. Switch networks in MetaMask.`);
      }
    }
    class _HtlcNotDeployedError2 extends Error {
      constructor() {
        super(...arguments);
        this.isHtlcNotDeployed = true;
      }
    }
    try {
      const code = await Promise.race([
        signer.provider.getCode(htlcAddr),
        new Promise((_, rej) => setTimeout(() => rej(new Error("getCode timed out")), 15e3))
      ]);
      if (!code || code === "0x") throw new _HtlcNotDeployedError2(`HTLC contract not deployed at ${htlcAddr} on this network`);
    } catch (codeErr) {
      if (codeErr.isHtlcNotDeployed) throw codeErr;
      const msg = codeErr instanceof Error ? codeErr.message : String(codeErr);
      throw new Error(`HTLC contract check failed (network/RPC error \u2014 check MetaMask): ${msg}`);
    }
    const ZERO_ADDRESS = "0x0000000000000000000000000000000000000000";
    const htlc = new Contract(htlcAddr, HTLC_ABI, signer);
    let receipt;
    let _broadcastTxHash;
    try {
      const tx = await htlc.lock(recipient, ZERO_ADDRESS, amount, hashLock, timeLock, { value: amount, gasLimit: 300000n, ...await bumpedTxFees(signer) });
      _broadcastTxHash = tx.hash;
      try {
        onBroadcast?.(tx.hash);
      } catch {
      }
      let ethWaitId;
      const ethTimeoutReject = new Promise((_, reject) => {
        ethWaitId = setTimeout(() => reject(new Error("lockETH: tx.wait() timed out after 120s \u2014 tx may still confirm")), 12e4);
      });
      try {
        receipt = await Promise.race([tx.wait(), ethTimeoutReject]);
      } finally {
        clearTimeout(ethWaitId);
      }
    } catch (lockErr) {
      const _re = lockErr;
      if (_re.code === "TRANSACTION_REPLACED") {
        if (_re.reason === "cancelled" || _re.cancelled) {
          throw new Error("lockETH: lock transaction was cancelled in the wallet \u2014 no ETH was locked; retry the swap.");
        }
        if (_re.replacement?.hash) {
          try {
            onBroadcast?.(_re.replacement.hash);
          } catch {
          }
        }
        if (_re.receipt && _re.receipt.status === 1) {
          const _sid = authenticatedLockedSwapId(htlc, htlcAddr, hashLock, _re.receipt.logs);
          if (_sid) return _sid;
        }
        throw Object.assign(
          new Error("lockETH: lock tx was sped up; the replacement is on-chain \u2014 reload to adopt the lock"),
          { broadcasted: true, txHash: _re.replacement?.hash ?? _broadcastTxHash }
        );
      }
      const msg = lockErr instanceof Error ? lockErr.message : String(lockErr);
      throw Object.assign(new Error(
        `lockETH: tx failed or receipt lost \u2014 if ETH was deducted, scan the HTLC contract ${htlcAddr} for a Locked event from your address to recover the swap ID. Original error: ${msg}`
      ), _broadcastTxHash ? { broadcasted: true, txHash: _broadcastTxHash } : {});
    }
    if (!receipt) throw Object.assign(new Error("Transaction was dropped or replaced before confirmation"), _broadcastTxHash ? { broadcasted: true, txHash: _broadcastTxHash } : {});
    if (receipt.status !== 1) throw new Error("Transaction reverted on-chain");
    {
      const _sid = authenticatedLockedSwapId(htlc, htlcAddr, hashLock, receipt.logs);
      if (_sid) return _sid;
    }
    throw Object.assign(new Error("Locked event not found in transaction receipt"), _broadcastTxHash ? { broadcasted: true, txHash: _broadcastTxHash } : {});
  } finally {
    _activeLocks.delete(lockKey);
  }
}
var _claimInFlight = /* @__PURE__ */ new Set();
async function claimSwap(htlcAddr, swapId, secret, signer, expectedChainId) {
  if (secret.length !== 32) {
    throw new Error(`Secret must be exactly 32 bytes; got ${secret.length}`);
  }
  const claimKey = `${htlcAddr.toLowerCase()}:${swapId.toLowerCase()}`;
  if (_claimInFlight.has(claimKey)) {
    throw new Error(`claimSwap already in-flight for swap ${swapId} \u2014 duplicate call rejected`);
  }
  _claimInFlight.add(claimKey);
  let broadcastReached = false;
  try {
    if (expectedChainId !== void 0) {
      let _claimNetTimer;
      const network = await Promise.race([
        signer.provider.getNetwork(),
        new Promise((_, rej) => {
          _claimNetTimer = setTimeout(() => rej(new Error("getNetwork timed out")), 15e3);
        })
      ]).finally(() => clearTimeout(_claimNetTimer));
      if (network.chainId !== BigInt(expectedChainId)) {
        throw new Error(`Chain mismatch: wallet is on chainId ${network.chainId}, expected ${expectedChainId}. Switch networks in MetaMask.`);
      }
    }
    let preflightTimerId;
    const swapData = await Promise.race([
      getSwap(htlcAddr, swapId, signer.provider),
      new Promise((_, reject) => {
        preflightTimerId = setTimeout(() => reject(new Error("EVM pre-flight check timed out after 15s")), 15e3);
      })
    ]).finally(() => clearTimeout(preflightTimerId));
    if (!swapData || swapData.amount === 0n) {
      throw new Error(`Swap ${swapId.slice(0, 18)}... not found or unfunded \u2014 aborting claim to protect secret`);
    }
    if (swapData.claimed) {
      throw new Error(`Swap ${swapId.slice(0, 18)}... already claimed \u2014 secret already on-chain`);
    }
    if (swapData.refunded) {
      throw new Error(`Swap ${swapId.slice(0, 18)}... already refunded \u2014 cannot claim`);
    }
    const signerAddress = (await Promise.race([
      signer.getAddress(),
      new Promise((_, rej) => setTimeout(() => rej(new Error("getAddress timed out")), 15e3))
    ])).toLowerCase();
    if (swapData.recipient.toLowerCase() !== signerAddress) {
      throw new Error(
        `Swap ${swapId.slice(0, 18)}... recipient mismatch: HTLC is for ${swapData.recipient} but signer is ${signerAddress}. Aborting to protect secret.`
      );
    }
    if (swapData.timeLock === 0n) {
      throw new Error("[claimSwap] timeLock is zero \u2014 invalid swap data from contract. Aborting to protect secret.");
    }
    if (swapData.timeLock < 1000000000n || swapData.timeLock > 100000000000n) {
      throw new Error(
        `[claimSwap] timeLock ${swapData.timeLock} is not a plausible unix timestamp (expected ~1.7e9) \u2014 contract invariant violated. Aborting to protect secret.`
      );
    }
    let nowSec;
    try {
      let _claimBlockTimerId;
      const latest = await Promise.race([
        signer.provider.getBlock("latest"),
        new Promise((_, rej) => {
          _claimBlockTimerId = setTimeout(() => rej(new Error("[claimSwap] getBlock timed out")), 15e3);
        })
      ]).finally(() => clearTimeout(_claimBlockTimerId));
      if (latest && Number.isFinite(latest.timestamp)) nowSec = BigInt(latest.timestamp);
    } catch {
    }
    if (nowSec === void 0) {
      throw new Error(
        `[claimSwap] could not read chain time to verify swap ${swapId.slice(0, 18)}... is before its timelock \u2014 refusing to broadcast (a claim at/after timeLock reverts and exposes the secret). Retry.`
      );
    }
    if (nowSec >= swapData.timeLock) {
      throw new Error(
        `Swap ${swapId.slice(0, 18)}... EVM timelock expired at unix ${swapData.timeLock} (now: ${nowSec}) \u2014 claim would revert and expose secret`
      );
    }
    const computedHash = ethers.sha256(secret).toLowerCase();
    const expectedHash = swapData.hashLock.toLowerCase();
    if (computedHash !== expectedHash) {
      throw new Error(
        `Secret does not match hashLock for swap ${swapId.slice(0, 18)}\u2026 (computed ${computedHash.slice(0, 10)}\u2026, expected ${expectedHash.slice(0, 10)}\u2026). Do not broadcast \u2014 wrong secret would be exposed in calldata.`
      );
    }
    const htlc = new Contract(htlcAddr, HTLC_ABI, signer);
    const secretHex = ethers.hexlify(secret);
    let txSubmitted = false;
    try {
      broadcastReached = true;
      let submitTimerId;
      const tx = await Promise.race([
        htlc.claim(swapId, secretHex, { gasLimit: 250000n, ...await bumpedTxFees(signer) }),
        new Promise((_, rej) => {
          submitTimerId = setTimeout(() => rej(new Error("[claimSwap] claim() submission timed out after 30s")), 3e4);
        })
      ]).finally(() => clearTimeout(submitTimerId));
      txSubmitted = true;
      secret.fill(0);
      let claimTimeoutId;
      let receipt;
      try {
        receipt = await Promise.race([
          tx.wait(),
          new Promise((_, reject) => {
            claimTimeoutId = setTimeout(
              () => {
                const err = new Error(
                  `Claim tx ${tx.hash} broadcast but receipt timed out after 120s. WARNING: the secret is now public in the mempool. Once the tx confirms, the secret will appear in the Claimed event \u2014 use it to claim the counterparty HTLC. Check block explorer for tx status.`
                );
                err.txHash = tx.hash;
                reject(err);
              },
              12e4
            );
          })
        ]).finally(() => clearTimeout(claimTimeoutId));
      } catch (waitErr) {
        const _re = waitErr;
        if (_re.code === "TRANSACTION_REPLACED") {
          if (_re.reason === "cancelled" || _re.cancelled) {
            throw new Error("claimSwap: claim was cancelled in the wallet \u2014 retry the claim (your secret is preserved).");
          }
          if (_re.receipt && _re.receipt.status === 1) {
            for (const log of _re.receipt.logs) {
              try {
                const p = htlc.interface.parseLog(log);
                if (p && p.name === "Claimed" && p.args[0]?.toLowerCase() === swapId.toLowerCase()) return { blockNumber: _re.receipt.blockNumber };
              } catch {
              }
            }
          }
          throw new Error("claimSwap: claim tx was sped up; the replacement is on-chain \u2014 reload to confirm and finalize the claim.");
        }
        throw waitErr;
      }
      if (!receipt) throw new Error("Claim transaction dropped \u2014 secret not revealed on-chain");
      if (receipt.status !== 1) {
        try {
          let _postClaimGsTimer;
          const postClaimData = await Promise.race([
            getSwap(htlcAddr, swapId, signer.provider),
            new Promise((_, rej) => {
              _postClaimGsTimer = setTimeout(() => rej(new Error("[claimSwap] post-revert getSwap timed out")), 15e3);
            })
          ]).finally(() => clearTimeout(_postClaimGsTimer));
          if (postClaimData?.claimed) {
            throw new Error("Claim reverted: HTLC was already claimed by another party \u2014 check block explorer. The secret may be recoverable from the claiming tx calldata.");
          }
        } catch (innerErr) {
          if (innerErr instanceof Error && innerErr.message.includes("claimed by another")) throw innerErr;
          throw new Error(
            `Claim tx reverted and post-revert check failed. Secret may now be visible in mempool calldata for swap ${swapId.slice(0, 18)}\u2026 \u2014 check the block explorer and claim the counterparty HTLC immediately if still possible. Original error: ${innerErr instanceof Error ? innerErr.message : String(innerErr)}`
          );
        }
        throw new Error("Claim transaction reverted on-chain");
      }
      let claimEventFound = false;
      for (const log of receipt.logs) {
        try {
          const parsed = htlc.interface.parseLog(log);
          if (parsed && parsed.name === "Claimed" && parsed.args[0]?.toLowerCase() === swapId.toLowerCase()) {
            claimEventFound = true;
            break;
          }
        } catch {
        }
      }
      if (!claimEventFound) {
        throw new Error("Claim tx confirmed but Claimed event not found in receipt \u2014 ABI mismatch or contract issue");
      }
      return { blockNumber: receipt.blockNumber };
    } finally {
      if (!txSubmitted) {
        secret.fill(0);
      }
    }
  } catch (claimErr) {
    if (!broadcastReached && claimErr instanceof Error && !claimErr.preBroadcast) {
      try {
        claimErr.preBroadcast = true;
      } catch {
      }
    }
    throw claimErr;
  } finally {
    _claimInFlight.delete(claimKey);
  }
}
async function refundSwap(htlcAddr, swapId, signer) {
  const provider = signer.provider;
  if (!provider) throw new Error("Signer has no provider attached");
  const htlc = new Contract(htlcAddr, HTLC_ABI, signer);
  let broadcastReached = false;
  try {
    let preflight15Id;
    const swapData = await Promise.race([
      getSwap(htlcAddr, swapId, provider),
      new Promise((_, reject) => {
        preflight15Id = setTimeout(() => reject(new Error("[refundSwap] getSwap timed out after 15s")), 15e3);
      })
    ]).finally(() => clearTimeout(preflight15Id));
    if (!swapData) throw new Error("Swap not found \u2014 may not be funded yet");
    const signerAddress = (await Promise.race([
      signer.getAddress(),
      new Promise((_, rej) => setTimeout(() => rej(new Error("getAddress timed out")), 15e3))
    ])).toLowerCase();
    if (swapData.initiator.toLowerCase() !== signerAddress) {
      throw new Error(
        `refundSwap: caller ${signerAddress} is not the HTLC initiator (${swapData.initiator}). Only the initiator can trigger a refund.`
      );
    }
    if (swapData.claimed) throw new Error("Swap already claimed \u2014 initiator revealed the secret on-chain");
    if (swapData.refunded || swapData.amount === 0n) throw new Error("Swap already refunded");
    if (swapData.timeLock === 0n) {
      throw new Error("[refundSwap] timeLock is zero \u2014 invalid swap data from contract.");
    }
    if (swapData.timeLock < 1000000000n || swapData.timeLock > 100000000000n) {
      throw new Error(`[refundSwap] timeLock value ${swapData.timeLock} is not a plausible unix timestamp (expected ~1.7e9). Contract invariant violated.`);
    }
    let _blockTimeoutId;
    const latestForRefund = await Promise.race([
      provider.getBlock("latest"),
      new Promise((_, rej) => {
        _blockTimeoutId = setTimeout(() => rej(new Error("[refundSwap] getBlock timed out after 15s")), 15e3);
      })
    ]).finally(() => clearTimeout(_blockTimeoutId));
    if (!latestForRefund || !Number.isFinite(latestForRefund.timestamp)) {
      throw new Error("[refundSwap] could not read latest block timestamp \u2014 cannot verify timelock expiry.");
    }
    const nowSec = BigInt(latestForRefund.timestamp);
    if (nowSec <= swapData.timeLock) {
      const rawDelta = swapData.timeLock - nowSec;
      const secsLeft = rawDelta > BigInt(Number.MAX_SAFE_INTEGER) ? Number.MAX_SAFE_INTEGER : Number(rawDelta);
      throw new Error(`Timelock has not expired yet. ~${Math.ceil(secsLeft / 60).toLocaleString()} minutes remaining.`);
    }
    broadcastReached = true;
    const tx = await Promise.race([
      htlc.refund(swapId, { gasLimit: 150000n, ...await bumpedTxFees(signer) }),
      new Promise((_, rej) => setTimeout(() => rej(new Error("[refundSwap] refund() submission timed out after 30s")), 3e4))
    ]);
    let receipt;
    try {
      let refundWaitId;
      receipt = await Promise.race([
        tx.wait(),
        new Promise((_, reject) => {
          refundWaitId = setTimeout(() => reject(new Error("[refundSwap] tx.wait timed out after 120s \u2014 tx may still confirm")), 12e4);
        })
      ]).finally(() => clearTimeout(refundWaitId));
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      const _re = e;
      if (_re.code === "TRANSACTION_REPLACED") {
        if (_re.reason === "cancelled" || _re.cancelled) {
          throw new Error("refundSwap: refund was cancelled in the wallet \u2014 retry the refund.");
        }
        if (!_re.receipt) {
          throw new Error("refundSwap: refund tx was sped up; the replacement is on-chain \u2014 reload to confirm the refund.");
        }
        receipt = _re.receipt;
      } else if (msg.includes("CALL_EXCEPTION")) {
        try {
          let _ceGsTimer;
          const postRevert = await Promise.race([
            getSwap(htlcAddr, swapId, provider),
            new Promise((_, rej) => {
              _ceGsTimer = setTimeout(() => rej(new Error("[refundSwap] CALL_EXCEPTION getSwap timed out")), 15e3);
            })
          ]).finally(() => clearTimeout(_ceGsTimer));
          if (postRevert?.claimed) {
            throw new Error("Swap was claimed before refund executed \u2014 secret is on-chain, check Claimed events");
          }
        } catch (checkErr) {
          const checkMsg = checkErr instanceof Error ? checkErr.message : String(checkErr);
          if (checkMsg.includes("Swap was claimed")) throw checkErr;
        }
        throw new Error("Refund rejected by contract \u2014 timelock may not have expired yet");
      } else {
        throw e;
      }
    }
    if (receipt === null) {
      throw new Error("Refund transaction was dropped from mempool \u2014 may need to rebroadcast");
    }
    if (receipt.status !== 1) {
      try {
        let _postRefundGsTimer;
        const postRevert = await Promise.race([
          getSwap(htlcAddr, swapId, provider),
          new Promise((_, rej) => {
            _postRefundGsTimer = setTimeout(() => rej(new Error("[refundSwap] post-revert getSwap timed out")), 15e3);
          })
        ]).finally(() => clearTimeout(_postRefundGsTimer));
        if (postRevert?.claimed) {
          throw new Error("Swap was claimed before refund executed \u2014 secret is on-chain, check Claimed events");
        }
      } catch (checkErr) {
        const checkMsg = checkErr instanceof Error ? checkErr.message : String(checkErr);
        if (checkMsg.includes("Swap was claimed")) throw checkErr;
      }
      throw new Error("Refund rejected by contract \u2014 timelock may not have expired yet");
    }
  } catch (refundErr) {
    if (!broadcastReached && refundErr instanceof Error && !refundErr.preBroadcast) {
      try {
        refundErr.preBroadcast = true;
      } catch {
      }
    }
    throw refundErr;
  }
}
async function getSwap(htlcAddr, swapId, provider, blockTag) {
  const htlc = new Contract(htlcAddr, HTLC_ABI, provider);
  let _gsTimer;
  const result = await Promise.race([
    blockTag !== void 0 ? htlc.getSwap(swapId, { blockTag }) : htlc.getSwap(swapId),
    new Promise((_, rej) => {
      _gsTimer = setTimeout(() => rej(new Error("[getSwap] contract call timed out after 15s")), 15e3);
    })
  ]).finally(() => clearTimeout(_gsTimer));
  const initiator = result[0];
  if (initiator === ethers.ZeroAddress) {
    return null;
  }
  if (result[5] === 0n) {
    return null;
  }
  return {
    initiator: ethers.getAddress(initiator),
    recipient: ethers.getAddress(result[1]),
    token: result[2] === ethers.ZeroAddress ? ethers.ZeroAddress : ethers.getAddress(result[2]),
    amount: result[3],
    hashLock: result[4],
    timeLock: result[5],
    claimed: result[6],
    refunded: result[7]
  };
}
var SAFE_TAG_MEMO_TTL_MS = 60 * 6e4;
var _safeTagUnsupportedChains = /* @__PURE__ */ new Map();
function isUnsupportedBlockTagError(err) {
  const e = err;
  const code = e?.code ?? e?.error?.code ?? e?.info?.error?.code;
  if (code === -32602 || code === "INVALID_ARGUMENT") return true;
  let stringified = "";
  try {
    stringified = JSON.stringify(e);
  } catch {
  }
  const msg = [e?.message, e?.shortMessage, e?.error?.message, e?.info?.error?.message, stringified].filter((s) => typeof s === "string").join(" | ").toLowerCase();
  if (!msg) return false;
  if (msg.includes("invalid block tag") || msg.includes("unknown block") || msg.includes("invalid params")) return true;
  if ((msg.includes("safe") || msg.includes("finalized")) && msg.includes("block") && msg.includes("not found")) return true;
  return msg.includes("block tag") && (msg.includes("invalid") || msg.includes("unknown") || msg.includes("unsupported") || msg.includes("not found") || msg.includes("does not") || msg.includes("doesn't"));
}
async function isEvmLockAtSafeDepth(htlcAddr, swapId, provider, requiredConfirmations, inv) {
  let lock = null;
  let safeServed = false;
  let chainKey = "";
  try {
    chainKey = String((await provider.getNetwork()).chainId);
  } catch {
  }
  const _memoTs = chainKey ? _safeTagUnsupportedChains.get(chainKey) : void 0;
  if (_memoTs !== void 0 && Date.now() - _memoTs < SAFE_TAG_MEMO_TTL_MS) {
    safeServed = false;
  } else {
    if (_memoTs !== void 0 && chainKey) _safeTagUnsupportedChains.delete(chainKey);
    try {
      lock = await getSwap(htlcAddr, swapId, provider, "safe");
      safeServed = true;
    } catch (err) {
      if (isUnsupportedBlockTagError(err)) {
        if (chainKey) _safeTagUnsupportedChains.set(chainKey, Date.now());
        safeServed = false;
      } else {
        return false;
      }
    }
  }
  if (!safeServed) {
    try {
      const tip = await Promise.race([
        provider.getBlockNumber(),
        new Promise((_, rej) => setTimeout(() => rej(new Error("getBlockNumber timeout")), 15e3))
      ]);
      if (!(requiredConfirmations > 1 && tip > requiredConfirmations)) return false;
      lock = await getSwap(htlcAddr, swapId, provider, tip - (requiredConfirmations - 1));
    } catch {
      return false;
    }
  }
  if (!lock) return false;
  if (lock.claimed || lock.refunded) return false;
  if (lock.hashLock.toLowerCase() !== inv.hashLock.toLowerCase()) return false;
  if (inv.recipient && lock.recipient.toLowerCase() !== inv.recipient.toLowerCase()) return false;
  if (inv.minAmount !== void 0 && lock.amount < inv.minAmount) return false;
  if (inv.token !== void 0 && lock.token.toLowerCase() !== inv.token.toLowerCase()) return false;
  if (inv.minTimeLock !== void 0 && lock.timeLock < inv.minTimeLock) return false;
  return true;
}

// src/gates.ts
var GateFailure = class extends Error {
  constructor(reason, disposition) {
    super(reason);
    this.name = "GateFailure";
    this.reason = reason;
    this.disposition = disposition;
  }
};
function mintFundProof(a) {
  return { ...a, leg: "X", for: "fundY" };
}
function mintRevealAuthorization(a) {
  return { ...a, leg: "Y", for: "reveal" };
}
function aggregateChainNow(leafTimestamps, leafCount) {
  const oks = leafTimestamps.filter((t) => t !== null);
  return oks.length === leafCount && oks.length > 0 ? Math.max(...oks) : null;
}
function validateEvmTimeLock(raw) {
  if (raw === null || raw === void 0) return null;
  const tl = Number(raw);
  return Number.isFinite(tl) && tl >= 1e9 && tl <= 1e11 ? tl : null;
}
function p2shScriptHex(redeemScript) {
  return "a914" + bytesToHex(hash160(redeemScript)) + "87";
}
function requiredConfirmationsFor(chain) {
  return Math.max(1, chainConfigs[chain]?.requiredConfirmations ?? 3);
}
function avgBlockSecFor(chain) {
  return chainConfigs[chain]?.avgBlockTimeSec ?? 600;
}
function isValidOutpoint(o) {
  return !!o && typeof o.tx_hash === "string" && /^[0-9a-f]{64}$/.test(o.tx_hash) && Number.isInteger(o.tx_pos) && o.tx_pos >= 0;
}
function parseHtlcCltv(redeemScript) {
  const s = redeemScript;
  const PUSH_AT = 60;
  if (s.length < PUSH_AT + 3) return null;
  if (s[0] !== 99 || s[1] !== 168 || s[2] !== 32) return null;
  if (s[35] !== 136 || s[36] !== 118 || s[37] !== 169 || s[38] !== 20) return null;
  if (s[59] !== 103) return null;
  let pos = PUSH_AT;
  const op = s[pos++];
  let len;
  if (op >= 1 && op <= 75) {
    len = op;
  } else if (op === 76) {
    if (pos >= s.length) return null;
    len = s[pos++];
  } else if (op === 77) {
    if (pos + 1 >= s.length) return null;
    len = s[pos] | s[pos + 1] << 8;
    pos += 2;
  } else return null;
  if (len < 1 || len > 5) return null;
  if (pos + len >= s.length) return null;
  if (s[pos + len] !== 177) return null;
  if (s[pos + len - 1] & 128) return null;
  let n = 0;
  for (let i = 0; i < len; i++) n += s[pos + i] * 2 ** (8 * i);
  return n;
}
async function reverifyBuriedOutpoint(client, chain, redeemScript, recordedOutpoint, counterpartyLocktime, label) {
  if (!isValidOutpoint(recordedOutpoint)) {
    throw new GateFailure(`${label}: no valid recorded funding outpoint to re-verify \u2014 rebuild before the irreversible action`, "rebuild");
  }
  let freshHeight = 0;
  try {
    freshHeight = (await client.getBlockHeight())[0];
  } catch {
    freshHeight = 0;
  }
  if (!freshHeight || freshHeight <= 0) {
    throw new GateFailure(`${label}: counterparty chain height unavailable \u2014 fail closed; retry`, "rearm");
  }
  const vReqConf = requiredConfirmationsFor(chain);
  let vUtxos;
  try {
    vUtxos = await client.getUTXOs(getHTLCScripthash(redeemScript), p2shScriptHex(redeemScript));
  } catch {
    throw new GateFailure(`${label}: could not read counterparty HTLC UTXOs \u2014 fail closed; retry`, "rearm");
  }
  const vConfirmed = vUtxos.filter(
    (u) => u.height > 0 && freshHeight - u.height + 1 >= vReqConf && Number.isFinite(u.value) && u.value >= 0
  );
  const sameOutpoint = vConfirmed.find((u) => u.tx_hash === recordedOutpoint.tx_hash && u.tx_pos === recordedOutpoint.tx_pos);
  if (!sameOutpoint) {
    throw new GateFailure(`${label}: counterparty HTLC funding no longer confirmed at the required depth (possible reorg / double-spend) \u2014 fail closed`, "rebuild");
  }
  let rawFundingTx;
  try {
    rawFundingTx = await client.getTx(recordedOutpoint.tx_hash);
  } catch {
    throw new GateFailure(`${label}: could not fetch the counterparty funding tx to authenticate \u2014 fail closed; retry`, "rearm");
  }
  const fetchRawTx = (txid) => txid.toLowerCase() === recordedOutpoint.tx_hash.toLowerCase() ? Promise.resolve(rawFundingTx) : client.getTx(txid);
  let vAuthed;
  try {
    vAuthed = await verifyAndAuthenticateUtxo(sameOutpoint, redeemScript, fetchRawTx);
  } catch {
    throw new GateFailure(`${label}: counterparty HTLC funding output failed re-authentication \u2014 fail closed`, "rebuild");
  }
  if (!(vAuthed.value > 0)) {
    throw new GateFailure(`${label}: counterparty HTLC funding output failed re-authentication (non-positive value) \u2014 fail closed`, "rebuild");
  }
  if (spvSupported(chain)) {
    let spvConfs;
    try {
      spvConfs = await verifyConfirmations(client, chain, recordedOutpoint.tx_hash, sameOutpoint.height, rawFundingTx, freshHeight);
    } catch {
      throw new GateFailure(`${label}: could not SPV-verify counterparty funding depth (header/Merkle proof failed) \u2014 fail closed; retry`, "rearm");
    }
    if (spvConfs < vReqConf) {
      throw new GateFailure(`${label}: SPV-verified funding depth (${spvConfs}) below required ${vReqConf} \u2014 possible proxy height manipulation; fail closed`, "rearm");
    }
  }
  const scriptCltv = parseHtlcCltv(redeemScript);
  if (scriptCltv === null) {
    throw new GateFailure(`${label}: could not read a CLTV from the counterparty HTLC redeem script \u2014 fail closed`, "rebuild");
  }
  if (scriptCltv !== counterpartyLocktime) {
    throw new GateFailure(
      `${label}: recorded counterparty locktime (${counterpartyLocktime}) disagrees with the authenticated HTLC redeem script CLTV (${scriptCltv}) \u2014 fail closed`,
      "rebuild"
    );
  }
  return { freshHeight, vReqConf, sameOutpoint, rawFundingTx };
}
async function assertRevealSafe(client, p) {
  const { role, theirChain, counterpartyRedeemScript, recordedOutpoint, counterpartyLocktime } = p;
  const buried = await reverifyBuriedOutpoint(client, theirChain, counterpartyRedeemScript, recordedOutpoint, counterpartyLocktime, "reveal");
  const chainNow = await getChainTimeSec(client);
  if (chainNow === null) {
    throw new GateFailure("reveal: could not read chain time to verify the responder refund timelock \u2014 not revealing the secret; retry", "rearm");
  }
  let marginBasis = "none";
  if (role === "initiator") {
    const cpLock = counterpartyLocktime;
    let respRemainingSec;
    if (cpLock >= 15e8) {
      marginBasis = "timestamp-cltv";
      respRemainingSec = cpLock - chainNow;
    } else {
      marginBasis = "height-cltv";
      let spvHeight = buried.freshHeight;
      if (spvSupported(theirChain)) {
        try {
          spvHeight = await spvVerifiedTipFresh(client, theirChain, buried.freshHeight);
        } catch {
          throw new GateFailure("reveal: could not SPV-verify the current counterparty height (stale / under-report) \u2014 not revealing the secret; retry", "rearm");
        }
      }
      respRemainingSec = minSecondsUntilRefund(cpLock - spvHeight, avgBlockSecFor(theirChain));
    }
    if (respRemainingSec < CLAIM_MARGIN_SEC) {
      throw new GateFailure(
        `reveal: responder HTLC refund timelock too close (~${Math.max(0, Math.floor(respRemainingSec / 3600))}h remaining, below the ${Math.floor(CLAIM_MARGIN_SEC / 3600)}h claim margin) \u2014 revealing now would let the responder refund AND claim your leg. Not revealing the secret; refund your own leg once its timelock passes.`,
        "abort"
      );
    }
  }
  return mintRevealAuthorization({
    chain: theirChain,
    outpoint: { tx_hash: buried.sameOutpoint.tx_hash, tx_pos: buried.sameOutpoint.tx_pos },
    tipHeight: buried.freshHeight,
    capturedAtChainSec: chainNow,
    role,
    marginBasis
  });
}
async function assertLegBuriedForFunding(client, p) {
  const { theirChain, myChain, myChainIsEvm, counterpartyRedeemScript, recordedOutpoint, counterpartyLocktime } = p;
  const buried = await reverifyBuriedOutpoint(client, theirChain, counterpartyRedeemScript, recordedOutpoint, counterpartyLocktime, "fund");
  const theirBlockSec = chainConfigs[theirChain]?.avgBlockTimeSec;
  const myBlockSec = chainConfigs[myChain]?.avgBlockTimeSec;
  if (!Number.isFinite(theirBlockSec) || (theirBlockSec ?? 0) <= 0 || !Number.isFinite(myBlockSec) || (myBlockSec ?? 0) <= 0) {
    throw new GateFailure("fund: chain block-time configuration is invalid \u2014 cannot verify swap timelock safety", "abort");
  }
  const responderLockSec = myChainIsEvm ? RESPONDER_LOCK_SEC : LOCKTIME_BLOCKS.responder * myBlockSec;
  let marginHeight = buried.freshHeight;
  if (spvSupported(theirChain)) {
    try {
      marginHeight = await spvVerifiedTipFresh(client, theirChain, buried.freshHeight);
    } catch {
      throw new GateFailure("fund: could not SPV-verify / freshness-bound the counterparty tip (stale / under-report) \u2014 not committing your funds; retry", "rearm");
    }
  }
  const remainingBlocks = counterpartyLocktime - marginHeight;
  if (remainingBlocks <= 0) {
    throw new GateFailure("fund: counterparty HTLC locktime has already expired \u2014 not committing your funds", "abort");
  }
  const maxLock = (chainConfigs[theirChain]?.maxLockBlocks ?? 2016) * 3;
  if (remainingBlocks > maxLock) {
    throw new GateFailure("fund: counterparty HTLC locktime is suspiciously far in the future (possible grief lock) \u2014 not committing your funds", "abort");
  }
  if (marginTooTight(remainingBlocks, theirBlockSec, responderLockSec + CLAIM_MARGIN_SEC)) {
    throw new GateFailure(
      `fund: counterparty HTLC expires too soon relative to your ~${Math.ceil(responderLockSec / 3600)}h lock plus the ${Math.floor(CLAIM_MARGIN_SEC / 3600)}h claim margin \u2014 unsafe to commit your funds`,
      "abort"
    );
  }
  const chainNow = await getChainTimeSec(client);
  if (chainNow === null) {
    throw new GateFailure("fund: could not read chain time \u2014 not committing your funds; retry", "rearm");
  }
  return mintFundProof({
    chain: theirChain,
    outpoint: { tx_hash: buried.sameOutpoint.tx_hash, tx_pos: buried.sameOutpoint.tx_pos },
    tipHeight: buried.freshHeight,
    capturedAtChainSec: chainNow,
    role: "responder",
    marginBasis: "height-cltv"
  });
}
function evmLeaves(provider) {
  const ls = provider.__leafProviders;
  return Array.isArray(ls) && ls.length > 0 ? ls : [provider];
}
async function readLeafChainSec(lp) {
  let timer;
  try {
    const b = await Promise.race([
      lp.getBlock("latest"),
      new Promise((res) => {
        timer = setTimeout(() => res(null), 15e3);
      })
    ]);
    const ts = b?.timestamp;
    return b && Number.isFinite(ts) ? Number(ts) : null;
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}
async function assertEvmLegBuriedForFunding(provider, p) {
  const leaves = evmLeaves(provider);
  if (leaves.length < 2) {
    throw new GateFailure("evm-fund: the EVM read provider is not a quorum>=2 provider \u2014 refusing to mint on single-backend trust", "rearm");
  }
  const tsList = await Promise.all(leaves.map(readLeafChainSec));
  const chainNow = aggregateChainNow(tsList, leaves.length);
  const minTimeLock = chainNow == null ? BigInt("9999999999999999") : BigInt(Math.ceil(chainNow + RESPONDER_LOCK_SEC + EVM_CLAIM_MARGIN_SEC));
  let atSafeDepth = false;
  try {
    atSafeDepth = await isEvmLockAtSafeDepth(p.htlcAddr, p.swapId, provider, p.requiredConfirmations, {
      hashLock: p.hashLock,
      recipient: p.recipient,
      minAmount: p.minAmount,
      minTimeLock,
      token: p.token
    });
  } catch {
    atSafeDepth = false;
  }
  if (!atSafeDepth) {
    throw new GateFailure("evm-fund: counterparty EVM lock is not at a reorg-safe depth, its refund timelock is too short, or a binding (hashLock/recipient/amount/token) mismatched \u2014 not committing your funds; retry", "rearm");
  }
  if (chainNow == null) {
    throw new GateFailure("evm-fund: could not corroborate the EVM chain clock across quorum leaves \u2014 fail closed; retry", "rearm");
  }
  let tipHeight = 0;
  try {
    tipHeight = await provider.getBlockNumber();
  } catch {
    tipHeight = 0;
  }
  return mintFundProof({
    chain: p.chain,
    swapId: p.swapId,
    tipHeight,
    capturedAtChainSec: chainNow,
    role: "responder",
    marginBasis: "evm-timestamp"
  });
}
async function assertEvmRevealSafe(provider, p) {
  const leaves = evmLeaves(provider);
  if (leaves.length < 2) {
    throw new GateFailure("evm-reveal: the EVM read provider is not a quorum>=2 provider \u2014 refusing to mint on single-backend trust", "rearm");
  }
  let atSafeDepth = false;
  try {
    atSafeDepth = await isEvmLockAtSafeDepth(p.htlcAddr, p.swapId, provider, p.requiredConfirmations, {
      hashLock: p.hashLock,
      recipient: p.recipient,
      minAmount: p.minAmount,
      token: p.token
    });
  } catch {
    atSafeDepth = false;
  }
  if (!atSafeDepth) {
    throw new GateFailure("evm-reveal: counterparty EVM lock is not at a reorg-safe depth, or a binding (hashLock/recipient/amount/token) mismatched \u2014 not revealing your secret; retry", "rearm");
  }
  const [tsList, sw] = await Promise.all([
    Promise.all(leaves.map(readLeafChainSec)),
    getSwap(p.htlcAddr, p.swapId, provider).catch(() => null)
  ]);
  const chainNow = aggregateChainNow(tsList, leaves.length);
  const evmExpiry = validateEvmTimeLock(sw ? sw.timeLock : null);
  if (chainNow === null || evmExpiry === null) {
    throw new GateFailure("evm-reveal: cannot read the on-chain responder EVM lock timelock / chain time yet \u2014 not revealing your secret; retry", "rearm");
  }
  if (evmExpiry - chainNow < EVM_CLAIM_MARGIN_SEC) {
    throw new GateFailure(
      `evm-reveal: responder EVM lock refund timelock too close (~${Math.max(0, Math.floor((evmExpiry - chainNow) / 3600))}h remaining, below the ${Math.floor(EVM_CLAIM_MARGIN_SEC / 3600)}h claim margin) \u2014 revealing now would let the responder refund AND claim your leg. Not revealing your secret; refund your own leg once its timelock passes.`,
      "abort"
    );
  }
  let tipHeight = 0;
  try {
    tipHeight = await provider.getBlockNumber();
  } catch {
    tipHeight = 0;
  }
  return mintRevealAuthorization({
    chain: p.chain,
    swapId: p.swapId,
    tipHeight,
    capturedAtChainSec: chainNow,
    role: "initiator",
    marginBasis: "evm-timestamp"
  });
}
var NATIVE_ETH_ADDR = NATIVE_ETH_ADDRESS.toLowerCase();
var MnemonicSeedVault = class {
  constructor(mnemonic, signer) {
    this.mnemonic = mnemonic;
    this.signer = signer;
  }
  async signingKey(chain, hdPath) {
    if (this.mnemonic === null) throw new Error("SeedVault disposed \u2014 no key material available");
    return this.signer(chain, this.mnemonic, hdPath);
  }
  async swapKss() {
    if (this.mnemonic === null) return null;
    return deriveSwapKss(this.mnemonic);
  }
  dispose() {
    this.mnemonic = null;
  }
};
var fundedKey = (id) => `bch2swap:funded:${id}`;
var fundLocktimeKey = (id) => `bch2swap:fundlocktime:${id}`;
var fundRecipientKey = (id) => `bch2swap:fundrecipient:${id}`;
var fundedHtlcKey = (id) => `bch2swap:fundedhtlc:${id}`;
var fundedTxKey = (id) => `bch2swap:fundedtx:${id}`;
var recordKey = (id) => `bch2swap:record:${id}`;
var durableSecretKey = (id) => `bch2swap:encsecret:${id}`;
var claimTxKey = (id) => `bch2swap:claimtx:${id}`;
var claimBroadcastKey = (id) => `bch2swap:claimbroadcast:${id}`;
var refundBroadcastKey = (id) => `bch2swap:refundbroadcast:${id}`;
var refundTxKey = (id) => `bch2swap:refundtx:${id}`;
var lockPendingKey = (id) => `bch2swap:lockpending:${id}`;
var evmLockTxKey = (id) => `bch2swap:evmlocktx:${id}`;
var refundRacePendingKey = (id) => `bch2swap:refundracepending:${id}`;
var LOCK_PENDING_SENTINEL = "pending";
function durableHtlc(h) {
  return {
    redeemScript: bytesToHex(h.redeemScript),
    p2shAddress: h.p2shAddress,
    secretHash: bytesToHex(h.params.secretHash),
    recipientPkh: bytesToHex(h.params.recipientPubkeyHash),
    refundPkh: bytesToHex(h.params.refundPubkeyHash),
    locktime: h.params.locktime
  };
}
var HEX20 = /^[0-9a-f]{40}$/;
var HEX64 = /^[0-9a-f]{64}$/;
var BYTES32_0X = /^0x[0-9a-fA-F]{64}$/;
function evmLeaves2(provider) {
  const ls = provider.__leafProviders;
  return Array.isArray(ls) && ls.length > 0 ? ls : [provider];
}
var HTLC_IFACE = new ethers.Interface(HTLC_ABI);
function isDefinitiveBroadcastRejection(err) {
  const msg = (err instanceof Error ? err.message : String(err ?? "")).toLowerCase();
  if (!msg) return false;
  if (/tim(e|ed)\s?out|timeout|econnreset|econnrefused|etimedout|socket hang up|network|unreachable|fetch failed|abort|websocket|\b1006\b|disconnect|no (response|reply)|already (in|known)|txn-already-known|in block chain|mempool/i.test(msg)) {
    return false;
  }
  return /reject|bad-txns|missing ?inputs|missingorspent|min relay fee|insufficient (fee|priority)|mandatory-script-verify|non-mandatory-script-verify|scriptsig|dust|non-?final|absurdly-high-fee|belowout|verify (flag|failed)|invalid|malformed|^\s*(16|64|18|256):\s/i.test(msg);
}
function isHtlcRefundAvailable(locktime, currentHeight) {
  if (locktime >= 5e8) return Math.floor(Date.now() / 1e3) >= locktime;
  return currentHeight !== null && currentHeight >= locktime;
}
function isResumableSwapState(s) {
  return !!(s?.myFundingTxid || s?.myHTLC);
}
function validateReconstructionInputs(args) {
  const { myChainIsEvm, fundingTxid, locktimeStr, secretHash } = args;
  if (myChainIsEvm) return { ok: false };
  if (!fundingTxid || typeof fundingTxid !== "string" || !/^[0-9a-f]{64}$/.test(fundingTxid)) return { ok: false };
  let lt = NaN;
  try {
    lt = parseInt(locktimeStr ?? "", 10);
  } catch {
  }
  if (!Number.isInteger(lt) || lt <= 0 || lt >= 2147483648) return { ok: false };
  if (!secretHash || secretHash.length !== 32 || secretHash.every((b) => b === 0)) return { ok: false };
  return { ok: true, fundingTxid, locktime: lt };
}
var SwapController = class _SwapController {
  constructor(record, deps) {
    this.listeners = /* @__PURE__ */ new Map();
    /** In-memory only. The re-derivable HTLC preimage — NEVER written durably in plaintext (design §3, fix #5). */
    this.secret = null;
    this.disposed = false;
    /** FIX #10 (resume): set true when resume()'s myHTLC on-chain authentication was NOT a DEFINITIVE 'ok' (a
     *  DEFINITIVE 'mismatch' or a network-blip 'indeterminate'). While set, refund()/revealAndClaim()/
     *  claimWithKnownSecret() refuse any NEW irreversible broadcast — an idempotent ADOPT of an already-broadcast tx is
     *  still allowed (it reveals nothing new). Cleared only by a DEFINITIVE re-authentication to 'ok'. */
    this.irreversibleBlocked = false;
    this.record = { ...record };
    this.deps = deps;
    this.id = record.id;
    this.role = record.role;
    this.myChain = record.role === "initiator" ? record.offer.sendChain : record.offer.receiveChain;
    this.theirChain = record.role === "initiator" ? record.offer.receiveChain : record.offer.sendChain;
  }
  // ── events ─────────────────────────────────────────────────────────────────────────────────────────────
  /** Subscribe to a structured event. Returns an unsubscribe fn. */
  on(type, cb) {
    let set = this.listeners.get(type);
    if (!set) {
      set = /* @__PURE__ */ new Set();
      this.listeners.set(type, set);
    }
    set.add(cb);
    return () => this.off(type, cb);
  }
  off(type, cb) {
    this.listeners.get(type)?.delete(cb);
  }
  emit(e) {
    const set = this.listeners.get(e.type);
    if (!set) return;
    for (const cb of [...set]) {
      try {
        cb(e);
      } catch {
      }
    }
  }
  setPhase(phase) {
    this.record.phase = phase;
    this.emit({ type: "phase", phase });
  }
  status(message) {
    this.emit({ type: "status", message });
  }
  // ── snapshot / lifecycle ─────────────────────────────────────────────────────────────────────────────────
  getState() {
    return Object.freeze({
      id: this.id,
      role: this.role,
      phase: this.record.phase,
      myChain: this.myChain,
      theirChain: this.theirChain,
      myFundingTxid: this.record.myFundingTxid,
      fundLocktime: this.record.fundLocktime,
      myHTLC: this.record.myHTLC ? Object.freeze({ ...this.record.myHTLC }) : void 0,
      disposed: this.disposed,
      hasSecret: !!(this.secret && this.secret.length === 32),
      resumeAuth: this.resumeAuthValue,
      resumeGate: this.resumeGateValue
    });
  }
  /** Abort + zeroize the ONLY in-memory secret + tell the vault to zeroize. Idempotent; post-dispose actions throw. */
  dispose() {
    if (this.disposed) return;
    this.disposed = true;
    if (this.secret) {
      this.secret.fill(0);
      this.secret = null;
    }
    try {
      this.deps.seedVault.dispose();
    } catch {
    }
    this.listeners.clear();
  }
  assertLive() {
    if (this.disposed) throw new Error("SwapController disposed \u2014 no further actions permitted");
  }
  // ── prepare() ──────────────────────────────────────────────────────────────────────────────────────────
  /**
   * Derive per-swap keys, RECOVER S, and authenticate it against the offer's secretHash — fail-closed. Grounds in
   * SwapExecute.tsx recoverSecret (~2663-2677): for an `hmac-v1` offer as the initiator, S = swapSecretFromKss(
   * K_ss, nonce), and sha256(S) MUST equal offer.secretHash. FIX #5: refuse unless the scheme is `hmac-v1` (S is
   * re-derivable from the seed on any device) OR an encrypted-at-rest durable S exists — never advance a swap whose
   * secret a crash would strand. Also refuses a suspended pair. Transitions `taken -> prepared`.
   */
  async prepare() {
    this.assertLive();
    const rec = this.record;
    if (rec.phase !== "taken" && rec.phase !== "prepared") {
      throw new Error(`prepare: unexpected phase '${rec.phase}' \u2014 prepare runs from 'taken' (or re-runs from 'prepared')`);
    }
    if (isSwapPairSuspended(this.myChain, this.theirChain)) {
      throw new Error(`prepare: swap pair ${this.myChain}/${this.theirChain} is suspended \u2014 refusing to prepare`);
    }
    const secretHashHex = (rec.offer.secretHash ?? "").toLowerCase().replace(/^0x/, "");
    if (!HEX64.test(secretHashHex)) {
      throw new Error("prepare: offer.secretHash is missing / not a 32-byte hex hash \u2014 cannot authenticate the secret");
    }
    const isHmacV1 = rec.offer.secretScheme === SWAP_SECRET_SCHEME;
    const durableSecretHex = await this.deps.durable.get(durableSecretKey(rec.id));
    if (!isHmacV1 && !durableSecretHex) {
      throw new Error(
        `prepare: offer secretScheme '${rec.offer.secretScheme ?? "none"}' is not '${SWAP_SECRET_SCHEME}' and no encrypted-at-rest durable secret is present \u2014 refusing to prepare a swap whose secret a crash would strand (fix #5)`
      );
    }
    const S = await this.recoverSecret(secretHashHex, isHmacV1, durableSecretHex);
    if (!S || S.length !== 32) {
      throw new Error("prepare: could not derive/recover the 32-byte swap secret (vault locked, bad nonce, or absent durable S)");
    }
    if (bytesToHex(sha256(S)) !== secretHashHex) {
      S.fill(0);
      throw new Error("prepare: recovered secret does not hash to offer.secretHash (tampered nonce / wrong scheme) \u2014 fail closed");
    }
    if (this.secret) this.secret.fill(0);
    this.secret = S;
    this.setPhase("prepared");
    this.status("prepare:ok");
    await this.persistRecord();
  }
  /**
   * The INITIATOR's re-derivable secret for the reveal path (mirrors buildClaimTx's `state.secret ?? recoverSecret()`
   * ~7204-7207): return the in-memory S if present, else RE-DERIVE it (hmac-v1 from K_ss+nonce, or a durable S) and
   * RE-AUTHENTICATE sha256(S) === offer.secretHash before caching it. Returns null (fail closed) on any miss/mismatch.
   */
  async loadInitiatorSecret() {
    if (this.secret && this.secret.length === 32) return this.secret;
    const secretHashHex = (this.record.offer.secretHash ?? "").toLowerCase().replace(/^0x/, "");
    if (!HEX64.test(secretHashHex)) return null;
    const isHmacV1 = this.record.offer.secretScheme === SWAP_SECRET_SCHEME;
    const durableSecretHex = await this.deps.durable.get(durableSecretKey(this.record.id));
    const S = await this.recoverSecret(secretHashHex, isHmacV1, durableSecretHex);
    if (!S || S.length !== 32) return null;
    if (bytesToHex(sha256(S)) !== secretHashHex) {
      S.fill(0);
      return null;
    }
    if (this.secret) this.secret.fill(0);
    this.secret = S;
    return S;
  }
  /** Recover the 32-byte preimage: hmac-v1 -> derive from K_ss + nonce; else -> decode a durable S. Returns null on miss. */
  async recoverSecret(secretHashHex, isHmacV1, durableSecretHex) {
    if (isHmacV1 && this.role === "initiator") {
      const nonceHex = (this.record.offer.secretNonce ?? "").toLowerCase();
      if (!/^[0-9a-f]{32}$/.test(nonceHex)) return null;
      const kss = await this.deps.seedVault.swapKss();
      if (!kss || kss.length !== 32) return null;
      try {
        const nonce = hexToBytes(nonceHex);
        if (nonce.length !== SWAP_NONCE_BYTES) return null;
        return swapSecretFromKss(kss, nonce);
      } finally {
        kss.fill(0);
      }
    }
    if (durableSecretHex && HEX64.test(durableSecretHex.toLowerCase())) {
      try {
        return hexToBytes(durableSecretHex.toLowerCase());
      } catch {
        return null;
      }
    }
    return null;
  }
  // ── fundLegX() — the initiator funds its OWN UTXO leg X ──────────────────────────────────────────────────
  /**
   * Fund the initiator's own UTXO leg. Faithfully ports the proven handleBroadcastFunding path:
   *   (1) SPV verifyFundingHeight on the build height (H1-LOCKTIME-PROXY-001 ~5100) — fail closed if the proxy
   *       height is not a real PoW block (an inflated height would push OUR refund CLTV ~forever, stranding coins).
   *   (2) select + reserve inputs INSIDE reservation.withUtxoLock (candidateUtxos -> greedy FIFO -> reserveInputs
   *       ~5432-5457) so a concurrent funding cannot double-spend an input.
   *   (3) build the funding tx via createInitiatorHTLC + fundHTLC/buildHTLCFundingTx (~5512), signed with the
   *       seedVault key.
   *   (4) commit the durable write-set {funded, fundlocktime, fundrecipient, fundedhtlc} ATOMICALLY (fix #4) BEFORE
   *       the broadcast; a commit throw ABORTS without broadcasting.
   *   (5) broadcast — the whole (2)-(5) sequence runs inside mutex.withLock('bch2swap:fund:'+id) (fix #3
   *       single-flight); a durable `funded` sentinel is re-checked inside the lock so a second call ADOPTS the
   *       prior txid instead of double-broadcasting. myFundingTxid is written after the broadcast.
   * Transitions `taken|prepared -> initiator_funded`.
   */
  async fundLegX() {
    this.assertLive();
    if (this.record.role !== "initiator") {
      throw new Error("fundLegX: only the initiator funds leg X (the responder funds leg Y via fundLegY)");
    }
    return this.fundOwnLeg({
      label: "fundLegX",
      expectRole: "initiator",
      targetPhase: "initiator_funded",
      amountSats: this.legXAmountSats(),
      buildHtlc: (state, buildHeight, recipientPkh, refundPkh) => createInitiatorHTLC(state, buildHeight, recipientPkh, refundPkh)
    });
  }
  // ── fundLegY(proof) — the RESPONDER funds its OWN UTXO leg Y ────────────────────────────────────────────────
  /**
   * Fund the RESPONDER's own UTXO leg Y (receiveChain), reusing fundLegX's proven select/reserve/build/
   * durable-commit/broadcast machinery but with the RESPONDER HTLC (createResponderHTLC — LOCKTIME_BLOCKS.responder,
   * ~12h, well under the initiator's ~36h) and the leg-Y amount (offer.receiveAmount). It STRUCTURALLY requires a
   * `FundProof` (compile-time) — the only minter is verifyCounterpartyLegForFunding — so a bot cannot fund leg Y
   * without first proving leg X is buried + the timelock margin is safe.
   *
   * FIX #2 (zero proof-reuse window, R175): the passed `proof`'s captured values are NEVER trusted to authorize the
   * broadcast. Inside the fund mutex, at the broadcast choke point, we RE-MINT from a FRESH read of the counterparty
   * (initiator) leg X (verifyCounterpartyLegForFunding -> assertLegBuriedForFunding). A fresh throw ABORTS without
   * broadcasting — funds never move against a leg X that reorged / double-spent / drifted past the margin since the
   * proof was minted. Transitions `taken|prepared -> responder_funded`. Grounds in handleCounterpartyFunded + the
   * responder fund path (~5230-5281).
   */
  async fundLegY(proof) {
    this.assertLive();
    if (this.record.role !== "responder") {
      throw new Error("fundLegY: only the responder funds leg Y (the initiator funds leg X via fundLegX)");
    }
    if (proof.leg !== "X" || proof.for !== "fundY") {
      throw new Error("fundLegY: the supplied FundProof is not a leg-X fund authorization \u2014 refusing to fund");
    }
    return this.fundOwnLeg({
      label: "fundLegY",
      expectRole: "responder",
      targetPhase: "responder_funded",
      amountSats: this.legYAmountSats(),
      // Height-based responder CLTV (buildHeight + LOCKTIME_BLOCKS.responder). The EVM-anchored TIMESTAMP CLTV (R167)
      // is a step-7 topology; this UTXO<->UTXO path uses the default height locktime.
      buildHtlc: (state, buildHeight, recipientPkh, refundPkh) => createResponderHTLC(state, buildHeight, recipientPkh, refundPkh),
      // FIX #2: re-mint the counterparty-leg-X burial proof FRESH at the broadcast choke point (throws -> abort).
      preBroadcastReverify: async () => {
        await this.verifyCounterpartyLegForFunding();
      }
    });
  }
  /**
   * Shared own-leg funding machinery for fundLegX (initiator) + fundLegY (responder). Faithfully ports the proven
   * handleBroadcastFunding path — see the fundLegX doc block for the (1)-(5) sequence. The only per-role differences
   * are the HTLC factory, the leg amount, the target phase, and the optional `preBroadcastReverify` (fix #2, leg Y).
   */
  async fundOwnLeg(opts) {
    const { label, expectRole, targetPhase, amountSats, buildHtlc, preBroadcastReverify } = opts;
    const rec = this.record;
    if (rec.role !== expectRole) {
      throw new Error(`${label}: wrong role '${rec.role}' \u2014 refusing to fund`);
    }
    if (rec.phase !== "taken" && rec.phase !== "prepared") {
      throw new Error(`${label}: unexpected phase '${rec.phase}' \u2014 fund runs from 'taken' or 'prepared'`);
    }
    if (isSwapPairSuspended(this.myChain, this.theirChain)) {
      throw new Error(`${label}: swap pair ${this.myChain}/${this.theirChain} is suspended \u2014 refusing to fund`);
    }
    const cfg = chainConfigs[this.myChain];
    if (!cfg || cfg.isEvm) {
      throw new Error(`${label}: own leg (${this.myChain}) is not a UTXO chain \u2014 EVM funding is step 7`);
    }
    const claimPkhHex = (rec.counterpartyClaimPkh ?? "").toLowerCase().replace(/^0x/, "");
    if (!HEX20.test(claimPkhHex)) {
      throw new Error(`${label}: counterpartyClaimPkh (the counterparty receive pkh on the own leg) is missing \u2014 cannot build the HTLC`);
    }
    if (expectRole === "initiator") {
      const isHmacV1 = rec.offer.secretScheme === SWAP_SECRET_SCHEME;
      const durableSecretHex = await this.deps.durable.get(durableSecretKey(rec.id));
      if (!isHmacV1 && !durableSecretHex) {
        throw new Error(
          `${label}: offer secretScheme '${rec.offer.secretScheme ?? "none"}' is not '${SWAP_SECRET_SCHEME}' and no encrypted-at-rest durable secret is present \u2014 refusing to fund a swap whose secret a crash would strand (fix #5)`
        );
      }
    }
    const client = this.deps.chainClientFor(this.myChain);
    this.status(`${label}:verifying-height`);
    const [buildHeight] = await client.getBlockHeight();
    if (!Number.isInteger(buildHeight) || buildHeight <= 0 || buildHeight > maxPlausibleBlockHeight()) {
      throw new Error(`${label}: proxy-reported ${this.myChain} height ${buildHeight} is implausible \u2014 refusing to set an unrecoverable refund timelock`);
    }
    if (spvSupported(this.myChain)) {
      await verifyFundingHeight(client, this.myChain, buildHeight);
    }
    const sk = await this.deps.seedVault.signingKey(this.myChain);
    const myPkh = hash160(sk.publicKey);
    const p2pkhScript = new Uint8Array([118, 169, 20, ...myPkh, 136, 172]);
    const claimPkh = hexToBytes(claimPkhHex);
    const lockName = `bch2swap:fund:${rec.id}`;
    const outcome = await this.deps.mutex.withLock(lockName, async () => {
      const prior = await this.deps.durable.get(fundedKey(rec.id));
      if (prior && HEX64.test(prior.toLowerCase())) {
        return { txid: prior.toLowerCase(), adopted: true };
      }
      this.status(`${label}:selecting-inputs`);
      const scripthash = p2pkhScripthash(myPkh);
      const chainUtxos = await client.getUTXOs(scripthash, bytesToHex(p2pkhScript));
      const now = this.deps.clock();
      const picked = await this.deps.reservation.withUtxoLock(() => {
        this.deps.reservation.releaseSwap(rec.id);
        const valid = chainUtxos.filter((u) => Number.isFinite(u.value) && u.value > 0).map((u) => ({ tx_hash: u.tx_hash, tx_pos: u.tx_pos, value: u.value, height: u.height }));
        const candidates = this.deps.reservation.candidateUtxos(rec.id, valid, now);
        const sel = this.greedySelect(candidates, amountSats);
        if (!sel) return null;
        this.deps.reservation.reserveInputs(rec.id, sel, now);
        return sel;
      });
      if (!picked || picked.length === 0) {
        this.deps.reservation.releaseSwap(rec.id);
        throw new Error(`${label}: insufficient spendable UTXOs to fund the HTLC`);
      }
      try {
        let selected = picked;
        if (!(cfg.useBip143 ?? false)) {
          this.status(`${label}:authenticating-inputs`);
          const fetchRawTx = (txid) => client.getTx(txid);
          const authed = [];
          for (const u of picked) {
            const a = await verifyAndAuthenticateP2pkhInput(u, myPkh, fetchRawTx);
            authed.push({ ...u, value: a.value });
          }
          const authTotal = authed.reduce((s, x) => s + x.value, 0);
          if (authTotal < amountSats) {
            throw new Error(`${label}: authenticated input total is below the funding amount (possible proxy value inflation) \u2014 not signing`);
          }
          selected = authed;
        }
        const htlc = buildHtlc(this.buildSwapState(expectRole), buildHeight, claimPkh, myPkh);
        this.status(`${label}:building-tx`);
        const tx = await fundHTLC(htlc, selected, sk.privateKey, sk.publicKey, p2pkhScript, amountSats, this.myChain);
        const totalIn = selected.reduce((s, u) => s + u.value, 0);
        const changeVal = totalIn - amountSats - tx.fee;
        if (changeVal > 0) this.deps.reservation.recordChange(rec.id, { tx_hash: tx.txid, tx_pos: 1, value: changeVal, height: 0 }, now);
        const canonical = tx.txid.toLowerCase();
        if (preBroadcastReverify) {
          this.status(`${label}:reverifying-counterparty`);
          await preBroadcastReverify();
        }
        this.status(`${label}:committing`);
        await this.deps.durable.commit([
          [fundedKey(rec.id), canonical],
          [fundLocktimeKey(rec.id), String(htlc.params.locktime)],
          [fundRecipientKey(rec.id), bytesToHex(claimPkh)],
          [fundedHtlcKey(rec.id), JSON.stringify(durableHtlc(htlc))],
          [fundedTxKey(rec.id), tx.rawTx]
        ]);
        this.status(`${label}:broadcasting`);
        await client.broadcastTx(tx.rawTx);
        return { txid: canonical, htlc, adopted: false };
      } catch (e) {
        this.deps.reservation.releaseSwap(rec.id);
        throw e;
      }
    });
    let fundedHtlc = outcome.htlc ? durableHtlc(outcome.htlc) : void 0;
    let fundLocktime = outcome.htlc ? outcome.htlc.params.locktime : void 0;
    if (outcome.adopted) {
      const hydrated = await this.readDurableFundedHtlc(rec.id);
      if (hydrated) {
        fundedHtlc = hydrated;
        fundLocktime = hydrated.locktime;
      }
    }
    this.record = {
      ...this.record,
      myFundingTxid: outcome.txid,
      myHTLC: fundedHtlc ?? this.record.myHTLC,
      fundLocktime: fundLocktime ?? this.record.fundLocktime,
      funded: true
    };
    this.setPhase(targetPhase);
    this.status(`${label}:funded`);
    await this.persistRecord();
    return { txid: outcome.txid };
  }
  // ── counterparty-leg proof minters (the ONLY controller-side minters) ──────────────────────────────────────
  /**
   * RESPONDER-ONLY. Mint a `FundProof` by SPV-verifying the counterparty (initiator) leg X is buried at the required
   * depth + the responder timelock margin is safe (gates.assertLegBuriedForFunding over leg X). Returns the branded
   * proof or THROWS a GateFailure (mints nothing) on any failure/uncertainty — fail closed, no funds move. This is
   * the only way to obtain the `FundProof` that fundLegY requires (design §4).
   */
  async verifyCounterpartyLegForFunding() {
    this.assertLive();
    if (this.record.role !== "responder") {
      throw new Error("verifyCounterpartyLegForFunding: responder-only (the initiator does not fund against a FundProof)");
    }
    const { redeemScript, locktime, outpoint } = this.counterpartyLeg("verifyCounterpartyLegForFunding");
    const client = this.deps.chainClientFor(this.theirChain);
    const myChainIsEvm = !!chainConfigs[this.myChain]?.isEvm;
    return assertLegBuriedForFunding(client, {
      theirChain: this.theirChain,
      myChain: this.myChain,
      myChainIsEvm,
      counterpartyRedeemScript: redeemScript,
      recordedOutpoint: outpoint,
      counterpartyLocktime: locktime
    });
  }
  /**
   * INITIATOR-ONLY. Mint a `RevealAuthorization` by SPV-verifying the counterparty (responder) leg Y is buried +
   * the 4h claim-margin runway on leg Y holds (gates.assertRevealSafe with role:'initiator' over leg Y). Returns the
   * branded authorization or THROWS a GateFailure (mints nothing) — the secret NEVER leaks on any failure. This is
   * the only way to obtain the `RevealAuthorization` that revealAndClaim requires (design §4).
   */
  async verifyCounterpartyLegForReveal() {
    this.assertLive();
    if (this.record.role !== "initiator") {
      throw new Error("verifyCounterpartyLegForReveal: initiator-only (only the initiator makes the irreversible secret reveal)");
    }
    const { redeemScript, locktime, outpoint } = this.counterpartyLeg("verifyCounterpartyLegForReveal");
    const client = this.deps.chainClientFor(this.theirChain);
    return assertRevealSafe(client, {
      role: "initiator",
      theirChain: this.theirChain,
      counterpartyRedeemScript: redeemScript,
      recordedOutpoint: outpoint,
      counterpartyLocktime: locktime
    });
  }
  // ── revealAndClaim(auth) — the INITIATOR's single irreversible secret reveal (claim of leg Y) ────────────────
  /**
   * The initiator's ONE irreversible action: reveal S by broadcasting the secret-bearing claim of the counterparty
   * (responder) leg Y. STRUCTURALLY requires a `RevealAuthorization` (compile-time). Ports handleBroadcastClaim
   * (~7787-8075). Fund-safety corrections baked in:
   *   FIX #3: throw unless `auth.role === 'initiator'` — a margin-skipped responder authorization (marginBasis:'none')
   *     must NEVER drive the initiator's reveal (it deliberately skips the 4h double-dip margin).
   *   FIX #8 (triangulation): the built claim carries the exact funding outpoint it spends (`.spent`). Require
   *     `auth.outpoint === claimTx.spent`, and — via the fresh re-mint below — that this same outpoint is STILL
   *     confirmed at >= reqConf. A cached claim tx LACKING `.spent` fails closed (R-REVEAL-FAILCLOSE ~7980): discard
   *     it + rebuild rather than broadcast the secret against an unverifiable outpoint.
   *   FIX #2 (zero reuse window): inside the claim mutex at the broadcast choke point, RE-MINT assertRevealSafe from
   *     a FRESH read (never the passed auth's captured values). A fresh throw ABORTS — S is never emitted.
   * The claim tx {txid,rawTx,spent} is committed durably (durable-before-broadcast) BEFORE the broadcast, under a
   * single-flight mutex ('bch2swap:claim:'+id) with a `claimbroadcast` sentinel so a second call / crash-resume
   * ADOPTS the prior claim instead of re-revealing. S is NEVER emitted on any throw. Transitions
   * `responder_funded -> claimed`.
   */
  async revealAndClaim(auth) {
    this.assertLive();
    const rec = this.record;
    if (rec.role !== "initiator") {
      throw new Error("revealAndClaim: only the initiator reveals the secret (the responder uses claimWithKnownSecret)");
    }
    if (auth.role !== "initiator" || auth.leg !== "Y" || auth.for !== "reveal") {
      throw new Error("revealAndClaim: the supplied authorization is not an initiator leg-Y reveal authorization \u2014 refusing to reveal the secret (fix #3)");
    }
    const adopted = await this.priorClaimTxid(rec.id);
    if (adopted) {
      this.record = { ...this.record, myClaimTxid: adopted };
      this.status("revealAndClaim:adopted");
      return { txid: adopted };
    }
    this.assertIrreversibleAllowed("revealAndClaim");
    if (await this.deps.durable.get(refundBroadcastKey(rec.id))) {
      throw new Error("revealAndClaim: a refund is already in flight \u2014 refusing to reveal the secret while a refund is active (R181 cross-guard)");
    }
    if (rec.phase !== "responder_funded" && rec.phase !== "claimed") {
      throw new Error(`revealAndClaim: unexpected phase '${rec.phase}' \u2014 reveal runs from 'responder_funded'`);
    }
    const cfg = chainConfigs[this.theirChain];
    if (!cfg || cfg.isEvm) {
      throw new Error("revealAndClaim: leg Y is not a UTXO chain \u2014 EVM reveal is step 7");
    }
    if (!auth.outpoint) {
      throw new Error("revealAndClaim: the reveal authorization carries no outpoint \u2014 cannot bind the claim (fix #8)");
    }
    const secret = await this.loadInitiatorSecret();
    if (!secret || secret.length !== 32) {
      throw new Error("revealAndClaim: the swap secret is not available (vault locked / not re-derivable) \u2014 cannot reveal");
    }
    const { redeemScript, locktime } = this.counterpartyLeg("revealAndClaim");
    const client = this.deps.chainClientFor(this.theirChain);
    const cachedRaw = await this.deps.durable.get(claimTxKey(rec.id));
    if (cachedRaw) {
      let cached = null;
      try {
        cached = JSON.parse(cachedRaw);
      } catch {
        cached = null;
      }
      if (cached && (!cached.spent || !this.isOutpoint(cached.spent))) {
        await this.deps.durable.remove(claimTxKey(rec.id));
        throw new Error("revealAndClaim: cached claim tx lacks a `.spent` outpoint \u2014 discarding + failing closed before revealing the secret (R-REVEAL-FAILCLOSE)");
      }
    }
    this.status("revealAndClaim:building-claim");
    const claimTx = await this.buildSecretClaim(this.theirChain, redeemScript, secret, auth.outpoint);
    if (!claimTx.spent || !this.isOutpoint(claimTx.spent)) {
      throw new Error("revealAndClaim: built claim has no spent outpoint \u2014 failing closed before revealing the secret (fix #8)");
    }
    if (claimTx.spent.tx_hash !== auth.outpoint.tx_hash || claimTx.spent.tx_pos !== auth.outpoint.tx_pos) {
      await this.deps.durable.remove(claimTxKey(rec.id));
      throw new Error("revealAndClaim: built claim spends a different outpoint than the authorization is bound to (possible reorg) \u2014 discarding + rebuilding, not revealing the secret (fix #8)");
    }
    const lockName = `bch2swap:claim:${rec.id}`;
    const finalTxid = await this.deps.mutex.withLock(lockName, async () => {
      const sentinel = await this.deps.durable.get(claimBroadcastKey(rec.id));
      if (sentinel) {
        const priorRaw = await this.deps.durable.get(claimTxKey(rec.id));
        if (priorRaw) {
          try {
            const prior = JSON.parse(priorRaw);
            if (prior?.txid && HEX64.test(prior.txid.toLowerCase())) return prior.txid.toLowerCase();
          } catch {
          }
        }
      }
      if (await this.deps.durable.get(refundBroadcastKey(rec.id))) {
        throw new Error("revealAndClaim: a refund became active \u2014 refusing to reveal the secret");
      }
      this.status("revealAndClaim:reverifying");
      await assertRevealSafe(client, {
        role: "initiator",
        theirChain: this.theirChain,
        counterpartyRedeemScript: redeemScript,
        recordedOutpoint: claimTx.spent,
        counterpartyLocktime: locktime
      });
      this.status("revealAndClaim:committing");
      await this.deps.durable.commit([
        [claimTxKey(rec.id), JSON.stringify(claimTx)],
        [claimBroadcastKey(rec.id), "1"]
      ]);
      this.status("revealAndClaim:broadcasting");
      await this.broadcastClaimWithSentinelGuard(client, claimTx.rawTx, rec.id);
      return claimTx.txid.toLowerCase();
    });
    let effectiveClaimTx = claimTx;
    if (finalTxid !== claimTx.txid.toLowerCase()) {
      const priorRaw = await this.deps.durable.get(claimTxKey(rec.id));
      if (priorRaw) {
        try {
          const p = JSON.parse(priorRaw);
          if (p?.txid && p?.rawTx && p?.spent) effectiveClaimTx = { txid: p.txid, rawTx: p.rawTx, spent: p.spent };
        } catch {
        }
      }
    }
    this.record = { ...this.record, claimTx: effectiveClaimTx, myClaimTxid: finalTxid };
    this.setPhase("claimed");
    this.status("revealAndClaim:claimed");
    await this.persistRecord();
    return { txid: finalTxid };
  }
  // ── watchForSecret() — the RESPONDER learns S from the initiator's on-chain claim of its OWN leg ─────────────
  /**
   * RESPONDER-ONLY. Poll the responder's OWN funded leg (leg Y, myChain) history for the initiator's spend, which
   * reveals S in its scriptSig. `extractSecret` parses the preimage and we RE-VERIFY `sha256(S) === hashLock` (the
   * hash COMMITTED in the funded redeemScript — §9.4) before saving; a forged/mismatched preimage is REJECTED.
   * Ports watchForSecret (~7499-7766) as a single scheduler-driven poll: it NEVER throws on absence (returns
   * `{secret:null}`) and, on discovery, transitions `responder_funded -> claimed`. Grounds the extract hash in
   * myHTLC.params.secretHash (R263 on-chain binding).
   */
  async watchForSecret() {
    this.assertLive();
    const rec = this.record;
    if (rec.role !== "responder") {
      throw new Error("watchForSecret: responder-only (the initiator holds S from prepare())");
    }
    const myHtlc = rec.myHTLC;
    if (!myHtlc) return { secret: null };
    const hashLockHex = (myHtlc.secretHash ?? "").toLowerCase();
    if (!HEX64.test(hashLockHex)) return { secret: null };
    const redeemScript = hexToBytes((myHtlc.redeemScript ?? "").toLowerCase());
    const client = this.deps.chainClientFor(this.myChain);
    let history;
    try {
      history = await client.getHistory(getHTLCScripthash(redeemScript), "a914" + bytesToHex(hash160(redeemScript)) + "87");
    } catch {
      return { secret: null };
    }
    for (const item of history) {
      if (typeof item?.tx_hash !== "string" || !HEX64.test(item.tx_hash.toLowerCase())) continue;
      let rawTx;
      try {
        rawTx = await client.getTx(item.tx_hash);
      } catch {
        continue;
      }
      let candidate;
      try {
        candidate = extractSecret(rawTx, hashLockHex);
      } catch {
        candidate = null;
      }
      if (!candidate || candidate.length !== 32) continue;
      if (bytesToHex(sha256(candidate)) !== hashLockHex) continue;
      if (this.secret) this.secret.fill(0);
      this.secret = candidate;
      if (rec.phase === "responder_funded") this.setPhase("claimed");
      this.status("watchForSecret:secret-found");
      await this.persistRecord();
      return { secret: candidate };
    }
    return { secret: null };
  }
  // ── claimWithKnownSecret() — the RESPONDER claims leg X with the now-PUBLIC secret ──────────────────────────
  /**
   * RESPONDER-ONLY. Claim the counterparty (initiator) leg X (theirChain) with the now-PUBLIC secret learned via
   * watchForSecret. The reveal margin gate is DELIBERATELY SKIPPED (the secret is already public — no double-dip
   * risk, design §1), but single-flight + durable-before-broadcast still apply, and it REFUSES if a refund of the
   * same HTLC is in flight (a claim + refund must not race the same outpoint). Transitions `claimed -> completed`.
   */
  async claimWithKnownSecret() {
    this.assertLive();
    const rec = this.record;
    if (rec.role !== "responder") {
      throw new Error("claimWithKnownSecret: responder-only (the initiator reveals via revealAndClaim)");
    }
    const adopted = await this.priorClaimTxid(rec.id);
    if (adopted) {
      this.record = { ...this.record, myClaimTxid: adopted };
      this.status("claimWithKnownSecret:adopted");
      return { txid: adopted };
    }
    this.assertIrreversibleAllowed("claimWithKnownSecret");
    if (rec.phase !== "claimed" && rec.phase !== "responder_funded") {
      throw new Error(`claimWithKnownSecret: unexpected phase '${rec.phase}' \u2014 the responder claim runs after the secret is public`);
    }
    const cfg = chainConfigs[this.theirChain];
    if (!cfg || cfg.isEvm) {
      throw new Error("claimWithKnownSecret: leg X is not a UTXO chain \u2014 EVM claim is step 7");
    }
    const refundInFlight = await this.deps.durable.get(refundBroadcastKey(rec.id));
    if (refundInFlight) {
      throw new Error("claimWithKnownSecret: a refund is already in flight \u2014 refusing to claim while a refund is active");
    }
    const secret = this.secret;
    if (!secret || secret.length !== 32) {
      throw new Error("claimWithKnownSecret: the public secret is not available \u2014 run watchForSecret first");
    }
    const { redeemScript } = this.counterpartyLeg("claimWithKnownSecret");
    const client = this.deps.chainClientFor(this.theirChain);
    this.status("claimWithKnownSecret:building-claim");
    const claimTx = await this.buildSecretClaim(this.theirChain, redeemScript, secret);
    const lockName = `bch2swap:claim:${rec.id}`;
    const finalTxid = await this.deps.mutex.withLock(lockName, async () => {
      const sentinel = await this.deps.durable.get(claimBroadcastKey(rec.id));
      if (sentinel) {
        const priorRaw = await this.deps.durable.get(claimTxKey(rec.id));
        if (priorRaw) {
          try {
            const prior = JSON.parse(priorRaw);
            if (prior?.txid && HEX64.test(prior.txid.toLowerCase())) return prior.txid.toLowerCase();
          } catch {
          }
        }
      }
      if (await this.deps.durable.get(refundBroadcastKey(rec.id))) {
        throw new Error("claimWithKnownSecret: a refund became active \u2014 refusing to claim");
      }
      this.status("claimWithKnownSecret:committing");
      await this.deps.durable.commit([
        [claimTxKey(rec.id), JSON.stringify(claimTx)],
        [claimBroadcastKey(rec.id), "1"]
      ]);
      this.status("claimWithKnownSecret:broadcasting");
      await this.broadcastClaimWithSentinelGuard(client, claimTx.rawTx, rec.id);
      return claimTx.txid.toLowerCase();
    });
    this.record = { ...this.record, claimTx, myClaimTxid: finalTxid };
    this.setPhase("completed");
    this.status("claimWithKnownSecret:completed");
    await this.persistRecord();
    return { txid: finalTxid };
  }
  // ── canRefund() / refund() — recover OUR OWN funded leg after its timelock (§9.7) ───────────────────────────
  /**
   * PURE predicate (no side effects, no network): is OUR funded HTLC refundable at the host-supplied `currentHeight`?
   * Exposes the ported isHtlcRefundAvailable(myHTLC.locktime, tip) for the host to render an affordance. This is only
   * an availability HINT — the REAL enforcer is the on-chain CLTV plus the FRESH-tip re-check inside refund() (§9.7).
   * Returns false when there is no funded own HTLC.
   */
  canRefund(currentHeight) {
    const h = this.record.myHTLC;
    if (!h || !Number.isInteger(h.locktime)) return false;
    return isHtlcRefundAvailable(h.locktime, currentHeight);
  }
  /**
   * Recover OUR OWN funded leg after its timelock. Grounds in SwapExecute.tsx handleBroadcastRefund (~8349-8641):
   *   - §9.7: RE-CHECK isHtlcRefundAvailable against a FRESH tip immediately before build (the on-chain CLTV is the
   *     real enforcer, but never build/broadcast a premature refund the node will reject).
   *   - build buildHTLCRefundTx (nSequence 0xfffffffe + nLockTime=locktime are set INSIDE the builder). Carries NO secret.
   *   - R280-H1 / fix #4 durable-before-broadcast: PERSIST the raw refund tx + a `refundbroadcast` sentinel via
   *     durable.commit BEFORE the broadcast; a commit throw ABORTS the broadcast.
   *   - broadcast under a SINGLE-FLIGHT mutex.
   *   - arm the reorg-safe confirmRefund finalizer.
   * FIX (deferred from step 5 — R181 claim<->refund cross-guard): take the SAME 'bch2swap:claim:'+id lock the claim
   * paths use (and refuse if a `claimbroadcast` sentinel is set) so a claim and a refund never race the same outpoint.
   * FIX #10: refuse if resume left the myHTLC authentication non-definitive (see assertIrreversibleAllowed).
   * Transitions -> 'refunded' at broadcast; the recovery material is KEPT until confirmRefund reaches reorg-safe depth.
   */
  async refund() {
    this.assertLive();
    const rec = this.record;
    const myHtlc = rec.myHTLC;
    if (!myHtlc || typeof myHtlc.redeemScript !== "string" || !/^[0-9a-f]+$/i.test(myHtlc.redeemScript) || !Number.isInteger(myHtlc.locktime)) {
      throw new Error("refund: no valid funded own HTLC recorded \u2014 nothing to refund");
    }
    const cfg = chainConfigs[this.myChain];
    if (!cfg || cfg.isEvm) {
      throw new Error("refund: own leg is not a UTXO chain \u2014 EVM refund is step 7");
    }
    this.assertIrreversibleAllowed("refund");
    if (await this.deps.durable.get(claimBroadcastKey(rec.id))) {
      throw new Error("refund: a claim is already in flight \u2014 refusing to refund while a claim is active (R181 cross-guard)");
    }
    const redeemScript = hexToBytes(myHtlc.redeemScript.toLowerCase());
    const locktime = myHtlc.locktime;
    const client = this.deps.chainClientFor(this.myChain);
    this.status("refund:checking-timelock");
    const [freshTip] = await client.getBlockHeight();
    const tip = Number.isInteger(freshTip) && freshTip > 0 ? freshTip : null;
    if (!isHtlcRefundAvailable(locktime, tip)) {
      throw new Error(`refund: HTLC refund timelock has not passed yet (locktime ${locktime}, tip ${tip ?? "unknown"}) \u2014 not building a premature refund`);
    }
    const sk = await this.deps.seedVault.signingKey(this.myChain);
    const myPkh = hash160(sk.publicKey);
    const destScriptPubKey = new Uint8Array([118, 169, 20, ...myPkh, 136, 172]);
    const lockName = `bch2swap:claim:${rec.id}`;
    const finalTxid = await this.deps.mutex.withLock(lockName, async () => {
      if (await this.deps.durable.get(refundBroadcastKey(rec.id))) {
        const prior = await this.readDurableRefundTx(rec.id);
        if (prior) return prior.txid.toLowerCase();
      }
      if (await this.deps.durable.get(claimBroadcastKey(rec.id))) {
        throw new Error("refund: a claim became active \u2014 refusing to refund");
      }
      this.status("refund:selecting-utxo");
      const scriptHex = "a914" + bytesToHex(hash160(redeemScript)) + "87";
      const utxos = await client.getUTXOs(getHTLCScripthash(redeemScript), scriptHex);
      const valid = utxos.filter((u) => u && typeof u.tx_hash === "string" && Number.isInteger(u.tx_pos) && Number.isFinite(u.value) && u.value > 0);
      if (valid.length === 0) throw new Error("refund: no UTXO at the HTLC address \u2014 already refunded or never funded");
      const selected = [...valid].sort((a, b) => b.value - a.value)[0];
      const authed = await verifyAndAuthenticateUtxo(
        { tx_hash: selected.tx_hash, tx_pos: selected.tx_pos, value: selected.value, height: selected.height },
        redeemScript,
        (txid) => client.getTx(txid)
      );
      if (!(authed.value > 0)) throw new Error("refund: HTLC funding output failed re-authentication \u2014 not signing the refund");
      this.status("refund:building");
      const refundTx = await buildHTLCRefundTx(authed, redeemScript, locktime, sk.privateKey, sk.publicKey, destScriptPubKey, this.myChain);
      const refundRec = { txid: refundTx.txid, rawTx: refundTx.rawTx, spent: { tx_hash: selected.tx_hash, tx_pos: selected.tx_pos } };
      this.status("refund:committing");
      await this.deps.durable.commit([
        [refundTxKey(rec.id), JSON.stringify(refundRec)],
        [refundBroadcastKey(rec.id), "1"]
      ]);
      this.status("refund:broadcasting");
      await client.broadcastTx(refundTx.rawTx);
      return refundTx.txid.toLowerCase();
    });
    const durableRefund = await this.readDurableRefundTx(rec.id);
    this.record = {
      ...this.record,
      refundTx: durableRefund ? { txid: durableRefund.txid, rawTx: durableRefund.rawTx } : this.record.refundTx
    };
    this.setPhase("refunded");
    this.status("refund:broadcast");
    await this.persistRecord();
    try {
      await this.confirmRefund();
    } catch {
    }
    return { txid: finalTxid };
  }
  // ── reorg-safe finalizers (§9.6) — delete non-recoverable material ONLY at reorg-safe SPV depth ─────────────
  /**
   * CLAIM finalizer (§9.6). Ground: SwapExecute.tsx confirmClaim (~8019-8112). Polls the counterparty leg (theirChain)
   * for OUR claim txid; ONLY once it is buried at >= requiredConfirmations VERIFIED BY SPV (verifyConfirmations,
   * provenTxid-bound) does it delete the non-recoverable secret + claim cache + record. On 0-conf / absent / short
   * depth / inconclusive-or-pruned SPV read it KEEPS everything (fail closed). Single poll — the host re-drives it.
   */
  async confirmClaim() {
    this.assertLive();
    const rec = this.record;
    const claimTxid = (rec.myClaimTxid ?? rec.claimTx?.txid ?? "").toLowerCase();
    const cp = rec.counterpartyHTLC;
    if (!HEX64.test(claimTxid) || !cp || typeof cp.redeemScript !== "string" || !/^[0-9a-f]+$/i.test(cp.redeemScript)) return { finalized: false };
    const cfg = chainConfigs[this.theirChain];
    if (!cfg || cfg.isEvm) return { finalized: false };
    const redeemScript = hexToBytes(cp.redeemScript.toLowerCase());
    const client = this.deps.chainClientFor(this.theirChain);
    const reqConf = Math.max(1, cfg.requiredConfirmations ?? 6);
    let history;
    try {
      history = await client.getHistory(getHTLCScripthash(redeemScript), "a914" + bytesToHex(hash160(redeemScript)) + "87");
    } catch {
      return { finalized: false };
    }
    const entry = history.find((h) => typeof h?.tx_hash === "string" && h.tx_hash.toLowerCase() === claimTxid && Number.isInteger(h.height) && h.height > 0);
    if (!entry) return { finalized: false };
    const ok = await this.spvReorgSafe(client, this.theirChain, claimTxid, entry.height, rec.claimTx?.rawTx, reqConf);
    if (!ok) return { finalized: false };
    if (this.secret) {
      this.secret.fill(0);
      this.secret = null;
    }
    await this.wipeDurable([claimTxKey(rec.id), claimBroadcastKey(rec.id), durableSecretKey(rec.id), recordKey(rec.id)]);
    this.setPhase("completed");
    this.status("confirmClaim:finalized");
    return { finalized: true };
  }
  /**
   * REFUND finalizer (§9.6). Ground: SwapExecute.tsx confirmRefund (~8466-8531). Polls OUR OWN leg (myChain) for OUR
   * refund txid; ONLY once buried at >= requiredConfirmations VERIFIED BY SPV does it wipe the recovery material. On
   * 0-conf / dropped / short depth / inconclusive-or-pruned read it KEEPS refundtx/refundbroadcast/state — "give up
   * POLLING after 4h but KEEP everything" maps to a single non-finalizing poll (SwapExecute.tsx:8468). The secret/state
   * are wiped ONLY if no claim is in flight (a co-running winning claim needs the shared preimage); the refundtx +
   * sentinel are always cleared at reorg-safe depth. Fail-closed = keep material.
   */
  async confirmRefund() {
    this.assertLive();
    const rec = this.record;
    const durableRefund = await this.readDurableRefundTx(rec.id);
    const refund = durableRefund ?? (rec.refundTx ? { txid: rec.refundTx.txid, rawTx: rec.refundTx.rawTx } : null);
    const myHtlc = rec.myHTLC;
    if (!refund || !HEX64.test(refund.txid.toLowerCase()) || !myHtlc || typeof myHtlc.redeemScript !== "string" || !/^[0-9a-f]+$/i.test(myHtlc.redeemScript)) return { finalized: false };
    const cfg = chainConfigs[this.myChain];
    if (!cfg || cfg.isEvm) return { finalized: false };
    const redeemScript = hexToBytes(myHtlc.redeemScript.toLowerCase());
    const client = this.deps.chainClientFor(this.myChain);
    const reqConf = Math.max(1, cfg.requiredConfirmations ?? 6);
    const refundTxid = refund.txid.toLowerCase();
    let history;
    try {
      history = await client.getHistory(getHTLCScripthash(redeemScript), "a914" + bytesToHex(hash160(redeemScript)) + "87");
    } catch {
      return { finalized: false };
    }
    const entry = history.find((h) => typeof h?.tx_hash === "string" && h.tx_hash.toLowerCase() === refundTxid && Number.isInteger(h.height) && h.height > 0);
    if (!entry) return { finalized: false };
    const ok = await this.spvReorgSafe(client, this.myChain, refundTxid, entry.height, refund.rawTx, reqConf);
    if (!ok) return { finalized: false };
    this.setPhase("refunded");
    const claimSeen = !!await this.deps.durable.get(claimBroadcastKey(rec.id));
    const wipe = [refundTxKey(rec.id), refundBroadcastKey(rec.id)];
    if (!claimSeen) {
      if (this.secret) {
        this.secret.fill(0);
        this.secret = null;
      }
      wipe.push(durableSecretKey(rec.id), recordKey(rec.id), fundedKey(rec.id), fundLocktimeKey(rec.id), fundRecipientKey(rec.id), fundedHtlcKey(rec.id), fundedTxKey(rec.id));
    }
    await this.wipeDurable(wipe);
    this.status("confirmRefund:finalized");
    return { finalized: true };
  }
  /**
   * Pruned-safe SETTLE for a tangled completed swap (§9.6 / SwapExecute.tsx trySettleIfBothLegsSpent ~6809). Only when
   * the `claimbroadcast` sentinel is set AND BOTH legs are spent on the LIVE UTXO set is the swap terminal (their claim
   * of our leg used our revealed secret, or both refunded) — nothing left to recover — so wipe + finalize. If OUR leg
   * is still funded (refundable) it returns false + KEEPS the recovery material (fail closed). Any inconclusive read
   * returns false. Returns true iff it settled.
   */
  async trySettleIfBothLegsSpent() {
    this.assertLive();
    if (this.irreversibleBlocked) return false;
    const rec = this.record;
    if (!await this.deps.durable.get(claimBroadcastKey(rec.id))) return false;
    const myHtlc = rec.myHTLC;
    const cpHtlc = rec.counterpartyHTLC;
    if (!myHtlc || !cpHtlc || typeof myHtlc.redeemScript !== "string" || typeof cpHtlc.redeemScript !== "string") return false;
    if (chainConfigs[this.myChain]?.isEvm || chainConfigs[this.theirChain]?.isEvm) return false;
    try {
      const cpRedeem = hexToBytes(cpHtlc.redeemScript.toLowerCase());
      const cpClient = this.deps.chainClientFor(this.theirChain);
      const cpUtxos = await cpClient.getUTXOs(getHTLCScripthash(cpRedeem), "a914" + bytesToHex(hash160(cpRedeem)) + "87");
      if (cpUtxos.some((u) => Number.isFinite(u.value) && u.value > 0)) return false;
      const myRedeem = hexToBytes(myHtlc.redeemScript.toLowerCase());
      const myClient = this.deps.chainClientFor(this.myChain);
      const myUtxos = await myClient.getUTXOs(getHTLCScripthash(myRedeem), "a914" + bytesToHex(hash160(myRedeem)) + "87");
      if (myUtxos.some((u) => Number.isFinite(u.value) && u.value > 0)) return false;
      if (!await this.ownLegSpendReorgSafe(myClient, myRedeem)) return false;
      if (this.secret) {
        this.secret.fill(0);
        this.secret = null;
      }
      await this.wipeDurable([claimTxKey(rec.id), claimBroadcastKey(rec.id), durableSecretKey(rec.id), recordKey(rec.id)]);
      this.setPhase("completed");
      this.status("trySettle:finalized");
      return true;
    } catch {
      return false;
    }
  }
  /**
   * §9.6 reorg-safe proof that OUR OWN leg's HTLC funding output has been SPENT and that spend is buried at
   * >= requiredConfirmations SPV-VERIFIED depth (the same anchor confirmClaim / confirmRefund use). The spend is the
   * confirmed HTLC-scripthash history tx that is NOT our own funding tx. FAIL CLOSED (returns false): a transient read
   * error, a 0-conf / short-depth spend, a pruned/unprovable SPV read, or the absence of any confirmed spend all KEEP
   * the recovery material. Never trusts a bare getUTXOs "empty" read to authorize the teardown.
   */
  async ownLegSpendReorgSafe(client, myRedeem) {
    const rec = this.record;
    const cfg = chainConfigs[this.myChain];
    if (!cfg || cfg.isEvm) return false;
    const reqConf = Math.max(1, cfg.requiredConfirmations ?? 6);
    const fundingTxid = (rec.myFundingTxid ?? "").toLowerCase();
    let history;
    try {
      history = await client.getHistory(getHTLCScripthash(myRedeem), "a914" + bytesToHex(hash160(myRedeem)) + "87");
    } catch {
      return false;
    }
    for (const h of history) {
      if (typeof h?.tx_hash !== "string" || !HEX64.test(h.tx_hash.toLowerCase()) || !Number.isInteger(h.height) || h.height <= 0) continue;
      const txid = h.tx_hash.toLowerCase();
      if (txid === fundingTxid) continue;
      if (await this.spvReorgSafe(client, this.myChain, txid, h.height, void 0, reqConf)) return true;
    }
    return false;
  }
  // ── resume() — rehydrate a stalled / crashed / new-device swap from durable state (fix #10) ──────────────────
  /**
   * Rehydrate a swap from a durable record: re-derive S, RECONSTRUCT + on-chain-AUTHENTICATE myHTLC, run the
   * FINALIZERS-FIRST (refund-first short-circuit), rebroadcast a funded-but-missing funding tx idempotently, and
   * re-enter the correct gate from CHAIN truth (isResumableSwapState), NOT the persisted status. FIX #10 (critical): a
   * DEFINITIVE myHTLC 'mismatch' fails closed; an INDETERMINATE (network-blip) auth may WAIT / re-poll ONLY — neither
   * authorizes any irreversible broadcast (refund/claim) until authentication is DEFINITIVE 'ok'. Returns the controller.
   */
  static async resume(record, deps) {
    const ctrl = new _SwapController(record, deps);
    await ctrl.rehydrate();
    return ctrl;
  }
  async rehydrate() {
    this.assertLive();
    const rec = this.record;
    try {
      await this.loadInitiatorSecret();
    } catch {
    }
    await this.reconstructMyHtlc();
    const auth = await this.authenticateMyHtlcAgainstFunding();
    this.resumeAuthValue = auth;
    this.irreversibleBlocked = auth === "mismatch" || auth === "indeterminate";
    if (auth === "mismatch") {
      this.status("resume:auth-mismatch");
      this.emit({ type: "error", error: new Error("resume: myHTLC failed on-chain authentication (DEFINITIVE P2SH mismatch) \u2014 failing closed, no irreversible action permitted (fix #10)") });
    } else if (auth === "indeterminate") {
      this.status("resume:auth-indeterminate");
    } else if (auth === "ok") {
      this.status("resume:auth-ok");
    }
    if (await this.deps.durable.get(refundBroadcastKey(rec.id))) {
      const r = await this.confirmRefund();
      if (!r.finalized) await this.rebroadcastRefundIfDropped();
      this.setResumeGate(r.finalized ? "refund-finalized" : "refund-in-flight");
      return;
    }
    if (await this.deps.durable.get(claimBroadcastKey(rec.id))) {
      if (await this.trySettleIfBothLegsSpent()) {
        this.setResumeGate("settled");
        return;
      }
      const c = await this.confirmClaim();
      this.setResumeGate(c.finalized ? "claim-finalized" : "claim-in-flight");
      return;
    }
    await this.rebroadcastFundingIfMissing();
    await this.rebroadcastRefundIfDropped();
    this.setResumeGate(isResumableSwapState(rec) ? "post-funding" : "pre-funding");
  }
  setResumeGate(gate) {
    this.resumeGateValue = gate;
    this.status(`resume:${gate}`);
  }
  /**
   * Authenticate our recorded myHTLC against the LIVE on-chain funding output (faithful port of SwapExecute.tsx:4699
   * authenticateMyHtlcAgainstFunding; the React mountedRef guards + Promise.race timeouts are dropped — the SDK client
   * owns transport timeouts). Returns:
   *   'ok'            — the funding output[0] byte-matches our HTLC P2SH (unspent set OR self-authenticated raw tx),
   *   'mismatch'      — a DEFINITIVE tamper (non-bare-hex funding txid, or output[0] present but not our P2SH),
   *   'indeterminate' — an AMBIGUOUS read (network/cold-proxy getTx failure) BUT the funding txid is in our own HTLC
   *                     scripthash history (a genuine, possibly-already-spent funding) — caller may WAIT / re-poll,
   *   'skip'          — no UTXO myHTLC / funding txid to check (an EVM leg, or not funded yet).
   * FIX #10: only 'ok' authorizes an irreversible action; 'mismatch' fails closed; 'indeterminate' waits.
   */
  async authenticateMyHtlcAgainstFunding() {
    const h = this.record.myHTLC;
    const ft = this.record.myFundingTxid;
    const myChainIsEvm = !!chainConfigs[this.myChain]?.isEvm;
    if (!h || !ft || typeof ft !== "string" || myChainIsEvm) return "skip";
    if (!HEX64.test(ft.toLowerCase())) return "mismatch";
    const ftLower = ft.toLowerCase();
    const redeemScript = hexToBytes((h.redeemScript ?? "").toLowerCase());
    const client = this.deps.chainClientFor(this.myChain);
    let inOwnHistory = false;
    try {
      const sh = getHTLCScripthash(redeemScript);
      const scriptHex = "a914" + bytesToHex(hash160(redeemScript)) + "87";
      let ownUnspent = false;
      try {
        const own = await client.getUTXOs(sh, scriptHex);
        ownUnspent = Array.isArray(own) && own.some((u) => typeof u?.tx_hash === "string" && u.tx_hash.toLowerCase() === ftLower && u.tx_pos === 0);
        const hist = await client.getHistory(sh, scriptHex);
        inOwnHistory = Array.isArray(hist) && hist.some((x) => typeof x?.tx_hash === "string" && x.tx_hash.toLowerCase() === ftLower);
      } catch {
      }
      if (ownUnspent) return "ok";
      const auth = await verifyAndAuthenticateUtxo(
        { tx_hash: ftLower, tx_pos: 0, value: 0, height: 0 },
        redeemScript,
        (txid) => client.getTx(txid)
      );
      return auth.value > 0 ? "ok" : "mismatch";
    } catch (e) {
      const m = e instanceof Error ? e.message : String(e);
      if (/does not match the HTLC P2SH|malformed UTXO tx_hash|malformed UTXO tx_pos/i.test(m)) return "mismatch";
      return inOwnHistory ? "indeterminate" : "mismatch";
    }
  }
  /**
   * RECONSTRUCT myHTLC on resume from the durable side-channels when the states-map copy is gone (R170 fundedhtlc, then
   * R277 fundlocktime + funding-txid rebuild). The single trust anchor is the on-chain P2SH byte-match
   * (verifyAndAuthenticateUtxo): a lying/tampered source can only DENY a rebuild (fail-closed skip), never install a
   * bad refund/watch target. No-op if myHTLC already present, or on an EVM leg.
   */
  async reconstructMyHtlc() {
    const rec = this.record;
    if (rec.myHTLC) return;
    const myChainIsEvm = !!chainConfigs[this.myChain]?.isEvm;
    if (myChainIsEvm) return;
    const hydrated = await this.readDurableFundedHtlc(rec.id);
    if (hydrated) {
      this.record = { ...rec, myHTLC: hydrated, fundLocktime: rec.fundLocktime ?? hydrated.locktime };
      return;
    }
    const fltStr = await this.deps.durable.get(fundLocktimeKey(rec.id)) ?? (rec.fundLocktime !== void 0 ? String(rec.fundLocktime) : null);
    const secretHashHex = (rec.offer.secretHash ?? "").toLowerCase().replace(/^0x/, "");
    const secretHash = HEX64.test(secretHashHex) ? hexToBytes(secretHashHex) : null;
    const gate = validateReconstructionInputs({ myChainIsEvm, fundingTxid: rec.myFundingTxid, locktimeStr: fltStr, secretHash });
    if (!gate.ok || !gate.fundingTxid || gate.locktime === void 0 || !secretHash) return;
    const claimPkhHex = (rec.counterpartyClaimPkh ?? await this.deps.durable.get(fundRecipientKey(rec.id)) ?? "").toLowerCase().replace(/^0x/, "");
    if (!HEX20.test(claimPkhHex)) return;
    let refundPkh;
    try {
      const sk = await this.deps.seedVault.signingKey(this.myChain);
      refundPkh = hash160(sk.publicKey);
    } catch {
      return;
    }
    const params = { secretHash, recipientPubkeyHash: hexToBytes(claimPkhHex), refundPubkeyHash: refundPkh, locktime: gate.locktime };
    let rebuilt;
    try {
      rebuilt = createHTLC(params, this.myChain);
    } catch {
      return;
    }
    const client = this.deps.chainClientFor(this.myChain);
    try {
      const authed = await verifyAndAuthenticateUtxo(
        { tx_hash: gate.fundingTxid, tx_pos: 0, value: NaN, height: 0 },
        rebuilt.redeemScript,
        (txid) => client.getTx(txid)
      );
      if (!(authed.value > 0)) return;
    } catch {
      return;
    }
    this.record = { ...rec, myHTLC: durableHtlc(rebuilt), fundLocktime: gate.locktime };
  }
  /**
   * If the durable 'funded' sentinel/txid is set but the funding tx is NOT on-chain, rebroadcast the EXACT durable raw
   * funding tx (bch2swap:fundedtx, step 4) IDEMPOTENTLY (same txid — the node dedups) rather than re-selecting inputs
   * (which would pick different inputs -> a divergent txid than the durable sentinel). Fail-closed: if we cannot tell
   * whether the funding is on-chain (read error), we do NOT rebroadcast blindly.
   */
  async rebroadcastFundingIfMissing() {
    const rec = this.record;
    const fundedSentinel = (await this.deps.durable.get(fundedKey(rec.id)))?.toLowerCase();
    const fundingTxid = (rec.myFundingTxid ?? fundedSentinel ?? "").toLowerCase();
    if (!HEX64.test(fundingTxid)) return;
    const rawTx = await this.deps.durable.get(fundedTxKey(rec.id));
    if (!rawTx) return;
    const myHtlc = rec.myHTLC;
    if (!myHtlc || typeof myHtlc.redeemScript !== "string") return;
    if (chainConfigs[this.myChain]?.isEvm) return;
    const client = this.deps.chainClientFor(this.myChain);
    const redeemScript = hexToBytes(myHtlc.redeemScript.toLowerCase());
    let onChain = false;
    try {
      const hist = await client.getHistory(getHTLCScripthash(redeemScript), "a914" + bytesToHex(hash160(redeemScript)) + "87");
      onChain = Array.isArray(hist) && hist.some((h) => typeof h?.tx_hash === "string" && h.tx_hash.toLowerCase() === fundingTxid);
    } catch {
      return;
    }
    if (onChain) return;
    this.status("resume:rebroadcast-funding");
    try {
      await client.broadcastTx(rawTx);
    } catch {
    }
  }
  /**
   * §9.7 refund-reachability is not one-shot: if a refund was broadcast (durable refundtx + refundbroadcast sentinel)
   * but its txid is NOT in the HTLC history AND the funding output is STILL unspent, the refund DROPPED — resubmit the
   * EXACT durable refund tx (idempotent, same txid). Resume-driven (NOT the immediate post-broadcast poll, where a
   * 0-conf refund is indistinguishable from a dropped one). Fail-closed: a read error / an already-spent funding output
   * does NOT rebroadcast, and this NEVER wipes.
   */
  async rebroadcastRefundIfDropped() {
    const rec = this.record;
    if (!await this.deps.durable.get(refundBroadcastKey(rec.id))) return;
    const refund = await this.readDurableRefundTx(rec.id);
    if (!refund || !HEX64.test(refund.txid.toLowerCase())) return;
    const myHtlc = rec.myHTLC;
    if (!myHtlc || typeof myHtlc.redeemScript !== "string") return;
    if (chainConfigs[this.myChain]?.isEvm) return;
    const client = this.deps.chainClientFor(this.myChain);
    const redeemScript = hexToBytes(myHtlc.redeemScript.toLowerCase());
    const scriptHex = "a914" + bytesToHex(hash160(redeemScript)) + "87";
    const refundTxid = refund.txid.toLowerCase();
    try {
      const hist = await client.getHistory(getHTLCScripthash(redeemScript), scriptHex);
      if (Array.isArray(hist) && hist.some((h) => typeof h?.tx_hash === "string" && h.tx_hash.toLowerCase() === refundTxid)) return;
      const utxos = await client.getUTXOs(getHTLCScripthash(redeemScript), scriptHex);
      if (!Array.isArray(utxos) || utxos.length === 0) return;
    } catch {
      return;
    }
    this.status("resume:rebroadcast-dropped-refund");
    try {
      await client.broadcastTx(refund.rawTx);
    } catch {
    }
  }
  /** Step-5 deferred idempotent-adopt source: the PRIOR winning claim txid iff the `claimbroadcast` sentinel is set and
   *  a durable claim tx (or record.myClaimTxid) supplies a bare-hex txid; else null. */
  async priorClaimTxid(id) {
    if (!await this.deps.durable.get(claimBroadcastKey(id))) return null;
    const priorRaw = await this.deps.durable.get(claimTxKey(id));
    if (priorRaw) {
      try {
        const p = JSON.parse(priorRaw);
        if (p?.txid && HEX64.test(p.txid.toLowerCase())) return p.txid.toLowerCase();
      } catch {
      }
    }
    const mine = (this.record.myClaimTxid ?? "").toLowerCase();
    return HEX64.test(mine) ? mine : null;
  }
  /** Read + validate the durable refund tx cache (R280-H1). */
  async readDurableRefundTx(id) {
    try {
      const raw = await this.deps.durable.get(refundTxKey(id));
      if (!raw) return null;
      const r = JSON.parse(raw);
      if (typeof r.txid === "string" && HEX64.test(r.txid.toLowerCase()) && typeof r.rawTx === "string") {
        return { txid: r.txid, rawTx: r.rawTx, spent: r.spent };
      }
      return null;
    } catch {
      return null;
    }
  }
  /**
   * §9.6 reorg-safe depth check for a terminal tx (claim/refund) at `height` on `chain`. Requires BOTH a proxy depth
   * >= reqConf AND — on spvSupported mainnets — verifyConfirmations (SPV, provenTxid-bound) >= reqConf. FAIL CLOSED:
   * any unknown tip, SPV throw (pruned/short/tampered header/Merkle proof), or below-required depth returns false
   * (the caller KEEPS all recovery material). Regtest / non-SPV chains fall back to the proxy depth (test-only).
   */
  async spvReorgSafe(client, chain, txid, height, rawTx, reqConf) {
    let tip = NaN;
    try {
      const [h] = await client.getBlockHeight();
      tip = Number.isInteger(h) ? h : NaN;
    } catch {
      tip = NaN;
    }
    if (!Number.isFinite(tip)) return false;
    const depth = tip - height + 1;
    if (!(depth >= reqConf)) return false;
    if (!spvSupported(chain)) return true;
    let raw = rawTx;
    if (!raw) {
      try {
        raw = await client.getTx(txid);
      } catch {
        return false;
      }
    }
    try {
      return await verifyConfirmations(client, chain, txid, height, raw, tip) >= reqConf;
    } catch {
      return false;
    }
  }
  /** Fail-closed = keep material: refuse a NEW irreversible broadcast while a resume's myHTLC auth is not definitive (fix #10). */
  assertIrreversibleAllowed(label) {
    if (this.irreversibleBlocked) {
      throw new Error(`${label}: myHTLC on-chain authentication is not DEFINITIVE 'ok' (${this.resumeAuthValue ?? "unknown"}) \u2014 refusing an irreversible broadcast until re-authenticated (fix #10)`);
    }
  }
  /** Best-effort delete of a set of durable keys (§9.6 wipe — reached only at reorg-safe depth). */
  async wipeDurable(keys) {
    for (const k of keys) {
      try {
        await this.deps.durable.remove(k);
      } catch {
      }
    }
  }
  // ── helpers ──────────────────────────────────────────────────────────────────────────────────────────────
  /** leg X amount in sats (offer.sendAmount = the initiator's locked amount, base-unit sats < 2^53). Fail closed. */
  legXAmountSats() {
    return this.amountSats(this.record.offer.sendAmount, "fundLegX", "leg X");
  }
  /** leg Y amount in sats (offer.receiveAmount = the RESPONDER's locked amount on receiveChain). Fail closed. */
  legYAmountSats() {
    return this.amountSats(this.record.offer.receiveAmount, "fundLegY", "leg Y");
  }
  amountSats(raw, label, leg) {
    const n = typeof raw === "number" ? raw : Number(raw);
    if (!Number.isInteger(n) || !Number.isFinite(n) || n <= 0) {
      throw new Error(`${label}: invalid ${leg} amount '${String(raw)}' \u2014 refusing to build the funding tx`);
    }
    return n;
  }
  /** A minimal SwapState for createInitiatorHTLC/createResponderHTLC (they read only offer.{send,receive}Chain +
   *  secretHash). `role` selects which leg-chain the builder reads; the address fields are UI-only here. */
  buildSwapState(role = "initiator") {
    const secretHashHex = (this.record.offer.secretHash ?? "").toLowerCase().replace(/^0x/, "");
    return {
      offer: this.record.offer,
      role,
      secretHash: hexToBytes(secretHashHex),
      claimAddress: this.record.offer.initiatorReceiveAddress ?? "",
      refundAddress: this.record.offer.initiatorSendAddress ?? ""
    };
  }
  /** True iff `o` is a structurally-valid funding outpoint {tx_hash:64-hex, tx_pos:non-negative int}. */
  isOutpoint(o) {
    return !!o && typeof o.tx_hash === "string" && HEX64.test(o.tx_hash.toLowerCase()) && Number.isInteger(o.tx_pos) && o.tx_pos >= 0;
  }
  /**
   * Resolve the counterparty HTLC (redeemScript + locktime) and its recorded funding outpoint — the leg the
   * fund/reveal gates re-verify + the claim spends. Fail closed if the host has not recorded a valid HTLC/outpoint.
   */
  counterpartyLeg(label) {
    const c = this.record.counterpartyHTLC;
    if (!c || typeof c.redeemScript !== "string" || !/^[0-9a-f]+$/i.test(c.redeemScript) || !Number.isInteger(c.locktime)) {
      throw new Error(`${label}: no valid counterparty HTLC recorded \u2014 cannot verify / claim the counterparty leg`);
    }
    const outpoint = this.record.counterpartyFundingOutpoint;
    if (!this.isOutpoint(outpoint)) {
      throw new Error(`${label}: no valid counterparty funding outpoint recorded \u2014 cannot bind the gate / claim`);
    }
    return { redeemScript: hexToBytes(c.redeemScript.toLowerCase()), locktime: c.locktime, outpoint };
  }
  /**
   * Build a signed secret-bearing claim of the counterparty HTLC on `chain`, carrying the exact funding outpoint it
   * spends (`.spent` — load-bearing for the fix #8 triangulation + the pre-reveal double-spend re-check). Prefers the
   * `preferOutpoint` (the authorized one) when it is in the fresh UTXO set, else the largest valid output (mirrors
   * buildClaimTx ~7244/7690). Authenticates the chosen output's VALUE + P2SH scriptPubKey against its self-derived
   * raw tx before signing (never trusts the proxy listunspent value). Signs with the seed-derived key on `chain`
   * (whose hash160 is the HTLC recipient pkh) and sweeps to that same pkh. THROWS on no claimable/authenticatable UTXO.
   */
  async buildSecretClaim(chain, redeemScript, secret, preferOutpoint) {
    const client = this.deps.chainClientFor(chain);
    const scripthash = getHTLCScripthash(redeemScript);
    const scriptHex = "a914" + bytesToHex(hash160(redeemScript)) + "87";
    const raw = await client.getUTXOs(scripthash, scriptHex);
    const valid = raw.filter((u) => u && typeof u.tx_hash === "string" && Number.isInteger(u.tx_pos) && Number.isFinite(u.value) && u.value > 0);
    if (valid.length === 0) {
      throw new Error("buildSecretClaim: counterparty HTLC has no claimable UTXO (spent / not yet visible) \u2014 cannot build the claim");
    }
    let chosen = preferOutpoint ? valid.find((u) => u.tx_hash === preferOutpoint.tx_hash && u.tx_pos === preferOutpoint.tx_pos) : void 0;
    if (!chosen) chosen = [...valid].sort((a, b) => b.value - a.value)[0];
    const authed = await verifyAndAuthenticateUtxo(
      { tx_hash: chosen.tx_hash, tx_pos: chosen.tx_pos, value: chosen.value, height: chosen.height },
      redeemScript,
      (txid) => client.getTx(txid)
    );
    if (!(authed.value > 0)) {
      throw new Error("buildSecretClaim: counterparty HTLC funding output failed re-authentication \u2014 not signing the claim");
    }
    const sk = await this.deps.seedVault.signingKey(chain);
    const destPkh = hash160(sk.publicKey);
    const tx = await claimHTLC(authed, redeemScript, secret, sk.privateKey, sk.publicKey, destPkh, chain);
    return { txid: tx.txid, rawTx: tx.rawTx, spent: { tx_hash: chosen.tx_hash, tx_pos: chosen.tx_pos } };
  }
  /**
   * Greedy FIFO UTXO selection — ported from prepareFundingTx (~5431-5457): oldest-confirmed-first (immature
   * coinbase is newest, so it is spent last), tie-break by value desc, accumulate until amount + estimated fee is
   * covered, then decide the change-output count AFTER fee. Returns the selected inputs or null (insufficient).
   * Uses the chain's static config fee rate (a LIVE deadline-scaled rate is a separate seam; step 4 keeps it simple).
   */
  greedySelect(candidates, amountSats) {
    const cfg = chainConfigs[this.myChain];
    const feePerByte = Number.isFinite(cfg.feePerByte) && (cfg.feePerByte ?? 0) > 0 ? cfg.feePerByte : 1;
    const rawDust = cfg.dustThreshold ?? 546;
    const dust = Number.isFinite(rawDust) && rawDust >= 0 ? rawDust : 546;
    const fifo = (a, b) => (a.height > 0 ? a.height : Infinity) - (b.height > 0 ? b.height : Infinity) || b.value - a.value;
    const selected = [];
    let total = 0;
    for (const u of [...candidates].sort(fifo)) {
      selected.push(u);
      total += u.value;
      const numOutputs = total - amountSats > dust ? 2 : 1;
      const estFee = (selected.length * 148 + numOutputs * 34 + 10) * feePerByte;
      if (total >= amountSats + estFee) break;
    }
    const fee2 = (selected.length * 148 + 2 * 34 + 10) * feePerByte;
    const fee1 = (selected.length * 148 + 1 * 34 + 10) * feePerByte;
    const finalOutputs = total - amountSats - fee2 > dust ? 2 : 1;
    const needed = amountSats + (finalOutputs === 2 ? fee2 : fee1);
    if (selected.length === 0 || total < needed) return null;
    return selected;
  }
  /** Read + validate the durable funded-HTLC side-channel (R170) for the adopt path. */
  async readDurableFundedHtlc(id) {
    try {
      const raw = await this.deps.durable.get(fundedHtlcKey(id));
      if (!raw) return null;
      const r = JSON.parse(raw);
      if (typeof r.redeemScript !== "string" || typeof r.p2shAddress !== "string" || typeof r.secretHash !== "string" || typeof r.recipientPkh !== "string" || typeof r.refundPkh !== "string" || !Number.isInteger(r.locktime)) {
        return null;
      }
      return r;
    } catch {
      return null;
    }
  }
  // ============================================================================================================
  // EVM PARITY (P1b step 7) — the EVM fund-critical half: the EVM reveal + the refund-race secret recovery.
  //
  // The two GATE minters (assertEvmLegBuriedForFunding quorum>=2 -> FundProof; assertEvmRevealSafe quorum>=2 ->
  // RevealAuthorization) already exist + are verified in gates.ts; these methods drive them over the injected
  // quorum>=2 `evmProviderFor` provider and the injected `evmSignerFor` Node ethers.Wallet, and call the proven
  // on-chain handlers (lockETH/lockTokens/claimSwap/refundSwap) from evm-client.ts. Same three corrections as the
  // UTXO half: fix #2 (RE-MINT the gate FRESH at the broadcast choke point — never trust the passed proof's
  // captured values), fix #4 (durable-before-broadcast), fix #10 (assertIrreversibleAllowed on every irreversible
  // broadcast). PLUS fix #7 (the refund-race Claimed-event recovery corroborated across quorum>=2 leaves).
  // ============================================================================================================
  // ── EVM seams + small resolvers ──────────────────────────────────────────────────────────────────────────
  /** The injected quorum>=2 EVM read Provider for `chain` (the EVM GATE surface). Fail closed if not injected. */
  evmProvider(chain) {
    if (!this.deps.evmProviderFor) throw new Error("EVM provider factory (evmProviderFor) is not injected \u2014 cannot run the EVM leg");
    return this.deps.evmProviderFor(chain);
  }
  /** The injected EVM Signer (a Node ethers.Wallet from the seed) for `chain`. Fail closed if not injected. */
  evmSigner(chain) {
    if (!this.deps.evmSignerFor) throw new Error("EVM signer factory (evmSignerFor) is not injected \u2014 cannot sign the EVM leg");
    return this.deps.evmSignerFor(chain);
  }
  /** Resolve `chain` -> its numeric EvmChainId + the canonical EVM config (htlcAddress, requiredConfirmations, lock
   *  bounds). Fail closed if `chain` is not an EVM chain or has no deployed config. */
  evmCfgFor(chain) {
    const cc = chainConfigs[chain];
    if (!cc || !cc.isEvm || !Number.isInteger(cc.evmChainId)) {
      throw new Error(`EVM leg: chain '${chain}' is not an EVM chain \u2014 cannot run the EVM path`);
    }
    const evmChainId = cc.evmChainId;
    const cfg = getEvmConfig(evmChainId);
    if (!cfg) throw new Error(`EVM leg: no EVM config for chain '${chain}' (chainId ${evmChainId})`);
    const htlcAddr = cfg.htlcAddress;
    if (!/^0x[0-9a-fA-F]{40}$/.test(htlcAddr) || htlcAddr.toLowerCase() === NATIVE_ETH_ADDR) {
      throw new Error(`EVM leg: no deployed HTLC contract for chain '${chain}' (chainId ${evmChainId})`);
    }
    return { evmChainId, cfg, htlcAddr };
  }
  /** FIX #10 §5(#10): carry EVM amounts as base-unit strings — never `Number()` an 18-dec (wei) value. Accept a
   *  decimal-integer base-unit string (canonical) or a legacy safe-integer number; throw on anything else. */
  evmAmountBaseUnits(raw, label) {
    if (typeof raw === "number") {
      if (!Number.isSafeInteger(raw) || raw <= 0) throw new Error(`${label}: invalid EVM amount '${String(raw)}'`);
      return BigInt(raw);
    }
    const s = (raw ?? "").trim();
    if (!/^[0-9]+$/.test(s)) {
      throw new Error(`${label}: EVM amount '${String(raw)}' is not an integer base-unit string \u2014 refusing (fix #10: never Number() an 18-dec value)`);
    }
    const b = BigInt(s);
    if (b <= 0n) throw new Error(`${label}: EVM amount must be > 0 (got ${s})`);
    return b;
  }
  /** The offer secretHash as a 0x-prefixed bytes32 (the on-chain hashLock). Fail closed if malformed. */
  hashLock0x(label) {
    const h = (this.record.offer.secretHash ?? "").toLowerCase().replace(/^0x/, "");
    if (!HEX64.test(h)) throw new Error(`${label}: offer.secretHash is not a 32-byte hex hash \u2014 cannot bind the EVM hashLock`);
    return "0x" + h;
  }
  /** Resolve the COUNTERPARTY EVM leg (the leg WE verify/claim on theirChain): htlc addr, swapId, requiredConfirmations,
   *  hashLock, the recipient (= OUR EVM address, who may claim it), minAmount (what we receive), and its token. */
  counterpartyEvmLeg(label) {
    const { evmChainId, cfg, htlcAddr } = this.evmCfgFor(this.theirChain);
    const swapId = (this.record.counterpartyEvmSwapId ?? "").toLowerCase();
    if (!BYTES32_0X.test(swapId)) throw new Error(`${label}: no valid counterparty EVM swapId recorded \u2014 cannot verify/claim the EVM leg`);
    const recipient = this.record.myEvmAddress ?? "";
    if (!ethers.isAddress(recipient)) throw new Error(`${label}: our EVM address (myEvmAddress) is missing/invalid \u2014 cannot bind the claim recipient`);
    const token = this.record.counterpartyEvmToken ?? this.record.offer.evmInfo?.tokenAddress ?? "";
    if (!ethers.isAddress(token)) throw new Error(`${label}: counterparty EVM token address is missing/invalid \u2014 cannot bind the token`);
    const rawAmt = this.role === "initiator" ? this.record.offer.receiveAmount : this.record.offer.sendAmount;
    const minAmount = this.evmAmountBaseUnits(rawAmt, label);
    return {
      evmChainId,
      htlcAddr,
      requiredConfirmations: Math.max(1, cfg.requiredConfirmations),
      swapId,
      hashLock: this.hashLock0x(label),
      recipient,
      minAmount,
      token
    };
  }
  // ── (1) verifyEvmCounterpartyLegForFunding -> FundProof (responder-only) ──────────────────────────────────
  /**
   * RESPONDER-ONLY. Mint a `FundProof` by proving the counterparty (initiator) EVM leg is locked at a reorg-safe
   * depth with all invariants bound (gates.assertEvmLegBuriedForFunding over the injected quorum>=2 provider). The
   * ONLY controller-side minter of an EVM `FundProof`. Grounds in verifyEvmCounterpartyHTLC (SwapExecute.tsx
   * ~3055-3460): the responder-fund gate re-asserts DEPTH + {hashLock, recipient, minAmount, minTimeLock, token} and
   * fails closed (quorum>=2) before the responder commits its own leg. Returns the branded proof or THROWS
   * (mints nothing) — including refusing a single-leaf provider (fix #7/#1, done inside the gate).
   */
  async verifyEvmCounterpartyLegForFunding() {
    this.assertLive();
    if (this.record.role !== "responder") {
      throw new Error("verifyEvmCounterpartyLegForFunding: responder-only (the initiator does not fund against a FundProof)");
    }
    const leg = this.counterpartyEvmLeg("verifyEvmCounterpartyLegForFunding");
    const provider = this.evmProvider(this.theirChain);
    return assertEvmLegBuriedForFunding(provider, {
      chain: this.theirChain,
      htlcAddr: leg.htlcAddr,
      swapId: leg.swapId,
      requiredConfirmations: leg.requiredConfirmations,
      hashLock: leg.hashLock,
      recipient: leg.recipient,
      minAmount: leg.minAmount,
      token: leg.token
    });
  }
  // ── (2) verifyEvmCounterpartyLegForReveal -> RevealAuthorization (initiator-only) ─────────────────────────
  /**
   * INITIATOR-ONLY. Mint a `RevealAuthorization` by proving the counterparty (responder) EVM leg is at a reorg-safe
   * depth AND keeps >= 4h (EVM_CLAIM_MARGIN_SEC) runway on its FRESH on-chain timeLock (gates.assertEvmRevealSafe,
   * quorum>=2). The ONLY controller-side minter of an EVM `RevealAuthorization`. Grounds in handleEvmClaim gate #2 +
   * the R258/R260/R261/R278 margin re-check (SwapExecute.tsx ~2128-2258). Returns the branded auth or THROWS — the
   * secret NEVER leaks on any failure (this only READS the chain; it does not touch the secret).
   */
  async verifyEvmCounterpartyLegForReveal() {
    this.assertLive();
    if (this.record.role !== "initiator") {
      throw new Error("verifyEvmCounterpartyLegForReveal: initiator-only (only the initiator makes the irreversible secret reveal)");
    }
    const leg = this.counterpartyEvmLeg("verifyEvmCounterpartyLegForReveal");
    const provider = this.evmProvider(this.theirChain);
    return assertEvmRevealSafe(provider, {
      chain: this.theirChain,
      htlcAddr: leg.htlcAddr,
      swapId: leg.swapId,
      requiredConfirmations: leg.requiredConfirmations,
      hashLock: leg.hashLock,
      recipient: leg.recipient,
      minAmount: leg.minAmount,
      token: leg.token
    });
  }
  /** FIX #2 re-mint used by lockEvm at the broadcast choke point: re-prove the counterparty leg is buried FRESH. Uses
   *  the EVM gate when the counterparty leg is EVM, else the UTXO gate — either throws (aborting the lock) on any doubt. */
  async reverifyCounterpartyLegForFunding() {
    const theirIsEvm = !!chainConfigs[this.theirChain]?.isEvm;
    if (theirIsEvm) {
      await this.verifyEvmCounterpartyLegForFunding();
    } else {
      await this.verifyCounterpartyLegForFunding();
    }
  }
  // ── (3) lockEvm(proof) — lock OUR OWN EVM leg (responder/initiator) ───────────────────────────────────────
  /**
   * Lock OUR OWN EVM leg (lockETH or lockTokens per isNativeToken) with the injected Node signer. STRUCTURALLY
   * requires a `FundProof` (compile-time — the two brands are non-interchangeable, fix #1). Grounds in handleEvmFund
   * (SwapExecute.tsx ~1089-1360).
   *   FIX #2 (zero proof-reuse window): inside the fund mutex, at the choke point, RE-MINT the counterparty-leg burial
   *     FRESH (assertEvmLegBuriedForFunding) — never the passed proof's captured values. A fresh throw ABORTS before
   *     any lock tx is broadcast.
   *   FIX #4 (durable-before-broadcast): the lockpending + evmlocktx recovery markers are committed durably in the
   *     lock's onBroadcast callback — the instant the tx is broadcast (before it mines) — because the EVM lock is
   *     irreversible once mined; the funded=swapId sentinel is committed the moment the lock resolves with its id.
   *   FIX #10: gated by assertIrreversibleAllowed. Single-flight (fix #3) under mutex.withLock; a prior funded swapId
   *     is ADOPTED rather than re-locked (a second on-chain lock would strand a fresh per-nonce swapId). Handles the
   *     onBroadcast-replacement hash (a MetaMask speed-up; a Node signer typically won't) by capturing the final hash.
   */
  async lockEvm(proof) {
    this.assertLive();
    const rec = this.record;
    if (proof.leg !== "X" || proof.for !== "fundY") {
      throw new Error("lockEvm: the supplied FundProof is not a leg-X fund authorization \u2014 refusing to lock");
    }
    this.assertIrreversibleAllowed("lockEvm");
    if (rec.phase !== "taken" && rec.phase !== "prepared") {
      throw new Error(`lockEvm: unexpected phase '${rec.phase}' \u2014 the EVM lock runs from 'taken' or 'prepared'`);
    }
    if (isSwapPairSuspended(this.myChain, this.theirChain)) {
      throw new Error(`lockEvm: swap pair ${this.myChain}/${this.theirChain} is suspended \u2014 refusing to lock`);
    }
    const { evmChainId, cfg, htlcAddr } = this.evmCfgFor(this.myChain);
    const recipient = rec.counterpartyEvmAddress ?? "";
    if (!ethers.isAddress(recipient)) throw new Error("lockEvm: counterparty EVM recipient address (counterpartyEvmAddress) is missing/invalid \u2014 cannot lock");
    const token = rec.myEvmToken ?? rec.offer.evmInfo?.tokenAddress ?? "";
    if (!ethers.isAddress(token)) throw new Error("lockEvm: our EVM token address is missing/invalid \u2014 cannot lock");
    const amount = this.evmAmountBaseUnits(this.role === "initiator" ? rec.offer.sendAmount : rec.offer.receiveAmount, "lockEvm");
    const hashLock = this.hashLock0x("lockEvm");
    const signer = this.evmSigner(this.myChain);
    const targetPhase = this.role === "initiator" ? "initiator_funded" : "responder_funded";
    const lockName = `bch2swap:fund:${rec.id}`;
    const outcome = await this.deps.mutex.withLock(lockName, async () => {
      const prior = (await this.deps.durable.get(fundedKey(rec.id)))?.toLowerCase();
      if (prior && BYTES32_0X.test(prior)) return { swapId: prior, txHash: "", adopted: true };
      const pendingMarker = await this.deps.durable.get(lockPendingKey(rec.id));
      if (pendingMarker) {
        const markedHash = await this.deps.durable.get(evmLockTxKey(rec.id));
        const lockTxHash = markedHash && BYTES32_0X.test(markedHash.toLowerCase()) ? markedHash.toLowerCase() : BYTES32_0X.test(pendingMarker.toLowerCase()) ? pendingMarker.toLowerCase() : null;
        if (!lockTxHash) {
          throw new Error("lockEvm: a prior EVM lock is in-flight (pending marker set, tx hash not yet recorded) \u2014 refusing to re-lock (would risk a double-lock); retry once it resolves (fix #4)");
        }
        const readProvider = this.evmProvider(this.myChain);
        let sender = "";
        try {
          sender = await signer.getAddress();
        } catch {
          sender = "";
        }
        let recovery;
        try {
          recovery = await recoverLockFromTx(htlcAddr, lockTxHash, readProvider, {
            sender,
            hashLock,
            recipient,
            minAmount: amount,
            fromBlock: rec.evmLockBlock
          });
        } catch {
          recovery = { kind: "blocked" };
        }
        if (recovery.kind === "locked") {
          await this.deps.durable.commit([[fundedKey(rec.id), recovery.swapId.toLowerCase()]]);
          await this.deps.durable.remove(lockPendingKey(rec.id));
          return { swapId: recovery.swapId, txHash: lockTxHash, adopted: true };
        }
        if (recovery.kind === "blocked") {
          throw new Error("lockEvm: a prior EVM lock tx is still pending / its disposition is indeterminate \u2014 refusing to re-lock (would risk a double-lock + strand); retry once it resolves (fix #4)");
        }
      }
      this.status("lockEvm:reverifying-counterparty");
      await this.reverifyCounterpartyLegForFunding();
      let nowSec = null;
      try {
        const b = await signer.provider?.getBlock("latest");
        if (b && Number.isFinite(b.timestamp)) nowSec = Number(b.timestamp);
      } catch {
        nowSec = null;
      }
      if (nowSec === null) throw new Error("lockEvm: could not read the EVM chain clock to set the lock timeLock \u2014 not locking; retry");
      const timeLock = BigInt(nowSec + evmLockSecondsForRole(cfg, this.role));
      this.status("lockEvm:committing-recovery-marker");
      await this.deps.durable.commit([[lockPendingKey(rec.id), LOCK_PENDING_SENTINEL]]);
      let finalHash = "";
      let onBroadcastCommit = null;
      const onBroadcast = (h) => {
        finalHash = h;
        onBroadcastCommit = this.deps.durable.commit([[lockPendingKey(rec.id), h], [evmLockTxKey(rec.id), h]]);
      };
      this.status("lockEvm:broadcasting");
      const swapId = isNativeToken(token) ? await lockETH(htlcAddr, recipient, amount, hashLock, timeLock, signer, evmChainId, onBroadcast) : await lockTokens(htlcAddr, recipient, token, amount, hashLock, timeLock, signer, evmChainId, onBroadcast);
      if (onBroadcastCommit) {
        try {
          await onBroadcastCommit;
        } catch {
        }
      }
      await this.deps.durable.commit([[fundedKey(rec.id), swapId.toLowerCase()]]);
      await this.deps.durable.remove(lockPendingKey(rec.id));
      return { swapId, txHash: finalHash, adopted: false };
    });
    this.record = { ...this.record, myEvmSwapId: outcome.swapId, myFundingTxid: outcome.swapId, funded: true };
    this.setPhase(targetPhase);
    this.status("lockEvm:locked");
    await this.persistRecord();
    return { swapId: outcome.swapId, txHash: outcome.txHash };
  }
  // ── (4) revealAndClaimEvm(auth) — the INITIATOR reveals S by claiming the counterparty EVM leg ────────────
  /**
   * The initiator's ONE irreversible EVM action: reveal S by claiming the counterparty (responder) EVM leg with S in
   * the claim calldata (evmClaimSwap = claimSwap). STRUCTURALLY requires a `RevealAuthorization` (compile-time).
   * Grounds in handleEvmClaim (SwapExecute.tsx ~2128-2430).
   *   FIX #3: throw unless `auth.role === 'initiator'` — a margin-skipped responder authorization must NEVER drive the
   *     initiator's reveal.
   *   FIX #2: inside the claim mutex at the broadcast choke point, RE-MINT assertEvmRevealSafe FRESH (quorum>=2 depth +
   *     the 4h margin re-derived from the FRESH on-chain timeLock) — never the passed auth's captured values. A throw
   *     ABORTS; S is never sent. (claimSwap itself also re-checks sha256(S)===hashLock + expiry + recipient before it
   *     broadcasts, so S never reaches calldata on a bad claim — defense in depth.)
   *   FIX #4: a durable `claimbroadcast` sentinel is committed BEFORE the secret-revealing claim; a second call /
   *     crash-resume ADOPTS instead of re-revealing. FIX #10: gated by assertIrreversibleAllowed. R181 cross-guard:
   *     refuses to reveal while a refund is in flight. Transitions `responder_funded -> claimed`.
   */
  async revealAndClaimEvm(auth) {
    this.assertLive();
    const rec = this.record;
    if (rec.role !== "initiator") {
      throw new Error("revealAndClaimEvm: only the initiator reveals the secret (the responder uses watchForClaimEvm/claimWithKnownSecret)");
    }
    if (auth.role !== "initiator" || auth.leg !== "Y" || auth.for !== "reveal") {
      throw new Error("revealAndClaimEvm: the supplied authorization is not an initiator leg-Y reveal authorization \u2014 refusing to reveal the secret (fix #3)");
    }
    if (await this.deps.durable.get(claimBroadcastKey(rec.id))) {
      this.status("revealAndClaimEvm:adopted");
      return { txHash: rec.myClaimTxid ?? "" };
    }
    this.assertIrreversibleAllowed("revealAndClaimEvm");
    if (await this.deps.durable.get(refundBroadcastKey(rec.id))) {
      throw new Error("revealAndClaimEvm: a refund is already in flight \u2014 refusing to reveal the secret (R181 cross-guard)");
    }
    if (rec.phase !== "responder_funded" && rec.phase !== "claimed") {
      throw new Error(`revealAndClaimEvm: unexpected phase '${rec.phase}' \u2014 reveal runs from 'responder_funded'`);
    }
    const leg = this.counterpartyEvmLeg("revealAndClaimEvm");
    const secret = await this.loadInitiatorSecret();
    if (!secret || secret.length !== 32) {
      throw new Error("revealAndClaimEvm: the swap secret is not available (vault locked / not re-derivable) \u2014 cannot reveal");
    }
    const provider = this.evmProvider(this.theirChain);
    const signer = this.evmSigner(this.theirChain);
    const lockName = `bch2swap:claim:${rec.id}`;
    const result = await this.deps.mutex.withLock(lockName, async () => {
      if (await this.deps.durable.get(claimBroadcastKey(rec.id))) return { swapId: leg.swapId };
      if (await this.deps.durable.get(refundBroadcastKey(rec.id))) {
        throw new Error("revealAndClaimEvm: a refund became active \u2014 refusing to reveal the secret");
      }
      this.status("revealAndClaimEvm:reverifying");
      await assertEvmRevealSafe(provider, {
        chain: this.theirChain,
        htlcAddr: leg.htlcAddr,
        swapId: leg.swapId,
        requiredConfirmations: leg.requiredConfirmations,
        hashLock: leg.hashLock,
        recipient: leg.recipient,
        minAmount: leg.minAmount,
        token: leg.token
      });
      this.status("revealAndClaimEvm:committing");
      await this.deps.durable.commit([[claimBroadcastKey(rec.id), "1"]]);
      this.status("revealAndClaimEvm:broadcasting");
      await this.claimEvmWithSentinelGuard(leg.htlcAddr, leg.swapId, secret.slice(), signer, leg.evmChainId);
      return { swapId: leg.swapId };
    });
    this.record = { ...this.record, myClaimTxid: result.swapId };
    this.setPhase("claimed");
    this.status("revealAndClaimEvm:claimed");
    await this.persistRecord();
    return { txHash: result.swapId };
  }
  // ── (5) refundEvm() — refund OUR OWN EVM lock, with the refund-race secret-recovery pivot (fix #7) ─────────
  /**
   * Refund OUR OWN EVM lock (evmRefundSwap = refundSwap) after its timelock. §9.7: reachable after expiry (suspension
   * never gates a refund). A durable `refundbroadcast` sentinel is committed BEFORE the send (durable-before-broadcast)
   * under the shared claim/refund single-flight lock, so a claim and a refund can never race.
   *
   * THE REFUND-RACE PIVOT (fund-loss-critical, fix #7): if refundSwap REVERTS because the counterparty ALREADY CLAIMED
   * our lock (took it with S), we do NOT treat that as a plain error. S is now PUBLIC in the on-chain `Claimed` event,
   * so we RECOVER it — corroborated across quorum>=2 leaves (never conclude "safe to abandon" while an honest leaf may
   * still yield S), verify sha256(S)===hashLock (the authenticator), and use S to CLAIM the OTHER (counterparty) leg so
   * we are made whole. Grounds in the 'already claimed' branch (SwapExecute.tsx:2423) + watchForClaim/watchAndRefund.
   */
  async refundEvm() {
    this.assertLive();
    const rec = this.record;
    const { evmChainId, htlcAddr } = this.evmCfgFor(this.myChain);
    const swapId = (rec.myEvmSwapId ?? "").toLowerCase();
    if (!BYTES32_0X.test(swapId)) throw new Error("refundEvm: no valid own EVM swapId (myEvmSwapId) recorded \u2014 nothing to refund");
    this.assertIrreversibleAllowed("refundEvm");
    if (await this.deps.durable.get(refundRacePendingKey(rec.id))) {
      this.status("refundEvm:refund-race-pending");
      return await this.recoverFromRefundRace(htlcAddr, swapId);
    }
    if (await this.deps.durable.get(claimBroadcastKey(rec.id))) {
      throw new Error("refundEvm: a claim is already in flight \u2014 refusing to refund while a claim is active (R181 cross-guard)");
    }
    const signer = this.evmSigner(this.myChain);
    const lockName = `bch2swap:claim:${rec.id}`;
    let outcome;
    try {
      outcome = await this.deps.mutex.withLock(lockName, async () => {
        if (await this.deps.durable.get(refundBroadcastKey(rec.id))) {
          return { refunded: await this.evmSwapIsRefunded(signer.provider, htlcAddr, swapId) };
        }
        if (await this.deps.durable.get(claimBroadcastKey(rec.id))) {
          throw new Error("refundEvm: a claim became active \u2014 refusing to refund");
        }
        this.status("refundEvm:committing");
        await this.deps.durable.commit([[refundBroadcastKey(rec.id), "1"]]);
        this.status("refundEvm:broadcasting");
        await refundSwap(htlcAddr, swapId, signer);
        return { refunded: true };
      });
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      if (/already claimed|was claimed|claimed before refund|secret is on-chain/i.test(msg)) {
        return await this.recoverFromRefundRace(htlcAddr, swapId);
      }
      const isPreBroadcast = !!e?.preBroadcast;
      if (isPreBroadcast || /not found|not the HTLC initiator|already refunded|Timelock has not expired|timelock may not have expired|dropped from mempool|not a plausible unix|timeLock is zero|could not read latest block/i.test(msg)) {
        try {
          await this.deps.durable.remove(refundBroadcastKey(rec.id));
        } catch {
        }
      }
      throw e;
    }
    if (outcome.refunded) {
      this.setPhase("refunded");
      this.status("refundEvm:broadcast");
    } else {
      this.status("refundEvm:refund-pending");
    }
    await this.persistRecord();
    return { txHash: swapId };
  }
  /** Best-effort on-chain check used by refundEvm's adopt path (fix #4): is OUR own EVM swap actually REFUNDED? Reads
   *  getSwap over the given provider and returns `!!swap.refunded`; fail-closed to `false` on any read error / missing
   *  provider (a not-yet-confirmed / dropped refund must never be finalized as a completed 'refunded'). */
  async evmSwapIsRefunded(provider, htlcAddr, swapId) {
    if (!provider) return false;
    try {
      const sw = await getSwap(htlcAddr, swapId, provider);
      return !!sw?.refunded;
    } catch {
      return false;
    }
  }
  /** Broadcast a UTXO claim, clearing the durable claimbroadcast sentinel ONLY on a DEFINITIVE pre-broadcast node
   *  rejection (the node validated + refused the tx — it never entered any mempool, so the secret is not public and a
   *  retry can rebuild + re-broadcast), so a later call re-arms instead of ADOPTING a never-broadcast claim (fix #3).
   *  An AMBIGUOUS / timeout / post-broadcast failure (the tx MAY have reached a mempool) LEAVES the sentinel set
   *  (R201 fail-safe). The UTXO analogue of claimEvmWithSentinelGuard — same definitive-vs-ambiguous classification. */
  async broadcastClaimWithSentinelGuard(client, rawTx, id) {
    try {
      await client.broadcastTx(rawTx);
    } catch (e) {
      if (isDefinitiveBroadcastRejection(e)) {
        try {
          await this.deps.durable.remove(claimBroadcastKey(id));
        } catch {
        }
      }
      throw e;
    }
  }
  /** Broadcast an EVM claim, clearing the durable claimbroadcast sentinel ONLY on a PRE-broadcast throw (claimSwap tags
   *  pre-flight failures `preBroadcast:true` — no secret revealed), so a later call re-arms instead of adopting a
   *  never-broadcast claim (fix #3). A POST-broadcast / ambiguous failure LEAVES the sentinel set (R201 fail-safe). */
  async claimEvmWithSentinelGuard(htlcAddr, swapId, secret, signer, chainId) {
    try {
      await claimSwap(htlcAddr, swapId, secret, signer, chainId);
    } catch (e) {
      if (e?.preBroadcast === true) {
        try {
          await this.deps.durable.remove(claimBroadcastKey(this.record.id));
        } catch {
        }
      }
      throw e;
    }
  }
  /**
   * THE REFUND-RACE PIVOT body (fix #7). Recover S from OUR OWN EVM lock's on-chain `Claimed` event, corroborated
   * across quorum>=2 leaves, verify sha256(S)===hashLock, then claim the OTHER (counterparty) leg with the now-public
   * S so we are made whole. If S is not YET extractable (a lagging/pruned leaf), we KEEP the refund sentinel and throw
   * a RETRYABLE error — never conclude "safe to abandon" while S may still be extractable from an honest leaf.
   */
  async recoverFromRefundRace(myHtlcAddr, mySwapId) {
    const rec = this.record;
    const hashLockHex = (rec.offer.secretHash ?? "").toLowerCase().replace(/^0x/, "");
    const provider = this.evmProvider(this.myChain);
    this.status("refundEvm:recovering-secret");
    const recovered = await this.readEvmClaimedSecret(provider, myHtlcAddr, mySwapId, hashLockHex);
    if (!recovered) {
      try {
        await this.deps.durable.set(refundRacePendingKey(rec.id), "1");
      } catch {
      }
      throw new Error("refundEvm: our EVM lock was already claimed but S is not yet corroborated from the on-chain Claimed event (quorum>=2) \u2014 retry; never abandon while S may still be recoverable from an honest leaf (fix #7)");
    }
    if (bytesToHex(sha256(recovered)) !== hashLockHex) {
      recovered.fill(0);
      throw new Error("refundEvm: recovered preimage does not hash to the swap secretHash \u2014 fail closed");
    }
    if (this.secret) this.secret.fill(0);
    this.secret = recovered;
    try {
      await this.deps.durable.remove(refundBroadcastKey(rec.id));
    } catch {
    }
    this.status("refundEvm:claiming-other-leg");
    const theirIsEvm = !!chainConfigs[this.theirChain]?.isEvm;
    const result = theirIsEvm ? await this.claimEvmCounterpartyWithPublicSecret() : { txHash: (await this.claimWithKnownSecret()).txid };
    try {
      await this.deps.durable.remove(refundRacePendingKey(rec.id));
    } catch {
    }
    return result;
  }
  /** Claim the COUNTERPARTY EVM leg with the now-PUBLIC secret (the refund-race pivot's EVM<->EVM branch). No reveal
   *  margin gate (the secret is already public — no double-dip race), but the durable claimbroadcast sentinel + the
   *  single-flight lock still apply. Uses claimSwap (which re-checks sha256(S)===hashLock + recipient on-chain). */
  async claimEvmCounterpartyWithPublicSecret() {
    const rec = this.record;
    const secret = this.secret;
    if (!secret || secret.length !== 32) throw new Error("claimEvmCounterpartyWithPublicSecret: the public secret is not available");
    const leg = this.counterpartyEvmLeg("claimEvmCounterpartyWithPublicSecret");
    const signer = this.evmSigner(this.theirChain);
    const lockName = `bch2swap:claim:${rec.id}`;
    const result = await this.deps.mutex.withLock(lockName, async () => {
      if (await this.deps.durable.get(claimBroadcastKey(rec.id))) return { swapId: leg.swapId };
      await this.deps.durable.commit([[claimBroadcastKey(rec.id), "1"]]);
      await this.claimEvmWithSentinelGuard(leg.htlcAddr, leg.swapId, secret.slice(), signer, leg.evmChainId);
      return { swapId: leg.swapId };
    });
    this.record = { ...this.record, myClaimTxid: result.swapId };
    this.setPhase("completed");
    this.status("refundEvm:made-whole");
    await this.persistRecord();
    return { txHash: result.swapId };
  }
  // ── (6) watchForClaimEvm() — the RESPONDER watches its OWN EVM lock for the initiator's claim ──────────────
  /**
   * RESPONDER-ONLY. Watch OUR OWN EVM lock (myEvmSwapId) for the initiator's `Claimed` event, EXTRACT + VERIFY S
   * (sha256(S)===hashLock — the authenticator, so a quorum>=1 hash-verified liveness read is acceptable here per
   * R-POLYHIST), and SAVE it. Grounds in handleEvmFund's responder watch (watchForClaim, SwapExecute.tsx ~1250-1310).
   * A single scheduler-driven scan: NEVER throws on absence (returns `{secret:null}`); a forged/mismatched preimage is
   * REJECTED (the hash check). On discovery, transitions `responder_funded -> claimed`.
   */
  async watchForClaimEvm() {
    this.assertLive();
    const rec = this.record;
    if (rec.role !== "responder") {
      throw new Error("watchForClaimEvm: responder-only (the initiator holds S from prepare())");
    }
    const swapId = (rec.myEvmSwapId ?? "").toLowerCase();
    if (!BYTES32_0X.test(swapId)) return { secret: null };
    const hashLockHex = (rec.offer.secretHash ?? "").toLowerCase().replace(/^0x/, "");
    if (!HEX64.test(hashLockHex)) return { secret: null };
    let htlcAddr;
    let provider;
    try {
      htlcAddr = this.evmCfgFor(this.myChain).htlcAddr;
      provider = this.evmProvider(this.myChain);
    } catch {
      return { secret: null };
    }
    let secret;
    try {
      secret = await this.readEvmClaimedSecret(provider, htlcAddr, swapId, hashLockHex);
    } catch {
      return { secret: null };
    }
    if (!secret) return { secret: null };
    if (this.secret) this.secret.fill(0);
    this.secret = secret;
    if (rec.phase === "responder_funded") this.setPhase("claimed");
    this.status("watchForClaimEvm:secret-found");
    await this.persistRecord();
    return { secret };
  }
  /**
   * Read + hash-VERIFY the preimage S from a `Claimed` event on the given EVM swapId, corroborated across the
   * provider's quorum leaves. Returns the FIRST S from ANY leaf whose sha256 equals `hashLockHex` (the authenticator —
   * so a single honest leaf is sufficient to TRUST the value), else null. The hash check makes a forged/foreign
   * Claimed log unusable (fund-safe), and reading every leaf means a lagging/pruned leaf never falsely hides an S that
   * an honest leaf still holds (the fix #7 "never abandon while S may be extractable" property). Never throws on a
   * per-leaf read error (a leaf that errors just doesn't contribute an S).
   */
  async readEvmClaimedSecret(provider, htlcAddr, swapId, hashLockHex) {
    const leaves = evmLeaves2(provider);
    const claimedFrag = HTLC_IFACE.getEvent("Claimed");
    if (!claimedFrag) return null;
    const topic0 = claimedFrag.topicHash;
    const idTopic = ethers.zeroPadValue(swapId, 32);
    const lockBlock = Number.isInteger(this.record.evmLockBlock) ? this.record.evmLockBlock : 0;
    for (const leaf of leaves) {
      const found = await this.scanLeafForClaimedSecret(leaf, htlcAddr, topic0, idTopic, swapId, hashLockHex, lockBlock);
      if (found) return found;
    }
    return null;
  }
  static {
    /**
     * FIX #1 (fund-loss): scan ONE leaf for the hash-verified Claimed preimage with a BOUNDED, WINDOWED getLogs — the
     * SDK's proven watchForClaim windowing (evm-client.ts ~L1486) ported into a single, non-blocking sweep. The old code
     * issued one UNBOUNDED `getLogs({fromBlock: evmLockBlock, toBlock:'latest'})`; a real public RPC rejects a wide range
     * ('range too large'), so S was never recovered and the refund-race loser could not be made whole. Here each query is
     * capped to CLAIMED_LOG_WINDOW blocks, fromBlock slides forward window-by-window, and a range-too-large / transient
     * rejection SHRINK-and-retries the SAME window (halving to a floor) before the leaf is abandoned. Returns the FIRST S
     * whose sha256 equals `hashLockHex` (the authenticator — a single honest leaf suffices to TRUST it), else null.
     */
    this.CLAIMED_LOG_WINDOW = 9e3;
  }
  // matches watchForClaim's 9000-block cap (public-RPC-safe)
  async scanLeafForClaimedSecret(leaf, htlcAddr, topic0, idTopic, swapId, hashLockHex, lockBlock) {
    let tip;
    try {
      tip = await Promise.race([
        leaf.getBlockNumber(),
        new Promise((_, rej) => setTimeout(() => rej(new Error("getBlockNumber timed out")), 15e3))
      ]);
    } catch {
      return null;
    }
    if (!Number.isFinite(tip) || tip <= 0) return null;
    let from = lockBlock > 0 ? Math.min(lockBlock, tip) : Math.max(0, tip - 9e4);
    let window2 = _SwapController.CLAIMED_LOG_WINDOW;
    const MAX_QUERIES = 1e4;
    let guard = 0;
    while (from <= tip && guard++ < MAX_QUERIES) {
      const to = Math.min(tip, from + window2 - 1);
      let logs = null;
      try {
        logs = await leaf.getLogs({ address: htlcAddr, topics: [topic0, idTopic], fromBlock: from, toBlock: to });
      } catch {
        if (window2 > 1) {
          window2 = Math.max(1, Math.floor(window2 / 2));
          continue;
        }
        return null;
      }
      if (Array.isArray(logs)) {
        for (const log of logs) {
          let parsed;
          try {
            parsed = HTLC_IFACE.parseLog({ topics: [...log.topics ?? []], data: log.data });
          } catch {
            continue;
          }
          if (!parsed || parsed.name !== "Claimed") continue;
          if (String(parsed.args[0]).toLowerCase() !== swapId.toLowerCase()) continue;
          const secretHex = parsed.args[1];
          if (!secretHex || secretHex === "0x" + "0".repeat(64)) continue;
          let sb;
          try {
            sb = ethers.getBytes(secretHex);
          } catch {
            continue;
          }
          if (sb.length !== 32) continue;
          if (bytesToHex(sha256(sb)) !== hashLockHex) continue;
          return sb;
        }
      }
      from = to + 1;
      window2 = _SwapController.CLAIMED_LOG_WINDOW;
    }
    return null;
  }
  /** Best-effort persist of the full record (rehydration source for resume in step 6). Not fund-critical — the
   *  fund-critical write-set is committed atomically inside fundLegX BEFORE the broadcast. */
  async persistRecord() {
    try {
      await this.deps.durable.set(recordKey(this.id), JSON.stringify(this.record));
    } catch (e) {
      this.emit({ type: "error", error: e instanceof Error ? e : new Error(String(e)) });
    }
  }
};

// src/storage.ts
var DurableStoreInconsistentError = class extends Error {
  constructor(message, commitError, rollbackErrors) {
    super(message);
    this.commitError = commitError;
    this.rollbackErrors = rollbackErrors;
    this.storeInconsistent = true;
    this.name = "DurableStoreInconsistentError";
  }
};
var InMemoryDurableStore = class {
  constructor() {
    this.m = /* @__PURE__ */ new Map();
  }
  async get(key) {
    return this.m.has(key) ? this.m.get(key) : null;
  }
  async set(key, value) {
    this.m.set(key, value);
  }
  async remove(key) {
    this.m.delete(key);
  }
  async commit(entries) {
    const prior = /* @__PURE__ */ new Map();
    for (const [k] of entries) if (!prior.has(k)) prior.set(k, this.m.has(k) ? this.m.get(k) : null);
    const written = [];
    try {
      for (const [k, v] of entries) {
        this.m.set(k, v);
        written.push(k);
        if (this.m.get(k) !== v) throw new Error(`InMemoryDurableStore.commit read-back mismatch for ${k}`);
      }
    } catch (e) {
      for (const k of written) {
        const p = prior.get(k) ?? null;
        if (p === null) this.m.delete(k);
        else this.m.set(k, p);
      }
      throw e instanceof Error ? e : new Error(String(e));
    }
  }
};
var LocalStorageDurableStore = class {
  constructor(storage) {
    const s = storage ?? (typeof localStorage !== "undefined" ? localStorage : void 0);
    if (!s) throw new Error("LocalStorageDurableStore requires a Storage (localStorage unavailable in this environment)");
    this.s = s;
  }
  async get(key) {
    return this.s.getItem(key);
  }
  async remove(key) {
    this.s.removeItem(key);
  }
  async set(key, value) {
    this.s.setItem(key, value);
    if (this.s.getItem(key) !== value) throw new Error(`LocalStorageDurableStore.set read-back mismatch for ${key}`);
  }
  async commit(entries) {
    const prior = /* @__PURE__ */ new Map();
    for (const [k] of entries) if (!prior.has(k)) prior.set(k, this.s.getItem(k));
    const written = [];
    try {
      for (const [k, v] of entries) {
        this.s.setItem(k, v);
        written.push(k);
        if (this.s.getItem(k) !== v) throw new Error(`LocalStorageDurableStore.commit read-back mismatch for ${k}`);
      }
    } catch (e) {
      const commitError = e instanceof Error ? e : new Error(String(e));
      const rollbackErrors = [];
      for (const k of written) {
        const p = prior.get(k) ?? null;
        try {
          if (p === null) this.s.removeItem(k);
          else this.s.setItem(k, p);
        } catch (re) {
          rollbackErrors.push({ key: k, error: re });
        }
      }
      if (rollbackErrors.length > 0) {
        const keys = rollbackErrors.map((r) => r.key).join(", ");
        throw new DurableStoreInconsistentError(
          `LocalStorageDurableStore.commit rollback FAILED for [${keys}] after a commit error (${commitError.message}) \u2014 the store is in an INCONSISTENT partial-write state and must not be trusted.`,
          commitError,
          rollbackErrors
        );
      }
      throw commitError;
    }
  }
};
var InMemorySessionStore = class {
  constructor() {
    this.m = /* @__PURE__ */ new Map();
  }
  async get(key) {
    return this.m.has(key) ? this.m.get(key) : null;
  }
  async set(key, value) {
    this.m.set(key, value);
  }
  async remove(key) {
    this.m.delete(key);
  }
};
var WindowSessionStore = class {
  constructor(storage) {
    const s = storage ?? (typeof sessionStorage !== "undefined" ? sessionStorage : void 0);
    if (!s) throw new Error("WindowSessionStore requires a Storage (sessionStorage unavailable in this environment)");
    this.s = s;
  }
  async get(key) {
    return this.s.getItem(key);
  }
  async set(key, value) {
    this.s.setItem(key, value);
  }
  async remove(key) {
    this.s.removeItem(key);
  }
};
var MutexBusyError = class extends Error {
  constructor(name, scope) {
    super(`Lock "${name}" is held by another ${scope} holder \u2014 refusing to run a second concurrent holder.`);
    this.mutexBusy = true;
    this.name = "MutexBusyError";
  }
};
var MutexUnavailableError = class extends Error {
  constructor(name) {
    super(`No cross-tab lock medium available for "${name}" (Web Locks API absent and localStorage unusable) \u2014 refusing to run the fund/lock body without a cross-tab lock.`);
    this.mutexUnavailable = true;
    this.name = "MutexUnavailableError";
  }
};
var _randToken = () => `${Date.now().toString(36)}.${Math.random().toString(36).slice(2, 10)}`;
var _CAS_PREFIX = "bch2swap:mutexcas:";
function _parseCas(raw) {
  if (!raw) return null;
  const ix = raw.lastIndexOf("@");
  if (ix < 0) return null;
  const ts = parseInt(raw.slice(ix + 1), 10);
  return Number.isFinite(ts) ? { token: raw.slice(0, ix), ts } : null;
}
var InProcessMutex = class {
  constructor(opts) {
    this.tails = /* @__PURE__ */ new Map();
    this.store = opts?.store;
    this.ttlMs = opts?.ttlMs ?? 24e4;
    this.token = opts?.token ?? _randToken();
    this.now = opts?.now ?? (() => Date.now());
    this.settle = opts?.settle ?? (() => new Promise((res) => setTimeout(res, 30 + Math.floor(Math.random() * 90))));
  }
  withLock(name, fn) {
    const prev = this.tails.get(name) ?? Promise.resolve();
    const run = prev.then(() => this.guarded(name, fn), () => this.guarded(name, fn));
    this.tails.set(name, run.then(() => {
    }, () => {
    }));
    return run;
  }
  // Durable cross-process CAS backstop: refuse if a live PEER token holds the sentinel; else write our token, read it
  // back (a racing peer that overwrote us => throw), run fn, release only if the sentinel is still ours.
  async guarded(name, fn) {
    if (!this.store) return await fn();
    const store = this.store;
    const key = _CAS_PREFIX + name;
    const now = this.now();
    const existing = _parseCas(await store.get(key));
    if (existing && existing.token !== this.token && now - existing.ts < this.ttlMs) {
      throw new MutexBusyError(name, "cross-process");
    }
    const stamp = `${this.token}@${now}`;
    await store.set(key, stamp);
    await this.settle();
    if (await store.get(key) !== stamp) throw new MutexBusyError(name, "cross-process");
    let hb;
    try {
      hb = setInterval(() => {
        void (async () => {
          try {
            if (_parseCas(await store.get(key))?.token === this.token) await store.set(key, `${this.token}@${this.now()}`);
          } catch {
          }
        })();
      }, Math.max(1, Math.floor(this.ttlMs / 3)));
    } catch {
    }
    try {
      return await fn();
    } finally {
      if (hb) {
        try {
          clearInterval(hb);
        } catch {
        }
      }
      try {
        if (_parseCas(await store.get(key))?.token === this.token) await store.remove(key);
      } catch {
      }
    }
  }
};
var BrowserMutex = class {
  constructor(opts) {
    this.token = opts?.token ?? _randToken();
    this.ttlMs = opts?.ttlMs ?? 24e4;
    this.ls = opts?.localStorage ?? (typeof localStorage !== "undefined" ? localStorage : void 0);
    const injectedLocks = opts?.locks;
    if (injectedLocks !== void 0) {
      this.locks = injectedLocks ?? void 0;
    } else {
      const nav = typeof navigator !== "undefined" ? navigator : void 0;
      this.locks = nav && nav.locks && typeof nav.locks.request === "function" ? nav.locks : void 0;
    }
  }
  async withLock(name, fn) {
    if (this.locks) return this.locks.request(name, async () => await fn());
    const s = this.ls;
    if (!s) throw new MutexUnavailableError(name);
    const key = `bch2swap:xtlock:${name}`;
    const readTok = () => {
      try {
        return _parseCas(s.getItem(key));
      } catch {
        return null;
      }
    };
    const peerHeld = () => {
      const t = readTok();
      return !!t && t.token !== this.token && Date.now() - t.ts < this.ttlMs;
    };
    if (peerHeld()) throw new MutexBusyError(name, "cross-tab");
    try {
      s.setItem(key, `${this.token}@${Date.now()}`);
    } catch {
      throw new MutexUnavailableError(name);
    }
    await new Promise((res) => {
      setTimeout(res, 30 + Math.floor(Math.random() * 90));
    });
    const after = readTok();
    if (after && after.token !== this.token) throw new MutexBusyError(name, "cross-tab");
    let hb;
    try {
      hb = setInterval(() => {
        try {
          if (readTok()?.token === this.token) s.setItem(key, `${this.token}@${Date.now()}`);
        } catch {
        }
      }, 2e4);
    } catch {
    }
    try {
      return await fn();
    } finally {
      if (hb) {
        try {
          clearInterval(hb);
        } catch {
        }
      }
      try {
        if (readTok()?.token === this.token) s.removeItem(key);
      } catch {
      }
    }
  }
};

// src/utxo-reservation.ts
var ukey = (u) => `${u.tx_hash}:${u.tx_pos}`;
var TTL_MS = 60 * 6e4;
var UtxoReservationRegistry = class {
  constructor(mirror) {
    this.reservedBy = /* @__PURE__ */ new Map();
    // input key -> in-flight funding that spends it
    this.knownChange = /* @__PURE__ */ new Map();
    // input key -> 0-conf change spendable before it confirms
    this.mutexTail = Promise.resolve();
    this.mirror = mirror;
  }
  prune(now) {
    for (const [k, e] of this.reservedBy) if (now - e.ts > TTL_MS) this.reservedBy.delete(k);
    for (const [k, e] of this.knownChange) if (now - e.ts > TTL_MS) this.knownChange.delete(k);
  }
  // Mirror this instance's INPUT reservations (each with its own ts) so a peer would exclude them.
  persist() {
    if (!this.mirror) return;
    const rows = [];
    for (const [k, e] of this.reservedBy) rows.push([k, e.ts]);
    try {
      this.mirror.persistReserved(rows);
    } catch {
    }
  }
  // Tiny async mutex: makes each funding's release→candidate→select→reserve sequence atomic, closing the TOCTOU where
  // two fundings could both select before either reserves. A throwing fn does NOT wedge the chain (tail swallows).
  withUtxoLock(fn) {
    const run = this.mutexTail.then(fn, fn);
    this.mutexTail = run.then(() => {
    }, () => {
    });
    return run;
  }
  // Candidate inputs for `swapId`: (chain UTXOs minus inputs reserved by OTHER swaps) ∪ (0-conf change not re-spent by
  // another), deduped by outpoint. Call INSIDE withUtxoLock, after releaseSwap(swapId).
  candidateUtxos(swapId, chainUtxos, now = Date.now()) {
    this.prune(now);
    const otherTabReserved = this.mirror ? this.mirror.readOtherReserved(now) : /* @__PURE__ */ new Set();
    const reservedByOther = (k) => {
      const r = this.reservedBy.get(k);
      if (r && r.owner !== swapId) return true;
      return otherTabReserved.has(k);
    };
    const out = /* @__PURE__ */ new Map();
    for (const u of chainUtxos) {
      if (reservedByOther(ukey(u))) continue;
      out.set(ukey(u), u);
    }
    for (const [k, e] of this.knownChange) {
      if (reservedByOther(k)) continue;
      if (!out.has(k)) out.set(k, e.v);
    }
    return [...out.values()];
  }
  // Reserve `swapId`'s selected inputs. Call INSIDE withUtxoLock, immediately after a successful (sufficient) selection.
  reserveInputs(swapId, inputs, now = Date.now()) {
    for (const u of inputs) this.reservedBy.set(ukey(u), { v: true, ts: now, owner: swapId });
    this.persist();
  }
  // Record `swapId`'s funding change output so a later funding may spend it before it confirms.
  recordChange(swapId, change, now = Date.now()) {
    if (change.value > 0) this.knownChange.set(ukey(change), { v: change, ts: now, owner: swapId });
  }
  // Release everything `swapId` holds. Call before re-selecting (retry-safe) and on ANY funding failure / unmount so a
  // non-broadcast selection never strands its inputs. Idempotent.
  releaseSwap(swapId) {
    for (const [k, e] of this.reservedBy) if (e.owner === swapId) this.reservedBy.delete(k);
    for (const [k, e] of this.knownChange) if (e.owner === swapId) this.knownChange.delete(k);
    this.persist();
  }
  // Test-only: wipe all in-memory state (the injected mirror, if any, owns its own storage).
  reset() {
    this.reservedBy.clear();
    this.knownChange.clear();
    this.mutexTail = Promise.resolve();
    this.persist();
  }
};

// src/order-book/adapter.ts
var BOOK_TO_OFFER = {
  BCH2: "bch2",
  BCH: "bch",
  BTC: "btc",
  BC2: "bc2",
  ETH: "eth",
  BASE: "base",
  ARB: "arb",
  POLY: "poly"
};
var OFFER_TO_BOOK = {
  bch2: "BCH2",
  bch: "BCH",
  btc: "BTC",
  bc2: "BC2",
  eth: "ETH",
  base: "BASE",
  arb: "ARB",
  poly: "POLY"
};
function bookChainToOffer(code) {
  const upper = String(code).toUpperCase();
  const mapped = BOOK_TO_OFFER[upper];
  if (!mapped) throw new Error(`bookChainToOffer: unknown order-book chain code '${code}'`);
  return mapped;
}
function offerChainToBook(chain) {
  const lower = String(chain).toLowerCase();
  const mapped = OFFER_TO_BOOK[lower];
  if (!mapped) throw new Error(`offerChainToBook: unknown SwapOffer chain '${chain}'`);
  return mapped;
}
function proposalToOffer(proposal, overrides) {
  const offer = {
    id: "",
    sendChain: bookChainToOffer(proposal.offerChain),
    receiveChain: bookChainToOffer(proposal.wantChain),
    sendAmount: proposal.sendAmount,
    // base-unit decimal string (sats/wei), carried through verbatim
    receiveAmount: proposal.receiveAmount,
    secretHash: proposal.secretHash,
    secretNonce: proposal.secretNonce || void 0,
    secretScheme: proposal.secretScheme || void 0,
    makerIdPub: proposal.makerIdPub || void 0,
    makerSig: proposal.makerSig || void 0,
    authPub: proposal.authPub || void 0,
    // initiator (maker) addresses: prefer the explicit fields, fall back to the mirrored refund/receive names
    initiatorSendAddress: proposal.initiatorSendAddress || proposal.refundAddress || "",
    initiatorReceiveAddress: proposal.initiatorReceiveAddress || proposal.receiveAddress || "",
    status: "open",
    createdAt: 0,
    expiresAt: 0
  };
  if (proposal.evmInfo !== void 0) offer.evmInfo = proposal.evmInfo;
  if (proposal.evmAddress !== void 0) offer.evmAddress = proposal.evmAddress;
  return overrides ? { ...offer, ...overrides } : offer;
}
function orderToOffer(order, overrides) {
  const base = proposalToOffer(order.proposal, {
    id: order.id,
    status: order.status,
    createdAt: order.createdAt,
    expiresAt: order.expiresAt,
    // chains come from the proposal, but the order-level codes are authoritative if they ever diverge
    sendChain: bookChainToOffer(order.offerChain),
    receiveChain: bookChainToOffer(order.wantChain)
  });
  if (order.takerAuthPub !== void 0) base.takerAuthPub = order.takerAuthPub;
  return overrides ? { ...base, ...overrides } : base;
}
function offerToProposal(offer, overrides) {
  const proposal = {
    offerChain: offerChainToBook(offer.sendChain),
    wantChain: offerChainToBook(offer.receiveChain),
    sendAmount: String(offer.sendAmount),
    receiveAmount: String(offer.receiveAmount),
    secretHash: offer.secretHash,
    secretNonce: offer.secretNonce ?? "",
    secretScheme: offer.secretScheme ?? "",
    makerIdPub: offer.makerIdPub ?? "",
    makerSig: offer.makerSig ?? "",
    authPub: offer.authPub ?? "",
    refundAddress: offer.initiatorSendAddress,
    receiveAddress: offer.initiatorReceiveAddress,
    initiatorSendAddress: offer.initiatorSendAddress,
    initiatorReceiveAddress: offer.initiatorReceiveAddress,
    hashLock: offer.secretHash
    // the HTLC hash lock is the secret hash
  };
  if (offer.evmInfo !== void 0) proposal.evmInfo = offer.evmInfo;
  if (offer.evmAddress !== void 0) proposal.evmAddress = offer.evmAddress;
  return overrides ? { ...proposal, ...overrides } : proposal;
}

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
    if (order.proposal.authPub !== makerPubKey) {
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
      takerAuthPub: takerPubKey,
      // the identity presented to takeOrder (real proxy field)
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

export { BrowserMutex, CentralizedOrderBook, DurableStoreInconsistentError, GateFailure, InMemoryDurableStore, InMemorySessionStore, InProcessMutex, LocalStorageDurableStore, MAX_PBKDF2_ITERATIONS, MIN_PBKDF2_ITERATIONS, MnemonicSeedVault, MockOrderBook, MutexBusyError, MutexUnavailableError, PBKDF2_ITERATIONS, SwapController, UtxoReservationRegistry, WindowSessionStore, bc1AddressToScripthash, bookChainToOffer, decodeBase58, decodeBech32, decodeBech32m, decodeCashAddr, decodeLegacyAddress, decodeWIF, decryptMnemonic, encodeBase582 as encodeBase58, encodeBech32, encodeBech32m, encodeCashAddr2 as encodeCashAddr, encodeLegacyAddress, encodeWIF, encryptMnemonic, hash1602 as hash160, isBech32Address, offerChainToBook, offerToProposal, orderToOffer, p2pkScripthash, p2pkhScripthash, p2shP2wpkhScripthash, p2trScripthash, p2wpkhScripthash, proposalToOffer, pubkeyToBC2Address, pubkeyToBCH2Address, pubkeyToBCHAddress, pubkeyToBTCAddress, pubkeyToBech32Address, pubkeyToP2SHP2WPKHAddress, resolveIterations, validatePassword, xonlyPubkeyToP2TRAddress };
