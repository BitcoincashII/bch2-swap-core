import { HDKey } from '@scure/bip32';
import { validateMnemonic, mnemonicToSeedSync } from '@scure/bip39';
import { wordlist } from '@scure/bip39/wordlists/english';
import { hmac } from '@noble/hashes/hmac';
import { sha256 } from '@noble/hashes/sha256';
import * as secp256k12 from '@noble/secp256k1';
import { ripemd160 } from '@noble/hashes/ripemd160';

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
  initiator: 216};
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
function p2pkhScripthash(pubkeyHash) {
  const script = new Uint8Array([118, 169, 20, ...pubkeyHash, 136, 172]);
  const hash = sha256(script);
  const reversed = new Uint8Array(hash.length);
  for (let i = 0; i < hash.length; i++) {
    reversed[i] = hash[hash.length - 1 - i];
  }
  return Array.from(reversed).map((b) => b.toString(16).padStart(2, "0")).join("");
}
function hash2562(d) {
  return sha256(sha256(d));
}
function equalBytes(a, b) {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i];
  return d === 0;
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
var MAX_HEADER_FUTURE_SEC = 7200;
function medianTimePast(window) {
  const w = window.slice(-11).slice().sort((a, b) => a - b);
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

// src/swap-controller.ts
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
var recordKey = (id) => `bch2swap:record:${id}`;
var durableSecretKey = (id) => `bch2swap:encsecret:${id}`;
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
var SwapController = class {
  constructor(record, deps) {
    this.listeners = /* @__PURE__ */ new Map();
    /** In-memory only. The re-derivable HTLC preimage — NEVER written durably in plaintext (design §3, fix #5). */
    this.secret = null;
    this.disposed = false;
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
      disposed: this.disposed
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
    const rec = this.record;
    if (rec.role !== "initiator") {
      throw new Error("fundLegX: only the initiator funds leg X (responder/EVM funding is step 7)");
    }
    if (rec.phase !== "taken" && rec.phase !== "prepared") {
      throw new Error(`fundLegX: unexpected phase '${rec.phase}' \u2014 fund runs from 'taken' or 'prepared'`);
    }
    if (isSwapPairSuspended(this.myChain, this.theirChain)) {
      throw new Error(`fundLegX: swap pair ${this.myChain}/${this.theirChain} is suspended \u2014 refusing to fund`);
    }
    const cfg = chainConfigs[this.myChain];
    if (!cfg || cfg.isEvm) {
      throw new Error(`fundLegX: leg X (${this.myChain}) is not a UTXO chain \u2014 EVM funding is step 7`);
    }
    const claimPkhHex = (rec.counterpartyClaimPkh ?? "").toLowerCase().replace(/^0x/, "");
    if (!HEX20.test(claimPkhHex)) {
      throw new Error("fundLegX: counterpartyClaimPkh (the taker receive pkh on leg X) is missing \u2014 cannot build the HTLC");
    }
    const amountSats = this.legXAmountSats();
    const client = this.deps.chainClientFor(this.myChain);
    this.status("fundLegX:verifying-height");
    const [buildHeight] = await client.getBlockHeight();
    if (!Number.isInteger(buildHeight) || buildHeight <= 0 || buildHeight > maxPlausibleBlockHeight()) {
      throw new Error(`fundLegX: proxy-reported ${this.myChain} height ${buildHeight} is implausible \u2014 refusing to set an unrecoverable refund timelock`);
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
      this.status("fundLegX:selecting-inputs");
      const scripthash = p2pkhScripthash(myPkh);
      const chainUtxos = await client.getUTXOs(scripthash, bytesToHex(p2pkhScript));
      const now = this.deps.clock();
      const selected = await this.deps.reservation.withUtxoLock(() => {
        this.deps.reservation.releaseSwap(rec.id);
        const valid = chainUtxos.filter((u) => Number.isFinite(u.value) && u.value > 0).map((u) => ({ tx_hash: u.tx_hash, tx_pos: u.tx_pos, value: u.value, height: u.height }));
        const candidates = this.deps.reservation.candidateUtxos(rec.id, valid, now);
        const picked = this.greedySelect(candidates, amountSats);
        if (!picked) return null;
        this.deps.reservation.reserveInputs(rec.id, picked, now);
        return picked;
      });
      if (!selected || selected.length === 0) {
        this.deps.reservation.releaseSwap(rec.id);
        throw new Error("fundLegX: insufficient spendable UTXOs to fund the HTLC");
      }
      try {
        const htlc = createInitiatorHTLC(this.buildSwapState(), buildHeight, claimPkh, myPkh);
        this.status("fundLegX:building-tx");
        const tx = await fundHTLC(htlc, selected, sk.privateKey, sk.publicKey, p2pkhScript, amountSats, this.myChain);
        const totalIn = selected.reduce((s, u) => s + u.value, 0);
        const changeVal = totalIn - amountSats - tx.fee;
        if (changeVal > 0) this.deps.reservation.recordChange(rec.id, { tx_hash: tx.txid, tx_pos: 1, value: changeVal, height: 0 }, now);
        const canonical = tx.txid.toLowerCase();
        this.status("fundLegX:committing");
        await this.deps.durable.commit([
          [fundedKey(rec.id), canonical],
          [fundLocktimeKey(rec.id), String(htlc.params.locktime)],
          [fundRecipientKey(rec.id), bytesToHex(claimPkh)],
          [fundedHtlcKey(rec.id), JSON.stringify(durableHtlc(htlc))]
        ]);
        this.status("fundLegX:broadcasting");
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
    this.setPhase("initiator_funded");
    this.status("fundLegX:funded");
    await this.persistRecord();
    return { txid: outcome.txid };
  }
  // ── helpers ──────────────────────────────────────────────────────────────────────────────────────────────
  /** leg X amount in sats (offer.sendAmount is base-unit sats < 2^53 for a UTXO leg). Fail closed on garbage. */
  legXAmountSats() {
    const raw = this.record.offer.sendAmount;
    const n = typeof raw === "number" ? raw : Number(raw);
    if (!Number.isInteger(n) || !Number.isFinite(n) || n <= 0) {
      throw new Error(`fundLegX: invalid leg X amount '${String(raw)}' \u2014 refusing to build the funding tx`);
    }
    return n;
  }
  /** A minimal SwapState for createInitiatorHTLC (it reads only offer.sendChain + secretHash). */
  buildSwapState() {
    const secretHashHex = (this.record.offer.secretHash ?? "").toLowerCase().replace(/^0x/, "");
    return {
      offer: this.record.offer,
      role: "initiator",
      secretHash: hexToBytes(secretHashHex),
      claimAddress: this.record.offer.initiatorReceiveAddress ?? "",
      refundAddress: this.record.offer.initiatorSendAddress ?? ""
    };
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

export { MnemonicSeedVault, SwapController };
