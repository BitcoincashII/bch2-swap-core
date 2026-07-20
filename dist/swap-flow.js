import * as secp256k1 from '@noble/secp256k1';
import { sha256 } from '@noble/hashes/sha256';
export { sha256 } from '@noble/hashes/sha256';
import { ripemd160 } from '@noble/hashes/ripemd160';

// src/htlc-builder.ts

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
  const r = feeRate ?? configRate ?? 1;
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
  const signature = await secp256k1.signAsync(sighash, recipientPrivateKey, { lowS: true });
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
    const sig = await secp256k1.signAsync(sighash, inputs[i].privateKey, { lowS: true });
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
function generateSecret() {
  const secret = new Uint8Array(32);
  crypto.getRandomValues(secret);
  return secret;
}
function hashSecret(secret) {
  return sha256(secret);
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
  const locktime = explicitLocktime ?? currentHeight + LOCKTIME_BLOCKS.responder;
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

export { claimHTLC, createInitiatorHTLC, createResponderHTLC, extractSecret, fundHTLC, generateSecret, getHTLCScripthash, hash160, hashSecret, hexToBytes, verifyAndAuthenticateP2pkhInput, verifyAndAuthenticateUtxo };
