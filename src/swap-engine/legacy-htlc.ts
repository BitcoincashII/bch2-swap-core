/**
 * HTLC transaction construction for BCH2/BCH/BTC/BC2 atomic swaps (Path A).
 *
 * Direct port of bch2htlc/htlc.go + funding.go.
 *
 * Signing: ECDSA DER on all four chains — NOT Schnorr.
 * BCH2/BCH: BIP143 sighash + SIGHASH_FORKID (0x41)
 * BTC/BC2:  legacy P2SH sighash + SIGHASH_ALL (0x01)
 */

import * as secp256k1 from '@noble/secp256k1';
import { sha256 } from '@noble/hashes/sha256';
import { hash160 } from '../address-codec';

// ── Constants ─────────────────────────────────────────────────────────────────

/** Block-based relative timelock for BCH2↔ERC-20 HTLCs. */
export const HTLC_CSV_BLOCKS = 288;

/** SIGHASH_ALL | SIGHASH_FORKID — BCH/BCH2 replay-protection flag. */
export const SIGHASH_ALL_FORKID = 0x41;

/** Plain SIGHASH_ALL — BTC/BC2. */
export const SIGHASH_ALL = 0x01;

export const DUST_SATOSHIS = 546;
export const DEFAULT_FEE_SATOSHIS = 500;

/** BIP68 bit-22: time-based relative locktime. */
export const SEQ_LOCKTIME_TYPE_FLAG = 0x00400000;

/** 1 << 9 = 512 seconds per BIP68 time unit. */
export const SEQ_LOCKTIME_GRANULARITY = 9;

// BCH↔BCH2 regtest (time-based, smallest valid units for fast test harness)
export const BCH_SWAP_BCH2_CSV_NSEQUENCE = (SEQ_LOCKTIME_TYPE_FLAG | 1) >>> 0;
export const BCH_SWAP_BCH_CSV_NSEQUENCE  = (SEQ_LOCKTIME_TYPE_FLAG | 2) >>> 0;

// Mainnet production values
export const MAINNET_BCH_SWAP_BCH2_CSV  = (SEQ_LOCKTIME_TYPE_FLAG | 338)  >>> 0; // ≈2d
export const MAINNET_BCH_SWAP_BCH_CSV   = (SEQ_LOCKTIME_TYPE_FLAG | 1182) >>> 0; // ≈7d
export const MAINNET_BTC_SWAP_BCH2_CSV  = (SEQ_LOCKTIME_TYPE_FLAG | 337)  >>> 0; // ≈2d
export const MAINNET_BTC_SWAP_BTC_CSV   = (SEQ_LOCKTIME_TYPE_FLAG | 1687) >>> 0; // ≈10d
export const MAINNET_BC2_SWAP_BCH2_CSV  = (SEQ_LOCKTIME_TYPE_FLAG | 337)  >>> 0; // ≈2d
export const MAINNET_BC2_SWAP_BC2_CSV   = (SEQ_LOCKTIME_TYPE_FLAG | 1687) >>> 0; // ≈10d

// ── P2SH / P2PKH script builders ─────────────────────────────────────────────

/**
 * Build the HTLC redeem script:
 *   OP_IF OP_SHA256 <hashLock> OP_EQUALVERIFY <buyerPubKey> OP_CHECKSIG
 *   OP_ELSE <csvNSequence> OP_CSV OP_DROP <sellerPubKey> OP_CHECKSIG OP_ENDIF
 *
 * OP_CHECKSIG validates ECDSA (not Schnorr) on all chains.
 * csvNSequence should carry SEQ_LOCKTIME_TYPE_FLAG for time-based locks.
 * The spending tx nSequence must equal this value (BIP112 type-match rule).
 */
export function buildRedeemScript(
  buyerPubKey: Uint8Array,
  sellerPubKey: Uint8Array,
  csvNSequence: number,
  hashLock: Uint8Array,
): Uint8Array {
  return concat([
    new Uint8Array([0x63]),        // OP_IF
    new Uint8Array([0xa8]),        // OP_SHA256
    pushData(hashLock),            // push 32-byte hashLock
    new Uint8Array([0x88]),        // OP_EQUALVERIFY
    pushData(buyerPubKey),         // push buyerPubKey (33 bytes)
    new Uint8Array([0xac]),        // OP_CHECKSIG
    new Uint8Array([0x67]),        // OP_ELSE
    encodeCSV(csvNSequence),       // minimal CSV push
    new Uint8Array([0xb2]),        // OP_CSV
    new Uint8Array([0x75]),        // OP_DROP
    pushData(sellerPubKey),        // push sellerPubKey (33 bytes)
    new Uint8Array([0xac]),        // OP_CHECKSIG
    new Uint8Array([0x68]),        // OP_ENDIF
  ]);
}

/** OP_HASH160 <hash160(redeemScript)> OP_EQUAL */
export function p2shScriptPubKey(redeemScript: Uint8Array): Uint8Array {
  const h = hash160(redeemScript);
  return new Uint8Array([0xa9, 0x14, ...h, 0x87]);
}

/** OP_DUP OP_HASH160 <hash160(pubKey)> OP_EQUALVERIFY OP_CHECKSIG */
export function p2pkhScriptPubKey(pubKey: Uint8Array): Uint8Array {
  const h = hash160(pubKey);
  return new Uint8Array([0x76, 0xa9, 0x14, ...h, 0x88, 0xac]);
}

// ── Claim transaction ─────────────────────────────────────────────────────────

/**
 * Build a claim transaction (IF branch) that reveals secret s.
 *   scriptSig: <DER-sig> <secret> OP_1 <redeemScript>
 *   nSequence:  0xFFFFFFFF (no CSV on claim branch)
 *
 * sighashType: SIGHASH_ALL_FORKID (0x41) for BCH/BCH2; SIGHASH_ALL (0x01) for BTC/BC2.
 * Signing uses ECDSA DER on all chains (NOT Schnorr).
 */
export async function buildClaimTx(
  prevTxID: Uint8Array,       // 32 bytes, internal (natural) byte order
  prevVout: number,
  htlcSatoshis: number,
  redeemScript: Uint8Array,
  buyerPrivKey: Uint8Array,   // zeroed after use
  buyerPubKey: Uint8Array,
  secret: Uint8Array,
  sighashType: number,
): Promise<Uint8Array> {
  if (secret.length === 0) throw new Error('secret must not be empty');
  const net = htlcSatoshis - DEFAULT_FEE_SATOSHIS;
  if (net < DUST_SATOSHIS) {
    throw new Error(`net output ${net} after fee is below dust threshold ${DUST_SATOSHIS}`);
  }

  const outputScript = p2pkhScriptPubKey(buyerPubKey);
  const sequence = 0xFFFFFFFF;
  const locktime = 0;

  const sighash = sighashType === SIGHASH_ALL
    ? legacySighashSingle(prevTxID, prevVout, sequence, redeemScript, net, outputScript, locktime, sighashType)
    : bip143Sighash(prevTxID, prevVout, sequence, redeemScript, htlcSatoshis, outputScript, net, locktime, sighashType);

  const sig = await ecdsaSign(sighash, buyerPrivKey, sighashType);
  const scriptSig = buildP2SHScriptSig(sig, secret, redeemScript);
  return buildRawTx(prevTxID, prevVout, scriptSig, sequence, outputScript, net, locktime);
}

// ── Refund transaction ────────────────────────────────────────────────────────

/**
 * Build a refund transaction (ELSE branch) for the seller.
 *   scriptSig: <DER-sig> OP_0 <redeemScript>
 *   nSequence:  csvNSequence (must equal OP_CSV operand — BIP68/BIP112 enforcement)
 *
 * sighashType: SIGHASH_ALL_FORKID (0x41) for BCH/BCH2; SIGHASH_ALL (0x01) for BTC/BC2.
 */
export async function buildRefundTx(
  prevTxID: Uint8Array,
  prevVout: number,
  htlcSatoshis: number,
  redeemScript: Uint8Array,
  sellerPrivKey: Uint8Array,  // zeroed after use
  sellerPubKey: Uint8Array,
  csvNSequence: number,
  sighashType: number,
): Promise<Uint8Array> {
  const net = htlcSatoshis - DEFAULT_FEE_SATOSHIS;
  if (net < DUST_SATOSHIS) {
    throw new Error(`net output ${net} after fee is below dust threshold ${DUST_SATOSHIS}`);
  }

  const outputScript = p2pkhScriptPubKey(sellerPubKey);
  const sequence = csvNSequence >>> 0;
  const locktime = 0;

  const sighash = sighashType === SIGHASH_ALL
    ? legacySighashSingle(prevTxID, prevVout, sequence, redeemScript, net, outputScript, locktime, sighashType)
    : bip143Sighash(prevTxID, prevVout, sequence, redeemScript, htlcSatoshis, outputScript, net, locktime, sighashType);

  const sig = await ecdsaSign(sighash, sellerPrivKey, sighashType);
  const scriptSig = buildP2SHScriptSig(sig, null, redeemScript);
  return buildRawTx(prevTxID, prevVout, scriptSig, sequence, outputScript, net, locktime);
}

// ── Funding transaction ───────────────────────────────────────────────────────

/**
 * Build a funding transaction: spend one P2PKH UTXO to create the HTLC + change.
 *   Output 0: P2SH HTLC  (htlcSatoshis)
 *   Output 1: P2PKH change (inputSatoshis - htlcSatoshis - feeSatoshis)
 *
 * sighashType: SIGHASH_ALL_FORKID (0x41) for BCH/BCH2; SIGHASH_ALL (0x01) for BTC/BC2.
 */
export async function buildFundingTx(
  prevTxID: Uint8Array,
  prevVout: number,
  inputSatoshis: number,
  funderPrivKey: Uint8Array,  // zeroed after use
  funderPubKey: Uint8Array,
  htlcRedeemScript: Uint8Array,
  htlcSatoshis: number,
  feeSatoshis: number,
  sighashType: number,
): Promise<Uint8Array> {
  // R322-AUDIT: validate amounts + enforce a claimability floor. buildClaimTx/buildRefundTx both require
  // htlcSatoshis - DEFAULT_FEE_SATOSHIS >= DUST_SATOSHIS, so an HTLC funded below that floor confirms on-chain
  // but is spendable by NEITHER branch — funds permanently stranded. Reject it at funding time (mirrors the
  // DEX's fee-aware minClaimableHtlcAmount floor).
  for (const [name, v] of [['inputSatoshis', inputSatoshis], ['htlcSatoshis', htlcSatoshis], ['feeSatoshis', feeSatoshis]] as const) {
    if (!Number.isInteger(v) || v <= 0) throw new Error(`${name} must be a positive integer, got ${v}`);
  }
  const CLAIMABLE_FLOOR = DEFAULT_FEE_SATOSHIS + DUST_SATOSHIS;
  if (htlcSatoshis < CLAIMABLE_FLOOR) {
    throw new Error(`htlcSatoshis ${htlcSatoshis} is below the claimable floor ${CLAIMABLE_FLOOR} (fee + dust) — the funded HTLC would be unspendable by both the claim and refund branches`);
  }
  const change = inputSatoshis - htlcSatoshis - feeSatoshis;
  if (change < DUST_SATOSHIS) {
    throw new Error(`change ${change} sat is below dust threshold ${DUST_SATOSHIS}`);
  }

  const outputs: TxOutput[] = [
    { amount: htlcSatoshis, script: p2shScriptPubKey(htlcRedeemScript) },
    { amount: change,       script: p2pkhScriptPubKey(funderPubKey) },
  ];

  const sequence = 0xFFFFFFFF;
  const locktime = 0;
  const scriptCode = p2pkhScriptPubKey(funderPubKey);

  const sighash = sighashType === SIGHASH_ALL
    ? legacySighashOutputs(prevTxID, prevVout, sequence, scriptCode, outputs, locktime, sighashType)
    : bip143SighashOutputs(prevTxID, prevVout, sequence, scriptCode, inputSatoshis, outputs, locktime, sighashType);

  const sig = await ecdsaSign(sighash, funderPrivKey, sighashType);
  const scriptSig = buildP2PKHScriptSig(sig, funderPubKey);
  return buildRawTxOutputs(prevTxID, prevVout, scriptSig, sequence, outputs, locktime);
}

// ── Secret extraction ─────────────────────────────────────────────────────────

/**
 * Extract the 32-byte preimage s from a P2SH claim scriptSig.
 * Layout: <sigLen> <sig> <0x20> <secret(32B)> 0x51 <redeemScript...>
 */
export function extractSecretFromScriptSig(scriptSig: Uint8Array): Uint8Array {
  let pos = 0;

  if (pos >= scriptSig.length) throw new Error('scriptSig too short: no sig push');
  const op0 = scriptSig[pos++];
  let sigLen: number;
  if (op0 >= 0x01 && op0 <= 0x4b) {
    sigLen = op0;
  } else if (op0 === 0x4c) {
    if (pos >= scriptSig.length) throw new Error('scriptSig truncated after OP_PUSHDATA1');
    sigLen = scriptSig[pos++];
  } else if (op0 === 0x4d) {
    if (pos + 2 > scriptSig.length) throw new Error('scriptSig truncated after OP_PUSHDATA2');
    sigLen = scriptSig[pos] | (scriptSig[pos + 1] << 8);
    pos += 2;
  } else {
    throw new Error(`unexpected scriptSig opcode 0x${op0.toString(16).padStart(2, '0')} at pos 0`);
  }
  if (pos + sigLen > scriptSig.length) throw new Error('scriptSig: sig data overflows buffer');
  pos += sigLen;

  if (pos >= scriptSig.length) throw new Error('scriptSig too short: no secret push');
  const op1 = scriptSig[pos++];
  let secretLen: number;
  if (op1 >= 0x01 && op1 <= 0x4b) {
    secretLen = op1;
  } else if (op1 === 0x4c) {
    if (pos >= scriptSig.length) throw new Error('scriptSig truncated in secret OP_PUSHDATA1');
    secretLen = scriptSig[pos++];
  } else {
    throw new Error(`unexpected secret push opcode 0x${op1.toString(16).padStart(2, '0')}`);
  }
  if (secretLen !== 32) throw new Error(`expected 32-byte secret, got ${secretLen} bytes`);
  if (pos + 32 > scriptSig.length) throw new Error('scriptSig: secret data overflows buffer');

  return scriptSig.slice(pos, pos + 32);
}

// ── Script encoding helpers ───────────────────────────────────────────────────

/**
 * Minimal script data push.
 *  len == 0       → [0x00]
 *  len 1-75       → [len, ...data]
 *  len 76-255     → [0x4c, len, ...data]   OP_PUSHDATA1
 *  len 256-65535  → [0x4d, lo, hi, ...data] OP_PUSHDATA2
 */
export function pushData(data: Uint8Array): Uint8Array {
  const n = data.length;
  if (n === 0) return new Uint8Array([0x00]);
  if (n <= 75) return concat([new Uint8Array([n]), data]);
  if (n <= 255) return concat([new Uint8Array([0x4c, n]), data]);
  if (n <= 65535) return concat([new Uint8Array([0x4d, n & 0xff, (n >> 8) & 0xff]), data]);
  return concat([new Uint8Array([0x4e, n & 0xff, (n >> 8) & 0xff, (n >> 16) & 0xff, (n >> 24) & 0xff]), data]);
}

/**
 * Encode a BIP68 nSequence as a minimal script push for OP_CSV.
 *
 * Block-based values 1-16 → OP_1..OP_16 (MINIMALDATA-compliant; both BCH and BCH2
 * reject non-minimal single-byte integer pushes at mempool accept time).
 * All other values (including time-based: SEQ_LOCKTIME_TYPE_FLAG always set, value > 16)
 * → minimal CScriptNum encoding via pushScriptInt.
 */
export function encodeCSV(nSequence: number): Uint8Array {
  const n = nSequence >>> 0;
  if (n === 0) return new Uint8Array([0x00]);
  if (n <= 16) return new Uint8Array([0x50 + n]); // OP_1 (0x51) .. OP_16 (0x60)
  return pushScriptInt(n);
}

/** Minimal CScriptNum LE encoding of a non-negative integer, wrapped in pushData. */
function pushScriptInt(v: number): Uint8Array {
  if (v === 0) return new Uint8Array([0x00]);
  const bytes: number[] = [];
  let rem = v >>> 0;
  while (rem > 0) {
    bytes.push(rem & 0xff);
    rem = (rem >>> 8);
  }
  // If high bit of last byte is set, add zero padding byte (sign disambiguation)
  if (bytes[bytes.length - 1] & 0x80) bytes.push(0x00);
  return pushData(new Uint8Array(bytes));
}

// ── Sighash — exported for test validation ────────────────────────────────────

/**
 * Pre-BIP143 ("legacy") sighash for a single-input, single-output P2SH spend.
 * Used for BTC/BC2 HTLC claim/refund inputs.
 *
 * Preimage: version(4) | vinCount(1) | prevTxID(32) | prevVout(4) |
 *           scriptCode(var) | sequence(4) | voutCount(1) |
 *           outputAmount(8) | outputScript(var) | locktime(4) | sighashType(4)
 */
export function legacySighashSingle(
  prevTxID: Uint8Array,
  prevVout: number,
  sequence: number,
  scriptCode: Uint8Array,
  outputAmount: number,
  outputScript: Uint8Array,
  locktime: number,
  sighashType: number,
): Uint8Array {
  return dsha256(concat([
    le32(2),
    new Uint8Array([0x01]),
    prevTxID,
    le32(prevVout),
    varint(scriptCode.length),
    scriptCode,
    le32(sequence >>> 0),
    new Uint8Array([0x01]),
    le64(outputAmount),
    varint(outputScript.length),
    outputScript,
    le32(locktime),
    le32(sighashType),
  ]));
}

/**
 * Pre-BIP143 legacy sighash for a single-input, multi-output transaction.
 * Used for BTC/BC2 P2PKH funding inputs.
 */
export function legacySighashOutputs(
  prevTxID: Uint8Array,
  prevVout: number,
  sequence: number,
  scriptCode: Uint8Array,
  outputs: TxOutput[],
  locktime: number,
  sighashType: number,
): Uint8Array {
  const outParts = outputs.flatMap(o => [le64(o.amount), varint(o.script.length), o.script]);
  return dsha256(concat([
    le32(2),
    new Uint8Array([0x01]),
    prevTxID,
    le32(prevVout),
    varint(scriptCode.length),
    scriptCode,
    le32(sequence >>> 0),
    varint(outputs.length),
    concat(outParts),
    le32(locktime),
    le32(sighashType),
  ]));
}

/**
 * BIP143 sighash for BCH2/BCH (SIGHASH_FORKID) single-output spend.
 * scriptCode is the full redeemScript for P2SH; inputAmount is the HTLC value.
 */
export function bip143Sighash(
  prevTxID: Uint8Array,
  prevVout: number,
  sequence: number,
  scriptCode: Uint8Array,
  inputAmount: number,
  outputScript: Uint8Array,
  outputAmount: number,
  locktime: number,
  sighashType: number,
): Uint8Array {
  const hashPrevouts = dsha256(concat([prevTxID, le32(prevVout)]));
  const hashSequence = dsha256(le32(sequence >>> 0));
  const hashOutputs  = dsha256(concat([le64(outputAmount), varint(outputScript.length), outputScript]));

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
    le32(sighashType),
  ]));
}

/**
 * BIP143 sighash for BCH2/BCH multi-output (funding) transaction.
 */
export function bip143SighashOutputs(
  prevTxID: Uint8Array,
  prevVout: number,
  sequence: number,
  scriptCode: Uint8Array,
  inputAmount: number,
  outputs: TxOutput[],
  locktime: number,
  sighashType: number,
): Uint8Array {
  const hashPrevouts = dsha256(concat([prevTxID, le32(prevVout)]));
  const hashSequence = dsha256(le32(sequence >>> 0));
  const hashOutputs  = dsha256(concat(outputs.flatMap(o => [le64(o.amount), varint(o.script.length), o.script])));

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
    le32(sighashType),
  ]));
}

// ── TxOutput type (exported for callers and test helpers) ─────────────────────

export interface TxOutput {
  amount: number;
  script: Uint8Array;
}

// ── Raw transaction serialization ─────────────────────────────────────────────

function buildRawTx(
  prevTxID: Uint8Array,
  prevVout: number,
  scriptSig: Uint8Array,
  sequence: number,
  outputScript: Uint8Array,
  outputAmount: number,
  locktime: number,
): Uint8Array {
  return concat([
    le32(2),
    new Uint8Array([0x01]),
    prevTxID,
    le32(prevVout),
    varint(scriptSig.length),
    scriptSig,
    le32(sequence >>> 0),
    new Uint8Array([0x01]),
    le64(outputAmount),
    varint(outputScript.length),
    outputScript,
    le32(locktime),
  ]);
}

function buildRawTxOutputs(
  prevTxID: Uint8Array,
  prevVout: number,
  scriptSig: Uint8Array,
  sequence: number,
  outputs: TxOutput[],
  locktime: number,
): Uint8Array {
  return concat([
    le32(2),
    new Uint8Array([0x01]),
    prevTxID,
    le32(prevVout),
    varint(scriptSig.length),
    scriptSig,
    le32(sequence >>> 0),
    varint(outputs.length),
    concat(outputs.flatMap(o => [le64(o.amount), varint(o.script.length), o.script])),
    le32(locktime),
  ]);
}

function buildP2SHScriptSig(
  sig: Uint8Array,
  secret: Uint8Array | null,
  redeemScript: Uint8Array,
): Uint8Array {
  const parts: Uint8Array[] = [pushData(sig)];
  if (secret !== null) {
    parts.push(pushData(secret));
    parts.push(new Uint8Array([0x51])); // OP_1 — MINIMALDATA-compliant truthy
  } else {
    parts.push(new Uint8Array([0x00])); // OP_0 — pushes empty (false)
  }
  parts.push(pushData(redeemScript));
  return concat(parts);
}

function buildP2PKHScriptSig(sig: Uint8Array, pubKey: Uint8Array): Uint8Array {
  return concat([pushData(sig), pushData(pubKey)]);
}

// ── ECDSA signing ─────────────────────────────────────────────────────────────

async function ecdsaSign(
  sighash: Uint8Array,
  privKey: Uint8Array,
  sighashType: number,
): Promise<Uint8Array> {
  try {
    const signature = await secp256k1.signAsync(sighash, privKey);
    const sigCompact = signature.toCompactRawBytes();
    const sigDer = compactToDER(sigCompact);
    return new Uint8Array([...sigDer, sighashType]);
  } finally {
    zeroBytes(privKey);
  }
}

function compactToDER(compact: Uint8Array): Uint8Array {
  const r = compact.slice(0, 32);
  const s = compact.slice(32, 64);

  function encodeInt(b: Uint8Array): Uint8Array {
    let start = 0;
    while (start < b.length - 1 && b[start] === 0) start++;
    const trimmed = b.slice(start);
    return (trimmed[0] & 0x80) ? new Uint8Array([0, ...trimmed]) : trimmed;
  }

  const rEnc = encodeInt(r);
  const sEnc = encodeInt(s);
  const totalLen = 2 + rEnc.length + 2 + sEnc.length;
  const der = new Uint8Array(2 + totalLen);
  let pos = 0;
  der[pos++] = 0x30;
  der[pos++] = totalLen;
  der[pos++] = 0x02;
  der[pos++] = rEnc.length;
  der.set(rEnc, pos); pos += rEnc.length;
  der[pos++] = 0x02;
  der[pos++] = sEnc.length;
  der.set(sEnc, pos);
  return der;
}

function zeroBytes(arr: Uint8Array): void {
  crypto.getRandomValues(arr);
  arr.fill(0);
}

// ── Byte utilities ────────────────────────────────────────────────────────────

function le32(v: number): Uint8Array {
  const n = v >>> 0;
  return new Uint8Array([n & 0xff, (n >> 8) & 0xff, (n >> 16) & 0xff, (n >> 24) & 0xff]);
}

function le64(v: number): Uint8Array {
  const lo = v >>> 0;
  const hi = Math.floor(v / 0x100000000) >>> 0;
  return new Uint8Array([
    lo & 0xff, (lo >> 8) & 0xff, (lo >> 16) & 0xff, (lo >> 24) & 0xff,
    hi & 0xff, (hi >> 8) & 0xff, (hi >> 16) & 0xff, (hi >> 24) & 0xff,
  ]);
}

function varint(n: number): Uint8Array {
  if (n < 0xfd) return new Uint8Array([n]);
  if (n <= 0xffff) return new Uint8Array([0xfd, n & 0xff, (n >> 8) & 0xff]);
  if (n <= 0xffffffff) return new Uint8Array([0xfe, n & 0xff, (n >> 8) & 0xff, (n >> 16) & 0xff, (n >> 24) & 0xff]);
  throw new Error(`varint value too large: ${n}`);
}

function dsha256(data: Uint8Array): Uint8Array {
  return sha256(sha256(data));
}

function concat(parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((s, p) => s + p.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) { out.set(p, off); off += p.length; }
  return out;
}
