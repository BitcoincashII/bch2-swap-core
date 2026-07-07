import * as secp256k1 from '@noble/secp256k1';
import { sha256 } from '@noble/hashes/sha256';
import { ripemd160 } from '@noble/hashes/ripemd160';

// src/htlc-builder.ts
function hash160(data) {
  return ripemd160(sha256(data));
}

// src/htlc-builder.ts
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
  for (const [name, v] of [["inputSatoshis", inputSatoshis], ["htlcSatoshis", htlcSatoshis], ["feeSatoshis", feeSatoshis]]) {
    if (!Number.isInteger(v) || v <= 0) throw new Error(`${name} must be a positive integer, got ${v}`);
  }
  const CLAIMABLE_FLOOR = DEFAULT_FEE_SATOSHIS + DUST_SATOSHIS;
  if (htlcSatoshis < CLAIMABLE_FLOOR) {
    throw new Error(`htlcSatoshis ${htlcSatoshis} is below the claimable floor ${CLAIMABLE_FLOOR} (fee + dust) \u2014 the funded HTLC would be unspendable by both the claim and refund branches`);
  }
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

export { BCH_SWAP_BCH2_CSV_NSEQUENCE, BCH_SWAP_BCH_CSV_NSEQUENCE, DEFAULT_FEE_SATOSHIS, DUST_SATOSHIS, HTLC_CSV_BLOCKS, MAINNET_BC2_SWAP_BC2_CSV, MAINNET_BC2_SWAP_BCH2_CSV, MAINNET_BCH_SWAP_BCH2_CSV, MAINNET_BCH_SWAP_BCH_CSV, MAINNET_BTC_SWAP_BCH2_CSV, MAINNET_BTC_SWAP_BTC_CSV, SEQ_LOCKTIME_GRANULARITY, SEQ_LOCKTIME_TYPE_FLAG, SIGHASH_ALL, SIGHASH_ALL_FORKID, bip143Sighash, bip143SighashOutputs, buildClaimTx, buildFundingTx, buildRedeemScript, buildRefundTx, encodeCSV, extractSecretFromScriptSig, legacySighashOutputs, legacySighashSingle, p2pkhScriptPubKey, p2shScriptPubKey, pushData };
