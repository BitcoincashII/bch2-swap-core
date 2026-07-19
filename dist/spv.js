import { sha256 } from '@noble/hashes/sha256';

// src/spv.ts
function hash256(d) {
  return sha256(sha256(d));
}
function concat(...arrs) {
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
function hexToBytes(h) {
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
function verifyChainFromCheckpoint(headersAfterCp, cp, p, trustedNowSec) {
  if (cp.height < p.anchorHeight - 1) throw new Error(`SPV: checkpoint ${cp.height} is pre-fork (< ${p.anchorHeight - 1})`);
  const cpHashInternal = reverse(hexToBytes(cp.hashDisplay));
  return verifyHeaderChain(headersAfterCp, cp.height + 1, cpHashInternal, p, cp.time, trustedNowSec, [cp.time]);
}
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
  return hash256(raw);
}
function checkPoW(raw, bits, powLimit) {
  const { target, negative, overflow } = targetFromCompact(bits);
  if (negative || overflow || target === 0n || target > powLimit) return false;
  return leBytesToBigInt(hash256(raw)) <= target;
}
function merkleRootFromBranch(txidInternal, branchInternal, pos) {
  let h = txidInternal;
  let index = pos >>> 0;
  for (const sib of branchInternal) {
    h = index & 1 ? hash256(concat(sib, h)) : hash256(concat(h, sib));
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
  return concat(tx.slice(0, 4), tx.slice(inputsStart, outputsEnd), tx.slice(tx.length - 4));
}
function verifyMerkleInclusion(rawTxHex, merkleHexReversed, pos, merkleRootInternal) {
  const rawTx = legacySerialization(hexToBytes(rawTxHex));
  const txidInternal = hash256(rawTx);
  const branchInternal = merkleHexReversed.map((h) => reverse(hexToBytes(h)));
  const root = merkleRootFromBranch(txidInternal, branchInternal, pos);
  if (!equalBytes(root, merkleRootInternal)) throw new Error("Merkle inclusion proof does not match the block header merkle root");
  return bytesToHex(reverse(txidInternal));
}
function bytesToHex(a) {
  let s = "";
  for (const b of a) s += b.toString(16).padStart(2, "0");
  return s;
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

export { BC2_MAINNET_CHECKPOINT, BC2_MAINNET_LEGACY, BCH2_MAINNET_ASERT, BCH2_MAINNET_CHECKPOINT, BCH_MAINNET_ASERT, BCH_MAINNET_CHECKPOINT, BTC_MAINNET_CHECKPOINT, BTC_MAINNET_LEGACY, blockHashInternal, calculateASERT, checkPoW, compactFromTarget, getNextWorkRequiredASERT, getNextWorkRequiredLegacy, hash256, merkleRootFromBranch, parseHeader, targetFromCompact, verifyChainFromCheckpoint, verifyHeaderChain, verifyLegacyChunk, verifyMerkleInclusion };
