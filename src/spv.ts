// spv.ts — client-side SPV verification for BCH2 (and BCH/BTC/BC2) UTXO chains.
//
// R175 (UTXO-DEPTH-PROXY): the proxy's reported block height / confirmation depth was TRUSTED when deciding a
// counterparty HTLC is buried deeply enough to safely reveal the secret. This module removes that trust: it
// verifies a proof-of-work header chain from a hardcoded per-chain checkpoint and verifies a Merkle-inclusion
// proof that a funding tx is in a block at a claimed height. Every function is fail-closed — callers must treat
// any throw / false as "not safe, do not reveal the secret".
//
// The BCH2 difficulty algorithm is ASERT (aserti3-2d). This is a BIT-EXACT port of the node's consensus code
// (bch2-bc2-fork: src/pow.cpp CalculateASERT / GetNextWorkRequired, src/arith_uint256.cpp Set/GetCompact,
// enforced at src/validation.cpp:5201 `block.nBits != GetNextWorkRequired(...)` → bad-diffbits). Because the node
// rejects any block whose nBits differs from the ASERT result, recomputing nBits and requiring equality is the
// correct consensus check and never rejects a valid header. The C++ semantics map onto BigInt cleanly:
//   • C++ integer `/` truncates toward zero  === BigInt `/`
//   • C++ arithmetic `>>` (floors)           === BigInt `>>`
//   • C++ uint16_t(x) (low 16 bits, two's-c) === BigInt `x & 0xFFFFn`
import { sha256 } from '@noble/hashes/sha256';

/** Double-SHA256 (a.k.a. hash256) — the block-hash and Merkle-node primitive. */
export function hash256(d: Uint8Array): Uint8Array { return sha256(sha256(d)); }

function concat(...arrs: Uint8Array[]): Uint8Array {
  let n = 0; for (const a of arrs) n += a.length;
  const out = new Uint8Array(n); let o = 0;
  for (const a of arrs) { out.set(a, o); o += a.length; }
  return out;
}
function reverse(a: Uint8Array): Uint8Array { const b = new Uint8Array(a.length); for (let i = 0; i < a.length; i++) b[i] = a[a.length - 1 - i]; return b; }
function equalBytes(a: Uint8Array, b: Uint8Array): boolean { if (a.length !== b.length) return false; let d = 0; for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i]; return d === 0; }
function hexToBytes(h: string): Uint8Array { const s = h.startsWith('0x') ? h.slice(2) : h; if (s.length % 2) throw new Error('odd hex'); const out = new Uint8Array(s.length / 2); for (let i = 0; i < out.length; i++) { const b = parseInt(s.substr(i * 2, 2), 16); if (Number.isNaN(b)) throw new Error('bad hex'); out[i] = b; } return out; }
/** Interpret 32 bytes as a little-endian 256-bit integer (arith_uint256 semantics). */
function leBytesToBigInt(a: Uint8Array): bigint { let n = 0n; for (let i = a.length - 1; i >= 0; i--) n = (n << 8n) | BigInt(a[i]); return n; }
function bitLength(n: bigint): number { return n <= 0n ? 0 : n.toString(2).length; }

// ── Compact "nBits" ⇄ target (exact port of arith_uint256::SetCompact / GetCompact) ─────────────────────────
export function targetFromCompact(nCompact: number): { target: bigint; negative: boolean; overflow: boolean } {
  const nSize = nCompact >>> 24;
  const nWordRaw = nCompact & 0x007fffff;
  let nWord = BigInt(nWordRaw);
  let target: bigint;
  if (nSize <= 3) { nWord >>= BigInt(8 * (3 - nSize)); target = nWord; }
  else { target = BigInt(nWordRaw) << BigInt(8 * (nSize - 3)); }
  const negative = nWord !== 0n && (nCompact & 0x00800000) !== 0;
  const overflow = nWord !== 0n && ((nSize > 34) || (nWord > 0xffn && nSize > 33) || (nWord > 0xffffn && nSize > 32));
  return { target, negative, overflow };
}

export function compactFromTarget(target: bigint): number {
  let nSize = Math.floor((bitLength(target) + 7) / 8);
  let low: bigint;
  if (nSize <= 3) low = (target & 0xffffffffffffffffn) << BigInt(8 * (3 - nSize));
  else low = (target >> BigInt(8 * (nSize - 3))) & 0xffffffffffffffffn;
  let nCompact = Number(low & 0xffffffffn) >>> 0;
  if (nCompact & 0x00800000) { nCompact >>>= 8; nSize++; }
  nCompact = (nCompact | (nSize << 24)) >>> 0;
  return nCompact;
}

// ── CalculateASERT (exact BigInt port of src/pow.cpp) ────────────────────────────────────────────────────────
export function calculateASERT(refTarget: bigint, spacing: bigint, timeDiff: bigint, heightDiff: bigint, powLimit: bigint, halfLife: bigint): bigint {
  if (heightDiff < 0n) throw new Error('ASERT: negative heightDiff');
  if (refTarget <= 0n || refTarget > powLimit) throw new Error('ASERT: refTarget out of range');
  // exponent = ((timeDiff - spacing*(heightDiff+1)) * 65536) / halfLife  (BigInt / truncates toward zero)
  const exponent = ((timeDiff - spacing * (heightDiff + 1n)) * 65536n) / halfLife;
  const shifts0 = exponent >> 16n;          // arithmetic (floor) shift
  const frac = exponent & 0xFFFFn;          // uint16_t(exponent)
  const factor = 65536n + ((195766423245049n * frac + 971821376n * frac * frac + 5127n * frac * frac * frac + (1n << 47n)) >> 48n);
  let nextTarget = refTarget * factor;
  const shifts = shifts0 - 16n;
  if (shifts <= 0n) nextTarget >>= (-shifts);
  else nextTarget <<= shifts;              // BigInt is unbounded; the > powLimit clamp below matches the ref's overflow→powLimit
  if (nextTarget === 0n) return 1n;
  if (nextTarget > powLimit) return powLimit;
  return nextTarget;
}

// ── Per-chain ASERT / PoW consensus parameters ───────────────────────────────────────────────────────────────
export interface AsertParams {
  anchorHeight: number;      // first post-fork block (gets anchorBits directly)
  anchorBits: number;        // compact nBits of the anchor block
  anchorParentTime: number;  // timestamp of the block BEFORE the anchor (the fork block)
  spacing: bigint;           // nPowTargetSpacing
  powLimit: bigint;
  halfLife: (nextHeight: number) => bigint; // GetASERTHalfLife(nextHeight)
}

// BCH2 mainnet — from src/kernel/chainparams.cpp (anchor 53201 / 0x1903a30c / parentTime 1772649180;
// half-life 3600s → 172800s at height ≥ 92736; powLimit 00000000ffffffff…; spacing 600).
export const BCH2_MAINNET_ASERT: AsertParams = {
  anchorHeight: 53201,
  anchorBits: 0x1903a30c,
  anchorParentTime: 1772649180,
  spacing: 600n,
  powLimit: 0x00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffn,
  halfLife: (h) => (h >= 92736 ? 172800n : 3600n),
};

// Bitcoin Cash mainnet — same aserti3-2d algorithm as BCH2, different anchor (the Nov-2020 ASERT activation):
// anchor 661647 / 0x1804dafe / parentTime 1605447844; fixed 2-day half-life. Validated bit-exact vs mainnet.
export const BCH_MAINNET_ASERT: AsertParams = {
  anchorHeight: 661647,
  anchorBits: 0x1804dafe,
  anchorParentTime: 1605447844,
  spacing: 600n,
  powLimit: 0x00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffn,
  halfLife: () => 172800n,
};

// ── Legacy (Bitcoin) 2016-block retarget — for BTC / BC2 ─────────────────────────────────────────────────────
export interface LegacyParams { powLimit: bigint; targetTimespan: bigint; interval: number; }
// BTC mainnet: 2-week timespan, 2016-block interval. Retarget math validated bit-exact vs mainnet (boundary 955584).
export const BTC_MAINNET_LEGACY: LegacyParams = { powLimit: 0x00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffn, targetTimespan: 1_209_600n, interval: 2016 };
// BitcoinII (BC2) mainnet: same classic Bitcoin DAA (BC2 is "BTC-like before the fork"). Validated bit-exact vs
// real BitcoinII mainnet (boundary 56448 → 0x183e88b6, via Dallas electrumx-bc2 COIN=BitcoinII NET=mainnet).
export const BC2_MAINNET_LEGACY: LegacyParams = { powLimit: 0x00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffn, targetTimespan: 1_209_600n, interval: 2016 };

/**
 * Expected compact nBits for the block at `height` under the classic Bitcoin DAA. Non-retarget blocks keep the
 * previous block's nBits; every `interval`-th block retargets from the timespan of the last interval. `prevBits`
 * and `prevTime` are block height-1; `firstTime` is block (height - interval) — needed only at retarget boundaries.
 */
export function getNextWorkRequiredLegacy(height: number, prevBits: number, prevTime: number, firstTime: number, p: LegacyParams): number {
  if (height % p.interval !== 0) return prevBits; // (mainnet: no testnet min-difficulty rule)
  let actual = BigInt(prevTime - firstTime);
  if (actual < p.targetTimespan / 4n) actual = p.targetTimespan / 4n;
  if (actual > p.targetTimespan * 4n) actual = p.targetTimespan * 4n;
  const { target } = targetFromCompact(prevBits);
  let next = (target * actual) / p.targetTimespan;
  if (next > p.powLimit) next = p.powLimit;
  return compactFromTarget(next);
}

export interface Checkpoint {
  height: number;
  hashDisplay: string;
  time: number;
  bits?: number; // legacy (retarget) chains only: the checkpoint's own nBits + it MUST sit on a retarget boundary
}

// Bitcoin mainnet checkpoint — MUST be a retarget boundary (height % 2016 == 0) so every later retarget's
// (height-2016) lookback lands on the checkpoint or an already-verified boundary. Refresh per release.
export const BTC_MAINNET_CHECKPOINT: Checkpoint = {
  height: 955584,
  hashDisplay: '00000000000000000001e265c627e0a27ad347deb4d6b921f249eddfbf78e011',
  time: 1782525607,
  bits: 0x17021a42,
};

// BitcoinII (BC2) mainnet checkpoint — also a retarget boundary (56448 % 2016 == 0). Refresh per release.
export const BC2_MAINNET_CHECKPOINT: Checkpoint = {
  height: 56448,
  hashDisplay: '0000000000000000303afa22bcc2736d86b5142a6c8d313f45df822ef44ae907',
  time: 1779492169,
  bits: 0x183e88b6,
};

// Recent buried BCH2 mainnet block, hardcoded as the TRUSTED anchor for header-chain verification. The client
// verifies a contiguous PoW+ASERT chain from here to the tip, so this bounds the header fetch. REFRESH PER
// RELEASE to keep the fetch small. Validated bit-exact at capture (2026-07-07, electrum.bch2.org; see spv.test).
export const BCH2_MAINNET_CHECKPOINT: Checkpoint = {
  height: 71000,
  hashDisplay: '0000000000000009271d1b0554f651d7102b8f7622f74c50eb20963f62910117',
  time: 1783333735,
};

// Bitcoin Cash mainnet checkpoint (buried; refresh per release). Validated at capture (2026-07-07, bch.imaginary.cash).
export const BCH_MAINNET_CHECKPOINT: Checkpoint = {
  height: 958521,
  hashDisplay: '000000000000000001d83f6025669747451cc3d676f9577044f87f6b66410b00',
  time: 1783373746,
};

/** Verify headers starting immediately AFTER a trusted checkpoint (headersAfterCp[0] is block cp.height+1). */
export function verifyChainFromCheckpoint(headersAfterCp: Uint8Array[], cp: Checkpoint, p: AsertParams, trustedNowSec: number): Map<number, BlockHeader> {
  // R175-SPV: the checkpoint (and therefore everything verified above it) MUST be post-fork — pre-fork BC2
  // blocks use a different DAA and are out of scope. anchorHeight = forkBlock+1, so cp.height ≥ anchorHeight-1.
  if (cp.height < p.anchorHeight - 1) throw new Error(`SPV: checkpoint ${cp.height} is pre-fork (< ${p.anchorHeight - 1})`);
  const cpHashInternal = reverse(hexToBytes(cp.hashDisplay)); // display hash → internal (LE) order
  return verifyHeaderChain(headersAfterCp, cp.height + 1, cpHashInternal, p, cp.time, trustedNowSec, [cp.time]);
}

/** Expected compact nBits for the block at height prevHeight+1, given its parent's height+timestamp. */
export function getNextWorkRequiredASERT(prevHeight: number, prevTime: number, p: AsertParams): number {
  const nextHeight = prevHeight + 1;
  // R175-SPV: ONLY post-fork BCH2 blocks (height ≥ anchorHeight = forkBlock+1) use ASERT. Blocks at/below the
  // fork block (53200) are pre-fork BC2 blocks under the old Bitcoin DAA — never verify them here. Fail closed.
  if (nextHeight < p.anchorHeight) throw new Error(`SPV: height ${nextHeight} is at/below the fork block (pre-fork BC2, not ASERT)`);
  if (nextHeight === p.anchorHeight) return p.anchorBits;
  const { target: refTarget, negative, overflow } = targetFromCompact(p.anchorBits);
  if (negative || overflow || refTarget === 0n) throw new Error('ASERT: bad anchor bits');
  const timeDiff = BigInt(prevTime - p.anchorParentTime);
  const heightDiff = BigInt(prevHeight - p.anchorHeight);
  return compactFromTarget(calculateASERT(refTarget, p.spacing, timeDiff, heightDiff, p.powLimit, p.halfLife(nextHeight)));
}

// ── Block header parse + PoW check ───────────────────────────────────────────────────────────────────────────
export interface BlockHeader {
  version: number;
  prevHash: Uint8Array;   // internal (little-endian) byte order
  merkleRoot: Uint8Array; // internal (little-endian) byte order
  time: number;
  bits: number;
  nonce: number;
  raw: Uint8Array;        // the 80 bytes
}

export function parseHeader(raw: Uint8Array): BlockHeader {
  if (raw.length !== 80) throw new Error('header must be exactly 80 bytes');
  const dv = new DataView(raw.buffer, raw.byteOffset, 80);
  return {
    version: dv.getInt32(0, true),
    prevHash: raw.slice(4, 36),
    merkleRoot: raw.slice(36, 68),
    time: dv.getUint32(68, true),
    bits: dv.getUint32(72, true),
    nonce: dv.getUint32(76, true),
    raw: raw.slice(0, 80),
  };
}

/** Block hash in internal (LE) byte order. Display hash = reverse(this). */
export function blockHashInternal(raw: Uint8Array): Uint8Array { return hash256(raw); }

/** True iff the header's PoW satisfies its own nBits and nBits is within powLimit. */
export function checkPoW(raw: Uint8Array, bits: number, powLimit: bigint): boolean {
  const { target, negative, overflow } = targetFromCompact(bits);
  if (negative || overflow || target === 0n || target > powLimit) return false;
  return leBytesToBigInt(hash256(raw)) <= target;
}

// ── Merkle inclusion (Electrum transaction.get_merkle format) ────────────────────────────────────────────────
/** Recompute the Merkle root (internal order) from a txid (internal order) + branch (internal order) + position. */
export function merkleRootFromBranch(txidInternal: Uint8Array, branchInternal: Uint8Array[], pos: number): Uint8Array {
  let h = txidInternal;
  let index = pos >>> 0;
  for (const sib of branchInternal) {
    h = (index & 1) ? hash256(concat(sib, h)) : hash256(concat(h, sib));
    index >>>= 1;
  }
  return h;
}

/** Read a Bitcoin varint at `off`; returns [value, bytesConsumed]. */
function readVarIntAt(tx: Uint8Array, off: number): [number, number] {
  const b = tx[off];
  if (b === undefined) throw new Error('SPV: varint out of range');
  if (b < 0xfd) return [b, 1];
  if (b === 0xfd) return [tx[off + 1] | (tx[off + 2] << 8), 3];
  if (b === 0xfe) return [(tx[off + 1] | (tx[off + 2] << 8) | (tx[off + 3] << 16) | (tx[off + 4] << 24)) >>> 0, 5];
  let v = 0; for (let i = 0; i < 6; i++) v += tx[off + 1 + i] * 2 ** (8 * i); // low 6 bytes (counts never exceed this)
  return [v, 9];
}

/**
 * R281-SEGWIT-003: return the LEGACY (txid) serialization of a tx, stripping BIP144 witness data if present. A
 * SegWit tx is nVersion(4)|0x00 marker|0x01 flag|inputs|outputs|witness|nLockTime(4); its TXID — the Merkle-tree
 * leaf — is hash256 over nVersion|inputs|outputs|nLockTime, EXCLUDING the witness. Without this, a counterparty who
 * funds a BTC/BC2 HTLC from SegWit UTXOs produces a witness-serialized funding tx whose hash256 = the WTXID != txid,
 * so the SPV inclusion proof would never match and the swap would fail-closed (liveness loss) even though the
 * funding is real. Returns the input unchanged when not SegWit (all bch2/bch txs, and any legacy btc/bc2 tx). Throws
 * on malformed structure — the caller then fails closed, which is exactly today's behavior, so this can only ADD
 * liveness, never a fund-loss (a wrong strip fails the Merkle/txid-binding check just like the un-stripped bytes do).
 */
function legacySerialization(tx: Uint8Array): Uint8Array {
  if (tx.length < 10 || tx[4] !== 0x00) return tx; // a real non-witness tx has >=1 input, so byte 4 is never 0x00
  if (tx[5] !== 0x01) throw new Error('SPV: SegWit marker (0x00) without a valid flag (0x01)');
  const inputsStart = 6;
  let o = inputsStart;
  const [nIn, nInLen] = readVarIntAt(tx, o); o += nInLen;
  if (nIn === 0 || nIn > 100_000) throw new Error('SPV: implausible input count in SegWit tx');
  for (let i = 0; i < nIn; i++) {
    o += 36; // prevout (32-byte txid + 4-byte vout)
    const [ssLen, ssLenLen] = readVarIntAt(tx, o); o += ssLenLen + ssLen + 4; // scriptSig + nSequence(4)
    if (o > tx.length) throw new Error('SPV: input overruns SegWit tx');
  }
  const [nOut, nOutLen] = readVarIntAt(tx, o); o += nOutLen;
  if (nOut > 100_000) throw new Error('SPV: implausible output count in SegWit tx');
  for (let i = 0; i < nOut; i++) {
    o += 8; // 8-byte value
    const [spkLen, spkLenLen] = readVarIntAt(tx, o); o += spkLenLen + spkLen;
    if (o > tx.length) throw new Error('SPV: output overruns SegWit tx');
  }
  const outputsEnd = o; // witness follows (skipped), then the trailing 4-byte nLockTime
  if (tx.length < outputsEnd + 4) throw new Error('SPV: SegWit tx too short for nLockTime');
  return concat(tx.slice(0, 4), tx.slice(inputsStart, outputsEnd), tx.slice(tx.length - 4));
}

/**
 * Verify a funding tx is included in a block whose header Merkle root is `merkleRootInternal`.
 * `rawTxHex` = the raw tx; a SegWit (BIP144) serialization is stripped to its legacy form so hash256 === txid (the
 * Merkle-tree leaf). `merkleHexReversed` / `pos` come straight from Electrum `blockchain.transaction.get_merkle`
 * (hashes are in display/reversed hex). Returns the display txid on success; throws on any mismatch (fail-closed).
 */
export function verifyMerkleInclusion(rawTxHex: string, merkleHexReversed: string[], pos: number, merkleRootInternal: Uint8Array): string {
  const rawTx = legacySerialization(hexToBytes(rawTxHex));
  const txidInternal = hash256(rawTx);
  const branchInternal = merkleHexReversed.map((h) => reverse(hexToBytes(h)));
  const root = merkleRootFromBranch(txidInternal, branchInternal, pos);
  if (!equalBytes(root, merkleRootInternal)) throw new Error('Merkle inclusion proof does not match the block header merkle root');
  return bytesToHex(reverse(txidInternal));
}

function bytesToHex(a: Uint8Array): string { let s = ''; for (const b of a) s += b.toString(16).padStart(2, '0'); return s; }

// ── Contiguous header-chain verification ─────────────────────────────────────────────────────────────────────
/**
 * Verify a contiguous run of headers `[startHeight … startHeight+headers.length-1]` descends by PoW from a
 * trusted checkpoint. `prevHashOfStart` is the internal-order block hash the FIRST header must point back to
 * (the checkpoint's own hash, verified by the caller). Each header must: (1) link to its predecessor,
 * (2) satisfy its own PoW, (3) carry the EXACT ASERT nBits for its height. Throws on the first failure.
 * Returns the verified headers keyed by height.
 */
// SPV-HEADER-TIME-001: header timestamps MUST be bounded, or a malicious proxy can feed an inflated (far-future)
// parent timestamp that collapses the ASERT-required target to powLimit — then mine a fake fork at difficulty ~1
// to fabricate confirmation depth. `trustedNowSec` = the caller's wall clock; `priorTimes` = up to 11 timestamps
// immediately before startHeight, so median-time-past is continuous across fetched chunks.
const MAX_HEADER_FUTURE_SEC = 7200; // 2h — Bitcoin's block-timestamp future limit

function medianTimePast(window: number[]): number {
  const w = window.slice(-11).slice().sort((a, b) => a - b);
  return w[Math.floor(w.length / 2)];
}

export function verifyHeaderChain(
  headers: Uint8Array[],
  startHeight: number,
  prevHashOfStart: Uint8Array,
  p: AsertParams,
  prevTimeOfStart: number,
  trustedNowSec: number,
  priorTimes: number[] = [],
): Map<number, BlockHeader> {
  const out = new Map<number, BlockHeader>();
  let expectedPrevHash = prevHashOfStart;
  let prevTime = prevTimeOfStart;
  let prevHeight = startHeight - 1;
  const times = priorTimes.slice(-11); // rolling median-time-past window
  for (let i = 0; i < headers.length; i++) {
    const height = startHeight + i;
    const h = parseHeader(headers[i]);
    if (!equalBytes(h.prevHash, expectedPrevHash)) throw new Error(`header ${height}: prevHash does not link to ${prevHeight}`);
    if (!checkPoW(h.raw, h.bits, p.powLimit)) throw new Error(`header ${height}: proof-of-work below target`);
    // Future-time bound: caps ASERT target inflation to ~2^(2h/halfLife) ≈ negligible — closes the difficulty-collapse.
    if (h.time > trustedNowSec + MAX_HEADER_FUTURE_SEC) throw new Error(`header ${height}: timestamp ${h.time} exceeds trusted now + 2h`);
    // Median-time-past monotonicity (once 11 predecessors are known): blocks the backwards/oscillating timestamp game.
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

/**
 * Legacy (Bitcoin-DAA) analogue of verifyHeaderChain for BTC/BC2. Same link + PoW checks, but the nBits rule is
 * the 2016-block retarget: non-boundary blocks must equal the previous block's nBits; a boundary block
 * (height % interval == 0) recomputes from the interval timespan, which needs the time of block (height-interval)
 * — supplied via `getPriorTime` (resolves the checkpoint or any already-verified header). `prevBitsOfStart`/
 * `prevTimeOfStart` are the header immediately before `startHeight` (i.e. the checkpoint, or the prior chunk's
 * last header). Throws (fail-closed) on the first failure. Requires the checkpoint to sit on a retarget boundary
 * so every `height-interval` lookback resolves.
 */
export function verifyLegacyChunk(
  headers: Uint8Array[], startHeight: number, prevHashOfStart: Uint8Array, prevBitsOfStart: number,
  prevTimeOfStart: number, p: LegacyParams, getPriorTime: (height: number) => number,
  trustedNowSec: number, priorTimes: number[] = [],
): Map<number, BlockHeader> {
  const out = new Map<number, BlockHeader>();
  let expectedPrevHash = prevHashOfStart;
  let prevBits = prevBitsOfStart;
  let prevTime = prevTimeOfStart;
  let prevHeight = startHeight - 1;
  const times = priorTimes.slice(-11); // rolling median-time-past window
  for (let i = 0; i < headers.length; i++) {
    const height = startHeight + i;
    const h = parseHeader(headers[i]);
    if (!equalBytes(h.prevHash, expectedPrevHash)) throw new Error(`legacy header ${height}: prevHash does not link to ${prevHeight}`);
    if (!checkPoW(h.raw, h.bits, p.powLimit)) throw new Error(`legacy header ${height}: proof-of-work below target`);
    // Same consensus timestamp bounds as the ASERT path (SPV-HEADER-TIME-001). Less exploitable here (the 4x/2016
    // retarget clamp caps difficulty collapse) but enforced for parity + backwards-timestamp defense.
    if (h.time > trustedNowSec + MAX_HEADER_FUTURE_SEC) throw new Error(`legacy header ${height}: timestamp ${h.time} exceeds trusted now + 2h`);
    if (times.length >= 11 && h.time <= medianTimePast(times)) throw new Error(`legacy header ${height}: timestamp ${h.time} not above median-time-past`);
    let expected: number;
    if (height % p.interval !== 0) {
      expected = prevBits;
    } else {
      const firstTime = getPriorTime(height - p.interval); // throws if the lookback isn't available
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
