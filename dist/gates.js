import { sha256 } from '@noble/hashes/sha256';
import '@noble/secp256k1';
import { ripemd160 } from '@noble/hashes/ripemd160';
import { Contract, ethers } from 'ethers';

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
var REGTEST = globalThis.process?.env?.BCH2_SWAP_NETWORK === "regtest";
function legacy(params, cp) {
  if (cp.bits === void 0) throw new Error("legacy checkpoint missing bits");
  if (cp.height % params.interval !== 0) throw new Error("legacy checkpoint not on a retarget boundary");
  return { mode: "legacy", params, checkpoint: { ...cp, bits: cp.bits } };
}
var SPV = REGTEST ? {} : {
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

// src/chain-config.ts
var REGTEST2 = globalThis.process?.env?.BCH2_SWAP_NETWORK === "regtest";
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
    addressPrefix: REGTEST2 ? "bchreg" : "bitcoincash",
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
    p2shVersionByte: REGTEST2 ? 196 : 5,
    p2pkhVersionByte: REGTEST2 ? 111 : 0,
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
    p2shVersionByte: REGTEST2 ? 196 : 5,
    p2pkhVersionByte: REGTEST2 ? 111 : 0,
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
  // ~36 hours (R-TIMELOCK-K: raised from 144 so the ÷K responder fund gate still leaves a funding window)
  responder: 72
  // ~12 hours (R-TIMELOCK-K: kept at 12h — the initiator's claim window on this leg needs K*margin + confs)
};
var TIMELOCK_SAFETY_K = 2;
var CLAIM_MARGIN_BLOCKS = 24;
function minSecondsUntilRefund(blocksRemaining, chainBlockSec) {
  return blocksRemaining * chainBlockSec / TIMELOCK_SAFETY_K;
}

// src/htlc-builder.ts
function hexToBytes2(hex) {
  if (hex.length % 2 !== 0) throw new Error("Invalid hex: odd length");
  if (!/^[0-9a-fA-F]*$/.test(hex)) throw new Error("Invalid hex: non-hex characters");
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
  }
  return bytes;
}
function bytesToHex2(bytes) {
  return Array.from(bytes).map((b) => b.toString(16).padStart(2, "0")).join("");
}
function reverseBytes(bytes) {
  const r = new Uint8Array(bytes.length);
  for (let i = 0; i < bytes.length; i++) r[i] = bytes[bytes.length - 1 - i];
  return r;
}
function hash2562(data) {
  return sha256(sha256(data));
}
function hash160(data) {
  return ripemd160(sha256(data));
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
function htlcScripthash(redeemScript) {
  const scriptHash = hash160(redeemScript);
  const p2shScript = new Uint8Array([169, 20, ...scriptHash, 135]);
  const hash = sha256(p2shScript);
  return bytesToHex2(reverseBytes(hash));
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
    tx = hexToBytes2(rawTxHex);
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
  const computedTxid = bytesToHex2(reverseBytes(hash2562(stripped)));
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
function getHTLCScripthash(redeemScript) {
  return htlcScripthash(redeemScript);
}

// src/timelock-gates.ts
var CLAIM_MARGIN_SEC = CLAIM_MARGIN_BLOCKS * 600;
function marginTooTight(remainingBlocks, blockSec, requiredSec) {
  return minSecondsUntilRefund(remainingBlocks, blockSec) < requiredSec;
}
function claimWindowTooTight(remainingBlocks) {
  return remainingBlocks < CLAIM_MARGIN_BLOCKS * TIMELOCK_SAFETY_K;
}
function orderingUnsafe(responderRemainingBlocks, theirBlockSec, ownRemainingBlocks, myBlockSec, claimMarginSec = CLAIM_MARGIN_SEC) {
  const responderLegRemainingSec = responderRemainingBlocks * theirBlockSec;
  const initiatorLegRemainingSec = minSecondsUntilRefund(ownRemainingBlocks, myBlockSec);
  return responderLegRemainingSec + claimMarginSec >= initiatorLegRemainingSec;
}
var UTXO_REF_BLOCK_SEC = chainConfigs.bch2.avgBlockTimeSec;
var RESPONDER_LOCK_SEC = LOCKTIME_BLOCKS.responder * UTXO_REF_BLOCK_SEC;
var EVM_CLAIM_MARGIN_SEC = 24 * UTXO_REF_BLOCK_SEC;
var HTLC_ABI = [
  "function lock(address recipient, address token, uint256 amount, bytes32 hashLock, uint256 timeLock) payable returns (bytes32)",
  "function claim(bytes32 id, bytes32 secret)",
  "function refund(bytes32 id)",
  "function getSwap(bytes32 id) view returns (address initiator, address recipient, address token, uint256 amount, bytes32 hashLock, uint256 timeLock, bool claimed, bool refunded)",
  "event Locked(bytes32 indexed id, address indexed initiator, address recipient, address token, uint256 amount, bytes32 hashLock, uint256 timeLock)",
  "event Claimed(bytes32 indexed id, bytes32 secret)",
  "event Refunded(bytes32 indexed id)"
];
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
  return "a914" + bytesToHex2(hash160(redeemScript)) + "87";
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
async function reverifyBuriedOutpoint(client, chain, redeemScript, recordedOutpoint, label) {
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
  return { freshHeight, vReqConf, sameOutpoint, rawFundingTx };
}
async function assertRevealSafe(client, p) {
  const { role, theirChain, counterpartyRedeemScript, recordedOutpoint, counterpartyLocktime } = p;
  const buried = await reverifyBuriedOutpoint(client, theirChain, counterpartyRedeemScript, recordedOutpoint, "reveal");
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
  const buried = await reverifyBuriedOutpoint(client, theirChain, counterpartyRedeemScript, recordedOutpoint, "fund");
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
async function assertOrderingSafe(myChainClient, p) {
  const { theirChain, myChain, remainingBlocks, myLocktime, myFundingTxid } = p;
  const theirBlockSec = chainConfigs[theirChain]?.avgBlockTimeSec;
  const myBlockSec = chainConfigs[myChain]?.avgBlockTimeSec;
  if (!Number.isFinite(theirBlockSec) || (theirBlockSec ?? 0) <= 0 || !Number.isFinite(myBlockSec) || (myBlockSec ?? 0) <= 0) {
    throw new GateFailure("ordering: chain block-time configuration is invalid \u2014 cannot verify swap timelock safety", "abort");
  }
  if (claimWindowTooTight(remainingBlocks)) {
    throw new GateFailure(
      `ordering: counterparty HTLC locktime nearly expired (${remainingBlocks} blocks remaining) \u2014 too risky to claim; the counterparty may refund before your claim confirms`,
      "abort"
    );
  }
  let ownLocktime = myLocktime;
  if (ownLocktime === void 0) {
    if (myFundingTxid) {
      throw new GateFailure("ordering: your funded HTLC locktime is unrecoverable locally \u2014 aborting to avoid an unsafe claim (recover via the funding txid)", "abort");
    }
    return;
  }
  let myHeight = 0;
  try {
    myHeight = (await myChainClient.getBlockHeight())[0];
  } catch {
    myHeight = 0;
  }
  if (!myHeight || myHeight <= 0) {
    throw new GateFailure("ordering: your chain block height is unavailable \u2014 aborting to avoid an unsafe claim", "abort");
  }
  if (spvSupported(myChain)) {
    try {
      myHeight = await spvVerifiedTipFresh(myChainClient, myChain, myHeight);
    } catch {
    }
  }
  if (orderingUnsafe(remainingBlocks, theirBlockSec, ownLocktime - myHeight, myBlockSec, CLAIM_MARGIN_SEC)) {
    throw new GateFailure(
      "ordering: the responder HTLC refund does not mature safely before your own leg minus the claim margin \u2014 aborting to prevent double-spend risk",
      "abort"
    );
  }
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

export { GateFailure, aggregateChainNow, assertEvmLegBuriedForFunding, assertEvmRevealSafe, assertLegBuriedForFunding, assertOrderingSafe, assertRevealSafe, validateEvmTimeLock };
