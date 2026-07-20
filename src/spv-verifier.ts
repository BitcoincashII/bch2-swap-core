// spv-verifier.ts — the trust-removal layer for R175. Uses the SPV core (core/spv.ts) + the proxy's new
// header/merkle methods to verify a funding tx's confirmation depth WITHOUT trusting the proxy's reported
// height. Every path is fail-closed: any missing/inconsistent data throws, and callers must treat a throw as
// "not safe, do not reveal the secret / do not commit funds".
//
// Scope: all four UTXO mainnets — BCH2 + BCH (ASERT, single anchor) and BTC + BC2 (classic 2016-block retarget,
// boundary-anchored checkpoint). Regtest keeps the legacy proxy-trusted path (spvSupported=false), so the test
// DEX is unaffected. Every chain's difficulty params are validated bit-exact vs that chain's real mainnet.
//
// SDK port (P1b step 1): copied VERBATIM from the app's src/electrum/spv-verifier.ts, changing ONLY (a) the
// client parameter type (ElectrumProxyClient -> the injected ChainClient interface), (b) import paths
// (./spv / ./chain-client), and (c) the REGTEST env read (Vite import.meta.env -> the SDK's portable
// globalThis.process.env pattern, mirroring chain-config.ts). No verification logic, threshold, or
// fail-closed direction is changed. The SPV trust anchor is the HARDCODED ./spv constants only — never a
// runtime/injected anchor for mainnet chains (fix #6); the sole injection path is __setSpvConfigForTests
// (test-only). getChainTimeSec/parseHeaderTimeSec are ported from the app's SwapExecute.tsx (fix #9).
import type { ChainClient } from './chain-client';
import {
  BCH2_MAINNET_ASERT, BCH2_MAINNET_CHECKPOINT, BCH_MAINNET_ASERT, BCH_MAINNET_CHECKPOINT,
  BTC_MAINNET_LEGACY, BTC_MAINNET_CHECKPOINT, BC2_MAINNET_LEGACY, BC2_MAINNET_CHECKPOINT,
  verifyHeaderChain, verifyLegacyChunk, verifyMerkleInclusion, blockHashInternal,
  type AsertParams, type LegacyParams, type Checkpoint, type BlockHeader,
} from './spv';

// SDK env change (fix #6): the app derived REGTEST from Vite's `import.meta.env.VITE_NETWORK`. The SDK is
// framework-agnostic (Node/bundler/browser), so read the same signal the SDK already uses in chain-config.ts:
// BCH2_SWAP_NETWORK=regtest via a portable globalThis.process.env probe (absent process => mainnet). Regtest
// disables SPV (SPV = {}), keeping the legacy proxy-trusted path; mainnet uses the hardcoded ./spv anchors.
const REGTEST = (globalThis as { process?: { env?: Record<string, string | undefined> } })
  .process?.env?.BCH2_SWAP_NETWORK === 'regtest';

// ASERT chains verify from a single fixed anchor; legacy chains verify the classic 2016-block retarget from a
// boundary-anchored checkpoint (its `bits` seed the first post-checkpoint nBits check; its height % 2016 == 0 so
// every retarget's (height-2016) lookback lands on the checkpoint or an already-verified boundary).
type SpvChain =
  | { mode: 'asert'; params: AsertParams; checkpoint: Checkpoint }
  | { mode: 'legacy'; params: LegacyParams; checkpoint: Checkpoint & { bits: number } };
function legacy(params: LegacyParams, cp: Checkpoint): SpvChain {
  if (cp.bits === undefined) throw new Error('legacy checkpoint missing bits');
  if (cp.height % params.interval !== 0) throw new Error('legacy checkpoint not on a retarget boundary');
  return { mode: 'legacy', params, checkpoint: { ...cp, bits: cp.bits } };
}
const SPV: Record<string, SpvChain> = REGTEST ? {} : {
  bch2: { mode: 'asert', params: BCH2_MAINNET_ASERT, checkpoint: BCH2_MAINNET_CHECKPOINT },
  bch: { mode: 'asert', params: BCH_MAINNET_ASERT, checkpoint: BCH_MAINNET_CHECKPOINT },
  btc: legacy(BTC_MAINNET_LEGACY, BTC_MAINNET_CHECKPOINT),
  bc2: legacy(BC2_MAINNET_LEGACY, BC2_MAINNET_CHECKPOINT),
};

/** True iff SPV depth verification is available for this chain (else callers use the legacy trusted path). */
export function spvSupported(chain: string): boolean { return chain in SPV; }

const HEADERS_PER_CALL = 500;

interface Verified { tipHeight: number; lastHashInternal: Uint8Array; lastTime: number; lastBits: number; headers: Map<number, BlockHeader>; }
const cache = new Map<string, Verified>();
const locks = new Map<string, Promise<unknown>>();

function reverseHexToInternal(displayHex: string): Uint8Array {
  const s = displayHex.startsWith('0x') ? displayHex.slice(2) : displayHex;
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(s.substr(i * 2, 2), 16);
  return out.reverse();
}
function splitHeaders(hex: string, count: number): Uint8Array[] {
  const out: Uint8Array[] = [];
  for (let i = 0; i < count; i++) {
    const chunk = hex.slice(i * 160, (i + 1) * 160);
    if (chunk.length !== 160) throw new Error('SPV: short header in batch');
    const b = new Uint8Array(80);
    for (let j = 0; j < 80; j++) b[j] = parseInt(chunk.substr(j * 2, 2), 16);
    out.push(b);
  }
  return out;
}

/** Serialize per-chain chain-extension so concurrent gates don't double-fetch or race the cache. */
async function withLock<T>(chain: string, fn: () => Promise<T>): Promise<T> {
  const prev = locks.get(chain) ?? Promise.resolve();
  let release!: () => void;
  const p = new Promise<void>((r) => { release = r; });
  locks.set(chain, prev.then(() => p));
  await prev.catch(() => { /* ignore prior failure */ });
  try { return await fn(); } finally { release(); }
}

/** Extend (or build) the verified header chain up to `tipHeight`, anchored at the hardcoded checkpoint. */
async function extendVerifiedChain(client: ChainClient, chain: string, tipHeight: number): Promise<Verified> {
  const cfg = SPV[chain];
  if (!cfg) throw new Error(`SPV not supported for ${chain}`);
  if (tipHeight <= cfg.checkpoint.height) throw new Error(`SPV: tip ${tipHeight} is at/below checkpoint ${cfg.checkpoint.height}`);
  return withLock(chain, async () => {
    let v = cache.get(chain);
    if (!v) v = {
      tipHeight: cfg.checkpoint.height,
      lastHashInternal: reverseHexToInternal(cfg.checkpoint.hashDisplay),
      lastTime: cfg.checkpoint.time,
      lastBits: cfg.mode === 'legacy' ? cfg.checkpoint.bits : 0,
      headers: new Map(),
    };
    // SPV-HEADER-TIME-001: the client wall clock is the trusted "now" the header future-bound is checked against.
    const trustedNowSec = Math.floor(Date.now() / 1000);
    while (v.tipHeight < tipHeight) {
      const start = v.tipHeight + 1;
      const want = Math.min(HEADERS_PER_CALL, tipHeight - v.tipHeight);
      const res = await client.getBlockHeaders(start, want);
      const raws = splitHeaders(res.hex, res.count);
      if (raws.length === 0) throw new Error('SPV: proxy returned no headers');
      // Up-to-11 timestamps immediately before `start`, so median-time-past stays continuous across fetched chunks.
      const priorTimes: number[] = [];
      for (let hh = start - 11; hh < start; hh++) {
        if (hh === cfg.checkpoint.height) priorTimes.push(cfg.checkpoint.time);
        else { const hd = v.headers.get(hh); if (hd) priorTimes.push(hd.time); }
      }
      let map: Map<number, BlockHeader>;
      if (cfg.mode === 'asert') {
        map = verifyHeaderChain(raws, start, v.lastHashInternal, cfg.params, v.lastTime, trustedNowSec, priorTimes); // throws on bad link/PoW/nBits/time
      } else {
        const vv = v;
        const cp = cfg.checkpoint;
        const getPriorTime = (height: number): number => {
          if (height === cp.height) return cp.time;
          const hd = vv.headers.get(height);
          if (!hd) throw new Error(`SPV: missing retarget lookback header ${height}`);
          return hd.time;
        };
        map = verifyLegacyChunk(raws, start, v.lastHashInternal, v.lastBits, v.lastTime, cfg.params, getPriorTime, trustedNowSec, priorTimes);
      }
      for (const [h, hdr] of map) v.headers.set(h, hdr);
      const lastHeight = start + raws.length - 1;
      const last = map.get(lastHeight)!;
      v.lastHashInternal = blockHashInternal(last.raw);
      v.lastTime = last.time;
      v.lastBits = last.bits;
      v.tipHeight = lastHeight;
    }
    cache.set(chain, v);
    return v;
  });
}

/**
 * Verify — WITHOUT trusting the proxy's height — that a funding tx is buried at a real confirmation depth.
 * Verifies (a) a PoW+ASERT header chain from the hardcoded checkpoint to `tipHeight`, and (b) a Merkle-inclusion
 * proof that `txid` (raw bytes `rawTxHex`) is in the block at `claimedHeight`, against that verified header.
 * Returns the VERIFIED confirmation count (tip − height + 1). Throws (fail-closed) on any inconsistency.
 */
export async function verifyConfirmations(
  client: ChainClient, chain: string, txid: string, claimedHeight: number, rawTxHex: string, tipHeight: number,
): Promise<number> {
  const cfg = SPV[chain];
  if (!cfg) throw new Error(`SPV not supported for ${chain}`);
  // Post-fork only (ASERT chains): a funding tx at/below the fork block is out of scope (pre-fork BC2 DAA).
  if (cfg.mode === 'asert' && claimedHeight < cfg.params.anchorHeight) throw new Error(`SPV: funding height ${claimedHeight} is pre-fork (< ${cfg.params.anchorHeight})`);
  if (!Number.isInteger(claimedHeight) || claimedHeight <= cfg.checkpoint.height) throw new Error(`SPV: funding height ${claimedHeight} at/below checkpoint`);
  if (claimedHeight > tipHeight) throw new Error(`SPV: funding height ${claimedHeight} above tip ${tipHeight}`);
  const v = await extendVerifiedChain(client, chain, tipHeight);
  const header = v.headers.get(claimedHeight);
  if (!header) throw new Error(`SPV: no verified header at height ${claimedHeight}`);
  const proof = await client.getMerkleProof(txid, claimedHeight);
  if (proof.block_height !== claimedHeight) throw new Error(`SPV: proof height ${proof.block_height} != ${claimedHeight}`);
  const provenTxid = verifyMerkleInclusion(rawTxHex, proof.merkle, proof.pos, header.merkleRoot); // throws on Merkle mismatch
  // R175-SPV (CRITICAL): bind the proven leaf to the REQUESTED txid. verifyMerkleInclusion only proves that
  // hash256(rawTxHex) is in the block — nothing ties rawTxHex to `txid`. Without this, a lying proxy could return
  // the bytes + branch of an UNRELATED deeply-buried tx so the proof passes while the real funding tx is shallow
  // (fabricated depth — exactly the attack R175 closes). Require the reconstructed txid to match. Fail closed.
  if (provenTxid.toLowerCase() !== txid.toLowerCase()) throw new Error(`SPV: proven txid ${provenTxid} != requested ${txid}`);
  // Bound the depth by the freshly-supplied tip too (understating via a lower proxy tip is fail-closed/safe) so a
  // stale monotonic cache tip after a reorg cannot overstate confirmations.
  return Math.min(v.tipHeight, tipHeight) - claimedHeight + 1;
}

/**
 * H1-LOCKTIME-PROXY-001: SPV-verify that `claimedHeight` (from the UNTRUSTED proxy) is a REAL, PoW-backed block
 * height BEFORE it is used as the base for a UTXO HTLC refund CLTV (locktime = claimedHeight + LOCKTIME_BLOCKS). A
 * hostile/MITM proxy that inflates the height would push the funder's OWN refund maturity ~forever, permanently
 * stranding the coins we are about to fund. extendVerifiedChain builds a PoW+difficulty header chain from the
 * hardcoded checkpoint up to `claimedHeight`; the proxy cannot forge valid headers for blocks that do not exist, so
 * an inflated/unverifiable height THROWS here (fail-closed). spvSupported chains only — callers gate on
 * spvSupported(chain). Same trust model as verifyConfirmations (R175). Returns the SPV-verified tip (>= claimed).
 */
export async function verifyFundingHeight(client: ChainClient, chain: string, claimedHeight: number): Promise<number> {
  const cfg = SPV[chain];
  if (!cfg) throw new Error(`SPV not supported for ${chain}`);
  if (!Number.isInteger(claimedHeight) || claimedHeight <= cfg.checkpoint.height) {
    throw new Error(`SPV: claimed funding height ${claimedHeight} at/below checkpoint ${cfg.checkpoint.height}`);
  }
  const v = await extendVerifiedChain(client, chain, claimedHeight); // throws if the proxy cannot supply valid PoW headers up to claimedHeight
  if (v.tipHeight < claimedHeight) throw new Error(`SPV: verified tip ${v.tipHeight} below claimed height ${claimedHeight}`);
  return v.tipHeight;
}

// R175-SPV (timing gates): the maximum age of the SPV-verified tip header for a TIMING/MARGIN decision. A proxy can
// under-report the height only by presenting a real-but-OLD tip; bounding the tip's PoW-validated timestamp to this
// window bounds under-reporting. WORST CASE is ~2x this window in blocks, not 1x: block nTime may legally run up to
// MAX_HEADER_FUTURE_SEC (+2h) ahead of real time (spv.ts), and this staleness check only bounds now - nTime <= 2h, so
// a maximally-future-stamped stale tip stacks the two windows to ~4h => ~24 blocks at 600s. The K=2 timelock margins
// absorb this with slack (the reveal gate keeps actual >= 48-24 = 24 blocks; the fund gates keep >= 168). A genuine
// chain stall beyond this window fails CLOSED (the gate blocks + retries) — safe, not a fund risk.
export const MAX_TIMING_TIP_STALENESS_SEC = 2 * 60 * 60; // 2h

/**
 * R175-SPV (timing gates): SPV-verify a height used in a TIMING/MARGIN decision (reveal-margin, fund-gate remaining
 * time), bounding BOTH proxy lies. extendVerifiedChain catches OVER-reporting — the proxy cannot forge PoW headers for
 * non-existent higher blocks, so an inflated/unverifiable tip THROWS (fail-closed). This ADDS an under-report guard:
 * the PoW-validated tip header's timestamp must be within `maxStalenessSec` of the client's trusted now, so a proxy
 * cannot present a real-but-STALE tip to make the client think fewer blocks have passed than really have — the vector
 * that would let the initiator reveal the secret too close to the responder's refund (double-dip). Fail-closed on a
 * stale tip or unverifiable PoW. spvSupported chains only (callers gate on spvSupported). Returns the verified tip.
 */
export async function spvVerifiedTipFresh(
  client: ChainClient, chain: string, claimedTip: number, maxStalenessSec: number = MAX_TIMING_TIP_STALENESS_SEC,
): Promise<number> {
  const cfg = SPV[chain];
  if (!cfg) throw new Error(`SPV not supported for ${chain}`);
  if (!Number.isInteger(claimedTip) || claimedTip <= cfg.checkpoint.height) {
    throw new Error(`SPV: claimed tip ${claimedTip} at/below checkpoint ${cfg.checkpoint.height}`);
  }
  const v = await extendVerifiedChain(client, chain, claimedTip); // throws if the proxy can't supply valid PoW headers up to claimedTip (over-report guard)
  if (v.tipHeight < claimedTip) throw new Error(`SPV: verified tip ${v.tipHeight} below claimed ${claimedTip}`);
  // Under-report guard: the PoW-validated tip's timestamp must be recent. Block nTime can run slightly ahead of real
  // time (consensus allows +2h), so a negative/small staleness is fine; only a genuinely-old tip is rejected.
  const stalenessSec = Math.floor(Date.now() / 1000) - v.lastTime;
  if (stalenessSec > maxStalenessSec) {
    throw new Error(`SPV: verified tip is stale (${Math.floor(stalenessSec / 60)}min > ${Math.floor(maxStalenessSec / 60)}min) — possible proxy height under-reporting`);
  }
  return v.tipHeight;
}

// R261-CHAINTIME-001 (MEGASWEEP-2 A): UTXO chain time from the tip block header's nTime (4-byte LITTLE-ENDIAN field at
// byte offset 68 = hex offset 136..144). A unix-timestamp CLTV is enforced on-chain by the block time (MTP/BIP113),
// NOT the local wall clock — so a secret-reveal margin on a timestamp-CLTV leg MUST anchor to chain time, not Date.now()
// (a clock skewed BEHIND would overstate the remaining time and reveal the secret within the real margin -> lose both
// legs). An INFLATED proxy timestamp -> SMALLER remaining -> fails CLOSED (safe); the deflate-direction residual is the
// already-accepted R175 proxy-trust class. Ported verbatim from the app's SwapExecute.tsx (fix #9).
export function parseHeaderTimeSec(headerHex: string): number | null {
  if (typeof headerHex !== 'string' || headerHex.length < 144) return null;
  const be = headerHex.slice(136, 144).match(/../g)?.reverse().join('');
  if (!be) return null;
  const t = parseInt(be, 16);
  return (Number.isInteger(t) && t >= 1e9 && t <= 1e11) ? t : null;
}
export async function getChainTimeSec(client: ChainClient): Promise<number | null> {
  try {
    const hdr = await Promise.race([
      client.request<{ height: number; hex: string }>('blockchain.headers.subscribe', []),
      new Promise<null>((res) => setTimeout(() => res(null), 15_000)),
    ]);
    return (hdr && typeof hdr.hex === 'string') ? parseHeaderTimeSec(hdr.hex) : null;
  } catch { return null; }
}

/** Test-only: reset the in-memory verified-chain cache. */
export function __resetSpvCacheForTests(): void { cache.clear(); locks.clear(); }
/** Test-only: inject SPV config for a chain (e.g. a fixture-derived checkpoint). */
export function __setSpvConfigForTests(chain: string, params: AsertParams, checkpoint: Checkpoint): void { SPV[chain] = { mode: 'asert', params, checkpoint }; }
/** Test-only: run just the header-chain verification and return the verified tip height. */
export async function __getVerifiedTipForTests(client: ChainClient, chain: string, tipHeight: number): Promise<number> {
  return (await extendVerifiedChain(client, chain, tipHeight)).tipHeight;
}
