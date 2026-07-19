// FEE-DEADLINE-FIX: live, deadline-aware fee rates for UTXO claim/refund/funding.
//
// Root problem: claim/refund txs were built at a FIXED per-chain rate (bch2/bch/bc2=1, btc=10 sat/vB) with no
// live estimation and no bump path. In a fee spike a claim near its safety margin or a refund near its CLTV can
// sit unconfirmed past the deadline → the counterparty spends the other branch → fund loss. On the three
// first-seen chains a broadcast tx CANNOT be replaced, so the only defense is pricing it correctly UP FRONT and
// scaling the fee UP as the deadline nears. maxFeeRate(chain) caps the rate AND sizes the funding floor
// (minClaimableHtlcAmount), so a funded HTLC is always claimable even at the worst-case fee.
import type { Chain } from './swap-types';
import { getChainConfig, maxFeeRate, FEE_URGENCY_MAX_MULT, FEE_URGENCY_START_FACTOR } from './chain-config';

const FEE_CACHE_TTL_MS = 45_000;
const _cache = new Map<Chain, { rate: number; at: number }>();

function configFloor(chain: Chain): number {
  const f = getChainConfig(chain).feePerByte;
  return typeof f === 'number' && Number.isFinite(f) && f > 0 ? f : 1;
}

/**
 * Live network BASE fee rate (sat/vByte) for a chain. `estimate` performs the proxy round-trip
 * (proxy-side max(mempoolminfee, estimatesmartfee)); this floors it to the chain's static rate and clamps to
 * maxFeeRate, caching 45s. FAIL-SAFE: any error / non-finite / non-positive estimate → the static config floor,
 * so the result is NEVER below the config floor (≥ minrelay) and never zero. Deadline scaling is applied by the
 * caller via deadlineAwareFeeRate(). Cache is bypassable with force=true (e.g. after a min-relay-fee reject).
 */
export async function fetchFeeRate(
  chain: Chain,
  estimate: () => Promise<number | null | undefined>,
  force = false,
): Promise<number> {
  const floor = configFloor(chain);
  const cap = maxFeeRate(chain);
  const cached = _cache.get(chain);
  if (!force && cached && Date.now() - cached.at < FEE_CACHE_TTL_MS) return cached.rate;
  let rate = floor;
  try {
    const live = await estimate();
    if (typeof live === 'number' && Number.isFinite(live) && live > 0) {
      rate = Math.max(floor, Math.min(Math.ceil(live), cap));
    }
  } catch { /* fail-safe: keep the config floor */ }
  _cache.set(chain, { rate, at: Date.now() });
  return rate;
}

/** Test/reset hook. */
export function _clearFeeRateCache(): void { _cache.clear(); }

/**
 * Scale a base rate UP as a leg's remaining runway (seconds) approaches the safety margin (seconds). Returns
 * an integer sat/vByte clamped to [configFloor, maxFeeRate]. The ramp starts at FEE_URGENCY_START_FACTOR ×
 * margin of runway and reaches FEE_URGENCY_MAX_MULT × base at/inside the margin. The PRIMARY protection is the
 * live `baseRate` (which already tracks congestion via mempoolminfee/estimatesmartfee); this ramp is a
 * best-effort urgency boost on top. It keys off remainingSec/marginSec, which the caller derives from a
 * best-effort tip — a stale/under-reported tip only SHRINKS the multiplier back toward 1 (i.e. degrades to the
 * live base rate), never below it, so a lying proxy cannot underprice below the live network rate. Feed
 * chain-time-anchored values where available (never Date.now() on a timestamp CLTV). A non-finite/≤0 marginSec
 * or non-finite remainingSec ⇒ no ramp (mult=1), never a lower-than-base fee.
 */
export function deadlineAwareFeeRate(
  chain: Chain,
  baseRate: number,
  remainingSec: number,
  marginSec: number,
): number {
  const floor = configFloor(chain);
  const cap = maxFeeRate(chain);
  const base = Math.max(floor, Math.min(Number.isFinite(baseRate) ? baseRate : floor, cap));
  let mult = 1;
  if (Number.isFinite(remainingSec) && Number.isFinite(marginSec) && marginSec > 0) {
    if (remainingSec <= marginSec) {
      mult = FEE_URGENCY_MAX_MULT; // at/inside the margin: maximum urgency
    } else {
      const startAt = marginSec * FEE_URGENCY_START_FACTOR;
      if (remainingSec < startAt) {
        const frac = (startAt - remainingSec) / (startAt - marginSec); // 0..1 approaching the margin
        mult = 1 + frac * (FEE_URGENCY_MAX_MULT - 1);
      }
    }
  }
  return Math.max(floor, Math.min(Math.ceil(base * mult), cap));
}
