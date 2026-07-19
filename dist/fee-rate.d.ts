import { C as Chain } from './swap-types-s0IAnIBY.js';

/**
 * Live network BASE fee rate (sat/vByte) for a chain. `estimate` performs the proxy round-trip
 * (proxy-side max(mempoolminfee, estimatesmartfee)); this floors it to the chain's static rate and clamps to
 * maxFeeRate, caching 45s. FAIL-SAFE: any error / non-finite / non-positive estimate → the static config floor,
 * so the result is NEVER below the config floor (≥ minrelay) and never zero. Deadline scaling is applied by the
 * caller via deadlineAwareFeeRate(). Cache is bypassable with force=true (e.g. after a min-relay-fee reject).
 */
declare function fetchFeeRate(chain: Chain, estimate: () => Promise<number | null | undefined>, force?: boolean): Promise<number>;
/** Test/reset hook. */
declare function _clearFeeRateCache(): void;
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
declare function deadlineAwareFeeRate(chain: Chain, baseRate: number, remainingSec: number, marginSec: number): number;

export { _clearFeeRateCache, deadlineAwareFeeRate, fetchFeeRate };
