import { describe, it, expect, beforeEach } from 'vitest';
import { fetchFeeRate, deadlineAwareFeeRate, _clearFeeRateCache } from './fee-rate';
import { maxFeeRate, getChainConfig, FEE_URGENCY_MAX_MULT } from './chain-config';

// FEE-DEADLINE-FIX: the fee source + deadline ramp must NEVER produce a fee below the config floor (min-relay
// risk / stuck tx) or above maxFeeRate (which the funding floor guaranteed affordable), and must FAIL-SAFE to
// the floor when live estimation is unavailable. The floor<->maxFeeRate clamp is the fund-safety invariant.

const FLOOR_BCH2 = getChainConfig('bch2').feePerByte ?? 1; // 1
const FLOOR_BTC = getChainConfig('btc').feePerByte ?? 1;   // 10
const CAP_BCH2 = maxFeeRate('bch2'); // 20
const CAP_BTC = maxFeeRate('btc');   // 100
const MARGIN = 4 * 3600;             // 4h, == CLAIM_MARGIN_SEC

describe('deadlineAwareFeeRate', () => {
  it('far from the deadline → base rate (mult 1), clamped to [floor, cap]', () => {
    // remaining well beyond FEE_URGENCY_START_FACTOR*margin ⇒ no ramp
    expect(deadlineAwareFeeRate('bch2', 3, MARGIN * 100, MARGIN)).toBe(3);
    expect(deadlineAwareFeeRate('btc', 15, MARGIN * 100, MARGIN)).toBe(15);
  });

  it('at/inside the safety margin → base * MAX_MULT, clamped to cap', () => {
    expect(deadlineAwareFeeRate('bch2', 3, MARGIN, MARGIN)).toBe(3 * FEE_URGENCY_MAX_MULT); // 9, under cap 20
    expect(deadlineAwareFeeRate('bch2', 0.5, 60, MARGIN)).toBe(Math.max(FLOOR_BCH2, Math.min(Math.ceil(1 * FEE_URGENCY_MAX_MULT), CAP_BCH2)));
  });

  it('clamps to maxFeeRate — a high base * mult can never exceed the cap', () => {
    expect(deadlineAwareFeeRate('bch2', 50, MARGIN, MARGIN)).toBe(CAP_BCH2);   // 50*3 -> clamped to 20
    expect(deadlineAwareFeeRate('btc', 200, MARGIN, MARGIN)).toBe(CAP_BTC);    // clamped to 100
  });

  it('never below the config floor', () => {
    expect(deadlineAwareFeeRate('btc', 0, MARGIN * 100, MARGIN)).toBe(FLOOR_BTC); // base clamps up to floor 10
    expect(deadlineAwareFeeRate('bch2', -5, MARGIN * 100, MARGIN)).toBe(FLOOR_BCH2);
  });

  it('non-finite remaining / margin ⇒ no ramp (mult 1), never a lower fee', () => {
    expect(deadlineAwareFeeRate('bch2', 5, Number.POSITIVE_INFINITY, MARGIN)).toBe(5);
    expect(deadlineAwareFeeRate('bch2', 5, 100, 0)).toBe(5);       // margin 0 ⇒ no ramp
    expect(deadlineAwareFeeRate('bch2', 5, NaN, MARGIN)).toBe(5);
  });

  it('is monotonic: less remaining runway ⇒ fee never decreases', () => {
    let prev = 0;
    for (const rem of [MARGIN * 10, MARGIN * 4, MARGIN * 3, MARGIN * 2, MARGIN, MARGIN / 2, 0]) {
      const f = deadlineAwareFeeRate('btc', 12, rem, MARGIN);
      expect(f).toBeGreaterThanOrEqual(prev);
      expect(f).toBeLessThanOrEqual(CAP_BTC);
      prev = f;
    }
  });
});

describe('fetchFeeRate (fail-safe + clamp)', () => {
  beforeEach(() => _clearFeeRateCache());

  it('valid live estimate → clamped to [floor, cap]', async () => {
    expect(await fetchFeeRate('bch2', async () => 7)).toBe(7);
    expect(await fetchFeeRate('bch2', async () => 999, true)).toBe(CAP_BCH2);   // clamps to 20
    expect(await fetchFeeRate('btc', async () => 3, true)).toBe(FLOOR_BTC);     // floors up to 10
  });

  it('estimate throws → config floor (fail-safe)', async () => {
    expect(await fetchFeeRate('bch2', async () => { throw new Error('proxy down'); })).toBe(FLOOR_BCH2);
    expect(await fetchFeeRate('btc', async () => { throw new Error('x'); }, true)).toBe(FLOOR_BTC);
  });

  it('estimate returns 0 / negative / NaN / null → config floor', async () => {
    expect(await fetchFeeRate('bch2', async () => 0, true)).toBe(FLOOR_BCH2);
    expect(await fetchFeeRate('bch2', async () => -3, true)).toBe(FLOOR_BCH2);
    expect(await fetchFeeRate('bch2', async () => NaN, true)).toBe(FLOOR_BCH2);
    expect(await fetchFeeRate('bch2', async () => null, true)).toBe(FLOOR_BCH2);
  });

  it('caches within TTL (does not re-call estimate) and force bypasses', async () => {
    let calls = 0;
    const est = async () => { calls++; return 5; };
    expect(await fetchFeeRate('bch2', est)).toBe(5);
    expect(await fetchFeeRate('bch2', est)).toBe(5); // cached
    expect(calls).toBe(1);
    await fetchFeeRate('bch2', async () => { calls++; return 8; }, true); // force re-fetch
    expect(calls).toBe(2);
  });
});
