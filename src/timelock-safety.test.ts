import { describe, it, expect } from 'vitest';
import {
  LOCKTIME_BLOCKS, TIMELOCK_SAFETY_K, CLAIM_MARGIN_BLOCKS, CLAIM_CONF_BUFFER_BLOCKS,
  minSecondsUntilRefund, maxSecondsUntilRefund,
} from './chain-config';

// R-TIMELOCK-K: BCH2 is minority-hashrate, so a height-based (CLTV) leg can mature faster in wall-clock than the
// nominal 600s/block. The swap-safety gates size every "seconds until a leg refunds" estimate conservatively by K so
// a K-fold block-rate acceleration can't invert the effective timelock ordering (the audited fund-theft class).
const K = TIMELOCK_SAFETY_K;
const BCH2_SEC = 600;

describe('R-TIMELOCK-K — conservative block-rate safety', () => {
  it('minSecondsUntilRefund UNDER-estimates by K (assumes the chain could mine K× faster)', () => {
    expect(minSecondsUntilRefund(100, 600)).toBe((100 * 600) / K);
    expect(minSecondsUntilRefund(100, 600)).toBeLessThan(100 * 600); // strictly below nominal for K>1
  });

  it('maxSecondsUntilRefund OVER-estimates by K (assumes the chain could mine K× slower)', () => {
    expect(maxSecondsUntilRefund(100, 600)).toBe(100 * 600 * K);
    expect(maxSecondsUntilRefund(100, 600)).toBeGreaterThan(100 * 600);
  });

  it('startup-assertion invariant holds: initiator >= K*(responder + claimMargin)', () => {
    expect(LOCKTIME_BLOCKS.initiator).toBeGreaterThanOrEqual(K * (LOCKTIME_BLOCKS.responder + CLAIM_MARGIN_BLOCKS));
  });

  it('FUND-GATE FLOOR is K-safe: even at a K-fold acceleration the initiator leg outlasts responderLock + margin', () => {
    // The responder fund gate (SwapExecute.tsx:5936) requires:
    //   minSecondsUntilRefund(initBlocksRemaining, 600) >= responderLockSec + claimMarginSec
    const responderLockSec = LOCKTIME_BLOCKS.responder * BCH2_SEC;
    const marginSec = CLAIM_MARGIN_BLOCKS * BCH2_SEC;
    // Minimum initiator-leg blocks the gate accepts:
    const floorBlocks = Math.ceil(((responderLockSec + marginSec) * K) / BCH2_SEC);
    // At that floor, even under a K-fold acceleration the initiator leg matures no sooner than responderLock + margin:
    expect(minSecondsUntilRefund(floorBlocks, BCH2_SEC)).toBeGreaterThanOrEqual(responderLockSec + marginSec);
    // …and the initiator lock is long enough to REACH that floor and still leave a funding window (>0 blocks):
    expect(LOCKTIME_BLOCKS.initiator).toBeGreaterThan(floorBlocks);
  });

  it('CLAIM-WINDOW is K-safe: the initiator can still reveal on the SHORT responder leg AFTER confirmations', () => {
    // The regression in R-TIMELOCK-K v1: responder lock (48) == K*CLAIM_MARGIN_BLOCKS (48), so the initiator's ÷K
    // reveal/claim gate (which needs K*CLAIM_MARGIN_BLOCKS blocks left on the responder leg) could NEVER pass once
    // confirmations consumed a few blocks -> every UTXO<->UTXO swap bricked. Guard: responder lock must exceed the
    // gate threshold with room for the ~6 confirmations the initiator waits before revealing.
    const claimGateThresholdBlocks = TIMELOCK_SAFETY_K * CLAIM_MARGIN_BLOCKS; // reveal/claim gate needs >= this many left
    const MAX_UTXO_CONF = 6; // the initiator waits for the responder funding to confirm (bch2/bch = 6, the max)
    // After confirmations, the responder leg still has more than the gate threshold -> the initiator CAN reveal:
    expect(LOCKTIME_BLOCKS.responder - MAX_UTXO_CONF).toBeGreaterThan(claimGateThresholdBlocks);
    // …enforced by the startup assertion:
    expect(LOCKTIME_BLOCKS.responder).toBeGreaterThanOrEqual(claimGateThresholdBlocks + CLAIM_CONF_BUFFER_BLOCKS);
  });

  it('the v1 regression params (responder 48) would BRICK swaps — regression guard', () => {
    // With responder=48, K=2: claim gate needs 48 blocks left, but after 6 confs only 42 remain -> initiator can
    // never reveal. The current responder lock must be strictly greater than the gate threshold + confirmations.
    const BRICKED_RESPONDER = 48;
    expect(BRICKED_RESPONDER - 6).toBeLessThan(TIMELOCK_SAFETY_K * CLAIM_MARGIN_BLOCKS); // 42 < 48 -> bricked
    expect(LOCKTIME_BLOCKS.responder).toBeGreaterThan(BRICKED_RESPONDER);
  });

  it('the OLD params (144/72) were NOT K-safe — this is the hole the fix closes', () => {
    const OLD_INIT = 144, OLD_RESP = 72;
    // Old nominal gate floor was (72+24)*600 = 57600s -> 96 blocks. Under a K=2 acceleration those 96 blocks mine in
    // 96*300 = 28800s = 8h < responderLock(72*600 = 12h) + margin -> effective ordering INVERTS. A K-safe config would
    // have required initiator >= K*(72+24) = 192, but the old initiator lock was only 144.
    expect(OLD_INIT).toBeLessThan(K * (OLD_RESP + CLAIM_MARGIN_BLOCKS));
    // The new config IS K-safe (regression guard against reverting the params):
    expect(LOCKTIME_BLOCKS.initiator).toBeGreaterThanOrEqual(K * (LOCKTIME_BLOCKS.responder + CLAIM_MARGIN_BLOCKS));
  });
});
