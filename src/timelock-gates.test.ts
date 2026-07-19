import { describe, it, expect } from 'vitest';
import { marginTooTight, claimWindowTooTight, orderingUnsafe, CLAIM_MARGIN_SEC } from './timelock-gates';
import { LOCKTIME_BLOCKS, CLAIM_MARGIN_BLOCKS, TIMELOCK_SAFETY_K, minSecondsUntilRefund } from './chain-config';

const BSEC = 600; // all UTXO chains
// Real gate thresholds (mirror SwapExecute): responder EVM lock (72 blk) + EVM claim margin (24 blk).
const RESPONDER_LOCK_SEC = LOCKTIME_BLOCKS.responder * BSEC; // 43200
const EVM_CLAIM_MARGIN_SEC = CLAIM_MARGIN_BLOCKS * BSEC;     // 14400

describe('timelock-gates: pure margin predicates (extracted from SwapExecute)', () => {
  it('CLAIM_MARGIN_SEC is the 4h fixed margin', () => {
    expect(CLAIM_MARGIN_SEC).toBe(24 * 600);
    expect(CLAIM_MARGIN_SEC).toBe(CLAIM_MARGIN_BLOCKS * 600);
  });

  describe('marginTooTight (÷K height-CLTV runway gate)', () => {
    it('is exactly minSecondsUntilRefund(blocks,sec) < requiredSec', () => {
      for (const [b, req] of [[100, 14400], [48, 14400], [192, 57600], [10, 999999]] as const) {
        expect(marginTooTight(b, BSEC, req)).toBe(minSecondsUntilRefund(b, BSEC) < req);
      }
    });
    it('reveal-margin boundary: needs >= 48 blocks for the 4h claim margin (K=2 => blocks*300 >= 14400)', () => {
      expect(marginTooTight(48, BSEC, CLAIM_MARGIN_SEC)).toBe(false); // 48*300 = 14400, not < 14400
      expect(marginTooTight(47, BSEC, CLAIM_MARGIN_SEC)).toBe(true);  // 47*300 = 14100 < 14400
    });
    it('EVM-responder pre-lock boundary: needs >= 192 blocks for RESPONDER_LOCK + EVM claim margin', () => {
      const req = RESPONDER_LOCK_SEC + EVM_CLAIM_MARGIN_SEC; // 57600
      expect(marginTooTight(192, BSEC, req)).toBe(false); // 192*300 = 57600
      expect(marginTooTight(191, BSEC, req)).toBe(true);  // 191*300 = 57300 < 57600
    });
  });

  describe('claimWindowTooTight (block-count gate; the {…,48}-brick regression guard)', () => {
    it('boundary is K·CLAIM_MARGIN_BLOCKS = 48 blocks', () => {
      expect(claimWindowTooTight(CLAIM_MARGIN_BLOCKS * TIMELOCK_SAFETY_K)).toBe(false); // 48 ok
      expect(claimWindowTooTight(48)).toBe(false);
      expect(claimWindowTooTight(47)).toBe(true);
      expect(claimWindowTooTight(0)).toBe(true);
    });
    it('a freshly-verified 72-block responder leg minus ~6 confs still clears (the fix for the 48-block brick)', () => {
      // Under the OLD {180,48} params the responder leg was 48 blocks; after ~6 confs only 42 remained < 48 => bricked.
      // Under 216/72 the responder leg is 72; after 6 confs 66 remain, comfortably above 48.
      expect(claimWindowTooTight(LOCKTIME_BLOCKS.responder - 6)).toBe(false); // 66 ok
      expect(claimWindowTooTight(48 - 6)).toBe(true);                          // 42 would brick (regression guard)
    });
  });

  describe('orderingUnsafe (cross-leg double-dip ordering)', () => {
    it('standard 216/72 params (responder refunds well before our own leg) are SAFE', () => {
      // responder leg 72 blk face value; own initiator leg 216 blk ÷K
      expect(orderingUnsafe(LOCKTIME_BLOCKS.responder, BSEC, LOCKTIME_BLOCKS.initiator, BSEC)).toBe(false);
    });
    it('boundary: own-leg ÷K runway must EXCEED responder-leg + margin (>= is unsafe)', () => {
      // responder 72*600=43200 + 14400 = 57600; own/K = own*300; equal at own=192
      expect(orderingUnsafe(72, BSEC, 192, BSEC, CLAIM_MARGIN_SEC)).toBe(true);  // 57600 >= 57600
      expect(orderingUnsafe(72, BSEC, 193, BSEC, CLAIM_MARGIN_SEC)).toBe(false); // 57600 >= 57900 is false
    });
    it('inversion (own leg shorter than responder leg + margin) is UNSAFE', () => {
      expect(orderingUnsafe(72, BSEC, 100, BSEC)).toBe(true); // own 100*300=30000 < 43200+14400
    });
    it('compares wall-clock, not raw blocks: a slower own-chain shrinks effective own runway', () => {
      // own 192 blocks at 1200s/blk => minSecondsUntilRefund = 192*600 = 115200 >> 57600 => safe
      expect(orderingUnsafe(72, BSEC, 192, 1200, CLAIM_MARGIN_SEC)).toBe(false);
      // own 72 blocks at 1200s/blk => 72*600 = 43200 < 57600 => unsafe
      expect(orderingUnsafe(72, BSEC, 72, 1200, CLAIM_MARGIN_SEC)).toBe(true);
    });
  });
});
