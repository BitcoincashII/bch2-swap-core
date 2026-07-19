// Pure timelock-margin gate predicates extracted from SwapExecute.tsx so the fund-loss-critical arithmetic can be
// unit-tested at its boundaries (previously it lived inline in a ~9700-line component with no coverage — see the
// Tier-2 audit). Each function returns TRUE when the gate must ABORT/fail-closed (the decision is "unsafe"). The
// component keeps its own bindings for user-facing messages and calls these for the boolean decision, so the tested
// logic IS the runtime logic. All comparisons are in wall-clock SECONDS unless noted; the ÷K conservatism lives in
// minSecondsUntilRefund (K-fold block acceleration on a minority-hashrate chain can mature a height CLTV early).
import { minSecondsUntilRefund, CLAIM_MARGIN_BLOCKS, TIMELOCK_SAFETY_K } from './chain-config';

/** 4h fixed claim margin (matches EVM_CLAIM_MARGIN_SEC and the inline `24 * 600`). */
export const CLAIM_MARGIN_SEC = CLAIM_MARGIN_BLOCKS * 600;

/**
 * Height-CLTV margin gate (SwapExecute responder-fund @6009, EVM-responder pre-lock @1554, reveal @7472): a leg whose
 * refund is a block-height CLTV must have at least `requiredSec` of CONSERVATIVE (÷K) wall-clock runway left. TRUE =>
 * too tight => abort/do-not-commit. `blockSec` must be > 0 (callers validate chain block-time separately).
 */
export function marginTooTight(remainingBlocks: number, blockSec: number, requiredSec: number): boolean {
  return minSecondsUntilRefund(remainingBlocks, blockSec) < requiredSec;
}

/**
 * Claim-window block gate (SwapExecute initiator @6018, resume pre-check @4374): the counterparty leg we will claim
 * must have more than K·CLAIM_MARGIN_BLOCKS blocks left, else its refund could race our claim's confirmation. TRUE =>
 * nearly expired => abort. Pure block count (no chain-time conversion) — this is the guard whose earlier {180,48}
 * params bricked UTXO↔UTXO swaps (48-block responder leg minus ~6 confs left < 48), fixed by 216/72 + K=2.
 */
export function claimWindowTooTight(remainingBlocks: number): boolean {
  return remainingBlocks < CLAIM_MARGIN_BLOCKS * TIMELOCK_SAFETY_K;
}

/**
 * Cross-leg ordering gate (SwapExecute initiator @6084, R26-ATOM-002): the responder (counterparty) leg's refund must
 * mature STRICTLY BEFORE our own initiator leg minus the claim margin, so the two HTLCs are never simultaneously
 * claimable+refundable (the double-dip inversion). Compared in wall-clock seconds, normalized per chain. Our OWN leg's
 * runway is ÷K-conservative (it could mature early); the counterparty leg's is taken at face (a shorter observed
 * responder leg is what we WANT). TRUE => ordering not safe => abort.
 */
export function orderingUnsafe(
  responderRemainingBlocks: number, theirBlockSec: number,
  ownRemainingBlocks: number, myBlockSec: number,
  claimMarginSec: number = CLAIM_MARGIN_SEC,
): boolean {
  const responderLegRemainingSec = responderRemainingBlocks * theirBlockSec;
  const initiatorLegRemainingSec = minSecondsUntilRefund(ownRemainingBlocks, myBlockSec);
  return responderLegRemainingSec + claimMarginSec >= initiatorLegRemainingSec;
}
