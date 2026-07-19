/** 4h fixed claim margin (matches EVM_CLAIM_MARGIN_SEC and the inline `24 * 600`). */
declare const CLAIM_MARGIN_SEC: number;
/**
 * Height-CLTV margin gate (SwapExecute responder-fund @6009, EVM-responder pre-lock @1554, reveal @7472): a leg whose
 * refund is a block-height CLTV must have at least `requiredSec` of CONSERVATIVE (÷K) wall-clock runway left. TRUE =>
 * too tight => abort/do-not-commit. `blockSec` must be > 0 (callers validate chain block-time separately).
 */
declare function marginTooTight(remainingBlocks: number, blockSec: number, requiredSec: number): boolean;
/**
 * Claim-window block gate (SwapExecute initiator @6018, resume pre-check @4374): the counterparty leg we will claim
 * must have more than K·CLAIM_MARGIN_BLOCKS blocks left, else its refund could race our claim's confirmation. TRUE =>
 * nearly expired => abort. Pure block count (no chain-time conversion) — this is the guard whose earlier {180,48}
 * params bricked UTXO↔UTXO swaps (48-block responder leg minus ~6 confs left < 48), fixed by 216/72 + K=2.
 */
declare function claimWindowTooTight(remainingBlocks: number): boolean;
/**
 * Cross-leg ordering gate (SwapExecute initiator @6084, R26-ATOM-002): the responder (counterparty) leg's refund must
 * mature STRICTLY BEFORE our own initiator leg minus the claim margin, so the two HTLCs are never simultaneously
 * claimable+refundable (the double-dip inversion). Compared in wall-clock seconds, normalized per chain. Our OWN leg's
 * runway is ÷K-conservative (it could mature early); the counterparty leg's is taken at face (a shorter observed
 * responder leg is what we WANT). TRUE => ordering not safe => abort.
 */
declare function orderingUnsafe(responderRemainingBlocks: number, theirBlockSec: number, ownRemainingBlocks: number, myBlockSec: number, claimMarginSec?: number): boolean;

export { CLAIM_MARGIN_SEC, claimWindowTooTight, marginTooTight, orderingUnsafe };
