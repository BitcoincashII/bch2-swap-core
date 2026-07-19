// src/chain-config.ts
globalThis.process?.env?.BCH2_SWAP_NETWORK === "regtest";
var TIMELOCK_SAFETY_K = 2;
var CLAIM_MARGIN_BLOCKS = 24;
function minSecondsUntilRefund(blocksRemaining, chainBlockSec) {
  return blocksRemaining * chainBlockSec / TIMELOCK_SAFETY_K;
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

export { CLAIM_MARGIN_SEC, claimWindowTooTight, marginTooTight, orderingUnsafe };
