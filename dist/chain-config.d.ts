import { C as Chain, a as ChainConfig } from './swap-types-CsSbca8_.js';

declare const chainConfigs: Record<Chain, ChainConfig>;
declare const LOCKTIME_BLOCKS: {
    initiator: number;
    responder: number;
};
declare const TIMELOCK_SAFETY_K = 2;
declare const CLAIM_MARGIN_BLOCKS = 24;
declare const CLAIM_CONF_BUFFER_BLOCKS = 12;
declare function minSecondsUntilRefund(blocksRemaining: number, chainBlockSec: number): number;
declare function maxSecondsUntilRefund(blocks: number, chainBlockSec: number): number;
declare const SUSPENDED_SWAP_CHAINS: ReadonlySet<Chain>;
declare function isSwapSuspended(chain: Chain): boolean;
/**
 * Canonical two-leg suspension gate: a swap is suspended if EITHER leg is on a suspended chain.
 * Every create / take / fund entry point (SwapCreate, SwapBrowse, SwapExecute — mirrored by the
 * proxy's SUSPENDED_CHAINS 403) MUST route through this single predicate so a new call site cannot
 * silently bypass the gate. The bc2-suspension test locks the full chain-pair truth table, and the
 * inversion this prevents is a both-legs fund-loss (see SUSPENDED_SWAP_CHAINS above), so this is the
 * one invariant that must never regress while any chain is suspended.
 */
declare function isSwapPairSuspended(chainA: Chain, chainB: Chain): boolean;
declare const MAX_FEE_RATE_SAT_PER_BYTE: Record<Chain, number>;
declare function maxFeeRate(chain: Chain): number;
declare const FEE_URGENCY_MAX_MULT = 3;
declare const FEE_URGENCY_START_FACTOR = 4;
declare function getChainConfig(chain: Chain): ChainConfig;

export { CLAIM_CONF_BUFFER_BLOCKS, CLAIM_MARGIN_BLOCKS, FEE_URGENCY_MAX_MULT, FEE_URGENCY_START_FACTOR, LOCKTIME_BLOCKS, MAX_FEE_RATE_SAT_PER_BYTE, SUSPENDED_SWAP_CHAINS, TIMELOCK_SAFETY_K, chainConfigs, getChainConfig, isSwapPairSuspended, isSwapSuspended, maxFeeRate, maxSecondsUntilRefund, minSecondsUntilRefund };
