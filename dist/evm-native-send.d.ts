/** Gas units for a plain value transfer (no calldata). On Arbitrum, estimateGas folds the L1 data cost in, so this
 *  is only the FALLBACK when estimateGas is unavailable. */
declare const NATIVE_TRANSFER_GAS = 21000n;
/** Effective gas cost (wei) with a safety margin, used both to RESERVE gas on MAX and to preflight affordability.
 *  Margin covers fee movement between quote and inclusion (and Arbitrum's L1-fee variability). marginBps=2000 = +20%. */
declare function estimateGasCostWei(gasLimit: bigint, maxFeePerGasWei: bigint, marginBps?: bigint): bigint;
/** Max native ETH (wei) that can actually be sent = balance − reserved gas cost, floored at 0.
 *  Sending the FULL balance would leave nothing for gas and always fail — MAX must reserve gas. */
declare function computeMaxSendableWei(balanceWei: bigint, gasCostWei: bigint): bigint;
/** Fail BEFORE broadcast (with a clear, user-facing message) if the balance cannot cover value + gas. A raw
 *  ethers "insufficient funds" is opaque; this makes the MAX/gas relationship explicit to the user. */
declare function assertNativeSendAffordable(balanceWei: bigint, valueWei: bigint, gasCostWei: bigint): void;

export { NATIVE_TRANSFER_GAS, assertNativeSendAffordable, computeMaxSendableWei, estimateGasCostWei };
