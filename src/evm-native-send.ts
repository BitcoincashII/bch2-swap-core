// R282-NATIVE-ETH-SEND-001: pure helpers for a native ETH (value-transfer) wallet send.
// The ethers plumbing (provider/wallet/sendTransaction) lives in the components alongside sendErc20 so it reuses
// the same proven key-lifecycle + receipt-wait + cleanup pattern. Only the gas-reserve / affordability math — the
// part that is easy to get subtly wrong and where a mistake burns real funds — is extracted here so it can be
// unit-tested against exact wei values. All amounts are bigint wei; no floats.

/** Gas units for a plain value transfer (no calldata). On Arbitrum, estimateGas folds the L1 data cost in, so this
 *  is only the FALLBACK when estimateGas is unavailable. */
export const NATIVE_TRANSFER_GAS = 21_000n;

/** Effective gas cost (wei) with a safety margin, used both to RESERVE gas on MAX and to preflight affordability.
 *  Margin covers fee movement between quote and inclusion (and Arbitrum's L1-fee variability). marginBps=2000 = +20%. */
export function estimateGasCostWei(gasLimit: bigint, maxFeePerGasWei: bigint, marginBps = 2000n): bigint {
  if (gasLimit < 0n || maxFeePerGasWei < 0n || marginBps < 0n) {
    throw new Error('estimateGasCostWei: negative input');
  }
  return (gasLimit * maxFeePerGasWei * (10_000n + marginBps)) / 10_000n;
}

/** Max native ETH (wei) that can actually be sent = balance − reserved gas cost, floored at 0.
 *  Sending the FULL balance would leave nothing for gas and always fail — MAX must reserve gas. */
export function computeMaxSendableWei(balanceWei: bigint, gasCostWei: bigint): bigint {
  if (balanceWei < 0n || gasCostWei < 0n) throw new Error('computeMaxSendableWei: negative input');
  const max = balanceWei - gasCostWei;
  return max > 0n ? max : 0n;
}

/** Fail BEFORE broadcast (with a clear, user-facing message) if the balance cannot cover value + gas. A raw
 *  ethers "insufficient funds" is opaque; this makes the MAX/gas relationship explicit to the user. */
export function assertNativeSendAffordable(balanceWei: bigint, valueWei: bigint, gasCostWei: bigint): void {
  if (valueWei <= 0n) throw new Error('Invalid amount');
  if (balanceWei < valueWei + gasCostWei) {
    throw new Error('Insufficient balance to cover the amount plus network gas — use MAX or a smaller amount.');
  }
}
