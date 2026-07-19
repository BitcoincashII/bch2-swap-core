// src/evm-native-send.ts
var NATIVE_TRANSFER_GAS = 21000n;
function estimateGasCostWei(gasLimit, maxFeePerGasWei, marginBps = 2000n) {
  if (gasLimit < 0n || maxFeePerGasWei < 0n || marginBps < 0n) {
    throw new Error("estimateGasCostWei: negative input");
  }
  return gasLimit * maxFeePerGasWei * (10000n + marginBps) / 10000n;
}
function computeMaxSendableWei(balanceWei, gasCostWei) {
  if (balanceWei < 0n || gasCostWei < 0n) throw new Error("computeMaxSendableWei: negative input");
  const max = balanceWei - gasCostWei;
  return max > 0n ? max : 0n;
}
function assertNativeSendAffordable(balanceWei, valueWei, gasCostWei) {
  if (valueWei <= 0n) throw new Error("Invalid amount");
  if (balanceWei < valueWei + gasCostWei) {
    throw new Error("Insufficient balance to cover the amount plus network gas \u2014 use MAX or a smaller amount.");
  }
}

export { NATIVE_TRANSFER_GAS, assertNativeSendAffordable, computeMaxSendableWei, estimateGasCostWei };
