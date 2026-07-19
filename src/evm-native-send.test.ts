import { describe, it, expect } from 'vitest';
import {
  NATIVE_TRANSFER_GAS,
  estimateGasCostWei,
  computeMaxSendableWei,
  assertNativeSendAffordable,
} from './evm-native-send';

describe('evm-native-send gas/affordability math (R282)', () => {
  const gwei = 1_000_000_000n;
  const eth = 1_000_000_000_000_000_000n;

  describe('estimateGasCostWei', () => {
    it('applies the default +20% margin', () => {
      // 21000 * 1 gwei = 21000 gwei; +20% = 25200 gwei
      expect(estimateGasCostWei(NATIVE_TRANSFER_GAS, gwei)).toBe(25_200n * gwei);
    });
    it('honors a custom margin', () => {
      expect(estimateGasCostWei(21_000n, gwei, 0n)).toBe(21_000n * gwei);
      expect(estimateGasCostWei(21_000n, gwei, 10_000n)).toBe(42_000n * gwei); // +100%
    });
    it('rejects negative input', () => {
      expect(() => estimateGasCostWei(-1n, gwei)).toThrow(/negative/);
    });
  });

  describe('computeMaxSendableWei', () => {
    it('subtracts the reserved gas from the balance', () => {
      const gas = estimateGasCostWei(NATIVE_TRANSFER_GAS, gwei); // 25200 gwei
      expect(computeMaxSendableWei(eth, gas)).toBe(eth - gas);
    });
    it('floors at 0 when gas exceeds the balance (dust wallet)', () => {
      expect(computeMaxSendableWei(1000n, 25_200n * gwei)).toBe(0n);
    });
    it('never returns the full balance (gas is always reserved)', () => {
      const gas = estimateGasCostWei(NATIVE_TRANSFER_GAS, gwei);
      expect(computeMaxSendableWei(eth, gas)).toBeLessThan(eth);
    });
  });

  describe('assertNativeSendAffordable', () => {
    const gas = estimateGasCostWei(NATIVE_TRANSFER_GAS, gwei);
    it('passes when balance covers value + gas', () => {
      expect(() => assertNativeSendAffordable(eth, eth / 2n, gas)).not.toThrow();
    });
    it('a MAX-computed amount is exactly affordable (round-trip)', () => {
      // MAX reserves `gas`; the actual send gas is <= that reserve, so value+actualGas <= balance.
      const maxWei = computeMaxSendableWei(eth, gas);
      expect(() => assertNativeSendAffordable(eth, maxWei, gas)).not.toThrow();
    });
    it('rejects sending the FULL balance (no room for gas)', () => {
      expect(() => assertNativeSendAffordable(eth, eth, gas)).toThrow(/plus network gas/);
    });
    it('rejects when value alone exceeds balance', () => {
      expect(() => assertNativeSendAffordable(eth, eth * 2n, 0n)).toThrow(/plus network gas/);
    });
    it('rejects a zero/negative amount', () => {
      expect(() => assertNativeSendAffordable(eth, 0n, gas)).toThrow(/Invalid amount/);
    });
  });
});
