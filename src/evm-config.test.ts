/**
 * Regression tests for the R124-XCHAIN-001 EVM/UTXO timelock-inversion fix.
 *
 * The CRITICAL bug (round 124): EVM HTLC locks were sized in RAW blocks (initiator minLockBlocks*2,
 * responder *1) with no wall-clock normalization, so on Base Sepolia an EVM-initiator lock (~20min)
 * was SHORTER than a UTXO-responder lock (12h) — letting a malicious maker refund the EVM leg then
 * still claim the UTXO leg with the secret. These tests pin the wall-clock-normalized invariant so a
 * future regression (or a new chain config) can't silently reintroduce the inversion.
 */
import { describe, it, expect } from 'vitest';
import {
  getEvmConfig,
  evmLockBlocksForRole,
  evmLockSecondsForRole,
  INITIATOR_LOCK_SEC,
  RESPONDER_LOCK_SEC,
  EVM_CLAIM_MARGIN_SEC,
  SUPPORTED_EVM_CHAINS,
  validateEvmConfigs,
} from './evm-config';
import { LOCKTIME_BLOCKS, chainConfigs } from './chain-config';
import type { EvmChainId } from './swap-types';

const UTXO_REF_SEC = chainConfigs.bch2.avgBlockTimeSec; // 600

describe('R124-XCHAIN-001 EVM timelock normalization', () => {
  it('canonical lock seconds derive from the UTXO reference (24h initiator / 12h responder)', () => {
    expect(INITIATOR_LOCK_SEC).toBe(LOCKTIME_BLOCKS.initiator * UTXO_REF_SEC); // 144*600 = 86400 (24h)
    expect(RESPONDER_LOCK_SEC).toBe(LOCKTIME_BLOCKS.responder * UTXO_REF_SEC); // 72*600  = 43200 (12h)
    expect(INITIATOR_LOCK_SEC).toBeGreaterThan(RESPONDER_LOCK_SEC);
  });

  // Run the invariant for every chain so a newly-added/edited config is covered automatically.
  const chainIds = Array.from(new Set([84532 as EvmChainId, ...SUPPORTED_EVM_CHAINS]));
  for (const chainId of chainIds) {
    const cfg = getEvmConfig(chainId);
    if (!cfg) continue;
    describe(`chain ${chainId} (${cfg.name}, ${cfg.avgBlockTimeSec}s/block)`, () => {
      const init = evmLockBlocksForRole(cfg, 'initiator');
      const resp = evmLockBlocksForRole(cfg, 'responder');

      it('initiator lock strictly exceeds responder lock (no inversion after clamping)', () => {
        expect(init).toBeGreaterThan(resp);
      });

      it('both locks fit the contract [minLockBlocks, maxLockBlocks-1] range', () => {
        for (const blocks of [init, resp]) {
          expect(blocks).toBeGreaterThanOrEqual(cfg.minLockBlocks);
          expect(blocks).toBeLessThanOrEqual(cfg.maxLockBlocks - 1);
        }
      });

      it('EVM-responder lock (sec) is strictly less than the UTXO-initiator lock (sec)', () => {
        // UTXO-init / EVM-resp topology safety.
        const respSec = resp * cfg.avgBlockTimeSec;
        const utxoInitSec = LOCKTIME_BLOCKS.initiator * UTXO_REF_SEC;
        expect(respSec).toBeLessThan(utxoInitSec);
      });

      it('EVM-initiator lock (sec) exceeds the UTXO-responder lock (sec) + claim margin', () => {
        // EVM-init / UTXO-resp topology safety — the exact R124-XCHAIN-001 inversion guard.
        const initSec = init * cfg.avgBlockTimeSec;
        const utxoRespSec = LOCKTIME_BLOCKS.responder * UTXO_REF_SEC;
        expect(initSec).toBeGreaterThan(utxoRespSec + EVM_CLAIM_MARGIN_SEC);
      });
    });
  }

  it('validateEvmConfigs() does not throw for the live supported chains', () => {
    expect(() => validateEvmConfigs()).not.toThrow();
  });
});

/**
 * R138b-XCHAIN-001 — unix-timestamp lock basis + canonical-contract reconciliation.
 *
 * The deployed TokenHTLC is block.timestamp based; the client was converted from block.number to
 * unix-timestamp timelocks, and the Base Sepolia config was re-pointed at the canonical contract +
 * MockUSDC (matching packages/swap-core). These tests pin the seconds-based lock basis and the
 * config alignment so a regression can't silently re-introduce the wrong contract or the wrong basis.
 */
describe('R138b-XCHAIN-001 unix-timestamp lock basis', () => {
  const chainIds = Array.from(new Set([84532 as EvmChainId, ...SUPPORTED_EVM_CHAINS]));
  for (const chainId of chainIds) {
    const cfg = getEvmConfig(chainId);
    if (!cfg) continue;
    describe(`chain ${chainId} (${cfg.name})`, () => {
      const initSec = evmLockSecondsForRole(cfg, 'initiator');
      const respSec = evmLockSecondsForRole(cfg, 'responder');

      it('seconds-based locks: initiator strictly exceeds responder (no inversion)', () => {
        expect(initSec).toBeGreaterThan(respSec);
      });

      it('both seconds-locks fit the contract [minLockSeconds, maxLockSeconds] window', () => {
        for (const sec of [initSec, respSec]) {
          expect(sec).toBeGreaterThanOrEqual(cfg.minLockSeconds);
          expect(sec).toBeLessThanOrEqual(cfg.maxLockSeconds);
        }
      });

      it('EVM-responder lock (sec) is strictly less than the UTXO-initiator lock (sec)', () => {
        expect(respSec).toBeLessThan(LOCKTIME_BLOCKS.initiator * UTXO_REF_SEC);
      });

      it('EVM-initiator lock (sec) exceeds the UTXO-responder lock (sec) + claim margin', () => {
        expect(initSec).toBeGreaterThan(LOCKTIME_BLOCKS.responder * UTXO_REF_SEC + EVM_CLAIM_MARGIN_SEC);
      });
    });
  }

  it('MAINNET: Polygon (137) + Arbitrum (42161) are the supported chains with deployed HTLCs + real tokens', () => {
    expect(SUPPORTED_EVM_CHAINS).toEqual([137, 42161]);
    // Polygon
    const poly = getEvmConfig(137 as EvmChainId)!;
    expect(poly.htlcAddress.toLowerCase()).toBe('0x405a6dd5b51a00c5f789c9d215e4986ba1dc9963');
    expect(poly.tokens.USDC.address.toLowerCase()).toBe('0x3c499c542cef5e3811e1192ce70d8cc03d5c3359');
    expect(poly.tokens.USDT.address.toLowerCase()).toBe('0xc2132d05d31c914a87c6611c10748aeb04b58e8f');
    // Arbitrum
    const arb = getEvmConfig(42161 as EvmChainId)!;
    expect(arb.htlcAddress.toLowerCase()).toBe('0x141f8f62f92c6486a7efe8d0891a6800d7ed1186');
    expect(arb.tokens.USDC.address.toLowerCase()).toBe('0xaf88d065e77c8cc2239327c5edb3a432268e5831');
    expect(arb.tokens.USDT.address.toLowerCase()).toBe('0xfd086bc7cd5c481dcc9c85ebe478a1c0b69fcbb9');
    // both bounds MUST equal the deployed contracts' MIN/MAX_LOCK_SECONDS (6h / 48h).
    for (const cfg of [poly, arb]) { expect(cfg.minLockSeconds).toBe(21_600); expect(cfg.maxLockSeconds).toBe(172_800); }
  });
});
