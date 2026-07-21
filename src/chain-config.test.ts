import { describe, it, expect, vi } from 'vitest';
import {
  chainConfigs,
  getChainConfig,
  LOCKTIME_BLOCKS,
  TIMELOCK_SAFETY_K,
  CLAIM_MARGIN_BLOCKS,
  CLAIM_CONF_BUFFER_BLOCKS,
  minSecondsUntilRefund,
  maxSecondsUntilRefund,
  MAX_FEE_RATE_SAT_PER_BYTE,
  maxFeeRate,
  FEE_URGENCY_MAX_MULT,
  FEE_URGENCY_START_FACTOR,
  SUSPENDED_SWAP_CHAINS,
  isSwapSuspended,
  isSwapPairSuspended,
} from './chain-config';
import type { Chain } from './swap-types';

/**
 * chain-config.ts holds the per-chain, fund-safety-critical constants that every HTLC and safety
 * gate is sized against: required confirmations, the block-count timelocks and their wall-clock
 * conversion factor, the fee ceilings that also size the "guaranteed-claimable" funding floor, the
 * dust thresholds, and the address encodings. A silent edit to any of these can invert the timelock
 * ordering or strand a leg, so this test pins the ACTUAL current values — a future accidental change
 * to a fund-safety param must fail here.
 *
 * The suite runs with BCH2_SWAP_NETWORK unset, so the module's REGTEST flag is false and every
 * address prefix / version byte resolves to its MAINNET encoding. The regtest branch of that toggle
 * is exercised explicitly via a fresh re-import at the bottom of the file.
 */

const ALL_CHAINS: Chain[] = ['bch2', 'bch', 'btc', 'bc2', 'eth', 'base', 'arb', 'poly'];
const UTXO_CHAINS: Chain[] = ['bch2', 'bch', 'btc', 'bc2'];
const EVM_CHAINS: Chain[] = ['eth', 'base', 'arb', 'poly'];

// Guard the toggle-dependent assertions so that running the whole suite under regtest can't produce
// a false failure; the regtest encodings get their own explicit block below.
const proc = (globalThis as { process?: { env?: Record<string, string | undefined> } }).process;
const RUNNING_REGTEST = proc?.env?.BCH2_SWAP_NETWORK === 'regtest';

// ── Per-chain UTXO fund-safety params (MAINNET encodings) ──────────────────────────────────────
interface ExpectedUtxo {
  name: string;
  ticker: string;
  sighashType: number;
  useBip143: boolean;
  avgBlockTimeSec: number;
  dustThreshold: number;
  feePerByte: number;
  bip44CoinType: number;
  requiredConfirmations: number;
  maxFeeRateSatPerByte: number;
  addressPrefix?: string; // CashAddr chains only
  p2shVersionByte: number; // mainnet
  p2pkhVersionByte?: number; // Base58 chains only (btc/bc2)
}

const EXPECTED_UTXO: Record<'bch2' | 'bch' | 'btc' | 'bc2', ExpectedUtxo> = {
  bch2: {
    name: 'Bitcoin Cash II',
    ticker: 'BCH2',
    addressPrefix: 'bitcoincashii',
    p2shVersionByte: 0x05,
    sighashType: 0x41, // SIGHASH_ALL | SIGHASH_FORKID
    useBip143: true,
    avgBlockTimeSec: 600,
    dustThreshold: 182,
    feePerByte: 1,
    bip44CoinType: 20145,
    requiredConfirmations: 6, // minority-hashrate chain: 6 confs ~= 1h
    maxFeeRateSatPerByte: 20,
  },
  bch: {
    name: 'Bitcoin Cash',
    ticker: 'BCH',
    addressPrefix: 'bitcoincash', // mainnet (regtest => 'bchreg')
    p2shVersionByte: 0x05,
    sighashType: 0x41,
    useBip143: true,
    avgBlockTimeSec: 600,
    dustThreshold: 182,
    feePerByte: 1,
    bip44CoinType: 145,
    requiredConfirmations: 6,
    maxFeeRateSatPerByte: 20,
  },
  btc: {
    name: 'Bitcoin',
    ticker: 'BTC',
    p2shVersionByte: 0x05, // mainnet (regtest => 0xc4)
    p2pkhVersionByte: 0x00, // mainnet (regtest => 0x6f)
    sighashType: 0x01, // SIGHASH_ALL (no FORKID)
    useBip143: false,
    avgBlockTimeSec: 600,
    dustThreshold: 546,
    feePerByte: 10,
    bip44CoinType: 0,
    requiredConfirmations: 2,
    maxFeeRateSatPerByte: 100,
  },
  bc2: {
    name: 'Bitcoin II',
    ticker: 'BC2',
    p2shVersionByte: 0x05,
    p2pkhVersionByte: 0x00,
    sighashType: 0x01,
    useBip143: false,
    avgBlockTimeSec: 600,
    dustThreshold: 546,
    feePerByte: 1,
    bip44CoinType: 1,
    requiredConfirmations: 3,
    maxFeeRateSatPerByte: 20,
  },
};

// ── Per-chain EVM params ───────────────────────────────────────────────────────────────────────
interface ExpectedEvm {
  name: string;
  ticker: string;
  evmChainId: number;
  avgBlockTimeSec: number;
  minLockBlocks: number; // NOTE: dead code for EVM (real params live in evm-config.ts); pinned so an edit is noticed
  maxLockBlocks: number;
  maxFeeRateSatPerByte: number;
}

const EXPECTED_EVM: Record<'eth' | 'base' | 'arb' | 'poly', ExpectedEvm> = {
  eth: { name: 'Ethereum Sepolia', ticker: 'ETH', evmChainId: 11155111, avgBlockTimeSec: 12, minLockBlocks: 3_600, maxLockBlocks: 86_400, maxFeeRateSatPerByte: 0 },
  base: { name: 'Base Sepolia', ticker: 'BASE', evmChainId: 84532, avgBlockTimeSec: 2, minLockBlocks: 21_600, maxLockBlocks: 518_400, maxFeeRateSatPerByte: 0 },
  arb: { name: 'Arbitrum', ticker: 'ARB', evmChainId: 42161, avgBlockTimeSec: 1, minLockBlocks: 43_200, maxLockBlocks: 1_036_800, maxFeeRateSatPerByte: 0 },
  poly: { name: 'Polygon', ticker: 'POL', evmChainId: 137, avgBlockTimeSec: 2, minLockBlocks: 10_800, maxLockBlocks: 86_400, maxFeeRateSatPerByte: 0 },
};

describe('chainConfigs — UTXO chains', () => {
  for (const chain of UTXO_CHAINS) {
    const exp = EXPECTED_UTXO[chain as 'bch2' | 'bch' | 'btc' | 'bc2'];
    describe(`${chain}`, () => {
      const cfg = chainConfigs[chain];

      it('identity: name + ticker', () => {
        expect(cfg.name).toBe(exp.name);
        expect(cfg.ticker).toBe(exp.ticker);
      });

      it('is NOT flagged as an EVM chain', () => {
        expect(cfg.isEvm).toBeUndefined();
        expect(cfg.evmChainId).toBeUndefined();
      });

      it('signing flags: sighashType + useBip143 (FORKID topology)', () => {
        expect(cfg.sighashType).toBe(exp.sighashType);
        expect(cfg.useBip143).toBe(exp.useBip143);
      });

      it('avgBlockTimeSec (the wall-clock basis the timelock gates convert against)', () => {
        expect(cfg.avgBlockTimeSec).toBe(exp.avgBlockTimeSec);
      });

      it('dustThreshold', () => {
        expect(cfg.dustThreshold).toBe(exp.dustThreshold);
      });

      it('feePerByte (live base rate)', () => {
        expect(cfg.feePerByte).toBe(exp.feePerByte);
      });

      it('MAX_FEE_RATE_SAT_PER_BYTE ceiling (also sizes the guaranteed-claimable funding floor)', () => {
        expect(MAX_FEE_RATE_SAT_PER_BYTE[chain]).toBe(exp.maxFeeRateSatPerByte);
        // The live base rate must never exceed the ceiling, or a funded leg could become unclaimable.
        expect(cfg.feePerByte!).toBeLessThanOrEqual(MAX_FEE_RATE_SAT_PER_BYTE[chain]);
      });

      it('bip44CoinType (derivation path — key-reuse isolation)', () => {
        expect(cfg.bip44CoinType).toBe(exp.bip44CoinType);
      });

      it('requiredConfirmations (reorg / double-spend depth)', () => {
        expect(cfg.requiredConfirmations).toBe(exp.requiredConfirmations);
      });

      it('has at least one Electrum server configured', () => {
        expect(Array.isArray(cfg.electrumServers)).toBe(true);
        expect(cfg.electrumServers!.length).toBeGreaterThan(0);
        for (const s of cfg.electrumServers!) {
          expect(typeof s.host).toBe('string');
          expect(s.host.length).toBeGreaterThan(0);
          expect(typeof s.port).toBe('number');
          expect(s.ssl).toBe(true);
        }
      });

      // Address encodings are REGTEST-toggled; assert the mainnet values only when the suite is not
      // running under regtest. The regtest branch is covered by the re-import block below.
      it.skipIf(RUNNING_REGTEST)('mainnet address prefix / version bytes', () => {
        if (exp.addressPrefix !== undefined) {
          expect(cfg.addressPrefix).toBe(exp.addressPrefix);
        } else {
          expect(cfg.addressPrefix).toBeUndefined();
        }
        expect(cfg.p2shVersionByte).toBe(exp.p2shVersionByte);
        if (exp.p2pkhVersionByte !== undefined) {
          expect(cfg.p2pkhVersionByte).toBe(exp.p2pkhVersionByte);
        } else {
          expect(cfg.p2pkhVersionByte).toBeUndefined();
        }
      });
    });
  }

  it('BCH2 uses a coin type distinct from BCH so keys never cross-derive', () => {
    expect(chainConfigs.bch2.bip44CoinType).not.toBe(chainConfigs.bch.bip44CoinType);
  });
});

describe('chainConfigs — EVM chains', () => {
  for (const chain of EVM_CHAINS) {
    const exp = EXPECTED_EVM[chain as 'eth' | 'base' | 'arb' | 'poly'];
    describe(`${chain}`, () => {
      const cfg = chainConfigs[chain];

      it('identity + isEvm + evmChainId', () => {
        expect(cfg.name).toBe(exp.name);
        expect(cfg.ticker).toBe(exp.ticker);
        expect(cfg.isEvm).toBe(true);
        expect(cfg.evmChainId).toBe(exp.evmChainId);
      });

      it('avgBlockTimeSec', () => {
        expect(cfg.avgBlockTimeSec).toBe(exp.avgBlockTimeSec);
      });

      it('min/maxLockBlocks (dead code — real EVM lock params live in evm-config.ts, pinned to catch edits)', () => {
        expect(cfg.minLockBlocks).toBe(exp.minLockBlocks);
        expect(cfg.maxLockBlocks).toBe(exp.maxLockBlocks);
        expect(cfg.maxLockBlocks!).toBeGreaterThan(cfg.minLockBlocks!);
      });

      it('carries NO UTXO fund params (no dust / conf / fee-byte / sighash fields leak onto an EVM entry)', () => {
        expect(cfg.dustThreshold).toBeUndefined();
        expect(cfg.requiredConfirmations).toBeUndefined();
        expect(cfg.feePerByte).toBeUndefined();
        expect(cfg.sighashType).toBeUndefined();
        expect(cfg.useBip143).toBeUndefined();
        expect(cfg.addressPrefix).toBeUndefined();
        expect(cfg.p2shVersionByte).toBeUndefined();
      });

      it('MAX_FEE_RATE ceiling is 0 (no UTXO fee on an EVM leg)', () => {
        expect(MAX_FEE_RATE_SAT_PER_BYTE[chain]).toBe(exp.maxFeeRateSatPerByte);
      });
    });
  }
});

describe('chainConfigs — every declared Chain has an entry', () => {
  it('has exactly the 8 supported chains, no more no fewer', () => {
    expect(Object.keys(chainConfigs).sort()).toEqual([...ALL_CHAINS].sort());
  });
});

describe('getChainConfig()', () => {
  it('returns the SAME config object for each known chain', () => {
    for (const chain of ALL_CHAINS) {
      expect(getChainConfig(chain)).toBe(chainConfigs[chain]);
    }
  });

  it('fail-closed: throws on an unknown chain string cast to Chain (would otherwise return undefined)', () => {
    expect(() => getChainConfig('doge' as unknown as Chain)).toThrow(/unknown chain/);
    expect(() => getChainConfig('' as unknown as Chain)).toThrow(/unknown chain/);
  });
});

// ── Timelock constants ──────────────────────────────────────────────────────────────────────────
describe('timelock constants (block-count HTLC locks + wall-clock safety factor)', () => {
  it('LOCKTIME_BLOCKS: initiator 216 (~36h), responder 72 (~12h)', () => {
    expect(LOCKTIME_BLOCKS.initiator).toBe(216);
    expect(LOCKTIME_BLOCKS.responder).toBe(72);
    // Ordering invariant: the initiator must lock strictly longer than the responder.
    expect(LOCKTIME_BLOCKS.initiator).toBeGreaterThan(LOCKTIME_BLOCKS.responder);
  });

  it('TIMELOCK_SAFETY_K is 2 (survive up to a 2x nominal block rate)', () => {
    expect(TIMELOCK_SAFETY_K).toBe(2);
  });

  it('CLAIM_MARGIN_BLOCKS is 24 (~4h claim+confirm safety margin)', () => {
    expect(CLAIM_MARGIN_BLOCKS).toBe(24);
  });

  it('CLAIM_CONF_BUFFER_BLOCKS is 12 (confirmations the responder leg loses before reveal)', () => {
    expect(CLAIM_CONF_BUFFER_BLOCKS).toBe(12);
  });

  it('the two module-level K-safety invariants hold for the pinned constants', () => {
    // Fund-gate / ordering: initiator >= K*(responder + claimMargin).
    expect(LOCKTIME_BLOCKS.initiator).toBeGreaterThanOrEqual(
      TIMELOCK_SAFETY_K * (LOCKTIME_BLOCKS.responder + CLAIM_MARGIN_BLOCKS),
    );
    // Claim-window: responder >= K*claimMargin + confBuffer.
    expect(LOCKTIME_BLOCKS.responder).toBeGreaterThanOrEqual(
      TIMELOCK_SAFETY_K * CLAIM_MARGIN_BLOCKS + CLAIM_CONF_BUFFER_BLOCKS,
    );
  });

  it('module loads without tripping its startup assertion (proves the current constants are self-consistent)', async () => {
    await expect(import('./chain-config')).resolves.toBeDefined();
  });
});

// ── Wall-clock conversions ────────────────────────────────────────────────────────────────────
describe('minSecondsUntilRefund / maxSecondsUntilRefund (the ÷K and ×K conversions)', () => {
  it('minSecondsUntilRefund divides by K (conservative LOWER bound — chain could mine K× faster)', () => {
    // 72 responder blocks @ 600s ÷ K(2) = 21600s (6h), NOT the nominal 43200s.
    expect(minSecondsUntilRefund(72, 600)).toBe((72 * 600) / TIMELOCK_SAFETY_K);
    expect(minSecondsUntilRefund(72, 600)).toBe(21_600);
    // Strictly below nominal for K>1 so the gate under-estimates the counterparty's refund time.
    expect(minSecondsUntilRefund(72, 600)).toBeLessThan(72 * 600);
  });

  it('maxSecondsUntilRefund multiplies by K (conservative UPPER bound — chain could mine K× slower)', () => {
    // 72 responder blocks @ 600s × K(2) = 86400s (24h).
    expect(maxSecondsUntilRefund(72, 600)).toBe(72 * 600 * TIMELOCK_SAFETY_K);
    expect(maxSecondsUntilRefund(72, 600)).toBe(86_400);
    expect(maxSecondsUntilRefund(72, 600)).toBeGreaterThan(72 * 600);
  });

  it('the two bounds bracket the nominal estimate: min < nominal < max', () => {
    const blocks = LOCKTIME_BLOCKS.initiator;
    const sec = chainConfigs.bch2.avgBlockTimeSec;
    const nominal = blocks * sec;
    expect(minSecondsUntilRefund(blocks, sec)).toBeLessThan(nominal);
    expect(maxSecondsUntilRefund(blocks, sec)).toBeGreaterThan(nominal);
    // max is K^2 the min (÷K vs ×K).
    expect(maxSecondsUntilRefund(blocks, sec)).toBe(
      minSecondsUntilRefund(blocks, sec) * TIMELOCK_SAFETY_K * TIMELOCK_SAFETY_K,
    );
  });

  it('zero blocks remaining => zero seconds on both bounds', () => {
    expect(minSecondsUntilRefund(0, 600)).toBe(0);
    expect(maxSecondsUntilRefund(0, 600)).toBe(0);
  });
});

// ── Fee caps + urgency ramp ────────────────────────────────────────────────────────────────────
describe('fee caps + urgency ramp', () => {
  it('MAX_FEE_RATE_SAT_PER_BYTE record is exactly the pinned per-chain ceilings', () => {
    expect(MAX_FEE_RATE_SAT_PER_BYTE).toEqual({
      bch2: 20, bch: 20, btc: 100, bc2: 20, eth: 0, base: 0, arb: 0, poly: 0,
    });
  });

  it('maxFeeRate() returns the ceiling for UTXO chains', () => {
    expect(maxFeeRate('bch2')).toBe(20);
    expect(maxFeeRate('bch')).toBe(20);
    expect(maxFeeRate('btc')).toBe(100);
    expect(maxFeeRate('bc2')).toBe(20);
  });

  it('maxFeeRate() falls back to 1 for the 0-ceiling EVM chains (0 is falsy => `|| 1`)', () => {
    // Pins the ACTUAL behavior: EVM chains have no UTXO fee, so the || fallback yields 1, not 0.
    for (const chain of EVM_CHAINS) {
      expect(MAX_FEE_RATE_SAT_PER_BYTE[chain]).toBe(0);
      expect(maxFeeRate(chain)).toBe(1);
    }
  });

  it('FEE_URGENCY_MAX_MULT is 3 and FEE_URGENCY_START_FACTOR is 4', () => {
    expect(FEE_URGENCY_MAX_MULT).toBe(3);
    expect(FEE_URGENCY_START_FACTOR).toBe(4);
    // The ramp must begin (START_FACTOR) before the peak multiplier so it can climb gradually.
    expect(FEE_URGENCY_START_FACTOR).toBeGreaterThan(FEE_URGENCY_MAX_MULT - 1);
  });

  it('worst-case ramped rate never exceeds the ceiling for any UTXO chain', () => {
    // The ramp scales the live base rate up to FEE_URGENCY_MAX_MULT but clamps to MAX_FEE_RATE.
    // The base * max-mult must stay within the ceiling for the pinned base rates, otherwise the
    // guaranteed-claimable floor (sized at MAX_FEE_RATE) would not cover the ramped claim fee.
    for (const chain of UTXO_CHAINS) {
      const base = chainConfigs[chain].feePerByte!;
      const ramped = base * FEE_URGENCY_MAX_MULT;
      // Not every base*mult is <= ceiling in general (that's what the clamp is for), but for the
      // current pinned values the ceiling is comfortably above the ramped base rate.
      expect(MAX_FEE_RATE_SAT_PER_BYTE[chain]).toBeGreaterThanOrEqual(ramped);
    }
  });
});

// ── Suspension gate ──────────────────────────────────────────────────────────────────────────
describe('swap-pair suspension gate', () => {
  it('SUSPENDED_SWAP_CHAINS contains exactly bc2', () => {
    expect(SUSPENDED_SWAP_CHAINS.has('bc2')).toBe(true);
    expect(SUSPENDED_SWAP_CHAINS.size).toBe(1);
    // No other chain is suspended.
    for (const chain of ALL_CHAINS) {
      expect(SUSPENDED_SWAP_CHAINS.has(chain)).toBe(chain === 'bc2');
    }
  });

  it('isSwapSuspended: true only for bc2', () => {
    for (const chain of ALL_CHAINS) {
      expect(isSwapSuspended(chain)).toBe(chain === 'bc2');
    }
  });

  it('isSwapPairSuspended: FULL truth table — a pair is suspended iff EITHER leg is bc2', () => {
    for (const a of ALL_CHAINS) {
      for (const b of ALL_CHAINS) {
        const expected = a === 'bc2' || b === 'bc2';
        expect(isSwapPairSuspended(a, b)).toBe(expected);
      }
    }
  });

  it('a bc2 leg is suspended regardless of counterparty; a non-bc2/non-bc2 pair is allowed', () => {
    expect(isSwapPairSuspended('bc2', 'bch2')).toBe(true);
    expect(isSwapPairSuspended('bch2', 'bc2')).toBe(true);
    expect(isSwapPairSuspended('bc2', 'bc2')).toBe(true);
    expect(isSwapPairSuspended('bch2', 'poly')).toBe(false);
    expect(isSwapPairSuspended('btc', 'eth')).toBe(false);
  });
});

// ── REGTEST toggle: exercises the OTHER branch of the address-encoding switch ──────────────────
describe('REGTEST toggle (BCH2_SWAP_NETWORK=regtest) — regtest address encodings', () => {
  it('re-derives regtest prefixes / version bytes while BCH2 stays bitcoincashii', async () => {
    const env = proc?.env;
    if (!env) {
      // No process.env (unexpected under vitest/node) — nothing to toggle.
      expect(true).toBe(true);
      return;
    }
    const prev = env.BCH2_SWAP_NETWORK;
    env.BCH2_SWAP_NETWORK = 'regtest';
    vi.resetModules();
    try {
      const mod = await import('./chain-config');
      // BCH2's regtest node still emits the 'bitcoincashii' prefix — unchanged by the toggle.
      expect(mod.chainConfigs.bch2.addressPrefix).toBe('bitcoincashii');
      // BCH switches to the regtest CashAddr prefix.
      expect(mod.chainConfigs.bch.addressPrefix).toBe('bchreg');
      // BTC/BC2 switch to the Base58 regtest/testnet version bytes.
      expect(mod.chainConfigs.btc.p2shVersionByte).toBe(0xc4);
      expect(mod.chainConfigs.btc.p2pkhVersionByte).toBe(0x6f);
      expect(mod.chainConfigs.bc2.p2shVersionByte).toBe(0xc4);
      expect(mod.chainConfigs.bc2.p2pkhVersionByte).toBe(0x6f);
    } finally {
      if (prev === undefined) delete env.BCH2_SWAP_NETWORK;
      else env.BCH2_SWAP_NETWORK = prev;
      vi.resetModules();
    }
  });
});
