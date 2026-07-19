import type { Chain, ChainConfig } from './swap-types';

// R268-NETWORK: regtest/mainnet UTXO encoding toggle. DEFAULTS TO MAINNET. Set the env var
// BCH2_SWAP_NETWORK=regtest (Node) to derive REGTEST address encodings that match the swap DEX's regtest
// nodes: BCH2 is UNCHANGED (its regtest node emits the 'bitcoincashii' prefix); BCH -> 'bchreg', BTC/BC2 ->
// P2PKH 0x6f / P2SH 0xc4. Portable read via globalThis so the SDK works under Node, bundlers, and browsers
// without a Vite/@types/node dependency; absent process (browser) => mainnet.
const REGTEST = (globalThis as { process?: { env?: Record<string, string | undefined> } })
  .process?.env?.BCH2_SWAP_NETWORK === 'regtest';

export const chainConfigs: Record<Chain, ChainConfig> = {
  bch2: {
    name: 'Bitcoin Cash II',
    ticker: 'BCH2',
    addressPrefix: 'bitcoincashii',
    p2shVersionByte: 0x05,
    sighashType: 0x41, // SIGHASH_ALL | SIGHASH_FORKID
    useBip143: true,
    electrumServers: [
      { host: 'electrum.bch2.org', port: 50002, ssl: true },
      { host: '144.202.73.66', port: 50002, ssl: true },
    ],
    avgBlockTimeSec: 600,
    dustThreshold: 182, // 1000 sat/kvB relay rate: 1000/1000*(34+148)=182 sat for P2PKH
    feePerByte: 1,
    bip44CoinType: 20145, // BCH2-specific; differs from BCH (145) to prevent key reuse. BREAKING: existing wallets derived under 145 must re-derive.
    // R117-CHAIN-001: raised from 3 to 6 — BCH2 is a minority-hashrate chain; 51%-attack cost
    // on 3 BCH2 blocks is extremely low. 6 confs ≈ 1 hour at 10-min blocks. Re-assess at mainnet launch.
    requiredConfirmations: 6,
  },
  bch: {
    name: 'Bitcoin Cash',
    ticker: 'BCH',
    addressPrefix: REGTEST ? 'bchreg' : 'bitcoincash',
    p2shVersionByte: 0x05,
    sighashType: 0x41, // SIGHASH_ALL | SIGHASH_FORKID
    useBip143: true,
    electrumServers: [
      { host: 'bch0.kister.net', port: 50002, ssl: true },
      { host: 'blackie.c3-soft.com', port: 50002, ssl: true },
    ],
    avgBlockTimeSec: 600,
    dustThreshold: 182, // 1000 sat/kvB relay rate: same as BCH2
    feePerByte: 1,
    bip44CoinType: 145,
    // R116-CHAIN-001: raised from 3 to 6 — BCH hashrate is orders of magnitude below BTC's,
    // making a 51% attack on 3 BCH blocks much cheaper than 2 BTC blocks. 6 confs ≈ 1 hour.
    requiredConfirmations: 6,
  },
  btc: {
    name: 'Bitcoin',
    ticker: 'BTC',
    p2shVersionByte: REGTEST ? 0xc4 : 0x05,
    p2pkhVersionByte: REGTEST ? 0x6f : 0x00,
    sighashType: 0x01, // SIGHASH_ALL
    useBip143: false,
    electrumServers: [
      { host: 'electrum.blockstream.info', port: 50002, ssl: true },
      { host: 'electrum.emzy.de', port: 50002, ssl: true },
    ],
    avgBlockTimeSec: 600,
    dustThreshold: 546,
    feePerByte: 10,
    bip44CoinType: 0,
    requiredConfirmations: 2,
  },
  bc2: {
    name: 'Bitcoin II',
    ticker: 'BC2',
    p2shVersionByte: REGTEST ? 0xc4 : 0x05,
    p2pkhVersionByte: REGTEST ? 0x6f : 0x00,
    sighashType: 0x01, // SIGHASH_ALL
    useBip143: false,
    electrumServers: [
      { host: 'infra1.bitcoin-ii.org', port: 50009, ssl: true },
      { host: '50.6.6.41', port: 50009, ssl: true },
    ],
    avgBlockTimeSec: 600,
    dustThreshold: 546,
    feePerByte: 1,
    bip44CoinType: 1, // SLIP-0044 testnet reserved. WARNING: key reuse risk with any BTC/LTC testnet wallet using same mnemonic. TODO: register a custom coin type (e.g. 20002) before BC2 mainnet.
    requiredConfirmations: 3,
  },
  // R21-HTLC-001: EVM responder minLockBlocks must be ~12h (not ~24h).
  // The UTXO initiator locks for LOCKTIME_BLOCKS.initiator (216 blocks, ~36h). The EVM responder must lock for
  // strictly less time so the initiator cannot simultaneously claim EVM and refund UTXO.
  // Rule: EVM minLockBlocks ≈ LOCKTIME_BLOCKS.responder * avgBlockTimeSec / evmAvgBlockTimeSec
  eth: {
    name: 'Ethereum Sepolia',
    ticker: 'ETH',
    isEvm: true,
    evmChainId: 11155111,
    avgBlockTimeSec: 12,
    // NOTE: minLockBlocks/maxLockBlocks for EVM chains in this file are DEAD CODE.
    // The swap engine reads lock parameters from evm-config.ts (EVM_CHAINS).
    // These values are intentionally different (production vs testnet scales).
    // Do NOT rely on chain-config.ts for EVM timing parameters. See R38-CFG-002.
    minLockBlocks: 3_600,    // ~12h at 12s/block (half of UTXO initiator locktime)
    maxLockBlocks: 86_400,   // ~12 days at 12s/block
  },
  base: {
    name: 'Base Sepolia',
    ticker: 'BASE',
    isEvm: true,
    evmChainId: 84532,
    avgBlockTimeSec: 2,
    // NOTE: minLockBlocks/maxLockBlocks for EVM chains in this file are DEAD CODE.
    // The swap engine reads lock parameters from evm-config.ts (EVM_CHAINS).
    // These values are intentionally different (production vs testnet scales).
    // Do NOT rely on chain-config.ts for EVM timing parameters. See R38-CFG-002.
    minLockBlocks: 21_600,   // ~12h at 2s/block (half of UTXO initiator locktime)
    maxLockBlocks: 518_400,  // ~12 days at 2s/block
  },
  arb: {
    name: 'Arbitrum',
    ticker: 'ARB',
    isEvm: true,
    evmChainId: 42161,
    avgBlockTimeSec: 1,
    // NOTE: minLockBlocks/maxLockBlocks for EVM chains in this file are DEAD CODE.
    // The swap engine reads lock parameters from evm-config.ts (EVM_CHAINS).
    // These values are intentionally different (production vs testnet scales).
    // Do NOT rely on chain-config.ts for EVM timing parameters. See R38-CFG-002.
    minLockBlocks: 43_200,    // ~12h at 1s/block (half of UTXO initiator locktime)
    maxLockBlocks: 1_036_800, // ~12 days at 1s/block
  },
  poly: {
    name: 'Polygon',
    ticker: 'POL',
    isEvm: true,
    evmChainId: 137,
    avgBlockTimeSec: 2,
    // Dead code for EVM chains (lock params come from evm-config.ts EVM_CHAINS). See R38-CFG-002.
    minLockBlocks: 10_800, // ~6h at 2s/block
    maxLockBlocks: 86_400, // ~48h at 2s/block
  },
};

// Locktime blocks for each role
// Initiator locks funds for longer, responder for shorter
// This ensures the initiator can always claim before the responder can refund
export const LOCKTIME_BLOCKS = {
  initiator: 216, // ~36 hours (R-TIMELOCK-K: raised from 144 so the ÷K responder fund gate still leaves a funding window)
  responder: 72,  // ~12 hours (R-TIMELOCK-K: kept at 12h — the initiator's claim window on this leg needs K*margin + confs)
};

// R-TIMELOCK-K: BCH2 is MINORITY-HASHRATE, so a height-based (CLTV) leg can mature FASTER in wall-clock than the
// nominal block time — from natural variance or an attacker pointing hashrate at the low-difficulty chain (ASERT
// claws the rate back within a few blocks, bounding SUSTAINED acceleration, but not short bursts). Timelocks are
// heights, but the safety comparisons are wall-clock, so a fast chain can invert the effective ordering. Every
// "seconds until a leg refunds" estimate used in a swap-safety gate is therefore sized conservatively by this factor
// so a K-fold acceleration cannot invert the ordering or shrink a claim window below the margin. K=2 = survive up to
// a 2x nominal block rate. See minSecondsUntilRefund / maxSecondsUntilRefund below.
export const TIMELOCK_SAFETY_K = 2;

// Fixed claim+confirm safety margin in NOMINAL blocks (4h at 600s) — matches EVM_CLAIM_MARGIN_SEC.
export const CLAIM_MARGIN_BLOCKS = 24;

// Blocks the responder leg loses to confirmations before the initiator can reveal/claim it (max UTXO
// requiredConfirmations is 6; +slack). The responder lock must exceed K*CLAIM_MARGIN_BLOCKS by this much or the
// initiator's ÷K claim/reveal gates can never pass (the swap would brick — the R-TIMELOCK-K v1 regression).
export const CLAIM_CONF_BUFFER_BLOCKS = 12;

// Conservative LOWER bound on wall-clock seconds until a height-based leg (`blocksRemaining` away) becomes refundable,
// assuming the chain could mine up to K x FASTER than nominal. Use wherever the risk is the COUNTERPARTY leg you must
// claim refunding EARLY (responder fund gate, reveal gate, EVM-responder pre-lock, the ordering guards' fast side).
export function minSecondsUntilRefund(blocksRemaining: number, chainBlockSec: number): number {
  return (blocksRemaining * chainBlockSec) / TIMELOCK_SAFETY_K;
}

// Conservative UPPER bound on wall-clock seconds a height-based leg (`blocks` away) could take to refund, assuming the
// chain could mine up to K x SLOWER. Use wherever the risk is a leg maturing LATE (the cross-chain ordering guards).
export function maxSecondsUntilRefund(blocks: number, chainBlockSec: number): number {
  return blocks * chainBlockSec * TIMELOCK_SAFETY_K;
}

// R113-CHAIN-001 + R-TIMELOCK-K: startup assertion — catch misconfigured locktimes at module init time. The initiator
// lock must be >= K x (responder lock + claim margin) so the conservative responder fund gate (which requires the
// initiator leg to have that many blocks left even at a K-fold acceleration) can still be satisfied — i.e. swaps are
// possible AND K-safe. Ordering (responder < initiator) and absolute floors are also enforced.
if (
  LOCKTIME_BLOCKS.initiator < 24 ||
  LOCKTIME_BLOCKS.responder < 12 ||
  LOCKTIME_BLOCKS.responder >= LOCKTIME_BLOCKS.initiator ||
  // Fund-gate / ordering K-safety: the responder only funds when the initiator leg has K*(responder+margin) blocks
  // left; the initiator lock must exceed that so a funding window exists AND a K-fold acceleration can't invert.
  LOCKTIME_BLOCKS.initiator < TIMELOCK_SAFETY_K * (LOCKTIME_BLOCKS.responder + CLAIM_MARGIN_BLOCKS) ||
  // Claim-window K-safety (the R-TIMELOCK-K v1 regression guard): the initiator claims the SHORT responder leg via a
  // ÷K reveal/claim gate that needs K*CLAIM_MARGIN_BLOCKS blocks of runway; after confirmations consume some, the
  // responder lock must still exceed that or the initiator can never reveal (swap bricks, both refund).
  LOCKTIME_BLOCKS.responder < TIMELOCK_SAFETY_K * CLAIM_MARGIN_BLOCKS + CLAIM_CONF_BUFFER_BLOCKS
) {
  throw new Error(
    'chain-config: LOCKTIME_BLOCKS misconfigured — need initiator >= 24, responder >= 12, responder < initiator, ' +
    `initiator >= K*(responder+claimMargin) = ${TIMELOCK_SAFETY_K * (LOCKTIME_BLOCKS.responder + CLAIM_MARGIN_BLOCKS)}, ` +
    `and responder >= K*claimMargin+confBuffer = ${TIMELOCK_SAFETY_K * CLAIM_MARGIN_BLOCKS + CLAIM_CONF_BUFFER_BLOCKS}`,
  );
}

// BC2 trading is SUSPENDED (2026-07): BC2's real block time is ~21000s, but the HTLC refund
// timelocks are block-count based (LOCKTIME_BLOCKS). On a ~35x-slower chain a 72-block responder
// leg matures ~17.5 days out while a fast-chain 216-block initiator leg matures in ~36h — inverting
// the timelock ordering the safety gates assume (they convert blocks->wall-clock via avgBlockTimeSec,
// which is 600 for bc2, so they cannot see the inversion). Until BC2 gets per-chain wall-clock-
// normalized timelocks, no offer may be CREATED or TAKEN on bc2. Holding/receiving BC2 is unaffected.
export const SUSPENDED_SWAP_CHAINS: ReadonlySet<Chain> = new Set<Chain>(['bc2']);
export function isSwapSuspended(chain: Chain): boolean {
  return SUSPENDED_SWAP_CHAINS.has(chain);
}

/**
 * Canonical two-leg suspension gate: a swap is suspended if EITHER leg is on a suspended chain.
 * Every create / take / fund entry point (SwapCreate, SwapBrowse, SwapExecute — mirrored by the
 * proxy's SUSPENDED_CHAINS 403) MUST route through this single predicate so a new call site cannot
 * silently bypass the gate. The bc2-suspension test locks the full chain-pair truth table, and the
 * inversion this prevents is a both-legs fund-loss (see SUSPENDED_SWAP_CHAINS above), so this is the
 * one invariant that must never regress while any chain is suspended.
 */
export function isSwapPairSuspended(chainA: Chain, chainB: Chain): boolean {
  return isSwapSuspended(chainA) || isSwapSuspended(chainB);
}

// ── Dynamic fee: ceiling + deadline-aware ramp ──────────────────────────────────────────────────────
// MAX_FEE_RATE bounds the live/deadline-scaled claim & refund fee AND sizes the funding floor
// (minClaimableHtlcAmount) — a HTLC that funds is guaranteed claimable even at the WORST-CASE fee, so a
// fee spike can never strand a leg. This coupling is the core fund-safety invariant of the fee fix: the
// ramp clamps to MAX_FEE_RATE and the floor is sized at MAX_FEE_RATE, so claim fee <= what funding covered.
// BTC = 100 sat/vB (covers most real spikes; ~$15-25 worst-case min swap); BCH-family = 20 (min impact ~1c);
// EVM chains have no UTXO fee (0). Tune per chain as fee markets evolve.
export const MAX_FEE_RATE_SAT_PER_BYTE: Record<Chain, number> = {
  bch2: 20, bch: 20, btc: 100, bc2: 20, eth: 0, base: 0, arb: 0, poly: 0,
};
export function maxFeeRate(chain: Chain): number {
  return MAX_FEE_RATE_SAT_PER_BYTE[chain] || 1;
}

// Deadline-aware ramp: as a leg's remaining runway shrinks toward the safety margin, scale the live base
// rate up to FEE_URGENCY_MAX_MULT. On the first-seen chains (bch2/bch/bc2) a broadcast tx cannot be
// replaced, so pricing UP as the deadline nears is the only defense — the ramp must be adequate up-front.
export const FEE_URGENCY_MAX_MULT = 3;      // at/inside the safety margin, pay up to 3x the live base rate
export const FEE_URGENCY_START_FACTOR = 4;  // begin ramping once remaining runway < 4x the safety margin

export function getChainConfig(chain: Chain): ChainConfig {
  // R115-CHAIN-002: runtime guard — chainConfigs is Record<Chain, ChainConfig> so TypeScript
  // prevents compile-time misses, but a runtime-cast string (e.g. userInput as Chain) would
  // silently return undefined, causing a TypeError on the first property access at the call site.
  const cfg = chainConfigs[chain];
  if (!cfg) throw new Error(`getChainConfig: unknown chain '${chain}'`);
  return cfg;
}
