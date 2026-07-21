// ============================================================================
// EVM Chain Configuration — TESTNET (Base Sepolia + Arb Sepolia)
// ============================================================================

import { ethers } from 'ethers';
import type { EvmChainId } from './swap-types';
import { LOCKTIME_BLOCKS, chainConfigs, minSecondsUntilRefund, maxSecondsUntilRefund } from './chain-config';
export type { EvmChainId };

export interface EvmToken {
  symbol: string;
  address: string;
  decimals: number;
  name: string;
}

export interface EvmChainConfig {
  chainId: EvmChainId;
  name: string;
  shortName: string;
  nativeSymbol: string;
  avgBlockTimeSec: number;
  // R143-EVM-CONFDEPTH-001: confirmation depth required before a UTXO responder commits its
  // (irreversible) UTXO leg against a counterparty EVM lock. The UTXO leg already enforces per-chain
  // requiredConfirmations (chain-config.ts) + a broadcast-time re-verify (R125-SE-010); the EVM leg
  // previously accepted the lock at the unconfirmed/shallow `latest` tip (0-conf), which an OP-stack
  // sequencer tip-reorg / same-nonce replacement can drop — a cross-chain atomicity break (the
  // secret-reveal lands on the OTHER chain and does NOT reorg with the lock). Sized past each chain's
  // shallow-reorg horizon for its block time.
  requiredConfirmations: number;
  htlcAddress: string;
  // R138b-XCHAIN-001: the deployed TokenHTLC/TokenHTLCTestnet is UNIX-TIMESTAMP based
  // (timeLock is an absolute block.timestamp in seconds, bounded by [minLockSeconds, maxLockSeconds]).
  // These are the AUTHORITATIVE lock bounds for the swap engine. minLockBlocks/maxLockBlocks are
  // retained only as a coarse block-window hint for eth_getLogs event scanning (which is block-number
  // based regardless of the timelock basis) and for the deploy-gate startup checks.
  minLockSeconds: number;
  maxLockSeconds: number;
  minLockBlocks: number;
  maxLockBlocks: number;
  rpcUrl: string;
  tokens: Record<string, EvmToken>;
}

// R266-NATIVE-ETH: declared ABOVE EVM_CHAINS so the ETH token entries (address: NATIVE_ETH_ADDRESS) below can
// reference it without a temporal-dead-zone ReferenceError at module load.
export const NATIVE_ETH_ADDRESS = '0x0000000000000000000000000000000000000000';

export const EVM_CHAINS: Partial<Record<EvmChainId, EvmChainConfig>> = {
  // R114-CFG-002: Ethereum Sepolia (11155111) — in EvmChainId type but no contract deployed.
  // Included here so getEvmConfig(11155111) returns a config (not null → crash) and so
  // validateEvmConfigs() can check it. DO NOT add to SUPPORTED_EVM_CHAINS until deployed.
  11155111: {
    chainId: 11155111,
    name: 'Ethereum Sepolia',
    shortName: 'eth',
    nativeSymbol: 'ETH',
    avgBlockTimeSec: 12,
    requiredConfirmations: 4, // R143: ~48s; Ethereum Sepolia (not deployed/used yet)
    htlcAddress: '0x0000000000000000000000000000000000000000', // TODO: deploy contract
    minLockSeconds: 300,
    maxLockSeconds: 86400,
    minLockBlocks: 300,
    maxLockBlocks: 86400,
    rpcUrl: 'https://ethereum-sepolia-rpc.publicnode.com',
    tokens: {},
  },
  // R266-ARB-ENABLE: HTLC DEPLOYED on Arbitrum Sepolia + added to SUPPORTED_EVM_CHAINS. Lock params are identical
  // to the proven-safe Base Sepolia (300/86400, on-chain-verified), and Arbitrum supports the 'safe'/'finalized'
  // block tags so the R148/R206 reorg-safe finality reads work. USDT/USDC already deployed on Arbitrum Sepolia.
  421614: {
    chainId: 421614,
    name: 'Arbitrum Sepolia',
    shortName: 'arb',
    nativeSymbol: 'ETH',
    avgBlockTimeSec: 1,
    requiredConfirmations: 30, // R143: ~30s at 1s/block (≈ Base Sepolia's 15×2s reorg-safe window)
    htlcAddress: '0x405A6dD5b51a00C5F789C9D215e4986ba1Dc9963', // R266: deployed TokenHTLCTestnet (MIN/MAX_LOCK_SECONDS 300/86400, verified on-chain)
    // WARNING: minLockBlocks here overrides chain-config.ts values (mainnet=43200/86400).
    // Swap engine reads from evm-config.ts for EVM-chain config. Keep these consistent with chain-config.ts
    // when deploying to mainnet.
    // R31-EVM-003: 300 blocks = ~5 min on Arb Sepolia (1s/block). Mainnet should use 2160+ (72 min at 1s/block).
    minLockSeconds: 300,
    maxLockSeconds: 86400,
    minLockBlocks: 300,
    maxLockBlocks: 86400,
    rpcUrl: 'https://sepolia-rollup.arbitrum.io/rpc',
    tokens: {
      USDT: {
        symbol: 'USDT',
        address: '0x1F6A3cEE99F04A306FE99E0E783be4C07DEd2525',
        decimals: 6,
        name: 'Tether USD',
      },
      USDC: {
        symbol: 'USDC',
        address: '0x77a07183922417C381262723fFe548dBF1afa838',
        decimals: 6,
        name: 'USD Coin',
      },
      ETH: { symbol: 'ETH', address: NATIVE_ETH_ADDRESS, decimals: 18, name: 'Ether' }, // R266: native ETH swappable (HTLC address(0) path)
    },
  },
  84532: {
    chainId: 84532,
    name: 'Base Sepolia',
    shortName: 'base',
    nativeSymbol: 'ETH',
    avgBlockTimeSec: 2,
    requiredConfirmations: 15, // R143: ~30s, past Base Sepolia OP-stack tip-reorg horizon (2s blocks)
    // R138b-XCHAIN-001: canonical TokenHTLCTestnet (UNIX-TIMESTAMP based, MIN_LOCK_SECONDS=300,
    // MAX_LOCK_SECONDS=86400, verified on-chain). Reconciled with packages/swap-core
    // (TOKEN_HTLC_ADDRESS.baseSepoliaTestnet) + prover/e2e/config-base-sepolia.json (htlc_test_address).
    // PREVIOUS value 0xe0ED04861A00FC1f2656AEbde11590CDcBA767a2 was the ZK-DEX BCH2SwapEscrow
    // (no lock/claim/getSwap selectors) — every EVM lock reverted. See AUDIT_LOG R138 / R138b.
    htlcAddress: '0x9A7D64F9dF98112A16E56B1eD9F2Bb8D9986a4cF',
    // R138b-XCHAIN-001: authoritative lock bounds in SECONDS, matching the deployed contract's
    // MIN_LOCK_SECONDS/MAX_LOCK_SECONDS read on-chain. minLockBlocks/maxLockBlocks below are a
    // coarse block-window hint for event scanning only (Base Sepolia ~2s/block → 86400 blocks ≈ 48h).
    minLockSeconds: 300,
    maxLockSeconds: 86400,
    minLockBlocks: 300,
    maxLockBlocks: 86400,
    rpcUrl: 'https://sepolia.base.org',
    tokens: {
      USDC: {
        symbol: 'USDC',
        // R138b-XCHAIN-001: canonical MockUSDC shared with packages/swap-core + web-wallet
        // (prover/e2e/config-base-sepolia.json usdc_address). PREVIOUS 0x94F6567f… was a divergent
        // bch2-swap-only MockUSDC deployment, breaking interop with canonical-ecosystem counterparties.
        address: '0x5cAd6F5A4eC28Ec42e3953A728a5Eea35719BB0D',
        decimals: 6,
        name: 'USD Coin',
      },
      // NOTE: no canonical testnet USDT exists in packages/swap-core. This MockUSDT is bch2-swap-internal
      // (offers are takeable only between bch2-swap users, not canonical-ecosystem wallets). Verified deployed.
      USDT: {
        symbol: 'USDT',
        address: '0x0F697BB2f8eAdb75C868CfD58e6096Ab726B3E49',
        decimals: 6,
        name: 'Tether USD',
      },
      ETH: { symbol: 'ETH', address: NATIVE_ETH_ADDRESS, decimals: 18, name: 'Ether' }, // R266: native ETH swappable (HTLC address(0) path)
    },
  },
  // ── Polygon MAINNET (137) — TokenHTLCSwap deployed 0x405A6dD5b51a00C5F789C9D215e4986ba1Dc9963 (MIN 6h / MAX 48h,
  //    verified on-chain). Token addresses match the KDF/NonKYC PLG20 contracts. minLock/maxLockSeconds MUST equal
  //    the deployed contract's MIN_LOCK_SECONDS/MAX_LOCK_SECONDS. ───────────────────────────────────────────────
  137: {
    chainId: 137,
    name: 'Polygon',
    shortName: 'poly',
    nativeSymbol: 'POL',
    avgBlockTimeSec: 2,
    requiredConfirmations: 128, // Polygon reorg safety — well beyond ~16-block milestone finality
    htlcAddress: '0x405A6dD5b51a00C5F789C9D215e4986ba1Dc9963',
    minLockSeconds: 21_600,  // 6h — MUST match contract MIN_LOCK_SECONDS
    maxLockSeconds: 172_800, // 48h — MUST match contract MAX_LOCK_SECONDS
    minLockBlocks: 10_800,   // ~6h at 2s (event-scan hint only)
    maxLockBlocks: 86_400,   // ~48h at 2s (event-scan hint only)
    // R-POLYHIST: primary must be tenderly (NOT publicnode) — getPublicProvider prepends rpcUrl, and ethers'
    // FallbackProvider uses the FIRST leaf for getLogs; publicnode 403s on getLogs+historical and poisons the
    // read, so it's dropped from Polygon entirely. tenderly serves latest+historical+getLogs; drpc backs it.
    rpcUrl: 'https://polygon.gateway.tenderly.co',
    tokens: {
      USDC: { symbol: 'USDC', address: '0x3c499c542cEF5E3811e1192ce70d8cC03d5c3359', decimals: 6, name: 'USD Coin' },   // native Circle USDC (KDF/NonKYC USDC-PLG20)
      USDT: { symbol: 'USDT', address: '0xc2132D05D31c914a87C6611C10748AEb04B58e8F', decimals: 6, name: 'Tether USD' }, // USDT-PLG20
      POL:  { symbol: 'POL', address: NATIVE_ETH_ADDRESS, decimals: 18, name: 'Polygon' },                              // native gas token (HTLC address(0) path)
    },
  },
  // ── Arbitrum One MAINNET (42161) — TokenHTLCSwap 0x141F8f62F92c6486a7EfE8D0891A6800d7ED1186 (MIN 6h / MAX 48h,
  //    verified on-chain). Native Circle USDC + USDT + native ETH. ───────────────────────────────────────────────
  42161: {
    chainId: 42161,
    name: 'Arbitrum',
    shortName: 'arb',
    nativeSymbol: 'ETH',
    avgBlockTimeSec: 1,
    requiredConfirmations: 30, // Arbitrum soft finality is fast (sequencer); reorgs are rare
    htlcAddress: '0x141F8f62F92c6486a7EfE8D0891A6800d7ED1186',
    minLockSeconds: 21_600,  // 6h — MUST match contract MIN_LOCK_SECONDS
    maxLockSeconds: 172_800, // 48h — MUST match contract MAX_LOCK_SECONDS
    minLockBlocks: 21_600,
    maxLockBlocks: 172_800,
    // R-POLYHIST: primary must be arb1 (NOT publicnode) — getPublicProvider prepends rpcUrl and ethers uses the FIRST
    // leaf for getLogs; publicnode 403s getLogs beyond ~100 blocks and would poison the secret-read. See FALLBACK_RPCS.
    rpcUrl: 'https://arb1.arbitrum.io/rpc',
    tokens: {
      USDC: { symbol: 'USDC', address: '0xaf88d065e77c8cC2239327C5EDb3A432268e5831', decimals: 6, name: 'USD Coin' },   // native Circle USDC
      USDT: { symbol: 'USDT', address: '0xFd086bC7CD5C481DCC9C85ebE478A1C0b69FCbb9', decimals: 6, name: 'Tether USD' }, // USDT (Arbitrum)
      ETH:  { symbol: 'ETH', address: NATIVE_ETH_ADDRESS, decimals: 18, name: 'Ether' },                                // native gas token
    },
  },
};

// R266-ARB-ENABLE: Arbitrum Sepolia (421614) now ENABLED — HTLC deployed (0x405A6dD5…), lock params == Base Sepolia
// (300/86400, verified), 'safe'/'finalized' tags supported, USDT/USDC already live there.
// R138b-XCHAIN-001: 84532 RE-ENABLED. The R138 CRITICAL is remediated by the full reconciliation:
// htlcAddress now points at the canonical UNIX-TIMESTAMP TokenHTLCTestnet (0x9A7D64F9…), USDC matches
// the canonical MockUSDC, and the client timeLock basis was converted from block.number to
// block.timestamp (see evm-client.ts claim/refund expiry checks + SwapExecute timeLock computation,
// and evmLockSecondsForRole below). EVM ↔ UTXO swaps are functional again against the deployed contracts.
// MAINNET: Polygon (137) is the live EVM chain. The Sepolia testnets (84532/421614) remain configured above
// but are no longer offered. Every chain here MUST have a deployed HTLC (validateEvmConfigs enforces it).
export const SUPPORTED_EVM_CHAINS: EvmChainId[] = [137, 42161];

// R30-EVM-002: use EVM_CHAINS as the single source of truth — previously hardcoded chain ID checks
// meant a newly added chain in EVM_CHAINS would silently return null from getEvmConfig.
/**
 * Returns the EVM chain config for the given chainId, or null if the chain is not configured.
 * @throws — does NOT throw; returns null for unknown chains.
 *   Callers MUST null-check the return value before accessing any fields.
 *   R39-CFG-001: use `if (!cfg) throw ...` at call sites to produce chain-specific error messages.
 */
export function getEvmConfig(chainId: EvmChainId): EvmChainConfig | null {
  return EVM_CHAINS[chainId] ?? null;
}

export function getEvmTokenSymbols(chainId: EvmChainId): string[] {
  return Object.keys(EVM_CHAINS[chainId]?.tokens ?? {});
}

// ============================================================================
// R124-XCHAIN-001: wall-clock-normalized EVM HTLC lock durations
// ----------------------------------------------------------------------------
// The universal atomic-swap safety rule is: the INITIATOR's lock must outlast the
// RESPONDER's lock in WALL-CLOCK time, so that after the initiator reveals the secret
// (by claiming the responder's HTLC near the responder's expiry) the responder still
// has time to claim the initiator's HTLC. The old EVM lock formula used RAW BLOCK
// counts (initiator minLockBlocks*2, responder minLockBlocks*1) with no block-time
// normalization. On Base Sepolia (2s/block) that gave a ~20min initiator EVM lock —
// SHORTER than a 12h responder UTXO lock — so in an EVM-initiator / UTXO-responder
// swap the initiator could refund their EVM lock after 20min and STILL claim the
// responder's 12h UTXO lock with the secret. We now derive EVM locks from the same
// canonical wall-clock seconds as the UTXO side, so the invariant holds in EVERY
// chain topology (UTXO↔UTXO, UTXO↔EVM, EVM↔UTXO, EVM↔EVM).
const UTXO_REF_BLOCK_SEC = chainConfigs.bch2.avgBlockTimeSec; // 600s — UTXO reference block time
/** Canonical initiator lock duration in wall-clock seconds (= UTXO initiator: 216 * 600 = 36h). */
export const INITIATOR_LOCK_SEC = LOCKTIME_BLOCKS.initiator * UTXO_REF_BLOCK_SEC;
/** Canonical responder lock duration in wall-clock seconds (= UTXO responder: 72 * 600 = 12h). */
export const RESPONDER_LOCK_SEC = LOCKTIME_BLOCKS.responder * UTXO_REF_BLOCK_SEC;
/** Wall-clock claim safety margin (= UTXO initiator margin: 24 blocks * 600 = 4h). */
export const EVM_CLAIM_MARGIN_SEC = 24 * UTXO_REF_BLOCK_SEC;

/**
 * Wall-clock-normalized EVM HTLC lock duration, in EVM blocks, for a swap role on a chain.
 * Both roles derive from the same canonical seconds as the UTXO side, then clamp into the
 * contract's accepted [minLockBlocks, maxLockBlocks-1] range. Callers MUST have already
 * null-checked the config. See R124-XCHAIN-001.
 */
export function evmLockBlocksForRole(cfg: EvmChainConfig, role: 'initiator' | 'responder'): number {
  const sec = role === 'initiator' ? INITIATOR_LOCK_SEC : RESPONDER_LOCK_SEC;
  const blocks = Math.ceil(sec / cfg.avgBlockTimeSec);
  // Respect the contract's accepted range. Floor at minLockBlocks (contract MIN), ceil at
  // maxLockBlocks-1 (strictly under contract MAX). validateEvmConfigs() asserts that this
  // clamp cannot invert the initiator>responder ordering for any SUPPORTED chain.
  return Math.min(Math.max(blocks, cfg.minLockBlocks), cfg.maxLockBlocks - 1);
}

/**
 * R138b-XCHAIN-001: wall-clock-normalized EVM HTLC lock DURATION in SECONDS for a role.
 * The deployed TokenHTLC is unix-timestamp based, so the lock duration is used directly (no
 * block-time conversion) — this is the natural basis and removes the block→wall-clock mismatch
 * that drove the R124 timelock-inversion class. Clamped into the contract's accepted
 * [minLockSeconds, maxLockSeconds] window. Callers MUST have already null-checked the config.
 *
 * On testnet maxLockSeconds=86400 (24h) == INITIATOR_LOCK_SEC, so the initiator clamps to exactly
 * the contract MAX. Callers compute timeLock = (latest block.timestamp) + this value, and the
 * contract's TooLong guard checks (timeLock - block.timestamp); since the lock tx mines strictly
 * AFTER the timestamp we read, (timeLock - block.timestamp) is strictly < this value at mine time,
 * so it never trips `> MAX_LOCK_SECONDS`. See SwapExecute timeLock computation.
 */
export function evmLockSecondsForRole(cfg: EvmChainConfig, role: 'initiator' | 'responder'): number {
  const sec = role === 'initiator' ? INITIATOR_LOCK_SEC : RESPONDER_LOCK_SEC;
  return Math.min(Math.max(sec, cfg.minLockSeconds), cfg.maxLockSeconds);
}

// NATIVE_ETH_ADDRESS is declared above EVM_CHAINS (R266) to avoid a TDZ; isNativeToken references it.
export function isNativeToken(tokenAddress: string): boolean {
  return tokenAddress === NATIVE_ETH_ADDRESS;
}

/**
 * R-EVMTOKEN-ALLOWLIST-001: Assert an offer's EVM token is one of the canonically-configured tokens for its chain,
 * binding the CLAIMED symbol to the CANONICAL address. Returns the canonical address on success; THROWS otherwise.
 *
 * WHY THIS IS LOAD-BEARING: the offer's `evmInfo.tokenAddress`/`tokenSymbol` come from the untrusted order-book box,
 * and the on-chain finality gate (isEvmLockAtSafeDepth) binds `lock.token === inv.token` where `inv.token` IS that
 * same offer field — a self-referential check that a maker who both advertises AND locks an attacker-chosen token
 * (worthless / fee-on-transfer / rebasing / ERC-777) trivially satisfies. This allowlist is the ONLY place that
 * authenticates the token identity against locally-trusted config, mirroring the live app's offer-ingest canonical
 * check (offer-ingest.ts R30-BROWSE-003 / R31-FE-002). Without it, a taker can be induced to fund a real leg against
 * a leg that pays back a worthless/short token.
 *
 *  - Native (zero-address): allowed only when the chain carries a configured native token entry; returns the
 *    zero-address as-is (the symbol is resolved from local config elsewhere, not trusted from the offer).
 *  - Non-native: REQUIRES a claimed symbol AND that the address equals the canonical address configured for that
 *    symbol on that chain — this rejects both an unrecognized token and the "advertise USDC, lock USDT" swap.
 */
export function assertCanonicalEvmToken(evmChainId: EvmChainId, tokenAddress: string, tokenSymbol?: string): string {
  const cfg = EVM_CHAINS[evmChainId];
  if (!cfg) throw new Error(`EVM token check: chain ${evmChainId} is not configured — refusing`);
  const tokens = cfg.tokens ?? {};
  const addrLc = (tokenAddress ?? '').toLowerCase();
  if (addrLc === NATIVE_ETH_ADDRESS.toLowerCase()) {
    const nativeLocal = Object.values(tokens).find((t) => t.address.toLowerCase() === NATIVE_ETH_ADDRESS.toLowerCase());
    if (!nativeLocal) throw new Error(`EVM token check: chain ${evmChainId} has no configured native token — refusing`);
    return NATIVE_ETH_ADDRESS;
  }
  const claimed = typeof tokenSymbol === 'string' ? tokenSymbol.toUpperCase().slice(0, 10) : '';
  if (!claimed) {
    throw new Error(`EVM token check: non-native token ${tokenAddress} on chain ${evmChainId} carries no symbol to bind — refusing`);
  }
  const canonical = tokens[claimed]?.address;
  if (!canonical || addrLc !== canonical.toLowerCase()) {
    throw new Error(
      `EVM token check: token ${tokenAddress} (claimed '${claimed}') is not the canonical ${claimed} on chain ${evmChainId} — ` +
      `refusing an unrecognized / non-allowlisted token`,
    );
  }
  return canonical;
}

/**
 * Validate that every chain in SUPPORTED_EVM_CHAINS has a deployed HTLC contract address.
 * Call this at startup to catch misconfiguration before any swaps are attempted.
 */
export function validateEvmConfigs(): void {
  for (const [chainId, cfg] of Object.entries(EVM_CHAINS)) {
    if (!cfg) continue;
    if (cfg.htlcAddress === NATIVE_ETH_ADDRESS || cfg.htlcAddress === '') {
      if (SUPPORTED_EVM_CHAINS.includes(Number(chainId) as EvmChainId)) {
        throw new Error(`EVM chain ${chainId} is in SUPPORTED_EVM_CHAINS but has no HTLC contract address`);
      }
    }
    // R143-EVM-CONFDEPTH-001: requiredConfirmations is fund-critical (gates the responder's irreversible
    // commit against the counterparty EVM lock). A 0/negative/non-integer value would silently disable the
    // depth gate (fail-open). Enforce a sane positive integer for every configured EVM chain.
    if (!Number.isInteger(cfg.requiredConfirmations) || cfg.requiredConfirmations < 1) {
      throw new Error(`EVM config chain ${chainId}: requiredConfirmations must be a positive integer (got ${cfg.requiredConfirmations})`);
    }
    // R109-CFG-001: validate EIP-55 checksum for token addresses on ALL chains (not just
    // SUPPORTED_EVM_CHAINS). Previously unsupported chains like Arbitrum Sepolia (421614)
    // skipped token address validation entirely, silently accepting malformed addresses.
    for (const [symbol, tok] of Object.entries(cfg.tokens ?? {})) {
      if (!/^0x[0-9a-fA-F]{40}$/.test(tok.address)) {
        throw new Error(`EVM config chain ${chainId}: token ${symbol} address "${tok.address}" is not a valid EVM address`);
      }
      try {
        ethers.getAddress(tok.address);
      } catch {
        throw new Error(`EVM config chain ${chainId}: token ${symbol} address '${tok.address}' has invalid EIP-55 checksum`);
      }
      // R110-CFG-003: validate decimals — a misconfigured value like 60 would cause off-by-10^54
      // scaling errors in amount calculations without this guard.
      if (!Number.isInteger(tok.decimals) || tok.decimals < 0 || tok.decimals > 18) {
        throw new Error(`EVM config chain ${chainId}: token ${symbol} decimals=${tok.decimals} must be an integer in [0, 18]`);
      }
    }
    // R113-CFG-004: for ALL chains — validate htlcAddress format when present and non-zero.
    // A chain promoted from WIP to SUPPORTED with a malformed htlcAddress would otherwise
    // pass validation silently until its first live swap attempt.
    if (cfg.htlcAddress && cfg.htlcAddress !== NATIVE_ETH_ADDRESS) {
      if (!/^0x[0-9a-fA-F]{40}$/.test(cfg.htlcAddress)) {
        throw new Error(`EVM config error: chain ${chainId} htlcAddress '${cfg.htlcAddress}' is not a valid EVM address`);
      }
      try { ethers.getAddress(cfg.htlcAddress); } catch {
        throw new Error(`EVM config error: chain ${chainId} htlcAddress '${cfg.htlcAddress}' has invalid EIP-55 checksum`);
      }
    }
    // R105-CFG-001: only validate timing parameters for actively supported chains
    // R114-CFG-001: removed duplicate htlcAddress EIP-55 block here — the ALL-chains block above
    // (R113-CFG-004) now covers all non-zero addresses; the SUPPORTED-only block was dead code. — a WIP chain
    // with placeholder low values (e.g. 421614 with minLockBlocks=300 when minimum is 150 for
    // testnet) must not block startup. The zero-address check above still applies to ALL chains.
    if (SUPPORTED_EVM_CHAINS.includes(Number(chainId) as EvmChainId)) {
      // R118-EVM-002: minLockBlocks > 0 check scoped to SUPPORTED_EVM_CHAINS only — WIP chains
      // may legitimately use placeholder 0 values while the contract is not yet deployed.
      if (typeof cfg.minLockBlocks !== 'number' || cfg.minLockBlocks <= 0) {
        throw new Error(`EVM chain ${chainId} minLockBlocks must be a positive number, got ${cfg.minLockBlocks}`);
      }
      // R31-EVM-003: enforce minimum HTLC window — 150 blocks is the floor;
      // any lower risks HTLC expiry during normal network congestion.
      if (cfg.minLockBlocks < 150) {
        throw new Error(`EVM chain ${chainId} minLockBlocks=${cfg.minLockBlocks} is too short (minimum 150); increase to at least 300 for testnet or 2160 for mainnet`);
      }
      // R33-EVM-007: additional sanity checks
      if (cfg.avgBlockTimeSec <= 0) {
        throw new Error(`EVM chain ${chainId} avgBlockTimeSec must be > 0`);
      }
      if (cfg.maxLockBlocks <= cfg.minLockBlocks) {
        throw new Error(`EVM chain ${chainId} maxLockBlocks (${cfg.maxLockBlocks}) must exceed minLockBlocks (${cfg.minLockBlocks})`);
      }
      // R138b-XCHAIN-001: validate the AUTHORITATIVE seconds-based bounds (the unix-timestamp contract
      // basis). These must match the deployed contract's MIN_LOCK_SECONDS/MAX_LOCK_SECONDS.
      if (!Number.isFinite(cfg.minLockSeconds) || cfg.minLockSeconds <= 0
          || !Number.isFinite(cfg.maxLockSeconds) || cfg.maxLockSeconds <= cfg.minLockSeconds) {
        throw new Error(`EVM chain ${chainId} minLockSeconds/maxLockSeconds invalid (got ${cfg.minLockSeconds}/${cfg.maxLockSeconds})`);
      }
      // R124-XCHAIN-001: BIDIRECTIONAL cross-chain timelock safety. The old check only covered the
      // UTXO-initiator / EVM-responder topology and missed the inverse (EVM-initiator / UTXO-responder),
      // which allowed a timelock inversion. Validate the wall-clock-normalized EVM locks against BOTH:
      // R138b-XCHAIN-001: validate in SECONDS (the unix-timestamp contract basis), not blocks.
      const initEvmSec = evmLockSecondsForRole(cfg, 'initiator');
      const respEvmSec = evmLockSecondsForRole(cfg, 'responder');
      // (a) clamping must not invert the role ordering on this chain.
      if (initEvmSec <= respEvmSec) {
        throw new Error(
          `EVM chain ${chainId}: normalized initiator lock (${initEvmSec}s) must exceed ` +
          `responder lock (${respEvmSec}s) after clamping — raise maxLockSeconds.`
        );
      }
      // R-TIMELOCK-K: the UTXO legs are height CLTVs; on minority-hashrate BCH2 the wall-clock time to reach them can
      // deviate from nominal. Guard against BOTH directions: (b) the UTXO INITIATOR lock could mature EARLY (use the
      // conservative LOWER bound ÷K), (c) the UTXO RESPONDER lock could mature LATE (use the conservative UPPER bound
      // ×K). This keeps the cross-chain ordering safe even under a K-fold block-rate deviation.
      const utxoInitiatorSecMin = minSecondsUntilRefund(LOCKTIME_BLOCKS.initiator, chainConfigs.bch2.avgBlockTimeSec);
      const utxoResponderSecMax = maxSecondsUntilRefund(LOCKTIME_BLOCKS.responder, chainConfigs.bch2.avgBlockTimeSec);
      // (b) UTXO-initiator / EVM-responder: EVM responder lock must be strictly less than the UTXO initiator lock,
      // even if that UTXO leg matures K× early.
      if (respEvmSec >= utxoInitiatorSecMin) {
        throw new Error(
          `EVM chain ${chainId}: responder EVM lock ${respEvmSec}s >= conservative UTXO initiator lock ${utxoInitiatorSecMin}s ` +
          `— swap safety invariant violated (EVM-responder topology).`
        );
      }
      // (c) EVM-initiator / UTXO-responder: EVM initiator lock must exceed the UTXO responder lock + claim margin,
      // even if that UTXO leg matures K× late.
      if (initEvmSec <= utxoResponderSecMax + EVM_CLAIM_MARGIN_SEC) {
        throw new Error(
          `EVM chain ${chainId}: initiator EVM lock ${initEvmSec}s must exceed conservative UTXO responder lock ` +
          `${utxoResponderSecMax}s + claim margin ${EVM_CLAIM_MARGIN_SEC}s — R124-XCHAIN-001 inversion guard.`
        );
      }
    }
  }
  // R38-CFG-002: EVM minLockBlocks/maxLockBlocks in evm-config.ts override any values in
  // chain-config.ts. chain-config.ts EVM lock values are DEAD CODE for the swap engine.
  // R108-CFG-002: removed unconditional console.warn that polluted production console on every startup.
}
