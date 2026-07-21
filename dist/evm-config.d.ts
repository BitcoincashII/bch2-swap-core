import { E as EvmChainId } from './swap-types-CsSbca8_.js';

interface EvmToken {
    symbol: string;
    address: string;
    decimals: number;
    name: string;
}
interface EvmChainConfig {
    chainId: EvmChainId;
    name: string;
    shortName: string;
    nativeSymbol: string;
    avgBlockTimeSec: number;
    requiredConfirmations: number;
    htlcAddress: string;
    minLockSeconds: number;
    maxLockSeconds: number;
    minLockBlocks: number;
    maxLockBlocks: number;
    rpcUrl: string;
    tokens: Record<string, EvmToken>;
}
declare const NATIVE_ETH_ADDRESS = "0x0000000000000000000000000000000000000000";
declare const EVM_CHAINS: Partial<Record<EvmChainId, EvmChainConfig>>;
declare const SUPPORTED_EVM_CHAINS: EvmChainId[];
/**
 * Returns the EVM chain config for the given chainId, or null if the chain is not configured.
 * @throws — does NOT throw; returns null for unknown chains.
 *   Callers MUST null-check the return value before accessing any fields.
 *   R39-CFG-001: use `if (!cfg) throw ...` at call sites to produce chain-specific error messages.
 */
declare function getEvmConfig(chainId: EvmChainId): EvmChainConfig | null;
declare function getEvmTokenSymbols(chainId: EvmChainId): string[];
/** Canonical initiator lock duration in wall-clock seconds (= UTXO initiator: 216 * 600 = 36h). */
declare const INITIATOR_LOCK_SEC: number;
/** Canonical responder lock duration in wall-clock seconds (= UTXO responder: 72 * 600 = 12h). */
declare const RESPONDER_LOCK_SEC: number;
/** Wall-clock claim safety margin (= UTXO initiator margin: 24 blocks * 600 = 4h). */
declare const EVM_CLAIM_MARGIN_SEC: number;
/**
 * Wall-clock-normalized EVM HTLC lock duration, in EVM blocks, for a swap role on a chain.
 * Both roles derive from the same canonical seconds as the UTXO side, then clamp into the
 * contract's accepted [minLockBlocks, maxLockBlocks-1] range. Callers MUST have already
 * null-checked the config. See R124-XCHAIN-001.
 */
declare function evmLockBlocksForRole(cfg: EvmChainConfig, role: 'initiator' | 'responder'): number;
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
declare function evmLockSecondsForRole(cfg: EvmChainConfig, role: 'initiator' | 'responder'): number;
declare function isNativeToken(tokenAddress: string): boolean;
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
declare function assertCanonicalEvmToken(evmChainId: EvmChainId, tokenAddress: string, tokenSymbol?: string): string;
/**
 * Validate that every chain in SUPPORTED_EVM_CHAINS has a deployed HTLC contract address.
 * Call this at startup to catch misconfiguration before any swaps are attempted.
 */
declare function validateEvmConfigs(): void;

export { EVM_CHAINS, EVM_CLAIM_MARGIN_SEC, type EvmChainConfig, EvmChainId, type EvmToken, INITIATOR_LOCK_SEC, NATIVE_ETH_ADDRESS, RESPONDER_LOCK_SEC, SUPPORTED_EVM_CHAINS, assertCanonicalEvmToken, evmLockBlocksForRole, evmLockSecondsForRole, getEvmConfig, getEvmTokenSymbols, isNativeToken, validateEvmConfigs };
