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
 * Validate that every chain in SUPPORTED_EVM_CHAINS has a deployed HTLC contract address.
 * Call this at startup to catch misconfiguration before any swaps are attempted.
 */
declare function validateEvmConfigs(): void;

export { EVM_CHAINS, EVM_CLAIM_MARGIN_SEC, type EvmChainConfig, EvmChainId, type EvmToken, INITIATOR_LOCK_SEC, NATIVE_ETH_ADDRESS, RESPONDER_LOCK_SEC, SUPPORTED_EVM_CHAINS, evmLockBlocksForRole, evmLockSecondsForRole, getEvmConfig, getEvmTokenSymbols, isNativeToken, validateEvmConfigs };
