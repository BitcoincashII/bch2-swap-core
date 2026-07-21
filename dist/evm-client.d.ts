import { BrowserProvider, Signer, Provider, JsonRpcProvider } from 'ethers';

/**
 * EVM / MetaMask interaction layer (ethers v6).
 *
 * All HTLC operations use sha256(secret) as the hashLock — matching the
 * OP_SHA256 used on the UTXO side.
 */

declare const HTLC_ABI: string[];
interface MetaMaskConnection {
    provider: BrowserProvider;
    signer: Signer;
    address: string;
    chainId: number;
}
interface SwapData {
    initiator: string;
    recipient: string;
    token: string;
    amount: bigint;
    hashLock: string;
    timeLock: bigint;
    claimed: boolean;
    refunded: boolean;
}
/** Connect to MetaMask and return provider, signer, address, and chainId. */
declare function connectMetaMask(): Promise<MetaMaskConnection>;
/** Ask MetaMask to switch to the requested network by chainId. */
declare function switchToChain(chainId: number): Promise<void>;
/** Get ERC-20 token balance in raw units. */
declare function getTokenBalance(tokenAddr: string, walletAddr: string, provider: Provider): Promise<bigint>;
/** Approve HTLC to spend `amount` of the given ERC-20 token. */
declare function approveToken(tokenAddr: string, spenderAddr: string, amount: bigint, signer: Signer): Promise<void>;
/**
 * Ensures the HTLC contract has sufficient ERC-20 allowance, approving if needed.
 *
 * Security: validates spenderAddr against the canonical HTLC address for this chainId
 * (R34-EVM-001) and rejects chains where the HTLC is not yet deployed (R35-EVM-002).
 * These internal checks are the authoritative enforcement point — do NOT remove them
 * even if callers also pre-validate. Defense in depth is intentional.
 */
declare function ensureAllowance(tokenAddr: string, ownerAddr: string, spenderAddr: string, amount: bigint, signer: Signer, provider: Provider, chainId: number): Promise<void>;
/**
 * Takes a raw 32-byte secret preimage (NOT the secretHash/hashLock).
 * Calling this with an already-hashed value will double-hash and create
 * an unclaimable HTLC.
 */
declare function hashPreimage(secret: Uint8Array): string;
declare function makeEvmProvider(rpc: string): JsonRpcProvider;
/**
 * Lock ERC-20 tokens in the HTLC.
 * Returns the swap ID (bytes32 as hex string).
 */
/**
 * R160-EVMLOCK-POSTBROADCAST-001: classify a broadcast-but-untracked lock tx (the durable
 * `bch2swap:lockpending:<id>` marker) so a reload can ADOPT an existing lock instead of re-locking it
 * (which would strand a second batch under a fresh per-nonce swapId). Outcomes:
 *  - { kind: 'locked', swapId } : mined OK, Locked event parsed → adopt this swapId.
 *  - { kind: 'safe' }           : mined+reverted OR not found anywhere (dropped) → no funds locked → re-lock is safe.
 *  - { kind: 'blocked' }        : still pending in mempool, OR mined-success with no Locked event (anomalous)
 *                                 → re-locking could duplicate → caller must wait + verify, NOT re-lock.
 */
declare function recoverLockFromTx(htlcAddr: string, txHash: string, provider: Provider, scan?: {
    sender: string;
    hashLock: string;
    recipient?: string;
    minAmount?: bigint;
    fromBlock?: number;
}): Promise<{
    kind: 'locked';
    swapId: string;
    blockNumber?: number;
} | {
    kind: 'safe' | 'blocked';
}>;
declare function lockTokens(htlcAddr: string, recipient: string, tokenAddr: string, amount: bigint, hashLock: string, // bytes32 hex string (sha256 of secret)
timeLock: bigint, signer: Signer, expectedChainId: number, // R106-EVM-002: required — callers must pass the expected chainId for chain validation
onBroadcast?: (txHash: string) => void): Promise<string>;
/**
 * Lock native ETH in the HTLC.
 * Returns the swap ID (bytes32 as hex string).
 */
declare function lockETH(htlcAddr: string, recipient: string, amount: bigint, hashLock: string, // bytes32 hex string
timeLock: bigint, signer: Signer, expectedChainId: number, // R106-EVM-002: required — callers must pass the expected chainId for chain validation
onBroadcast?: (txHash: string) => void): Promise<string>;
/** Claim a funded HTLC by revealing the secret. */
declare function claimSwap(htlcAddr: string, swapId: string, secret: Uint8Array, signer: Signer, expectedChainId?: number): Promise<{
    blockNumber: number;
}>;
/** Refund a timed-out HTLC. */
declare function refundSwap(htlcAddr: string, swapId: string, signer: Signer): Promise<void>;
/** Fetch the full swap struct from the HTLC contract.
 *  Returns null if the swap does not exist (zero initiator address).
 */
declare function getSwap(htlcAddr: string, swapId: string, provider: Provider, blockTag?: number | string): Promise<SwapData | null>;
declare function isEvmLockAtSafeDepth(htlcAddr: string, swapId: string, provider: Provider, requiredConfirmations: number, inv: {
    hashLock: string;
    recipient?: string;
    minAmount?: bigint;
    minTimeLock?: bigint;
    token?: string;
}): Promise<boolean>;
declare function watchForClaim(htlcAddr: string, swapId: string, provider: Provider, fromBlock: number | undefined, expectedHashLock: string, signal?: AbortSignal): Promise<Uint8Array>;
/**
 * Polls until the EVM HTLC timelock expires, then refunds the swap.
 * Call this on the responder side after funding if the initiator goes offline.
 * Returns the refund tx hash.
 *
 * When this throws Error('CLAIMED_WITH_SECRET'), the Error has a `.secret: Uint8Array` property.
 * The CALLER MUST call `err.secret.fill(0)` after using the secret to prevent heap exposure.
 *
 * @internal NOT CURRENTLY USED — wire up a caller with proper CLAIMED_WITH_SECRET + provider
 * cleanup before deploying this function in production.
 */
declare function watchAndRefund(htlcAddress: string, swapId: string, provider: JsonRpcProvider, signer: Signer, timeLockSec: number, // R138b-XCHAIN-001: absolute unix timestamp (seconds), not a block number
onBlockUpdate?: (current: number, target: number) => void, expectedHashLock?: string | null, signal?: AbortSignal): Promise<string>;
/** Create a Provider for a given chainId using the configured RPC URL + fallbacks.
 * R206-EVM-QUORUM-001: opts.quorum lets FINALITY-gating call sites (the irreversible secret-reveal /
 * re-lock / claim-finalize reads) require N-of-leaves AGREEMENT instead of the ethers default quorum=1
 * (= first-responder, which a single hostile/lagging RPC can answer). Only applies when a FallbackProvider
 * is built (>=2 leaves); a single-URL chain has no FallbackProvider to gate, so quorum is clamped to the
 * leaf count (with a warning) rather than tripping ethers' "quorum exceed provider weight" assertion.
 * Non-finality reads MUST keep the default (call with no opts) for liveness. */
declare function getPublicProvider(chainId: number, opts?: {
    quorum?: number;
}): Provider;
/**
 * R38-EVM-003: Safely destroy a provider, handling both JsonRpcProvider (which has .destroy())
 * and FallbackProvider (which does not — but wraps multiple JsonRpcProviders that each do).
 * Use this instead of inline `(provider as ethers.JsonRpcProvider).destroy?.()` calls, which
 * silently no-op on FallbackProvider and leave its sub-providers' connections open.
 */
declare function destroyProvider(provider: Provider | null | undefined): void;

export { HTLC_ABI, type MetaMaskConnection, type SwapData, approveToken, claimSwap, connectMetaMask, destroyProvider, ensureAllowance, getPublicProvider, getSwap, getTokenBalance, hashPreimage, isEvmLockAtSafeDepth, lockETH, lockTokens, makeEvmProvider, recoverLockFromTx, refundSwap, switchToChain, watchAndRefund, watchForClaim };
