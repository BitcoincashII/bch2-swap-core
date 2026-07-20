import { ChainClient } from './chain-client.js';
import { AsertParams, Checkpoint } from './spv.js';

/** True iff SPV depth verification is available for this chain (else callers use the legacy trusted path). */
declare function spvSupported(chain: string): boolean;
/**
 * Verify — WITHOUT trusting the proxy's height — that a funding tx is buried at a real confirmation depth.
 * Verifies (a) a PoW+ASERT header chain from the hardcoded checkpoint to `tipHeight`, and (b) a Merkle-inclusion
 * proof that `txid` (raw bytes `rawTxHex`) is in the block at `claimedHeight`, against that verified header.
 * Returns the VERIFIED confirmation count (tip − height + 1). Throws (fail-closed) on any inconsistency.
 */
declare function verifyConfirmations(client: ChainClient, chain: string, txid: string, claimedHeight: number, rawTxHex: string, tipHeight: number): Promise<number>;
/**
 * H1-LOCKTIME-PROXY-001: SPV-verify that `claimedHeight` (from the UNTRUSTED proxy) is a REAL, PoW-backed block
 * height BEFORE it is used as the base for a UTXO HTLC refund CLTV (locktime = claimedHeight + LOCKTIME_BLOCKS). A
 * hostile/MITM proxy that inflates the height would push the funder's OWN refund maturity ~forever, permanently
 * stranding the coins we are about to fund. extendVerifiedChain builds a PoW+difficulty header chain from the
 * hardcoded checkpoint up to `claimedHeight`; the proxy cannot forge valid headers for blocks that do not exist, so
 * an inflated/unverifiable height THROWS here (fail-closed). spvSupported chains only — callers gate on
 * spvSupported(chain). Same trust model as verifyConfirmations (R175). Returns the SPV-verified tip (>= claimed).
 */
declare function verifyFundingHeight(client: ChainClient, chain: string, claimedHeight: number): Promise<number>;
declare const MAX_TIMING_TIP_STALENESS_SEC: number;
/**
 * R175-SPV (timing gates): SPV-verify a height used in a TIMING/MARGIN decision (reveal-margin, fund-gate remaining
 * time), bounding BOTH proxy lies. extendVerifiedChain catches OVER-reporting — the proxy cannot forge PoW headers for
 * non-existent higher blocks, so an inflated/unverifiable tip THROWS (fail-closed). This ADDS an under-report guard:
 * the PoW-validated tip header's timestamp must be within `maxStalenessSec` of the client's trusted now, so a proxy
 * cannot present a real-but-STALE tip to make the client think fewer blocks have passed than really have — the vector
 * that would let the initiator reveal the secret too close to the responder's refund (double-dip). Fail-closed on a
 * stale tip or unverifiable PoW. spvSupported chains only (callers gate on spvSupported). Returns the verified tip.
 */
declare function spvVerifiedTipFresh(client: ChainClient, chain: string, claimedTip: number, maxStalenessSec?: number): Promise<number>;
declare function parseHeaderTimeSec(headerHex: string): number | null;
declare function getChainTimeSec(client: ChainClient): Promise<number | null>;
/** Test-only: reset the in-memory verified-chain cache. */
declare function __resetSpvCacheForTests(): void;
/** Test-only: inject SPV config for a chain (e.g. a fixture-derived checkpoint). */
declare function __setSpvConfigForTests(chain: string, params: AsertParams, checkpoint: Checkpoint): void;
/** Test-only: run just the header-chain verification and return the verified tip height. */
declare function __getVerifiedTipForTests(client: ChainClient, chain: string, tipHeight: number): Promise<number>;

export { MAX_TIMING_TIP_STALENESS_SEC, __getVerifiedTipForTests, __resetSpvCacheForTests, __setSpvConfigForTests, getChainTimeSec, parseHeaderTimeSec, spvSupported, spvVerifiedTipFresh, verifyConfirmations, verifyFundingHeight };
