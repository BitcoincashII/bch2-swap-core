/** Double-SHA256 (a.k.a. hash256) — the block-hash and Merkle-node primitive. */
declare function hash256(d: Uint8Array): Uint8Array;
declare function targetFromCompact(nCompact: number): {
    target: bigint;
    negative: boolean;
    overflow: boolean;
};
declare function compactFromTarget(target: bigint): number;
declare function calculateASERT(refTarget: bigint, spacing: bigint, timeDiff: bigint, heightDiff: bigint, powLimit: bigint, halfLife: bigint): bigint;
interface AsertParams {
    anchorHeight: number;
    anchorBits: number;
    anchorParentTime: number;
    spacing: bigint;
    powLimit: bigint;
    halfLife: (nextHeight: number) => bigint;
}
declare const BCH2_MAINNET_ASERT: AsertParams;
declare const BCH_MAINNET_ASERT: AsertParams;
interface LegacyParams {
    powLimit: bigint;
    targetTimespan: bigint;
    interval: number;
}
declare const BTC_MAINNET_LEGACY: LegacyParams;
declare const BC2_MAINNET_LEGACY: LegacyParams;
/**
 * Expected compact nBits for the block at `height` under the classic Bitcoin DAA. Non-retarget blocks keep the
 * previous block's nBits; every `interval`-th block retargets from the timespan of the last interval. `prevBits`
 * and `prevTime` are block height-1; `firstTime` is block (height - interval) — needed only at retarget boundaries.
 */
declare function getNextWorkRequiredLegacy(height: number, prevBits: number, prevTime: number, firstTime: number, p: LegacyParams): number;
interface Checkpoint {
    height: number;
    hashDisplay: string;
    time: number;
    bits?: number;
}
declare const BTC_MAINNET_CHECKPOINT: Checkpoint;
declare const BC2_MAINNET_CHECKPOINT: Checkpoint;
declare const BCH2_MAINNET_CHECKPOINT: Checkpoint;
declare const BCH_MAINNET_CHECKPOINT: Checkpoint;
/** Verify headers starting immediately AFTER a trusted checkpoint (headersAfterCp[0] is block cp.height+1). */
declare function verifyChainFromCheckpoint(headersAfterCp: Uint8Array[], cp: Checkpoint, p: AsertParams, trustedNowSec: number): Map<number, BlockHeader>;
/** Expected compact nBits for the block at height prevHeight+1, given its parent's height+timestamp. */
declare function getNextWorkRequiredASERT(prevHeight: number, prevTime: number, p: AsertParams): number;
interface BlockHeader {
    version: number;
    prevHash: Uint8Array;
    merkleRoot: Uint8Array;
    time: number;
    bits: number;
    nonce: number;
    raw: Uint8Array;
}
declare function parseHeader(raw: Uint8Array): BlockHeader;
/** Block hash in internal (LE) byte order. Display hash = reverse(this). */
declare function blockHashInternal(raw: Uint8Array): Uint8Array;
/** True iff the header's PoW satisfies its own nBits and nBits is within powLimit. */
declare function checkPoW(raw: Uint8Array, bits: number, powLimit: bigint): boolean;
/** Recompute the Merkle root (internal order) from a txid (internal order) + branch (internal order) + position. */
declare function merkleRootFromBranch(txidInternal: Uint8Array, branchInternal: Uint8Array[], pos: number): Uint8Array;
/**
 * Verify a funding tx is included in a block whose header Merkle root is `merkleRootInternal`.
 * `rawTxHex` = the raw tx; a SegWit (BIP144) serialization is stripped to its legacy form so hash256 === txid (the
 * Merkle-tree leaf). `merkleHexReversed` / `pos` come straight from Electrum `blockchain.transaction.get_merkle`
 * (hashes are in display/reversed hex). Returns the display txid on success; throws on any mismatch (fail-closed).
 */
declare function verifyMerkleInclusion(rawTxHex: string, merkleHexReversed: string[], pos: number, merkleRootInternal: Uint8Array): string;
declare function verifyHeaderChain(headers: Uint8Array[], startHeight: number, prevHashOfStart: Uint8Array, p: AsertParams, prevTimeOfStart: number, trustedNowSec: number, priorTimes?: number[]): Map<number, BlockHeader>;
/**
 * Legacy (Bitcoin-DAA) analogue of verifyHeaderChain for BTC/BC2. Same link + PoW checks, but the nBits rule is
 * the 2016-block retarget: non-boundary blocks must equal the previous block's nBits; a boundary block
 * (height % interval == 0) recomputes from the interval timespan, which needs the time of block (height-interval)
 * — supplied via `getPriorTime` (resolves the checkpoint or any already-verified header). `prevBitsOfStart`/
 * `prevTimeOfStart` are the header immediately before `startHeight` (i.e. the checkpoint, or the prior chunk's
 * last header). Throws (fail-closed) on the first failure. Requires the checkpoint to sit on a retarget boundary
 * so every `height-interval` lookback resolves.
 */
declare function verifyLegacyChunk(headers: Uint8Array[], startHeight: number, prevHashOfStart: Uint8Array, prevBitsOfStart: number, prevTimeOfStart: number, p: LegacyParams, getPriorTime: (height: number) => number, trustedNowSec: number, priorTimes?: number[]): Map<number, BlockHeader>;

export { type AsertParams, BC2_MAINNET_CHECKPOINT, BC2_MAINNET_LEGACY, BCH2_MAINNET_ASERT, BCH2_MAINNET_CHECKPOINT, BCH_MAINNET_ASERT, BCH_MAINNET_CHECKPOINT, BTC_MAINNET_CHECKPOINT, BTC_MAINNET_LEGACY, type BlockHeader, type Checkpoint, type LegacyParams, blockHashInternal, calculateASERT, checkPoW, compactFromTarget, getNextWorkRequiredASERT, getNextWorkRequiredLegacy, hash256, merkleRootFromBranch, parseHeader, targetFromCompact, verifyChainFromCheckpoint, verifyHeaderChain, verifyLegacyChunk, verifyMerkleInclusion };
