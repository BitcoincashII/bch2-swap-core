import { ChainClient } from './chain-client.js';
import { Provider } from 'ethers';

/**
 * What the caller (the controller) should do next. The gate itself does nothing beyond throwing — these are
 * HINTS, never load-bearing for fund-safety (the throw already prevented the irreversible action):
 *  - 'rebuild': the cached claim/outpoint is stale (vanished / double-spent / spent-less) — discard the cached
 *               claim tx, rebuild it against the fresh outpoint, and re-enter the gate.
 *  - 'rearm'  : a TRANSIENT / recoverable condition (height/UTXO/SPV/chain-time/RPC read failed, or a possible
 *               proxy under/over-report) — re-arm the watcher/poll and retry automatically.
 *  - 'abort'  : a genuine DANGER dead-end (timelock margin too tight / ordering inversion / config invalid) —
 *               do NOT retry-reveal; the safe move is to refund your own leg once its timelock passes.
 */
type GateDisposition = 'rebuild' | 'rearm' | 'abort';
/** Thrown by every gate on any failure. The secret is never emitted and no proof is minted. */
declare class GateFailure extends Error {
    readonly reason: string;
    readonly disposition: GateDisposition;
    constructor(reason: string, disposition: GateDisposition);
}
interface Outpoint {
    tx_hash: string;
    tx_pos: number;
}
type MarginBasis = 'height-cltv' | 'timestamp-cltv' | 'evm-timestamp' | 'none';
/** The exact facts a gate proved, carried inside the branded proof for the controller to triangulate later. */
interface ProvenLegAnchor {
    /** The leg's chain the proof was minted against. */
    readonly chain: string;
    /** UTXO leg: the funding outpoint the proof is BOUND to (tx_hash is a content hash — reorg tx cannot reuse it). */
    readonly outpoint?: Readonly<Outpoint>;
    /** EVM leg: the on-chain swapId the proof is bound to. */
    readonly swapId?: string;
    /** SPV-verified tip height (UTXO) / EVM block number (EVM) at mint — audit only. */
    readonly tipHeight: number;
    /** CHAIN time (seconds) captured at mint (fix #9 — never Date.now). May only ever FAIL a proof for staleness. */
    readonly capturedAtChainSec: number;
    /** The role the proof authorizes an action for. */
    readonly role: 'initiator' | 'responder';
    /** Which margin basis the proof cleared. */
    readonly marginBasis: MarginBasis;
}
declare const FUND_BRAND: unique symbol;
declare const REVEAL_BRAND: unique symbol;
/** Opaque proof that leg X is buried + ordered so the responder may fund leg Y. NOT a RevealAuthorization. */
type FundProof = ProvenLegAnchor & {
    readonly leg: 'X';
    readonly for: 'fundY';
    readonly [FUND_BRAND]: true;
};
/**
 * Opaque authorization for the initiator's single irreversible secret reveal on leg Y. NOT a FundProof.
 * CONSUMER OBLIGATION: a RevealAuthorization minted for role:'responder' (marginBasis:'none') deliberately SKIPS
 * the 4h claim-margin (a responder claims an ALREADY-PUBLIC secret — no double-dip risk). The initiator's
 * irreversible reveal path (revealAndClaim, step 5) MUST therefore assert `auth.role === 'initiator'` before
 * broadcasting, so a margin-skipped responder auth can never authorize an initiator secret reveal.
 */
type RevealAuthorization = ProvenLegAnchor & {
    readonly leg: 'Y';
    readonly for: 'reveal';
    readonly [REVEAL_BRAND]: true;
};
interface GateUtxo {
    tx_hash: string;
    tx_pos: number;
    value: number;
    height: number;
}
interface GateChainClient extends ChainClient {
    /** listunspent for a P2SH scripthash (+ optional script hex for the real proxy; ignored by the mock). */
    getUTXOs(scripthash: string, scriptHex?: string): Promise<GateUtxo[]>;
    /** Raw tx hex for a txid (self-authenticated by verifyAndAuthenticateUtxo + the SPV Merkle proof). */
    getTx(txid: string): Promise<string>;
    /** Fresh tip height [height, unsubscribe] — matches proxy-client.getBlockHeight. */
    getBlockHeight(onNewBlock?: (height: number) => void): Promise<[number, () => void]>;
}
/**
 * R278-EVM-MARGIN-QUORUM-001 (#6): aggregate the EVM-leg chain clock from per-leaf getBlock timestamps. Requires
 * EVERY configured RPC leaf to have answered (a single unavailable/lying backend must not set the clock alone),
 * then takes the MAX so a leaf reporting the clock BEHIND cannot deflate it. Returns null → caller fails closed.
 */
declare function aggregateChainNow(leafTimestamps: Array<number | null>, leafCount: number): number | null;
/**
 * R261/R278 (#6): validate a getSwap-reported EVM refund timeLock. Accepts only a finite unix-seconds value in
 * [1e9, 1e11] (rejects a block-number-shaped or absurd-future value a lying RPC might return). Returns null →
 * caller fails closed. Accepts bigint (ethers getSwap) or number.
 */
declare function validateEvmTimeLock(raw: number | bigint | null | undefined): number | null;
/**
 * Read the CLTV operand out of an HTLC redeem script (the exact layout htlc-builder.ts createHTLCRedeemScript emits):
 *   OP_IF OP_SHA256 <32 secretHash> OP_EQUALVERIFY OP_DUP OP_HASH160 <20 recipientPkh>
 *   OP_ELSE <push locktime> OP_CHECKLOCKTIMEVERIFY OP_DROP OP_DUP OP_HASH160 <20 refundPkh> OP_ENDIF ...
 * The locktime push always begins at a fixed offset (60) right after OP_ELSE. Returns the pushed number
 * (a little-endian CScriptNum) or null when the bytes are not this exact HTLC layout, or the operand is not a
 * plain positive push (the caller fails closed on null). The redeemScript is the value the funds are locked to
 * on-chain — its hash160 IS the funded P2SH — so its CLTV is the AUTHENTICATED timelock the margin must be
 * sized from, and it must agree with the caller's counterpartyLocktime record.
 */
declare function parseHtlcCltv(redeemScript: Uint8Array): number | null;
interface RevealSafeParams {
    /** Only the INITIATOR reveals the secret; a responder claims an ALREADY-PUBLIC secret and is NOT margin-blocked. */
    role: 'initiator' | 'responder';
    /** The counterparty leg (leg Y) chain the claim spends. */
    theirChain: string;
    /** The counterparty (responder) HTLC redeem script. */
    counterpartyRedeemScript: Uint8Array;
    /** The EXACT funding outpoint the cached claim tx spends (= claimTx.spent). */
    recordedOutpoint: Outpoint;
    /** The counterparty HTLC locktime: a block height, or a unix timestamp (>= 1.5e9) for an EVM-anchored CLTV. */
    counterpartyLocktime: number;
    /** R-UNDERFUND-001: the amount (sats) WE claim from this leg — the authenticated funded value must be >= this, or a
     *  dust-funded counterparty leg would pass and we would reveal/commit our own full leg against it. For the initiator
     *  reveal this is offer.receiveAmount (leg Y); the responder-fund equivalent is offer.sendAmount (leg X). */
    expectedFundedValueSats: number;
}
/**
 * R220 exact-outpoint re-check + R139/R175 authentication + R175 SPV depth + R258/R261 initiator-only 4h margin.
 * The margin branch anchors to CHAIN time (timestamp CLTV) or an SPV-fresh height (height CLTV); either way it
 * fails closed rather than reveal the secret within the margin. THROWS + mints nothing on any doubt.
 */
declare function assertRevealSafe(client: GateChainClient, p: RevealSafeParams): Promise<RevealAuthorization>;
interface FundGateParams {
    /** The counterparty (initiator) leg X chain — the leg the responder will eventually claim. */
    theirChain: string;
    /** The responder's OWN leg Y chain. */
    myChain: string;
    /** True when the responder funds leg Y on an EVM chain (R133: its lock is RESPONDER_LOCK_SEC wall-clock). */
    myChainIsEvm: boolean;
    /** The counterparty (initiator) HTLC redeem script. */
    counterpartyRedeemScript: Uint8Array;
    /** The initiator funding outpoint the responder recorded. */
    recordedOutpoint: Outpoint;
    /** The initiator leg X block-height CLTV. */
    counterpartyLocktime: number;
    /** R-UNDERFUND-001: the amount (sats) the responder will claim from leg X (= offer.sendAmount). The authenticated
     *  funded value of leg X must be >= this, or a dust-funded leg X would pass and the responder would fund its full
     *  leg Y against it. */
    expectedFundedValueSats: number;
}
/**
 * Burial re-verify (R220/R139/R175) of leg X + R125/R133 responder margin: the initiator leg must outlast the
 * responder's OWN lock (RESPONDER_LOCK_SEC on EVM, else LOCKTIME_BLOCKS.responder * myBlockSec) plus the 4h claim
 * margin, sized by the ÷K minSecondsUntilRefund conservatism. THROWS + mints nothing on any doubt.
 */
declare function assertLegBuriedForFunding(client: GateChainClient, p: FundGateParams): Promise<FundProof>;
interface OrderingParams {
    /** The counterparty (responder) leg chain — the leg the initiator will claim. */
    theirChain: string;
    /** The initiator's OWN leg chain. */
    myChain: string;
    /** The responder leg's observed blocks-to-refund on theirChain. */
    remainingBlocks: number;
    /** The initiator's own-leg locktime (from myHTLC or the durable fundlocktime replay); undefined if unrecoverable. */
    myLocktime: number | undefined;
    /** The initiator's own funding txid, if any — distinguishes a FUNDED leg (R277 fail-closed) from an unfunded one. */
    myFundingTxid: string | undefined;
}
/**
 * R125 claim-window + R228-ATOM-002 cross-domain WALL-CLOCK ordering, both in the initiator's normal path.
 * R277: if the own-leg locktime is unrecoverable AND the leg is FUNDED, fail closed (never claim without the
 * ordering check); an UNFUNDED own leg has nothing at maturity risk, so it is safe to skip. R175: prefer an
 * SPV-fresh myHeight when available (never fail-closed here — over-estimating our OWN leg only risks a failed
 * swap we can always refund, and this sits on the claim path, so a myChain stall must not forfeit the claim).
 */
declare function assertOrderingSafe(myChainClient: GateChainClient, p: OrderingParams): Promise<void>;
interface EvmFundGateParams {
    /** The counterparty (initiator) EVM leg chain id label (audit only). */
    chain: string;
    htlcAddr: string;
    swapId: string;
    requiredConfirmations: number;
    /** bytes32 hashLock (0x-prefixed) the lock must carry. */
    hashLock: string;
    /** The responder's EVM recipient address the lock must pay. */
    recipient: string;
    /** The agreed minimum amount (base units) the lock must fund. */
    minAmount: bigint;
    /** The canonical token contract the lock must use. */
    token: string;
}
/**
 * R143/R148/R280/R322: the responder-fund EVM gate. Corroborate the chain clock across ALL quorum leaves (MAX,
 * fail-closed to an impossible minTimeLock if any leaf is silent — R322), then require isEvmLockAtSafeDepth
 * (quorum >= 2) to confirm the lock is at a reorg-safe depth AND binds {hashLock, recipient, minAmount,
 * minTimeLock, token}. minTimeLock = corroborated chainNow + RESPONDER_LOCK_SEC + EVM_CLAIM_MARGIN_SEC (R280-H2).
 * The injected `provider` MUST be the quorum >= 2 read provider. THROWS + mints nothing on any doubt.
 */
declare function assertEvmLegBuriedForFunding(provider: Provider, p: EvmFundGateParams): Promise<FundProof>;
interface EvmRevealGateParams {
    /** The counterparty (responder) EVM leg chain id label (audit only). */
    chain: string;
    htlcAddr: string;
    swapId: string;
    requiredConfirmations: number;
    hashLock: string;
    recipient: string;
    /** REQUIRED (not optional): part of the proven R148 gate#2 binding — omitting it would let the initiator reveal
     *  S against an under-funded lock (receive less than given, secret now public). isEvmLockAtSafeDepth enforces it. */
    minAmount: bigint;
    token: string;
}
/**
 * R148 gate#2 + R258/R260/R261/R278: the initiator EVM secret-reveal gate. isEvmLockAtSafeDepth (quorum >= 2)
 * re-asserts reorg-safe DEPTH + binds {hashLock, recipient, minAmount, token}, then the broadcast-time MARGIN is
 * re-derived from the FRESH on-chain timeLock (untamperable) and a corroborated chain clock (MAX across leaves).
 * Fail closed unless (evmExpiry - chainNow) >= EVM_CLAIM_MARGIN_SEC. THROWS + mints nothing on any doubt.
 */
declare function assertEvmRevealSafe(provider: Provider, p: EvmRevealGateParams): Promise<RevealAuthorization>;

export { type EvmFundGateParams, type EvmRevealGateParams, type FundGateParams, type FundProof, type GateChainClient, type GateDisposition, GateFailure, type GateUtxo, type MarginBasis, type OrderingParams, type Outpoint, type ProvenLegAnchor, type RevealAuthorization, type RevealSafeParams, aggregateChainNow, assertEvmLegBuriedForFunding, assertEvmRevealSafe, assertLegBuriedForFunding, assertOrderingSafe, assertRevealSafe, parseHtlcCltv, validateEvmTimeLock };
