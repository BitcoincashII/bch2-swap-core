import { S as SwapOffer, C as Chain } from './swap-types-CsSbca8_.js';
import { GateChainClient, FundProof, RevealAuthorization } from './gates.js';
import { DurableStore, SessionStore, Mutex } from './storage.js';
import { UtxoReservationRegistry } from './utxo-reservation.js';
import { Provider, Signer } from 'ethers';
import './chain-client.js';

interface SwapChainClient extends GateChainClient {
    /** Broadcast a signed raw tx; resolves the node's ack txid, THROWS on a node reject (so a fund failure aborts). */
    broadcastTx(rawTx: string): Promise<string>;
    /** blockchain.scripthash.get_history — the spend/confirm history the responder's secret-watcher scans (leg Y).
     *  Matches ElectrumProxyClient.getHistory verbatim so the app client + the test mock satisfy it with no adapter. */
    getHistory(scripthash: string, scriptHex?: string, timeoutMs?: number): Promise<Array<{
        tx_hash: string;
        height: number;
    }>>;
}

/** The controller's fund-safety phase enum (design §1/§3). */
type SwapPhase = 'prepared' | 'initiator_funded' | 'responder_funded' | 'claimed' | 'completed' | 'refunded' | 'failed';
/**
 * A record's phase also carries the pre-prepare ENTRY state `taken` (the swap has been taken but keys/secret
 * are not yet derived), so the `taken -> prepared` and `taken|prepared -> initiator_funded` transitions are
 * representable while `SwapPhase` stays exactly the 7 post-prepare states.
 */
type RecordPhase = 'taken' | SwapPhase;
/** A durably-serializable HTLC (hex-encoded byte fields) — the exact FUNDED HTLC (R170 fundedhtlc side-channel). */
interface DurableHTLC {
    redeemScript: string;
    p2shAddress: string;
    secretHash: string;
    recipientPkh: string;
    refundPkh: string;
    locktime: number;
}
/** The counterparty funding outpoint a cached claim tx spends (design §3 — `.spent` is load-bearing later). */
interface Outpoint {
    tx_hash: string;
    tx_pos: number;
}
/**
 * One durable record per swap id. Written ATOMICALLY inside the broadcast mutex BEFORE any irreversible
 * broadcast returns (durable-before-broadcast). Fields not needed until steps 5-7 are optional and left for
 * those steps to populate; the ones below cover the skeleton + prepare + fundLegX (step 4).
 */
interface DurableSwapRecord {
    id: string;
    role: 'initiator' | 'responder';
    /** The offer, carrying `secretScheme` + `secretNonce` so S is re-derivable (never plaintext-stored). */
    offer: SwapOffer;
    phase: RecordPhase;
    /** The pkh that may CLAIM leg X with the secret (the counterparty's receive pkh on myChain). Needed to build
     *  the initiator HTLC in fundLegX; the host populates it from the taker's acceptance. */
    counterpartyClaimPkh?: string;
    /** THIS side's funded HTLC (set once fundLegX builds + broadcasts). */
    myHTLC?: DurableHTLC;
    counterpartyHTLC?: DurableHTLC;
    /** The counterparty's funding OUTPOINT the host recorded when it observed the counterparty HTLC confirm — the
     *  exact output the fund/reveal gates re-verify + bind their proof to (design §3). UTXO topologies only. */
    counterpartyFundingOutpoint?: Outpoint;
    counterpartyEvmSwapId?: string;
    counterpartyEvmTimeLock?: number;
    /** OUR own EVM lock's swapId (bytes32 hex), set by lockEvm; watched by watchForClaimEvm, refunded by refundEvm. */
    myEvmSwapId?: string;
    /** OUR EVM address — the recipient when WE claim the counterparty EVM leg (revealAndClaimEvm), and the initiator of
     *  our own lock (the address refundSwap authenticates against). */
    myEvmAddress?: string;
    /** The counterparty's EVM address — the recipient of the lock WE create (lockEvm), i.e. who may claim our EVM leg. */
    counterpartyEvmAddress?: string;
    /** The token WE lock on our EVM leg (native => NATIVE_ETH_ADDRESS). Defaults to offer.evmInfo.tokenAddress. */
    myEvmToken?: string;
    /** The token the COUNTERPARTY locked on their EVM leg (the gate binds it). Defaults to offer.evmInfo.tokenAddress. */
    counterpartyEvmToken?: string;
    /** The block our own EVM lock mined at — a lower bound for the getLogs Claimed-event scan (watch / refund-race). */
    evmLockBlock?: number;
    myFundingTxid?: string;
    fundLocktime?: number;
    respLocktime?: number;
    claimTx?: {
        txid: string;
        rawTx: string;
        spent?: Outpoint;
    };
    myClaimTxid?: string;
    refundTx?: {
        txid: string;
        rawTx: string;
    };
    funded?: boolean;
}
/** A signing key pair for a UTXO leg (private + compressed public key). The caller owns the buffers. */
interface SigningKeyPair {
    readonly privateKey: Uint8Array;
    readonly publicKey: Uint8Array;
}
/**
 * The seed capability the controller is injected with. It wraps a mnemonic the HOST holds and DERIVES ON
 * DEMAND — the raw seed is never globalized/returned/put on the wire (fix: MetaMask is NOT on the path). Back
 * it with the SDK's seed-secret.ts (deriveSwapKss/swapSecretFromKss) + a per-chain HD signing derivation.
 */
interface SeedVault {
    /** A UTXO signing key for `chain` (optionally at an explicit HD path). Derived on demand. */
    signingKey(chain: Chain, hdPath?: string): Promise<SigningKeyPair>;
    /** K_ss = seed -> m/83'/0'/0' (deriveSwapKss). `null` when locked / unavailable. Caller zeroes the buffer. */
    swapKss(): Promise<Uint8Array | null>;
    /** Zeroize all cached key material. Idempotent. Called by SwapController.dispose(). */
    dispose(): void;
}
/**
 * A default SeedVault over a host-held mnemonic. Derives K_ss via the frozen seed-secret path and a UTXO
 * signing key via a caller-supplied per-chain signer (kept injectable so the SDK does not hard-wire an HD
 * wallet here — wallet-core owns that). Zeroizes the mnemonic copy on dispose.
 */
declare class MnemonicSeedVault implements SeedVault {
    private mnemonic;
    private readonly signer;
    constructor(mnemonic: string, signer: (chain: Chain, mnemonic: string, hdPath?: string) => Promise<SigningKeyPair>);
    signingKey(chain: Chain, hdPath?: string): Promise<SigningKeyPair>;
    swapKss(): Promise<Uint8Array | null>;
    dispose(): void;
}
/** Scheduler seam (design §2) — steps a machine via `tick()`. Unused in step 4; optional. */
interface Scheduler {
    /** Run `fn` after `delayMs`; returns a cancel handle. */
    schedule(fn: () => void, delayMs: number): () => void;
}
interface SwapControllerDeps {
    /** The untrusted chain transport the SPV layer verifies against (Node injects proxyUrl+ws; tests inject a mock).
     *  A SwapChainClient = the read-only GateChainClient gate surface + the broadcast write method funding needs. */
    chainClientFor(chain: Chain): SwapChainClient;
    seedVault: SeedVault;
    durable: DurableStore;
    session: SessionStore;
    mutex: Mutex;
    reservation: UtxoReservationRegistry;
    /** Liveness/UX only — anti-theft margins anchor to CHAIN time, never this clock (fix #9). */
    clock: () => number;
    scheduler?: Scheduler;
    evmProviderFor?: (chain: Chain) => Provider;
    evmSignerFor?: (chain: Chain) => Signer;
}
type SwapControllerEvent = {
    type: 'phase';
    phase: RecordPhase;
} | {
    type: 'status';
    message: string;
} | {
    type: 'error';
    error: Error;
};
type SwapEventType = SwapControllerEvent['type'];
/** An immutable view of the controller for the host to render an affordance. */
interface SwapSnapshot {
    id: string;
    role: 'initiator' | 'responder';
    phase: RecordPhase;
    myChain: Chain;
    theirChain: Chain;
    myFundingTxid?: string;
    fundLocktime?: number;
    myHTLC?: DurableHTLC;
    /** The EVM block at which our leg was locked — the lossless floor for the counterparty-secret scan (R-EVMLOCKBLOCK-001). */
    evmLockBlock?: number;
    disposed: boolean;
    /** True iff an in-memory re-derivable 32-byte secret is currently loaded. */
    hasSecret: boolean;
    /** Set by resume(): the myHTLC on-chain authentication disposition (fix #10 — only 'ok' authorizes irreversibility). */
    resumeAuth?: 'ok' | 'mismatch' | 'indeterminate' | 'skip';
    /** Set by resume(): which gate the swap re-entered, computed from CHAIN truth (isResumableSwapState), not status. */
    resumeGate?: string;
}
declare class SwapController {
    private record;
    private readonly deps;
    private readonly listeners;
    readonly id: string;
    readonly role: 'initiator' | 'responder';
    readonly myChain: Chain;
    readonly theirChain: Chain;
    /** In-memory only. The re-derivable HTLC preimage — NEVER written durably in plaintext (design §3, fix #5). */
    private secret;
    private disposed;
    /** FIX #10 (resume): set true when resume()'s myHTLC on-chain authentication was NOT a DEFINITIVE 'ok' (a
     *  DEFINITIVE 'mismatch' or a network-blip 'indeterminate'). While set, refund()/revealAndClaim()/
     *  claimWithKnownSecret() refuse any NEW irreversible broadcast — an idempotent ADOPT of an already-broadcast tx is
     *  still allowed (it reveals nothing new). Cleared only by a DEFINITIVE re-authentication to 'ok'. */
    private irreversibleBlocked;
    /** resume() diagnostics (snapshot-exposed): the myHTLC auth disposition + the gate re-entered from CHAIN truth. */
    private resumeAuthValue?;
    private resumeGateValue?;
    constructor(record: DurableSwapRecord, deps: SwapControllerDeps);
    /** Subscribe to a structured event. Returns an unsubscribe fn. */
    on(type: SwapEventType, cb: (e: SwapControllerEvent) => void): () => void;
    off(type: SwapEventType, cb: (e: SwapControllerEvent) => void): void;
    private emit;
    private setPhase;
    private status;
    getState(): SwapSnapshot;
    /** Abort + zeroize the ONLY in-memory secret + tell the vault to zeroize. Idempotent; post-dispose actions throw. */
    dispose(): void;
    private assertLive;
    /**
     * Derive per-swap keys, RECOVER S, and authenticate it against the offer's secretHash — fail-closed. Grounds in
     * SwapExecute.tsx recoverSecret (~2663-2677): for an `hmac-v1` offer as the initiator, S = swapSecretFromKss(
     * K_ss, nonce), and sha256(S) MUST equal offer.secretHash. FIX #5: refuse unless the scheme is `hmac-v1` (S is
     * re-derivable from the seed on any device) OR an encrypted-at-rest durable S exists — never advance a swap whose
     * secret a crash would strand. Also refuses a suspended pair. Transitions `taken -> prepared`.
     */
    prepare(): Promise<void>;
    /**
     * The INITIATOR's re-derivable secret for the reveal path (mirrors buildClaimTx's `state.secret ?? recoverSecret()`
     * ~7204-7207): return the in-memory S if present, else RE-DERIVE it (hmac-v1 from K_ss+nonce, or a durable S) and
     * RE-AUTHENTICATE sha256(S) === offer.secretHash before caching it. Returns null (fail closed) on any miss/mismatch.
     */
    private loadInitiatorSecret;
    /** Recover the 32-byte preimage: hmac-v1 -> derive from K_ss + nonce; else -> decode a durable S. Returns null on miss. */
    private recoverSecret;
    /**
     * Fund the initiator's own UTXO leg. Faithfully ports the proven handleBroadcastFunding path:
     *   (1) SPV verifyFundingHeight on the build height (H1-LOCKTIME-PROXY-001 ~5100) — fail closed if the proxy
     *       height is not a real PoW block (an inflated height would push OUR refund CLTV ~forever, stranding coins).
     *   (2) select + reserve inputs INSIDE reservation.withUtxoLock (candidateUtxos -> greedy FIFO -> reserveInputs
     *       ~5432-5457) so a concurrent funding cannot double-spend an input.
     *   (3) build the funding tx via createInitiatorHTLC + fundHTLC/buildHTLCFundingTx (~5512), signed with the
     *       seedVault key.
     *   (4) commit the durable write-set {funded, fundlocktime, fundrecipient, fundedhtlc} ATOMICALLY (fix #4) BEFORE
     *       the broadcast; a commit throw ABORTS without broadcasting.
     *   (5) broadcast — the whole (2)-(5) sequence runs inside mutex.withLock('bch2swap:fund:'+id) (fix #3
     *       single-flight); a durable `funded` sentinel is re-checked inside the lock so a second call ADOPTS the
     *       prior txid instead of double-broadcasting. myFundingTxid is written after the broadcast.
     * Transitions `taken|prepared -> initiator_funded`.
     */
    fundLegX(): Promise<{
        txid: string;
    }>;
    /**
     * Fund the RESPONDER's own UTXO leg Y (receiveChain), reusing fundLegX's proven select/reserve/build/
     * durable-commit/broadcast machinery but with the RESPONDER HTLC (createResponderHTLC — LOCKTIME_BLOCKS.responder,
     * ~12h, well under the initiator's ~36h) and the leg-Y amount (offer.receiveAmount). It STRUCTURALLY requires a
     * `FundProof` (compile-time) — the only minter is verifyCounterpartyLegForFunding — so a bot cannot fund leg Y
     * without first proving leg X is buried + the timelock margin is safe.
     *
     * FIX #2 (zero proof-reuse window, R175): the passed `proof`'s captured values are NEVER trusted to authorize the
     * broadcast. Inside the fund mutex, at the broadcast choke point, we RE-MINT from a FRESH read of the counterparty
     * (initiator) leg X (verifyCounterpartyLegForFunding -> assertLegBuriedForFunding). A fresh throw ABORTS without
     * broadcasting — funds never move against a leg X that reorged / double-spent / drifted past the margin since the
     * proof was minted. Transitions `taken|prepared -> responder_funded`. Grounds in handleCounterpartyFunded + the
     * responder fund path (~5230-5281).
     */
    fundLegY(proof: FundProof): Promise<{
        txid: string;
    }>;
    /**
     * Shared own-leg funding machinery for fundLegX (initiator) + fundLegY (responder). Faithfully ports the proven
     * handleBroadcastFunding path — see the fundLegX doc block for the (1)-(5) sequence. The only per-role differences
     * are the HTLC factory, the leg amount, the target phase, and the optional `preBroadcastReverify` (fix #2, leg Y).
     */
    private fundOwnLeg;
    /**
     * RESPONDER-ONLY. Mint a `FundProof` by SPV-verifying the counterparty (initiator) leg X is buried at the required
     * depth + the responder timelock margin is safe (gates.assertLegBuriedForFunding over leg X). Returns the branded
     * proof or THROWS a GateFailure (mints nothing) on any failure/uncertainty — fail closed, no funds move. This is
     * the only way to obtain the `FundProof` that fundLegY requires (design §4).
     */
    verifyCounterpartyLegForFunding(): Promise<FundProof>;
    /**
     * INITIATOR-ONLY. Mint a `RevealAuthorization` by SPV-verifying the counterparty (responder) leg Y is buried +
     * the 4h claim-margin runway on leg Y holds (gates.assertRevealSafe with role:'initiator' over leg Y). Returns the
     * branded authorization or THROWS a GateFailure (mints nothing) — the secret NEVER leaks on any failure. This is
     * the only way to obtain the `RevealAuthorization` that revealAndClaim requires (design §4).
     */
    verifyCounterpartyLegForReveal(): Promise<RevealAuthorization>;
    /**
     * The initiator's ONE irreversible action: reveal S by broadcasting the secret-bearing claim of the counterparty
     * (responder) leg Y. STRUCTURALLY requires a `RevealAuthorization` (compile-time). Ports handleBroadcastClaim
     * (~7787-8075). Fund-safety corrections baked in:
     *   FIX #3: throw unless `auth.role === 'initiator'` — a margin-skipped responder authorization (marginBasis:'none')
     *     must NEVER drive the initiator's reveal (it deliberately skips the 4h double-dip margin).
     *   FIX #8 (triangulation): the built claim carries the exact funding outpoint it spends (`.spent`). Require
     *     `auth.outpoint === claimTx.spent`, and — via the fresh re-mint below — that this same outpoint is STILL
     *     confirmed at >= reqConf. A cached claim tx LACKING `.spent` fails closed (R-REVEAL-FAILCLOSE ~7980): discard
     *     it + rebuild rather than broadcast the secret against an unverifiable outpoint.
     *   FIX #2 (zero reuse window): inside the claim mutex at the broadcast choke point, RE-MINT assertRevealSafe from
     *     a FRESH read (never the passed auth's captured values). A fresh throw ABORTS — S is never emitted.
     * The claim tx {txid,rawTx,spent} is committed durably (durable-before-broadcast) BEFORE the broadcast, under a
     * single-flight mutex ('bch2swap:claim:'+id) with a `claimbroadcast` sentinel so a second call / crash-resume
     * ADOPTS the prior claim instead of re-revealing. S is NEVER emitted on any throw. Transitions
     * `responder_funded -> claimed`.
     */
    revealAndClaim(auth: RevealAuthorization): Promise<{
        txid: string;
    }>;
    /**
     * RESPONDER-ONLY. Poll the responder's OWN funded leg (leg Y, myChain) history for the initiator's spend, which
     * reveals S in its scriptSig. `extractSecret` parses the preimage and we RE-VERIFY `sha256(S) === hashLock` (the
     * hash COMMITTED in the funded redeemScript — §9.4) before saving; a forged/mismatched preimage is REJECTED.
     * Ports watchForSecret (~7499-7766) as a single scheduler-driven poll: it NEVER throws on absence (returns
     * `{secret:null}`) and, on discovery, transitions `responder_funded -> claimed`. Grounds the extract hash in
     * myHTLC.params.secretHash (R263 on-chain binding).
     */
    watchForSecret(): Promise<{
        secret: Uint8Array | null;
    }>;
    /**
     * RESPONDER-ONLY. Claim the counterparty (initiator) leg X (theirChain) with the now-PUBLIC secret learned via
     * watchForSecret. The reveal margin gate is DELIBERATELY SKIPPED (the secret is already public — no double-dip
     * risk, design §1), but single-flight + durable-before-broadcast still apply, and it REFUSES if a refund of the
     * same HTLC is in flight (a claim + refund must not race the same outpoint). Transitions `claimed -> completed`.
     */
    claimWithKnownSecret(): Promise<{
        txid: string;
    }>;
    /**
     * PURE predicate (no side effects, no network): is OUR funded HTLC refundable at the host-supplied `currentHeight`?
     * Exposes the ported isHtlcRefundAvailable(myHTLC.locktime, tip) for the host to render an affordance. This is only
     * an availability HINT — the REAL enforcer is the on-chain CLTV plus the FRESH-tip re-check inside refund() (§9.7).
     * Returns false when there is no funded own HTLC.
     */
    canRefund(currentHeight: number | null): boolean;
    /**
     * Recover OUR OWN funded leg after its timelock. Grounds in SwapExecute.tsx handleBroadcastRefund (~8349-8641):
     *   - §9.7: RE-CHECK isHtlcRefundAvailable against a FRESH tip immediately before build (the on-chain CLTV is the
     *     real enforcer, but never build/broadcast a premature refund the node will reject).
     *   - build buildHTLCRefundTx (nSequence 0xfffffffe + nLockTime=locktime are set INSIDE the builder). Carries NO secret.
     *   - R280-H1 / fix #4 durable-before-broadcast: PERSIST the raw refund tx + a `refundbroadcast` sentinel via
     *     durable.commit BEFORE the broadcast; a commit throw ABORTS the broadcast.
     *   - broadcast under a SINGLE-FLIGHT mutex.
     *   - arm the reorg-safe confirmRefund finalizer.
     * FIX (deferred from step 5 — R181 claim<->refund cross-guard): take the SAME 'bch2swap:claim:'+id lock the claim
     * paths use (and refuse if a `claimbroadcast` sentinel is set) so a claim and a refund never race the same outpoint.
     * FIX #10: refuse if resume left the myHTLC authentication non-definitive (see assertIrreversibleAllowed).
     * Transitions -> 'refunded' at broadcast; the recovery material is KEPT until confirmRefund reaches reorg-safe depth.
     */
    refund(): Promise<{
        txid: string;
    }>;
    /**
     * CLAIM finalizer (§9.6). Ground: SwapExecute.tsx confirmClaim (~8019-8112). Polls the counterparty leg (theirChain)
     * for OUR claim txid; ONLY once it is buried at >= requiredConfirmations VERIFIED BY SPV (verifyConfirmations,
     * provenTxid-bound) does it delete the non-recoverable secret + claim cache + record. On 0-conf / absent / short
     * depth / inconclusive-or-pruned SPV read it KEEPS everything (fail closed). Single poll — the host re-drives it.
     */
    confirmClaim(): Promise<{
        finalized: boolean;
    }>;
    /**
     * REFUND finalizer (§9.6). Ground: SwapExecute.tsx confirmRefund (~8466-8531). Polls OUR OWN leg (myChain) for OUR
     * refund txid; ONLY once buried at >= requiredConfirmations VERIFIED BY SPV does it wipe the recovery material. On
     * 0-conf / dropped / short depth / inconclusive-or-pruned read it KEEPS refundtx/refundbroadcast/state — "give up
     * POLLING after 4h but KEEP everything" maps to a single non-finalizing poll (SwapExecute.tsx:8468). The secret/state
     * are wiped ONLY if no claim is in flight (a co-running winning claim needs the shared preimage); the refundtx +
     * sentinel are always cleared at reorg-safe depth. Fail-closed = keep material.
     */
    confirmRefund(): Promise<{
        finalized: boolean;
    }>;
    /**
     * Pruned-safe SETTLE for a tangled completed swap (§9.6 / SwapExecute.tsx trySettleIfBothLegsSpent ~6809). Only when
     * the `claimbroadcast` sentinel is set AND BOTH legs are spent on the LIVE UTXO set is the swap terminal (their claim
     * of our leg used our revealed secret, or both refunded) — nothing left to recover — so wipe + finalize. If OUR leg
     * is still funded (refundable) it returns false + KEEPS the recovery material (fail closed). Any inconclusive read
     * returns false. Returns true iff it settled.
     */
    trySettleIfBothLegsSpent(): Promise<boolean>;
    /**
     * §9.6 reorg-safe proof that OUR OWN leg's HTLC funding output has been SPENT and that spend is buried at
     * >= requiredConfirmations SPV-VERIFIED depth (the same anchor confirmClaim / confirmRefund use). The spend is the
     * confirmed HTLC-scripthash history tx that is NOT our own funding tx. FAIL CLOSED (returns false): a transient read
     * error, a 0-conf / short-depth spend, a pruned/unprovable SPV read, or the absence of any confirmed spend all KEEP
     * the recovery material. Never trusts a bare getUTXOs "empty" read to authorize the teardown.
     */
    private ownLegSpendReorgSafe;
    /**
     * §9.6 reorg-safe proof that OUR claim of the RECEIVE leg (theirChain) is buried at >= requiredConfirmations
     * SPV-VERIFIED depth. Mirrors confirmClaim's proof (find our claim txid in the counterparty HTLC-scripthash history
     * + spvReorgSafe against the recorded rawTx). FAIL CLOSED (false) on any doubt: a transient read error, a 0-conf /
     * short-depth claim, a pruned/unprovable SPV read, or the absence of our claim in history all KEEP the material.
     * Used by trySettleIfBothLegsSpent to gate the wipe of the receive-leg claim material (secret + claimTx).
     */
    private claimBuriedReorgSafe;
    /**
     * Rehydrate a swap from a durable record: re-derive S, RECONSTRUCT + on-chain-AUTHENTICATE myHTLC, run the
     * FINALIZERS-FIRST (refund-first short-circuit), rebroadcast a funded-but-missing funding tx idempotently, and
     * re-enter the correct gate from CHAIN truth (isResumableSwapState), NOT the persisted status. FIX #10 (critical): a
     * DEFINITIVE myHTLC 'mismatch' fails closed; an INDETERMINATE (network-blip) auth may WAIT / re-poll ONLY — neither
     * authorizes any irreversible broadcast (refund/claim) until authentication is DEFINITIVE 'ok'. Returns the controller.
     */
    static resume(record: DurableSwapRecord, deps: SwapControllerDeps): Promise<SwapController>;
    private rehydrate;
    private setResumeGate;
    /**
     * Authenticate our recorded myHTLC against the LIVE on-chain funding output (faithful port of SwapExecute.tsx:4699
     * authenticateMyHtlcAgainstFunding; the React mountedRef guards + Promise.race timeouts are dropped — the SDK client
     * owns transport timeouts). Returns:
     *   'ok'            — the funding output[0] byte-matches our HTLC P2SH (unspent set OR self-authenticated raw tx),
     *   'mismatch'      — a DEFINITIVE tamper (non-bare-hex funding txid, or output[0] present but not our P2SH),
     *   'indeterminate' — an AMBIGUOUS read (network/cold-proxy getTx failure) BUT the funding txid is in our own HTLC
     *                     scripthash history (a genuine, possibly-already-spent funding) — caller may WAIT / re-poll,
     *   'skip'          — no UTXO myHTLC / funding txid to check (an EVM leg, or not funded yet).
     * FIX #10: only 'ok' authorizes an irreversible action; 'mismatch' fails closed; 'indeterminate' waits.
     */
    private authenticateMyHtlcAgainstFunding;
    /**
     * RECONSTRUCT myHTLC on resume from the durable side-channels when the states-map copy is gone (R170 fundedhtlc, then
     * R277 fundlocktime + funding-txid rebuild). The single trust anchor is the on-chain P2SH byte-match
     * (verifyAndAuthenticateUtxo): a lying/tampered source can only DENY a rebuild (fail-closed skip), never install a
     * bad refund/watch target. No-op if myHTLC already present, or on an EVM leg.
     */
    private reconstructMyHtlc;
    /**
     * If the durable 'funded' sentinel/txid is set but the funding tx is NOT on-chain, rebroadcast the EXACT durable raw
     * funding tx (bch2swap:fundedtx, step 4) IDEMPOTENTLY (same txid — the node dedups) rather than re-selecting inputs
     * (which would pick different inputs -> a divergent txid than the durable sentinel). Fail-closed: if we cannot tell
     * whether the funding is on-chain (read error), we do NOT rebroadcast blindly.
     */
    private rebroadcastFundingIfMissing;
    /**
     * §9.7 refund-reachability is not one-shot: if a refund was broadcast (durable refundtx + refundbroadcast sentinel)
     * but its txid is NOT in the HTLC history AND the funding output is STILL unspent, the refund DROPPED — resubmit the
     * EXACT durable refund tx (idempotent, same txid). Resume-driven (NOT the immediate post-broadcast poll, where a
     * 0-conf refund is indistinguishable from a dropped one). Fail-closed: a read error / an already-spent funding output
     * does NOT rebroadcast, and this NEVER wipes.
     */
    private rebroadcastRefundIfDropped;
    /**
     * R-UTXO-CLAIM-REDRIVE-001: the UTXO analogue of confirmClaimEvm's orphan re-drive (and the claim-side sibling of
     * rebroadcastRefundIfDropped). A UTXO receive-leg (leg X) claim that was broadcast then PERMANENTLY dropped (mempool
     * eviction under fee pressure / a restrictive-policy reorg that does not re-admit it) is otherwise never re-sent:
     * confirmClaim finds the txid absent + returns not-finalized WITHOUT re-broadcasting, and priorClaimTxid adopts the
     * never-confirmed txid on the local sentinel alone — so the claim never lands and, after leg X's longer refund
     * timelock, the counterparty refunds it (receive-leg-value loss, S already public). On resume: if OUR claim txid is
     * ABSENT from leg X's history AND leg X is STILL unspent (proving the claim dropped, not landed), re-broadcast the
     * durable claim rawTx idempotently (same txid). Fail-closed: do nothing on a read error, if the claim is present
     * (mempool/confirmed), or if leg X is already spent (claim landed / counterparty took it). Returns true iff re-sent.
     */
    private rebroadcastClaimIfDropped;
    /** Step-5 deferred idempotent-adopt source: the PRIOR winning claim txid iff the `claimbroadcast` sentinel is set and
     *  a durable claim tx (or record.myClaimTxid) supplies a bare-hex txid; else null. */
    private priorClaimTxid;
    /** Read + validate the durable refund tx cache (R280-H1). */
    private readDurableRefundTx;
    /**
     * §9.6 reorg-safe depth check for a terminal tx (claim/refund) at `height` on `chain`. Requires BOTH a proxy depth
     * >= reqConf AND — on spvSupported mainnets — verifyConfirmations (SPV, provenTxid-bound) >= reqConf. FAIL CLOSED:
     * any unknown tip, SPV throw (pruned/short/tampered header/Merkle proof), or below-required depth returns false
     * (the caller KEEPS all recovery material). Regtest / non-SPV chains fall back to the proxy depth (test-only).
     */
    private spvReorgSafe;
    /** Fail-closed = keep material: refuse a NEW irreversible broadcast while a resume's myHTLC auth is not definitive (fix #10). */
    private assertIrreversibleAllowed;
    /** Best-effort delete of a set of durable keys (§9.6 wipe — reached only at reorg-safe depth). */
    private wipeDurable;
    /** leg X amount in sats (offer.sendAmount = the initiator's locked amount, base-unit sats < 2^53). Fail closed. */
    private legXAmountSats;
    /** leg Y amount in sats (offer.receiveAmount = the RESPONDER's locked amount on receiveChain). Fail closed. */
    private legYAmountSats;
    /** R-CPRECIP-001: the {recipientPkh, secretHash} the COUNTERPARTY leg's redeemScript MUST commit for us to be able to
     *  claim it — hash160 of OUR claim key on theirChain (exactly the pkh buildSecretClaim sweeps to) + the offer
     *  secretHash. The UTXO gates bind the recorded counterparty script against these (parity with the EVM
     *  isEvmLockAtSafeDepth {recipient, hashLock} binds), rejecting a substituted-recipient / substituted-secret leg. */
    private counterpartyLegBinds;
    private amountSats;
    /** A minimal SwapState for createInitiatorHTLC/createResponderHTLC (they read only offer.{send,receive}Chain +
     *  secretHash). `role` selects which leg-chain the builder reads; the address fields are UI-only here. */
    private buildSwapState;
    /** True iff `o` is a structurally-valid funding outpoint {tx_hash:64-hex, tx_pos:non-negative int}. */
    private isOutpoint;
    /**
     * Resolve the counterparty HTLC (redeemScript + locktime) and its recorded funding outpoint — the leg the
     * fund/reveal gates re-verify + the claim spends. Fail closed if the host has not recorded a valid HTLC/outpoint.
     */
    private counterpartyLeg;
    /**
     * Build a signed secret-bearing claim of the counterparty HTLC on `chain`, carrying the exact funding outpoint it
     * spends (`.spent` — load-bearing for the fix #8 triangulation + the pre-reveal double-spend re-check). Prefers the
     * `preferOutpoint` (the authorized one) when it is in the fresh UTXO set, else the largest valid output (mirrors
     * buildClaimTx ~7244/7690). Authenticates the chosen output's VALUE + P2SH scriptPubKey against its self-derived
     * raw tx before signing (never trusts the proxy listunspent value). Signs with the seed-derived key on `chain`
     * (whose hash160 is the HTLC recipient pkh) and sweeps to that same pkh. THROWS on no claimable/authenticatable UTXO.
     */
    /**
     * R-FEE-DEADLINE-001: the LIVE, deadline-aware sat/vByte for a UTXO claim/refund (wires the previously-inert
     * fee-rate module into the fund-critical paths). (1) live base rate via fetchFeeRate — the proxy's
     * blockchain.estimatefee (max(mempoolminfee, estimatesmartfee)), floored to the config rate + clamped to
     * maxFeeRate, fail-safe to the floor on any error. (2) scaled UP by deadlineAwareFeeRate as the leg's refund
     * runway (from the AUTHENTICATED redeemScript CLTV + a best-effort tip) approaches CLAIM_MARGIN; a stale/
     * under-reported tip only shrinks the multiplier toward the live base, never below it (a lying proxy can't
     * underprice below the live network rate). Without this the tx builds at the STATIC config rate and, on a
     * fee-volatile chain (BTC/BCH) during a sustained spike, the secret-revealing claim can enter the mempool but
     * not confirm inside the reveal margin → the counterparty refunds one leg and claims the other = double-loss.
     */
    private legAwareFeeRate;
    private buildSecretClaim;
    /**
     * Greedy FIFO UTXO selection — ported from prepareFundingTx (~5431-5457): oldest-confirmed-first (immature
     * coinbase is newest, so it is spent last), tie-break by value desc, accumulate until amount + estimated fee is
     * covered, then decide the change-output count AFTER fee. Returns the selected inputs or null (insufficient).
     * Uses the chain's static config fee rate (a LIVE deadline-scaled rate is a separate seam; step 4 keeps it simple).
     */
    private greedySelect;
    /** Read + validate the durable funded-HTLC side-channel (R170) for the adopt path. */
    private readDurableFundedHtlc;
    /** The injected quorum>=2 EVM read Provider for `chain` (the EVM GATE surface). Fail closed if not injected. */
    private evmProvider;
    /** The injected EVM Signer (a Node ethers.Wallet from the seed) for `chain`. Fail closed if not injected. */
    private evmSigner;
    /** Resolve `chain` -> its numeric EvmChainId + the canonical EVM config (htlcAddress, requiredConfirmations, lock
     *  bounds). Fail closed if `chain` is not an EVM chain or has no deployed config. */
    private evmCfgFor;
    /** FIX #10 §5(#10): carry EVM amounts as base-unit strings — never `Number()` an 18-dec (wei) value. Accept a
     *  decimal-integer base-unit string (canonical) or a legacy safe-integer number; throw on anything else. */
    private evmAmountBaseUnits;
    /** The offer secretHash as a 0x-prefixed bytes32 (the on-chain hashLock). Fail closed if malformed. */
    private hashLock0x;
    /** Resolve the COUNTERPARTY EVM leg (the leg WE verify/claim on theirChain): htlc addr, swapId, requiredConfirmations,
     *  hashLock, the recipient (= OUR EVM address, who may claim it), minAmount (what we receive), and its token. */
    private counterpartyEvmLeg;
    /**
     * RESPONDER-ONLY. Mint a `FundProof` by proving the counterparty (initiator) EVM leg is locked at a reorg-safe
     * depth with all invariants bound (gates.assertEvmLegBuriedForFunding over the injected quorum>=2 provider). The
     * ONLY controller-side minter of an EVM `FundProof`. Grounds in verifyEvmCounterpartyHTLC (SwapExecute.tsx
     * ~3055-3460): the responder-fund gate re-asserts DEPTH + {hashLock, recipient, minAmount, minTimeLock, token} and
     * fails closed (quorum>=2) before the responder commits its own leg. Returns the branded proof or THROWS
     * (mints nothing) — including refusing a single-leaf provider (fix #7/#1, done inside the gate).
     */
    verifyEvmCounterpartyLegForFunding(): Promise<FundProof>;
    /**
     * INITIATOR-ONLY. Mint a `RevealAuthorization` by proving the counterparty (responder) EVM leg is at a reorg-safe
     * depth AND keeps >= 4h (EVM_CLAIM_MARGIN_SEC) runway on its FRESH on-chain timeLock (gates.assertEvmRevealSafe,
     * quorum>=2). The ONLY controller-side minter of an EVM `RevealAuthorization`. Grounds in handleEvmClaim gate #2 +
     * the R258/R260/R261/R278 margin re-check (SwapExecute.tsx ~2128-2258). Returns the branded auth or THROWS — the
     * secret NEVER leaks on any failure (this only READS the chain; it does not touch the secret).
     */
    verifyEvmCounterpartyLegForReveal(): Promise<RevealAuthorization>;
    /** FIX #2 re-mint used by lockEvm at the broadcast choke point: re-prove the counterparty leg is buried FRESH. Uses
     *  the EVM gate when the counterparty leg is EVM, else the UTXO gate — either throws (aborting the lock) on any doubt. */
    private reverifyCounterpartyLegForFunding;
    /**
     * Lock OUR OWN EVM leg (lockETH or lockTokens per isNativeToken) with the injected Node signer. STRUCTURALLY
     * requires a `FundProof` (compile-time — the two brands are non-interchangeable, fix #1). Grounds in handleEvmFund
     * (SwapExecute.tsx ~1089-1360).
     *   FIX #2 (zero proof-reuse window): inside the fund mutex, at the choke point, RE-MINT the counterparty-leg burial
     *     FRESH (assertEvmLegBuriedForFunding) — never the passed proof's captured values. A fresh throw ABORTS before
     *     any lock tx is broadcast.
     *   FIX #4 (durable-before-broadcast): the lockpending + evmlocktx recovery markers are committed durably in the
     *     lock's onBroadcast callback — the instant the tx is broadcast (before it mines) — because the EVM lock is
     *     irreversible once mined; the funded=swapId sentinel is committed the moment the lock resolves with its id.
     *   FIX #10: gated by assertIrreversibleAllowed. Single-flight (fix #3) under mutex.withLock; a prior funded swapId
     *     is ADOPTED rather than re-locked (a second on-chain lock would strand a fresh per-nonce swapId). Handles the
     *     onBroadcast-replacement hash (a MetaMask speed-up; a Node signer typically won't) by capturing the final hash.
     */
    lockEvm(proof: FundProof): Promise<{
        swapId: string;
        txHash: string;
    }>;
    /**
     * The initiator's ONE irreversible EVM action: reveal S by claiming the counterparty (responder) EVM leg with S in
     * the claim calldata (evmClaimSwap = claimSwap). STRUCTURALLY requires a `RevealAuthorization` (compile-time).
     * Grounds in handleEvmClaim (SwapExecute.tsx ~2128-2430).
     *   FIX #3: throw unless `auth.role === 'initiator'` — a margin-skipped responder authorization must NEVER drive the
     *     initiator's reveal.
     *   FIX #2: inside the claim mutex at the broadcast choke point, RE-MINT assertEvmRevealSafe FRESH (quorum>=2 depth +
     *     the 4h margin re-derived from the FRESH on-chain timeLock) — never the passed auth's captured values. A throw
     *     ABORTS; S is never sent. (claimSwap itself also re-checks sha256(S)===hashLock + expiry + recipient before it
     *     broadcasts, so S never reaches calldata on a bad claim — defense in depth.)
     *   FIX #4: a durable `claimbroadcast` sentinel is committed BEFORE the secret-revealing claim; a second call /
     *     crash-resume ADOPTS instead of re-revealing. FIX #10: gated by assertIrreversibleAllowed. R181 cross-guard:
     *     refuses to reveal while a refund is in flight. Transitions `responder_funded -> claimed`.
     */
    revealAndClaimEvm(auth: RevealAuthorization): Promise<{
        txHash: string;
    }>;
    /**
     * Refund OUR OWN EVM lock (evmRefundSwap = refundSwap) after its timelock. §9.7: reachable after expiry (suspension
     * never gates a refund). A durable `refundbroadcast` sentinel is committed BEFORE the send (durable-before-broadcast)
     * under the shared claim/refund single-flight lock, so a claim and a refund can never race.
     *
     * THE REFUND-RACE PIVOT (fund-loss-critical, fix #7): if refundSwap REVERTS because the counterparty ALREADY CLAIMED
     * our lock (took it with S), we do NOT treat that as a plain error. S is now PUBLIC in the on-chain `Claimed` event,
     * so we RECOVER it — corroborated across quorum>=2 leaves (never conclude "safe to abandon" while an honest leaf may
     * still yield S), verify sha256(S)===hashLock (the authenticator), and use S to CLAIM the OTHER (counterparty) leg so
     * we are made whole. Grounds in the 'already claimed' branch (SwapExecute.tsx:2423) + watchForClaim/watchAndRefund.
     */
    refundEvm(): Promise<{
        txHash: string;
    }>;
    /** Best-effort on-chain check used by refundEvm's adopt path (fix #4): is OUR own EVM swap actually REFUNDED? Reads
     *  getSwap over the given provider and returns `!!swap.refunded`; fail-closed to `false` on any read error / missing
     *  provider (a not-yet-confirmed / dropped refund must never be finalized as a completed 'refunded'). */
    private evmSwapIsRefunded;
    /**
     * R-EVMCLAIM-REORG-001: the claim-side analogue of evmSwapIsRefunded — the on-chain trust anchor for whether OUR
     * claim of an EVM leg actually stuck. Reads getSwap.claimed (fail-closed false on any read error or absent swap).
     * Used to corroborate the claimbroadcast sentinel before adopting a claim as final, so a 1-conf claim later orphaned
     * by a reorg is re-driven rather than falsely reported as complete.
     */
    private evmSwapIsClaimed;
    /**
     * R-EVMCLAIM-REORG-001: the reorg-safe finalizer + orphan re-driver for an EVM theirChain claim (confirmClaim +
     * trySettleIfBothLegsSpent both bail for EVM, so the resume claim branch never finalized/re-drove an EVM claim). It
     * reads getSwap.claimed at a REORG-SAFE depth (tip - reqConf + 1, the same depth basis isEvmLockAtSafeDepth uses for
     * the lock):
     *  - claimed at the buried depth        -> FINALIZE ('claimed' -> 'completed').
     *  - claimed at the tip but not buried  -> KEEP (still finalizing; a later resume finalizes it).
     *  - NOT claimed + the lock still funded (an ORPHANED 1-conf claim, or one that never mined) -> RE-BROADCAST the
     *    claim with the now-public S (skips the reveal margin gate — re-revealing a public S leaks nothing).
     *  - lock gone / refunded / any read error -> KEEP (never finalize or re-drive on doubt).
     * Fail-safe: a spurious re-broadcast at worst reverts on-chain (the contract enforces single-claim) — never a loss.
     */
    private confirmClaimEvm;
    /**
     * R-EVMCLAIM-REORG-001: re-broadcast an EVM claim that a reorg orphaned. S is already public (the orphaned claim
     * revealed it), so this SKIPS the reveal margin gate (re-revealing leaks nothing) — the initiator's S is re-derived
     * from the seed, the responder's is the in-memory public secret. Re-commits the sentinel around the fresh broadcast.
     */
    private reBroadcastOrphanedEvmClaim;
    /** Broadcast a UTXO claim, clearing the durable claimbroadcast sentinel ONLY on a DEFINITIVE pre-broadcast node
     *  rejection (the node validated + refused the tx — it never entered any mempool, so the secret is not public and a
     *  retry can rebuild + re-broadcast), so a later call re-arms instead of ADOPTING a never-broadcast claim (fix #3).
     *  An AMBIGUOUS / timeout / post-broadcast failure (the tx MAY have reached a mempool) LEAVES the sentinel set
     *  (R201 fail-safe). The UTXO analogue of claimEvmWithSentinelGuard — same definitive-vs-ambiguous classification. */
    private broadcastClaimWithSentinelGuard;
    /**
     * R-UTXO-REFUNDRACE-001 (B1): the refund-path analogue of broadcastClaimWithSentinelGuard. A DEFINITIVE node
     * rejection means no refund reached any mempool — critically 'bad-txns-inputs-missingorspent' (the counterparty
     * already CLAIMED our leg Y, revealing S), where the refund can NEVER succeed. Without clearing the sentinel it
     * would permanently block the responder's ONLY remaining payout — claimWithKnownSecret on leg X (still claimable
     * with the now-public S). Clear it on a definitive rejection (a min-relay-fee rejection also clears safely: the
     * outpoint is still unspent, so a refund retry re-arms and the claim cannot proceed while S is not yet public). An
     * AMBIGUOUS / timeout failure KEEPS the sentinel — the refund may still confirm (fail-safe).
     */
    private broadcastRefundWithSentinelGuard;
    /**
     * R-UTXO-REFUNDRACE-001 (B2): the UTXO analogue of recoverFromRefundRace, for the case where the refund broadcast
     * SUCCEEDED (so B1's definitive-rejection clear never fired and phase='refunded' was set) but the refund is later
     * ORPHANED — the initiator won the mempool/mining race and CLAIMED our leg Y, revealing S. Without this the responder
     * is permanently wedged: phase='refunded' (blocks claimWithKnownSecret at its phase gate) + the refundbroadcast
     * sentinel (blocks its cross-guard), so leg X — still claimable with the now-PUBLIC S until its LONGER timelock — is
     * forfeited, netting the strategic initiator BOTH legs. Detect the lost race (leg Y's HTLC output spent by a tx that
     * is NOT our refund and that reveals a preimage of our secretHash), recover S, clear the refund sentinel, reset phase
     * to 'claimed', and drive claimWithKnownSecret on leg X. Fail-closed: pivots ONLY on a confirmed-public S; otherwise
     * returns false and KEEPS all recovery material (the refund may still be pending — never abandon while S may still be
     * recoverable). RESPONDER-only (only the responder claims leg X with the counterparty's public secret).
     * @returns true iff the lost race was detected and S recovered (the leg-X claim is then driven best-effort).
     */
    private recoverUtxoRefundRace;
    /** Broadcast an EVM claim, clearing the durable claimbroadcast sentinel ONLY on a PRE-broadcast throw (claimSwap tags
     *  pre-flight failures `preBroadcast:true` — no secret revealed), so a later call re-arms instead of adopting a
     *  never-broadcast claim (fix #3). A POST-broadcast / ambiguous failure LEAVES the sentinel set (R201 fail-safe). */
    private claimEvmWithSentinelGuard;
    /**
     * R-EVM-REFUNDRACE-RESUME-001: the EVM-own-leg parity sibling of recoverUtxoRefundRace, wired into resume(). A
     * RESPONDER whose own EVM leg Y was CLAIMED by the initiator (S now public) — after it had already committed the
     * refundbroadcast sentinel but crashed before refundEvm's synchronous pivot (recoverFromRefundRace) cleared it — is
     * otherwise permanently wedged on resume: confirmRefund + recoverUtxoRefundRace + rebroadcastRefundIfDropped ALL bail
     * for an EVM own leg, so resume short-circuits at 'refund-in-flight' with the sentinel stuck, and claimWithKnownSecret
     * is blocked by the refund cross-guard — the responder forfeits leg X (still claimable with the public S until its
     * longer timelock) while the initiator nets both legs. Detect the lost race on-chain (our own EVM swap is claimed +
     * not refunded, so the refund can never confirm) and drive recoverFromRefundRace (recovers S from the Claimed event,
     * clears the sentinel, claims leg X). Fail-closed: pivots ONLY when getSwap shows claimed && !refunded; returns false
     * and KEEPS everything on any read error / not-claimed / S-not-yet-extractable (a later resume retries).
     * @returns true iff the pivot ran AND completed (S recovered + leg X claimed).
     */
    private recoverEvmRefundRaceOnResume;
    /**
     * R-EVM-REFUND-RESUBMIT-001: the EVM-own-leg sibling of rebroadcastRefundIfDropped — a refundEvm that committed the
     * refundbroadcast sentinel then dropped its refund tx (mempool eviction / crash during tx.wait) with the counterparty
     * NEVER claiming has no in-SDK path forward: confirmRefund + recoverUtxoRefundRace + rebroadcastRefundIfDropped all
     * bail for an EVM own leg, recoverEvmRefundRaceOnResume covers only the CLAIMED (race) case, and a manual refundEvm
     * re-call adopts the set sentinel and reports a false 'refund-pending' — the own EVM funds stay locked past expiry.
     * On resume this finalizes-or-resubmits: getSwap.refunded => finalize ('refunded'); exists && !claimed && !refunded
     * => re-invoke refundSwap (re-verifies expiry/initiator on-chain, idempotent — a still-pending original's loser
     * reverts) and finalize on a confirmed re-refund. Fail-closed: KEEP + no action on any read error, or when claimed
     * (the race case, handled above) / still-unconfirmed. Returns true iff the refund is now terminal (finalized).
     */
    private finalizeOrResubmitEvmRefund;
    /**
     * R-EVMLOCK-RESUME-001: reconstruct a crashed EVM own-leg lock on resume — the EVM parity of the UTXO
     * reconstructMyHtlc self-heal. lockEvm commits lockpending+evmlocktx the instant the lock BROADCASTS (onBroadcast),
     * but funded=swapId + record.myEvmSwapId are set only AFTER tx.wait resolves; a crash in that window leaves the leg
     * LOCKED on-chain with the record unable to refund/watch it (refundEvm/watchForClaimEvm both require myEvmSwapId).
     * Adopt the on-chain lock via recoverLockFromTx (reusing lockEvm's own quorum-corroborated logic): on 'locked',
     * commit the funded sentinel + reconstruct myEvmSwapId/myFundingTxid/funded so the own-leg payout paths work with NO
     * host re-lock and NO counterparty-leg re-verification. Fail-closed: no reconstruction on 'blocked' (retry later) /
     * 'safe' (never landed — the fund gate re-drives) / any read error. Returns true iff the lock was adopted.
     */
    private recoverEvmLockOnResume;
    /**
     * THE REFUND-RACE PIVOT body (fix #7). Recover S from OUR OWN EVM lock's on-chain `Claimed` event, corroborated
     * across quorum>=2 leaves, verify sha256(S)===hashLock, then claim the OTHER (counterparty) leg with the now-public
     * S so we are made whole. If S is not YET extractable (a lagging/pruned leaf), we KEEP the refund sentinel and throw
     * a RETRYABLE error — never conclude "safe to abandon" while S may still be extractable from an honest leaf.
     */
    private recoverFromRefundRace;
    /** Claim the COUNTERPARTY EVM leg with the now-PUBLIC secret (the refund-race pivot's EVM<->EVM branch). No reveal
     *  margin gate (the secret is already public — no double-dip race), but the durable claimbroadcast sentinel + the
     *  single-flight lock still apply. Uses claimSwap (which re-checks sha256(S)===hashLock + recipient on-chain). */
    private claimEvmCounterpartyWithPublicSecret;
    /**
     * RESPONDER-ONLY. Watch OUR OWN EVM lock (myEvmSwapId) for the initiator's `Claimed` event, EXTRACT + VERIFY S
     * (sha256(S)===hashLock — the authenticator, so a quorum>=1 hash-verified liveness read is acceptable here per
     * R-POLYHIST), and SAVE it. Grounds in handleEvmFund's responder watch (watchForClaim, SwapExecute.tsx ~1250-1310).
     * A single scheduler-driven scan: NEVER throws on absence (returns `{secret:null}`); a forged/mismatched preimage is
     * REJECTED (the hash check). On discovery, transitions `responder_funded -> claimed`.
     */
    watchForClaimEvm(): Promise<{
        secret: Uint8Array | null;
    }>;
    /**
     * Read + hash-VERIFY the preimage S from a `Claimed` event on the given EVM swapId, corroborated across the
     * provider's quorum leaves. Returns the FIRST S from ANY leaf whose sha256 equals `hashLockHex` (the authenticator —
     * so a single honest leaf is sufficient to TRUST the value), else null. The hash check makes a forged/foreign
     * Claimed log unusable (fund-safe), and reading every leaf means a lagging/pruned leaf never falsely hides an S that
     * an honest leaf still holds (the fix #7 "never abandon while S may be extractable" property). Never throws on a
     * per-leaf read error (a leaf that errors just doesn't contribute an S).
     */
    private readEvmClaimedSecret;
    /**
     * FIX #1 (fund-loss): scan ONE leaf for the hash-verified Claimed preimage with a BOUNDED, WINDOWED getLogs — the
     * SDK's proven watchForClaim windowing (evm-client.ts ~L1486) ported into a single, non-blocking sweep. The old code
     * issued one UNBOUNDED `getLogs({fromBlock: evmLockBlock, toBlock:'latest'})`; a real public RPC rejects a wide range
     * ('range too large'), so S was never recovered and the refund-race loser could not be made whole. Here each query is
     * capped to CLAIMED_LOG_WINDOW blocks, fromBlock slides forward window-by-window, and a range-too-large / transient
     * rejection SHRINK-and-retries the SAME window (halving to a floor) before the leaf is abandoned. Returns the FIRST S
     * whose sha256 equals `hashLockHex` (the authenticator — a single honest leaf suffices to TRUST it), else null.
     */
    private static readonly CLAIMED_LOG_WINDOW;
    private scanLeafForClaimedSecret;
    /** Best-effort persist of the full record (rehydration source for resume in step 6). Not fund-critical — the
     *  fund-critical write-set is committed atomically inside fundLegX BEFORE the broadcast. */
    private persistRecord;
}

export { type DurableHTLC, type DurableSwapRecord, MnemonicSeedVault, type Outpoint, type RecordPhase, type Scheduler, type SeedVault, type SigningKeyPair, type SwapChainClient, SwapController, type SwapControllerDeps, type SwapControllerEvent, type SwapEventType, type SwapPhase, type SwapSnapshot };
