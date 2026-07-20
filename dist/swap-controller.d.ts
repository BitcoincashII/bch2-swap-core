import { S as SwapOffer, C as Chain } from './swap-types-CbNzOsAe.js';
import { GateChainClient } from './gates.js';
import { DurableStore, SessionStore, Mutex } from './storage.js';
import { UtxoReservationRegistry } from './utxo-reservation.js';
import './chain-client.js';
import 'ethers';

interface SwapChainClient extends GateChainClient {
    /** Broadcast a signed raw tx; resolves the node's ack txid, THROWS on a node reject (so a fund failure aborts). */
    broadcastTx(rawTx: string): Promise<string>;
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
    counterpartyEvmSwapId?: string;
    counterpartyEvmTimeLock?: number;
    myFundingTxid?: string;
    fundLocktime?: number;
    respLocktime?: number;
    claimTx?: {
        txid: string;
        rawTx: string;
        spent?: Outpoint;
    };
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
    evmProviderFor?: (chain: Chain) => unknown;
    evmSignerFor?: (chain: Chain) => unknown;
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
    disposed: boolean;
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
    /** leg X amount in sats (offer.sendAmount is base-unit sats < 2^53 for a UTXO leg). Fail closed on garbage. */
    private legXAmountSats;
    /** A minimal SwapState for createInitiatorHTLC (it reads only offer.sendChain + secretHash). */
    private buildSwapState;
    /**
     * Greedy FIFO UTXO selection — ported from prepareFundingTx (~5431-5457): oldest-confirmed-first (immature
     * coinbase is newest, so it is spent last), tie-break by value desc, accumulate until amount + estimated fee is
     * covered, then decide the change-output count AFTER fee. Returns the selected inputs or null (insufficient).
     * Uses the chain's static config fee rate (a LIVE deadline-scaled rate is a separate seam; step 4 keeps it simple).
     */
    private greedySelect;
    /** Read + validate the durable funded-HTLC side-channel (R170) for the adopt path. */
    private readDurableFundedHtlc;
    /** Best-effort persist of the full record (rehydration source for resume in step 6). Not fund-critical — the
     *  fund-critical write-set is committed atomically inside fundLegX BEFORE the broadcast. */
    private persistRecord;
}

export { type DurableHTLC, type DurableSwapRecord, MnemonicSeedVault, type Outpoint, type RecordPhase, type Scheduler, type SeedVault, type SigningKeyPair, type SwapChainClient, SwapController, type SwapControllerDeps, type SwapControllerEvent, type SwapEventType, type SwapPhase, type SwapSnapshot };
