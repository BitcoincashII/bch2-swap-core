import { i as SwapParams, R as Role, S as State, j as SwapProposal, k as SwapResponse } from '../params-B0_XTQP-.js';
export { E as ErrAmountTooLow, a as ErrHashMismatch, b as ErrInsufficientConfirmations, c as ErrNoSecret, d as ErrOutputNotFound, e as ErrTimelockOrdering, f as ErrVerificationRequired, g as ErrWrongRole, h as ErrWrongState, l as isTerminal, m as isValidTransition, r as roleToString, s as stateToString, n as swapIDFromHashLock, v as validTransitions, o as validateParams, p as validateTimelockOrdering } from '../params-B0_XTQP-.js';

/**
 * UTXO chain client interface and in-memory mock for tests.
 *
 * Direct port of swapengine/chains.go.
 */
/**
 * Abstract interface over a UTXO chain (BCH2, BCH, BTC, BC2).
 * Production implementations query Electrum or a block explorer.
 */
interface UTXOChainClient {
    /**
     * Returns the satoshi amount and confirmation count for a specific P2SH
     * output in the given transaction.
     * Throws ErrOutputNotFound if the output does not exist.
     */
    getP2SHOutput(txid: string, scriptHash: Uint8Array): Promise<{
        satoshis: number;
        confs: number;
    }>;
    /**
     * Scans the chain/mempool for a UTXO paying exactly expectedSat to the given
     * P2SH script hash. Returns the funding txid when found, '' when not found,
     * throws on error.
     *
     * expectedSat is required so the probe matches THIS swap's HTLC and not a
     * different concurrent swap that happens to use the same P2SH script.
     */
    scanForHTLC(scriptHash: Uint8Array, expectedSat: number): Promise<string>;
}
/**
 * In-memory mock UTXO chain for testing.
 * Port of MockUTXOChain in swapengine/chains.go.
 */
declare class MockUTXOChain implements UTXOChainClient {
    private outputs;
    private scanError;
    /** Add a P2SH output keyed by txid + script hash. */
    addOutput(txid: string, scriptHash: Uint8Array, satoshis: number, confs: number): void;
    /** Update the confirmation count on an existing output. */
    setConfirmations(txid: string, scriptHash: Uint8Array, confs: number): void;
    /** Force scanForHTLC to return an error (simulates a probe failure). */
    setScanError(err: Error | null): void;
    getP2SHOutput(txid: string, scriptHash: Uint8Array): Promise<{
        satoshis: number;
        confs: number;
    }>;
    scanForHTLC(scriptHash: Uint8Array, expectedSat: number): Promise<string>;
}

/**
 * Verification gate — checks the counterparty HTLC before we commit funds.
 *
 * Direct port of swapengine/verify.go.
 *
 * H-derived-address robustness: the gate derives the expected P2SH hash from
 * the agreed swap parameters (including hashLock from the proposal, NOT a
 * counterparty-supplied address). A counterparty that constructs an HTLC with
 * the wrong hashLock will produce a structurally different script hash that
 * won't be found by getP2SHOutput, triggering ErrOutputNotFound.
 */

declare class VerificationGate {
    private readonly params;
    private readonly role;
    private readonly counterFundTxid;
    private readonly counterChain;
    constructor(params: SwapParams, role: Role, counterFundTxid: string, counterChain: UTXOChainClient);
    /**
     * Runs all five checks in order:
     *   1. Timelock ordering
     *   2. Build expected P2SH hash from agreed params (H-derived, not counterparty-supplied)
     *   3. Query chain for the output — throws ErrOutputNotFound if absent or wrong structure
     *   4. Confirmation depth — throws ErrInsufficientConfirmations
     *   5. Amount — throws ErrAmountTooLow
     */
    run(): Promise<void>;
}

/**
 * Swap record persistence.
 *
 * Port of swapengine/persist.go. localStorage replaces the atomic file-per-swap
 * pattern (tmp→rename). localStorage.setItem is synchronous and either
 * completes atomically or throws — it does NOT partially write. However, a
 * process crash can interrupt JS execution before setItem is called, leaving
 * the record at a prior state. This is the same behaviour as Go's atomic
 * rename: a crash before the rename leaves the old file. The recovery path
 * (recover.ts) handles this by resuming from the last persisted state.
 *
 * loadSwapRecords skips any entry that fails JSON.parse or is missing required
 * fields — same as Go's "skip corrupt files silently" behaviour.
 *
 * ATOMICITY NOTE: unlike Go's rename(2), localStorage does not provide POSIX
 * durability guarantees. In practice, browsers journal localStorage writes, but
 * callers should not rely on durability across hard resets. For production use,
 * IndexedDB with explicit transactions would offer stronger guarantees.
 */

/** JSON-serialisable snapshot of engine state — mirrors Go's SwapRecord struct. */
interface SwapRecord {
    swapID: string;
    role: Role;
    state: State;
    hashLock: string;
    ourPrivKey: string;
    ourPubKey: string;
    counterPubKey: string;
    ourCSVNSequence: number;
    counterCSVNSequence: number;
    ourAmountSat: number;
    counterAmountSat: number;
    minConfirmations: number;
    feeSatoshis: number;
    ourFundTxid: string;
    counterFundTxid: string;
    secret: string;
    htlcScriptHash: string;
}
/** Storage abstraction — injectable for tests (MemorySwapStorage) vs production (LocalSwapStorage). */
interface SwapStorage {
    save(swapID: string, record: SwapRecord): void;
    load(swapID: string): SwapRecord | null;
    loadAll(): SwapRecord[];
    delete(swapID: string): void;
}
/** Production implementation — uses localStorage. */
declare class LocalSwapStorage implements SwapStorage {
    private readonly prefix;
    save(swapID: string, record: SwapRecord): void;
    load(swapID: string): SwapRecord | null;
    loadAll(): SwapRecord[];
    delete(swapID: string): void;
}
/** In-memory implementation for tests — mirrors Go TempDir pattern. */
declare class MemorySwapStorage implements SwapStorage {
    private store;
    save(swapID: string, record: SwapRecord): void;
    load(swapID: string): SwapRecord | null;
    loadAll(): SwapRecord[];
    delete(swapID: string): void;
    /** Expose underlying map size for test assertions. */
    size(): number;
}
/**
 * Returns all valid records from storage, silently skipping corrupt or
 * incomplete entries (mirrors Go's LoadSwapRecords corrupt-file skipping).
 */
declare function loadSwapRecords(storage: SwapStorage): SwapRecord[];
/** Removes the persisted record for swapID. */
declare function deleteSwapRecord(storage: SwapStorage, swapID: string): void;

/**
 * Swap engine — orchestrates the state machine, verification gate, and HTLC
 * construction callbacks for one atomic swap leg.
 *
 * Direct port of swapengine/engine.go.
 *
 * Key differences from Go:
 *   - No sync.Mutex: TS is single-threaded; async calls are interleaved only
 *     at await points, and the state machine forbids concurrent transitions.
 *   - No context.Context: async methods do not accept a cancellation context;
 *     use AbortSignal at the HTLC-builder layer if needed.
 *   - Ephemeral key generation uses crypto.getRandomValues instead of btcec.
 *   - Persistence uses an injected SwapStorage instead of a filesystem dir.
 */

type FundFn = () => Promise<string>;
declare class Engine {
    private state;
    private role;
    private params;
    private swapID;
    private ourPrivKey;
    private secret;
    private counterFundTxid;
    private ourFundTxid;
    private htlcScriptHash;
    private verified;
    private ourChain;
    private storage;
    constructor(role: Role, params: SwapParams, ourChain?: UTXOChainClient | null, storage?: SwapStorage | null);
    getState(): State;
    getRole(): Role;
    getSwapID(): string;
    getOurFundTxid(): string;
    getHashLock(): Uint8Array;
    getOurPubKey(): Uint8Array;
    getHTLCScriptHash(): Uint8Array;
    /**
     * Returns the private key. Throws ErrNoSecret if Prepare has not been called.
     * Caller receives a copy — the engine's copy is retained.
     */
    getPrivKey(): Uint8Array;
    /**
     * Returns the revealed preimage. Throws ErrNoSecret if not yet known.
     */
    getSecret(): Uint8Array;
    setStorage(s: SwapStorage | null): void;
    setOurChain(c: UTXOChainClient | null): void;
    setCounterPubKey(pub: Uint8Array): void;
    /**
     * Transitions Created → Prepared.
     * Generates an ephemeral secp256k1 key pair and (for initiator) a random
     * hashLock. Persists the new state.
     *
     * Returns a SwapProposal (initiator) or SwapResponse (responder) for the
     * peer. Caller is responsible for transmitting it.
     */
    prepare(): Promise<SwapProposal | SwapResponse>;
    /**
     * Records that the counterparty has funded their HTLC.
     * Transitions Prepared → CounterpartyFunded (initiator) or
     *             Funded   → CounterpartyFunded (responder).
     */
    notifyCounterpartyFunded(counterFundTxid: string): Promise<void>;
    /**
     * Runs the verification gate against the counterparty's HTLC.
     * Transitions CounterpartyFunded → Verified.
     *
     * This is the unskippable gate before Fund().
     * Passing here is the only way to reach StateVerified.
     */
    verify(counterChain: UTXOChainClient): Promise<void>;
    /**
     * Funds our own HTLC.
     *
     * Initiator: requires StateVerified (gate is unskippable — no direct path from
     *            StateCounterpartyFunded or earlier).
     * Responder: requires StatePrepared.
     *
     * Double-fund probe (SEP-3): if ourChain is set, scanForHTLC is called first:
     *   - probe error   → return error; do NOT broadcast (safe = blocked)
     *   - HTLC found    → call recordFunded (idempotent); do NOT re-broadcast
     *   - HTLC absent   → call fundFn once, then transition to StateFunded
     *
     * scanForHTLC is passed ourAmountSat so the probe matches THIS swap's UTXO
     * and ignores any concurrent swap that shares the same P2SH script.
     *
     * @param htlcScriptHash 20-byte hash of our HTLC's redeemScript.
     * @param fundFn         Async callback that broadcasts the funding tx and
     *                       returns the txid.
     */
    fund(htlcScriptHash: Uint8Array, fundFn: FundFn): Promise<void>;
    /**
     * Records a confirmed funding txid without re-broadcasting.
     * Idempotent: safe to call when the HTLC already exists on-chain.
     */
    recordFunded(txid: string): Promise<void>;
    /**
     * Records the revealed preimage (responder learns it when initiator claims).
     * Validates SHA256(secret) == hashLock.
     * Responder transitions Verified → Revealed.
     */
    setRevealedSecret(secret: Uint8Array): Promise<void>;
    /** Marks the swap as Complete. */
    claim(): Promise<void>;
    /** Initiator: claims the responder's HTLC using the preimage. */
    claimAsInitiator(): Promise<Uint8Array>;
    /** Records that the counterparty's HTLC has timed out. */
    timeout(): Promise<void>;
    /** Initiates the refund sequence. */
    refund(): Promise<void>;
    /** Confirms the refund transaction was mined. */
    confirmRefund(): Promise<void>;
    /**
     * Moves to StateFailed. No-op if already in a terminal state (mirrors Go
     * `Fail` which is a no-op on terminal states rather than returning an error).
     */
    fail(): Promise<void>;
    /**
     * Enforces the validTransitions table.
     * Throws ErrWrongState if the transition is not allowed.
     */
    private transition;
    /**
     * Saves the current engine state to storage.
     * No-op when storage is null.
     */
    private persist;
    static fromRecord(rec: SwapRecord, chain: UTXOChainClient | null, storage: SwapStorage | null): Engine;
}

/**
 * Recovery logic: reconstruct an Engine from a persisted record and determine
 * what action to resume.
 *
 * Direct port of swapengine/recover.go.
 */

/**
 * What the caller should do after reconstructing an engine from a record.
 * Mirrors Go's RecoveryAction enum.
 */
declare enum RecoveryAction {
    None = 0,
    WaitForCounterparty = 1,
    VerifyAndFund = 2,
    ClaimOrTimeout = 3,
    Refund = 4,
    ConfirmRefund = 5
}
/**
 * Reconstruct an Engine from a persisted SwapRecord.
 * The engine is wired to the provided chain client.
 *
 * Must be called AFTER imports to avoid circular dependency (engine.ts imports
 * recover.ts; recover.ts imports Engine only as a type reference here, and the
 * actual Engine class is passed as a factory to avoid the cycle).
 */
declare function newFromRecord(rec: SwapRecord, chain: UTXOChainClient, storage: SwapStorage, engineFactory: (rec: SwapRecord, chain: UTXOChainClient, storage: SwapStorage) => Engine): Engine;
/**
 * Returns the recovery action appropriate for the engine's current state + role.
 * Mirrors Go's determineRecoveryAction.
 */
declare function determineRecoveryAction(role: Role, state: State): RecoveryAction;
/**
 * Loads all valid swap records from storage, reconstructs engines, and calls
 * resumeFn for each non-terminal swap. Terminal swaps are skipped.
 *
 * Mirrors Go's RecoverAndResume.
 *
 * @param storage      Persisted swap storage.
 * @param chainFactory Returns the appropriate chain client for a given swap, or
 *                     null to skip (useful when a chain is unavailable at startup).
 * @param resumeFn     Called with the reconstructed engine and suggested action.
 * @param engineFactory Injected to avoid circular import in engine.ts.
 * @returns Array of errors collected from resumeFn calls; does not throw.
 */
declare function recoverAndResume(storage: SwapStorage, chainFactory: (role: Role, swapID: string) => UTXOChainClient | null, resumeFn: (e: Engine, action: RecoveryAction) => Promise<void>, engineFactory: (rec: SwapRecord, chain: UTXOChainClient, storage: SwapStorage) => Engine): Promise<Error[]>;

export { Engine, type FundFn, LocalSwapStorage, MemorySwapStorage, MockUTXOChain, RecoveryAction, Role, State, SwapParams, SwapProposal, type SwapRecord, SwapResponse, type SwapStorage, type UTXOChainClient, VerificationGate, deleteSwapRecord, determineRecoveryAction, loadSwapRecords, newFromRecord, recoverAndResume };
