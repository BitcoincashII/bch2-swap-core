/**
 * Swap engine state machine: enums, valid transitions, and error types.
 *
 * Direct port of swapengine/state.go.
 */
declare enum State {
    Created = 0,
    Prepared = 1,
    Funded = 2,
    CounterpartyFunded = 3,
    Verified = 4,
    Revealed = 5,
    Complete = 6,
    TimedOut = 7,
    Refunding = 8,
    Refunded = 9,
    Failed = 10
}
declare enum Role {
    Initiator = 0,
    Responder = 1
}
declare function stateToString(s: State): string;
declare function roleToString(r: Role): string;
declare function isTerminal(s: State): boolean;
declare class ErrVerificationRequired extends Error {
    constructor(msg?: string);
}
declare class ErrWrongState extends Error {
    constructor(msg?: string);
}
declare class ErrWrongRole extends Error {
    constructor(msg?: string);
}
declare class ErrNoSecret extends Error {
    constructor(msg?: string);
}
declare class ErrHashMismatch extends Error {
    constructor(msg?: string);
}
declare class ErrOutputNotFound extends Error {
    constructor(msg?: string);
}
declare class ErrTimelockOrdering extends Error {
    constructor(msg?: string);
}
declare class ErrInsufficientConfirmations extends Error {
    constructor(msg?: string);
}
declare class ErrAmountTooLow extends Error {
    constructor(msg?: string);
}
/**
 * Valid state transitions indexed by [role][fromState] → []toState.
 * transition() enforces this table; no path allows skipping Verified.
 */
declare const validTransitions: Record<Role, Partial<Record<State, State[]>>>;
/** Returns true if the transition from→to is valid for the given role. */
declare function isValidTransition(role: Role, from: State, to: State): boolean;

/**
 * Swap parameters, proposal/response types, and SwapID derivation.
 *
 * Direct port of swapengine/params.go.
 */

interface SwapParams {
    hashLock: Uint8Array;
    ourPubKey: Uint8Array;
    counterPubKey: Uint8Array;
    ourCSVNSequence: number;
    counterCSVNSequence: number;
    ourAmountSat: number;
    counterAmountSat: number;
    minConfirmations: number;
    feeSatoshis: number;
}
/** Wire types exchanged during swap handshake. */
interface SwapProposal {
    swapID: string;
    hashLock: string;
    initiatorPubKey: string;
    initiatorCSV: number;
    initiatorAmountSat: number;
    responderAmountSat: number;
    minConfirmations: number;
    feeSatoshis: number;
}
interface SwapResponse {
    swapID: string;
    responderPubKey: string;
    responderCSV: number;
}
/**
 * Validates SwapParams; enforces timelockOrdering for the initiator role
 * (initiator CSV must be strictly less than responder CSV so the initiator
 * times out first, preventing the responder from claiming after refund).
 *
 * requireCounterPubKey = false is used in Prepare() before the key exchange.
 */
declare function validateParams(p: SwapParams, role: Role, requireCounterPubKey?: boolean): void;
/**
 * Validates timelock ordering without the counterPubKey requirement.
 * Used by the gate (verify.ts) where params may be partially filled.
 */
declare function validateTimelockOrdering(p: SwapParams, role: Role): void;
/** SwapID = hex(sha256(hashLock)[:16]) — 32 hex chars, 128-bit uniqueness. */
declare function swapIDFromHashLock(hashLock: Uint8Array): string;

export { ErrAmountTooLow as E, Role as R, State as S, ErrHashMismatch as a, ErrInsufficientConfirmations as b, ErrNoSecret as c, ErrOutputNotFound as d, ErrTimelockOrdering as e, ErrVerificationRequired as f, ErrWrongRole as g, ErrWrongState as h, type SwapParams as i, type SwapProposal as j, type SwapResponse as k, isTerminal as l, isValidTransition as m, swapIDFromHashLock as n, validateParams as o, validateTimelockOrdering as p, roleToString as r, stateToString as s, validTransitions as v };
