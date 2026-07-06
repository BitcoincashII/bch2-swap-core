/**
 * Swap engine state machine: enums, valid transitions, and error types.
 *
 * Direct port of swapengine/state.go.
 */

export enum State {
  Created             = 0,
  Prepared            = 1,
  Funded              = 2,
  CounterpartyFunded  = 3,
  Verified            = 4,
  Revealed            = 5,
  Complete            = 6,
  TimedOut            = 7,
  Refunding           = 8,
  Refunded            = 9,
  Failed              = 10,
}

export enum Role {
  Initiator = 0,
  Responder = 1,
}

export function stateToString(s: State): string {
  return State[s] ?? `State(${s})`;
}

export function roleToString(r: Role): string {
  return Role[r] ?? `Role(${r})`;
}

export function isTerminal(s: State): boolean {
  return s === State.Complete || s === State.Refunded || s === State.Failed;
}

// Mirrors Go error sentinels (port uses subclasses so instanceof works like errors.Is).

export class ErrVerificationRequired extends Error {
  constructor(msg?: string) {
    super(msg ?? 'swapengine: verification gate must pass before this action');
    this.name = 'ErrVerificationRequired';
  }
}

export class ErrWrongState extends Error {
  constructor(msg?: string) {
    super(msg ?? 'swapengine: action not valid in current state');
    this.name = 'ErrWrongState';
  }
}

export class ErrWrongRole extends Error {
  constructor(msg?: string) {
    super(msg ?? 'swapengine: action not valid for this role');
    this.name = 'ErrWrongRole';
  }
}

export class ErrNoSecret extends Error {
  constructor(msg?: string) {
    super(msg ?? 'swapengine: secret not available');
    this.name = 'ErrNoSecret';
  }
}

export class ErrHashMismatch extends Error {
  constructor(msg?: string) {
    super(msg ?? 'swapengine: SHA256(secret) does not match agreed hashLock');
    this.name = 'ErrHashMismatch';
  }
}

export class ErrOutputNotFound extends Error {
  constructor(msg?: string) {
    super(msg ?? 'swapengine: P2SH output not found');
    this.name = 'ErrOutputNotFound';
  }
}

export class ErrTimelockOrdering extends Error {
  constructor(msg?: string) {
    super(msg ?? 'swapengine: timelock ordering violated: initiator CSV must be < responder CSV');
    this.name = 'ErrTimelockOrdering';
  }
}

export class ErrInsufficientConfirmations extends Error {
  constructor(msg?: string) {
    super(msg ?? 'swapengine: counterparty HTLC has insufficient confirmations');
    this.name = 'ErrInsufficientConfirmations';
  }
}

export class ErrAmountTooLow extends Error {
  constructor(msg?: string) {
    super(msg ?? 'swapengine: counterparty HTLC amount is below agreed minimum');
    this.name = 'ErrAmountTooLow';
  }
}

/**
 * Valid state transitions indexed by [role][fromState] → []toState.
 * transition() enforces this table; no path allows skipping Verified.
 */
export const validTransitions: Record<Role, Partial<Record<State, State[]>>> = {
  [Role.Initiator]: {
    [State.Created]:            [State.Prepared, State.Failed],
    [State.Prepared]:           [State.CounterpartyFunded, State.Failed],
    [State.CounterpartyFunded]: [State.Verified, State.Failed],
    [State.Verified]:           [State.Funded, State.Failed],
    [State.Funded]:             [State.Complete, State.TimedOut, State.Failed],
    [State.TimedOut]:           [State.Refunding, State.Failed],
    [State.Refunding]:          [State.Refunded, State.Failed],
  },
  [Role.Responder]: {
    [State.Created]:            [State.Prepared, State.Failed],
    [State.Prepared]:           [State.Funded, State.Failed],
    [State.Funded]:             [State.CounterpartyFunded, State.TimedOut, State.Failed],
    [State.CounterpartyFunded]: [State.Verified, State.Failed],
    [State.Verified]:           [State.Revealed, State.Failed],
    [State.Revealed]:           [State.Complete, State.Failed],
    [State.TimedOut]:           [State.Refunding, State.Failed],
    [State.Refunding]:          [State.Refunded, State.Failed],
  },
};

/** Returns true if the transition from→to is valid for the given role. */
export function isValidTransition(role: Role, from: State, to: State): boolean {
  const allowed = validTransitions[role][from];
  return allowed !== undefined && allowed.includes(to);
}
