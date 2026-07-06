/**
 * Recovery logic: reconstruct an Engine from a persisted record and determine
 * what action to resume.
 *
 * Direct port of swapengine/recover.go.
 */

import { State, Role, isTerminal } from './state';
import type { SwapRecord, SwapStorage } from './persist';
import type { UTXOChainClient } from './chains';
import type { Engine } from './engine';

/**
 * What the caller should do after reconstructing an engine from a record.
 * Mirrors Go's RecoveryAction enum.
 */
export enum RecoveryAction {
  None                    = 0,
  WaitForCounterparty     = 1,
  VerifyAndFund           = 2,
  ClaimOrTimeout          = 3,
  Refund                  = 4,
  ConfirmRefund           = 5,
}

/**
 * Reconstruct an Engine from a persisted SwapRecord.
 * The engine is wired to the provided chain client.
 *
 * Must be called AFTER imports to avoid circular dependency (engine.ts imports
 * recover.ts; recover.ts imports Engine only as a type reference here, and the
 * actual Engine class is passed as a factory to avoid the cycle).
 */
export function newFromRecord(
  rec: SwapRecord,
  chain: UTXOChainClient,
  storage: SwapStorage,
  engineFactory: (rec: SwapRecord, chain: UTXOChainClient, storage: SwapStorage) => Engine,
): Engine {
  return engineFactory(rec, chain, storage);
}

/**
 * Returns the recovery action appropriate for the engine's current state + role.
 * Mirrors Go's determineRecoveryAction.
 */
export function determineRecoveryAction(role: Role, state: State): RecoveryAction {
  if (isTerminal(state)) return RecoveryAction.None;

  if (role === Role.Initiator) {
    switch (state) {
      case State.Created:
      case State.Prepared:            return RecoveryAction.WaitForCounterparty;
      case State.CounterpartyFunded:  return RecoveryAction.VerifyAndFund;
      case State.Verified:            return RecoveryAction.VerifyAndFund;
      case State.Funded:              return RecoveryAction.ClaimOrTimeout;
      case State.TimedOut:
      case State.Refunding:           return RecoveryAction.Refund;
      default:                        return RecoveryAction.None;
    }
  } else {
    switch (state) {
      case State.Created:
      case State.Prepared:            return RecoveryAction.WaitForCounterparty;
      case State.Funded:              return RecoveryAction.WaitForCounterparty;
      case State.CounterpartyFunded:  return RecoveryAction.VerifyAndFund;
      case State.Verified:            return RecoveryAction.ClaimOrTimeout;
      case State.Revealed:            return RecoveryAction.ClaimOrTimeout;
      case State.TimedOut:
      case State.Refunding:           return RecoveryAction.Refund;
      default:                        return RecoveryAction.None;
    }
  }
}

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
export async function recoverAndResume(
  storage: SwapStorage,
  chainFactory: (role: Role, swapID: string) => UTXOChainClient | null,
  resumeFn: (e: Engine, action: RecoveryAction) => Promise<void>,
  engineFactory: (rec: SwapRecord, chain: UTXOChainClient, storage: SwapStorage) => Engine,
): Promise<Error[]> {
  const records = storage.loadAll();
  const errors: Error[] = [];

  for (const rec of records) {
    if (isTerminal(rec.state)) continue;

    const chain = chainFactory(rec.role, rec.swapID);
    if (!chain) continue;

    const engine = engineFactory(rec, chain, storage);
    const action = determineRecoveryAction(rec.role, rec.state);

    try {
      await resumeFn(engine, action);
    } catch (err) {
      errors.push(err instanceof Error ? err : new Error(String(err)));
    }
  }

  return errors;
}
