/**
 * Swap parameters, proposal/response types, and SwapID derivation.
 *
 * Direct port of swapengine/params.go.
 */

import { sha256 } from '@noble/hashes/sha256';
import { Role, ErrTimelockOrdering } from './state';

export interface SwapParams {
  hashLock:             Uint8Array; // 32 bytes
  ourPubKey:            Uint8Array; // 33 bytes compressed; empty = generate in Prepare
  counterPubKey:        Uint8Array; // 33 bytes compressed
  ourCSVNSequence:      number;
  counterCSVNSequence:  number;
  ourAmountSat:         number;
  counterAmountSat:     number;
  minConfirmations:     number;
  feeSatoshis:          number;
}

/** Wire types exchanged during swap handshake. */
export interface SwapProposal {
  swapID:              string;       // 32 hex chars
  hashLock:            string;       // 64 hex chars
  initiatorPubKey:     string;       // 66 hex chars
  initiatorCSV:        number;
  initiatorAmountSat:  number;
  responderAmountSat:  number;
  minConfirmations:    number;
  feeSatoshis:         number;
}

export interface SwapResponse {
  swapID:          string;
  responderPubKey: string;         // 66 hex chars
  responderCSV:    number;
}

/**
 * Validates SwapParams; enforces timelockOrdering for the initiator role
 * (initiator CSV must be strictly less than responder CSV so the initiator
 * times out first, preventing the responder from claiming after refund).
 *
 * requireCounterPubKey = false is used in Prepare() before the key exchange.
 */
export function validateParams(
  p: SwapParams,
  role: Role,
  requireCounterPubKey = true,
): void {
  if (requireCounterPubKey && p.counterPubKey.length === 0) {
    throw new Error('swapengine: counterPubKey is required');
  }
  if (role === Role.Initiator) {
    if (p.ourCSVNSequence >= p.counterCSVNSequence) {
      throw new ErrTimelockOrdering(
        `swapengine: timelock ordering violated: initiator nSequence ` +
        `${p.ourCSVNSequence} must be < responder nSequence ${p.counterCSVNSequence}`,
      );
    }
  }
}

/**
 * Validates timelock ordering without the counterPubKey requirement.
 * Used by the gate (verify.ts) where params may be partially filled.
 */
export function validateTimelockOrdering(p: SwapParams, role: Role): void {
  validateParams(p, role, false);
}

/** SwapID = hex(sha256(hashLock)[:16]) — 32 hex chars, 128-bit uniqueness. */
export function swapIDFromHashLock(hashLock: Uint8Array): string {
  const h = sha256(hashLock);
  return Array.from(h.slice(0, 16))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}
