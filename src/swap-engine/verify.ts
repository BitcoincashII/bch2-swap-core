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

import { hash160 } from '../address-codec';
import { buildRedeemScript } from './legacy-htlc';
import { SwapParams, validateTimelockOrdering } from './params';
import { Role } from './state';
import {
  ErrOutputNotFound,
  ErrInsufficientConfirmations,
  ErrAmountTooLow,
} from './state';
import type { UTXOChainClient } from './chains';

export class VerificationGate {
  constructor(
    private readonly params:           SwapParams,
    private readonly role:             Role,
    private readonly counterFundTxid:  string,
    private readonly counterChain:     UTXOChainClient,
  ) {}

  /**
   * Runs all five checks in order:
   *   1. Timelock ordering
   *   2. Build expected P2SH hash from agreed params (H-derived, not counterparty-supplied)
   *   3. Query chain for the output — throws ErrOutputNotFound if absent or wrong structure
   *   4. Confirmation depth — throws ErrInsufficientConfirmations
   *   5. Amount — throws ErrAmountTooLow
   */
  async run(): Promise<void> {
    // 1. Timelock ordering (initiator CSV must be < responder CSV)
    validateTimelockOrdering(this.params, this.role);

    // 2. H-derived expected script hash — uses OUR agreed hashLock, not a counterparty address
    const redeemScript = buildRedeemScript(
      this.params.ourPubKey,
      this.params.counterPubKey,
      this.params.counterCSVNSequence,
      this.params.hashLock,
    );
    const expectedHash = hash160(redeemScript);

    // 3. Query the chain — throws ErrOutputNotFound on any structural mismatch
    const { satoshis, confs } = await this.counterChain.getP2SHOutput(
      this.counterFundTxid,
      expectedHash,
    );

    // 4. Confirmation depth
    const minConfs = this.params.minConfirmations;
    if (confs < minConfs) {
      throw new ErrInsufficientConfirmations(
        `swapengine: counterparty HTLC has ${confs} confirmations, need ${minConfs}`,
      );
    }

    // 5. Amount
    if (satoshis < this.params.counterAmountSat) {
      throw new ErrAmountTooLow(
        `swapengine: counterparty HTLC has ${satoshis} sat, expected >= ${this.params.counterAmountSat}`,
      );
    }
  }
}
