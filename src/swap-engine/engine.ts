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

import * as secp256k1 from '@noble/secp256k1';
import { sha256 } from '@noble/hashes/sha256';
import { hash160 } from '../address-codec';
import { buildRedeemScript } from './legacy-htlc';
import {
  State, Role,
  isValidTransition, isTerminal,
  ErrVerificationRequired, ErrWrongState, ErrWrongRole,
  ErrNoSecret, ErrHashMismatch,
} from './state';
import { SwapParams, validateParams, swapIDFromHashLock, SwapProposal, SwapResponse } from './params';
import { VerificationGate } from './verify';
import type { UTXOChainClient } from './chains';
import type { SwapStorage, SwapRecord } from './persist';

function toHex(b: Uint8Array): string {
  return Array.from(b).map(v => v.toString(16).padStart(2, '0')).join('');
}

function fromHex(h: string): Uint8Array {
  if (h.length % 2 !== 0) throw new Error('fromHex: odd-length hex string');
  const buf = new Uint8Array(h.length / 2);
  for (let i = 0; i < buf.length; i++) {
    buf[i] = parseInt(h.slice(i * 2, i * 2 + 2), 16);
  }
  return buf;
}

function generateKeyPair(): { privKey: Uint8Array; pubKey: Uint8Array } {
  while (true) {
    const privKey = new Uint8Array(32);
    crypto.getRandomValues(privKey);
    try {
      const pubKey = secp256k1.getPublicKey(privKey, true);
      return { privKey, pubKey };
    } catch {
      // Key out of range (< 1 in 2^128) — retry
    }
  }
}

export type FundFn = () => Promise<string>;

export class Engine {
  // Internal state — accessed directly by tests via (e as any).fieldName
  private state:          State;
  private role:           Role;
  private params:         SwapParams;
  private swapID:         string;
  private ourPrivKey:     Uint8Array;
  private secret:         Uint8Array | null;
  private counterFundTxid: string;
  private ourFundTxid:    string;
  private htlcScriptHash: Uint8Array; // 20 bytes; all-zero until set
  private verified:       boolean;

  private ourChain:   UTXOChainClient | null;
  private storage:    SwapStorage | null;

  constructor(role: Role, params: SwapParams, ourChain?: UTXOChainClient | null, storage?: SwapStorage | null) {
    this.role            = role;
    this.params          = { ...params };
    this.state           = State.Created;
    this.swapID          = '';
    this.ourPrivKey      = new Uint8Array(0);
    this.secret          = null;
    this.counterFundTxid = '';
    this.ourFundTxid     = '';
    this.htlcScriptHash  = new Uint8Array(20);
    this.verified        = false;
    this.ourChain        = ourChain ?? null;
    this.storage         = storage ?? null;
  }

  // ── Getters ───────────────────────────────────────────────────────────────

  getState():       State  { return this.state; }
  getRole():        Role   { return this.role; }
  getSwapID():      string { return this.swapID; }
  getOurFundTxid(): string { return this.ourFundTxid; }

  getHashLock(): Uint8Array {
    return this.params.hashLock.slice();
  }

  getOurPubKey(): Uint8Array {
    return this.params.ourPubKey.slice();
  }

  getHTLCScriptHash(): Uint8Array {
    return this.htlcScriptHash.slice();
  }

  /**
   * Returns the private key. Throws ErrNoSecret if Prepare has not been called.
   * Caller receives a copy — the engine's copy is retained.
   */
  getPrivKey(): Uint8Array {
    if (this.ourPrivKey.length === 0) throw new ErrNoSecret('swapengine: getPrivKey: prepare not called');
    return this.ourPrivKey.slice();
  }

  /**
   * Returns the revealed preimage. Throws ErrNoSecret if not yet known.
   */
  getSecret(): Uint8Array {
    if (!this.secret) throw new ErrNoSecret('swapengine: secret not available');
    return this.secret.slice();
  }

  // ── Setters ───────────────────────────────────────────────────────────────

  setStorage(s: SwapStorage | null): void  { this.storage = s; }
  setOurChain(c: UTXOChainClient | null): void { this.ourChain = c; }

  setCounterPubKey(pub: Uint8Array): void {
    this.params = { ...this.params, counterPubKey: pub };
  }

  // ── Core lifecycle ────────────────────────────────────────────────────────

  /**
   * Transitions Created → Prepared.
   * Generates an ephemeral secp256k1 key pair and (for initiator) a random
   * hashLock. Persists the new state.
   *
   * Returns a SwapProposal (initiator) or SwapResponse (responder) for the
   * peer. Caller is responsible for transmitting it.
   */
  async prepare(): Promise<SwapProposal | SwapResponse> {
    this.transition(State.Prepared);

    // Only generate a keypair if OurPubKey is not already set.
    // Mirrors Go: if len(e.params.OurPubKey) == 0 { generate } else { use existing }
    if (this.params.ourPubKey.length === 0) {
      const { privKey, pubKey } = generateKeyPair();
      this.ourPrivKey = privKey;
      this.params = { ...this.params, ourPubKey: pubKey };
    }

    if (this.role === Role.Initiator) {
      // Generate random preimage and derive hashLock = SHA256(secret)
      const secret = new Uint8Array(32);
      crypto.getRandomValues(secret);
      this.secret          = secret;
      const hashLock       = sha256(secret);
      this.params          = { ...this.params, hashLock };
      this.swapID          = swapIDFromHashLock(hashLock);

      await this.persist();

      return {
        swapID:             this.swapID,
        hashLock:           toHex(hashLock),
        initiatorPubKey:    toHex(this.params.ourPubKey),
        initiatorCSV:       this.params.ourCSVNSequence,
        initiatorAmountSat: this.params.ourAmountSat,
        responderAmountSat: this.params.counterAmountSat,
        minConfirmations:   this.params.minConfirmations,
        feeSatoshis:        this.params.feeSatoshis,
      } satisfies SwapProposal;
    } else {
      // Responder: swapID and hashLock come from the proposal (already in params)
      this.swapID = swapIDFromHashLock(this.params.hashLock);

      await this.persist();

      return {
        swapID:          this.swapID,
        responderPubKey: toHex(this.params.ourPubKey),
        responderCSV:    this.params.ourCSVNSequence,
      } satisfies SwapResponse;
    }
  }

  /**
   * Records that the counterparty has funded their HTLC.
   * Transitions Prepared → CounterpartyFunded (initiator) or
   *             Funded   → CounterpartyFunded (responder).
   */
  async notifyCounterpartyFunded(counterFundTxid: string): Promise<void> {
    if (
      (this.role === Role.Initiator && this.state !== State.Prepared) ||
      (this.role === Role.Responder && this.state !== State.Funded)
    ) {
      throw new ErrWrongState(
        `swapengine: notifyCounterpartyFunded called in state ${State[this.state]}`,
      );
    }
    this.counterFundTxid = counterFundTxid;
    this.transition(State.CounterpartyFunded);
    await this.persist();
  }

  /**
   * Runs the verification gate against the counterparty's HTLC.
   * Transitions CounterpartyFunded → Verified.
   *
   * This is the unskippable gate before Fund().
   * Passing here is the only way to reach StateVerified.
   */
  async verify(counterChain: UTXOChainClient): Promise<void> {
    if (this.state !== State.CounterpartyFunded) {
      throw new ErrWrongState(
        `swapengine: verify requires StateCounterpartyFunded, have ${State[this.state]}`,
      );
    }
    if (this.counterFundTxid === '') {
      throw new ErrWrongState('swapengine: verify: counterFundTxid not set');
    }

    const gate = new VerificationGate(
      this.params,
      this.role,
      this.counterFundTxid,
      counterChain,
    );
    await gate.run(); // throws on any check failure

    this.verified = true;
    this.transition(State.Verified);
    await this.persist();
  }

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
  async fund(htlcScriptHash: Uint8Array, fundFn: FundFn): Promise<void> {
    if (this.role === Role.Initiator) {
      // FUND-CRITICAL: initiator must be in StateVerified. No other path reaches it.
      if (this.state !== State.Verified) {
        throw new ErrVerificationRequired(
          `swapengine: fund: initiator must pass verification gate first (state=${State[this.state]})`,
        );
      }
    } else {
      if (this.state !== State.Prepared) {
        throw new ErrWrongState(
          `swapengine: fund: responder must be in StatePrepared (state=${State[this.state]})`,
        );
      }
    }

    // Write-ahead: persist htlcScriptHash so that if we crash after broadcast
    // but before the final persist, recovery finds the hash to probe with.
    this.htlcScriptHash = htlcScriptHash;
    await this.persist();

    // Double-fund probe (SEP-3)
    if (this.ourChain) {
      let existingTxid: string;
      try {
        existingTxid = await this.ourChain.scanForHTLC(htlcScriptHash, this.params.ourAmountSat);
      } catch (err) {
        // Probe error → block funding; safe to re-try later
        return Promise.reject(err);
      }

      if (existingTxid !== '') {
        // HTLC already exists on-chain (crash-before-persist case)
        await this.recordFunded(existingTxid);
        return;
      }
    }

    // Broadcast the funding tx exactly once
    const txid = await fundFn();
    await this.recordFunded(txid);
  }

  /**
   * Records a confirmed funding txid without re-broadcasting.
   * Idempotent: safe to call when the HTLC already exists on-chain.
   */
  async recordFunded(txid: string): Promise<void> {
    this.ourFundTxid = txid;
    this.transition(State.Funded);
    await this.persist();
  }

  /**
   * Records the revealed preimage (responder learns it when initiator claims).
   * Validates SHA256(secret) == hashLock.
   * Responder transitions Verified → Revealed.
   */
  async setRevealedSecret(secret: Uint8Array): Promise<void> {
    if (this.role !== Role.Responder) {
      throw new ErrWrongRole('swapengine: setRevealedSecret is only valid for the responder role');
    }
    const h = sha256(secret);
    const hl = this.params.hashLock;
    if (h.length !== hl.length || !h.every((b, i) => b === hl[i])) {
      throw new ErrHashMismatch();
    }
    this.secret = secret;
    this.transition(State.Revealed);
    await this.persist();
  }

  /** Marks the swap as Complete. */
  async claim(): Promise<void> {
    this.transition(State.Complete);
    await this.persist();
  }

  /** Initiator: claims the responder's HTLC using the preimage. */
  async claimAsInitiator(): Promise<Uint8Array> {
    if (this.role !== Role.Initiator) {
      throw new ErrWrongRole('swapengine: claimAsInitiator is only valid for the initiator role');
    }
    if (!this.secret) throw new ErrNoSecret();
    await this.claim();
    return this.secret.slice();
  }

  /** Records that the counterparty's HTLC has timed out. */
  async timeout(): Promise<void> {
    this.transition(State.TimedOut);
    await this.persist();
  }

  /** Initiates the refund sequence. */
  async refund(): Promise<void> {
    this.transition(State.Refunding);
    await this.persist();
  }

  /** Confirms the refund transaction was mined. */
  async confirmRefund(): Promise<void> {
    this.transition(State.Refunded);
    await this.persist();
  }

  /**
   * Moves to StateFailed. No-op if already in a terminal state (mirrors Go
   * `Fail` which is a no-op on terminal states rather than returning an error).
   */
  async fail(): Promise<void> {
    if (isTerminal(this.state)) return;
    this.transition(State.Failed);
    await this.persist();
  }

  // ── Internal helpers ───────────────────────────────────────────────────────

  /**
   * Enforces the validTransitions table.
   * Throws ErrWrongState if the transition is not allowed.
   */
  private transition(to: State): void {
    if (!isValidTransition(this.role, this.state, to)) {
      throw new ErrWrongState(
        `swapengine: invalid transition ${State[this.state]} → ${State[to]} for role ${Role[this.role]}`,
      );
    }
    this.state = to;
  }

  /**
   * Saves the current engine state to storage.
   * No-op when storage is null.
   */
  private async persist(): Promise<void> {
    if (!this.storage) return;
    const rec: SwapRecord = {
      swapID:              this.swapID,
      role:                this.role,
      state:               this.state,
      hashLock:            toHex(this.params.hashLock),
      ourPrivKey:          toHex(this.ourPrivKey),
      ourPubKey:           toHex(this.params.ourPubKey),
      counterPubKey:       toHex(this.params.counterPubKey),
      ourCSVNSequence:     this.params.ourCSVNSequence,
      counterCSVNSequence: this.params.counterCSVNSequence,
      ourAmountSat:        this.params.ourAmountSat,
      counterAmountSat:    this.params.counterAmountSat,
      minConfirmations:    this.params.minConfirmations,
      feeSatoshis:         this.params.feeSatoshis,
      ourFundTxid:         this.ourFundTxid,
      counterFundTxid:     this.counterFundTxid,
      secret:              this.secret ? toHex(this.secret) : '',
      htlcScriptHash:      toHex(this.htlcScriptHash),
    };
    this.storage.save(this.swapID !== '' ? this.swapID : '_pending', rec);
  }

  // ── Record reconstruction (used by newFromRecord in recover.ts) ───────────

  static fromRecord(rec: SwapRecord, chain: UTXOChainClient | null, storage: SwapStorage | null): Engine {
    const hashLock = fromHex(rec.hashLock);
    const params: SwapParams = {
      hashLock,
      ourPubKey:           fromHex(rec.ourPubKey),
      counterPubKey:       rec.counterPubKey ? fromHex(rec.counterPubKey) : new Uint8Array(0),
      ourCSVNSequence:     rec.ourCSVNSequence,
      counterCSVNSequence: rec.counterCSVNSequence,
      ourAmountSat:        rec.ourAmountSat,
      counterAmountSat:    rec.counterAmountSat,
      minConfirmations:    rec.minConfirmations,
      feeSatoshis:         rec.feeSatoshis,
    };
    const e = new Engine(rec.role, params, chain, storage);
    e.state           = rec.state;
    e.swapID          = rec.swapID;
    e.ourPrivKey      = fromHex(rec.ourPrivKey);
    e.ourFundTxid     = rec.ourFundTxid ?? '';
    e.counterFundTxid = rec.counterFundTxid ?? '';
    e.htlcScriptHash  = rec.htlcScriptHash ? fromHex(rec.htlcScriptHash) : new Uint8Array(20);
    e.secret          = rec.secret ? fromHex(rec.secret) : null;
    e.verified        = rec.state >= State.Verified;
    return e;
  }
}
