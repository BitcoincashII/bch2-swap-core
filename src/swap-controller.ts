// swap-controller.ts — the headless, framework-agnostic SwapController (P1b step 4).
//
// Extracts the PROVEN orchestration + irreversible-action gate-sequencing out of the React component
// bch2-swap/src/components/SwapExecute.tsx into a transport-injected state machine, so a bot / wallet / pool
// structurally cannot run a swap unsafely. This file ships the SKELETON + `prepare()` + `fundLegX()` (the
// initiator funding its OWN UTXO leg X). Steps 5-7 extend it (verifyCounterpartyLeg* -> proofs, fundLegY,
// revealAndClaim, watchForSecret, claimWithKnownSecret, refund, resume, EVM parity).
//
// Fund-safety corrections baked in here (from the P1b adversarial critique — see docs/P1B-SWAPCONTROLLER-DESIGN.md §5):
//   fix #3 (single-flight fails CLOSED): the ENTIRE select+reserve+build+commit+broadcast for a fund runs inside
//     `mutex.withLock('bch2swap:fund:'+id)`; a durable `funded` sentinel is re-checked INSIDE the lock and a second
//     broadcast is refused (adopt the prior txid instead).
//   fix #4 (durable-before-broadcast is truly atomic): the durable write-set {funded, fundlocktime, fundrecipient,
//     fundedhtlc} is committed via `durable.commit([...])` (all-or-nothing, throws on partial, read-back-verified)
//     BEFORE the irreversible broadcast; a commit throw ABORTS the broadcast (funds never move without a record).
//   fix #5 (refuse a non-re-derivable secret): prepare()/fundLegX throw unless the offer is `hmac-v1` (S is
//     re-derivable from the seed) OR an encrypted-at-rest durable S is present — never fund a secret a crash strands.
//
// Grounded in SwapExecute.tsx: the K_ss cache + recoverSecret gate (~2650-2677); buildHTLC's H1-LOCKTIME-PROXY-001
// verifyFundingHeight (~5100-5111); prepareFundingTx's withUtxoLock candidateUtxos/reserveInputs greedy FIFO
// selection (~5432-5457) + fundHTLC (~5512); handleBroadcastFunding's withCrossTabLock single-flight + the durable
// fund keys (~5785-5826). The one intentional divergence from the app is fix #4: the app writes the durable fund
// keys AFTER broadcast; the SDK writes them BEFORE (durable-before-broadcast).

import type { Chain, SwapOffer, SwapState } from './swap-types';
import type { GateChainClient, GateUtxo } from './gates';

// The controller's chain transport: the read-only GATE surface (SPV-verified) PLUS the broadcast WRITE method the
// fund/claim/refund paths need. Kept a superset of GateChainClient so gates.ts stays a pure read contract; the app's
// ElectrumProxyClient and the SDK test harness's MockElectrumClient both satisfy it verbatim (no adapter).
export interface SwapChainClient extends GateChainClient {
  /** Broadcast a signed raw tx; resolves the node's ack txid, THROWS on a node reject (so a fund failure aborts). */
  broadcastTx(rawTx: string): Promise<string>;
  /** blockchain.scripthash.get_history — the spend/confirm history the responder's secret-watcher scans (leg Y).
   *  Matches ElectrumProxyClient.getHistory verbatim so the app client + the test mock satisfy it with no adapter. */
  getHistory(scripthash: string, scriptHex?: string, timeoutMs?: number): Promise<Array<{ tx_hash: string; height: number }>>;
}
import type { DurableStore, SessionStore, Mutex } from './storage';
import { UtxoReservationRegistry, type ResUtxo } from './utxo-reservation';
import { deriveSwapKss, swapSecretFromKss, SWAP_SECRET_SCHEME, SWAP_NONCE_BYTES } from './seed-secret';
import {
  createInitiatorHTLC, createResponderHTLC, fundHTLC, claimHTLC, extractSecret,
  verifyAndAuthenticateP2pkhInput, verifyAndAuthenticateUtxo, getHTLCScripthash,
} from './swap-flow';
import { hexToBytes, bytesToHex, hash160, sha256, maxPlausibleBlockHeight, buildHTLCRefundTx, createHTLC } from './htlc-builder';
import { p2pkhScripthash } from './address-codec';
import { chainConfigs, isSwapPairSuspended } from './chain-config';
import { spvSupported, verifyFundingHeight, verifyConfirmations } from './spv-verifier';
import { assertLegBuriedForFunding, assertRevealSafe, type FundProof, type RevealAuthorization } from './gates';
import type { HTLCDetails, HTLCParams, Utxo } from './swap-types';

// ============================================================================
// Phase enum + durable record (design §3)
// ============================================================================

/** The controller's fund-safety phase enum (design §1/§3). */
export type SwapPhase =
  | 'prepared'
  | 'initiator_funded'
  | 'responder_funded'
  | 'claimed'
  | 'completed'
  | 'refunded'
  | 'failed';

/**
 * A record's phase also carries the pre-prepare ENTRY state `taken` (the swap has been taken but keys/secret
 * are not yet derived), so the `taken -> prepared` and `taken|prepared -> initiator_funded` transitions are
 * representable while `SwapPhase` stays exactly the 7 post-prepare states.
 */
export type RecordPhase = 'taken' | SwapPhase;

/** A durably-serializable HTLC (hex-encoded byte fields) — the exact FUNDED HTLC (R170 fundedhtlc side-channel). */
export interface DurableHTLC {
  redeemScript: string;    // hex
  p2shAddress: string;
  secretHash: string;      // hex (32 bytes)
  recipientPkh: string;    // hex (20 bytes) — who may claim this leg with the secret
  refundPkh: string;       // hex (20 bytes) — who may refund this leg after the locktime
  locktime: number;        // absolute block height (UTXO) or unix-seconds CLTV (R167 EVM-anchored)
}

/** The counterparty funding outpoint a cached claim tx spends (design §3 — `.spent` is load-bearing later). */
export interface Outpoint { tx_hash: string; tx_pos: number; }

/**
 * One durable record per swap id. Written ATOMICALLY inside the broadcast mutex BEFORE any irreversible
 * broadcast returns (durable-before-broadcast). Fields not needed until steps 5-7 are optional and left for
 * those steps to populate; the ones below cover the skeleton + prepare + fundLegX (step 4).
 */
export interface DurableSwapRecord {
  id: string;
  role: 'initiator' | 'responder';
  /** The offer, carrying `secretScheme` + `secretNonce` so S is re-derivable (never plaintext-stored). */
  offer: SwapOffer;
  phase: RecordPhase;

  /** The pkh that may CLAIM leg X with the secret (the counterparty's receive pkh on myChain). Needed to build
   *  the initiator HTLC in fundLegX; the host populates it from the taker's acceptance. */
  counterpartyClaimPkh?: string; // hex (20 bytes)

  /** THIS side's funded HTLC (set once fundLegX builds + broadcasts). */
  myHTLC?: DurableHTLC;

  // ── counterparty leg (steps 5-7 populate these) ──────────────────────────────────────────────────────
  counterpartyHTLC?: DurableHTLC;
  /** The counterparty's funding OUTPOINT the host recorded when it observed the counterparty HTLC confirm — the
   *  exact output the fund/reveal gates re-verify + bind their proof to (design §3). UTXO topologies only. */
  counterpartyFundingOutpoint?: Outpoint;
  counterpartyEvmSwapId?: string;
  counterpartyEvmTimeLock?: number; // R167 trusted EVM-leg expiry (absolute unix seconds)

  // ── funding / timelock durable singletons ────────────────────────────────────────────────────────────
  myFundingTxid?: string;
  fundLocktime?: number; // the only durable copy of a height CLTV (R237)
  respLocktime?: number; // R167 EVM-timestamp CLTV

  // ── irreversible-tx caches (steps 5-6 populate these) ────────────────────────────────────────────────
  claimTx?: { txid: string; rawTx: string; spent?: Outpoint };
  myClaimTxid?: string; // the broadcast (or adopted) claim txid, once revealAndClaim / claimWithKnownSecret settles
  refundTx?: { txid: string; rawTx: string };

  // ── durable sentinels ────────────────────────────────────────────────────────────────────────────────
  funded?: boolean;
}

// ============================================================================
// SeedVault capability — derives on demand, never exposes the raw seed
// ============================================================================

/** A signing key pair for a UTXO leg (private + compressed public key). The caller owns the buffers. */
export interface SigningKeyPair {
  readonly privateKey: Uint8Array;
  readonly publicKey: Uint8Array;
}

/**
 * The seed capability the controller is injected with. It wraps a mnemonic the HOST holds and DERIVES ON
 * DEMAND — the raw seed is never globalized/returned/put on the wire (fix: MetaMask is NOT on the path). Back
 * it with the SDK's seed-secret.ts (deriveSwapKss/swapSecretFromKss) + a per-chain HD signing derivation.
 */
export interface SeedVault {
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
export class MnemonicSeedVault implements SeedVault {
  private mnemonic: string | null;
  private readonly signer: (chain: Chain, mnemonic: string, hdPath?: string) => Promise<SigningKeyPair>;

  constructor(mnemonic: string, signer: (chain: Chain, mnemonic: string, hdPath?: string) => Promise<SigningKeyPair>) {
    this.mnemonic = mnemonic;
    this.signer = signer;
  }

  async signingKey(chain: Chain, hdPath?: string): Promise<SigningKeyPair> {
    if (this.mnemonic === null) throw new Error('SeedVault disposed — no key material available');
    return this.signer(chain, this.mnemonic, hdPath);
  }

  async swapKss(): Promise<Uint8Array | null> {
    if (this.mnemonic === null) return null;
    return deriveSwapKss(this.mnemonic);
  }

  dispose(): void {
    // Best-effort: overwrite the string reference (JS strings are immutable, so this only drops the reference —
    // the host is responsible for not retaining copies; the real zeroization guarantee is on the derived buffers).
    this.mnemonic = null;
  }
}

// ============================================================================
// Injected dependencies (design §2)
// ============================================================================

/** Scheduler seam (design §2) — steps a machine via `tick()`. Unused in step 4; optional. */
export interface Scheduler {
  /** Run `fn` after `delayMs`; returns a cancel handle. */
  schedule(fn: () => void, delayMs: number): () => void;
}

export interface SwapControllerDeps {
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
  // EVM funding is step 7 — these factories may be stubbed / omitted until then.
  evmProviderFor?: (chain: Chain) => unknown;
  evmSignerFor?: (chain: Chain) => unknown;
}

// ============================================================================
// Structured events (NO i18n / UI strings — machine-readable only)
// ============================================================================

export type SwapControllerEvent =
  | { type: 'phase'; phase: RecordPhase }
  | { type: 'status'; message: string }
  | { type: 'error'; error: Error };

export type SwapEventType = SwapControllerEvent['type'];

/** An immutable view of the controller for the host to render an affordance. */
export interface SwapSnapshot {
  id: string;
  role: 'initiator' | 'responder';
  phase: RecordPhase;
  myChain: Chain;
  theirChain: Chain;
  myFundingTxid?: string;
  fundLocktime?: number;
  myHTLC?: DurableHTLC;
  disposed: boolean;
  /** True iff an in-memory re-derivable 32-byte secret is currently loaded. */
  hasSecret: boolean;
  /** Set by resume(): the myHTLC on-chain authentication disposition (fix #10 — only 'ok' authorizes irreversibility). */
  resumeAuth?: 'ok' | 'mismatch' | 'indeterminate' | 'skip';
  /** Set by resume(): which gate the swap re-entered, computed from CHAIN truth (isResumableSwapState), not status. */
  resumeGate?: string;
}

// ============================================================================
// Durable key names — byte-identical to the app's localStorage keys so a browser adapter interops.
// ============================================================================

const fundedKey = (id: string): string => `bch2swap:funded:${id}`;
const fundLocktimeKey = (id: string): string => `bch2swap:fundlocktime:${id}`;
const fundRecipientKey = (id: string): string => `bch2swap:fundrecipient:${id}`;
const fundedHtlcKey = (id: string): string => `bch2swap:fundedhtlc:${id}`;
/** The signed raw funding tx, committed atomically with the fund keys so a crash BETWEEN commit and broadcast is
 *  recoverable: step-6 resume rebroadcasts THIS exact tx (idempotent — same txid) instead of re-selecting inputs
 *  (which would pick different inputs → a different txid than the durable `funded` sentinel). A signed tx is public
 *  material (it is broadcast anyway) — no secret is persisted. */
const fundedTxKey = (id: string): string => `bch2swap:fundedtx:${id}`;
const recordKey = (id: string): string => `bch2swap:record:${id}`;
/** Optional encrypted-at-rest durable S (fix #5): a non-hmac-v1 offer may only be prepared/funded if this exists. */
const durableSecretKey = (id: string): string => `bch2swap:encsecret:${id}`;
/** The secret-bearing claim tx (design §3 — `.spent` is load-bearing for the pre-reveal double-spend re-check +
 *  the fix #8 outpoint triangulation). It is public material once broadcast (durable-before-broadcast). */
const claimTxKey = (id: string): string => `bch2swap:claimtx:${id}`;
/** The winning-claim sentinel — set atomically WITH the claim tx inside the claim mutex, BEFORE the secret-bearing
 *  broadcast, so a second call (or a crash-resume) ADOPTS the prior claim txid instead of re-revealing. */
const claimBroadcastKey = (id: string): string => `bch2swap:claimbroadcast:${id}`;
/** A refund of our own HTLC is in flight (set by the step-6 refund path). The responder's public-secret claim
 *  refuses to run while this is set so a claim + refund cannot race the same outpoint. */
const refundBroadcastKey = (id: string): string => `bch2swap:refundbroadcast:${id}`;
/** The signed raw refund tx + the funding outpoint it spends (R280-H1 durable-before-broadcast). Committed atomically
 *  WITH the refundbroadcast sentinel BEFORE the broadcast, so a dropped/reorged refund is rebroadcastable and the
 *  reorg-safe finalizer keeps it until >= reqConf. A signed refund carries NO secret — it is public material. */
const refundTxKey = (id: string): string => `bch2swap:refundtx:${id}`;

function durableHtlc(h: HTLCDetails): DurableHTLC {
  return {
    redeemScript: bytesToHex(h.redeemScript),
    p2shAddress: h.p2shAddress,
    secretHash: bytesToHex(h.params.secretHash),
    recipientPkh: bytesToHex(h.params.recipientPubkeyHash),
    refundPkh: bytesToHex(h.params.refundPubkeyHash),
    locktime: h.params.locktime,
  };
}

const HEX20 = /^[0-9a-f]{40}$/;
const HEX64 = /^[0-9a-f]{64}$/;

// ============================================================================
// Ported pure helpers (step 6) — the availability + resume decision logic, brought into the SDK from the app so the
// controller and a future host share ONE implementation. Diff-verified byte-identical to their app originals except
// documented import/type changes (see the report). NONE touch network / storage / state: inputs in, decision out.
// ============================================================================

// isHtlcRefundAvailable — ported VERBATIM from bch2-swap/src/components/SwapExecute.tsx:355 (byte-identical body).
// R167: an HTLC is refundable once its locktime is reached. For a block-height locktime (< 500_000_000), compare the
// chain height; for a TIMESTAMP locktime (the responder's EVM-counterparty UTXO leg, >= 500_000_000), compare
// wall-clock seconds — the proxy-supplied height is IRRELEVANT to a timestamp CLTV, which the chain enforces via
// median-time-past. The on-chain CLTV is the real enforcer; this is only the UI/availability hint.
function isHtlcRefundAvailable(locktime: number, currentHeight: number | null): boolean {
  if (locktime >= 500_000_000) return Math.floor(Date.now() / 1000) >= locktime; // timestamp CLTV (MTP-enforced)
  return currentHeight !== null && currentHeight >= locktime; // block-height CLTV
}

// isResumableSwapState — ported VERBATIM from bch2-swap/src/core/swap-execute-logic.ts:38 (byte-identical body).
// R276: a swap is "resumable" (route through the funded resume branch) iff it has a funding txid or a built HTLC.
function isResumableSwapState(s: { myFundingTxid?: unknown; myHTLC?: unknown } | null | undefined): boolean {
  return !!(s?.myFundingTxid || s?.myHTLC);
}

// validateReconstructionInputs — ported VERBATIM from bch2-swap/src/core/swap-execute-logic.ts:61 (byte-identical
// body). R277: the pure fail-closed input gate at the head of the durable-locktime myHTLC reconstruction — the
// on-chain P2SH authentication downstream is the trust anchor, so this only screens obviously-unusable input.
function validateReconstructionInputs(args: {
  myChainIsEvm: boolean;
  haveMyHtlc: boolean;
  fundingTxid: string | null | undefined;
  locktimeStr: string | null | undefined;
  secretHash: Uint8Array | null | undefined;
}): { ok: boolean; fundingTxid?: string; locktime?: number } {
  const { myChainIsEvm, haveMyHtlc, fundingTxid, locktimeStr, secretHash } = args;
  if (myChainIsEvm) return { ok: false };
  if (haveMyHtlc) return { ok: false };
  if (!fundingTxid || typeof fundingTxid !== 'string' || !/^[0-9a-f]{64}$/.test(fundingTxid)) return { ok: false };
  let lt = NaN;
  try { lt = parseInt(locktimeStr ?? '', 10); } catch { /* ignore */ }
  if (!Number.isInteger(lt) || lt <= 0 || lt >= 2_147_483_648) return { ok: false };
  if (!secretHash || secretHash.length !== 32 || secretHash.every((b) => b === 0)) return { ok: false };
  return { ok: true, fundingTxid, locktime: lt };
}

// ============================================================================
// SwapController
// ============================================================================

export class SwapController {
  private record: DurableSwapRecord;
  private readonly deps: SwapControllerDeps;
  private readonly listeners = new Map<SwapEventType, Set<(e: SwapControllerEvent) => void>>();

  readonly id: string;
  readonly role: 'initiator' | 'responder';
  readonly myChain: Chain;
  readonly theirChain: Chain;

  /** In-memory only. The re-derivable HTLC preimage — NEVER written durably in plaintext (design §3, fix #5). */
  private secret: Uint8Array | null = null;
  private disposed = false;

  /** FIX #10 (resume): set true when resume()'s myHTLC on-chain authentication was NOT a DEFINITIVE 'ok' (a
   *  DEFINITIVE 'mismatch' or a network-blip 'indeterminate'). While set, refund()/revealAndClaim()/
   *  claimWithKnownSecret() refuse any NEW irreversible broadcast — an idempotent ADOPT of an already-broadcast tx is
   *  still allowed (it reveals nothing new). Cleared only by a DEFINITIVE re-authentication to 'ok'. */
  private irreversibleBlocked = false;
  /** resume() diagnostics (snapshot-exposed): the myHTLC auth disposition + the gate re-entered from CHAIN truth. */
  private resumeAuthValue?: 'ok' | 'mismatch' | 'indeterminate' | 'skip';
  private resumeGateValue?: string;

  constructor(record: DurableSwapRecord, deps: SwapControllerDeps) {
    this.record = { ...record };
    this.deps = deps;
    this.id = record.id;
    this.role = record.role;
    // Derive the leg chains from role + offer (initiator funds sendChain; responder funds receiveChain).
    this.myChain = record.role === 'initiator' ? record.offer.sendChain : record.offer.receiveChain;
    this.theirChain = record.role === 'initiator' ? record.offer.receiveChain : record.offer.sendChain;
  }

  // ── events ─────────────────────────────────────────────────────────────────────────────────────────────

  /** Subscribe to a structured event. Returns an unsubscribe fn. */
  on(type: SwapEventType, cb: (e: SwapControllerEvent) => void): () => void {
    let set = this.listeners.get(type);
    if (!set) { set = new Set(); this.listeners.set(type, set); }
    set.add(cb);
    return () => this.off(type, cb);
  }

  off(type: SwapEventType, cb: (e: SwapControllerEvent) => void): void {
    this.listeners.get(type)?.delete(cb);
  }

  private emit(e: SwapControllerEvent): void {
    const set = this.listeners.get(e.type);
    if (!set) return;
    for (const cb of [...set]) {
      try { cb(e); } catch { /* a listener throw must never break the state machine */ }
    }
  }

  private setPhase(phase: RecordPhase): void {
    this.record.phase = phase;
    this.emit({ type: 'phase', phase });
  }

  private status(message: string): void {
    this.emit({ type: 'status', message });
  }

  // ── snapshot / lifecycle ─────────────────────────────────────────────────────────────────────────────────

  getState(): SwapSnapshot {
    return Object.freeze({
      id: this.id,
      role: this.role,
      phase: this.record.phase,
      myChain: this.myChain,
      theirChain: this.theirChain,
      myFundingTxid: this.record.myFundingTxid,
      fundLocktime: this.record.fundLocktime,
      myHTLC: this.record.myHTLC ? Object.freeze({ ...this.record.myHTLC }) : undefined,
      disposed: this.disposed,
      hasSecret: !!(this.secret && this.secret.length === 32),
      resumeAuth: this.resumeAuthValue,
      resumeGate: this.resumeGateValue,
    });
  }

  /** Abort + zeroize the ONLY in-memory secret + tell the vault to zeroize. Idempotent; post-dispose actions throw. */
  dispose(): void {
    if (this.disposed) return;
    this.disposed = true;
    if (this.secret) { this.secret.fill(0); this.secret = null; }
    try { this.deps.seedVault.dispose(); } catch { /* best-effort */ }
    this.listeners.clear();
  }

  private assertLive(): void {
    if (this.disposed) throw new Error('SwapController disposed — no further actions permitted');
  }

  // ── prepare() ──────────────────────────────────────────────────────────────────────────────────────────

  /**
   * Derive per-swap keys, RECOVER S, and authenticate it against the offer's secretHash — fail-closed. Grounds in
   * SwapExecute.tsx recoverSecret (~2663-2677): for an `hmac-v1` offer as the initiator, S = swapSecretFromKss(
   * K_ss, nonce), and sha256(S) MUST equal offer.secretHash. FIX #5: refuse unless the scheme is `hmac-v1` (S is
   * re-derivable from the seed on any device) OR an encrypted-at-rest durable S exists — never advance a swap whose
   * secret a crash would strand. Also refuses a suspended pair. Transitions `taken -> prepared`.
   */
  async prepare(): Promise<void> {
    this.assertLive();
    const rec = this.record;
    if (rec.phase !== 'taken' && rec.phase !== 'prepared') {
      throw new Error(`prepare: unexpected phase '${rec.phase}' — prepare runs from 'taken' (or re-runs from 'prepared')`);
    }
    // Refuse a suspended pair BEFORE deriving anything (mirrors prepareFundingTx's isSwapPairSuspended gate).
    if (isSwapPairSuspended(this.myChain, this.theirChain)) {
      throw new Error(`prepare: swap pair ${this.myChain}/${this.theirChain} is suspended — refusing to prepare`);
    }

    const secretHashHex = (rec.offer.secretHash ?? '').toLowerCase().replace(/^0x/, '');
    if (!HEX64.test(secretHashHex)) {
      throw new Error('prepare: offer.secretHash is missing / not a 32-byte hex hash — cannot authenticate the secret');
    }

    // FIX #5 (fail closed): the secret must be RE-DERIVABLE. Either the offer is hmac-v1 (derive from the seed) or
    // an encrypted-at-rest durable S is present. A non-hmac-v1 offer with no durable S is refused before any derive.
    const isHmacV1 = rec.offer.secretScheme === SWAP_SECRET_SCHEME;
    const durableSecretHex = await this.deps.durable.get(durableSecretKey(rec.id));
    if (!isHmacV1 && !durableSecretHex) {
      throw new Error(
        `prepare: offer secretScheme '${rec.offer.secretScheme ?? 'none'}' is not '${SWAP_SECRET_SCHEME}' and no ` +
        `encrypted-at-rest durable secret is present — refusing to prepare a swap whose secret a crash would strand (fix #5)`,
      );
    }

    // Recover S. INITIATOR path: S = swapSecretFromKss(K_ss, nonce). (The responder learns S on-chain; a durable-S
    // offer supplies it directly. Both funnel through the same sha256(S) === secretHash authentication below.)
    const S = await this.recoverSecret(secretHashHex, isHmacV1, durableSecretHex);
    if (!S || S.length !== 32) {
      throw new Error('prepare: could not derive/recover the 32-byte swap secret (vault locked, bad nonce, or absent durable S)');
    }
    if (bytesToHex(sha256(S)) !== secretHashHex) {
      S.fill(0);
      throw new Error('prepare: recovered secret does not hash to offer.secretHash (tampered nonce / wrong scheme) — fail closed');
    }

    if (this.secret) this.secret.fill(0);
    this.secret = S;
    this.setPhase('prepared');
    this.status('prepare:ok');
    await this.persistRecord();
  }

  /**
   * The INITIATOR's re-derivable secret for the reveal path (mirrors buildClaimTx's `state.secret ?? recoverSecret()`
   * ~7204-7207): return the in-memory S if present, else RE-DERIVE it (hmac-v1 from K_ss+nonce, or a durable S) and
   * RE-AUTHENTICATE sha256(S) === offer.secretHash before caching it. Returns null (fail closed) on any miss/mismatch.
   */
  private async loadInitiatorSecret(): Promise<Uint8Array | null> {
    if (this.secret && this.secret.length === 32) return this.secret;
    const secretHashHex = (this.record.offer.secretHash ?? '').toLowerCase().replace(/^0x/, '');
    if (!HEX64.test(secretHashHex)) return null;
    const isHmacV1 = this.record.offer.secretScheme === SWAP_SECRET_SCHEME;
    const durableSecretHex = await this.deps.durable.get(durableSecretKey(this.record.id));
    const S = await this.recoverSecret(secretHashHex, isHmacV1, durableSecretHex);
    if (!S || S.length !== 32) return null;
    if (bytesToHex(sha256(S)) !== secretHashHex) { S.fill(0); return null; } // fail closed on a tampered nonce/scheme
    if (this.secret) this.secret.fill(0);
    this.secret = S;
    return S;
  }

  /** Recover the 32-byte preimage: hmac-v1 -> derive from K_ss + nonce; else -> decode a durable S. Returns null on miss. */
  private async recoverSecret(secretHashHex: string, isHmacV1: boolean, durableSecretHex: string | null): Promise<Uint8Array | null> {
    if (isHmacV1 && this.role === 'initiator') {
      const nonceHex = (this.record.offer.secretNonce ?? '').toLowerCase();
      if (!/^[0-9a-f]{32}$/.test(nonceHex)) return null; // 16-byte nonce
      const kss = await this.deps.seedVault.swapKss();
      if (!kss || kss.length !== 32) return null;
      try {
        const nonce = hexToBytes(nonceHex);
        if (nonce.length !== SWAP_NONCE_BYTES) return null;
        return swapSecretFromKss(kss, nonce);
      } finally {
        kss.fill(0); // the caller (this vault helper) owns + zeroes the returned K_ss buffer
      }
    }
    // Encrypted-at-rest durable S (fix #5 case 2). Step 4 accepts a hex-encoded durable secret whose sha256 the
    // caller re-authenticates below; wiring the key-encryption.ts decrypt is a later step.
    if (durableSecretHex && HEX64.test(durableSecretHex.toLowerCase())) {
      try { return hexToBytes(durableSecretHex.toLowerCase()); } catch { return null; }
    }
    return null;
  }

  // ── fundLegX() — the initiator funds its OWN UTXO leg X ──────────────────────────────────────────────────

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
  async fundLegX(): Promise<{ txid: string }> {
    this.assertLive();
    if (this.record.role !== 'initiator') {
      throw new Error('fundLegX: only the initiator funds leg X (the responder funds leg Y via fundLegY)');
    }
    return this.fundOwnLeg({
      label: 'fundLegX',
      expectRole: 'initiator',
      targetPhase: 'initiator_funded',
      amountSats: this.legXAmountSats(),
      buildHtlc: (state, buildHeight, recipientPkh, refundPkh) =>
        createInitiatorHTLC(state, buildHeight, recipientPkh, refundPkh),
    });
  }

  // ── fundLegY(proof) — the RESPONDER funds its OWN UTXO leg Y ────────────────────────────────────────────────

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
  async fundLegY(proof: FundProof): Promise<{ txid: string }> {
    this.assertLive();
    if (this.record.role !== 'responder') {
      throw new Error('fundLegY: only the responder funds leg Y (the initiator funds leg X via fundLegX)');
    }
    // `proof` is required at the TYPE level (safe-by-default, design §4). Its captured facts may only ever FAIL a
    // funding (staleness), never license skipping the fresh re-mint below (fix #2) — so we intentionally do not read
    // it to authorize anything; a structural discriminant touch keeps the param load-bearing without trusting it.
    if (proof.leg !== 'X' || proof.for !== 'fundY') {
      throw new Error('fundLegY: the supplied FundProof is not a leg-X fund authorization — refusing to fund');
    }
    return this.fundOwnLeg({
      label: 'fundLegY',
      expectRole: 'responder',
      targetPhase: 'responder_funded',
      amountSats: this.legYAmountSats(),
      // Height-based responder CLTV (buildHeight + LOCKTIME_BLOCKS.responder). The EVM-anchored TIMESTAMP CLTV (R167)
      // is a step-7 topology; this UTXO<->UTXO path uses the default height locktime.
      buildHtlc: (state, buildHeight, recipientPkh, refundPkh) =>
        createResponderHTLC(state, buildHeight, recipientPkh, refundPkh),
      // FIX #2: re-mint the counterparty-leg-X burial proof FRESH at the broadcast choke point (throws -> abort).
      preBroadcastReverify: async () => { await this.verifyCounterpartyLegForFunding(); },
    });
  }

  /**
   * Shared own-leg funding machinery for fundLegX (initiator) + fundLegY (responder). Faithfully ports the proven
   * handleBroadcastFunding path — see the fundLegX doc block for the (1)-(5) sequence. The only per-role differences
   * are the HTLC factory, the leg amount, the target phase, and the optional `preBroadcastReverify` (fix #2, leg Y).
   */
  private async fundOwnLeg(opts: {
    label: 'fundLegX' | 'fundLegY';
    expectRole: 'initiator' | 'responder';
    targetPhase: 'initiator_funded' | 'responder_funded';
    amountSats: number;
    buildHtlc: (state: SwapState, buildHeight: number, recipientPkh: Uint8Array, refundPkh: Uint8Array) => HTLCDetails;
    preBroadcastReverify?: () => Promise<void>;
  }): Promise<{ txid: string }> {
    const { label, expectRole, targetPhase, amountSats, buildHtlc, preBroadcastReverify } = opts;
    const rec = this.record;
    if (rec.role !== expectRole) {
      throw new Error(`${label}: wrong role '${rec.role}' — refusing to fund`);
    }
    if (rec.phase !== 'taken' && rec.phase !== 'prepared') {
      throw new Error(`${label}: unexpected phase '${rec.phase}' — fund runs from 'taken' or 'prepared'`);
    }
    if (isSwapPairSuspended(this.myChain, this.theirChain)) {
      throw new Error(`${label}: swap pair ${this.myChain}/${this.theirChain} is suspended — refusing to fund`);
    }
    const cfg = chainConfigs[this.myChain];
    if (!cfg || (cfg as { isEvm?: boolean }).isEvm) {
      throw new Error(`${label}: own leg (${this.myChain}) is not a UTXO chain — EVM funding is step 7`);
    }
    const claimPkhHex = (rec.counterpartyClaimPkh ?? '').toLowerCase().replace(/^0x/, '');
    if (!HEX20.test(claimPkhHex)) {
      throw new Error(`${label}: counterpartyClaimPkh (the counterparty receive pkh on the own leg) is missing — cannot build the HTLC`);
    }

    const client = this.deps.chainClientFor(this.myChain);

    // (1) H1-LOCKTIME-PROXY-001: SPV-verify the build height is a REAL PoW block before it becomes the refund CLTV
    // base. Fail closed on an implausible or unverifiable/inflated height (would strand the coins we are about to fund).
    this.status(`${label}:verifying-height`);
    const [buildHeight] = await client.getBlockHeight();
    if (!Number.isInteger(buildHeight) || buildHeight <= 0 || buildHeight > maxPlausibleBlockHeight()) {
      throw new Error(`${label}: proxy-reported ${this.myChain} height ${buildHeight} is implausible — refusing to set an unrecoverable refund timelock`);
    }
    if (spvSupported(this.myChain)) {
      await verifyFundingHeight(client, this.myChain, buildHeight); // THROWS (fail closed) on an inflated/unverifiable height
    }

    // Signing key (own P2PKH) — the refund pkh is hash160(pubkey).
    const sk = await this.deps.seedVault.signingKey(this.myChain);
    const myPkh = hash160(sk.publicKey);
    const p2pkhScript = new Uint8Array([0x76, 0xa9, 0x14, ...myPkh, 0x88, 0xac]);
    const claimPkh = hexToBytes(claimPkhHex);

    const lockName = `bch2swap:fund:${rec.id}`;
    // (5) single-flight (fix #3): the ENTIRE select+reserve+build+re-mint+commit+broadcast runs under one lock.
    const outcome = await this.deps.mutex.withLock(lockName, async (): Promise<{ txid: string; htlc?: HTLCDetails; adopted: boolean }> => {
      // Re-check the durable `funded` sentinel INSIDE the lock — a peer/tab that already funded means we must NOT
      // broadcast our (divergent) tx; ADOPT its txid instead (mirrors handleBroadcastFunding's prior-key adopt).
      const prior = await this.deps.durable.get(fundedKey(rec.id));
      if (prior && HEX64.test(prior.toLowerCase())) {
        return { txid: prior.toLowerCase(), adopted: true };
      }

      // (2) select + reserve inside the reservation lock (candidateUtxos -> greedy FIFO -> reserveInputs).
      this.status(`${label}:selecting-inputs`);
      const scripthash = p2pkhScripthash(myPkh);
      const chainUtxos = (await client.getUTXOs(scripthash, bytesToHex(p2pkhScript))) as GateUtxo[];
      const now = this.deps.clock();
      const picked = await this.deps.reservation.withUtxoLock<ResUtxo[] | null>(() => {
        this.deps.reservation.releaseSwap(rec.id); // retry-safe: drop this swap's own prior reservation first
        const valid: ResUtxo[] = chainUtxos
          .filter((u) => Number.isFinite(u.value) && u.value > 0)
          .map((u) => ({ tx_hash: u.tx_hash, tx_pos: u.tx_pos, value: u.value, height: u.height }));
        const candidates = this.deps.reservation.candidateUtxos(rec.id, valid, now);
        const sel = this.greedySelect(candidates, amountSats);
        if (!sel) return null;
        this.deps.reservation.reserveInputs(rec.id, sel, now);
        return sel;
      });
      if (!picked || picked.length === 0) {
        this.deps.reservation.releaseSwap(rec.id);
        throw new Error(`${label}: insufficient spendable UTXOs to fund the HTLC`);
      }

      try {
        // R260-INPUT-VALUE-AUTH-001: on LEGACY non-BIP143 chains the sighash does NOT commit the input value, so a
        // lying proxy's inflated listunspent `value` would yield a VALID sig -> too little change -> silent fee burn.
        // Authenticate each selected input against its self-derived raw tx and drive the build from that value.
        let selected: ResUtxo[] = picked;
        if (!(cfg.useBip143 ?? false)) {
          this.status(`${label}:authenticating-inputs`);
          const fetchRawTx = (txid: string) => client.getTx(txid);
          const authed: ResUtxo[] = [];
          for (const u of picked) {
            const a = await verifyAndAuthenticateP2pkhInput(u, myPkh, fetchRawTx);
            authed.push({ ...u, value: a.value });
          }
          const authTotal = authed.reduce((s, x) => s + x.value, 0);
          if (authTotal < amountSats) {
            throw new Error(`${label}: authenticated input total is below the funding amount (possible proxy value inflation) — not signing`);
          }
          selected = authed;
        }

        // (3) build the own-leg HTLC (initiator or responder) + the funding tx. Deterministic, so two concurrent
        // callers produce the SAME txid/locktime — the sentinel re-check keeps it single-broadcast.
        const htlc = buildHtlc(this.buildSwapState(expectRole), buildHeight, claimPkh, myPkh);
        this.status(`${label}:building-tx`);
        const tx = await fundHTLC(htlc, selected, sk.privateKey, sk.publicKey, p2pkhScript, amountSats, this.myChain);
        const totalIn = selected.reduce((s, u) => s + u.value, 0);
        const changeVal = totalIn - amountSats - tx.fee;
        if (changeVal > 0) this.deps.reservation.recordChange(rec.id, { tx_hash: tx.txid, tx_pos: 1, value: changeVal, height: 0 }, now);

        const canonical = tx.txid.toLowerCase();

        // FIX #2 (leg Y): re-mint the counterparty-leg-X burial proof from a FRESH read at the broadcast choke point.
        // A throw ABORTS before the durable commit + broadcast — the responder never commits funds against a leg X
        // that reorged / double-spent / drifted below the margin since the passed proof was minted.
        if (preBroadcastReverify) {
          this.status(`${label}:reverifying-counterparty`);
          await preBroadcastReverify();
        }

        // (4) durable-before-broadcast (fix #4): ATOMIC write-set, read-back-verified, THROWS on partial. If it
        // throws we ABORT here — the broadcast below never runs, so funds never move without a durable record.
        this.status(`${label}:committing`);
        await this.deps.durable.commit([
          [fundedKey(rec.id), canonical],
          [fundLocktimeKey(rec.id), String(htlc.params.locktime)],
          [fundRecipientKey(rec.id), bytesToHex(claimPkh)],
          [fundedHtlcKey(rec.id), JSON.stringify(durableHtlc(htlc))],
          [fundedTxKey(rec.id), tx.rawTx],
        ]);

        // (5) broadcast — only AFTER the durable write-set has landed.
        this.status(`${label}:broadcasting`);
        await client.broadcastTx(tx.rawTx);
        return { txid: canonical, htlc, adopted: false };
      } catch (e) {
        // Build / re-mint / commit / broadcast failed: release the reserved inputs so a retry can reselect (the
        // durable sentinel, if the commit succeeded, keeps a later call from double-broadcasting the same tx).
        this.deps.reservation.releaseSwap(rec.id);
        throw e;
      }
    });

    // Write myFundingTxid AFTER the broadcast. On the adopt path, rehydrate myHTLC/fundLocktime from the durable
    // funded-HTLC record so refund/watch target the ACTUALLY-funded address, not a divergent freshly-built one.
    let fundedHtlc = outcome.htlc ? durableHtlc(outcome.htlc) : undefined;
    let fundLocktime = outcome.htlc ? outcome.htlc.params.locktime : undefined;
    if (outcome.adopted) {
      const hydrated = await this.readDurableFundedHtlc(rec.id);
      if (hydrated) { fundedHtlc = hydrated; fundLocktime = hydrated.locktime; }
    }
    this.record = {
      ...this.record,
      myFundingTxid: outcome.txid,
      myHTLC: fundedHtlc ?? this.record.myHTLC,
      fundLocktime: fundLocktime ?? this.record.fundLocktime,
      funded: true,
    };
    this.setPhase(targetPhase);
    this.status(`${label}:funded`);
    await this.persistRecord();
    return { txid: outcome.txid };
  }

  // ── counterparty-leg proof minters (the ONLY controller-side minters) ──────────────────────────────────────

  /**
   * RESPONDER-ONLY. Mint a `FundProof` by SPV-verifying the counterparty (initiator) leg X is buried at the required
   * depth + the responder timelock margin is safe (gates.assertLegBuriedForFunding over leg X). Returns the branded
   * proof or THROWS a GateFailure (mints nothing) on any failure/uncertainty — fail closed, no funds move. This is
   * the only way to obtain the `FundProof` that fundLegY requires (design §4).
   */
  async verifyCounterpartyLegForFunding(): Promise<FundProof> {
    this.assertLive();
    if (this.record.role !== 'responder') {
      throw new Error('verifyCounterpartyLegForFunding: responder-only (the initiator does not fund against a FundProof)');
    }
    const { redeemScript, locktime, outpoint } = this.counterpartyLeg('verifyCounterpartyLegForFunding');
    const client = this.deps.chainClientFor(this.theirChain); // leg X lives on theirChain (the initiator's sendChain)
    const myChainIsEvm = !!(chainConfigs[this.myChain] as { isEvm?: boolean } | undefined)?.isEvm;
    return assertLegBuriedForFunding(client, {
      theirChain: this.theirChain,
      myChain: this.myChain,
      myChainIsEvm,
      counterpartyRedeemScript: redeemScript,
      recordedOutpoint: outpoint,
      counterpartyLocktime: locktime,
    });
  }

  /**
   * INITIATOR-ONLY. Mint a `RevealAuthorization` by SPV-verifying the counterparty (responder) leg Y is buried +
   * the 4h claim-margin runway on leg Y holds (gates.assertRevealSafe with role:'initiator' over leg Y). Returns the
   * branded authorization or THROWS a GateFailure (mints nothing) — the secret NEVER leaks on any failure. This is
   * the only way to obtain the `RevealAuthorization` that revealAndClaim requires (design §4).
   */
  async verifyCounterpartyLegForReveal(): Promise<RevealAuthorization> {
    this.assertLive();
    if (this.record.role !== 'initiator') {
      throw new Error('verifyCounterpartyLegForReveal: initiator-only (only the initiator makes the irreversible secret reveal)');
    }
    const { redeemScript, locktime, outpoint } = this.counterpartyLeg('verifyCounterpartyLegForReveal');
    const client = this.deps.chainClientFor(this.theirChain); // leg Y lives on theirChain (the responder's receiveChain)
    return assertRevealSafe(client, {
      role: 'initiator',
      theirChain: this.theirChain,
      counterpartyRedeemScript: redeemScript,
      recordedOutpoint: outpoint,
      counterpartyLocktime: locktime,
    });
  }

  // ── revealAndClaim(auth) — the INITIATOR's single irreversible secret reveal (claim of leg Y) ────────────────

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
  async revealAndClaim(auth: RevealAuthorization): Promise<{ txid: string }> {
    this.assertLive();
    const rec = this.record;
    if (rec.role !== 'initiator') {
      throw new Error('revealAndClaim: only the initiator reveals the secret (the responder uses claimWithKnownSecret)');
    }
    // FIX #3: a responder-role authorization (which SKIPS the 4h claim margin — already-public secret) must never
    // authorize the initiator's irreversible reveal. Fail closed BEFORE touching the secret or the chain.
    if (auth.role !== 'initiator' || auth.leg !== 'Y' || auth.for !== 'reveal') {
      throw new Error('revealAndClaim: the supplied authorization is not an initiator leg-Y reveal authorization — refusing to reveal the secret (fix #3)');
    }
    // Step-5 deferred idempotent-adopt: a post-confirmation / crash-resume re-call returns the PRIOR claim txid rather
    // than rebuilding (the counterparty leg-Y UTXO is now SPENT, so a rebuild would throw). It reveals nothing new, so
    // it is allowed even under the fix #10 auth block. This precedes the phase check so a 'claimed'/'completed' re-call
    // adopts instead of throwing on an unexpected phase.
    const adopted = await this.priorClaimTxid(rec.id);
    if (adopted) { this.record = { ...this.record, myClaimTxid: adopted } as DurableSwapRecord; this.status('revealAndClaim:adopted'); return { txid: adopted }; }
    // FIX #10: a resume whose myHTLC authentication was not DEFINITIVE 'ok' must NOT authorize an irreversible reveal.
    this.assertIrreversibleAllowed('revealAndClaim');
    // R181 claim<->refund cross-guard: never reveal the secret while a refund of the shared HTLC is in flight.
    if (await this.deps.durable.get(refundBroadcastKey(rec.id))) {
      throw new Error('revealAndClaim: a refund is already in flight — refusing to reveal the secret while a refund is active (R181 cross-guard)');
    }
    if (rec.phase !== 'responder_funded' && rec.phase !== 'claimed') {
      throw new Error(`revealAndClaim: unexpected phase '${rec.phase}' — reveal runs from 'responder_funded'`);
    }
    // Suspension gates ONLY new swaps (prepare/fund) — a fully-funded swap MUST always be able to SETTLE. Blocking
    // the claim of a suspended pair would strand a funded swap (mirrors the app claim path, which has no such gate).
    const cfg = chainConfigs[this.theirChain];
    if (!cfg || (cfg as { isEvm?: boolean }).isEvm) {
      throw new Error('revealAndClaim: leg Y is not a UTXO chain — EVM reveal is step 7');
    }
    if (!auth.outpoint) {
      throw new Error('revealAndClaim: the reveal authorization carries no outpoint — cannot bind the claim (fix #8)');
    }
    const secret = await this.loadInitiatorSecret();
    if (!secret || secret.length !== 32) {
      throw new Error('revealAndClaim: the swap secret is not available (vault locked / not re-derivable) — cannot reveal');
    }
    const { redeemScript, locktime } = this.counterpartyLeg('revealAndClaim');
    const client = this.deps.chainClientFor(this.theirChain);

    // R-REVEAL-FAILCLOSE (~7980): a cached claim tx LACKING `.spent` would skip the outpoint triangulation + SPV
    // re-verify below and reveal the secret against an unverifiable outpoint. Discard it + rebuild (fail closed).
    const cachedRaw = await this.deps.durable.get(claimTxKey(rec.id));
    if (cachedRaw) {
      let cached: { txid?: string; rawTx?: string; spent?: Outpoint } | null = null;
      try { cached = JSON.parse(cachedRaw) as { txid?: string; rawTx?: string; spent?: Outpoint }; } catch { cached = null; }
      if (cached && (!cached.spent || !this.isOutpoint(cached.spent))) {
        await this.deps.durable.remove(claimTxKey(rec.id)); // discard the spent-less cache; a rebuild regenerates it
        throw new Error('revealAndClaim: cached claim tx lacks a `.spent` outpoint — discarding + failing closed before revealing the secret (R-REVEAL-FAILCLOSE)');
      }
    }

    // Build the secret-bearing claim FRESH, preferring the exact authorized outpoint. It carries `.spent`.
    this.status('revealAndClaim:building-claim');
    const claimTx = await this.buildSecretClaim(this.theirChain, redeemScript, secret, auth.outpoint);

    // FIX #8 (triangulation, part 1 — equality): the claim MUST spend exactly the outpoint the authorization is
    // bound to. A divergence (a reorg re-mined the funding at a new outpoint between verify + reveal) fails closed.
    if (!claimTx.spent || !this.isOutpoint(claimTx.spent)) {
      throw new Error('revealAndClaim: built claim has no spent outpoint — failing closed before revealing the secret (fix #8)');
    }
    if (claimTx.spent.tx_hash !== auth.outpoint.tx_hash || claimTx.spent.tx_pos !== auth.outpoint.tx_pos) {
      await this.deps.durable.remove(claimTxKey(rec.id));
      throw new Error('revealAndClaim: built claim spends a different outpoint than the authorization is bound to (possible reorg) — discarding + rebuilding, not revealing the secret (fix #8)');
    }

    const lockName = `bch2swap:claim:${rec.id}`;
    const finalTxid = await this.deps.mutex.withLock(lockName, async (): Promise<string> => {
      // Single-flight adopt: a sibling call / crash-resume that already committed+broadcast the claim set the
      // sentinel WITH the durable claim tx — ADOPT its txid rather than re-revealing the (already-public) secret.
      const sentinel = await this.deps.durable.get(claimBroadcastKey(rec.id));
      if (sentinel) {
        const priorRaw = await this.deps.durable.get(claimTxKey(rec.id));
        if (priorRaw) {
          try {
            const prior = JSON.parse(priorRaw) as { txid?: string };
            if (prior?.txid && HEX64.test(prior.txid.toLowerCase())) return prior.txid.toLowerCase();
          } catch { /* fall through to a fresh, gated broadcast */ }
        }
      }

      // R181 cross-guard re-check INSIDE the lock: a refund could have raced in since the pre-check.
      if (await this.deps.durable.get(refundBroadcastKey(rec.id))) {
        throw new Error('revealAndClaim: a refund became active — refusing to reveal the secret');
      }
      // FIX #2: RE-MINT the reveal authorization from a FRESH read at the broadcast choke point, bound to the EXACT
      // outpoint the claim spends (part 2 of the fix #8 triangulation: still-confirmed-at >= reqConf via SPV). The
      // passed `auth`'s captured values are NEVER reused. A throw ABORTS here — S is never broadcast.
      this.status('revealAndClaim:reverifying');
      await assertRevealSafe(client, {
        role: 'initiator',
        theirChain: this.theirChain,
        counterpartyRedeemScript: redeemScript,
        recordedOutpoint: claimTx.spent as Outpoint,
        counterpartyLocktime: locktime,
      });

      // Durable-before-broadcast (fix #4): persist the claim tx + the winning-claim sentinel ATOMICALLY BEFORE the
      // irreversible secret-bearing broadcast. A commit throw ABORTS the broadcast — S is never emitted.
      this.status('revealAndClaim:committing');
      await this.deps.durable.commit([
        [claimTxKey(rec.id), JSON.stringify(claimTx)],
        [claimBroadcastKey(rec.id), '1'],
      ]);

      this.status('revealAndClaim:broadcasting');
      await client.broadcastTx(claimTx.rawTx);
      return claimTx.txid.toLowerCase();
    });

    // Keep record.claimTx consistent with myClaimTxid: on the ADOPT path finalTxid is a prior (possibly divergent)
    // txid, so rehydrate claimTx from the durable prior claim rather than storing the freshly-built (never-broadcast)
    // one — else a step-6 resume would read a claimTx.txid that disagrees with myClaimTxid.
    let effectiveClaimTx = claimTx;
    if (finalTxid !== claimTx.txid.toLowerCase()) {
      const priorRaw = await this.deps.durable.get(claimTxKey(rec.id));
      if (priorRaw) {
        try {
          const p = JSON.parse(priorRaw) as { txid?: string; rawTx?: string; spent?: Outpoint };
          if (p?.txid && p?.rawTx && p?.spent) effectiveClaimTx = { txid: p.txid, rawTx: p.rawTx, spent: p.spent };
        } catch { /* keep the freshly-built claimTx as a best-effort fallback */ }
      }
    }
    this.record = { ...this.record, claimTx: effectiveClaimTx, myClaimTxid: finalTxid } as DurableSwapRecord;
    this.setPhase('claimed');
    this.status('revealAndClaim:claimed');
    await this.persistRecord();
    return { txid: finalTxid };
  }

  // ── watchForSecret() — the RESPONDER learns S from the initiator's on-chain claim of its OWN leg ─────────────

  /**
   * RESPONDER-ONLY. Poll the responder's OWN funded leg (leg Y, myChain) history for the initiator's spend, which
   * reveals S in its scriptSig. `extractSecret` parses the preimage and we RE-VERIFY `sha256(S) === hashLock` (the
   * hash COMMITTED in the funded redeemScript — §9.4) before saving; a forged/mismatched preimage is REJECTED.
   * Ports watchForSecret (~7499-7766) as a single scheduler-driven poll: it NEVER throws on absence (returns
   * `{secret:null}`) and, on discovery, transitions `responder_funded -> claimed`. Grounds the extract hash in
   * myHTLC.params.secretHash (R263 on-chain binding).
   */
  async watchForSecret(): Promise<{ secret: Uint8Array | null }> {
    this.assertLive();
    const rec = this.record;
    if (rec.role !== 'responder') {
      throw new Error('watchForSecret: responder-only (the initiator holds S from prepare())');
    }
    // Watch OUR OWN funded leg (leg Y on myChain). The secret hash we validate against is the one committed in the
    // funded redeemScript at the polled address (R263), i.e. our own HTLC's secretHash — never the tamperable offer.
    const myHtlc = rec.myHTLC;
    if (!myHtlc) return { secret: null }; // not funded yet — nothing to watch; do not throw (design: never on absence)
    const hashLockHex = (myHtlc.secretHash ?? '').toLowerCase();
    if (!HEX64.test(hashLockHex)) return { secret: null };
    const redeemScript = hexToBytes((myHtlc.redeemScript ?? '').toLowerCase());
    const client = this.deps.chainClientFor(this.myChain);

    let history: Array<{ tx_hash: string; height: number }>;
    try {
      history = await client.getHistory(getHTLCScripthash(redeemScript), 'a914' + bytesToHex(hash160(redeemScript)) + '87');
    } catch { return { secret: null }; } // transient poll error — do NOT throw on absence; the scheduler re-polls

    for (const item of history) {
      if (typeof item?.tx_hash !== 'string' || !HEX64.test(item.tx_hash.toLowerCase())) continue;
      let rawTx: string;
      try { rawTx = await client.getTx(item.tx_hash); } catch { continue; }
      // R22/R53: pass the committed hash INTO extractSecret so it scans EVERY input for the preimage that hashes to
      // our hashLock and skips decoy inputs — a malicious claim tx that puts a non-matching 32-byte push on an
      // EARLIER input must not make us extract the wrong value and give up, missing the real secret in a later input
      // (§9.4, SwapExecute.tsx:7653). The external sha256 re-check below stays as belt-and-suspenders.
      let candidate: Uint8Array | null;
      try { candidate = extractSecret(rawTx, hashLockHex); } catch { candidate = null; }
      if (!candidate || candidate.length !== 32) continue;
      if (bytesToHex(sha256(candidate)) !== hashLockHex) continue; // forged / mismatched preimage — REJECT
      // Found + verified. Save it in memory (the responder's now-public secret) and advance to 'claimed'.
      if (this.secret) this.secret.fill(0);
      this.secret = candidate;
      if (rec.phase === 'responder_funded') this.setPhase('claimed');
      this.status('watchForSecret:secret-found');
      await this.persistRecord();
      return { secret: candidate };
    }
    return { secret: null };
  }

  // ── claimWithKnownSecret() — the RESPONDER claims leg X with the now-PUBLIC secret ──────────────────────────

  /**
   * RESPONDER-ONLY. Claim the counterparty (initiator) leg X (theirChain) with the now-PUBLIC secret learned via
   * watchForSecret. The reveal margin gate is DELIBERATELY SKIPPED (the secret is already public — no double-dip
   * risk, design §1), but single-flight + durable-before-broadcast still apply, and it REFUSES if a refund of the
   * same HTLC is in flight (a claim + refund must not race the same outpoint). Transitions `claimed -> completed`.
   */
  async claimWithKnownSecret(): Promise<{ txid: string }> {
    this.assertLive();
    const rec = this.record;
    if (rec.role !== 'responder') {
      throw new Error('claimWithKnownSecret: responder-only (the initiator reveals via revealAndClaim)');
    }
    // Step-5 deferred idempotent-adopt: a post-confirmation / crash-resume re-call returns the PRIOR claim txid rather
    // than rebuilding against a now-spent leg-X UTXO. Precedes the phase check so a 'completed' re-call adopts.
    const adopted = await this.priorClaimTxid(rec.id);
    if (adopted) { this.record = { ...this.record, myClaimTxid: adopted } as DurableSwapRecord; this.status('claimWithKnownSecret:adopted'); return { txid: adopted }; }
    // FIX #10: a resume whose myHTLC authentication was not DEFINITIVE 'ok' must NOT authorize an irreversible claim.
    this.assertIrreversibleAllowed('claimWithKnownSecret');
    if (rec.phase !== 'claimed' && rec.phase !== 'responder_funded') {
      throw new Error(`claimWithKnownSecret: unexpected phase '${rec.phase}' — the responder claim runs after the secret is public`);
    }
    const cfg = chainConfigs[this.theirChain];
    if (!cfg || (cfg as { isEvm?: boolean }).isEvm) {
      throw new Error('claimWithKnownSecret: leg X is not a UTXO chain — EVM claim is step 7');
    }
    // Refuse if a refund of our own HTLC is in flight (mirrors the R181 claim<->refund cross-guard). A public-secret
    // claim of leg X and a refund of leg Y are on different legs, but this keeps the single terminal-action invariant.
    const refundInFlight = await this.deps.durable.get(refundBroadcastKey(rec.id));
    if (refundInFlight) {
      throw new Error('claimWithKnownSecret: a refund is already in flight — refusing to claim while a refund is active');
    }
    const secret = this.secret;
    if (!secret || secret.length !== 32) {
      throw new Error('claimWithKnownSecret: the public secret is not available — run watchForSecret first');
    }
    const { redeemScript } = this.counterpartyLeg('claimWithKnownSecret');
    const client = this.deps.chainClientFor(this.theirChain);

    // Build the claim FRESH (no margin gate — the secret is public). Reveal-gate is skipped by design.
    this.status('claimWithKnownSecret:building-claim');
    const claimTx = await this.buildSecretClaim(this.theirChain, redeemScript, secret);

    const lockName = `bch2swap:claim:${rec.id}`;
    const finalTxid = await this.deps.mutex.withLock(lockName, async (): Promise<string> => {
      // Single-flight adopt (a sibling / crash-resume already broadcast this claim).
      const sentinel = await this.deps.durable.get(claimBroadcastKey(rec.id));
      if (sentinel) {
        const priorRaw = await this.deps.durable.get(claimTxKey(rec.id));
        if (priorRaw) {
          try {
            const prior = JSON.parse(priorRaw) as { txid?: string };
            if (prior?.txid && HEX64.test(prior.txid.toLowerCase())) return prior.txid.toLowerCase();
          } catch { /* fall through */ }
        }
      }
      // Re-check the refund sentinel INSIDE the lock (a refund could have raced in since the pre-check).
      if (await this.deps.durable.get(refundBroadcastKey(rec.id))) {
        throw new Error('claimWithKnownSecret: a refund became active — refusing to claim');
      }
      // Durable-before-broadcast (fix #4): persist the claim + sentinel ATOMICALLY BEFORE broadcasting.
      this.status('claimWithKnownSecret:committing');
      await this.deps.durable.commit([
        [claimTxKey(rec.id), JSON.stringify(claimTx)],
        [claimBroadcastKey(rec.id), '1'],
      ]);
      this.status('claimWithKnownSecret:broadcasting');
      await client.broadcastTx(claimTx.rawTx);
      return claimTx.txid.toLowerCase();
    });

    this.record = { ...this.record, claimTx, myClaimTxid: finalTxid } as DurableSwapRecord;
    this.setPhase('completed');
    this.status('claimWithKnownSecret:completed');
    await this.persistRecord();
    return { txid: finalTxid };
  }

  // ── canRefund() / refund() — recover OUR OWN funded leg after its timelock (§9.7) ───────────────────────────

  /**
   * PURE predicate (no side effects, no network): is OUR funded HTLC refundable at the host-supplied `currentHeight`?
   * Exposes the ported isHtlcRefundAvailable(myHTLC.locktime, tip) for the host to render an affordance. This is only
   * an availability HINT — the REAL enforcer is the on-chain CLTV plus the FRESH-tip re-check inside refund() (§9.7).
   * Returns false when there is no funded own HTLC.
   */
  canRefund(currentHeight: number | null): boolean {
    const h = this.record.myHTLC;
    if (!h || !Number.isInteger(h.locktime)) return false;
    return isHtlcRefundAvailable(h.locktime, currentHeight);
  }

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
  async refund(): Promise<{ txid: string }> {
    this.assertLive();
    const rec = this.record;
    // §9.7: refund is ALWAYS reachable after the timelock — suspension MUST NOT gate it, or a leg funded before the
    // pair was suspended (or a pair suspended mid-swap, e.g. BC2) could never be recovered after its CLTV expires
    // (fund loss). Suspension gates only prepare()/fundOwnLeg(). The fresh-tip isHtlcRefundAvailable re-check below
    // is the only precondition.
    const myHtlc = rec.myHTLC;
    if (!myHtlc || typeof myHtlc.redeemScript !== 'string' || !/^[0-9a-f]+$/i.test(myHtlc.redeemScript) || !Number.isInteger(myHtlc.locktime)) {
      throw new Error('refund: no valid funded own HTLC recorded — nothing to refund');
    }
    const cfg = chainConfigs[this.myChain];
    if (!cfg || (cfg as { isEvm?: boolean }).isEvm) {
      throw new Error('refund: own leg is not a UTXO chain — EVM refund is step 7');
    }
    // FIX #10: refuse an irreversible refund broadcast while a resume's myHTLC auth is not DEFINITIVE 'ok'.
    this.assertIrreversibleAllowed('refund');
    // R181 cross-guard (pre-check; re-checked inside the shared claim lock): never refund while a claim is in flight.
    if (await this.deps.durable.get(claimBroadcastKey(rec.id))) {
      throw new Error('refund: a claim is already in flight — refusing to refund while a claim is active (R181 cross-guard)');
    }

    const redeemScript = hexToBytes(myHtlc.redeemScript.toLowerCase());
    const locktime = myHtlc.locktime;
    const client = this.deps.chainClientFor(this.myChain);

    // §9.7: FRESH-tip refund-availability re-check immediately before building.
    this.status('refund:checking-timelock');
    const [freshTip] = await client.getBlockHeight();
    const tip = (Number.isInteger(freshTip) && freshTip > 0) ? freshTip : null;
    if (!isHtlcRefundAvailable(locktime, tip)) {
      throw new Error(`refund: HTLC refund timelock has not passed yet (locktime ${locktime}, tip ${tip ?? 'unknown'}) — not building a premature refund`);
    }

    const sk = await this.deps.seedVault.signingKey(this.myChain);
    const myPkh = hash160(sk.publicKey); // refund goes back to our own wallet (the refund pkh committed in the HTLC)
    const destScriptPubKey = new Uint8Array([0x76, 0xa9, 0x14, ...myPkh, 0x88, 0xac]);

    // Take the SAME 'bch2swap:claim:'+id single-flight lock the claim paths use (R181) so a claim and a refund can
    // never race the same outpoint; the refund tx + sentinel are committed durably BEFORE the broadcast.
    const lockName = `bch2swap:claim:${rec.id}`;
    const finalTxid = await this.deps.mutex.withLock(lockName, async (): Promise<string> => {
      // Adopt a prior refund (a sibling call / crash-resume already committed+broadcast it) instead of double-broadcasting.
      if (await this.deps.durable.get(refundBroadcastKey(rec.id))) {
        const prior = await this.readDurableRefundTx(rec.id);
        if (prior) return prior.txid.toLowerCase();
      }
      // Re-check the claim sentinel INSIDE the lock (a claim could have raced in since the pre-check).
      if (await this.deps.durable.get(claimBroadcastKey(rec.id))) {
        throw new Error('refund: a claim became active — refusing to refund');
      }
      // Select the HTLC UTXO to refund; authenticate its value + P2SH from the self-derived raw tx before signing.
      this.status('refund:selecting-utxo');
      const scriptHex = 'a914' + bytesToHex(hash160(redeemScript)) + '87';
      const utxos = (await client.getUTXOs(getHTLCScripthash(redeemScript), scriptHex)) as GateUtxo[];
      const valid = utxos.filter((u) => u && typeof u.tx_hash === 'string' && Number.isInteger(u.tx_pos) && Number.isFinite(u.value) && u.value > 0);
      if (valid.length === 0) throw new Error('refund: no UTXO at the HTLC address — already refunded or never funded');
      const selected = [...valid].sort((a, b) => b.value - a.value)[0];
      const authed = (await verifyAndAuthenticateUtxo(
        { tx_hash: selected.tx_hash, tx_pos: selected.tx_pos, value: selected.value, height: selected.height },
        redeemScript,
        (txid: string) => client.getTx(txid),
      )) as Utxo;
      if (!(authed.value > 0)) throw new Error('refund: HTLC funding output failed re-authentication — not signing the refund');

      // Build the refund tx (nSequence 0xfffffffe + nLockTime=locktime set inside buildHTLCRefundTx). No secret.
      this.status('refund:building');
      const refundTx = await buildHTLCRefundTx(authed, redeemScript, locktime, sk.privateKey, sk.publicKey, destScriptPubKey, this.myChain);
      const refundRec = { txid: refundTx.txid, rawTx: refundTx.rawTx, spent: { tx_hash: selected.tx_hash, tx_pos: selected.tx_pos } };

      // R280-H1 / fix #4 durable-before-broadcast: persist the raw refund tx + the sentinel ATOMICALLY BEFORE the
      // broadcast; a commit throw ABORTS here — the recovery material never lags the on-chain refund.
      this.status('refund:committing');
      await this.deps.durable.commit([
        [refundTxKey(rec.id), JSON.stringify(refundRec)],
        [refundBroadcastKey(rec.id), '1'],
      ]);
      this.status('refund:broadcasting');
      await client.broadcastTx(refundTx.rawTx);
      return refundTx.txid.toLowerCase();
    });

    // Rehydrate the durable refund tx (on the adopt path finalTxid is a prior txid) so record.refundTx is consistent.
    const durableRefund = await this.readDurableRefundTx(rec.id);
    this.record = {
      ...this.record,
      refundTx: durableRefund ? { txid: durableRefund.txid, rawTx: durableRefund.rawTx } : this.record.refundTx,
    };
    this.setPhase('refunded');
    this.status('refund:broadcast');
    await this.persistRecord();
    // Arm the reorg-safe finalizer (best-effort single poll; the host/scheduler re-drives it). It is fail-closed —
    // it KEEPS all recovery material on 0-conf / short depth / any doubt, wiping only at reorg-safe SPV depth.
    try { await this.confirmRefund(); } catch { /* the finalizer never wipes on doubt; a throw here must not undo the refund */ }
    return { txid: finalTxid };
  }

  // ── reorg-safe finalizers (§9.6) — delete non-recoverable material ONLY at reorg-safe SPV depth ─────────────

  /**
   * CLAIM finalizer (§9.6). Ground: SwapExecute.tsx confirmClaim (~8019-8112). Polls the counterparty leg (theirChain)
   * for OUR claim txid; ONLY once it is buried at >= requiredConfirmations VERIFIED BY SPV (verifyConfirmations,
   * provenTxid-bound) does it delete the non-recoverable secret + claim cache + record. On 0-conf / absent / short
   * depth / inconclusive-or-pruned SPV read it KEEPS everything (fail closed). Single poll — the host re-drives it.
   */
  async confirmClaim(): Promise<{ finalized: boolean }> {
    this.assertLive();
    const rec = this.record;
    const claimTxid = (rec.myClaimTxid ?? rec.claimTx?.txid ?? '').toLowerCase();
    const cp = rec.counterpartyHTLC;
    if (!HEX64.test(claimTxid) || !cp || typeof cp.redeemScript !== 'string' || !/^[0-9a-f]+$/i.test(cp.redeemScript)) return { finalized: false };
    const cfg = chainConfigs[this.theirChain];
    if (!cfg || (cfg as { isEvm?: boolean }).isEvm) return { finalized: false }; // EVM finalize is step 7
    const redeemScript = hexToBytes(cp.redeemScript.toLowerCase());
    const client = this.deps.chainClientFor(this.theirChain);
    const reqConf = Math.max(1, cfg.requiredConfirmations ?? 6);
    let history: Array<{ tx_hash: string; height: number }>;
    try { history = await client.getHistory(getHTLCScripthash(redeemScript), 'a914' + bytesToHex(hash160(redeemScript)) + '87'); }
    catch { return { finalized: false }; } // transient read error — KEEP everything
    const entry = history.find((h) => typeof h?.tx_hash === 'string' && h.tx_hash.toLowerCase() === claimTxid && Number.isInteger(h.height) && h.height > 0);
    if (!entry) return { finalized: false }; // 0-conf / absent — KEEP
    const ok = await this.spvReorgSafe(client, this.theirChain, claimTxid, entry.height, rec.claimTx?.rawTx, reqConf);
    if (!ok) return { finalized: false }; // short depth / pruned read / stale / unknown tip — KEEP
    // REORG-SAFE: now it is safe to destroy the non-recoverable secret + the secret-bearing claim cache + the record.
    if (this.secret) { this.secret.fill(0); this.secret = null; }
    await this.wipeDurable([claimTxKey(rec.id), claimBroadcastKey(rec.id), durableSecretKey(rec.id), recordKey(rec.id)]);
    this.setPhase('completed');
    this.status('confirmClaim:finalized');
    return { finalized: true };
  }

  /**
   * REFUND finalizer (§9.6). Ground: SwapExecute.tsx confirmRefund (~8466-8531). Polls OUR OWN leg (myChain) for OUR
   * refund txid; ONLY once buried at >= requiredConfirmations VERIFIED BY SPV does it wipe the recovery material. On
   * 0-conf / dropped / short depth / inconclusive-or-pruned read it KEEPS refundtx/refundbroadcast/state — "give up
   * POLLING after 4h but KEEP everything" maps to a single non-finalizing poll (SwapExecute.tsx:8468). The secret/state
   * are wiped ONLY if no claim is in flight (a co-running winning claim needs the shared preimage); the refundtx +
   * sentinel are always cleared at reorg-safe depth. Fail-closed = keep material.
   */
  async confirmRefund(): Promise<{ finalized: boolean }> {
    this.assertLive();
    const rec = this.record;
    const durableRefund = await this.readDurableRefundTx(rec.id);
    const refund = durableRefund ?? (rec.refundTx ? { txid: rec.refundTx.txid, rawTx: rec.refundTx.rawTx } : null);
    const myHtlc = rec.myHTLC;
    if (!refund || !HEX64.test(refund.txid.toLowerCase()) || !myHtlc || typeof myHtlc.redeemScript !== 'string' || !/^[0-9a-f]+$/i.test(myHtlc.redeemScript)) return { finalized: false };
    const cfg = chainConfigs[this.myChain];
    if (!cfg || (cfg as { isEvm?: boolean }).isEvm) return { finalized: false };
    const redeemScript = hexToBytes(myHtlc.redeemScript.toLowerCase());
    const client = this.deps.chainClientFor(this.myChain);
    const reqConf = Math.max(1, cfg.requiredConfirmations ?? 6);
    const refundTxid = refund.txid.toLowerCase();
    let history: Array<{ tx_hash: string; height: number }>;
    try { history = await client.getHistory(getHTLCScripthash(redeemScript), 'a914' + bytesToHex(hash160(redeemScript)) + '87'); }
    catch { return { finalized: false }; } // transient read error — KEEP everything
    const entry = history.find((h) => typeof h?.tx_hash === 'string' && h.tx_hash.toLowerCase() === refundTxid && Number.isInteger(h.height) && h.height > 0);
    if (!entry) return { finalized: false }; // 0-conf / dropped — KEEP refundtx/refundbroadcast/state (never wipe on a timeout). A genuinely-dropped refund is resubmitted by resume()'s rebroadcastRefundIfDropped (not here — a 0-conf refund is indistinguishable from a dropped one on the immediate post-broadcast poll).
    const ok = await this.spvReorgSafe(client, this.myChain, refundTxid, entry.height, refund.rawTx, reqConf);
    if (!ok) return { finalized: false }; // short depth / pruned read / stale / unknown tip — KEEP
    // REORG-SAFE. Record the terminal phase; wipe the secret/state ONLY if no claim is in flight; always clear the refund tx.
    this.setPhase('refunded');
    const claimSeen = !!(await this.deps.durable.get(claimBroadcastKey(rec.id)));
    const wipe: string[] = [refundTxKey(rec.id), refundBroadcastKey(rec.id)];
    if (!claimSeen) {
      if (this.secret) { this.secret.fill(0); this.secret = null; }
      wipe.push(durableSecretKey(rec.id), recordKey(rec.id), fundedKey(rec.id), fundLocktimeKey(rec.id), fundRecipientKey(rec.id), fundedHtlcKey(rec.id), fundedTxKey(rec.id));
    }
    await this.wipeDurable(wipe);
    this.status('confirmRefund:finalized');
    return { finalized: true };
  }

  /**
   * Pruned-safe SETTLE for a tangled completed swap (§9.6 / SwapExecute.tsx trySettleIfBothLegsSpent ~6809). Only when
   * the `claimbroadcast` sentinel is set AND BOTH legs are spent on the LIVE UTXO set is the swap terminal (their claim
   * of our leg used our revealed secret, or both refunded) — nothing left to recover — so wipe + finalize. If OUR leg
   * is still funded (refundable) it returns false + KEEPS the recovery material (fail closed). Any inconclusive read
   * returns false. Returns true iff it settled.
   */
  async trySettleIfBothLegsSpent(): Promise<boolean> {
    this.assertLive();
    const rec = this.record;
    if (!(await this.deps.durable.get(claimBroadcastKey(rec.id)))) return false; // no in-flight winning claim
    const myHtlc = rec.myHTLC; const cpHtlc = rec.counterpartyHTLC;
    if (!myHtlc || !cpHtlc || typeof myHtlc.redeemScript !== 'string' || typeof cpHtlc.redeemScript !== 'string') return false;
    if ((chainConfigs[this.myChain] as { isEvm?: boolean } | undefined)?.isEvm || (chainConfigs[this.theirChain] as { isEvm?: boolean } | undefined)?.isEvm) return false;
    try {
      const cpRedeem = hexToBytes(cpHtlc.redeemScript.toLowerCase());
      const cpClient = this.deps.chainClientFor(this.theirChain);
      const cpUtxos = (await cpClient.getUTXOs(getHTLCScripthash(cpRedeem), 'a914' + bytesToHex(hash160(cpRedeem)) + '87')) as GateUtxo[];
      if (cpUtxos.some((u) => Number.isFinite(u.value) && u.value > 0)) return false; // their leg still funded -> not settled
      const myRedeem = hexToBytes(myHtlc.redeemScript.toLowerCase());
      const myClient = this.deps.chainClientFor(this.myChain);
      const myUtxos = (await myClient.getUTXOs(getHTLCScripthash(myRedeem), 'a914' + bytesToHex(hash160(myRedeem)) + '87')) as GateUtxo[];
      if (myUtxos.some((u) => Number.isFinite(u.value) && u.value > 0)) return false; // OUR leg still funded -> refundable -> KEEP
      // BOTH legs spent -> terminal. Safe to wipe + finalize.
      if (this.secret) { this.secret.fill(0); this.secret = null; }
      await this.wipeDurable([claimTxKey(rec.id), claimBroadcastKey(rec.id), durableSecretKey(rec.id), recordKey(rec.id)]);
      this.setPhase('completed');
      this.status('trySettle:finalized');
      return true;
    } catch { return false; } // inconclusive (e.g. getUTXOs at-capacity throw) -> caller runs the normal resume
  }

  // ── resume() — rehydrate a stalled / crashed / new-device swap from durable state (fix #10) ──────────────────

  /**
   * Rehydrate a swap from a durable record: re-derive S, RECONSTRUCT + on-chain-AUTHENTICATE myHTLC, run the
   * FINALIZERS-FIRST (refund-first short-circuit), rebroadcast a funded-but-missing funding tx idempotently, and
   * re-enter the correct gate from CHAIN truth (isResumableSwapState), NOT the persisted status. FIX #10 (critical): a
   * DEFINITIVE myHTLC 'mismatch' fails closed; an INDETERMINATE (network-blip) auth may WAIT / re-poll ONLY — neither
   * authorizes any irreversible broadcast (refund/claim) until authentication is DEFINITIVE 'ok'. Returns the controller.
   */
  static async resume(record: DurableSwapRecord, deps: SwapControllerDeps): Promise<SwapController> {
    const ctrl = new SwapController(record, deps);
    await ctrl.rehydrate();
    return ctrl;
  }

  private async rehydrate(): Promise<void> {
    this.assertLive();
    const rec = this.record;

    // (0) Re-derive S from the seed (hmac-v1) or a durable S — best-effort; the responder learns S on-chain later.
    try { await this.loadInitiatorSecret(); } catch { /* responder / locked vault: S comes from watchForSecret */ }

    // (1) RECONSTRUCT myHTLC from the durable fundedhtlc / fundlocktime side-channels when the states-map copy is gone.
    await this.reconstructMyHtlc();

    // (2) Authenticate myHTLC against the LIVE on-chain P2SH (SwapExecute.tsx:4699). FIX #10.
    const auth = await this.authenticateMyHtlcAgainstFunding();
    this.resumeAuthValue = auth;
    this.irreversibleBlocked = (auth === 'mismatch' || auth === 'indeterminate');
    if (auth === 'mismatch') {
      this.status('resume:auth-mismatch');
      this.emit({ type: 'error', error: new Error('resume: myHTLC failed on-chain authentication (DEFINITIVE P2SH mismatch) — failing closed, no irreversible action permitted (fix #10)') });
    } else if (auth === 'indeterminate') {
      this.status('resume:auth-indeterminate'); // WAIT only — re-poll; no irreversible broadcast until DEFINITIVE 'ok'
    } else if (auth === 'ok') {
      this.status('resume:auth-ok');
    }

    // (3) FINALIZERS-FIRST + refund-first short-circuit. These only rebroadcast an ALREADY-committed tx / finalize at
    // reorg-safe depth (reveal nothing new), so they run regardless of the fix #10 auth block.
    if (await this.deps.durable.get(refundBroadcastKey(rec.id))) {
      const r = await this.confirmRefund();
      this.setResumeGate(r.finalized ? 'refund-finalized' : 'refund-in-flight');
      return; // refund-first short-circuit: a refund is in flight — do NOT also route to a claim / fund gate
    }
    if (await this.deps.durable.get(claimBroadcastKey(rec.id))) {
      if (await this.trySettleIfBothLegsSpent()) { this.setResumeGate('settled'); return; }
      const c = await this.confirmClaim();
      this.setResumeGate(c.finalized ? 'claim-finalized' : 'claim-in-flight');
      return;
    }

    // (4) If the durable 'funded' sentinel/txid is set but the funding tx is NOT on-chain, rebroadcast the durable raw
    // funding tx (bch2swap:fundedtx) IDEMPOTENTLY (same txid) rather than re-selecting inputs (which would diverge).
    await this.rebroadcastFundingIfMissing();
    // (4b) §9.7: if a refund was broadcast but dropped while the funding is still unspent, resubmit it (idempotent).
    await this.rebroadcastRefundIfDropped();

    // (5) Re-enter the correct gate computed from CHAIN truth (isResumableSwapState), not the persisted status. The
    // individual methods each re-verify chain truth at their own choke points; this only tells the host what to drive.
    this.setResumeGate(isResumableSwapState(rec) ? 'post-funding' : 'pre-funding');
  }

  private setResumeGate(gate: string): void {
    this.resumeGateValue = gate;
    this.status(`resume:${gate}`);
  }

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
  private async authenticateMyHtlcAgainstFunding(): Promise<'ok' | 'mismatch' | 'indeterminate' | 'skip'> {
    const h = this.record.myHTLC;
    const ft = this.record.myFundingTxid;
    const myChainIsEvm = !!(chainConfigs[this.myChain] as { isEvm?: boolean } | undefined)?.isEvm;
    if (!h || !ft || typeof ft !== 'string' || myChainIsEvm) return 'skip';
    if (!HEX64.test(ft.toLowerCase())) return 'mismatch'; // a non-bare-hex funding txid is itself a tamper on a UTXO leg (R257)
    const ftLower = ft.toLowerCase();
    const redeemScript = hexToBytes((h.redeemScript ?? '').toLowerCase());
    const client = this.deps.chainClientFor(this.myChain);
    let inOwnHistory = false; // R257-gate: declared OUTSIDE the try so the ambiguous-getTx catch can read it
    try {
      const sh = getHTLCScripthash(redeemScript);
      const scriptHex = 'a914' + bytesToHex(hash160(redeemScript)) + '87';
      let ownUnspent = false;
      try {
        const own = (await client.getUTXOs(sh, scriptHex)) as GateUtxo[];
        ownUnspent = Array.isArray(own) && own.some((u) => typeof u?.tx_hash === 'string' && u.tx_hash.toLowerCase() === ftLower && u.tx_pos === 0);
        const hist = await client.getHistory(sh, scriptHex);
        inOwnHistory = Array.isArray(hist) && hist.some((x) => typeof x?.tx_hash === 'string' && x.tx_hash.toLowerCase() === ftLower);
      } catch { /* warm-up / history failed: leave both false -> stricter ambiguous handling below */ }
      // In the unspent set => the funding output pays our myHTLC P2SH at vout 0 by definition -> authenticated.
      if (ownUnspent) return 'ok';
      const auth = await verifyAndAuthenticateUtxo(
        { tx_hash: ftLower, tx_pos: 0, value: 0, height: 0 },
        redeemScript,
        (txid: string) => client.getTx(txid),
      );
      return auth.value > 0 ? 'ok' : 'mismatch'; // output[0] present but not our P2SH -> mismatch
    } catch (e: unknown) {
      const m = e instanceof Error ? e.message : String(e);
      if (/does not match the HTLC P2SH|malformed UTXO tx_hash|malformed UTXO tx_pos/i.test(m)) return 'mismatch';
      // Ambiguous getTx (unreachable / timeout / internal): a GENUINE (possibly already-spent) funding is in our own
      // scripthash history -> 'indeterminate' (WAIT, arm the watch; do NOT strand a spent cold-proxy recovery); a
      // fabricated non-existent txid is NOT in our history -> fail CLOSED ('mismatch').
      return inOwnHistory ? 'indeterminate' : 'mismatch';
    }
  }

  /**
   * RECONSTRUCT myHTLC on resume from the durable side-channels when the states-map copy is gone (R170 fundedhtlc, then
   * R277 fundlocktime + funding-txid rebuild). The single trust anchor is the on-chain P2SH byte-match
   * (verifyAndAuthenticateUtxo): a lying/tampered source can only DENY a rebuild (fail-closed skip), never install a
   * bad refund/watch target. No-op if myHTLC already present, or on an EVM leg.
   */
  private async reconstructMyHtlc(): Promise<void> {
    const rec = this.record;
    if (rec.myHTLC) return;
    const myChainIsEvm = !!(chainConfigs[this.myChain] as { isEvm?: boolean } | undefined)?.isEvm;
    if (myChainIsEvm) return;
    // (a) durable fundedhtlc side-channel (R170) — already P2SH+params-bound when written.
    const hydrated = await this.readDurableFundedHtlc(rec.id);
    if (hydrated) { this.record = { ...rec, myHTLC: hydrated, fundLocktime: rec.fundLocktime ?? hydrated.locktime }; return; }
    // (b) durable fundlocktime + funding txid + counterparty claim pkh -> rebuild params + AUTHENTICATE on-chain (R277).
    const fltStr = (await this.deps.durable.get(fundLocktimeKey(rec.id))) ?? (rec.fundLocktime !== undefined ? String(rec.fundLocktime) : null);
    const secretHashHex = (rec.offer.secretHash ?? '').toLowerCase().replace(/^0x/, '');
    const secretHash = HEX64.test(secretHashHex) ? hexToBytes(secretHashHex) : null;
    const gate = validateReconstructionInputs({ myChainIsEvm, haveMyHtlc: false, fundingTxid: rec.myFundingTxid, locktimeStr: fltStr, secretHash });
    if (!gate.ok || !gate.fundingTxid || gate.locktime === undefined || !secretHash) return;
    const claimPkhHex = ((rec.counterpartyClaimPkh ?? (await this.deps.durable.get(fundRecipientKey(rec.id))) ?? '')).toLowerCase().replace(/^0x/, '');
    if (!HEX20.test(claimPkhHex)) return;
    let refundPkh: Uint8Array;
    try { const sk = await this.deps.seedVault.signingKey(this.myChain); refundPkh = hash160(sk.publicKey); } catch { return; }
    const params: HTLCParams = { secretHash, recipientPubkeyHash: hexToBytes(claimPkhHex), refundPubkeyHash: refundPkh, locktime: gate.locktime };
    let rebuilt: HTLCDetails;
    try { rebuilt = createHTLC(params, this.myChain); } catch { return; } // degenerate / out-of-range -> fail-closed skip
    // AUTHENTICATE against the on-chain funding output[0] — the R277 trust anchor (value: NaN feeds only a console hint).
    const client = this.deps.chainClientFor(this.myChain);
    try {
      const authed = await verifyAndAuthenticateUtxo(
        { tx_hash: gate.fundingTxid, tx_pos: 0, value: NaN as unknown as number, height: 0 },
        rebuilt.redeemScript,
        (txid: string) => client.getTx(txid),
      );
      if (!(authed.value > 0)) return;
    } catch { return; } // not authenticatable -> skip (leave myHTLC unset; a later re-poll may heal)
    this.record = { ...rec, myHTLC: durableHtlc(rebuilt), fundLocktime: gate.locktime };
  }

  /**
   * If the durable 'funded' sentinel/txid is set but the funding tx is NOT on-chain, rebroadcast the EXACT durable raw
   * funding tx (bch2swap:fundedtx, step 4) IDEMPOTENTLY (same txid — the node dedups) rather than re-selecting inputs
   * (which would pick different inputs -> a divergent txid than the durable sentinel). Fail-closed: if we cannot tell
   * whether the funding is on-chain (read error), we do NOT rebroadcast blindly.
   */
  private async rebroadcastFundingIfMissing(): Promise<void> {
    const rec = this.record;
    const fundedSentinel = (await this.deps.durable.get(fundedKey(rec.id)))?.toLowerCase();
    const fundingTxid = (rec.myFundingTxid ?? fundedSentinel ?? '').toLowerCase();
    if (!HEX64.test(fundingTxid)) return; // not funded yet — nothing to rebroadcast
    const rawTx = await this.deps.durable.get(fundedTxKey(rec.id));
    if (!rawTx) return; // no durable raw funding tx to rebroadcast (nothing safe to do)
    const myHtlc = rec.myHTLC;
    if (!myHtlc || typeof myHtlc.redeemScript !== 'string') return;
    if ((chainConfigs[this.myChain] as { isEvm?: boolean } | undefined)?.isEvm) return;
    const client = this.deps.chainClientFor(this.myChain);
    const redeemScript = hexToBytes(myHtlc.redeemScript.toLowerCase());
    let onChain = false;
    try {
      const hist = await client.getHistory(getHTLCScripthash(redeemScript), 'a914' + bytesToHex(hash160(redeemScript)) + '87');
      onChain = Array.isArray(hist) && hist.some((h) => typeof h?.tx_hash === 'string' && h.tx_hash.toLowerCase() === fundingTxid);
    } catch { return; } // can't tell -> do NOT rebroadcast blindly (fail-closed; a later resume retries)
    if (onChain) return;
    this.status('resume:rebroadcast-funding');
    try { await client.broadcastTx(rawTx); } catch { /* already-in-mempool / transient -> harmless; the node dedups by txid */ }
  }

  /**
   * §9.7 refund-reachability is not one-shot: if a refund was broadcast (durable refundtx + refundbroadcast sentinel)
   * but its txid is NOT in the HTLC history AND the funding output is STILL unspent, the refund DROPPED — resubmit the
   * EXACT durable refund tx (idempotent, same txid). Resume-driven (NOT the immediate post-broadcast poll, where a
   * 0-conf refund is indistinguishable from a dropped one). Fail-closed: a read error / an already-spent funding output
   * does NOT rebroadcast, and this NEVER wipes.
   */
  private async rebroadcastRefundIfDropped(): Promise<void> {
    const rec = this.record;
    if (!(await this.deps.durable.get(refundBroadcastKey(rec.id)))) return; // no refund was ever broadcast
    const refund = await this.readDurableRefundTx(rec.id);
    if (!refund || !HEX64.test(refund.txid.toLowerCase())) return;
    const myHtlc = rec.myHTLC;
    if (!myHtlc || typeof myHtlc.redeemScript !== 'string') return;
    if ((chainConfigs[this.myChain] as { isEvm?: boolean } | undefined)?.isEvm) return;
    const client = this.deps.chainClientFor(this.myChain);
    const redeemScript = hexToBytes(myHtlc.redeemScript.toLowerCase());
    const scriptHex = 'a914' + bytesToHex(hash160(redeemScript)) + '87';
    const refundTxid = refund.txid.toLowerCase();
    try {
      const hist = await client.getHistory(getHTLCScripthash(redeemScript), scriptHex);
      if (Array.isArray(hist) && hist.some((h) => typeof h?.tx_hash === 'string' && h.tx_hash.toLowerCase() === refundTxid)) return; // present (mempool/confirmed) — pending, not dropped
      const utxos = await client.getUTXOs(getHTLCScripthash(redeemScript), scriptHex);
      if (!Array.isArray(utxos) || utxos.length === 0) return; // funding already spent (refund landed / claimed) — nothing to resubmit
    } catch { return; } // can't tell -> do NOT rebroadcast blindly
    this.status('resume:rebroadcast-dropped-refund');
    try { await client.broadcastTx(refund.rawTx); } catch { /* in-mempool / transient — the node dedups by txid */ }
  }

  /** Step-5 deferred idempotent-adopt source: the PRIOR winning claim txid iff the `claimbroadcast` sentinel is set and
   *  a durable claim tx (or record.myClaimTxid) supplies a bare-hex txid; else null. */
  private async priorClaimTxid(id: string): Promise<string | null> {
    if (!(await this.deps.durable.get(claimBroadcastKey(id)))) return null;
    const priorRaw = await this.deps.durable.get(claimTxKey(id));
    if (priorRaw) {
      try { const p = JSON.parse(priorRaw) as { txid?: string }; if (p?.txid && HEX64.test(p.txid.toLowerCase())) return p.txid.toLowerCase(); } catch { /* fall through */ }
    }
    const mine = (this.record.myClaimTxid ?? '').toLowerCase();
    return HEX64.test(mine) ? mine : null;
  }

  /** Read + validate the durable refund tx cache (R280-H1). */
  private async readDurableRefundTx(id: string): Promise<{ txid: string; rawTx: string; spent?: Outpoint } | null> {
    try {
      const raw = await this.deps.durable.get(refundTxKey(id));
      if (!raw) return null;
      const r = JSON.parse(raw) as { txid?: string; rawTx?: string; spent?: Outpoint };
      if (typeof r.txid === 'string' && HEX64.test(r.txid.toLowerCase()) && typeof r.rawTx === 'string') {
        return { txid: r.txid, rawTx: r.rawTx, spent: r.spent };
      }
      return null;
    } catch { return null; }
  }

  /**
   * §9.6 reorg-safe depth check for a terminal tx (claim/refund) at `height` on `chain`. Requires BOTH a proxy depth
   * >= reqConf AND — on spvSupported mainnets — verifyConfirmations (SPV, provenTxid-bound) >= reqConf. FAIL CLOSED:
   * any unknown tip, SPV throw (pruned/short/tampered header/Merkle proof), or below-required depth returns false
   * (the caller KEEPS all recovery material). Regtest / non-SPV chains fall back to the proxy depth (test-only).
   */
  private async spvReorgSafe(client: SwapChainClient, chain: Chain, txid: string, height: number, rawTx: string | undefined, reqConf: number): Promise<boolean> {
    let tip = NaN;
    try { const [h] = await client.getBlockHeight(); tip = Number.isInteger(h) ? h : NaN; } catch { tip = NaN; }
    if (!Number.isFinite(tip)) return false; // unknown tip — never wipe on uncertainty
    const depth = tip - height + 1;
    if (!(depth >= reqConf)) return false;
    if (!spvSupported(chain)) return true; // regtest / non-SPV: proxy depth only (test-only chains)
    let raw = rawTx;
    if (!raw) { try { raw = await client.getTx(txid); } catch { return false; } }
    try { return (await verifyConfirmations(client, chain, txid, height, raw, tip)) >= reqConf; }
    catch { return false; } // pruned / short / tampered SPV read — KEEP everything
  }

  /** Fail-closed = keep material: refuse a NEW irreversible broadcast while a resume's myHTLC auth is not definitive (fix #10). */
  private assertIrreversibleAllowed(label: string): void {
    if (this.irreversibleBlocked) {
      throw new Error(`${label}: myHTLC on-chain authentication is not DEFINITIVE 'ok' (${this.resumeAuthValue ?? 'unknown'}) — refusing an irreversible broadcast until re-authenticated (fix #10)`);
    }
  }

  /** Best-effort delete of a set of durable keys (§9.6 wipe — reached only at reorg-safe depth). */
  private async wipeDurable(keys: string[]): Promise<void> {
    for (const k of keys) { try { await this.deps.durable.remove(k); } catch { /* best-effort */ } }
  }

  // ── helpers ──────────────────────────────────────────────────────────────────────────────────────────────

  /** leg X amount in sats (offer.sendAmount = the initiator's locked amount, base-unit sats < 2^53). Fail closed. */
  private legXAmountSats(): number {
    return this.amountSats(this.record.offer.sendAmount, 'fundLegX', 'leg X');
  }

  /** leg Y amount in sats (offer.receiveAmount = the RESPONDER's locked amount on receiveChain). Fail closed. */
  private legYAmountSats(): number {
    return this.amountSats(this.record.offer.receiveAmount, 'fundLegY', 'leg Y');
  }

  private amountSats(raw: string | number, label: string, leg: string): number {
    const n = typeof raw === 'number' ? raw : Number(raw);
    if (!Number.isInteger(n) || !Number.isFinite(n) || n <= 0) {
      throw new Error(`${label}: invalid ${leg} amount '${String(raw)}' — refusing to build the funding tx`);
    }
    return n;
  }

  /** A minimal SwapState for createInitiatorHTLC/createResponderHTLC (they read only offer.{send,receive}Chain +
   *  secretHash). `role` selects which leg-chain the builder reads; the address fields are UI-only here. */
  private buildSwapState(role: 'initiator' | 'responder' = 'initiator'): SwapState {
    const secretHashHex = (this.record.offer.secretHash ?? '').toLowerCase().replace(/^0x/, '');
    return {
      offer: this.record.offer,
      role,
      secretHash: hexToBytes(secretHashHex),
      claimAddress: this.record.offer.initiatorReceiveAddress ?? '',
      refundAddress: this.record.offer.initiatorSendAddress ?? '',
    };
  }

  /** True iff `o` is a structurally-valid funding outpoint {tx_hash:64-hex, tx_pos:non-negative int}. */
  private isOutpoint(o: Outpoint | undefined | null): o is Outpoint {
    return !!o && typeof o.tx_hash === 'string' && HEX64.test(o.tx_hash.toLowerCase())
      && Number.isInteger(o.tx_pos) && o.tx_pos >= 0;
  }

  /**
   * Resolve the counterparty HTLC (redeemScript + locktime) and its recorded funding outpoint — the leg the
   * fund/reveal gates re-verify + the claim spends. Fail closed if the host has not recorded a valid HTLC/outpoint.
   */
  private counterpartyLeg(label: string): { redeemScript: Uint8Array; locktime: number; outpoint: Outpoint } {
    const c = this.record.counterpartyHTLC;
    if (!c || typeof c.redeemScript !== 'string' || !/^[0-9a-f]+$/i.test(c.redeemScript) || !Number.isInteger(c.locktime)) {
      throw new Error(`${label}: no valid counterparty HTLC recorded — cannot verify / claim the counterparty leg`);
    }
    const outpoint = this.record.counterpartyFundingOutpoint;
    if (!this.isOutpoint(outpoint)) {
      throw new Error(`${label}: no valid counterparty funding outpoint recorded — cannot bind the gate / claim`);
    }
    return { redeemScript: hexToBytes(c.redeemScript.toLowerCase()), locktime: c.locktime, outpoint };
  }

  /**
   * Build a signed secret-bearing claim of the counterparty HTLC on `chain`, carrying the exact funding outpoint it
   * spends (`.spent` — load-bearing for the fix #8 triangulation + the pre-reveal double-spend re-check). Prefers the
   * `preferOutpoint` (the authorized one) when it is in the fresh UTXO set, else the largest valid output (mirrors
   * buildClaimTx ~7244/7690). Authenticates the chosen output's VALUE + P2SH scriptPubKey against its self-derived
   * raw tx before signing (never trusts the proxy listunspent value). Signs with the seed-derived key on `chain`
   * (whose hash160 is the HTLC recipient pkh) and sweeps to that same pkh. THROWS on no claimable/authenticatable UTXO.
   */
  private async buildSecretClaim(
    chain: Chain,
    redeemScript: Uint8Array,
    secret: Uint8Array,
    preferOutpoint?: Outpoint,
  ): Promise<{ txid: string; rawTx: string; spent: Outpoint }> {
    const client = this.deps.chainClientFor(chain);
    const scripthash = getHTLCScripthash(redeemScript);
    const scriptHex = 'a914' + bytesToHex(hash160(redeemScript)) + '87';
    const raw = (await client.getUTXOs(scripthash, scriptHex)) as GateUtxo[];
    const valid = raw.filter((u) => u && typeof u.tx_hash === 'string' && Number.isInteger(u.tx_pos) && Number.isFinite(u.value) && u.value > 0);
    if (valid.length === 0) {
      throw new Error('buildSecretClaim: counterparty HTLC has no claimable UTXO (spent / not yet visible) — cannot build the claim');
    }
    // Prefer the exact authorized outpoint; else the largest valid output.
    let chosen: GateUtxo | undefined = preferOutpoint
      ? valid.find((u) => u.tx_hash === preferOutpoint.tx_hash && u.tx_pos === preferOutpoint.tx_pos)
      : undefined;
    if (!chosen) chosen = [...valid].sort((a, b) => b.value - a.value)[0];

    // PROXY-TRUST-UTXO-VALUE-001: re-derive the value + verify the funded output's P2SH from the self-authenticated
    // raw tx before signing (never trust the proxy listunspent value/script).
    const authed = (await verifyAndAuthenticateUtxo(
      { tx_hash: chosen.tx_hash, tx_pos: chosen.tx_pos, value: chosen.value, height: chosen.height },
      redeemScript,
      (txid: string) => client.getTx(txid),
    )) as Utxo;
    if (!(authed.value > 0)) {
      throw new Error('buildSecretClaim: counterparty HTLC funding output failed re-authentication — not signing the claim');
    }

    const sk = await this.deps.seedVault.signingKey(chain);
    const destPkh = hash160(sk.publicKey); // sweep to the recipient pkh committed in the HTLC (our own claim key)
    const tx = await claimHTLC(authed, redeemScript, secret, sk.privateKey, sk.publicKey, destPkh, chain);
    return { txid: tx.txid, rawTx: tx.rawTx, spent: { tx_hash: chosen.tx_hash, tx_pos: chosen.tx_pos } };
  }

  /**
   * Greedy FIFO UTXO selection — ported from prepareFundingTx (~5431-5457): oldest-confirmed-first (immature
   * coinbase is newest, so it is spent last), tie-break by value desc, accumulate until amount + estimated fee is
   * covered, then decide the change-output count AFTER fee. Returns the selected inputs or null (insufficient).
   * Uses the chain's static config fee rate (a LIVE deadline-scaled rate is a separate seam; step 4 keeps it simple).
   */
  private greedySelect(candidates: ResUtxo[], amountSats: number): ResUtxo[] | null {
    const cfg = chainConfigs[this.myChain];
    const feePerByte = (Number.isFinite(cfg.feePerByte) && (cfg.feePerByte ?? 0) > 0) ? (cfg.feePerByte as number) : 1;
    const rawDust = cfg.dustThreshold ?? 546;
    const dust = (Number.isFinite(rawDust) && rawDust >= 0) ? rawDust : 546;
    const fifo = (a: ResUtxo, b: ResUtxo) =>
      ((a.height > 0 ? a.height : Infinity) - (b.height > 0 ? b.height : Infinity)) || (b.value - a.value);

    const selected: ResUtxo[] = [];
    let total = 0;
    for (const u of [...candidates].sort(fifo)) {
      selected.push(u);
      total += u.value;
      const numOutputs = (total - amountSats > dust) ? 2 : 1;
      const estFee = (selected.length * 148 + numOutputs * 34 + 10) * feePerByte;
      if (total >= amountSats + estFee) break;
    }
    const fee2 = (selected.length * 148 + 2 * 34 + 10) * feePerByte;
    const fee1 = (selected.length * 148 + 1 * 34 + 10) * feePerByte;
    const finalOutputs = (total - amountSats - fee2 > dust) ? 2 : 1;
    const needed = amountSats + (finalOutputs === 2 ? fee2 : fee1);
    if (selected.length === 0 || total < needed) return null;
    return selected;
  }

  /** Read + validate the durable funded-HTLC side-channel (R170) for the adopt path. */
  private async readDurableFundedHtlc(id: string): Promise<DurableHTLC | null> {
    try {
      const raw = await this.deps.durable.get(fundedHtlcKey(id));
      if (!raw) return null;
      const r = JSON.parse(raw) as Partial<DurableHTLC>;
      if (typeof r.redeemScript !== 'string' || typeof r.p2shAddress !== 'string' || typeof r.secretHash !== 'string'
        || typeof r.recipientPkh !== 'string' || typeof r.refundPkh !== 'string' || !Number.isInteger(r.locktime)) {
        return null;
      }
      return r as DurableHTLC;
    } catch { return null; }
  }

  /** Best-effort persist of the full record (rehydration source for resume in step 6). Not fund-critical — the
   *  fund-critical write-set is committed atomically inside fundLegX BEFORE the broadcast. */
  private async persistRecord(): Promise<void> {
    try { await this.deps.durable.set(recordKey(this.id), JSON.stringify(this.record)); }
    catch (e) { this.emit({ type: 'error', error: e instanceof Error ? e : new Error(String(e)) }); }
  }
}
