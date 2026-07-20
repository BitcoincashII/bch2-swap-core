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
import { hexToBytes, bytesToHex, hash160, sha256, maxPlausibleBlockHeight } from './htlc-builder';
import { p2pkhScripthash } from './address-codec';
import { chainConfigs, isSwapPairSuspended } from './chain-config';
import { spvSupported, verifyFundingHeight } from './spv-verifier';
import { assertLegBuriedForFunding, assertRevealSafe, type FundProof, type RevealAuthorization } from './gates';
import type { HTLCDetails, Utxo } from './swap-types';

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
    if (rec.phase !== 'responder_funded' && rec.phase !== 'claimed') {
      throw new Error(`revealAndClaim: unexpected phase '${rec.phase}' — reveal runs from 'responder_funded'`);
    }
    if (isSwapPairSuspended(this.myChain, this.theirChain)) {
      throw new Error(`revealAndClaim: swap pair ${this.myChain}/${this.theirChain} is suspended — refusing to reveal`);
    }
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
