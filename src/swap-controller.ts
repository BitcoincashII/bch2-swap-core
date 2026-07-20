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
}
import type { DurableStore, SessionStore, Mutex } from './storage';
import { UtxoReservationRegistry, type ResUtxo } from './utxo-reservation';
import { deriveSwapKss, swapSecretFromKss, SWAP_SECRET_SCHEME, SWAP_NONCE_BYTES } from './seed-secret';
import { createInitiatorHTLC, fundHTLC, verifyAndAuthenticateP2pkhInput } from './swap-flow';
import { hexToBytes, bytesToHex, hash160, sha256, maxPlausibleBlockHeight } from './htlc-builder';
import { p2pkhScripthash } from './address-codec';
import { chainConfigs, isSwapPairSuspended } from './chain-config';
import { spvSupported, verifyFundingHeight } from './spv-verifier';
import type { HTLCDetails } from './swap-types';

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
  counterpartyEvmSwapId?: string;
  counterpartyEvmTimeLock?: number; // R167 trusted EVM-leg expiry (absolute unix seconds)

  // ── funding / timelock durable singletons ────────────────────────────────────────────────────────────
  myFundingTxid?: string;
  fundLocktime?: number; // the only durable copy of a height CLTV (R237)
  respLocktime?: number; // R167 EVM-timestamp CLTV

  // ── irreversible-tx caches (steps 5-6 populate these) ────────────────────────────────────────────────
  claimTx?: { txid: string; rawTx: string; spent?: Outpoint };
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
    const rec = this.record;
    if (rec.role !== 'initiator') {
      throw new Error('fundLegX: only the initiator funds leg X (responder/EVM funding is step 7)');
    }
    if (rec.phase !== 'taken' && rec.phase !== 'prepared') {
      throw new Error(`fundLegX: unexpected phase '${rec.phase}' — fund runs from 'taken' or 'prepared'`);
    }
    if (isSwapPairSuspended(this.myChain, this.theirChain)) {
      throw new Error(`fundLegX: swap pair ${this.myChain}/${this.theirChain} is suspended — refusing to fund`);
    }
    const cfg = chainConfigs[this.myChain];
    if (!cfg || (cfg as { isEvm?: boolean }).isEvm) {
      throw new Error(`fundLegX: leg X (${this.myChain}) is not a UTXO chain — EVM funding is step 7`);
    }
    const claimPkhHex = (rec.counterpartyClaimPkh ?? '').toLowerCase().replace(/^0x/, '');
    if (!HEX20.test(claimPkhHex)) {
      throw new Error('fundLegX: counterpartyClaimPkh (the taker receive pkh on leg X) is missing — cannot build the HTLC');
    }
    const amountSats = this.legXAmountSats();

    const client = this.deps.chainClientFor(this.myChain);

    // (1) H1-LOCKTIME-PROXY-001: SPV-verify the build height is a REAL PoW block before it becomes the refund CLTV
    // base. Fail closed on an implausible or unverifiable/inflated height (would strand the coins we are about to fund).
    this.status('fundLegX:verifying-height');
    const [buildHeight] = await client.getBlockHeight();
    if (!Number.isInteger(buildHeight) || buildHeight <= 0 || buildHeight > maxPlausibleBlockHeight()) {
      throw new Error(`fundLegX: proxy-reported ${this.myChain} height ${buildHeight} is implausible — refusing to set an unrecoverable refund timelock`);
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
    // (5) single-flight (fix #3): the ENTIRE select+reserve+build+commit+broadcast runs under one lock.
    const outcome = await this.deps.mutex.withLock(lockName, async (): Promise<{ txid: string; htlc?: HTLCDetails; adopted: boolean }> => {
      // Re-check the durable `funded` sentinel INSIDE the lock — a peer/tab that already funded means we must NOT
      // broadcast our (divergent) tx; ADOPT its txid instead (mirrors handleBroadcastFunding's prior-key adopt).
      const prior = await this.deps.durable.get(fundedKey(rec.id));
      if (prior && HEX64.test(prior.toLowerCase())) {
        return { txid: prior.toLowerCase(), adopted: true };
      }

      // (2) select + reserve inside the reservation lock (candidateUtxos -> greedy FIFO -> reserveInputs).
      this.status('fundLegX:selecting-inputs');
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
        throw new Error('fundLegX: insufficient spendable UTXOs to fund the HTLC');
      }

      try {
        // R260-INPUT-VALUE-AUTH-001 (~5479-5509): on LEGACY non-BIP143 chains (btc) the sighash does NOT commit the
        // input value, so a lying/MITM proxy's inflated listunspent `value` would yield a VALID sig -> too little
        // change -> the user silently burns the difference to fees. Authenticate each selected input's value against
        // its self-derived raw tx and drive the build from the AUTHENTICATED value. BIP143 chains (bch2/bch) commit
        // the value -> a lie -> invalid sig -> node reject (DoS only), so the extra getTx is skipped.
        let selected: ResUtxo[] = picked;
        if (!(cfg.useBip143 ?? false)) {
          this.status('fundLegX:authenticating-inputs');
          const fetchRawTx = (txid: string) => client.getTx(txid);
          const authed: ResUtxo[] = [];
          for (const u of picked) {
            const a = await verifyAndAuthenticateP2pkhInput(u, myPkh, fetchRawTx);
            authed.push({ ...u, value: a.value });
          }
          const authTotal = authed.reduce((s, x) => s + x.value, 0);
          if (authTotal < amountSats) {
            throw new Error('fundLegX: authenticated input total is below the funding amount (possible proxy value inflation) — not signing');
          }
          selected = authed;
        }

        // (3) build: createInitiatorHTLC(buildHeight) -> fundHTLC (= buildHTLCFundingTx). Deterministic, so two
        // concurrent callers produce the SAME txid/locktime — the sentinel re-check keeps it single-broadcast.
        const htlc = createInitiatorHTLC(this.buildSwapState(), buildHeight, claimPkh, myPkh);
        this.status('fundLegX:building-tx');
        const tx = await fundHTLC(htlc, selected, sk.privateKey, sk.publicKey, p2pkhScript, amountSats, this.myChain);
        // Record 0-conf change so a concurrent funding may chain from it (no-op for a single swap).
        const totalIn = selected.reduce((s, u) => s + u.value, 0);
        const changeVal = totalIn - amountSats - tx.fee;
        if (changeVal > 0) this.deps.reservation.recordChange(rec.id, { tx_hash: tx.txid, tx_pos: 1, value: changeVal, height: 0 }, now);

        const canonical = tx.txid.toLowerCase();

        // (4) durable-before-broadcast (fix #4): ATOMIC write-set, read-back-verified, THROWS on partial. If it
        // throws we ABORT here — the broadcast below never runs, so funds never move without a durable record. The
        // raw tx is committed too so a crash between (4) and (5) is resolvable by an idempotent rebroadcast (step 6).
        this.status('fundLegX:committing');
        await this.deps.durable.commit([
          [fundedKey(rec.id), canonical],
          [fundLocktimeKey(rec.id), String(htlc.params.locktime)],
          [fundRecipientKey(rec.id), bytesToHex(claimPkh)],
          [fundedHtlcKey(rec.id), JSON.stringify(durableHtlc(htlc))],
          [fundedTxKey(rec.id), tx.rawTx],
        ]);

        // (5) broadcast — only AFTER the durable write-set has landed.
        this.status('fundLegX:broadcasting');
        await client.broadcastTx(tx.rawTx);
        return { txid: canonical, htlc, adopted: false };
      } catch (e) {
        // Build / commit / broadcast failed: release the reserved inputs so a retry can reselect (the durable
        // sentinel, if the commit succeeded, keeps a later call from double-broadcasting the same tx).
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
    this.setPhase('initiator_funded');
    this.status('fundLegX:funded');
    await this.persistRecord();
    return { txid: outcome.txid };
  }

  // ── helpers ──────────────────────────────────────────────────────────────────────────────────────────────

  /** leg X amount in sats (offer.sendAmount is base-unit sats < 2^53 for a UTXO leg). Fail closed on garbage. */
  private legXAmountSats(): number {
    const raw = this.record.offer.sendAmount;
    const n = typeof raw === 'number' ? raw : Number(raw);
    if (!Number.isInteger(n) || !Number.isFinite(n) || n <= 0) {
      throw new Error(`fundLegX: invalid leg X amount '${String(raw)}' — refusing to build the funding tx`);
    }
    return n;
  }

  /** A minimal SwapState for createInitiatorHTLC (it reads only offer.sendChain + secretHash). */
  private buildSwapState(): SwapState {
    const secretHashHex = (this.record.offer.secretHash ?? '').toLowerCase().replace(/^0x/, '');
    return {
      offer: this.record.offer,
      role: 'initiator',
      secretHash: hexToBytes(secretHashHex),
      claimAddress: this.record.offer.initiatorReceiveAddress ?? '',
      refundAddress: this.record.offer.initiatorSendAddress ?? '',
    };
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
