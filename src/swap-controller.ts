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
import { spvSupported, verifyFundingHeight, verifyConfirmations, parseHeaderTimeSec } from './spv-verifier';
import { fetchFeeRate, deadlineAwareFeeRate } from './fee-rate';
import { CLAIM_MARGIN_SEC } from './timelock-gates';
import {
  assertLegBuriedForFunding, assertRevealSafe, assertEvmLegBuriedForFunding, assertEvmRevealSafe, parseHtlcCltv,
  type FundProof, type RevealAuthorization,
} from './gates';
import type { HTLCDetails, HTLCParams, Utxo } from './swap-types';
// ── EVM parity (P1b step 7) — the injected quorum>=2 read provider + Node ethers.Wallet signer seams, plus the
// proven on-chain handlers (lockETH/lockTokens/claimSwap/refundSwap/getSwap) and the EVM leg config lookups. ──
import { ethers, type Provider, type Signer } from 'ethers';
import { lockETH, lockTokens, claimSwap, refundSwap, getSwap, recoverLockFromTx, ensureAllowance, HTLC_ABI, type SwapData } from './evm-client';
import { getEvmConfig, isNativeToken, evmLockSecondsForRole, assertCanonicalEvmToken, NATIVE_ETH_ADDRESS, type EvmChainId, type EvmChainConfig } from './evm-config';

/** The zero address (native-asset sentinel), lowercased — an HTLC config still pinned to it means "not deployed". */
const NATIVE_ETH_ADDR = NATIVE_ETH_ADDRESS.toLowerCase();

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

  // ── EVM leg specifics (step 7 — populated only on an EVM-leg topology) ────────────────────────────────
  /** OUR own EVM lock's swapId (bytes32 hex), set by lockEvm; watched by watchForClaimEvm, refunded by refundEvm. */
  myEvmSwapId?: string;
  /** OUR EVM address — the recipient when WE claim the counterparty EVM leg (revealAndClaimEvm), and the initiator of
   *  our own lock (the address refundSwap authenticates against). */
  myEvmAddress?: string;
  /** The counterparty's EVM address — the recipient of the lock WE create (lockEvm), i.e. who may claim our EVM leg. */
  counterpartyEvmAddress?: string;
  /** The token WE lock on our EVM leg (native => NATIVE_ETH_ADDRESS). Defaults to offer.evmInfo.tokenAddress. */
  myEvmToken?: string;
  /** The token the COUNTERPARTY locked on their EVM leg (the gate binds it). Defaults to offer.evmInfo.tokenAddress. */
  counterpartyEvmToken?: string;
  /** The block our own EVM lock mined at — a lower bound for the getLogs Claimed-event scan (watch / refund-race). */
  evmLockBlock?: number;

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
  // EVM parity (step 7) — the REAL seams. `evmProviderFor` returns the quorum>=2 read Provider the EVM GATE minters
  // (assertEvmLegBuriedForFunding / assertEvmRevealSafe) verify against + the refund-race Claimed-event corroboration
  // reads; `evmSignerFor` returns an ethers Signer (a Node `ethers.Wallet` derived from the seed — MetaMask is NOT on
  // the path, `connectMetaMask` is dead surface) the lock/claim/refund broadcasts sign with. Optional so a UTXO-only
  // host can omit them; the EVM methods fail closed (throw) if a needed factory is absent.
  evmProviderFor?: (chain: Chain) => Provider;
  evmSignerFor?: (chain: Chain) => Signer;
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
  /** The EVM block at which our leg was locked — the lossless floor for the counterparty-secret scan (R-EVMLOCKBLOCK-001). */
  evmLockBlock?: number;
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
/** EVM (step 7): the durable recovery marker holding a BROADCAST-but-unconfirmed lock tx hash (R160/R161). Written the
 *  instant the lock is broadcast (onBroadcast) so a crash between broadcast and the funded-key write is recoverable —
 *  the EVM lock is irreversible once mined. Cleared once the lock resolves with a known swapId (funded-key set). */
const lockPendingKey = (id: string): string => `bch2swap:lockpending:${id}`;
/** EVM (step 7): the live lock tx hash for a UI explorer link (R-EVMLOCKTX). Re-fires with the replacement hash on a
 *  MetaMask speed-up; a Node signer typically won't, but the seam is kept so the app adapter interops. */
const evmLockTxKey = (id: string): string => `bch2swap:evmlocktx:${id}`;
/** EVM (step 7, fix #2): a durable "refund-race recovery is pending" marker. Set when our own EVM lock was already
 *  CLAIMED by the counterparty (refundSwap reverts) but S is not YET extractable from the on-chain Claimed event
 *  (a lagging/pruned/transient leaf). While set, a re-called refundEvm RE-ENTERS recovery straight away — it must
 *  NEVER send a fresh refund and NEVER adopt the refund sentinel as a completed refund (which would strand the
 *  other leg we are owed). Cleared only once S is recovered + the other leg is claimed. */
const refundRacePendingKey = (id: string): string => `bch2swap:refundracepending:${id}`;
/** EVM (step 7, fix #5): the pre-broadcast lockpending marker value written BEFORE lockETH/lockTokens broadcasts so a
 *  crash between broadcast and the funded-key write is always recoverable; onBroadcast refines it with the real tx hash. */
const LOCK_PENDING_SENTINEL = 'pending';

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
const BYTES32_0X = /^0x[0-9a-fA-F]{64}$/;

/** The quorum leaves behind a Provider (the R224/R278 `__leafProviders` pattern gates.ts uses). A bare Provider with
 *  no attached leaves is treated as a single leaf — the EVM gates then REFUSE it (leaves.length < 2), so the quorum>=2
 *  requirement stays structural, not advisory. Reused here for the fix #7 Claimed-event corroboration across leaves. */
function evmLeaves(provider: Provider): Provider[] {
  const ls = (provider as unknown as { __leafProviders?: Provider[] }).__leafProviders;
  return Array.isArray(ls) && ls.length > 0 ? ls : [provider];
}
/** One shared Interface for parsing Claimed logs (built from the SAME HTLC_ABI the SUT + mocks use — no ABI drift). */
const HTLC_IFACE = new ethers.Interface(HTLC_ABI);

/**
 * FIX #3 (poisoned claim sentinel): classify a UTXO `broadcastTx` failure into DEFINITIVE-node-rejection vs AMBIGUOUS
 * — the UTXO analogue of the EVM claimSwap `preBroadcast` distinction. A DEFINITIVE rejection means the node VALIDATED
 * the tx and refused it, so it never entered ANY mempool: the secret in the claim scriptSig is NOT public and a retry
 * can rebuild + re-broadcast (the caller CLEARS the claimbroadcast sentinel). An AMBIGUOUS failure (timeout / connection
 * drop / already-known / anything unrecognized) means the tx MAY have reached a mempool — the secret MAY be public — so
 * the caller KEEPS the sentinel and a later call ADOPTS instead of re-revealing (fail-safe, R201). Fail-safe DEFAULT is
 * ambiguous (return false): a transport/timeout signal ALWAYS wins, and only a recognized node-validation rejection clears.
 */
function isDefinitiveBroadcastRejection(err: unknown): boolean {
  const msg = (err instanceof Error ? err.message : String(err ?? '')).toLowerCase();
  if (!msg) return false;
  // AMBIGUOUS transport/timeout/liveness signals ALWAYS win (the tx may already be in some node's mempool) → KEEP.
  if (/tim(e|ed)\s?out|timeout|econnreset|econnrefused|etimedout|socket hang up|network|unreachable|fetch failed|abort|websocket|\b1006\b|disconnect|no (response|reply)|already (in|known)|txn-already-known|in block chain|mempool/i.test(msg)) {
    return false;
  }
  // DEFINITIVE node-validation rejections: the node examined the tx and refused it (not in any mempool) → CLEAR.
  return /reject|bad-txns|missing ?inputs|missingorspent|min relay fee|insufficient (fee|priority)|mandatory-script-verify|non-mandatory-script-verify|scriptsig|dust|non-?final|absurdly-high-fee|belowout|verify (flag|failed)|invalid|malformed|^\s*(16|64|18|256):\s/i.test(msg);
}

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
      evmLockBlock: this.record.evmLockBlock,
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

    // FIX #5 (fund-safety, INITIATOR / leg-X only): NEVER fund a swap whose secret a crash would strand. The initiator's
    // secret must be RE-DERIVABLE — either the offer is hmac-v1 (S = swapSecretFromKss on any device) OR an
    // encrypted-at-rest durable S is present. prepare() enforces this at ~508-517, and the file header (lines 16-17)
    // claims fundLegX enforces it too — but a caller invoking fundLegX() DIRECTLY from 'taken' (skipping prepare) would
    // otherwise bypass it. The responder (leg Y) learns S on-chain, so it is exempt (gated on expectRole 'initiator').
    if (expectRole === 'initiator') {
      const isHmacV1 = rec.offer.secretScheme === SWAP_SECRET_SCHEME;
      const durableSecretHex = await this.deps.durable.get(durableSecretKey(rec.id));
      if (!isHmacV1 && !durableSecretHex) {
        throw new Error(
          `${label}: offer secretScheme '${rec.offer.secretScheme ?? 'none'}' is not '${SWAP_SECRET_SCHEME}' and no ` +
          `encrypted-at-rest durable secret is present — refusing to fund a swap whose secret a crash would strand (fix #5)`,
        );
      }
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
      // R-UNDERFUND-001: the responder claims leg X = offer.sendAmount — bind the gate so a dust-funded leg X is rejected.
      expectedFundedValueSats: this.amountSats(this.record.offer.sendAmount, 'verifyCounterpartyLegForFunding', 'counterparty leg X'),
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
      // R-UNDERFUND-001: the initiator claims leg Y = offer.receiveAmount — bind the gate so a dust-funded leg Y is
      // rejected BEFORE the irreversible secret reveal (else we reveal S against a dust leg and recover only dust).
      expectedFundedValueSats: this.amountSats(this.record.offer.receiveAmount, 'verifyCounterpartyLegForReveal', 'counterparty leg Y'),
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
        // R-UNDERFUND-001: re-bind the funded-value check at the broadcast choke point too — never reveal S against a
        // counterparty leg Y that holds less than offer.receiveAmount.
        expectedFundedValueSats: this.amountSats(this.record.offer.receiveAmount, 'revealAndClaim', 'counterparty leg Y'),
      });

      // Durable-before-broadcast (fix #4): persist the claim tx + the winning-claim sentinel ATOMICALLY BEFORE the
      // irreversible secret-bearing broadcast. A commit throw ABORTS the broadcast — S is never emitted.
      this.status('revealAndClaim:committing');
      await this.deps.durable.commit([
        [claimTxKey(rec.id), JSON.stringify(claimTx)],
        [claimBroadcastKey(rec.id), '1'],
      ]);

      this.status('revealAndClaim:broadcasting');
      // FIX #3: a DEFINITIVE pre-broadcast node rejection (the node validated + refused the tx — the secret never
      // entered any mempool) CLEARS the claimbroadcast sentinel we just set so a retry can rebuild + re-broadcast;
      // an ambiguous / timeout failure LEAVES it set (fail-safe, R201). Without this, a stale sentinel makes a later
      // call ADOPT a claim that never happened, wedging the swap (refund also refuses via the R181 cross-guard).
      await this.broadcastClaimWithSentinelGuard(client, claimTx.rawTx, rec.id);
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
      // FIX #3: clear the claimbroadcast sentinel on a DEFINITIVE pre-broadcast node rejection (retry can re-broadcast),
      // keep it on an ambiguous / timeout failure (fail-safe, R201) — same poisoned-sentinel guard as revealAndClaim.
      await this.broadcastClaimWithSentinelGuard(client, claimTx.rawTx, rec.id);
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
      // R-FEE-DEADLINE-001: refund at the live, deadline-aware rate too — a stuck refund past its own timelock is a
      // fund-recovery failure on a fee-volatile chain.
      const feeRate = await this.legAwareFeeRate(client, this.myChain, redeemScript);
      const refundTx = await buildHTLCRefundTx(authed, redeemScript, locktime, sk.privateKey, sk.publicKey, destScriptPubKey, this.myChain, feeRate);
      const refundRec = { txid: refundTx.txid, rawTx: refundTx.rawTx, spent: { tx_hash: selected.tx_hash, tx_pos: selected.tx_pos } };

      // R280-H1 / fix #4 durable-before-broadcast: persist the raw refund tx + the sentinel ATOMICALLY BEFORE the
      // broadcast; a commit throw ABORTS here — the recovery material never lags the on-chain refund.
      this.status('refund:committing');
      await this.deps.durable.commit([
        [refundTxKey(rec.id), JSON.stringify(refundRec)],
        [refundBroadcastKey(rec.id), '1'],
      ]);
      this.status('refund:broadcasting');
      // R-UTXO-REFUNDRACE-001 (B1): clear the refundbroadcast sentinel on a DEFINITIVE rejection (e.g. the counterparty
      // already claimed our leg Y), so a stuck sentinel never wedges the responder's leg-X recovery claim.
      await this.broadcastRefundWithSentinelGuard(client, refundTx.rawTx, rec.id);
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
    // FIX #10 (§9.6 never-wipe): a resume whose myHTLC on-chain authentication was NOT a DEFINITIVE 'ok' must KEEP all
    // non-recoverable material — never tear down the secret/record off a possibly-untrustworthy chain read.
    if (this.irreversibleBlocked) return false;
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
      // FIX (§9.6 never-wipe): a bare getUTXOs "both legs empty" read is NOT sufficient to destroy the non-recoverable
      // secret + durable record. A reorg, or a stale / incorrect proxy read that shows OUR still-funded leg as empty,
      // would trigger an unrecoverable teardown. Require the SPENDING of OUR OWN leg to be buried at reorg-safe SPV depth
      // (the SAME provenTxid-bound proof confirmClaim / confirmRefund require) before wiping — never wipe on a bare
      // getUTXOs read. Fail closed: KEEP on any doubt (0-conf spend / short depth / pruned SPV / read error).
      if (!(await this.ownLegSpendReorgSafe(myClient, myRedeem))) return false;
      // R-TRYSETTLE-RECV-001 (§9.6): ALSO require OUR claim of the RECEIVE leg (theirChain) to be buried at reorg-safe
      // depth before wiping its claim material. A bare cpUtxos "empty" read is satisfied at 1 confirmation, so a
      // shallow reorg on the receive leg AFTER the wipe would strand our re-claim (the secret + claimTx we just
      // destroyed). ownLegSpendReorgSafe above only proves OUR FUNDED leg's spend; this proves the RECEIVE leg's.
      // Mirrors confirmClaim; fail closed (KEEP) on any doubt.
      if (!(await this.claimBuriedReorgSafe())) return false;
      // BOTH legs spent + BOTH spends reorg-safe -> terminal. Safe to wipe + finalize.
      if (this.secret) { this.secret.fill(0); this.secret = null; }
      await this.wipeDurable([claimTxKey(rec.id), claimBroadcastKey(rec.id), durableSecretKey(rec.id), recordKey(rec.id)]);
      this.setPhase('completed');
      this.status('trySettle:finalized');
      return true;
    } catch { return false; } // inconclusive (e.g. getUTXOs at-capacity throw) -> caller runs the normal resume
  }

  /**
   * §9.6 reorg-safe proof that OUR OWN leg's HTLC funding output has been SPENT and that spend is buried at
   * >= requiredConfirmations SPV-VERIFIED depth (the same anchor confirmClaim / confirmRefund use). The spend is the
   * confirmed HTLC-scripthash history tx that is NOT our own funding tx. FAIL CLOSED (returns false): a transient read
   * error, a 0-conf / short-depth spend, a pruned/unprovable SPV read, or the absence of any confirmed spend all KEEP
   * the recovery material. Never trusts a bare getUTXOs "empty" read to authorize the teardown.
   */
  private async ownLegSpendReorgSafe(client: SwapChainClient, myRedeem: Uint8Array): Promise<boolean> {
    const rec = this.record;
    const cfg = chainConfigs[this.myChain];
    if (!cfg || (cfg as { isEvm?: boolean }).isEvm) return false;
    const reqConf = Math.max(1, cfg.requiredConfirmations ?? 6);
    const fundingTxid = (rec.myFundingTxid ?? '').toLowerCase();
    let history: Array<{ tx_hash: string; height: number }>;
    try { history = await client.getHistory(getHTLCScripthash(myRedeem), 'a914' + bytesToHex(hash160(myRedeem)) + '87'); }
    catch { return false; } // transient read error — never wipe
    for (const h of history) {
      if (typeof h?.tx_hash !== 'string' || !HEX64.test(h.tx_hash.toLowerCase()) || !Number.isInteger(h.height) || h.height <= 0) continue;
      const txid = h.tx_hash.toLowerCase();
      if (txid === fundingTxid) continue; // the funding tx itself, not its spend
      if (await this.spvReorgSafe(client, this.myChain, txid, h.height, undefined, reqConf)) return true;
    }
    return false;
  }

  /**
   * §9.6 reorg-safe proof that OUR claim of the RECEIVE leg (theirChain) is buried at >= requiredConfirmations
   * SPV-VERIFIED depth. Mirrors confirmClaim's proof (find our claim txid in the counterparty HTLC-scripthash history
   * + spvReorgSafe against the recorded rawTx). FAIL CLOSED (false) on any doubt: a transient read error, a 0-conf /
   * short-depth claim, a pruned/unprovable SPV read, or the absence of our claim in history all KEEP the material.
   * Used by trySettleIfBothLegsSpent to gate the wipe of the receive-leg claim material (secret + claimTx).
   */
  private async claimBuriedReorgSafe(): Promise<boolean> {
    const rec = this.record;
    const claimTxid = (rec.myClaimTxid ?? rec.claimTx?.txid ?? '').toLowerCase();
    const cp = rec.counterpartyHTLC;
    if (!HEX64.test(claimTxid) || !cp || typeof cp.redeemScript !== 'string' || !/^[0-9a-f]+$/i.test(cp.redeemScript)) return false;
    const cfg = chainConfigs[this.theirChain];
    if (!cfg || (cfg as { isEvm?: boolean }).isEvm) return false;
    const redeemScript = hexToBytes(cp.redeemScript.toLowerCase());
    const client = this.deps.chainClientFor(this.theirChain);
    const reqConf = Math.max(1, cfg.requiredConfirmations ?? 6);
    let history: Array<{ tx_hash: string; height: number }>;
    try { history = await client.getHistory(getHTLCScripthash(redeemScript), 'a914' + bytesToHex(hash160(redeemScript)) + '87'); }
    catch { return false; } // transient read error — never wipe
    const entry = history.find((h) => typeof h?.tx_hash === 'string' && h.tx_hash.toLowerCase() === claimTxid && Number.isInteger(h.height) && h.height > 0);
    if (!entry) return false; // 0-conf / absent — KEEP
    return this.spvReorgSafe(client, this.theirChain, claimTxid, entry.height, rec.claimTx?.rawTx, reqConf);
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
      // If the refund is not yet confirmed it may have DROPPED from the mempool — resubmit the exact durable refund
      // tx (idempotent) so §9.7 refund-reachability is not one-shot. This branch returns before step 4b, so the
      // resubmit MUST run here or it is never reached on a resume where a refund is in flight.
      if (r.finalized) { this.setResumeGate('refund-finalized'); return; }
      // R-UTXO-REFUNDRACE-001 (B2): the refund did not finalize — before treating it as merely pending, check whether
      // it LOST the race to the counterparty's secret-revealing claim of our leg Y (S now public). If so, recover S +
      // claim leg X rather than forever short-circuiting on 'refund-in-flight'.
      if (await this.recoverUtxoRefundRace()) { this.setResumeGate('refund-race-recovered'); return; }
      await this.rebroadcastRefundIfDropped();
      this.setResumeGate('refund-in-flight');
      return; // refund-first short-circuit: a refund is in flight — do NOT also route to a claim / fund gate
    }
    if (await this.deps.durable.get(claimBroadcastKey(rec.id))) {
      if (await this.trySettleIfBothLegsSpent()) { this.setResumeGate('settled'); return; }
      // R-EVMCLAIM-REORG-001: confirmClaim + trySettleIfBothLegsSpent both bail for an EVM theirChain, so a
      // reorg-orphaned EVM claim was never finalized OR re-driven. Route it to confirmClaimEvm, which corroborates
      // getSwap.claimed at a buried depth and either finalizes ('completed') or re-broadcasts the orphaned claim.
      if (!!(chainConfigs[this.theirChain] as { isEvm?: boolean } | undefined)?.isEvm) {
        const ce = await this.confirmClaimEvm();
        this.setResumeGate(ce.finalized ? 'claim-finalized' : 'claim-in-flight');
        return;
      }
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
  /**
   * R-FEE-DEADLINE-001: the LIVE, deadline-aware sat/vByte for a UTXO claim/refund (wires the previously-inert
   * fee-rate module into the fund-critical paths). (1) live base rate via fetchFeeRate — the proxy's
   * blockchain.estimatefee (max(mempoolminfee, estimatesmartfee)), floored to the config rate + clamped to
   * maxFeeRate, fail-safe to the floor on any error. (2) scaled UP by deadlineAwareFeeRate as the leg's refund
   * runway (from the AUTHENTICATED redeemScript CLTV + a best-effort tip) approaches CLAIM_MARGIN; a stale/
   * under-reported tip only shrinks the multiplier toward the live base, never below it (a lying proxy can't
   * underprice below the live network rate). Without this the tx builds at the STATIC config rate and, on a
   * fee-volatile chain (BTC/BCH) during a sustained spike, the secret-revealing claim can enter the mempool but
   * not confirm inside the reveal margin → the counterparty refunds one leg and claims the other = double-loss.
   */
  private async legAwareFeeRate(client: SwapChainClient, chain: Chain, redeemScript: Uint8Array): Promise<number> {
    const base = await fetchFeeRate(chain, async () => {
      try {
        const r = await client.request<{ satPerByte?: number }>('blockchain.estimatefee', []);
        return (r && typeof r.satPerByte === 'number') ? r.satPerByte : null;
      } catch { return null; }
    });
    let remainingSec: number | undefined;
    try {
      const cpLock = parseHtlcCltv(redeemScript);
      if (cpLock != null) {
        const hdr = await client.request<{ height: number; hex: string }>('blockchain.headers.subscribe', []);
        if (cpLock >= 500_000_000) {
          const now = parseHeaderTimeSec(hdr?.hex ?? '');
          if (now != null) remainingSec = cpLock - now;
        } else if (hdr && Number.isInteger(hdr.height)) {
          remainingSec = (cpLock - hdr.height) * (chainConfigs[chain]?.avgBlockTimeSec ?? 600);
        }
      }
    } catch { /* best-effort ramp: on any read failure keep the live base rate (already the primary protection) */ }
    return (remainingSec != null && Number.isFinite(remainingSec))
      ? deadlineAwareFeeRate(chain, base, remainingSec, CLAIM_MARGIN_SEC)
      : base;
  }

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
    // R-FEE-DEADLINE-001: build the secret-revealing claim at the LIVE, deadline-aware rate (not the static config
    // rate) so it confirms inside the reveal margin during a fee spike.
    const feeRate = await this.legAwareFeeRate(client, chain, redeemScript);
    const tx = await claimHTLC(authed, redeemScript, secret, sk.privateKey, sk.publicKey, destPkh, chain, feeRate);
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

  // ============================================================================================================
  // EVM PARITY (P1b step 7) — the EVM fund-critical half: the EVM reveal + the refund-race secret recovery.
  //
  // The two GATE minters (assertEvmLegBuriedForFunding quorum>=2 -> FundProof; assertEvmRevealSafe quorum>=2 ->
  // RevealAuthorization) already exist + are verified in gates.ts; these methods drive them over the injected
  // quorum>=2 `evmProviderFor` provider and the injected `evmSignerFor` Node ethers.Wallet, and call the proven
  // on-chain handlers (lockETH/lockTokens/claimSwap/refundSwap) from evm-client.ts. Same three corrections as the
  // UTXO half: fix #2 (RE-MINT the gate FRESH at the broadcast choke point — never trust the passed proof's
  // captured values), fix #4 (durable-before-broadcast), fix #10 (assertIrreversibleAllowed on every irreversible
  // broadcast). PLUS fix #7 (the refund-race Claimed-event recovery corroborated across quorum>=2 leaves).
  // ============================================================================================================

  // ── EVM seams + small resolvers ──────────────────────────────────────────────────────────────────────────

  /** The injected quorum>=2 EVM read Provider for `chain` (the EVM GATE surface). Fail closed if not injected. */
  private evmProvider(chain: Chain): Provider {
    if (!this.deps.evmProviderFor) throw new Error('EVM provider factory (evmProviderFor) is not injected — cannot run the EVM leg');
    return this.deps.evmProviderFor(chain);
  }
  /** The injected EVM Signer (a Node ethers.Wallet from the seed) for `chain`. Fail closed if not injected. */
  private evmSigner(chain: Chain): Signer {
    if (!this.deps.evmSignerFor) throw new Error('EVM signer factory (evmSignerFor) is not injected — cannot sign the EVM leg');
    return this.deps.evmSignerFor(chain);
  }

  /** Resolve `chain` -> its numeric EvmChainId + the canonical EVM config (htlcAddress, requiredConfirmations, lock
   *  bounds). Fail closed if `chain` is not an EVM chain or has no deployed config. */
  private evmCfgFor(chain: Chain): { evmChainId: EvmChainId; cfg: EvmChainConfig; htlcAddr: string } {
    const cc = chainConfigs[chain] as { isEvm?: boolean; evmChainId?: number } | undefined;
    if (!cc || !cc.isEvm || !Number.isInteger(cc.evmChainId)) {
      throw new Error(`EVM leg: chain '${chain}' is not an EVM chain — cannot run the EVM path`);
    }
    const evmChainId = cc.evmChainId as EvmChainId;
    const cfg = getEvmConfig(evmChainId);
    if (!cfg) throw new Error(`EVM leg: no EVM config for chain '${chain}' (chainId ${evmChainId})`);
    const htlcAddr = cfg.htlcAddress;
    if (!/^0x[0-9a-fA-F]{40}$/.test(htlcAddr) || htlcAddr.toLowerCase() === NATIVE_ETH_ADDR) {
      throw new Error(`EVM leg: no deployed HTLC contract for chain '${chain}' (chainId ${evmChainId})`);
    }
    return { evmChainId, cfg, htlcAddr };
  }

  /** FIX #10 §5(#10): carry EVM amounts as base-unit strings — never `Number()` an 18-dec (wei) value. Accept a
   *  decimal-integer base-unit string (canonical) or a legacy safe-integer number; throw on anything else. */
  private evmAmountBaseUnits(raw: string | number | undefined, label: string): bigint {
    if (typeof raw === 'number') {
      if (!Number.isSafeInteger(raw) || raw <= 0) throw new Error(`${label}: invalid EVM amount '${String(raw)}'`);
      return BigInt(raw);
    }
    const s = (raw ?? '').trim();
    if (!/^[0-9]+$/.test(s)) {
      throw new Error(`${label}: EVM amount '${String(raw)}' is not an integer base-unit string — refusing (fix #10: never Number() an 18-dec value)`);
    }
    const b = BigInt(s);
    if (b <= 0n) throw new Error(`${label}: EVM amount must be > 0 (got ${s})`);
    return b;
  }

  /** The offer secretHash as a 0x-prefixed bytes32 (the on-chain hashLock). Fail closed if malformed. */
  private hashLock0x(label: string): string {
    const h = (this.record.offer.secretHash ?? '').toLowerCase().replace(/^0x/, '');
    if (!HEX64.test(h)) throw new Error(`${label}: offer.secretHash is not a 32-byte hex hash — cannot bind the EVM hashLock`);
    return '0x' + h;
  }

  /** Resolve the COUNTERPARTY EVM leg (the leg WE verify/claim on theirChain): htlc addr, swapId, requiredConfirmations,
   *  hashLock, the recipient (= OUR EVM address, who may claim it), minAmount (what we receive), and its token. */
  private counterpartyEvmLeg(label: string): {
    evmChainId: EvmChainId; htlcAddr: string; requiredConfirmations: number; swapId: string;
    hashLock: string; recipient: string; minAmount: bigint; token: string;
  } {
    const { evmChainId, cfg, htlcAddr } = this.evmCfgFor(this.theirChain);
    const swapId = (this.record.counterpartyEvmSwapId ?? '').toLowerCase();
    if (!BYTES32_0X.test(swapId)) throw new Error(`${label}: no valid counterparty EVM swapId recorded — cannot verify/claim the EVM leg`);
    const recipient = (this.record.myEvmAddress ?? '');
    if (!ethers.isAddress(recipient)) throw new Error(`${label}: our EVM address (myEvmAddress) is missing/invalid — cannot bind the claim recipient`);
    const token = (this.record.counterpartyEvmToken ?? this.record.offer.evmInfo?.tokenAddress ?? '');
    if (!ethers.isAddress(token)) throw new Error(`${label}: counterparty EVM token address is missing/invalid — cannot bind the token`);
    // R-EVMTOKEN-ALLOWLIST-001: bind the offer token to a canonically-configured token (symbol<->address). The
    // finality gate below binds lock.token === this token, but this token is the UNTRUSTED offer field, so without
    // an allowlist a maker could advertise+lock an attacker-chosen token (worthless / fee-on-transfer / rebasing /
    // ERC-777) and pass the self-referential gate — leaving us to fund a real leg against a leg that pays back junk.
    assertCanonicalEvmToken(evmChainId, token, this.record.offer.evmInfo?.tokenSymbol);
    // What WE receive from the counterparty leg: initiator claims leg Y (offer.receiveAmount); responder claims leg X
    // (offer.sendAmount). The gate binds `minAmount` so we never reveal/commit against an under-funded lock.
    const rawAmt = this.role === 'initiator' ? this.record.offer.receiveAmount : this.record.offer.sendAmount;
    const minAmount = this.evmAmountBaseUnits(rawAmt, label);
    return {
      evmChainId, htlcAddr, requiredConfirmations: Math.max(1, cfg.requiredConfirmations),
      swapId, hashLock: this.hashLock0x(label), recipient, minAmount, token,
    };
  }

  // ── (1) verifyEvmCounterpartyLegForFunding -> FundProof (responder-only) ──────────────────────────────────

  /**
   * RESPONDER-ONLY. Mint a `FundProof` by proving the counterparty (initiator) EVM leg is locked at a reorg-safe
   * depth with all invariants bound (gates.assertEvmLegBuriedForFunding over the injected quorum>=2 provider). The
   * ONLY controller-side minter of an EVM `FundProof`. Grounds in verifyEvmCounterpartyHTLC (SwapExecute.tsx
   * ~3055-3460): the responder-fund gate re-asserts DEPTH + {hashLock, recipient, minAmount, minTimeLock, token} and
   * fails closed (quorum>=2) before the responder commits its own leg. Returns the branded proof or THROWS
   * (mints nothing) — including refusing a single-leaf provider (fix #7/#1, done inside the gate).
   */
  async verifyEvmCounterpartyLegForFunding(): Promise<FundProof> {
    this.assertLive();
    if (this.record.role !== 'responder') {
      throw new Error('verifyEvmCounterpartyLegForFunding: responder-only (the initiator does not fund against a FundProof)');
    }
    const leg = this.counterpartyEvmLeg('verifyEvmCounterpartyLegForFunding');
    const provider = this.evmProvider(this.theirChain); // the counterparty EVM leg lives on theirChain
    return assertEvmLegBuriedForFunding(provider, {
      chain: this.theirChain,
      htlcAddr: leg.htlcAddr,
      swapId: leg.swapId,
      requiredConfirmations: leg.requiredConfirmations,
      hashLock: leg.hashLock,
      recipient: leg.recipient,
      minAmount: leg.minAmount,
      token: leg.token,
    });
  }

  // ── (2) verifyEvmCounterpartyLegForReveal -> RevealAuthorization (initiator-only) ─────────────────────────

  /**
   * INITIATOR-ONLY. Mint a `RevealAuthorization` by proving the counterparty (responder) EVM leg is at a reorg-safe
   * depth AND keeps >= 4h (EVM_CLAIM_MARGIN_SEC) runway on its FRESH on-chain timeLock (gates.assertEvmRevealSafe,
   * quorum>=2). The ONLY controller-side minter of an EVM `RevealAuthorization`. Grounds in handleEvmClaim gate #2 +
   * the R258/R260/R261/R278 margin re-check (SwapExecute.tsx ~2128-2258). Returns the branded auth or THROWS — the
   * secret NEVER leaks on any failure (this only READS the chain; it does not touch the secret).
   */
  async verifyEvmCounterpartyLegForReveal(): Promise<RevealAuthorization> {
    this.assertLive();
    if (this.record.role !== 'initiator') {
      throw new Error('verifyEvmCounterpartyLegForReveal: initiator-only (only the initiator makes the irreversible secret reveal)');
    }
    const leg = this.counterpartyEvmLeg('verifyEvmCounterpartyLegForReveal');
    const provider = this.evmProvider(this.theirChain);
    return assertEvmRevealSafe(provider, {
      chain: this.theirChain,
      htlcAddr: leg.htlcAddr,
      swapId: leg.swapId,
      requiredConfirmations: leg.requiredConfirmations,
      hashLock: leg.hashLock,
      recipient: leg.recipient,
      minAmount: leg.minAmount,
      token: leg.token,
    });
  }

  /** FIX #2 re-mint used by lockEvm at the broadcast choke point: re-prove the counterparty leg is buried FRESH. Uses
   *  the EVM gate when the counterparty leg is EVM, else the UTXO gate — either throws (aborting the lock) on any doubt. */
  private async reverifyCounterpartyLegForFunding(): Promise<void> {
    const theirIsEvm = !!(chainConfigs[this.theirChain] as { isEvm?: boolean } | undefined)?.isEvm;
    if (theirIsEvm) { await this.verifyEvmCounterpartyLegForFunding(); }
    else { await this.verifyCounterpartyLegForFunding(); }
  }

  // ── (3) lockEvm(proof) — lock OUR OWN EVM leg (responder/initiator) ───────────────────────────────────────

  /**
   * Lock OUR OWN EVM leg (lockETH or lockTokens per isNativeToken) with the injected Node signer. STRUCTURALLY
   * requires a `FundProof` (compile-time — the two brands are non-interchangeable, fix #1). Grounds in handleEvmFund
   * (SwapExecute.tsx ~1089-1360).
   *   FIX #2 (zero proof-reuse window): inside the fund mutex, at the choke point, RE-MINT the counterparty-leg burial
   *     FRESH (assertEvmLegBuriedForFunding) — never the passed proof's captured values. A fresh throw ABORTS before
   *     any lock tx is broadcast.
   *   FIX #4 (durable-before-broadcast): the lockpending + evmlocktx recovery markers are committed durably in the
   *     lock's onBroadcast callback — the instant the tx is broadcast (before it mines) — because the EVM lock is
   *     irreversible once mined; the funded=swapId sentinel is committed the moment the lock resolves with its id.
   *   FIX #10: gated by assertIrreversibleAllowed. Single-flight (fix #3) under mutex.withLock; a prior funded swapId
   *     is ADOPTED rather than re-locked (a second on-chain lock would strand a fresh per-nonce swapId). Handles the
   *     onBroadcast-replacement hash (a MetaMask speed-up; a Node signer typically won't) by capturing the final hash.
   */
  async lockEvm(proof: FundProof): Promise<{ swapId: string; txHash: string }> {
    this.assertLive();
    const rec = this.record;
    // `proof` is required at the TYPE level (safe-by-default). Its captured facts may only ever FAIL a lock, never
    // license skipping the fresh re-mint below (fix #2) — a structural brand touch keeps it load-bearing.
    if (proof.leg !== 'X' || proof.for !== 'fundY') {
      throw new Error('lockEvm: the supplied FundProof is not a leg-X fund authorization — refusing to lock');
    }
    this.assertIrreversibleAllowed('lockEvm'); // fix #10
    if (rec.phase !== 'taken' && rec.phase !== 'prepared') {
      throw new Error(`lockEvm: unexpected phase '${rec.phase}' — the EVM lock runs from 'taken' or 'prepared'`);
    }
    if (isSwapPairSuspended(this.myChain, this.theirChain)) {
      throw new Error(`lockEvm: swap pair ${this.myChain}/${this.theirChain} is suspended — refusing to lock`);
    }
    const { evmChainId, cfg, htlcAddr } = this.evmCfgFor(this.myChain); // our own EVM leg lives on myChain
    const recipient = (rec.counterpartyEvmAddress ?? '');
    if (!ethers.isAddress(recipient)) throw new Error('lockEvm: counterparty EVM recipient address (counterpartyEvmAddress) is missing/invalid — cannot lock');
    const token = (rec.myEvmToken ?? rec.offer.evmInfo?.tokenAddress ?? '');
    if (!ethers.isAddress(token)) throw new Error('lockEvm: our EVM token address is missing/invalid — cannot lock');
    // R-EVMTOKEN-ALLOWLIST-001: our own lock must also be a canonically-configured token — never lock (or let the
    // counterparty be told we locked) an unrecognized/scam token. Symbol<->address bound against local config.
    assertCanonicalEvmToken(evmChainId, token, rec.offer.evmInfo?.tokenSymbol);
    // OUR leg amount: initiator locks offer.sendAmount, responder locks offer.receiveAmount (base units).
    const amount = this.evmAmountBaseUnits(this.role === 'initiator' ? rec.offer.sendAmount : rec.offer.receiveAmount, 'lockEvm');
    const hashLock = this.hashLock0x('lockEvm');
    const signer = this.evmSigner(this.myChain);
    const targetPhase: 'initiator_funded' | 'responder_funded' = this.role === 'initiator' ? 'initiator_funded' : 'responder_funded';

    const lockName = `bch2swap:fund:${rec.id}`;
    let lockBlockNum: number | null = null; // R-EVMLOCKBLOCK-001: captured inside the lock closure, read by the record update (stays null on the adopt path)
    const outcome = await this.deps.mutex.withLock(lockName, async (): Promise<{ swapId: string; txHash: string; adopted: boolean }> => {
      // Adopt a prior on-chain lock (the durable funded sentinel holds the bytes32 swapId) rather than double-locking.
      const prior = (await this.deps.durable.get(fundedKey(rec.id)))?.toLowerCase();
      if (prior && BYTES32_0X.test(prior)) return { swapId: prior, txHash: '', adopted: true };

      // FIX #4 (EVM double-lock): the funded sentinel above is written only AFTER the lock RESOLVES — but the
      // lockpending / evmlocktx recovery markers are written the instant the lock is BROADCAST (before it mines). A
      // re-call after the broadcast but before the funded sentinel lands must NOT re-lock (a second on-chain lock under
      // a fresh per-nonce swapId strands the first). Read those markers + recoverLockFromTx (quorum-corroborated) over
      // the recorded lock tx: ADOPT a prior lock ('locked' -> commit the funded sentinel, return its swapId, NO second
      // lock), or REFUSE while its disposition is uncertain ('blocked' / a pending marker with no tx hash yet — a
      // re-lock could double-lock). Only a definitive 'safe' (the prior lock dropped/reverted — moved no funds) falls
      // through to a fresh lock below.
      const pendingMarker = await this.deps.durable.get(lockPendingKey(rec.id));
      if (pendingMarker) {
        const markedHash = await this.deps.durable.get(evmLockTxKey(rec.id));
        const lockTxHash = (markedHash && BYTES32_0X.test(markedHash.toLowerCase())) ? markedHash.toLowerCase()
          : (BYTES32_0X.test(pendingMarker.toLowerCase()) ? pendingMarker.toLowerCase() : null);
        if (!lockTxHash) {
          // A pre-broadcast sentinel with no real tx hash yet: the lock may already be in the mempool. Fail closed.
          throw new Error('lockEvm: a prior EVM lock is in-flight (pending marker set, tx hash not yet recorded) — refusing to re-lock (would risk a double-lock); retry once it resolves (fix #4)');
        }
        const readProvider = this.evmProvider(this.myChain);
        let sender = '';
        try { sender = await signer.getAddress(); } catch { sender = ''; }
        let recovery: { kind: 'locked'; swapId: string } | { kind: 'safe' | 'blocked' };
        try {
          recovery = await recoverLockFromTx(htlcAddr, lockTxHash, readProvider, {
            sender, hashLock, recipient, minAmount: amount, fromBlock: rec.evmLockBlock,
          });
        } catch { recovery = { kind: 'blocked' }; }
        if (recovery.kind === 'locked') {
          // The prior lock is on-chain (authenticated Locked event, quorum-corroborated) — ADOPT it, no second lock.
          await this.deps.durable.commit([[fundedKey(rec.id), recovery.swapId.toLowerCase()]]);
          await this.deps.durable.remove(lockPendingKey(rec.id));
          return { swapId: recovery.swapId, txHash: lockTxHash, adopted: true };
        }
        if (recovery.kind === 'blocked') {
          throw new Error('lockEvm: a prior EVM lock tx is still pending / its disposition is indeterminate — refusing to re-lock (would risk a double-lock + strand); retry once it resolves (fix #4)');
        }
        // recovery.kind === 'safe': the prior lock never landed (dropped / reverted, moved no funds) — re-lock is safe.
      }

      // FIX #2: re-mint the counterparty-leg burial FRESH at the broadcast choke point. A throw ABORTS the lock.
      this.status('lockEvm:reverifying-counterparty');
      await this.reverifyCounterpartyLegForFunding();

      // R-EVMTOKEN-ALLOWANCE-001: an ERC-20 lock's transferFrom needs a prior allowance; this ported lockEvm dropped
      // the approve step the UI's handleEvmFund performs, so every fresh-signer stablecoin lock reverted (fails
      // closed, no fund loss, but the documented USDC/USDT path never worked through the SDK). Establish it here —
      // BEFORE the lockpending recovery sentinel is written below — so an approve failure throws with NO sentinel set
      // and the retry stays clean (placing it after the sentinel would wedge a failed approve as 'lock in-flight').
      // Native skips (msg.value carries the funds). ensureAllowance is self-hardened (owner==signer, spender==canonical
      // HTLC, undeployed-chain reject, timeouts) and broadcasts only a prerequisite approve that moves no HTLC funds.
      if (!isNativeToken(token)) {
        this.status('lockEvm:ensuring-allowance');
        const owner = await signer.getAddress();
        await ensureAllowance(token, owner, htlcAddr, amount, signer, this.evmProvider(this.myChain), evmChainId);
      }

      // The unix-timestamp timeLock is derived from the FRESH on-chain block clock (never the local clock) + the
      // role's wall-clock-normalized lock duration (evmLockSecondsForRole) — mirrors handleEvmFund ~1416-1460.
      let nowSec: number | null = null;
      try {
        const b = await (signer.provider as Provider | null)?.getBlock('latest');
        if (b && Number.isFinite(b.timestamp)) nowSec = Number(b.timestamp);
        if (b && Number.isInteger(b.number)) lockBlockNum = Number(b.number);
      } catch { nowSec = null; }
      if (nowSec === null) throw new Error('lockEvm: could not read the EVM chain clock to set the lock timeLock — not locking; retry');
      const timeLock = BigInt(nowSec + evmLockSecondsForRole(cfg, this.role));

      // FIX #5 (durable-before-broadcast): write the lockpending recovery marker BEFORE the irreversible lock
      // broadcast — committed + AWAITED — so a commit failure ABORTS the lock (funds never move without a durable
      // recovery record). The EXACT tx hash is not known until broadcast, so this pre-broadcast marker is a sentinel;
      // onBroadcast refines it with the real hash below. A commit throw here aborts BEFORE any lock tx is broadcast.
      this.status('lockEvm:committing-recovery-marker');
      await this.deps.durable.commit([[lockPendingKey(rec.id), LOCK_PENDING_SENTINEL]]);

      // FIX #5: record the recovery markers the INSTANT the lock is broadcast (onBroadcast fires before the tx mines).
      // The commit is tracked + AWAITED after the lock resolves (below) instead of being fire-and-forget — the
      // pre-broadcast marker above already guarantees recoverability, so this real-hash refinement is best-effort and
      // must NOT fail an already-broadcast lock. A Node signer won't fire a replacement; a speed-up re-fires the hash.
      let finalHash = '';
      let onBroadcastCommit: Promise<void> | null = null;
      const onBroadcast = (h: string): void => {
        finalHash = h;
        onBroadcastCommit = this.deps.durable.commit([[lockPendingKey(rec.id), h], [evmLockTxKey(rec.id), h]]);
      };

      this.status('lockEvm:broadcasting');
      const swapId = isNativeToken(token)
        ? await lockETH(htlcAddr, recipient, amount, hashLock, timeLock, signer, evmChainId, onBroadcast)
        : await lockTokens(htlcAddr, recipient, token, amount, hashLock, timeLock, signer, evmChainId, onBroadcast);
      // Await the real-hash marker refinement (no longer fire-and-forget). Best-effort: the lock is already broadcast,
      // so a failure here must not throw — the pre-broadcast sentinel keeps the swap recoverable regardless.
      if (onBroadcastCommit) { try { await onBroadcastCommit; } catch { /* best-effort real-hash refinement */ } }

      // The lock mined with a known swapId: commit funded=swapId (durable single-flight sentinel) + clear lockpending.
      await this.deps.durable.commit([[fundedKey(rec.id), swapId.toLowerCase()]]);
      await this.deps.durable.remove(lockPendingKey(rec.id));
      return { swapId, txHash: finalHash, adopted: false };
    });

    this.record = {
      ...this.record, myEvmSwapId: outcome.swapId, myFundingTxid: outcome.swapId, funded: true,
      // R-EVMLOCKBLOCK-001: persist the lock's block floor so readEvmClaimedSecret scans [lockBlock, tip] instead of
      // the tip-anchored [tip-90000, tip] window — the latter is only ~6-7h on a sub-second chain (Arbitrum) and
      // would slide past an early Claimed event, stranding the responder's secret recovery.
      ...(lockBlockNum !== null ? { evmLockBlock: lockBlockNum } : {}),
    };
    this.setPhase(targetPhase);
    this.status('lockEvm:locked');
    await this.persistRecord();
    return { swapId: outcome.swapId, txHash: outcome.txHash };
  }

  // ── (4) revealAndClaimEvm(auth) — the INITIATOR reveals S by claiming the counterparty EVM leg ────────────

  /**
   * The initiator's ONE irreversible EVM action: reveal S by claiming the counterparty (responder) EVM leg with S in
   * the claim calldata (evmClaimSwap = claimSwap). STRUCTURALLY requires a `RevealAuthorization` (compile-time).
   * Grounds in handleEvmClaim (SwapExecute.tsx ~2128-2430).
   *   FIX #3: throw unless `auth.role === 'initiator'` — a margin-skipped responder authorization must NEVER drive the
   *     initiator's reveal.
   *   FIX #2: inside the claim mutex at the broadcast choke point, RE-MINT assertEvmRevealSafe FRESH (quorum>=2 depth +
   *     the 4h margin re-derived from the FRESH on-chain timeLock) — never the passed auth's captured values. A throw
   *     ABORTS; S is never sent. (claimSwap itself also re-checks sha256(S)===hashLock + expiry + recipient before it
   *     broadcasts, so S never reaches calldata on a bad claim — defense in depth.)
   *   FIX #4: a durable `claimbroadcast` sentinel is committed BEFORE the secret-revealing claim; a second call /
   *     crash-resume ADOPTS instead of re-revealing. FIX #10: gated by assertIrreversibleAllowed. R181 cross-guard:
   *     refuses to reveal while a refund is in flight. Transitions `responder_funded -> claimed`.
   */
  async revealAndClaimEvm(auth: RevealAuthorization): Promise<{ txHash: string }> {
    this.assertLive();
    const rec = this.record;
    if (rec.role !== 'initiator') {
      throw new Error('revealAndClaimEvm: only the initiator reveals the secret (the responder uses watchForClaimEvm/claimWithKnownSecret)');
    }
    // FIX #3: a responder-role authorization (which SKIPS the 4h claim margin) must never drive the initiator's reveal.
    if (auth.role !== 'initiator' || auth.leg !== 'Y' || auth.for !== 'reveal') {
      throw new Error('revealAndClaimEvm: the supplied authorization is not an initiator leg-Y reveal authorization — refusing to reveal the secret (fix #3)');
    }
    // R-EVMCLAIM-REORG-001: adopt ONLY when the claim is CORROBORATED on-chain (getSwap.claimed). A claim confirmed at
    // 1-conf then ORPHANED by a reorg (the very risk requiredConfirmations exists for) leaves the sentinel set while
    // the lock is funded again (claimed=false); adopting on the local sentinel alone would falsely report success and
    // NEVER re-broadcast — the responder takes the other leg with the public S and we lose both (§6 CASE B). If the
    // sentinel is set but getSwap says NOT claimed (orphaned, or not yet mined), clear it and re-drive the claim below
    // (S is already public here, so re-revealing leaks nothing new).
    if (await this.deps.durable.get(claimBroadcastKey(rec.id))) {
      const legAdopt = this.counterpartyEvmLeg('revealAndClaimEvm');
      if (await this.evmSwapIsClaimed(this.evmProvider(this.theirChain), legAdopt.htlcAddr, legAdopt.swapId)) {
        this.status('revealAndClaimEvm:adopted');
        return { txHash: (rec.myClaimTxid ?? legAdopt.swapId) };
      }
      try { await this.deps.durable.remove(claimBroadcastKey(rec.id)); } catch { /* best-effort */ }
      this.status('revealAndClaimEvm:re-driving-orphaned-claim');
    }
    this.assertIrreversibleAllowed('revealAndClaimEvm'); // fix #10
    if (await this.deps.durable.get(refundBroadcastKey(rec.id))) {
      throw new Error('revealAndClaimEvm: a refund is already in flight — refusing to reveal the secret (R181 cross-guard)');
    }
    if (rec.phase !== 'responder_funded' && rec.phase !== 'claimed') {
      throw new Error(`revealAndClaimEvm: unexpected phase '${rec.phase}' — reveal runs from 'responder_funded'`);
    }
    const leg = this.counterpartyEvmLeg('revealAndClaimEvm');
    const secret = await this.loadInitiatorSecret();
    if (!secret || secret.length !== 32) {
      throw new Error('revealAndClaimEvm: the swap secret is not available (vault locked / not re-derivable) — cannot reveal');
    }
    const provider = this.evmProvider(this.theirChain);
    const signer = this.evmSigner(this.theirChain);

    const lockName = `bch2swap:claim:${rec.id}`;
    const result = await this.deps.mutex.withLock(lockName, async (): Promise<{ swapId: string }> => {
      // Single-flight adopt inside the lock.
      if (await this.deps.durable.get(claimBroadcastKey(rec.id))) return { swapId: leg.swapId };
      // R181 re-check inside the lock (a refund could have raced in).
      if (await this.deps.durable.get(refundBroadcastKey(rec.id))) {
        throw new Error('revealAndClaimEvm: a refund became active — refusing to reveal the secret');
      }
      // FIX #2: RE-MINT the reveal authorization from a FRESH read (quorum>=2 depth + 4h margin off the FRESH on-chain
      // timeLock). A throw ABORTS here — S is never broadcast.
      this.status('revealAndClaimEvm:reverifying');
      await assertEvmRevealSafe(provider, {
        chain: this.theirChain, htlcAddr: leg.htlcAddr, swapId: leg.swapId,
        requiredConfirmations: leg.requiredConfirmations, hashLock: leg.hashLock,
        recipient: leg.recipient, minAmount: leg.minAmount, token: leg.token,
      });
      // Durable-before-broadcast (fix #4): set the winning-claim sentinel BEFORE the secret-revealing claim.
      this.status('revealAndClaimEvm:committing');
      await this.deps.durable.commit([[claimBroadcastKey(rec.id), '1']]);
      // Reveal S. Pass a COPY — claimSwap zeroes its input buffer at submit, and we must not wipe our in-memory S
      // (the responder-side / finalizer paths still need it until the claim is reorg-safe). FIX #3: a PRE-broadcast
      // claimSwap throw (pre-flight getSwap/getBlock/timeout/chain-mismatch — no secret revealed) CLEARS the sentinel
      // we just set so a retry can re-arm; a post-broadcast/ambiguous failure LEAVES it set (R201 fail-safe).
      this.status('revealAndClaimEvm:broadcasting');
      await this.claimEvmWithSentinelGuard(leg.htlcAddr, leg.swapId, secret.slice(), signer, leg.evmChainId);
      return { swapId: leg.swapId };
    });

    // claimSwap surfaces { blockNumber }, not a tx hash, so we key the durable claim identity off the swapId.
    this.record = { ...this.record, myClaimTxid: result.swapId };
    this.setPhase('claimed');
    this.status('revealAndClaimEvm:claimed');
    await this.persistRecord();
    return { txHash: result.swapId };
  }

  // ── (5) refundEvm() — refund OUR OWN EVM lock, with the refund-race secret-recovery pivot (fix #7) ─────────

  /**
   * Refund OUR OWN EVM lock (evmRefundSwap = refundSwap) after its timelock. §9.7: reachable after expiry (suspension
   * never gates a refund). A durable `refundbroadcast` sentinel is committed BEFORE the send (durable-before-broadcast)
   * under the shared claim/refund single-flight lock, so a claim and a refund can never race.
   *
   * THE REFUND-RACE PIVOT (fund-loss-critical, fix #7): if refundSwap REVERTS because the counterparty ALREADY CLAIMED
   * our lock (took it with S), we do NOT treat that as a plain error. S is now PUBLIC in the on-chain `Claimed` event,
   * so we RECOVER it — corroborated across quorum>=2 leaves (never conclude "safe to abandon" while an honest leaf may
   * still yield S), verify sha256(S)===hashLock (the authenticator), and use S to CLAIM the OTHER (counterparty) leg so
   * we are made whole. Grounds in the 'already claimed' branch (SwapExecute.tsx:2423) + watchForClaim/watchAndRefund.
   */
  async refundEvm(): Promise<{ txHash: string }> {
    this.assertLive();
    const rec = this.record;
    const { evmChainId, htlcAddr } = this.evmCfgFor(this.myChain); // our own EVM leg lives on myChain
    void evmChainId;
    const swapId = (rec.myEvmSwapId ?? '').toLowerCase();
    if (!BYTES32_0X.test(swapId)) throw new Error('refundEvm: no valid own EVM swapId (myEvmSwapId) recorded — nothing to refund');
    this.assertIrreversibleAllowed('refundEvm'); // fix #10
    // FIX #2: if a refund-race recovery is already pending (our lock was CLAIMED, S not yet extractable), RE-ENTER
    // recovery straight away — never send a fresh refund, and never let the refund sentinel be adopted as a completed
    // refund below (which would strand the other leg we are owed). Cleared only once S is recovered + that leg claimed.
    if (await this.deps.durable.get(refundRacePendingKey(rec.id))) {
      this.status('refundEvm:refund-race-pending');
      return await this.recoverFromRefundRace(htlcAddr, swapId);
    }
    // R181 cross-guard (pre-check; re-checked inside the shared lock): never refund while OUR claim is in flight.
    if (await this.deps.durable.get(claimBroadcastKey(rec.id))) {
      throw new Error('refundEvm: a claim is already in flight — refusing to refund while a claim is active (R181 cross-guard)');
    }
    const signer = this.evmSigner(this.myChain);
    const lockName = `bch2swap:claim:${rec.id}`;
    let outcome: { refunded: boolean };
    try {
      outcome = await this.deps.mutex.withLock(lockName, async (): Promise<{ refunded: boolean }> => {
        // Adopt a prior refund (already broadcast) rather than double-broadcasting — but FIX #4: only FINALIZE as
        // 'refunded' if it actually refunded ON-CHAIN. An unconfirmed / dropped prior refund must NOT be reported as
        // a completed refund (getSwap.refunded is the trust anchor; fail-closed to not-refunded on any read error).
        if (await this.deps.durable.get(refundBroadcastKey(rec.id))) {
          return { refunded: await this.evmSwapIsRefunded(signer.provider as Provider | null, htlcAddr, swapId) };
        }
        if (await this.deps.durable.get(claimBroadcastKey(rec.id))) {
          throw new Error('refundEvm: a claim became active — refusing to refund');
        }
        // Durable-before-broadcast (§9.7): set the refundbroadcast sentinel BEFORE the send. refundSwap re-checks the
        // timelock/initiator/claimed state on-chain and RETURNS ONLY on a CONFIRMED refund (receipt.status===1) — else
        // it THROWS. So reaching the return below means the refund is genuinely confirmed (fix #4).
        this.status('refundEvm:committing');
        await this.deps.durable.commit([[refundBroadcastKey(rec.id), '1']]);
        this.status('refundEvm:broadcasting');
        await refundSwap(htlcAddr, swapId, signer);
        return { refunded: true };
      });
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      // THE PIVOT (fix #7 parity, R184): the refund reverted because the counterparty already CLAIMED our lock (S is
      // now public on-chain). Widened to match the contract-revert claim signals ('claimed before refund' / 'secret
      // is on-chain') as well as the pre-flight 'already claimed' / 'was claimed'.
      if (/already claimed|was claimed|claimed before refund|secret is on-chain/i.test(msg)) {
        return await this.recoverFromRefundRace(htlcAddr, swapId);
      }
      // A definitively-no-funds-moved failure — clear the sentinel we set so a later retry can re-arm. Covers the
      // PRE-broadcast reverts (not refundable yet / not ours / already refunded / unreadable clock) AND (fix #4) the
      // definitive post-broadcast no-funds-moved outcomes: a 'dropped from mempool' refund (never landed) and the
      // contract-revert 'timelock may not have expired'. FIX #5: ALSO clear when refundSwap tagged the throw
      // `preBroadcast:true` — a TRANSIENT pre-flight timeout (getSwap / getAddress / getBlock read failed before
      // htlc.refund() submitted, so no refund tx exists) that the message-based allowlist above would otherwise MISS,
      // leaving the sentinel set and WEDGING the refund. An AMBIGUOUS post-broadcast failure is left SET (fail-safe).
      const isPreBroadcast = !!(e as { preBroadcast?: boolean } | null)?.preBroadcast;
      if (isPreBroadcast || /not found|not the HTLC initiator|already refunded|Timelock has not expired|timelock may not have expired|dropped from mempool|not a plausible unix|timeLock is zero|could not read latest block/i.test(msg)) {
        try { await this.deps.durable.remove(refundBroadcastKey(rec.id)); } catch { /* best-effort */ }
      }
      throw e;
    }
    // FIX #4: transition to 'refunded' ONLY after a CONFIRMED refund (a fresh confirmed one above, or an adopt that
    // getSwap confirmed on-chain). An adopted-but-unconfirmed prior refund leaves the phase untouched (the reorg-safe
    // finalizer / resume reconcile it) so we never falsely mark 'refunded'.
    if (outcome.refunded) {
      this.setPhase('refunded');
      this.status('refundEvm:broadcast');
    } else {
      this.status('refundEvm:refund-pending');
    }
    await this.persistRecord();
    return { txHash: swapId };
  }

  /** Best-effort on-chain check used by refundEvm's adopt path (fix #4): is OUR own EVM swap actually REFUNDED? Reads
   *  getSwap over the given provider and returns `!!swap.refunded`; fail-closed to `false` on any read error / missing
   *  provider (a not-yet-confirmed / dropped refund must never be finalized as a completed 'refunded'). */
  private async evmSwapIsRefunded(provider: Provider | null, htlcAddr: string, swapId: string): Promise<boolean> {
    if (!provider) return false;
    try { const sw = await getSwap(htlcAddr, swapId, provider); return !!sw?.refunded; }
    catch { return false; }
  }

  /**
   * R-EVMCLAIM-REORG-001: the claim-side analogue of evmSwapIsRefunded — the on-chain trust anchor for whether OUR
   * claim of an EVM leg actually stuck. Reads getSwap.claimed (fail-closed false on any read error or absent swap).
   * Used to corroborate the claimbroadcast sentinel before adopting a claim as final, so a 1-conf claim later orphaned
   * by a reorg is re-driven rather than falsely reported as complete.
   */
  private async evmSwapIsClaimed(provider: Provider | null, htlcAddr: string, swapId: string): Promise<boolean> {
    if (!provider) return false;
    try { const sw = await getSwap(htlcAddr, swapId, provider); return !!sw?.claimed; }
    catch { return false; }
  }

  /**
   * R-EVMCLAIM-REORG-001: the reorg-safe finalizer + orphan re-driver for an EVM theirChain claim (confirmClaim +
   * trySettleIfBothLegsSpent both bail for EVM, so the resume claim branch never finalized/re-drove an EVM claim). It
   * reads getSwap.claimed at a REORG-SAFE depth (tip - reqConf + 1, the same depth basis isEvmLockAtSafeDepth uses for
   * the lock):
   *  - claimed at the buried depth        -> FINALIZE ('claimed' -> 'completed').
   *  - claimed at the tip but not buried  -> KEEP (still finalizing; a later resume finalizes it).
   *  - NOT claimed + the lock still funded (an ORPHANED 1-conf claim, or one that never mined) -> RE-BROADCAST the
   *    claim with the now-public S (skips the reveal margin gate — re-revealing a public S leaks nothing).
   *  - lock gone / refunded / any read error -> KEEP (never finalize or re-drive on doubt).
   * Fail-safe: a spurious re-broadcast at worst reverts on-chain (the contract enforces single-claim) — never a loss.
   */
  private async confirmClaimEvm(): Promise<{ finalized: boolean }> {
    const rec = this.record;
    const theirCfg = chainConfigs[this.theirChain];
    if (!theirCfg || !(theirCfg as { isEvm?: boolean }).isEvm) return { finalized: false };
    if (!(await this.deps.durable.get(claimBroadcastKey(rec.id)))) return { finalized: false };
    let leg: { htlcAddr: string; swapId: string; evmChainId: EvmChainId; requiredConfirmations: number };
    try { leg = this.counterpartyEvmLeg('confirmClaimEvm'); } catch { return { finalized: false }; }
    const provider = this.evmProvider(this.theirChain);
    const reqConf = leg.requiredConfirmations;
    let tip: number;
    try { tip = await provider.getBlockNumber(); } catch { return { finalized: false }; }
    if (!(reqConf > 1 && tip > reqConf)) return { finalized: false }; // too shallow to prove burial — KEEP waiting
    // Reorg-safe: is the claim recorded claimed as-of a buried block?
    let buried: SwapData | null;
    try { buried = await getSwap(leg.htlcAddr, leg.swapId, provider, tip - (reqConf - 1)); } catch { return { finalized: false }; }
    if (buried?.claimed) {
      this.setPhase('completed');
      this.status('confirmClaimEvm:finalized');
      await this.persistRecord();
      return { finalized: true };
    }
    // Not claimed at the buried depth — distinguish "claimed at tip, not yet buried" (KEEP) from "orphaned" (re-drive).
    let now: SwapData | null;
    try { now = await getSwap(leg.htlcAddr, leg.swapId, provider); } catch { return { finalized: false }; }
    if (now?.claimed) return { finalized: false };          // finalizing — will bury on the next pass; KEEP
    if (!now || now.refunded) return { finalized: false };  // lock gone / refunded — not a re-drivable orphaned claim
    // ORPHANED claim (the lock is present + NOT claimed) — re-broadcast the claim with the public S. Best-effort: a
    // failure here (e.g. margin/vault) keeps the state so a later resume retries; never throws out of resume.
    try { await this.reBroadcastOrphanedEvmClaim(leg); } catch { /* best-effort — a later resume retries */ }
    return { finalized: false };
  }

  /**
   * R-EVMCLAIM-REORG-001: re-broadcast an EVM claim that a reorg orphaned. S is already public (the orphaned claim
   * revealed it), so this SKIPS the reveal margin gate (re-revealing leaks nothing) — the initiator's S is re-derived
   * from the seed, the responder's is the in-memory public secret. Re-commits the sentinel around the fresh broadcast.
   */
  private async reBroadcastOrphanedEvmClaim(leg: { htlcAddr: string; swapId: string; evmChainId: EvmChainId }): Promise<void> {
    const rec = this.record;
    const secret = rec.role === 'initiator' ? await this.loadInitiatorSecret() : this.secret;
    if (!secret || secret.length !== 32) throw new Error('reBroadcastOrphanedEvmClaim: S unavailable to re-drive the orphaned EVM claim');
    const signer = this.evmSigner(this.theirChain);
    const lockName = `bch2swap:claim:${rec.id}`;
    await this.deps.mutex.withLock(lockName, async (): Promise<void> => {
      await this.deps.durable.commit([[claimBroadcastKey(rec.id), '1']]);
      this.status('confirmClaimEvm:re-broadcasting-orphaned-claim');
      await this.claimEvmWithSentinelGuard(leg.htlcAddr, leg.swapId, secret.slice(), signer, leg.evmChainId);
    });
  }

  /** Broadcast a UTXO claim, clearing the durable claimbroadcast sentinel ONLY on a DEFINITIVE pre-broadcast node
   *  rejection (the node validated + refused the tx — it never entered any mempool, so the secret is not public and a
   *  retry can rebuild + re-broadcast), so a later call re-arms instead of ADOPTING a never-broadcast claim (fix #3).
   *  An AMBIGUOUS / timeout / post-broadcast failure (the tx MAY have reached a mempool) LEAVES the sentinel set
   *  (R201 fail-safe). The UTXO analogue of claimEvmWithSentinelGuard — same definitive-vs-ambiguous classification. */
  private async broadcastClaimWithSentinelGuard(client: SwapChainClient, rawTx: string, id: string): Promise<void> {
    try {
      await client.broadcastTx(rawTx);
    } catch (e) {
      if (isDefinitiveBroadcastRejection(e)) {
        try { await this.deps.durable.remove(claimBroadcastKey(id)); } catch { /* best-effort */ }
      }
      throw e;
    }
  }

  /**
   * R-UTXO-REFUNDRACE-001 (B1): the refund-path analogue of broadcastClaimWithSentinelGuard. A DEFINITIVE node
   * rejection means no refund reached any mempool — critically 'bad-txns-inputs-missingorspent' (the counterparty
   * already CLAIMED our leg Y, revealing S), where the refund can NEVER succeed. Without clearing the sentinel it
   * would permanently block the responder's ONLY remaining payout — claimWithKnownSecret on leg X (still claimable
   * with the now-public S). Clear it on a definitive rejection (a min-relay-fee rejection also clears safely: the
   * outpoint is still unspent, so a refund retry re-arms and the claim cannot proceed while S is not yet public). An
   * AMBIGUOUS / timeout failure KEEPS the sentinel — the refund may still confirm (fail-safe).
   */
  private async broadcastRefundWithSentinelGuard(client: SwapChainClient, rawTx: string, id: string): Promise<void> {
    try {
      await client.broadcastTx(rawTx);
    } catch (e) {
      if (isDefinitiveBroadcastRejection(e)) {
        try { await this.deps.durable.remove(refundBroadcastKey(id)); } catch { /* best-effort */ }
      }
      throw e;
    }
  }

  /**
   * R-UTXO-REFUNDRACE-001 (B2): the UTXO analogue of recoverFromRefundRace, for the case where the refund broadcast
   * SUCCEEDED (so B1's definitive-rejection clear never fired and phase='refunded' was set) but the refund is later
   * ORPHANED — the initiator won the mempool/mining race and CLAIMED our leg Y, revealing S. Without this the responder
   * is permanently wedged: phase='refunded' (blocks claimWithKnownSecret at its phase gate) + the refundbroadcast
   * sentinel (blocks its cross-guard), so leg X — still claimable with the now-PUBLIC S until its LONGER timelock — is
   * forfeited, netting the strategic initiator BOTH legs. Detect the lost race (leg Y's HTLC output spent by a tx that
   * is NOT our refund and that reveals a preimage of our secretHash), recover S, clear the refund sentinel, reset phase
   * to 'claimed', and drive claimWithKnownSecret on leg X. Fail-closed: pivots ONLY on a confirmed-public S; otherwise
   * returns false and KEEPS all recovery material (the refund may still be pending — never abandon while S may still be
   * recoverable). RESPONDER-only (only the responder claims leg X with the counterparty's public secret).
   * @returns true iff the lost race was detected and S recovered (the leg-X claim is then driven best-effort).
   */
  private async recoverUtxoRefundRace(): Promise<boolean> {
    const rec = this.record;
    if (rec.role !== 'responder') return false;
    if (!(await this.deps.durable.get(refundBroadcastKey(rec.id)))) return false; // no refund was ever broadcast
    const myHtlc = rec.myHTLC;
    if (!myHtlc || typeof myHtlc.redeemScript !== 'string' || !/^[0-9a-f]+$/i.test(myHtlc.redeemScript)) return false;
    if ((chainConfigs[this.myChain] as { isEvm?: boolean } | undefined)?.isEvm) return false; // leg Y is UTXO here
    const hashLockHex = (rec.offer.secretHash ?? '').toLowerCase().replace(/^0x/, '');
    if (!HEX64.test(hashLockHex)) return false;
    const client = this.deps.chainClientFor(this.myChain); // our own leg Y lives on myChain
    const redeemScript = hexToBytes(myHtlc.redeemScript.toLowerCase());
    const scriptHex = 'a914' + bytesToHex(hash160(redeemScript)) + '87';
    const dr = await this.readDurableRefundTx(rec.id);
    const refundTxid = dr ? dr.txid.toLowerCase() : '';
    let history: Array<{ tx_hash: string; height: number }>;
    try { history = await client.getHistory(getHTLCScripthash(redeemScript), scriptHex); }
    catch { return false; } // transient read — can't tell; KEEP everything and retry later
    if (!Array.isArray(history)) return false;
    for (const item of history) {
      const txid = (item?.tx_hash ?? '').toLowerCase();
      if (!HEX64.test(txid) || txid === refundTxid) continue; // skip our own refund
      let raw: string;
      try { raw = await client.getTx(txid); } catch { continue; }
      let s: Uint8Array | null;
      try { s = extractSecret(raw, hashLockHex); } catch { s = null; }
      if (!s || s.length !== 32) continue;
      if (bytesToHex(sha256(s)) !== hashLockHex) continue; // belt-and-suspenders — only a true preimage of OUR hashLock
      // The counterparty CLAIMED our leg Y, revealing S — our refund lost the race and can never confirm. Recover:
      // save S, clear the refund sentinel + reset phase so claimWithKnownSecret's phase gate AND cross-guard pass.
      if (this.secret) this.secret.fill(0);
      this.secret = s;
      try { await this.deps.durable.remove(refundBroadcastKey(rec.id)); } catch { /* best-effort */ }
      this.setPhase('claimed');
      await this.persistRecord();
      this.status('recoverUtxoRefundRace:recovered-secret');
      // Drive the leg-X claim best-effort — a transient failure keeps the recovered state (S + cleared blockers persist),
      // so a later resume / host call completes the claim within leg X's timelock.
      try { await this.claimWithKnownSecret(); } catch { /* recovered state persisted; retry later */ }
      return true;
    }
    return false; // no foreign secret-revealing spend of leg Y — the refund may still be pending; KEEP everything
  }

  /** Broadcast an EVM claim, clearing the durable claimbroadcast sentinel ONLY on a PRE-broadcast throw (claimSwap tags
   *  pre-flight failures `preBroadcast:true` — no secret revealed), so a later call re-arms instead of adopting a
   *  never-broadcast claim (fix #3). A POST-broadcast / ambiguous failure LEAVES the sentinel set (R201 fail-safe). */
  private async claimEvmWithSentinelGuard(htlcAddr: string, swapId: string, secret: Uint8Array, signer: Signer, chainId: EvmChainId): Promise<void> {
    try {
      await claimSwap(htlcAddr, swapId, secret, signer, chainId);
    } catch (e) {
      if ((e as { preBroadcast?: boolean } | null)?.preBroadcast === true) {
        try { await this.deps.durable.remove(claimBroadcastKey(this.record.id)); } catch { /* best-effort */ }
      }
      throw e;
    }
  }

  /**
   * THE REFUND-RACE PIVOT body (fix #7). Recover S from OUR OWN EVM lock's on-chain `Claimed` event, corroborated
   * across quorum>=2 leaves, verify sha256(S)===hashLock, then claim the OTHER (counterparty) leg with the now-public
   * S so we are made whole. If S is not YET extractable (a lagging/pruned leaf), we KEEP the refund sentinel and throw
   * a RETRYABLE error — never conclude "safe to abandon" while S may still be extractable from an honest leaf.
   */
  private async recoverFromRefundRace(myHtlcAddr: string, mySwapId: string): Promise<{ txHash: string }> {
    const rec = this.record;
    const hashLockHex = (rec.offer.secretHash ?? '').toLowerCase().replace(/^0x/, '');
    const provider = this.evmProvider(this.myChain); // quorum>=2 read of OUR own EVM lock's Claimed event (fix #7)
    this.status('refundEvm:recovering-secret');
    const recovered = await this.readEvmClaimedSecret(provider, myHtlcAddr, mySwapId, hashLockHex);
    if (!recovered) {
      // Do NOT abandon while S may still be extractable — keep the refund sentinel AND set a durable refund-race
      // pending marker (fix #2) so a LATER refundEvm re-call RE-ENTERS this recovery instead of adopting the refund
      // sentinel as a completed refund / sending a fresh refund. Then surface a retryable error.
      try { await this.deps.durable.set(refundRacePendingKey(rec.id), '1'); } catch { /* best-effort */ }
      throw new Error('refundEvm: our EVM lock was already claimed but S is not yet corroborated from the on-chain Claimed event (quorum>=2) — retry; never abandon while S may still be recoverable from an honest leaf (fix #7)');
    }
    // Belt-and-suspenders: re-verify the authenticator before using S.
    if (bytesToHex(sha256(recovered)) !== hashLockHex) {
      recovered.fill(0);
      throw new Error('refundEvm: recovered preimage does not hash to the swap secretHash — fail closed');
    }
    if (this.secret) this.secret.fill(0);
    this.secret = recovered;
    // The refund did NOT execute (the counterparty took our lock) — clear the refund sentinel so the claim below is not
    // blocked by the claim<->refund cross-guard.
    try { await this.deps.durable.remove(refundBroadcastKey(rec.id)); } catch { /* best-effort */ }
    this.status('refundEvm:claiming-other-leg');
    // Claim the OTHER (counterparty) leg with the now-PUBLIC secret so we are made whole. UTXO leg -> the proven
    // claimWithKnownSecret path (single-flight + durable + reveal-margin-skipped, S already public); EVM leg -> claim
    // the counterparty EVM lock directly with the public S.
    const theirIsEvm = !!(chainConfigs[this.theirChain] as { isEvm?: boolean } | undefined)?.isEvm;
    const result = theirIsEvm
      ? await this.claimEvmCounterpartyWithPublicSecret()
      : { txHash: (await this.claimWithKnownSecret()).txid };
    // FIX #2: S recovered + the other leg claimed -> clear the refund-race pending marker (recovery is complete).
    try { await this.deps.durable.remove(refundRacePendingKey(rec.id)); } catch { /* best-effort */ }
    return result;
  }

  /** Claim the COUNTERPARTY EVM leg with the now-PUBLIC secret (the refund-race pivot's EVM<->EVM branch). No reveal
   *  margin gate (the secret is already public — no double-dip race), but the durable claimbroadcast sentinel + the
   *  single-flight lock still apply. Uses claimSwap (which re-checks sha256(S)===hashLock + recipient on-chain). */
  private async claimEvmCounterpartyWithPublicSecret(): Promise<{ txHash: string }> {
    const rec = this.record;
    const secret = this.secret;
    if (!secret || secret.length !== 32) throw new Error('claimEvmCounterpartyWithPublicSecret: the public secret is not available');
    const leg = this.counterpartyEvmLeg('claimEvmCounterpartyWithPublicSecret');
    const signer = this.evmSigner(this.theirChain);
    const lockName = `bch2swap:claim:${rec.id}`;
    const result = await this.deps.mutex.withLock(lockName, async (): Promise<{ swapId: string }> => {
      // R-EVMCLAIM-REORG-001: adopt the sentinel as a completed claim ONLY when getSwap.claimed corroborates it on-chain
      // — a 1-conf claim later orphaned by a reorg leaves the sentinel set with claimed=false, and a naive adopt would
      // strand the leg. If not claimed on-chain, clear the sentinel and re-broadcast below (S is already public).
      if (await this.deps.durable.get(claimBroadcastKey(rec.id))) {
        if (await this.evmSwapIsClaimed(signer.provider as Provider | null, leg.htlcAddr, leg.swapId)) return { swapId: leg.swapId };
        try { await this.deps.durable.remove(claimBroadcastKey(rec.id)); } catch { /* best-effort */ }
      }
      await this.deps.durable.commit([[claimBroadcastKey(rec.id), '1']]);
      // FIX #3: a PRE-broadcast claimSwap throw clears the sentinel we just set so a retry re-arms (the secret is
      // already public here, so no double-dip risk); a post-broadcast/ambiguous failure leaves it set (R201).
      await this.claimEvmWithSentinelGuard(leg.htlcAddr, leg.swapId, secret.slice(), signer, leg.evmChainId);
      return { swapId: leg.swapId };
    });
    this.record = { ...this.record, myClaimTxid: result.swapId };
    this.setPhase('completed');
    this.status('refundEvm:made-whole');
    await this.persistRecord();
    return { txHash: result.swapId };
  }

  // ── (6) watchForClaimEvm() — the RESPONDER watches its OWN EVM lock for the initiator's claim ──────────────

  /**
   * RESPONDER-ONLY. Watch OUR OWN EVM lock (myEvmSwapId) for the initiator's `Claimed` event, EXTRACT + VERIFY S
   * (sha256(S)===hashLock — the authenticator, so a quorum>=1 hash-verified liveness read is acceptable here per
   * R-POLYHIST), and SAVE it. Grounds in handleEvmFund's responder watch (watchForClaim, SwapExecute.tsx ~1250-1310).
   * A single scheduler-driven scan: NEVER throws on absence (returns `{secret:null}`); a forged/mismatched preimage is
   * REJECTED (the hash check). On discovery, transitions `responder_funded -> claimed`.
   */
  async watchForClaimEvm(): Promise<{ secret: Uint8Array | null }> {
    this.assertLive();
    const rec = this.record;
    if (rec.role !== 'responder') {
      throw new Error('watchForClaimEvm: responder-only (the initiator holds S from prepare())');
    }
    const swapId = (rec.myEvmSwapId ?? '').toLowerCase();
    if (!BYTES32_0X.test(swapId)) return { secret: null }; // not locked yet — nothing to watch (never throw on absence)
    const hashLockHex = (rec.offer.secretHash ?? '').toLowerCase().replace(/^0x/, '');
    if (!HEX64.test(hashLockHex)) return { secret: null };
    let htlcAddr: string;
    let provider: Provider;
    try { htlcAddr = this.evmCfgFor(this.myChain).htlcAddr; provider = this.evmProvider(this.myChain); }
    catch { return { secret: null }; } // misconfig / no provider — do not throw; the scheduler re-polls
    // quorum>=1 acceptable: the sha256(S)===hashLock check IS the authenticator (a lying leaf cannot fabricate an S
    // that hashes to our hashLock). readEvmClaimedSecret returns the first hash-verified S from ANY leaf.
    let secret: Uint8Array | null;
    try { secret = await this.readEvmClaimedSecret(provider, htlcAddr, swapId, hashLockHex); }
    catch { return { secret: null }; } // transient read error — never throw on absence; the scheduler re-polls
    if (!secret) return { secret: null };
    if (this.secret) this.secret.fill(0);
    this.secret = secret;
    if (rec.phase === 'responder_funded') this.setPhase('claimed');
    this.status('watchForClaimEvm:secret-found');
    await this.persistRecord();
    return { secret };
  }

  /**
   * Read + hash-VERIFY the preimage S from a `Claimed` event on the given EVM swapId, corroborated across the
   * provider's quorum leaves. Returns the FIRST S from ANY leaf whose sha256 equals `hashLockHex` (the authenticator —
   * so a single honest leaf is sufficient to TRUST the value), else null. The hash check makes a forged/foreign
   * Claimed log unusable (fund-safe), and reading every leaf means a lagging/pruned leaf never falsely hides an S that
   * an honest leaf still holds (the fix #7 "never abandon while S may be extractable" property). Never throws on a
   * per-leaf read error (a leaf that errors just doesn't contribute an S).
   */
  private async readEvmClaimedSecret(provider: Provider, htlcAddr: string, swapId: string, hashLockHex: string): Promise<Uint8Array | null> {
    const leaves = evmLeaves(provider);
    const claimedFrag = HTLC_IFACE.getEvent('Claimed');
    if (!claimedFrag) return null;
    const topic0 = claimedFrag.topicHash;
    const idTopic = ethers.zeroPadValue(swapId, 32); // the indexed bytes32 id
    const lockBlock = Number.isInteger(this.record.evmLockBlock) ? (this.record.evmLockBlock as number) : 0;
    for (const leaf of leaves) {
      const found = await this.scanLeafForClaimedSecret(leaf, htlcAddr, topic0, idTopic, swapId, hashLockHex, lockBlock);
      if (found) return found;
    }
    return null;
  }

  /**
   * FIX #1 (fund-loss): scan ONE leaf for the hash-verified Claimed preimage with a BOUNDED, WINDOWED getLogs — the
   * SDK's proven watchForClaim windowing (evm-client.ts ~L1486) ported into a single, non-blocking sweep. The old code
   * issued one UNBOUNDED `getLogs({fromBlock: evmLockBlock, toBlock:'latest'})`; a real public RPC rejects a wide range
   * ('range too large'), so S was never recovered and the refund-race loser could not be made whole. Here each query is
   * capped to CLAIMED_LOG_WINDOW blocks, fromBlock slides forward window-by-window, and a range-too-large / transient
   * rejection SHRINK-and-retries the SAME window (halving to a floor) before the leaf is abandoned. Returns the FIRST S
   * whose sha256 equals `hashLockHex` (the authenticator — a single honest leaf suffices to TRUST it), else null.
   */
  private static readonly CLAIMED_LOG_WINDOW = 9_000; // matches watchForClaim's 9000-block cap (public-RPC-safe)

  private async scanLeafForClaimedSecret(
    leaf: Provider, htlcAddr: string, topic0: string, idTopic: string, swapId: string, hashLockHex: string, lockBlock: number,
  ): Promise<Uint8Array | null> {
    // A NUMERIC tip is required so every query is a bounded [from,to] range (never fromBlock..'latest'). A leaf that
    // cannot report its tip simply doesn't contribute — the other leaves / a later poll still can (never throws).
    let tip: number;
    try {
      tip = await Promise.race([
        leaf.getBlockNumber(),
        new Promise<never>((_, rej) => setTimeout(() => rej(new Error('getBlockNumber timed out')), 15_000)),
      ]);
    } catch { return null; }
    if (!Number.isFinite(tip) || tip <= 0) return null;
    // fromBlock lower bound: our own lock's mine block (lossless). If unknown (0), floor near the tip like
    // watchForClaim (covers the ~24h lock window) rather than scanning from genesis.
    let from = lockBlock > 0 ? Math.min(lockBlock, tip) : Math.max(0, tip - 90_000);
    let window = SwapController.CLAIMED_LOG_WINDOW;
    const MAX_QUERIES = 10_000; // hard bound so a pathological RPC can never spin this single-sweep scan forever
    let guard = 0;
    while (from <= tip && guard++ < MAX_QUERIES) {
      const to = Math.min(tip, from + window - 1);
      let logs: Array<{ topics: ReadonlyArray<string>; data: string }> | null = null;
      try {
        logs = (await leaf.getLogs({ address: htlcAddr, topics: [topic0, idTopic], fromBlock: from, toBlock: to })) as unknown as Array<{ topics: ReadonlyArray<string>; data: string }>;
      } catch {
        // A wide-range rejection ('range too large') or a transient read error: SHRINK the window and retry the SAME
        // fromBlock (mirrors watchForClaim). At the floor (window===1) the leaf is unreliable -> abandon it (null).
        if (window > 1) { window = Math.max(1, Math.floor(window / 2)); continue; }
        return null;
      }
      if (Array.isArray(logs)) {
        for (const log of logs) {
          let parsed;
          try { parsed = HTLC_IFACE.parseLog({ topics: [...(log.topics ?? [])], data: log.data }); } catch { continue; }
          if (!parsed || parsed.name !== 'Claimed') continue;
          if (String(parsed.args[0]).toLowerCase() !== swapId.toLowerCase()) continue; // bind the exact swapId
          const secretHex = parsed.args[1] as string;
          if (!secretHex || secretHex === '0x' + '0'.repeat(64)) continue;
          let sb: Uint8Array;
          try { sb = ethers.getBytes(secretHex); } catch { continue; }
          if (sb.length !== 32) continue;
          if (bytesToHex(sha256(sb)) !== hashLockHex) continue; // THE authenticator — reject a forged/foreign preimage
          return sb;
        }
      }
      // Advance past the scanned window; restore the full window after a successful query.
      from = to + 1;
      window = SwapController.CLAIMED_LOG_WINDOW;
    }
    return null;
  }

  /** Best-effort persist of the full record (rehydration source for resume in step 6). Not fund-critical — the
   *  fund-critical write-set is committed atomically inside fundLegX BEFORE the broadcast. */
  private async persistRecord(): Promise<void> {
    try { await this.deps.durable.set(recordKey(this.id), JSON.stringify(this.record)); }
    catch (e) { this.emit({ type: 'error', error: e instanceof Error ? e : new Error(String(e)) }); }
  }
}
