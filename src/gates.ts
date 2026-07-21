// gates.ts — the safe-by-default fund-safety GATES (P1b step 2).
//
// This module ports the PROVEN irreversible-action gate sequences out of the React component
// bch2-swap/src/components/SwapExecute.tsx into pure verification functions over the injected transports.
// Each gate reads FRESH from the chain every call and either MINTS a branded proof object or THROWS a typed
// GateFailure — it MINTS NOTHING on any failure/uncertainty and NEVER mutates app state (the controller owns
// setClaimTx(null)/rearm/sentinels; the gate only tells it what happened via the disposition hint).
//
// The two proof brands are NON-INTERCHANGEABLE (fix #1): a FundProof authorizes `fundLegY` (responder), a
// RevealAuthorization authorizes the initiator's single irreversible secret reveal. They check DIFFERENT
// predicates (ordering + RESPONDER margin vs 4h CLAIM_MARGIN on leg Y + the outpoint binding), so one brand
// would make the compile-time guarantee a mirage. Each is an opaque private-brand symbol type with NO public
// constructor — external code structurally cannot forge one.
//
// Faithfulness: every audited check is carried over with the SAME threshold + fail-closed direction. Sources:
//   - assertRevealSafe            <- SwapExecute.tsx handleBroadcastClaim R220/R139/R175/R258/R261 (~7824-7973)
//   - assertLegBuriedForFunding   <- the counterparty-leg burial re-verify (R220/R139/R175) + the responder
//                                     margin gate R125/R133 (~6313-6344)
//   - assertOrderingSafe          <- the initiator claim-window + R228 cross-domain ordering (R277/R175) (~6347-6421)
//   - assertEvmLegBuriedForFunding <- verifyEvmCounterpartyHTLC responder-fund gate R143/R148/R280/R322 (~3337-3378)
//   - assertEvmRevealSafe         <- handleEvmClaim R148 gate#2 + R258/R260/R261/R278 EVM margin (~2140-2258)
//
// Fixes honored: #1 two brands; #2 the proof is minted from a FRESH read EVERY call (no reuse-window shortcut —
// capturedAtChainSec may only ever FAIL a proof for staleness at the controller, never license skipping a
// re-read); #6 the SPV anchor stays the hardcoded ./spv constants (via spv-verifier); #9 the anti-theft margin +
// the proof's capturedAtChainSec anchor to CHAIN time (getChainTimeSec / corroborated EVM block clock), never
// Date.now().

import type { ChainClient } from './chain-client';
import type { Chain } from './swap-types';
import type { Provider } from 'ethers';
import { verifyConfirmations, spvVerifiedTipFresh, spvVerifiedTipTimeSec, getChainTimeSec, spvSupported } from './spv-verifier';
import { verifyAndAuthenticateUtxo, getHTLCScripthash } from './swap-flow';
import { hash160, bytesToHex } from './htlc-builder';
import { chainConfigs, minSecondsUntilRefund, LOCKTIME_BLOCKS } from './chain-config';
import { CLAIM_MARGIN_SEC, marginTooTight, claimWindowTooTight, orderingUnsafe } from './timelock-gates';
import { RESPONDER_LOCK_SEC, EVM_CLAIM_MARGIN_SEC } from './evm-config';
import { isEvmLockAtSafeDepth, getSwap } from './evm-client';

// ============================================================================
// Typed failure — thrown by every gate. Carries a fail-closed reason + a controller disposition hint.
// ============================================================================

/**
 * What the caller (the controller) should do next. The gate itself does nothing beyond throwing — these are
 * HINTS, never load-bearing for fund-safety (the throw already prevented the irreversible action):
 *  - 'rebuild': the cached claim/outpoint is stale (vanished / double-spent / spent-less) — discard the cached
 *               claim tx, rebuild it against the fresh outpoint, and re-enter the gate.
 *  - 'rearm'  : a TRANSIENT / recoverable condition (height/UTXO/SPV/chain-time/RPC read failed, or a possible
 *               proxy under/over-report) — re-arm the watcher/poll and retry automatically.
 *  - 'abort'  : a genuine DANGER dead-end (timelock margin too tight / ordering inversion / config invalid) —
 *               do NOT retry-reveal; the safe move is to refund your own leg once its timelock passes.
 */
export type GateDisposition = 'rebuild' | 'rearm' | 'abort';

/** Thrown by every gate on any failure. The secret is never emitted and no proof is minted. */
export class GateFailure extends Error {
  readonly reason: string;
  readonly disposition: GateDisposition;
  constructor(reason: string, disposition: GateDisposition) {
    super(reason);
    this.name = 'GateFailure';
    this.reason = reason;
    this.disposition = disposition;
  }
}

// ============================================================================
// Branded opaque proof types (fix #1). No public constructor: the brand key is a module-private `unique symbol`,
// so external code cannot reference it to satisfy the type — the ONLY way to obtain one is a successful gate.
// ============================================================================

export interface Outpoint {
  tx_hash: string;
  tx_pos: number;
}

export type MarginBasis = 'height-cltv' | 'timestamp-cltv' | 'evm-timestamp' | 'none';

/** The exact facts a gate proved, carried inside the branded proof for the controller to triangulate later. */
export interface ProvenLegAnchor {
  /** The leg's chain the proof was minted against. */
  readonly chain: string;
  /** UTXO leg: the funding outpoint the proof is BOUND to (tx_hash is a content hash — reorg tx cannot reuse it). */
  readonly outpoint?: Readonly<Outpoint>;
  /** EVM leg: the on-chain swapId the proof is bound to. */
  readonly swapId?: string;
  /** SPV-verified tip height (UTXO) / EVM block number (EVM) at mint — audit only. */
  readonly tipHeight: number;
  /** CHAIN time (seconds) captured at mint (fix #9 — never Date.now). May only ever FAIL a proof for staleness. */
  readonly capturedAtChainSec: number;
  /** The role the proof authorizes an action for. */
  readonly role: 'initiator' | 'responder';
  /** Which margin basis the proof cleared. */
  readonly marginBasis: MarginBasis;
}

declare const FUND_BRAND: unique symbol;
declare const REVEAL_BRAND: unique symbol;

/** Opaque proof that leg X is buried + ordered so the responder may fund leg Y. NOT a RevealAuthorization. */
export type FundProof = ProvenLegAnchor & {
  readonly leg: 'X';
  readonly for: 'fundY';
  readonly [FUND_BRAND]: true;
};

/**
 * Opaque authorization for the initiator's single irreversible secret reveal on leg Y. NOT a FundProof.
 * CONSUMER OBLIGATION: a RevealAuthorization minted for role:'responder' (marginBasis:'none') deliberately SKIPS
 * the 4h claim-margin (a responder claims an ALREADY-PUBLIC secret — no double-dip risk). The initiator's
 * irreversible reveal path (revealAndClaim, step 5) MUST therefore assert `auth.role === 'initiator'` before
 * broadcasting, so a margin-skipped responder auth can never authorize an initiator secret reveal.
 */
export type RevealAuthorization = ProvenLegAnchor & {
  readonly leg: 'Y';
  readonly for: 'reveal';
  readonly [REVEAL_BRAND]: true;
};

// Private minters — the only way a branded value comes into existence. The brand is a phantom (type-level only),
// so the cast-through-unknown is the standard opaque-brand pattern; leg/for are real runtime discriminants.
function mintFundProof(a: ProvenLegAnchor): FundProof {
  return { ...a, leg: 'X', for: 'fundY' } as unknown as FundProof;
}
function mintRevealAuthorization(a: ProvenLegAnchor): RevealAuthorization {
  return { ...a, leg: 'Y', for: 'reveal' } as unknown as RevealAuthorization;
}

// ============================================================================
// Transport the UTXO gates read (superset of the SPV-only ChainClient). Structurally satisfied verbatim by the
// app's ElectrumProxyClient AND the SDK test harness's MockElectrumClient — no adapter.
// ============================================================================

export interface GateUtxo {
  tx_hash: string;
  tx_pos: number;
  value: number;
  height: number;
}

export interface GateChainClient extends ChainClient {
  /** listunspent for a P2SH scripthash (+ optional script hex for the real proxy; ignored by the mock). */
  getUTXOs(scripthash: string, scriptHex?: string): Promise<GateUtxo[]>;
  /** Raw tx hex for a txid (self-authenticated by verifyAndAuthenticateUtxo + the SPV Merkle proof). */
  getTx(txid: string): Promise<string>;
  /** Fresh tip height [height, unsubscribe] — matches proxy-client.getBlockHeight. */
  getBlockHeight(onNewBlock?: (height: number) => void): Promise<[number, () => void]>;
}

// ============================================================================
// Small pure helpers ported verbatim from the app (bch2-swap/src/core/swap-execute-logic.ts) — NOT yet in the
// SDK. Exported so the EVM-margin fail-closed matrix can unit-test them directly.
// ============================================================================

/**
 * R278-EVM-MARGIN-QUORUM-001 (#6): aggregate the EVM-leg chain clock from per-leaf getBlock timestamps. Requires
 * EVERY configured RPC leaf to have answered (a single unavailable/lying backend must not set the clock alone),
 * then takes the MAX so a leaf reporting the clock BEHIND cannot deflate it. Returns null → caller fails closed.
 */
export function aggregateChainNow(leafTimestamps: Array<number | null>, leafCount: number): number | null {
  const oks = leafTimestamps.filter((t): t is number => t !== null);
  return (oks.length === leafCount && oks.length > 0) ? Math.max(...oks) : null;
}

/**
 * R261/R278 (#6): validate a getSwap-reported EVM refund timeLock. Accepts only a finite unix-seconds value in
 * [1e9, 1e11] (rejects a block-number-shaped or absurd-future value a lying RPC might return). Returns null →
 * caller fails closed. Accepts bigint (ethers getSwap) or number.
 */
export function validateEvmTimeLock(raw: number | bigint | null | undefined): number | null {
  if (raw === null || raw === undefined) return null;
  const tl = Number(raw);
  return (Number.isFinite(tl) && tl >= 1e9 && tl <= 1e11) ? tl : null;
}

// The P2SH funded-output scriptPubKey hex for a redeem script: OP_HASH160 <hash160(redeem)> OP_EQUAL.
function p2shScriptHex(redeemScript: Uint8Array): string {
  return 'a914' + bytesToHex(hash160(redeemScript)) + '87';
}

// max(1, requiredConfirmations ?? 3) / avgBlockTimeSec ?? 600 — verbatim defaults from SwapExecute.
function requiredConfirmationsFor(chain: string): number {
  return Math.max(1, chainConfigs[chain as Chain]?.requiredConfirmations ?? 3);
}
function avgBlockSecFor(chain: string): number {
  return chainConfigs[chain as Chain]?.avgBlockTimeSec ?? 600;
}

function isValidOutpoint(o: Outpoint | undefined | null): o is Outpoint {
  return !!o && typeof o.tx_hash === 'string' && /^[0-9a-f]{64}$/.test(o.tx_hash)
    && Number.isInteger(o.tx_pos) && o.tx_pos >= 0;
}

/**
 * Read the CLTV operand out of an HTLC redeem script (the exact layout htlc-builder.ts createHTLCRedeemScript emits):
 *   OP_IF OP_SHA256 <32 secretHash> OP_EQUALVERIFY OP_DUP OP_HASH160 <20 recipientPkh>
 *   OP_ELSE <push locktime> OP_CHECKLOCKTIMEVERIFY OP_DROP OP_DUP OP_HASH160 <20 refundPkh> OP_ENDIF ...
 * The locktime push always begins at a fixed offset (60) right after OP_ELSE. Returns the pushed number
 * (a little-endian CScriptNum) or null when the bytes are not this exact HTLC layout, or the operand is not a
 * plain positive push (the caller fails closed on null). The redeemScript is the value the funds are locked to
 * on-chain — its hash160 IS the funded P2SH — so its CLTV is the AUTHENTICATED timelock the margin must be
 * sized from, and it must agree with the caller's counterpartyLocktime record.
 */
export function parseHtlcCltv(redeemScript: Uint8Array): number | null {
  const s = redeemScript;
  const PUSH_AT = 60; // the locktime push opcode, immediately after the fixed OP_ELSE prefix
  if (s.length < PUSH_AT + 3) return null;
  // Fixed prefix bytes of the createHTLCRedeemScript template.
  if (s[0] !== 0x63 || s[1] !== 0xa8 || s[2] !== 0x20) return null;                     // OP_IF OP_SHA256 push32
  if (s[35] !== 0x88 || s[36] !== 0x76 || s[37] !== 0xa9 || s[38] !== 0x14) return null; // OP_EQUALVERIFY OP_DUP OP_HASH160 push20
  if (s[59] !== 0x67) return null;                                                       // OP_ELSE
  // Read the pushed locktime bytes (a direct push 0x01..0x4b, or OP_PUSHDATA1/2 for completeness).
  let pos = PUSH_AT;
  const op = s[pos++];
  let len: number;
  if (op >= 0x01 && op <= 0x4b) { len = op; }
  else if (op === 0x4c) { if (pos >= s.length) return null; len = s[pos++]; }
  else if (op === 0x4d) { if (pos + 1 >= s.length) return null; len = s[pos] | (s[pos + 1] << 8); pos += 2; }
  else return null;                                                                      // not a data push (e.g. OP_0)
  if (len < 1 || len > 5) return null;                                                   // a CLTV CScriptNum is 1..5 bytes
  if (pos + len >= s.length) return null;                                                // need the trailing opcode too
  if (s[pos + len] !== 0xb1) return null;                                                // OP_CHECKLOCKTIMEVERIFY must follow the push
  // Decode the little-endian CScriptNum. A CLTV is always positive, so the top byte's sign bit is clear
  // (createHTLCRedeemScript appends a 0x00 sign byte when it would otherwise be set); reject a negative encoding.
  if (s[pos + len - 1] & 0x80) return null;
  let n = 0;
  for (let i = 0; i < len; i++) n += s[pos + i] * 2 ** (8 * i);
  return n;
}

// ============================================================================
// Shared UTXO burial re-verify: the R220 exact-outpoint re-check + R139/R175 authentication + R175 SPV depth.
// Used by BOTH the fund gate (leg X, responder) and the reveal gate (leg Y, initiator). Fail-closed throughout.
// ============================================================================

interface Buried {
  freshHeight: number;
  vReqConf: number;
  sameOutpoint: GateUtxo;
  rawFundingTx: string;
}

function bytesEq(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

async function reverifyBuriedOutpoint(
  client: GateChainClient,
  chain: string,
  redeemScript: Uint8Array,
  recordedOutpoint: Outpoint,
  counterpartyLocktime: number,
  expectedFundedValueSats: number,
  expectedRecipientPkh: Uint8Array,
  expectedSecretHash: Uint8Array,
  label: string,
): Promise<Buried> {
  // R-REVEAL-FAILCLOSE: without a valid recorded funding outpoint we cannot re-verify → rebuild the claim.
  if (!isValidOutpoint(recordedOutpoint)) {
    throw new GateFailure(`${label}: no valid recorded funding outpoint to re-verify — rebuild before the irreversible action`, 'rebuild');
  }
  // Fresh, chain-anchored tip height (R220). fetchBlockHeight equivalent — fail closed if unavailable.
  let freshHeight = 0;
  try { freshHeight = (await client.getBlockHeight())[0]; } catch { freshHeight = 0; }
  if (!freshHeight || freshHeight <= 0) {
    throw new GateFailure(`${label}: counterparty chain height unavailable — fail closed; retry`, 'rearm');
  }
  const vReqConf = requiredConfirmationsFor(chain);
  let vUtxos: GateUtxo[];
  try { vUtxos = await client.getUTXOs(getHTLCScripthash(redeemScript), p2shScriptHex(redeemScript)); }
  catch { throw new GateFailure(`${label}: could not read counterparty HTLC UTXOs — fail closed; retry`, 'rearm'); }
  // IDENTICAL depth filter to the build-time gate, but require the EXACT recorded outpoint (tx_hash is a content
  // hash, so a reorg-replacement tx cannot reuse it) — R220 fail-closed on reorg / double-spend.
  const vConfirmed = vUtxos.filter(
    (u) => u.height > 0 && (freshHeight - u.height + 1) >= vReqConf && Number.isFinite(u.value) && u.value >= 0,
  );
  const sameOutpoint = vConfirmed.find((u) => u.tx_hash === recordedOutpoint.tx_hash && u.tx_pos === recordedOutpoint.tx_pos);
  if (!sameOutpoint) {
    throw new GateFailure(`${label}: counterparty HTLC funding no longer confirmed at the required depth (possible reorg / double-spend) — fail closed`, 'rebuild');
  }
  // R139/R175: authenticate the outpoint against its self-derived raw tx (do not trust proxy value/script).
  let rawFundingTx: string;
  try { rawFundingTx = await client.getTx(recordedOutpoint.tx_hash); }
  catch { throw new GateFailure(`${label}: could not fetch the counterparty funding tx to authenticate — fail closed; retry`, 'rearm'); }
  const fetchRawTx = (txid: string) =>
    txid.toLowerCase() === recordedOutpoint.tx_hash.toLowerCase() ? Promise.resolve(rawFundingTx) : client.getTx(txid);
  let vAuthed: { value: number };
  try { vAuthed = await verifyAndAuthenticateUtxo(sameOutpoint, redeemScript, fetchRawTx); }
  catch { throw new GateFailure(`${label}: counterparty HTLC funding output failed re-authentication — fail closed`, 'rebuild'); }
  if (!(vAuthed.value > 0)) {
    throw new GateFailure(`${label}: counterparty HTLC funding output failed re-authentication (non-positive value) — fail closed`, 'rebuild');
  }
  // R-UNDERFUND-001: bind the AUTHENTICATED funded value to the offer amount the claim will actually recover. The EVM
  // sibling gate enforces this (isEvmLockAtSafeDepth rejects lock.amount < inv.minAmount, evm-client.ts:1379, with the
  // EvmRevealGateParams.minAmount comment noting that omitting it lets a party reveal against an under-funded lock);
  // the UTXO gate previously asserted only value>0. Without this bind a malicious maker/responder who dust-funds the
  // counterparty leg — REAL, buried, correct outpoint + consistent CLTV — passes every other check, and we then
  // fund/reveal our OWN full leg and can only ever claim back dust (whole-leg loss, no race/reorg needed). The value
  // is the authenticated value of the exact recorded outpoint the claim spends, so this also covers split-UTXO
  // funding. Fail closed ('abort' — the shortfall is the maker's choice, not a transient/rebuildable condition).
  if (!Number.isFinite(expectedFundedValueSats) || expectedFundedValueSats <= 0) {
    throw new GateFailure(`${label}: invalid expected counterparty funded amount — fail closed`, 'abort');
  }
  if (!(vAuthed.value >= expectedFundedValueSats)) {
    throw new GateFailure(
      `${label}: counterparty HTLC underfunded (authenticated ${vAuthed.value} sats < required ${expectedFundedValueSats} sats) — claim would under-recover; fail closed`,
      'abort',
    );
  }
  // R175-SPV (THE trust removal): PoW+Merkle depth WITHOUT trusting the proxy's height. Over-report guard: an
  // unverifiable/inflated tip THROWS. Fail closed on throw OR a verified depth below required.
  if (spvSupported(chain)) {
    let spvConfs: number;
    try { spvConfs = await verifyConfirmations(client, chain, recordedOutpoint.tx_hash, sameOutpoint.height, rawFundingTx, freshHeight); }
    catch { throw new GateFailure(`${label}: could not SPV-verify counterparty funding depth (header/Merkle proof failed) — fail closed; retry`, 'rearm'); }
    if (spvConfs < vReqConf) {
      throw new GateFailure(`${label}: SPV-verified funding depth (${spvConfs}) below required ${vReqConf} — possible proxy height manipulation; fail closed`, 'rearm');
    }
  }
  // FUND-SAFETY (record/authenticated-script consistency): the margin gates below size the counterparty leg's
  // runway from the caller-supplied counterpartyLocktime, but the on-chain timelock is the CLTV encoded inside the
  // redeemScript the funds are actually locked to (its hash160 IS the funded P2SH, just re-checked by
  // verifyAndAuthenticateUtxo above). A malformed / inconsistent durable record whose locktime field disagrees
  // with that authenticated CLTV would feed a WRONG margin (a record overstating the runway would wave a
  // near-expiry leg through). Parse the CLTV and require it to equal the passed locktime; fail closed (rebuild the
  // record from the on-chain leg) on any mismatch or an unparseable script.
  const scriptCltv = parseHtlcCltv(redeemScript);
  if (scriptCltv === null) {
    throw new GateFailure(`${label}: could not read a CLTV from the counterparty HTLC redeem script — fail closed`, 'rebuild');
  }
  if (scriptCltv !== counterpartyLocktime) {
    throw new GateFailure(
      `${label}: recorded counterparty locktime (${counterpartyLocktime}) disagrees with the authenticated HTLC redeem script CLTV (${scriptCltv}) — fail closed`,
      'rebuild',
    );
  }
  // R-CPRECIP-001: bind the counterparty redeemScript's RECIPIENT pkh + SECRETHASH to OUR claim identity + the offer
  // secret. The EVM sibling binds both (isEvmLockAtSafeDepth: lock.recipient===inv.recipient + lock.hashLock===inv.hashLock)
  // but the UTXO gate authenticated ONLY that the funding is locked to the RECORDED script, trusting its CONTENTS. A
  // malicious counterparty could fund a self-consistent HTLC naming THEIR OWN pkh as recipient (or a different
  // secretHash): depth / exact-outpoint / CLTV / value all pass, we fund our leg, they claim it with S, and OUR claim
  // of this leg is script-invalid (needs their key / a different preimage) so we recover nothing — deterministic
  // whole-leg theft, no race/reorg. parseHtlcCltv above already validated the fixed prefix (s[0..2]=OP_IF OP_SHA256
  // push32, s[35..38]=OP_EQUALVERIFY OP_DUP OP_HASH160 push20, s[59]=OP_ELSE), so the slices below are well-formed.
  // Fail closed ('abort' — a substituted recipient/secret is the counterparty's choice, not a transient condition).
  if (expectedSecretHash.length !== 32 || !bytesEq(redeemScript.slice(3, 35), expectedSecretHash)) {
    throw new GateFailure(`${label}: counterparty HTLC secretHash does not match the offer — the swap secret would not unlock this leg; fail closed`, 'abort');
  }
  if (expectedRecipientPkh.length !== 20 || !bytesEq(redeemScript.slice(39, 59), expectedRecipientPkh)) {
    throw new GateFailure(`${label}: counterparty HTLC recipient pkh does not match our claim key — we could never claim this leg; fail closed`, 'abort');
  }
  return { freshHeight, vReqConf, sameOutpoint, rawFundingTx };
}

// ============================================================================
// (1) REVEAL gate — the initiator's single irreversible secret reveal (claim of the counterparty leg Y).
//     Ports SwapExecute.tsx handleBroadcastClaim (~7824-7973). MINTS RevealAuthorization or THROWS.
// ============================================================================

export interface RevealSafeParams {
  /** Only the INITIATOR reveals the secret; a responder claims an ALREADY-PUBLIC secret and is NOT margin-blocked. */
  role: 'initiator' | 'responder';
  /** The counterparty leg (leg Y) chain the claim spends. */
  theirChain: string;
  /** The counterparty (responder) HTLC redeem script. */
  counterpartyRedeemScript: Uint8Array;
  /** The EXACT funding outpoint the cached claim tx spends (= claimTx.spent). */
  recordedOutpoint: Outpoint;
  /** The counterparty HTLC locktime: a block height, or a unix timestamp (>= 1.5e9) for an EVM-anchored CLTV. */
  counterpartyLocktime: number;
  /** R-UNDERFUND-001: the amount (sats) WE claim from this leg — the authenticated funded value must be >= this, or a
   *  dust-funded counterparty leg would pass and we would reveal/commit our own full leg against it. For the initiator
   *  reveal this is offer.receiveAmount (leg Y); the responder-fund equivalent is offer.sendAmount (leg X). */
  expectedFundedValueSats: number;
  /** R-CPRECIP-001: hash160 of OUR claim key on this leg's chain — the counterparty redeemScript's recipient pkh must
   *  equal it, or the leg cannot be claimed by us (buildSecretClaim sweeps to exactly this pkh). */
  expectedRecipientPkh: Uint8Array;
  /** R-CPRECIP-001: the offer secretHash (32 bytes) — the counterparty redeemScript's committed hash must equal it, or
   *  the swap secret would not unlock this leg. */
  expectedSecretHash: Uint8Array;
}

/**
 * R220 exact-outpoint re-check + R139/R175 authentication + R175 SPV depth + R258/R261 initiator-only 4h margin.
 * The margin branch anchors to CHAIN time (timestamp CLTV) or an SPV-fresh height (height CLTV); either way it
 * fails closed rather than reveal the secret within the margin. THROWS + mints nothing on any doubt.
 */
export async function assertRevealSafe(client: GateChainClient, p: RevealSafeParams): Promise<RevealAuthorization> {
  const { role, theirChain, counterpartyRedeemScript, recordedOutpoint, counterpartyLocktime, expectedFundedValueSats, expectedRecipientPkh, expectedSecretHash } = p;

  const buried = await reverifyBuriedOutpoint(client, theirChain, counterpartyRedeemScript, recordedOutpoint, counterpartyLocktime, expectedFundedValueSats, expectedRecipientPkh, expectedSecretHash, 'reveal');

  // fix #9: the reveal is the anti-theft path — anchor to CHAIN time (never Date.now). Fail closed if unreadable.
  const chainNow = await getChainTimeSec(client);
  if (chainNow === null) {
    throw new GateFailure('reveal: could not read chain time to verify the responder refund timelock — not revealing the secret; retry', 'rearm');
  }

  // R258-CLAIM-BROADCAST-MARGIN-001 + R261-CHAINTIME-001: the INITIATOR's reveal must keep >= 4h runway on the
  // responder (counterparty) leg or the responder can refund AND claim ours with the leaked secret (lose BOTH).
  // The RESPONDER reveals an already-public secret (no double-dip race) and is intentionally NOT margin-blocked.
  let marginBasis: MarginBasis = 'none';
  if (role === 'initiator') {
    const cpLock = counterpartyLocktime;
    let respRemainingSec: number;
    if (cpLock >= 500_000_000) {
      // TIMESTAMP-CLTV branch: BIP65 OP_CHECKLOCKTIMEVERIFY interprets ANY locktime >= 500_000_000 as a unix
      // TIMESTAMP (matches isHtlcRefundAvailable + isValidLocktime; the gap [5e8, 1.5e9) is not a valid height and
      // must NOT be treated as one — a mis-classified past-timestamp CLTV would compute a huge block "remaining"
      // and let us reveal against an ALREADY-refundable counterparty leg). A unix-timestamp CLTV is enforced by
      // block time, so the margin MUST anchor to chain time (a clock skewed BEHIND overstates remaining → reveal
      // within the margin).
      marginBasis = 'timestamp-cltv';
      // R-CHAINTIME-DEFLATE-001: anchor to the SPV/PoW-verified tip's nTime (deflate-protected), matching the
      // height branch's under-report guard. getChainTimeSec is an UNVERIFIED proxy header read; a proxy that
      // deflates the tip nTime would overstate the responder's remaining refund runway and let us reveal inside
      // the real danger window (lose BOTH legs). For an SPV-supported counterparty chain, use the verified tip
      // time and fail closed if it can't be verified; non-SPV chains keep the accepted proxy-trust residual.
      let tsNow = chainNow;
      if (spvSupported(theirChain)) {
        try { tsNow = await spvVerifiedTipTimeSec(client, theirChain, buried.freshHeight); }
        catch {
          throw new GateFailure('reveal: could not SPV-verify the counterparty chain time (stale / under-reported) — not revealing the secret; retry', 'rearm');
        }
      }
      respRemainingSec = cpLock - tsNow;
    } else {
      // HEIGHT-CLTV branch (UTXO<->UTXO): SPV-verify + freshness-bound the tip (under-report guard) so a real-but-
      // STALE tip cannot understate how close the responder leg is to refundable. Fail closed if unverified.
      marginBasis = 'height-cltv';
      let spvHeight = buried.freshHeight;
      if (spvSupported(theirChain)) {
        try { spvHeight = await spvVerifiedTipFresh(client, theirChain, buried.freshHeight); }
        catch {
          throw new GateFailure('reveal: could not SPV-verify the current counterparty height (stale / under-report) — not revealing the secret; retry', 'rearm');
        }
      }
      // R-TIMELOCK-K: the responder leg's height CLTV could mature early on a fast minority chain → ÷K runway.
      respRemainingSec = minSecondsUntilRefund(cpLock - spvHeight, avgBlockSecFor(theirChain));
    }
    if (respRemainingSec < CLAIM_MARGIN_SEC) {
      throw new GateFailure(
        `reveal: responder HTLC refund timelock too close (~${Math.max(0, Math.floor(respRemainingSec / 3600))}h remaining, below the ` +
        `${Math.floor(CLAIM_MARGIN_SEC / 3600)}h claim margin) — revealing now would let the responder refund AND claim your leg. Not revealing the secret; refund your own leg once its timelock passes.`,
        'abort',
      );
    }
  }

  return mintRevealAuthorization({
    chain: theirChain,
    outpoint: { tx_hash: buried.sameOutpoint.tx_hash, tx_pos: buried.sameOutpoint.tx_pos },
    tipHeight: buried.freshHeight,
    capturedAtChainSec: chainNow,
    role,
    marginBasis,
  });
}

// ============================================================================
// (2) FUND-Y gate — the RESPONDER verifies the counterparty (initiator) leg X is buried + the timelock margin is
//     safe before funding its own leg Y. Ports the burial re-verify + R125/R133 responder margin (~6313-6344).
//     MINTS FundProof (bound to leg X's outpoint) or THROWS.
// ============================================================================

export interface FundGateParams {
  /** The counterparty (initiator) leg X chain — the leg the responder will eventually claim. */
  theirChain: string;
  /** The responder's OWN leg Y chain. */
  myChain: string;
  /** True when the responder funds leg Y on an EVM chain (R133: its lock is RESPONDER_LOCK_SEC wall-clock). */
  myChainIsEvm: boolean;
  /** The counterparty (initiator) HTLC redeem script. */
  counterpartyRedeemScript: Uint8Array;
  /** The initiator funding outpoint the responder recorded. */
  recordedOutpoint: Outpoint;
  /** The initiator leg X block-height CLTV. */
  counterpartyLocktime: number;
  /** R-UNDERFUND-001: the amount (sats) the responder will claim from leg X (= offer.sendAmount). The authenticated
   *  funded value of leg X must be >= this, or a dust-funded leg X would pass and the responder would fund its full
   *  leg Y against it. */
  expectedFundedValueSats: number;
  /** R-CPRECIP-001: hash160 of the responder's claim key on leg X's chain — leg X's recipient pkh must equal it. */
  expectedRecipientPkh: Uint8Array;
  /** R-CPRECIP-001: the offer secretHash (32 bytes) — leg X's committed hash must equal it. */
  expectedSecretHash: Uint8Array;
}

/**
 * Burial re-verify (R220/R139/R175) of leg X + R125/R133 responder margin: the initiator leg must outlast the
 * responder's OWN lock (RESPONDER_LOCK_SEC on EVM, else LOCKTIME_BLOCKS.responder * myBlockSec) plus the 4h claim
 * margin, sized by the ÷K minSecondsUntilRefund conservatism. THROWS + mints nothing on any doubt.
 */
export async function assertLegBuriedForFunding(client: GateChainClient, p: FundGateParams): Promise<FundProof> {
  const { theirChain, myChain, myChainIsEvm, counterpartyRedeemScript, recordedOutpoint, counterpartyLocktime, expectedFundedValueSats, expectedRecipientPkh, expectedSecretHash } = p;

  const buried = await reverifyBuriedOutpoint(client, theirChain, counterpartyRedeemScript, recordedOutpoint, counterpartyLocktime, expectedFundedValueSats, expectedRecipientPkh, expectedSecretHash, 'fund');

  // R125: chain block-time configuration must be valid before any wall-clock timelock comparison.
  const theirBlockSec = chainConfigs[theirChain as Chain]?.avgBlockTimeSec;
  const myBlockSec = chainConfigs[myChain as Chain]?.avgBlockTimeSec;
  if (!Number.isFinite(theirBlockSec) || (theirBlockSec ?? 0) <= 0 || !Number.isFinite(myBlockSec) || (myBlockSec ?? 0) <= 0) {
    throw new GateFailure('fund: chain block-time configuration is invalid — cannot verify swap timelock safety', 'abort');
  }
  // R133-EVMRESP-MARGIN-001: the responder's wall-clock lock is RESPONDER_LOCK_SEC when it funds on EVM, else
  // LOCKTIME_BLOCKS.responder * myBlockSec (kept so a non-600s UTXO chain stays correct).
  const responderLockSec = myChainIsEvm ? RESPONDER_LOCK_SEC : LOCKTIME_BLOCKS.responder * (myBlockSec as number);
  // R175-SPV: SPV-verify + freshness-bound the tip BEFORE the timelock margin (mirrors the reveal gate + the
  // proven source ~6280). The fund margin is an anti-theft path (fix #9): a stale / under-reporting proxy would
  // OVER-state leg X's remaining runway and wave a near-expiry counterparty leg through, so the responder funds
  // leg Y against a leg the initiator can refund right after claiming Y (responder loses both). Fail closed.
  let marginHeight = buried.freshHeight;
  if (spvSupported(theirChain)) {
    try { marginHeight = await spvVerifiedTipFresh(client, theirChain, buried.freshHeight); }
    catch { throw new GateFailure('fund: could not SPV-verify / freshness-bound the counterparty tip (stale / under-report) — not committing your funds; retry', 'rearm'); }
  }
  const remainingBlocks = counterpartyLocktime - marginHeight;
  // R26: reject an already-expired counterparty locktime, or a suspiciously-far one (a griefing counterparty
  // who sets an absurd locktime) — proven source ~6291-6304 (maxLockBlocks default 2016 * 3).
  if (remainingBlocks <= 0) {
    throw new GateFailure('fund: counterparty HTLC locktime has already expired — not committing your funds', 'abort');
  }
  const maxLock = ((chainConfigs[theirChain as Chain]?.maxLockBlocks ?? 2016) * 3);
  if (remainingBlocks > maxLock) {
    throw new GateFailure('fund: counterparty HTLC locktime is suspiciously far in the future (possible grief lock) — not committing your funds', 'abort');
  }
  // R125-SE-001 / R125-TAKER-002: minSecondsUntilRefund(remaining, theirBlockSec) < responderLockSec + margin → abort.
  if (marginTooTight(remainingBlocks, theirBlockSec as number, responderLockSec + CLAIM_MARGIN_SEC)) {
    throw new GateFailure(
      `fund: counterparty HTLC expires too soon relative to your ~${Math.ceil(responderLockSec / 3600)}h lock plus the ` +
      `${Math.floor(CLAIM_MARGIN_SEC / 3600)}h claim margin — unsafe to commit your funds`,
      'abort',
    );
  }

  // fix #9: capture CHAIN time (never Date.now) for the proof's staleness field. Fail closed if unreadable.
  const chainNow = await getChainTimeSec(client);
  if (chainNow === null) {
    throw new GateFailure('fund: could not read chain time — not committing your funds; retry', 'rearm');
  }

  return mintFundProof({
    chain: theirChain,
    outpoint: { tx_hash: buried.sameOutpoint.tx_hash, tx_pos: buried.sameOutpoint.tx_pos },
    tipHeight: buried.freshHeight,
    capturedAtChainSec: chainNow,
    role: 'responder',
    marginBasis: 'height-cltv',
  });
}

// ============================================================================
// (3) ORDERING gate — the INITIATOR's build-time cross-domain ordering precondition (a pure assertion, not a
//     proof minter): the responder (counterparty) leg's refund must mature STRICTLY BEFORE the initiator's own
//     leg minus the claim margin. Ports the claim-window + R228 ordering (R277/R175) (~6347-6421). THROWS or returns.
// ============================================================================

export interface OrderingParams {
  /** The counterparty (responder) leg chain — the leg the initiator will claim. */
  theirChain: string;
  /** The initiator's OWN leg chain. */
  myChain: string;
  /** The responder leg's observed blocks-to-refund on theirChain. */
  remainingBlocks: number;
  /** The initiator's own-leg locktime (from myHTLC or the durable fundlocktime replay); undefined if unrecoverable. */
  myLocktime: number | undefined;
  /** The initiator's own funding txid, if any — distinguishes a FUNDED leg (R277 fail-closed) from an unfunded one. */
  myFundingTxid: string | undefined;
}

/**
 * R125 claim-window + R228-ATOM-002 cross-domain WALL-CLOCK ordering, both in the initiator's normal path.
 * R277: if the own-leg locktime is unrecoverable AND the leg is FUNDED, fail closed (never claim without the
 * ordering check); an UNFUNDED own leg has nothing at maturity risk, so it is safe to skip. R175: prefer an
 * SPV-fresh myHeight when available (never fail-closed here — over-estimating our OWN leg only risks a failed
 * swap we can always refund, and this sits on the claim path, so a myChain stall must not forfeit the claim).
 */
export async function assertOrderingSafe(myChainClient: GateChainClient, p: OrderingParams): Promise<void> {
  const { theirChain, myChain, remainingBlocks, myLocktime, myFundingTxid } = p;

  const theirBlockSec = chainConfigs[theirChain as Chain]?.avgBlockTimeSec;
  const myBlockSec = chainConfigs[myChain as Chain]?.avgBlockTimeSec;
  if (!Number.isFinite(theirBlockSec) || (theirBlockSec ?? 0) <= 0 || !Number.isFinite(myBlockSec) || (myBlockSec ?? 0) <= 0) {
    throw new GateFailure('ordering: chain block-time configuration is invalid — cannot verify swap timelock safety', 'abort');
  }
  // R125 initiator: the counterparty leg must have more than K * CLAIM_MARGIN_BLOCKS blocks left.
  if (claimWindowTooTight(remainingBlocks)) {
    throw new GateFailure(
      `ordering: counterparty HTLC locktime nearly expired (${remainingBlocks} blocks remaining) — too risky to claim; the counterparty may refund before your claim confirms`,
      'abort',
    );
  }
  // R277-FUNDLOCKTIME-RECON: resolve the own-leg locktime; fail closed only for a FUNDED leg with no source.
  let ownLocktime = myLocktime;
  if (ownLocktime === undefined) {
    if (myFundingTxid) {
      throw new GateFailure('ordering: your funded HTLC locktime is unrecoverable locally — aborting to avoid an unsafe claim (recover via the funding txid)', 'abort');
    }
    return; // unfunded own leg — nothing at maturity risk; the old skip behavior is preserved
  }
  let myHeight = 0;
  try { myHeight = (await myChainClient.getBlockHeight())[0]; } catch { myHeight = 0; }
  if (!myHeight || myHeight <= 0) {
    throw new GateFailure('ordering: your chain block height is unavailable — aborting to avoid an unsafe claim', 'abort');
  }
  // R175 own-leg hardening: prefer an SPV-fresh + freshness-bounded myHeight; NOT fail-closed (preserve claim liveness).
  if (spvSupported(myChain)) {
    try { myHeight = await spvVerifiedTipFresh(myChainClient, myChain, myHeight); }
    catch { /* SPV unavailable/stale — keep the raw height (no fund-loss on this gate) */ }
  }
  // R228-ATOM-002-XCHAIN-DOMAIN-001: responderLegRemainingSec + margin >= ÷K initiatorLegRemainingSec → abort.
  if (orderingUnsafe(remainingBlocks, theirBlockSec as number, ownLocktime - myHeight, myBlockSec as number, CLAIM_MARGIN_SEC)) {
    throw new GateFailure(
      'ordering: the responder HTLC refund does not mature safely before your own leg minus the claim margin — aborting to prevent double-spend risk',
      'abort',
    );
  }
}

// ============================================================================
// EVM parity — the same two brands, minted from the injected quorum EVM provider.
// ============================================================================

function evmLeaves(provider: Provider): Provider[] {
  const ls = (provider as unknown as { __leafProviders?: Provider[] }).__leafProviders;
  return Array.isArray(ls) && ls.length > 0 ? ls : [provider];
}

// One leaf's latest block timestamp (seconds) or null (unavailable) — the R224/R278 per-leaf clock read.
async function readLeafChainSec(lp: Provider): Promise<number | null> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    const b = await Promise.race([
      lp.getBlock('latest'),
      new Promise<null>((res) => { timer = setTimeout(() => res(null), 15_000); }),
    ]);
    const ts = (b as { timestamp?: number } | null)?.timestamp;
    return (b && Number.isFinite(ts)) ? Number(ts) : null;
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}

export interface EvmFundGateParams {
  /** The counterparty (initiator) EVM leg chain id label (audit only). */
  chain: string;
  htlcAddr: string;
  swapId: string;
  requiredConfirmations: number;
  /** bytes32 hashLock (0x-prefixed) the lock must carry. */
  hashLock: string;
  /** The responder's EVM recipient address the lock must pay. */
  recipient: string;
  /** The agreed minimum amount (base units) the lock must fund. */
  minAmount: bigint;
  /** The canonical token contract the lock must use. */
  token: string;
}

/**
 * R143/R148/R280/R322: the responder-fund EVM gate. Corroborate the chain clock across ALL quorum leaves (MAX,
 * fail-closed to an impossible minTimeLock if any leaf is silent — R322), then require isEvmLockAtSafeDepth
 * (quorum >= 2) to confirm the lock is at a reorg-safe depth AND binds {hashLock, recipient, minAmount,
 * minTimeLock, token}. minTimeLock = corroborated chainNow + RESPONDER_LOCK_SEC + EVM_CLAIM_MARGIN_SEC (R280-H2).
 * The injected `provider` MUST be the quorum >= 2 read provider. THROWS + mints nothing on any doubt.
 */
export async function assertEvmLegBuriedForFunding(provider: Provider, p: EvmFundGateParams): Promise<FundProof> {
  const leaves = evmLeaves(provider);
  // fix #7 / R278 / R206: a single-leaf provider silently degrades the chain-clock corroboration AND the depth
  // read to quorum=1 — one hostile/lagging RPC could then deflate chainNow past the margin. Refuse to mint on
  // single-backend trust rather than rely on the caller injecting a real quorum provider (structural, not advisory).
  if (leaves.length < 2) {
    throw new GateFailure('evm-fund: the EVM read provider is not a quorum>=2 provider — refusing to mint on single-backend trust', 'rearm');
  }
  const tsList = await Promise.all(leaves.map(readLeafChainSec));
  const chainNow = aggregateChainNow(tsList, leaves.length);
  // R322-AUDIT: an unverifiable clock → impossible threshold → the honest depth check fails closed.
  const minTimeLock = chainNow == null
    ? BigInt('9999999999999999')
    : BigInt(Math.ceil(chainNow + RESPONDER_LOCK_SEC + EVM_CLAIM_MARGIN_SEC));

  let atSafeDepth = false;
  try {
    atSafeDepth = await isEvmLockAtSafeDepth(p.htlcAddr, p.swapId, provider, p.requiredConfirmations, {
      hashLock: p.hashLock, recipient: p.recipient, minAmount: p.minAmount, minTimeLock, token: p.token,
    });
  } catch { atSafeDepth = false; }
  if (!atSafeDepth) {
    throw new GateFailure('evm-fund: counterparty EVM lock is not at a reorg-safe depth, its refund timelock is too short, or a binding (hashLock/recipient/amount/token) mismatched — not committing your funds; retry', 'rearm');
  }
  // Unreachable when atSafeDepth is true (a null clock forces an impossible minTimeLock → false), but assert it
  // so the proof's chain-time field is never a fabricated 0 (fix #9).
  if (chainNow == null) {
    throw new GateFailure('evm-fund: could not corroborate the EVM chain clock across quorum leaves — fail closed; retry', 'rearm');
  }
  let tipHeight = 0;
  try { tipHeight = await provider.getBlockNumber(); } catch { tipHeight = 0; }

  return mintFundProof({
    chain: p.chain,
    swapId: p.swapId,
    tipHeight,
    capturedAtChainSec: chainNow,
    role: 'responder',
    marginBasis: 'evm-timestamp',
  });
}

export interface EvmRevealGateParams {
  /** The counterparty (responder) EVM leg chain id label (audit only). */
  chain: string;
  htlcAddr: string;
  swapId: string;
  requiredConfirmations: number;
  hashLock: string;
  recipient: string;
  /** REQUIRED (not optional): part of the proven R148 gate#2 binding — omitting it would let the initiator reveal
   *  S against an under-funded lock (receive less than given, secret now public). isEvmLockAtSafeDepth enforces it. */
  minAmount: bigint;
  token: string;
}

/**
 * R148 gate#2 + R258/R260/R261/R278: the initiator EVM secret-reveal gate. isEvmLockAtSafeDepth (quorum >= 2)
 * re-asserts reorg-safe DEPTH + binds {hashLock, recipient, minAmount, token}, then the broadcast-time MARGIN is
 * re-derived from the FRESH on-chain timeLock (untamperable) and a corroborated chain clock (MAX across leaves).
 * Fail closed unless (evmExpiry - chainNow) >= EVM_CLAIM_MARGIN_SEC. THROWS + mints nothing on any doubt.
 */
export async function assertEvmRevealSafe(provider: Provider, p: EvmRevealGateParams): Promise<RevealAuthorization> {
  // fix #7 / R278 / R206: refuse a single-leaf provider — quorum>=2 backs BOTH the depth read and the chain-clock
  // corroboration below, or a lone hostile RPC could deflate chainNow past the 4h reveal margin (lose both legs).
  const leaves = evmLeaves(provider);
  if (leaves.length < 2) {
    throw new GateFailure('evm-reveal: the EVM read provider is not a quorum>=2 provider — refusing to mint on single-backend trust', 'rearm');
  }
  // R148 gate#2 (defense-in-depth at the broadcast choke point): reorg-safe depth + binding, quorum >= 2.
  let atSafeDepth = false;
  try {
    atSafeDepth = await isEvmLockAtSafeDepth(p.htlcAddr, p.swapId, provider, p.requiredConfirmations, {
      hashLock: p.hashLock, recipient: p.recipient, minAmount: p.minAmount, token: p.token,
    });
  } catch { atSafeDepth = false; }
  if (!atSafeDepth) {
    throw new GateFailure('evm-reveal: counterparty EVM lock is not at a reorg-safe depth, or a binding (hashLock/recipient/amount/token) mismatched — not revealing your secret; retry', 'rearm');
  }

  // R258/R260/R261/R278: the ONLY proximity check on the responder EVM leg's refund timelock before the reveal.
  // Read the FRESH on-chain timeLock (via getSwap under the quorum provider — an immutable value, so leaves agree)
  // and the chain clock from EVERY leaf (MAX defeats a behind-reporting leaf). Never the cached/tamperable value.
  const [tsList, sw] = await Promise.all([
    Promise.all(leaves.map(readLeafChainSec)),
    getSwap(p.htlcAddr, p.swapId, provider).catch(() => null),
  ]);
  const chainNow = aggregateChainNow(tsList, leaves.length);
  const evmExpiry = validateEvmTimeLock(sw ? sw.timeLock : null);
  // R259/R278: a TRANSIENT read failure (null clock / timeLock) fails closed but is recoverable → re-arm.
  if (chainNow === null || evmExpiry === null) {
    throw new GateFailure('evm-reveal: cannot read the on-chain responder EVM lock timelock / chain time yet — not revealing your secret; retry', 'rearm');
  }
  // R258: a genuine danger — do NOT re-arm; refund your own leg after its timelock.
  if ((evmExpiry - chainNow) < EVM_CLAIM_MARGIN_SEC) {
    throw new GateFailure(
      `evm-reveal: responder EVM lock refund timelock too close (~${Math.max(0, Math.floor((evmExpiry - chainNow) / 3600))}h remaining, below the ` +
      `${Math.floor(EVM_CLAIM_MARGIN_SEC / 3600)}h claim margin) — revealing now would let the responder refund AND claim your leg. Not revealing your secret; refund your own leg once its timelock passes.`,
      'abort',
    );
  }
  let tipHeight = 0;
  try { tipHeight = await provider.getBlockNumber(); } catch { tipHeight = 0; }

  return mintRevealAuthorization({
    chain: p.chain,
    swapId: p.swapId,
    tipHeight,
    capturedAtChainSec: chainNow,
    role: 'initiator',
    marginBasis: 'evm-timestamp',
  });
}
