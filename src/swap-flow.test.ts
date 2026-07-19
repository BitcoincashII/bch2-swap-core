/**
 * FAULT-INJECTION + invariant tests for src/core/swap-engine.ts.
 *
 * Focus: the cross-chain HTLC construction trust boundary. The swap engine turns a
 * (possibly proxy-supplied) block height plus party pubkey-hashes into an on-chain
 * HTLC. Two fund-safety invariants are locked in here:
 *
 *   1. LOCKTIME ORDERING (swap-engine.ts:141 / :172, chain-config.ts:131) — the
 *      responder's refund must mature STRICTLY BEFORE the initiator's, so the
 *      initiator always has time to claim the responder's leg (revealing the secret)
 *      before the responder can refund and walk. Inverting this loses the initiator's
 *      funds.
 *   2. PARTY-TO-PUBKEYHASH BINDING (swap-engine.ts:134-180) — recipient=claimer,
 *      refund=funder. Swapping the two args produces a DIFFERENT script/address, so a
 *      mis-wired caller can never accidentally build an HTLC the wrong party can sweep.
 *
 * Plus the R278 #14 note: an unauthenticated (proxy-supplied) build height feeds
 * directly into the responder's refund locktime; an inflated height pushes refund
 * maturity LATER. R167 mitigates the EVM-counterparty topology with an explicit
 * EVM-anchored timestamp CLTV; for a UTXO counterparty, authenticated height (SPV) is
 * the mainnet gate — this is documented arithmetically below.
 *
 * Pure functions (no proxy/RPC in-process), so the mock harness is used for an
 * INDEPENDENT cross-check of getHTLCScripthash (p2shScriptPubKeyHex) rather than for
 * injecting a lying client.
 */

import { describe, it, expect } from 'vitest';
import {
  createInitiatorHTLC,
  createResponderHTLC,
  getHTLCScripthash,
  hash160,
  sha256,
  hexToBytes,
} from './swap-flow';
import { LOCKTIME_BLOCKS, TIMELOCK_SAFETY_K, CLAIM_MARGIN_BLOCKS } from './chain-config';
import { createHTLC, bytesToHex } from './htlc-builder';
import { p2shScriptPubKeyHex } from './test-mocks';
import type { Chain, SwapState } from './swap-types';

// ============================================================================
// Fixtures
// ============================================================================

const SECRET = new Uint8Array(32).fill(0x42);
const SECRET_HASH = sha256(SECRET); // 32-byte hashLock

// Distinct 20-byte party hashes so the two roles are always distinguishable.
const INITIATOR_HASH = new Uint8Array(20).fill(0xa1);
const RESPONDER_HASH = new Uint8Array(20).fill(0xb2);

/** Minimal SwapState for the pure HTLC-construction helpers (they only read
 *  offer.sendChain / offer.receiveChain and state.secretHash). */
function makeState(sendChain: Chain, receiveChain: Chain): SwapState {
  return {
    offer: {
      id: 'test-offer',
      sendChain,
      receiveChain,
      sendAmount: '100000',
      receiveAmount: '100000',
      secretHash: bytesToHex(SECRET_HASH),
      initiatorSendAddress: 'addr-send',
      initiatorReceiveAddress: 'addr-recv',
      status: 'taken',
      createdAt: 0,
      expiresAt: 0,
    },
    role: 'initiator',
    secretHash: SECRET_HASH,
    claimAddress: 'claim-addr',
    refundAddress: 'refund-addr',
  } as SwapState;
}

function reverse(b: Uint8Array): Uint8Array {
  const out = new Uint8Array(b.length);
  for (let i = 0; i < b.length; i++) out[i] = b[b.length - 1 - i];
  return out;
}

// ============================================================================
// (1) Locktime derivation — height + LOCKTIME_BLOCKS
// ============================================================================

describe('createInitiatorHTLC / createResponderHTLC — locktime derivation', () => {
  const HEIGHT = 800_000;

  it('initiator locktime = currentHeight + LOCKTIME_BLOCKS.initiator (swap-engine.ts:141)', () => {
    const htlc = createInitiatorHTLC(makeState('bch2', 'btc'), HEIGHT, RESPONDER_HASH, INITIATOR_HASH);
    expect(htlc.params.locktime).toBe(HEIGHT + LOCKTIME_BLOCKS.initiator);
    expect(htlc.params.locktime).toBe(HEIGHT + 216); // R-TIMELOCK-K: initiator ~36h
  });

  it('responder locktime = currentHeight + LOCKTIME_BLOCKS.responder (swap-engine.ts:172)', () => {
    const htlc = createResponderHTLC(makeState('bch2', 'btc'), HEIGHT, INITIATOR_HASH, RESPONDER_HASH);
    expect(htlc.params.locktime).toBe(HEIGHT + LOCKTIME_BLOCKS.responder);
    expect(htlc.params.locktime).toBe(HEIGHT + 72); // R-TIMELOCK-K: responder ~12h
  });

  it('CROSS-CHAIN ORDERING INVARIANT: at the same height, responder refund matures STRICTLY BEFORE initiator refund (chain-config.ts:131-138)', () => {
    // Same build height for both legs — the ordering must hold from the timelock
    // constants alone. If this ever inverts, the responder could refund before the
    // initiator has a chance to claim, stealing the initiator's locked funds.
    const state = makeState('bch2', 'btc');
    const initiator = createInitiatorHTLC(state, HEIGHT, RESPONDER_HASH, INITIATOR_HASH);
    const responder = createResponderHTLC(state, HEIGHT, INITIATOR_HASH, RESPONDER_HASH);

    expect(responder.params.locktime).toBeLessThan(initiator.params.locktime);
    // And the constants themselves must satisfy the invariant (module-init assertion
    // in chain-config.ts:137 also enforces this, but assert it here explicitly).
    expect(LOCKTIME_BLOCKS.responder).toBeLessThan(LOCKTIME_BLOCKS.initiator);
    // R-TIMELOCK-K: the initiator lock must give the conservative fund gate room — initiator >= K*(responder+claimMargin)
    // — so a K-fold block-rate acceleration on minority-hashrate BCH2 can't invert the effective ordering. (The old
    // exact 2:1 ratio was too thin: it left only a 1.33x safety margin at the fund-gate floor.)
    expect(LOCKTIME_BLOCKS.initiator).toBeGreaterThanOrEqual(
      TIMELOCK_SAFETY_K * (LOCKTIME_BLOCKS.responder + CLAIM_MARGIN_BLOCKS),
    );
  });

  it('locktime is a positive block height (< LOCKTIME_HEIGHT_MAX), NOT a timestamp, on the height path', () => {
    const htlc = createResponderHTLC(makeState('bch2', 'btc'), HEIGHT, INITIATOR_HASH, RESPONDER_HASH);
    // Height locktimes must stay below 5e8 so the script encodes a height, not a unix ts.
    expect(htlc.params.locktime).toBeGreaterThan(0);
    expect(htlc.params.locktime).toBeLessThan(500_000_000);
  });
});

// ============================================================================
// (2) R167 explicitLocktime — EVM-anchored timestamp CLTV path
// ============================================================================

describe('createResponderHTLC — R167 explicitLocktime (EVM-anchor) path (swap-engine.ts:166-172)', () => {
  const HEIGHT = 800_000;
  // now + 12h as a unix timestamp — the trusted EVM-leg expiry the caller passes when
  // the counterparty is an EVM chain, so a malicious proxy HEIGHT cannot move maturity.
  const EVM_TS = 1_800_000_000;

  it('uses the explicit timestamp locktime and IGNORES the proxy-supplied height entirely', () => {
    const htlc = createResponderHTLC(makeState('base', 'bch2'), HEIGHT, INITIATOR_HASH, RESPONDER_HASH, EVM_TS);
    expect(htlc.params.locktime).toBe(EVM_TS);
    // Prove the height was not mixed in: locktime is exactly the timestamp, not height+72.
    expect(htlc.params.locktime).not.toBe(HEIGHT + LOCKTIME_BLOCKS.responder);
  });

  it('an INFLATED proxy height has ZERO effect when explicitLocktime is supplied (R167 neutralises the attack)', () => {
    const honest = createResponderHTLC(makeState('base', 'bch2'), HEIGHT, INITIATOR_HASH, RESPONDER_HASH, EVM_TS);
    const inflated = createResponderHTLC(makeState('base', 'bch2'), HEIGHT + 10_000_000, INITIATOR_HASH, RESPONDER_HASH, EVM_TS);
    expect(inflated.params.locktime).toBe(honest.params.locktime);
    expect(inflated.params.locktime).toBe(EVM_TS);
  });

  it('rejects a malformed explicitLocktime (a value in neither the height nor the timestamp window) — fails closed (htlc-builder.ts:252-257,270)', () => {
    // 6e8 is above LOCKTIME_HEIGHT_MAX (5e8) yet below LOCKTIME_TS_MIN (1.5e9): invalid.
    const bad = 600_000_000;
    expect(() =>
      createResponderHTLC(makeState('base', 'bch2'), HEIGHT, INITIATOR_HASH, RESPONDER_HASH, bad),
    ).toThrow(/locktime must be a block height/i);
  });
});

// ============================================================================
// (3) getHTLCScripthash — determinism + independent cross-check
// ============================================================================

describe('getHTLCScripthash (swap-engine.ts:190)', () => {
  const HEIGHT = 800_000;

  it('is deterministic: same redeemScript -> identical scripthash', () => {
    const a = createInitiatorHTLC(makeState('bch2', 'btc'), HEIGHT, RESPONDER_HASH, INITIATOR_HASH);
    const b = createInitiatorHTLC(makeState('bch2', 'btc'), HEIGHT, RESPONDER_HASH, INITIATOR_HASH);
    expect(bytesToHex(a.redeemScript)).toBe(bytesToHex(b.redeemScript));
    expect(getHTLCScripthash(a.redeemScript)).toBe(getHTLCScripthash(b.redeemScript));
  });

  it('a one-parameter change (different locktime) yields a DIFFERENT scripthash', () => {
    const state = makeState('bch2', 'btc');
    const a = createInitiatorHTLC(state, HEIGHT, RESPONDER_HASH, INITIATOR_HASH);
    const b = createInitiatorHTLC(state, HEIGHT + 1, RESPONDER_HASH, INITIATOR_HASH);
    expect(getHTLCScripthash(a.redeemScript)).not.toBe(getHTLCScripthash(b.redeemScript));
  });

  it('matches the independent Electrum-scripthash formula reverse(sha256(OP_HASH160<h160(rs)>OP_EQUAL)) — cross-checked via the mock harness p2shScriptPubKeyHex', () => {
    const htlc = createInitiatorHTLC(makeState('bch2', 'btc'), HEIGHT, RESPONDER_HASH, INITIATOR_HASH);
    // Build the P2SH scriptPubKey independently using the mock harness helper.
    const spkHex = p2shScriptPubKeyHex(bytesToHex(hash160(htlc.redeemScript)));
    const expected = bytesToHex(reverse(sha256(hexToBytes(spkHex))));
    expect(getHTLCScripthash(htlc.redeemScript)).toBe(expected);
  });
});

// ============================================================================
// (4) Party-to-pubkeyHash binding — recipient=claimer, refund=funder
// ============================================================================

describe('party-to-pubkeyHash binding (swap-engine.ts:134-180, htlc-builder.ts:259-297)', () => {
  const HEIGHT = 800_000;

  it('embeds recipient hash in the CLAIM branch and refund hash in the REFUND branch', () => {
    // Initiator HTLC: responder is the claimer (recipient), initiator is the funder (refund).
    const htlc = createInitiatorHTLC(makeState('bch2', 'btc'), HEIGHT, RESPONDER_HASH, INITIATOR_HASH);
    // recipientPubkeyHash occupies script bytes [39,59) (OP_IF..OP_HASH160 0x14 <20>).
    expect(bytesToHex(htlc.redeemScript.slice(39, 59))).toBe(bytesToHex(RESPONDER_HASH));
    // params round-trip the binding faithfully.
    expect(bytesToHex(htlc.params.recipientPubkeyHash)).toBe(bytesToHex(RESPONDER_HASH));
    expect(bytesToHex(htlc.params.refundPubkeyHash)).toBe(bytesToHex(INITIATOR_HASH));
  });

  it('SWAPPING recipient<->refund produces a DIFFERENT script/address/scripthash (a mis-wired caller cannot silently build a sweepable-by-wrong-party HTLC)', () => {
    const state = makeState('bch2', 'btc');
    const correct = createInitiatorHTLC(state, HEIGHT, RESPONDER_HASH, INITIATOR_HASH);
    const swapped = createInitiatorHTLC(state, HEIGHT, INITIATOR_HASH, RESPONDER_HASH);

    expect(bytesToHex(swapped.redeemScript)).not.toBe(bytesToHex(correct.redeemScript));
    expect(swapped.p2shAddress).not.toBe(correct.p2shAddress);
    expect(getHTLCScripthash(swapped.redeemScript)).not.toBe(getHTLCScripthash(correct.redeemScript));
  });

  it('degenerate guard: recipient == refund is rejected — a single party could otherwise both claim and refund (htlc-builder.ts:266-268)', () => {
    expect(() =>
      createInitiatorHTLC(makeState('bch2', 'btc'), HEIGHT, INITIATOR_HASH, INITIATOR_HASH),
    ).toThrow(/must differ/i);
  });
});

// ============================================================================
// (5) R278 #14 — proxy-inflated build height pushes responder refund maturity LATER
// ============================================================================

describe('R278 #14 — unauthenticated build height feeds responder refund maturity (swap-engine.ts:172)', () => {
  it('DOCUMENTS the attack arithmetic: an inflated height shifts refund maturity later by exactly the inflation delta', () => {
    const honestHeight = 800_000;
    const inflation = 20_000; // a lying/MITM proxy over-reports the tip
    const inflatedHeight = honestHeight + inflation;

    const honest = createResponderHTLC(makeState('bch2', 'btc'), honestHeight, INITIATOR_HASH, RESPONDER_HASH);
    const attacked = createResponderHTLC(makeState('bch2', 'btc'), inflatedHeight, INITIATOR_HASH, RESPONDER_HASH);

    // The refund CLTV height is derived DIRECTLY from the (untrusted) proxy height, so
    // the responder's refund matures `inflation` blocks LATER than it should. This locks
    // the responder's funds beyond the intended window and can erode the safety margin
    // relative to the initiator's leg — hence the funds move on the timelock ordering
    // remaining honest.
    expect(honest.params.locktime).toBe(honestHeight + LOCKTIME_BLOCKS.responder);
    expect(attacked.params.locktime).toBe(inflatedHeight + LOCKTIME_BLOCKS.responder);
    expect(attacked.params.locktime - honest.params.locktime).toBe(inflation);
    expect(attacked.params.locktime).toBeGreaterThan(honest.params.locktime);

    // MITIGATIONS (documented, not enforced by this pure function):
    //   - EVM-counterparty topology: R167 explicitLocktime anchors to the trusted EVM
    //     expiry so the proxy height is never consulted (see section 2 above).
    //   - UTXO-counterparty topology: authenticated height (client-side SPV) is the
    //     mainnet gate — this helper trusts whatever height the caller passes.
  });
});

// ============================================================================
// (6) EVM-chain fault injection — UTXO construction must fail closed
// ============================================================================

describe('assertUtxoChain fault injection (swap-engine.ts:101-105)', () => {
  const HEIGHT = 800_000;

  it('createInitiatorHTLC THROWS when sendChain is an EVM chain (no silent UTXO build for EVM)', () => {
    expect(() =>
      createInitiatorHTLC(makeState('base', 'bch2'), HEIGHT, RESPONDER_HASH, INITIATOR_HASH),
    ).toThrow(/not supported for EVM chain/i);
  });

  it('createResponderHTLC THROWS when receiveChain is an EVM chain', () => {
    expect(() =>
      createResponderHTLC(makeState('bch2', 'arb'), HEIGHT, INITIATOR_HASH, RESPONDER_HASH),
    ).toThrow(/not supported for EVM chain/i);
  });
});

// ============================================================================
// (7) Malformed pubkey-hash fault injection — propagated from redeem-script builder
// ============================================================================

describe('malformed pubkeyHash fault injection (htlc-builder.ts:263-264)', () => {
  const HEIGHT = 800_000;

  it('createInitiatorHTLC THROWS on a recipient hash that is not 20 bytes', () => {
    const bad = new Uint8Array(19).fill(0xaa);
    expect(() =>
      createInitiatorHTLC(makeState('bch2', 'btc'), HEIGHT, bad, INITIATOR_HASH),
    ).toThrow(/recipientPubkeyHash must be 20 bytes/i);
  });

  it('createResponderHTLC THROWS on a refund hash that is not 20 bytes', () => {
    const bad = new Uint8Array(32).fill(0xbb);
    expect(() =>
      createResponderHTLC(makeState('bch2', 'btc'), HEIGHT, INITIATOR_HASH, bad),
    ).toThrow(/refundPubkeyHash must be 20 bytes/i);
  });

  it('sanity: a correctly-built HTLC and a hand-built createHTLC with the same params agree (no hidden divergence)', () => {
    const state = makeState('bch2', 'btc');
    const viaEngine = createInitiatorHTLC(state, HEIGHT, RESPONDER_HASH, INITIATOR_HASH);
    const viaBuilder = createHTLC(
      {
        secretHash: SECRET_HASH,
        recipientPubkeyHash: RESPONDER_HASH,
        refundPubkeyHash: INITIATOR_HASH,
        locktime: HEIGHT + LOCKTIME_BLOCKS.initiator,
      },
      'bch2',
    );
    expect(bytesToHex(viaEngine.redeemScript)).toBe(bytesToHex(viaBuilder.redeemScript));
    expect(viaEngine.p2shAddress).toBe(viaBuilder.p2shAddress);
  });
});
