/**
 * FAIL-CLOSED matrix for src/gates.ts — the branded fund-safety proof minters.
 *
 * Every irreversible-action gate must THROW a GateFailure and MINT NOTHING on any doubt, and mint an
 * outpoint/swapId-bound proof only on the deep+fresh+ordered+margin-ok happy path. The two brands
 * (FundProof vs RevealAuthorization) are compile-time non-interchangeable (the // @ts-expect-error block).
 *
 * The UTXO gates run over a SYNTHETIC easy-difficulty PoW chain (same technique as spv-verifier.test.ts) so
 * the real R175 verifyConfirmations + spvVerifiedTipFresh + provenTxid binding execute fully offline; the EVM
 * gates run over MockEvmProvider (+ leaf providers for the quorum chain-clock reads).
 *
 * The funding output pays the P2SH of a REAL HTLC redeem script (htlc-builder createHTLCRedeemScript) so the
 * new CLTV-consistency check inside reverifyBuriedOutpoint can parse the authenticated CLTV and require it to
 * equal the caller-supplied counterpartyLocktime. Because the two must now agree, each test funds the exact
 * locktime it passes: the module fixture uses HEIGHT_LOCKTIME, and tests that need a different locktime build a
 * dedicated redeem + chain via buildHtlcChain().
 */

import { describe, it, expect, beforeEach } from 'vitest';
import type { Provider } from 'ethers';
import {
  assertRevealSafe, assertLegBuriedForFunding, assertOrderingSafe,
  assertEvmLegBuriedForFunding, assertEvmRevealSafe,
  aggregateChainNow, validateEvmTimeLock, parseHtlcCltv, GateFailure,
  type FundProof, type RevealAuthorization, type GateChainClient,
} from './gates';
import {
  __setSpvConfigForTests, __resetSpvCacheForTests, parseHeaderTimeSec,
} from './spv-verifier';
import { blockHashInternal, checkPoW, hash256, type AsertParams } from './spv';
import { hexToBytes, bytesToHex, hash160, createHTLCRedeemScript } from './htlc-builder';
import {
  MockElectrumClient, buildUtxoRawTx, MockEvmProvider, makeSwap, ZERO_ADDRESS,
  type MockElectrumOpts,
} from './test-mocks';

const toHexRev = (a: Uint8Array) => [...a].reverse().map((b) => b.toString(16).padStart(2, '0')).join('');

// ============================================================================
// Synthetic PoW chain builder — the fund block (checkpoint+1) is a single-tx block whose one tx funds a P2SH we
// control, so its merkle root == that funding txid and an empty-branch Merkle proof verifies. `tipAgeSec` shifts
// every timestamp uniformly back (constant ASERT target) to exercise spvVerifiedTipFresh's staleness bound.
// `fundValue` funds a 0-value output to drive the re-authentication non-positive-value branch.
// ============================================================================
function buildSynthChain(opts: {
  anchorHeight: number; count: number; spacing: number; bits: number; fundSpkHex: string; tipAgeSec?: number; fundValue?: number;
}) {
  const { anchorHeight, count, spacing, bits, fundSpkHex, tipAgeSec = 0, fundValue = 100000 } = opts;
  const powLimit = 1n << 255n;
  const nowSec = Math.floor(Date.now() / 1000);
  const anchorParentTime = nowSec - spacing * (count + 1) - tipAgeSec; // => tip block time == nowSec - tipAgeSec
  const T = (height: number) => anchorParentTime + spacing * (height - anchorHeight + 1);
  const params: AsertParams = { anchorHeight, anchorBits: bits, anchorParentTime, spacing: BigInt(spacing), powLimit, halfLife: () => 172800n };

  const fundHeight = anchorHeight + 1;
  const fund = buildUtxoRawTx([{ value: fundValue, scriptPubKeyHex: fundSpkHex }]);
  const fundRootInternal = hash256(hexToBytes(fund.rawTxHex)); // single-tx block: merkleRoot == txidInternal
  const checkpointHashInternal = hash256(new Uint8Array([0xc9, ...new Array(31).fill(0)]));
  const checkpoint = { height: anchorHeight, hashDisplay: toHexRev(checkpointHashInternal), time: T(anchorHeight) };

  const headersByHeight: Record<number, string> = {};
  let prevHashInternal = checkpointHashInternal;
  for (let i = 0; i < count; i++) {
    const height = fundHeight + i;
    const merkle = height === fundHeight ? fundRootInternal : hash256(new Uint8Array([height & 0xff, (height >> 8) & 0xff, 0x5a]));
    const raw = new Uint8Array(80);
    const dv = new DataView(raw.buffer);
    dv.setUint32(0, 0x20000000 >>> 0, true);
    raw.set(prevHashInternal, 4);
    raw.set(merkle, 36);
    dv.setUint32(68, T(height) >>> 0, true);
    dv.setUint32(72, bits >>> 0, true);
    let mined = false;
    for (let nonce = 0; nonce < 0xffffffff; nonce++) {
      dv.setUint32(76, nonce >>> 0, true);
      if (checkPoW(raw, bits, powLimit)) { mined = true; break; }
    }
    if (!mined) throw new Error(`could not mine synthetic header at ${height}`);
    headersByHeight[height] = bytesToHex(raw);
    prevHashInternal = blockHashInternal(raw);
  }
  const tip = anchorHeight + count;
  return { params, checkpoint, headersByHeight, fundHeight, fundTxid: fund.txid, fundRawHex: fund.rawTxHex, tip, fundValue };
}

// ============================================================================
// REAL HTLC redeem scripts + a chain funding their P2SH. The gate authenticates the redeemScript CLTV against
// the passed counterpartyLocktime, so a test funds the EXACT locktime it passes.
// ============================================================================
function htlcRedeem(locktime: number): Uint8Array {
  // recipient/refund pkhs only need to differ (the R72 degenerate-script guard); the CLTV is what the gate reads.
  return createHTLCRedeemScript({
    secretHash: new Uint8Array(32).fill(0xa5),
    recipientPubkeyHash: new Uint8Array(20).fill(0x11),
    refundPubkeyHash: new Uint8Array(20).fill(0x22),
    locktime,
  });
}
function p2shSpk(redeem: Uint8Array): string {
  return 'a914' + bytesToHex(hash160(redeem)) + '87';
}
// R-CLTV-DISCRIMINATOR: a RAW HTLC redeem script builder that does NOT validate the locktime — models a MALICIOUS
// responder crafting a CLTV in the rejected gap [5e8, 1.5e9) that createHTLCRedeemScript/isValidLocktime forbid.
function encodeScriptNumTest(n: number): Uint8Array {
  if (n === 0) return new Uint8Array(0);
  const bytes: number[] = [];
  let v = Math.abs(n);
  while (v > 0) { bytes.push(v & 0xff); v = Math.floor(v / 256); }
  if (bytes[bytes.length - 1] & 0x80) bytes.push(0x00); // positive sign byte (n > 0 here)
  return new Uint8Array(bytes);
}
function htlcRedeemRaw(locktime: number): Uint8Array {
  const lb = encodeScriptNumTest(locktime); // lb.length < 76 -> a bare length-prefixed push (matches pushData)
  return new Uint8Array([
    0x63, 0xa8, 0x20, ...new Uint8Array(32).fill(0xa5), 0x88, 0x76, 0xa9, 0x14, ...new Uint8Array(20).fill(0x11),
    0x67, lb.length, ...lb, 0xb1, 0x75, 0x76, 0xa9, 0x14, ...new Uint8Array(20).fill(0x22), 0x68, 0x88, 0xac,
  ]);
}
/** A real HTLC redeem script with the given CLTV + a synthetic PoW chain funding its P2SH. */
function buildHtlcChain(locktime: number, over: { tipAgeSec?: number; fundValue?: number } = {}) {
  const redeem = htlcRedeem(locktime);
  const ctx = buildSynthChain({ anchorHeight: 100000, count: 4, spacing: 600, bits: 0x20010000, fundSpkHex: p2shSpk(redeem), ...over });
  return { ctx, redeem };
}

const CHAIN = 'bc2'; // bc2's requiredConfirmations (3) is <= the fixture depth (4); avgBlockTimeSec 600.
const SYNTH_TIP = 100004; // anchorHeight(100000) + count(4) — deterministic, no build needed.
// One locktime that clears BOTH the reveal 4h claim margin (÷K 60000s >= 14400) AND the responder fund margin
// (÷K 60000s >= responderLock 43200 + margin 14400 = 57600).
const HEIGHT_LOCKTIME = SYNTH_TIP + 200; // 100204

const REDEEM = htlcRedeem(HEIGHT_LOCKTIME);
const FUND_SPK = p2shSpk(REDEEM);
const CTX = buildSynthChain({ anchorHeight: 100000, count: 4, spacing: 600, bits: 0x20010000, fundSpkHex: FUND_SPK });
const TIP_TIME = parseHeaderTimeSec(CTX.headersByHeight[CTX.tip])!; // chain time getChainTimeSec will report

type Ctx = ReturnType<typeof buildSynthChain>;
function utxoClient(ctx: Ctx, over: Partial<MockElectrumOpts> = {}): GateChainClient {
  return new MockElectrumClient({
    headersByHeight: ctx.headersByHeight,
    merkleProof: { block_height: ctx.fundHeight, merkle: [], pos: 0 },
    utxos: [{ tx_hash: ctx.fundTxid, tx_pos: 0, value: ctx.fundValue, height: ctx.fundHeight }],
    rawTxByTxid: { [ctx.fundTxid]: ctx.fundRawHex },
    height: ctx.tip,
    tipHeaderHex: ctx.headersByHeight[ctx.tip],
    ...over,
  }) as unknown as GateChainClient;
}
const outpoint = (ctx: Ctx) => ({ tx_hash: ctx.fundTxid, tx_pos: 0 });
/** Point the SPV verifier at a specific synthetic chain (dedicated-chain tests override the module CTX config). */
function useChain(ctx: Ctx): void {
  __setSpvConfigForTests(CHAIN, ctx.params, ctx.checkpoint);
  __resetSpvCacheForTests();
}

// ============================================================================
// (0) parseHtlcCltv — the new authenticated-CLTV reader powering the record/script consistency gate.
// ============================================================================
describe('parseHtlcCltv (authenticated HTLC CLTV reader)', () => {
  it('reads a block-height CLTV out of a real HTLC redeem script', () => {
    expect(parseHtlcCltv(htlcRedeem(100204))).toBe(100204);
    expect(parseHtlcCltv(htlcRedeem(90000))).toBe(90000);
    expect(parseHtlcCltv(htlcRedeem(499_999_999))).toBe(499_999_999);
  });
  it('reads a unix-timestamp CLTV (>= 1.5e9) out of a real HTLC redeem script', () => {
    expect(parseHtlcCltv(htlcRedeem(2_100_000_000))).toBe(2_100_000_000);
    expect(parseHtlcCltv(htlcRedeem(1_800_000_000))).toBe(1_800_000_000);
  });
  it('returns null for bytes that are not the HTLC layout (fail closed at the caller)', () => {
    expect(parseHtlcCltv(new Uint8Array(50).fill(0x77))).toBeNull(); // arbitrary junk
    expect(parseHtlcCltv(new Uint8Array(0))).toBeNull();             // empty
    expect(parseHtlcCltv(htlcRedeem(100204).slice(0, 40))).toBeNull(); // truncated before the CLTV push
  });
});

// ============================================================================
// (1) REVEAL gate — assertRevealSafe -> RevealAuthorization
// ============================================================================
describe('assertRevealSafe (initiator secret-reveal gate)', () => {
  beforeEach(() => { useChain(CTX); });

  it('HAPPY (height-CLTV): deep+fresh+margin-ok mints an OUTPOINT-BOUND RevealAuthorization', async () => {
    const auth = await assertRevealSafe(utxoClient(CTX), {
      role: 'initiator', theirChain: CHAIN, counterpartyRedeemScript: REDEEM, expectedFundedValueSats: 100000,
      recordedOutpoint: outpoint(CTX), counterpartyLocktime: HEIGHT_LOCKTIME, // 200 blocks => ÷K 60000s >= 4h
    });
    expect(auth.leg).toBe('Y');
    expect(auth.for).toBe('reveal');
    expect(auth.marginBasis).toBe('height-cltv');
    expect(auth.outpoint).toEqual({ tx_hash: CTX.fundTxid, tx_pos: 0 });
    expect(auth.chain).toBe(CHAIN);
    expect(auth.capturedAtChainSec).toBe(TIP_TIME);
  });

  it('HAPPY (timestamp-CLTV): a unix-timestamp CLTV anchored to chain time mints RevealAuthorization', async () => {
    const { ctx, redeem } = buildHtlcChain(2_100_000_000); // ~year 2036, far beyond the 4h margin vs chain-time now
    useChain(ctx);
    const auth = await assertRevealSafe(utxoClient(ctx), {
      role: 'initiator', theirChain: CHAIN, counterpartyRedeemScript: redeem, expectedFundedValueSats: 100000,
      recordedOutpoint: outpoint(ctx), counterpartyLocktime: 2_100_000_000,
    });
    expect(auth.marginBasis).toBe('timestamp-cltv');
    expect(auth.for).toBe('reveal');
  });

  it('FAIL-CLOSED: a VANISHED / double-spent outpoint throws (rebuild) and mints nothing', async () => {
    const client = utxoClient(CTX, { utxos: [] });
    await expect(assertRevealSafe(client, {
      role: 'initiator', theirChain: CHAIN, counterpartyRedeemScript: REDEEM, expectedFundedValueSats: 100000,
      recordedOutpoint: outpoint(CTX), counterpartyLocktime: HEIGHT_LOCKTIME,
    })).rejects.toMatchObject({ name: 'GateFailure', disposition: 'rebuild' });
  });

  it('FAIL-CLOSED: a spent-less / malformed recorded outpoint throws (rebuild)', async () => {
    await expect(assertRevealSafe(utxoClient(CTX), {
      role: 'initiator', theirChain: CHAIN, counterpartyRedeemScript: REDEEM, expectedFundedValueSats: 100000,
      recordedOutpoint: { tx_hash: 'not-hex', tx_pos: 0 }, counterpartyLocktime: HEIGHT_LOCKTIME,
    })).rejects.toMatchObject({ disposition: 'rebuild' });
  });

  it('FAIL-CLOSED: an over-reported / unverifiable SPV depth (proxy tip beyond supplied headers) throws (rearm)', async () => {
    const client = utxoClient(CTX, { height: CTX.tip + 10 }); // filter passes; SPV cannot reach the inflated tip
    await expect(assertRevealSafe(client, {
      role: 'initiator', theirChain: CHAIN, counterpartyRedeemScript: REDEEM, expectedFundedValueSats: 100000,
      recordedOutpoint: outpoint(CTX), counterpartyLocktime: HEIGHT_LOCKTIME,
    })).rejects.toMatchObject({ name: 'GateFailure', disposition: 'rearm' });
  });

  it('FAIL-CLOSED: a real-but-STALE tip (height-CLTV under-report guard) throws (rearm)', async () => {
    const { ctx, redeem } = buildHtlcChain(HEIGHT_LOCKTIME, { tipAgeSec: 3 * 3600 });
    useChain(ctx);
    await expect(assertRevealSafe(utxoClient(ctx), {
      role: 'initiator', theirChain: CHAIN, counterpartyRedeemScript: redeem, expectedFundedValueSats: 100000,
      recordedOutpoint: outpoint(ctx), counterpartyLocktime: HEIGHT_LOCKTIME,
    })).rejects.toMatchObject({ name: 'GateFailure', disposition: 'rearm' });
  });

  it('FAIL-CLOSED: margin < 4h on the height-CLTV branch throws (abort), mints nothing', async () => {
    const { ctx, redeem } = buildHtlcChain(SYNTH_TIP + 40); // ÷K 12000s < 14400s
    useChain(ctx);
    await expect(assertRevealSafe(utxoClient(ctx), {
      role: 'initiator', theirChain: CHAIN, counterpartyRedeemScript: redeem, expectedFundedValueSats: 100000,
      recordedOutpoint: outpoint(ctx), counterpartyLocktime: SYNTH_TIP + 40,
    })).rejects.toMatchObject({ name: 'GateFailure', disposition: 'abort' });
  });

  it('FAIL-CLOSED: margin < 4h on the timestamp-CLTV branch throws (abort)', async () => {
    const tsLock = Math.floor(Date.now() / 1000) + 1000; // 1000s < 14400s remaining vs chain-time now
    const { ctx, redeem } = buildHtlcChain(tsLock);
    useChain(ctx);
    await expect(assertRevealSafe(utxoClient(ctx), {
      role: 'initiator', theirChain: CHAIN, counterpartyRedeemScript: redeem, expectedFundedValueSats: 100000,
      recordedOutpoint: outpoint(ctx), counterpartyLocktime: tsLock,
    })).rejects.toMatchObject({ disposition: 'abort' });
  });

  it('FAIL-CLOSED (R-CHAINTIME-DEFLATE-001): a STALE/deflated proxy tip time on the timestamp-CLTV branch throws (rearm), not an overstated margin', async () => {
    // The counterparty leg is ~2h from refund (inside the 4h danger window) → an honest margin must abort. But a
    // proxy that deflates the tip nTime by 3h would make (cpLock - staleTipTime) ≈ 5h > 4h and pass. With the fix
    // the timestamp branch anchors to the SPV-verified tip whose staleness guard rejects the 3h-old tip → rearm.
    const tsLock = Math.floor(Date.now() / 1000) + 2 * 3600;
    const { ctx, redeem } = buildHtlcChain(tsLock, { tipAgeSec: 3 * 3600 });
    useChain(ctx);
    await expect(assertRevealSafe(utxoClient(ctx), {
      role: 'initiator', theirChain: CHAIN, counterpartyRedeemScript: redeem, expectedFundedValueSats: 100000,
      recordedOutpoint: outpoint(ctx), counterpartyLocktime: tsLock,
    })).rejects.toMatchObject({ name: 'GateFailure', disposition: 'rearm' });
  });

  it('FAIL-CLOSED (R-CLTV-DISCRIMINATOR): a counterparty CLTV in the gap [5e8, 1.5e9) is a PAST timestamp, not a height, and aborts', async () => {
    // A malicious responder funds the counterparty leg with CLTV=600_000_000. BIP65 (and isHtlcRefundAvailable /
    // isValidLocktime) treat >= 5e8 as a unix TIMESTAMP -> ~1989, already refundable. Before the fix the reveal gate's
    // discriminator (>= 1.5e9) mis-routed it to the HEIGHT branch -> ~6e8-block "remaining" -> margin passed -> the
    // initiator revealed against an already-refundable leg and lost both legs. Now it routes to the timestamp branch
    // (negative remaining) and fails closed.
    const GAP = 600_000_000;
    const redeem = htlcRedeemRaw(GAP);
    const gapCtx = buildSynthChain({ anchorHeight: 100000, count: 4, spacing: 600, bits: 0x20010000, fundSpkHex: p2shSpk(redeem) });
    useChain(gapCtx);
    await expect(assertRevealSafe(utxoClient(gapCtx), {
      role: 'initiator', theirChain: CHAIN, counterpartyRedeemScript: redeem, expectedFundedValueSats: 100000,
      recordedOutpoint: outpoint(gapCtx), counterpartyLocktime: GAP,
    })).rejects.toMatchObject({ name: 'GateFailure' }); // aborts; before the fix this MINTED a RevealAuthorization
  });

  it('FAIL-CLOSED: chain time unavailable (empty tip header) throws (rearm)', async () => {
    const client = utxoClient(CTX, { tipHeaderHex: '' });
    await expect(assertRevealSafe(client, {
      role: 'initiator', theirChain: CHAIN, counterpartyRedeemScript: REDEEM, expectedFundedValueSats: 100000,
      recordedOutpoint: outpoint(CTX), counterpartyLocktime: HEIGHT_LOCKTIME,
    })).rejects.toMatchObject({ disposition: 'rearm' });
  });

  it('RESPONDER (already-public secret) is NOT margin-blocked even with a near-expiry counterparty leg', async () => {
    const { ctx, redeem } = buildHtlcChain(SYNTH_TIP + 1); // would be far too tight for an initiator
    useChain(ctx);
    const auth = await assertRevealSafe(utxoClient(ctx), {
      role: 'responder', theirChain: CHAIN, counterpartyRedeemScript: redeem, expectedFundedValueSats: 100000,
      recordedOutpoint: outpoint(ctx), counterpartyLocktime: SYNTH_TIP + 1,
    });
    expect(auth.marginBasis).toBe('none');
    expect(auth.role).toBe('responder');
  });

  it('FAIL-CLOSED (hardening): a counterpartyLocktime that disagrees with the authenticated redeemScript CLTV throws (rebuild), mints nothing', async () => {
    // The funding output pays p2sh(REDEEM), whose encoded CLTV is HEIGHT_LOCKTIME. A durable record whose locktime
    // field says something else would feed a wrong margin — the gate parses the authenticated CLTV and fails closed.
    await expect(assertRevealSafe(utxoClient(CTX), {
      role: 'initiator', theirChain: CHAIN, counterpartyRedeemScript: REDEEM, expectedFundedValueSats: 100000,
      recordedOutpoint: outpoint(CTX), counterpartyLocktime: HEIGHT_LOCKTIME + 1, // disagrees with the script CLTV
    })).rejects.toMatchObject({ name: 'GateFailure', disposition: 'rebuild' });
  });

  it('FAIL-CLOSED (R-UNDERFUND-001): a dust-funded counterparty leg Y (authenticated value < offer amount) aborts — never reveal S against an under-funded leg', async () => {
    // The leg is REAL, buried, correct outpoint + consistent CLTV (every other check passes), funded 100000 while the
    // initiator is owed 100001. Before the fix the gate asserted only value>0 and MINTED — the initiator then revealed
    // S to recover dust while the responder claimed the full leg X.
    await expect(assertRevealSafe(utxoClient(CTX), {
      role: 'initiator', theirChain: CHAIN, counterpartyRedeemScript: REDEEM,
      recordedOutpoint: outpoint(CTX), counterpartyLocktime: HEIGHT_LOCKTIME,
      expectedFundedValueSats: 100001, // one sat above the authenticated funded value (100000)
    })).rejects.toMatchObject({ name: 'GateFailure', disposition: 'abort' });
  });
});

// ============================================================================
// (2) reverifyBuriedOutpoint fail-closed branches — shared by BOTH the reveal + fund gates (driven here via the
//     reveal gate). Every branch throws + mints nothing on any read failure / shallow / re-auth doubt.
// ============================================================================
describe('reverifyBuriedOutpoint fail-closed branches (shared burial re-verify)', () => {
  beforeEach(() => { useChain(CTX); });

  const reveal = (client: GateChainClient, over: Partial<Parameters<typeof assertRevealSafe>[1]> = {}) =>
    assertRevealSafe(client, {
      role: 'initiator', theirChain: CHAIN, counterpartyRedeemScript: REDEEM, expectedFundedValueSats: 100000,
      recordedOutpoint: outpoint(CTX), counterpartyLocktime: HEIGHT_LOCKTIME, ...over,
    });

  it('re-authentication throw: getTx returns bytes whose double-sha256 != the recorded txid -> rebuild', async () => {
    // A rawtx for a DIFFERENT output (value 99999) — its true txid != CTX.fundTxid, so parseAuthenticatedOutput's
    // txid binding rejects it. The funding UTXO is still "found" by the filter; the failure is at re-authentication.
    const lyingRawTx = buildUtxoRawTx([{ value: 99999, scriptPubKeyHex: FUND_SPK }]).rawTxHex;
    await expect(reveal(utxoClient(CTX, { lyingRawTx })))
      .rejects.toMatchObject({ name: 'GateFailure', disposition: 'rebuild' });
  });

  it('present-but-shallow funding: UTXO returned but depth < requiredConfirmations -> rebuild', async () => {
    // The recorded outpoint IS present, but at the tip (depth 1) — below bc2's requiredConfirmations (3). The
    // depth filter drops it, so the exact recorded outpoint is not found at the required depth: fail closed.
    const shallow = [{ tx_hash: CTX.fundTxid, tx_pos: 0, value: 100000, height: CTX.tip }];
    await expect(reveal(utxoClient(CTX, { utxos: shallow })))
      .rejects.toMatchObject({ name: 'GateFailure', disposition: 'rebuild' });
  });

  it('transient read: the tip height is unavailable (getBlockHeight 0) -> rearm', async () => {
    await expect(reveal(utxoClient(CTX, { height: 0 })))
      .rejects.toMatchObject({ name: 'GateFailure', disposition: 'rearm' });
  });

  it('transient read: getUTXOs errors -> rearm', async () => {
    const mock = new MockElectrumClient({ headersByHeight: CTX.headersByHeight, height: CTX.tip, tipHeaderHex: CTX.headersByHeight[CTX.tip] });
    mock.getUTXOs = async () => { throw new Error('electrum getUTXOs unreachable'); };
    await expect(reveal(mock as unknown as GateChainClient))
      .rejects.toMatchObject({ name: 'GateFailure', disposition: 'rearm' });
  });

  it('transient read: getTx errors (cannot fetch the funding tx to authenticate) -> rearm', async () => {
    await expect(reveal(utxoClient(CTX, { getTxThrows: true })))
      .rejects.toMatchObject({ name: 'GateFailure', disposition: 'rearm' });
  });

  it('re-authentication non-positive value: the funding output authenticates to value 0 -> rebuild', async () => {
    const { ctx, redeem } = buildHtlcChain(HEIGHT_LOCKTIME, { fundValue: 0 }); // funds a 0-value output
    useChain(ctx);
    await expect(assertRevealSafe(utxoClient(ctx), {
      role: 'initiator', theirChain: CHAIN, counterpartyRedeemScript: redeem, expectedFundedValueSats: 100000,
      recordedOutpoint: outpoint(ctx), counterpartyLocktime: HEIGHT_LOCKTIME,
    })).rejects.toMatchObject({ name: 'GateFailure', disposition: 'rebuild' });
  });
});

// ============================================================================
// (3) FUND-Y gate — assertLegBuriedForFunding -> FundProof
// ============================================================================
describe('assertLegBuriedForFunding (responder fund-Y gate)', () => {
  beforeEach(() => { useChain(CTX); });

  it('HAPPY: leg-X buried + responder margin ok mints an OUTPOINT-BOUND FundProof', async () => {
    const proof = await assertLegBuriedForFunding(utxoClient(CTX), {
      theirChain: CHAIN, myChain: 'bch2', myChainIsEvm: false, counterpartyRedeemScript: REDEEM, expectedFundedValueSats: 100000,
      recordedOutpoint: outpoint(CTX), counterpartyLocktime: HEIGHT_LOCKTIME, // ÷K 60000s >= 43200+14400
    });
    expect(proof.leg).toBe('X');
    expect(proof.for).toBe('fundY');
    expect(proof.outpoint).toEqual({ tx_hash: CTX.fundTxid, tx_pos: 0 });
    expect(proof.role).toBe('responder');
  });

  it('FAIL-CLOSED: responder margin too tight (initiator leg expires too soon) throws (abort)', async () => {
    const { ctx, redeem } = buildHtlcChain(SYNTH_TIP + 100); // ÷K 30000s < 57600s
    useChain(ctx);
    await expect(assertLegBuriedForFunding(utxoClient(ctx), {
      theirChain: CHAIN, myChain: 'bch2', myChainIsEvm: false, counterpartyRedeemScript: redeem, expectedFundedValueSats: 100000,
      recordedOutpoint: outpoint(ctx), counterpartyLocktime: SYNTH_TIP + 100,
    })).rejects.toMatchObject({ name: 'GateFailure', disposition: 'abort' });
  });

  it('FAIL-CLOSED: a vanished funding outpoint throws (rebuild) and mints nothing', async () => {
    await expect(assertLegBuriedForFunding(utxoClient(CTX, { utxos: [] }), {
      theirChain: CHAIN, myChain: 'bch2', myChainIsEvm: false, counterpartyRedeemScript: REDEEM, expectedFundedValueSats: 100000,
      recordedOutpoint: outpoint(CTX), counterpartyLocktime: HEIGHT_LOCKTIME,
    })).rejects.toMatchObject({ disposition: 'rebuild' });
  });

  it('FAIL-CLOSED (fix #4): a real-but-STALE tip fails the fund margin (rearm) — was silently minting before', async () => {
    // A locktime that PASSES the happy margin against the RAW tip (÷K 60000s >= 57600s), so the ONLY guard that can
    // catch it is the spvVerifiedTipFresh under-report bound the reveal gate had but the fund gate had dropped.
    const { ctx, redeem } = buildHtlcChain(HEIGHT_LOCKTIME, { tipAgeSec: 3 * 3600 });
    useChain(ctx);
    await expect(assertLegBuriedForFunding(utxoClient(ctx), {
      theirChain: CHAIN, myChain: 'bch2', myChainIsEvm: false, counterpartyRedeemScript: redeem, expectedFundedValueSats: 100000,
      recordedOutpoint: outpoint(ctx), counterpartyLocktime: HEIGHT_LOCKTIME,
    })).rejects.toMatchObject({ name: 'GateFailure', disposition: 'rearm' });
  });

  it('FAIL-CLOSED: an already-expired counterparty locktime (remaining <= 0) throws (abort)', async () => {
    const { ctx, redeem } = buildHtlcChain(90000); // well below the tip (100004) => already refundable
    useChain(ctx);
    await expect(assertLegBuriedForFunding(utxoClient(ctx), {
      theirChain: CHAIN, myChain: 'bch2', myChainIsEvm: false, counterpartyRedeemScript: redeem, expectedFundedValueSats: 100000,
      recordedOutpoint: outpoint(ctx), counterpartyLocktime: 90000,
    })).rejects.toMatchObject({ name: 'GateFailure', disposition: 'abort' });
  });

  it('FAIL-CLOSED: a suspiciously-far counterparty locktime (grief lock, remaining > maxLockBlocks*3) throws (abort)', async () => {
    const { ctx, redeem } = buildHtlcChain(110000); // remaining ~9996 > bc2 maxLockBlocks(2016)*3 = 6048
    useChain(ctx);
    await expect(assertLegBuriedForFunding(utxoClient(ctx), {
      theirChain: CHAIN, myChain: 'bch2', myChainIsEvm: false, counterpartyRedeemScript: redeem, expectedFundedValueSats: 100000,
      recordedOutpoint: outpoint(ctx), counterpartyLocktime: 110000,
    })).rejects.toMatchObject({ name: 'GateFailure', disposition: 'abort' });
  });

  it('EVM-responder margin branch (myChainIsEvm=true uses RESPONDER_LOCK_SEC): a leg too tight for the 12h wall-clock lock throws (abort)', async () => {
    // remaining = 100 blocks => ÷K 30000s. The EVM branch sizes the responder lock at RESPONDER_LOCK_SEC (43200s),
    // so the threshold is 43200+14400 = 57600 > 30000 -> abort. Had it wrongly used LOCKTIME_BLOCKS.responder *
    // poly's 2s/block (= 144s, threshold 14544 < 30000) it would have MINTED — so aborting proves the EVM branch ran.
    const { ctx, redeem } = buildHtlcChain(SYNTH_TIP + 100);
    useChain(ctx);
    await expect(assertLegBuriedForFunding(utxoClient(ctx), {
      theirChain: CHAIN, myChain: 'poly', myChainIsEvm: true, counterpartyRedeemScript: redeem, expectedFundedValueSats: 100000,
      recordedOutpoint: outpoint(ctx), counterpartyLocktime: SYNTH_TIP + 100,
    })).rejects.toMatchObject({ name: 'GateFailure', disposition: 'abort' });
  });

  it('FAIL-CLOSED (hardening): a counterpartyLocktime that disagrees with the authenticated redeemScript CLTV throws (rebuild)', async () => {
    await expect(assertLegBuriedForFunding(utxoClient(CTX), {
      theirChain: CHAIN, myChain: 'bch2', myChainIsEvm: false, counterpartyRedeemScript: REDEEM, expectedFundedValueSats: 100000,
      recordedOutpoint: outpoint(CTX), counterpartyLocktime: HEIGHT_LOCKTIME + 1, // disagrees with the script CLTV
    })).rejects.toMatchObject({ name: 'GateFailure', disposition: 'rebuild' });
  });

  it('FAIL-CLOSED (R-UNDERFUND-001): a dust-funded leg X (authenticated value < offer.sendAmount) aborts — the responder never funds leg Y against a dust leg X', async () => {
    // Leg X is REAL, buried, correct outpoint + consistent CLTV, funded 100000 while the responder is owed 100001.
    // Before the fix the fund gate asserted only value>0 and MINTED a FundProof, so the responder funded its full leg Y.
    await expect(assertLegBuriedForFunding(utxoClient(CTX), {
      theirChain: CHAIN, myChain: 'bch2', myChainIsEvm: false, counterpartyRedeemScript: REDEEM,
      recordedOutpoint: outpoint(CTX), counterpartyLocktime: HEIGHT_LOCKTIME,
      expectedFundedValueSats: 100001, // one sat above the authenticated funded value (100000)
    })).rejects.toMatchObject({ name: 'GateFailure', disposition: 'abort' });
  });

  it('FAIL-CLOSED (fix #1): a single-leaf EVM provider is refused (rearm) — quorum>=2 required', async () => {
    const singleLeaf = new MockEvmProvider({ block: { timestamp: CHAIN_NOW }, blockNumber: 5000 }); // no __leafProviders
    await expect(assertEvmLegBuriedForFunding(singleLeaf as unknown as Provider, {
      chain: 'poly', htlcAddr: '0xhtlc', swapId: '0xswap', requiredConfirmations: 2,
      hashLock: '0x' + '11'.repeat(32), recipient: '0xrecip', minAmount: 1n, token: '0xtok',
    })).rejects.toMatchObject({ name: 'GateFailure', disposition: 'rearm' });
  });
});

// ============================================================================
// (4) ORDERING gate — assertOrderingSafe (pure initiator precondition assertion)
// ============================================================================
describe('assertOrderingSafe (initiator cross-domain ordering)', () => {
  const heightClient = (h: number): GateChainClient =>
    new MockElectrumClient({ height: h }) as unknown as GateChainClient;

  it('HAPPY: a well-ordered pair resolves (responder leg matures safely before ours)', async () => {
    await expect(assertOrderingSafe(heightClient(2_000_000), {
      theirChain: 'bch2', myChain: 'btc', remainingBlocks: 60,
      myLocktime: 2_000_300, myFundingTxid: 'ab'.repeat(32),
    })).resolves.toBeUndefined();
  });

  it('FAIL-CLOSED: ordering inversion (responder leg not safely before ours) throws (abort)', async () => {
    await expect(assertOrderingSafe(heightClient(2_000_000), {
      theirChain: 'bch2', myChain: 'btc', remainingBlocks: 100,
      myLocktime: 2_000_100, myFundingTxid: 'ab'.repeat(32),
    })).rejects.toMatchObject({ name: 'GateFailure', disposition: 'abort' });
  });

  it('FAIL-CLOSED: claim window nearly expired throws (abort)', async () => {
    await expect(assertOrderingSafe(heightClient(2_000_000), {
      theirChain: 'bch2', myChain: 'btc', remainingBlocks: 10, // < K*CLAIM_MARGIN_BLOCKS (48)
      myLocktime: 2_000_400, myFundingTxid: 'ab'.repeat(32),
    })).rejects.toMatchObject({ disposition: 'abort' });
  });

  it('FAIL-CLOSED: own-chain height unavailable (getBlockHeight 0) throws (abort)', async () => {
    await expect(assertOrderingSafe(heightClient(0), {
      theirChain: 'bch2', myChain: 'btc', remainingBlocks: 60, // passes the claim-window gate
      myLocktime: 2_000_300, myFundingTxid: 'ab'.repeat(32),
    })).rejects.toMatchObject({ name: 'GateFailure', disposition: 'abort' });
  });

  it('R277 FAIL-CLOSED: a FUNDED own leg with an unrecoverable locktime throws (abort)', async () => {
    await expect(assertOrderingSafe(heightClient(2_000_000), {
      theirChain: 'bch2', myChain: 'btc', remainingBlocks: 60,
      myLocktime: undefined, myFundingTxid: 'ab'.repeat(32),
    })).rejects.toMatchObject({ disposition: 'abort' });
  });

  it('R277: an UNFUNDED own leg (no locktime, no funding) is safe to skip (resolves)', async () => {
    await expect(assertOrderingSafe(heightClient(2_000_000), {
      theirChain: 'bch2', myChain: 'btc', remainingBlocks: 60,
      myLocktime: undefined, myFundingTxid: undefined,
    })).resolves.toBeUndefined();
  });
});

// ============================================================================
// (5) EVM fund gate — assertEvmLegBuriedForFunding -> FundProof
// ============================================================================
const HTLC_ADDR = '0x405A6dD5b51a00C5F789C9D215e4986ba1Dc9963';
const SWAP_ID = '0x' + 'ab'.repeat(32);
const HASHLOCK = '0x' + '11'.repeat(32);
const RECIPIENT = '0x2222222222222222222222222222222222222222';
const CHAIN_NOW = 1_800_000_000;

function evmFundProvider(over: {
  safeSwap?: ReturnType<typeof makeSwap> | null;
  leafTs?: Array<number | null>;
} = {}): MockEvmProvider {
  const ts = over.leafTs ?? [CHAIN_NOW, CHAIN_NOW];
  const leaves = ts.map((t) => new MockEvmProvider({ block: t === null ? null : { timestamp: t } }));
  const safeSwap = over.safeSwap !== undefined ? over.safeSwap : makeSwap({
    hashLock: HASHLOCK, recipient: RECIPIENT, token: ZERO_ADDRESS,
    amount: 1_000_000_000_000_000_000n, timeLock: 1_900_000_000n,
  });
  return new MockEvmProvider({ safeSwap, swap: safeSwap, leafProviders: leaves, blockNumber: 5000 });
}

describe('assertEvmLegBuriedForFunding (responder EVM fund gate)', () => {
  const base = {
    chain: 'poly', htlcAddr: HTLC_ADDR, swapId: SWAP_ID, requiredConfirmations: 15,
    hashLock: HASHLOCK, recipient: RECIPIENT, minAmount: 1_000_000_000_000_000_000n, token: ZERO_ADDRESS,
  };

  it('HAPPY: reorg-safe depth + full binding + corroborated clock mints a SWAPID-BOUND FundProof', async () => {
    const proof = await assertEvmLegBuriedForFunding(evmFundProvider(), base);
    expect(proof.leg).toBe('X');
    expect(proof.for).toBe('fundY');
    expect(proof.swapId).toBe(SWAP_ID);
    expect(proof.marginBasis).toBe('evm-timestamp');
    expect(proof.capturedAtChainSec).toBe(CHAIN_NOW);
  });

  it('FAIL-CLOSED: an uncorroborated chain clock (a silent leaf) throws (rearm), mints nothing', async () => {
    await expect(assertEvmLegBuriedForFunding(evmFundProvider({ leafTs: [CHAIN_NOW, null] }), base))
      .rejects.toMatchObject({ name: 'GateFailure', disposition: 'rearm' });
  });

  it('FAIL-CLOSED: a hashLock binding mismatch throws (rearm)', async () => {
    const bad = makeSwap({ hashLock: '0x' + '22'.repeat(32), recipient: RECIPIENT, token: ZERO_ADDRESS, amount: 1_000_000_000_000_000_000n, timeLock: 1_900_000_000n });
    await expect(assertEvmLegBuriedForFunding(evmFundProvider({ safeSwap: bad }), base))
      .rejects.toMatchObject({ disposition: 'rearm' });
  });

  it('FAIL-CLOSED: a refund timelock below (chainNow + responderLock + margin) throws (rearm)', async () => {
    const shortTl = makeSwap({ hashLock: HASHLOCK, recipient: RECIPIENT, token: ZERO_ADDRESS, amount: 1_000_000_000_000_000_000n, timeLock: BigInt(CHAIN_NOW) }); // == now, < minTimeLock
    await expect(assertEvmLegBuriedForFunding(evmFundProvider({ safeSwap: shortTl }), base))
      .rejects.toMatchObject({ disposition: 'rearm' });
  });
});

// ============================================================================
// (6) EVM reveal gate — assertEvmRevealSafe -> RevealAuthorization
// ============================================================================
function evmRevealProvider(over: {
  swap?: ReturnType<typeof makeSwap> | null;
  leafTs?: Array<number | null>;
} = {}): MockEvmProvider {
  const ts = over.leafTs ?? [CHAIN_NOW, CHAIN_NOW];
  const leaves = ts.map((t) => new MockEvmProvider({ block: t === null ? null : { timestamp: t } }));
  const swap = over.swap !== undefined ? over.swap : makeSwap({
    hashLock: HASHLOCK, recipient: RECIPIENT, token: ZERO_ADDRESS,
    amount: 1_000_000_000_000_000_000n, timeLock: 1_900_000_000n,
  });
  return new MockEvmProvider({ safeSwap: swap, swap, leafProviders: leaves, blockNumber: 5000 });
}

describe('assertEvmRevealSafe (initiator EVM secret-reveal gate)', () => {
  const base = {
    chain: 'poly', htlcAddr: HTLC_ADDR, swapId: SWAP_ID, requiredConfirmations: 15,
    hashLock: HASHLOCK, recipient: RECIPIENT, minAmount: 1_000_000_000_000_000_000n, token: ZERO_ADDRESS,
  };

  it('HAPPY: reorg-safe depth + fresh-timeLock margin ok mints a SWAPID-BOUND RevealAuthorization', async () => {
    const auth = await assertEvmRevealSafe(evmRevealProvider(), base);
    expect(auth.leg).toBe('Y');
    expect(auth.for).toBe('reveal');
    expect(auth.swapId).toBe(SWAP_ID);
    expect(auth.capturedAtChainSec).toBe(CHAIN_NOW);
  });

  it('FAIL-CLOSED (fix #7): a single-leaf provider is refused (rearm), reveals nothing — quorum>=2 required', async () => {
    const singleLeaf = new MockEvmProvider({ block: { timestamp: CHAIN_NOW }, blockNumber: 5000 }); // no __leafProviders
    await expect(assertEvmRevealSafe(singleLeaf as unknown as Provider, base))
      .rejects.toMatchObject({ name: 'GateFailure', disposition: 'rearm' });
  });

  it('FAIL-CLOSED: gate#2 depth/binding fail (already claimed) throws (rearm), mints nothing', async () => {
    const claimed = makeSwap({ hashLock: HASHLOCK, recipient: RECIPIENT, token: ZERO_ADDRESS, amount: 1_000_000_000_000_000_000n, timeLock: 1_900_000_000n, claimed: true });
    await expect(assertEvmRevealSafe(evmRevealProvider({ swap: claimed }), base))
      .rejects.toMatchObject({ name: 'GateFailure', disposition: 'rearm' });
  });

  it('FAIL-CLOSED: a recipient binding mismatch (same-nonce replacement pays a different address) throws (rearm)', async () => {
    const badRecip = makeSwap({ hashLock: HASHLOCK, recipient: '0x' + '33'.repeat(20), token: ZERO_ADDRESS, amount: 1_000_000_000_000_000_000n, timeLock: 1_900_000_000n });
    await expect(assertEvmRevealSafe(evmRevealProvider({ swap: badRecip }), base))
      .rejects.toMatchObject({ name: 'GateFailure', disposition: 'rearm' });
  });

  it('FAIL-CLOSED: a token binding mismatch (lock funded with a different token) throws (rearm)', async () => {
    const badToken = makeSwap({ hashLock: HASHLOCK, recipient: RECIPIENT, token: '0x' + '44'.repeat(20), amount: 1_000_000_000_000_000_000n, timeLock: 1_900_000_000n });
    await expect(assertEvmRevealSafe(evmRevealProvider({ swap: badToken }), base))
      .rejects.toMatchObject({ name: 'GateFailure', disposition: 'rearm' });
  });

  it('FAIL-CLOSED: a minAmount binding mismatch (lock under-funded) throws (rearm)', async () => {
    const underFunded = makeSwap({ hashLock: HASHLOCK, recipient: RECIPIENT, token: ZERO_ADDRESS, amount: 999_999_999_999_999_999n, timeLock: 1_900_000_000n }); // < minAmount
    await expect(assertEvmRevealSafe(evmRevealProvider({ swap: underFunded }), base))
      .rejects.toMatchObject({ name: 'GateFailure', disposition: 'rearm' });
  });

  it('FAIL-CLOSED: EVM margin < 4h (fresh on-chain timeLock near expiry) throws (abort)', async () => {
    const tight = makeSwap({ hashLock: HASHLOCK, recipient: RECIPIENT, token: ZERO_ADDRESS, amount: 1_000_000_000_000_000_000n, timeLock: BigInt(CHAIN_NOW + 10000) }); // 10000s < 14400s
    await expect(assertEvmRevealSafe(evmRevealProvider({ swap: tight }), base))
      .rejects.toMatchObject({ disposition: 'abort' });
  });

  it('FAIL-CLOSED: an uncorroborated chain clock (silent leaf) throws (rearm)', async () => {
    await expect(assertEvmRevealSafe(evmRevealProvider({ leafTs: [CHAIN_NOW, null] }), base))
      .rejects.toMatchObject({ disposition: 'rearm' });
  });
});

// ============================================================================
// (7) Pure EVM-margin helpers
// ============================================================================
describe('aggregateChainNow / validateEvmTimeLock', () => {
  it('aggregateChainNow requires EVERY leaf and takes the MAX (defeats a behind-reporting leaf)', () => {
    expect(aggregateChainNow([100, 200], 2)).toBe(200);
    expect(aggregateChainNow([100, null], 2)).toBeNull(); // a silent leaf => fail closed
    expect(aggregateChainNow([], 0)).toBeNull();
  });
  it('validateEvmTimeLock accepts only a plausible unix-seconds value', () => {
    expect(validateEvmTimeLock(1_800_000_000n)).toBe(1_800_000_000);
    expect(validateEvmTimeLock(5_000_000)).toBeNull();   // block-number-shaped
    expect(validateEvmTimeLock(null)).toBeNull();
  });
});

// ============================================================================
// (8) Compile-time NON-INTERCHANGEABILITY (fix #1). Validated by `tsc --noEmit`, not the runtime (esbuild strips
// types): if the brands were interchangeable the @ts-expect-error would be UNUSED and tsc would fail.
// ============================================================================
function _brandCompileChecks(fp: FundProof, ra: RevealAuthorization): void {
  const needReveal: (a: RevealAuthorization) => void = () => {};
  const needFund: (f: FundProof) => void = () => {};
  needReveal(ra); // ok
  needFund(fp);   // ok
  // @ts-expect-error a FundProof must NOT satisfy RevealAuthorization
  needReveal(fp);
  // @ts-expect-error a RevealAuthorization must NOT satisfy FundProof
  needFund(ra);
}

describe('brand non-interchangeability', () => {
  it('GateFailure is the thrown type and _brandCompileChecks type-checks', () => {
    expect(new GateFailure('x', 'abort')).toBeInstanceOf(Error);
    expect(typeof _brandCompileChecks).toBe('function');
  });
});
