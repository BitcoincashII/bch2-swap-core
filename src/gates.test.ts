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
 */

import { describe, it, expect, beforeEach } from 'vitest';
import {
  assertRevealSafe, assertLegBuriedForFunding, assertOrderingSafe,
  assertEvmLegBuriedForFunding, assertEvmRevealSafe,
  aggregateChainNow, validateEvmTimeLock, GateFailure,
  type FundProof, type RevealAuthorization, type GateChainClient,
} from './gates';
import {
  __setSpvConfigForTests, __resetSpvCacheForTests, parseHeaderTimeSec,
} from './spv-verifier';
import { blockHashInternal, checkPoW, hash256, type AsertParams } from './spv';
import { hexToBytes, bytesToHex, hash160 } from './htlc-builder';
import {
  MockElectrumClient, buildUtxoRawTx, MockEvmProvider, makeSwap, ZERO_ADDRESS,
  type MockElectrumOpts,
} from './test-mocks';

const toHexRev = (a: Uint8Array) => [...a].reverse().map((b) => b.toString(16).padStart(2, '0')).join('');

// ============================================================================
// Synthetic PoW chain builder — the fund block (checkpoint+1) is a single-tx block whose one tx funds a P2SH we
// control, so its merkle root == that funding txid and an empty-branch Merkle proof verifies. `tipAgeSec` shifts
// every timestamp uniformly back (constant ASERT target) to exercise spvVerifiedTipFresh's staleness bound.
// ============================================================================
function buildSynthChain(opts: {
  anchorHeight: number; count: number; spacing: number; bits: number; fundSpkHex: string; tipAgeSec?: number;
}) {
  const { anchorHeight, count, spacing, bits, fundSpkHex, tipAgeSec = 0 } = opts;
  const powLimit = 1n << 255n;
  const nowSec = Math.floor(Date.now() / 1000);
  const anchorParentTime = nowSec - spacing * (count + 1) - tipAgeSec; // => tip block time == nowSec - tipAgeSec
  const T = (height: number) => anchorParentTime + spacing * (height - anchorHeight + 1);
  const params: AsertParams = { anchorHeight, anchorBits: bits, anchorParentTime, spacing: BigInt(spacing), powLimit, halfLife: () => 172800n };

  const fundHeight = anchorHeight + 1;
  const fund = buildUtxoRawTx([{ value: 100000, scriptPubKeyHex: fundSpkHex }]);
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
  return { params, checkpoint, headersByHeight, fundHeight, fundTxid: fund.txid, fundRawHex: fund.rawTxHex, tip };
}

// A fixed arbitrary "redeem script" — only its hash160 (the P2SH the funding output pays) matters to the gates.
const REDEEM = new Uint8Array(50).fill(0x77);
const FUND_SPK = 'a914' + bytesToHex(hash160(REDEEM)) + '87';
// Inject the synthetic PoW fixture UNDER a real UTXO chain so the timelock-margin gates (which read
// chainConfigs[chain].avgBlockTimeSec — no default) see a valid block time. bc2's requiredConfirmations (3) is
// <= the fixture depth (4). __setSpvConfigForTests forces asert-mode against the synthetic checkpoint.
const CHAIN = 'bc2';

const CTX = buildSynthChain({ anchorHeight: 100000, count: 4, spacing: 600, bits: 0x20010000, fundSpkHex: FUND_SPK });
const TIP_TIME = parseHeaderTimeSec(CTX.headersByHeight[CTX.tip])!; // chain time getChainTimeSec will report

type Ctx = ReturnType<typeof buildSynthChain>;
function utxoClient(ctx: Ctx, over: Partial<MockElectrumOpts> = {}): GateChainClient {
  return new MockElectrumClient({
    headersByHeight: ctx.headersByHeight,
    merkleProof: { block_height: ctx.fundHeight, merkle: [], pos: 0 },
    utxos: [{ tx_hash: ctx.fundTxid, tx_pos: 0, value: 100000, height: ctx.fundHeight }],
    rawTxByTxid: { [ctx.fundTxid]: ctx.fundRawHex },
    height: ctx.tip,
    tipHeaderHex: ctx.headersByHeight[ctx.tip],
    ...over,
  }) as unknown as GateChainClient;
}
const outpoint = (ctx: Ctx) => ({ tx_hash: ctx.fundTxid, tx_pos: 0 });

// ============================================================================
// (1) REVEAL gate — assertRevealSafe -> RevealAuthorization
// ============================================================================
describe('assertRevealSafe (initiator secret-reveal gate)', () => {
  beforeEach(() => {
    __setSpvConfigForTests(CHAIN, CTX.params, CTX.checkpoint);
    __resetSpvCacheForTests();
  });

  it('HAPPY (height-CLTV): deep+fresh+margin-ok mints an OUTPOINT-BOUND RevealAuthorization', async () => {
    const auth = await assertRevealSafe(utxoClient(CTX), {
      role: 'initiator', theirChain: CHAIN, counterpartyRedeemScript: REDEEM,
      recordedOutpoint: outpoint(CTX), counterpartyLocktime: CTX.tip + 100, // 100 blocks => ÷K 30000s >= 4h
    });
    expect(auth.leg).toBe('Y');
    expect(auth.for).toBe('reveal');
    expect(auth.marginBasis).toBe('height-cltv');
    expect(auth.outpoint).toEqual({ tx_hash: CTX.fundTxid, tx_pos: 0 });
    expect(auth.chain).toBe(CHAIN);
    expect(auth.capturedAtChainSec).toBe(TIP_TIME);
  });

  it('HAPPY (timestamp-CLTV): a unix-timestamp CLTV anchored to chain time mints RevealAuthorization', async () => {
    const auth = await assertRevealSafe(utxoClient(CTX), {
      role: 'initiator', theirChain: CHAIN, counterpartyRedeemScript: REDEEM,
      recordedOutpoint: outpoint(CTX), counterpartyLocktime: TIP_TIME + 20000, // 20000s > 4h margin
    });
    expect(auth.marginBasis).toBe('timestamp-cltv');
    expect(auth.for).toBe('reveal');
  });

  it('FAIL-CLOSED: a VANISHED / double-spent outpoint throws (rebuild) and mints nothing', async () => {
    const client = utxoClient(CTX, { utxos: [] });
    await expect(assertRevealSafe(client, {
      role: 'initiator', theirChain: CHAIN, counterpartyRedeemScript: REDEEM,
      recordedOutpoint: outpoint(CTX), counterpartyLocktime: CTX.tip + 100,
    })).rejects.toMatchObject({ name: 'GateFailure', disposition: 'rebuild' });
  });

  it('FAIL-CLOSED: a spent-less / malformed recorded outpoint throws (rebuild)', async () => {
    await expect(assertRevealSafe(utxoClient(CTX), {
      role: 'initiator', theirChain: CHAIN, counterpartyRedeemScript: REDEEM,
      recordedOutpoint: { tx_hash: 'not-hex', tx_pos: 0 }, counterpartyLocktime: CTX.tip + 100,
    })).rejects.toMatchObject({ disposition: 'rebuild' });
  });

  it('FAIL-CLOSED: an over-reported / unverifiable SPV depth (proxy tip beyond supplied headers) throws (rearm)', async () => {
    const client = utxoClient(CTX, { height: CTX.tip + 10 }); // filter passes; SPV cannot reach the inflated tip
    await expect(assertRevealSafe(client, {
      role: 'initiator', theirChain: CHAIN, counterpartyRedeemScript: REDEEM,
      recordedOutpoint: outpoint(CTX), counterpartyLocktime: CTX.tip + 100,
    })).rejects.toMatchObject({ name: 'GateFailure', disposition: 'rearm' });
  });

  it('FAIL-CLOSED: a real-but-STALE tip (height-CLTV under-report guard) throws (rearm)', async () => {
    const stale = buildSynthChain({ anchorHeight: 100000, count: 4, spacing: 600, bits: 0x20010000, fundSpkHex: FUND_SPK, tipAgeSec: 3 * 3600 });
    __setSpvConfigForTests(CHAIN, stale.params, stale.checkpoint);
    __resetSpvCacheForTests();
    await expect(assertRevealSafe(utxoClient(stale), {
      role: 'initiator', theirChain: CHAIN, counterpartyRedeemScript: REDEEM,
      recordedOutpoint: outpoint(stale), counterpartyLocktime: stale.tip + 100,
    })).rejects.toMatchObject({ name: 'GateFailure', disposition: 'rearm' });
  });

  it('FAIL-CLOSED: margin < 4h on the height-CLTV branch throws (abort), mints nothing', async () => {
    await expect(assertRevealSafe(utxoClient(CTX), {
      role: 'initiator', theirChain: CHAIN, counterpartyRedeemScript: REDEEM,
      recordedOutpoint: outpoint(CTX), counterpartyLocktime: CTX.tip + 40, // ÷K 12000s < 14400s
    })).rejects.toMatchObject({ name: 'GateFailure', disposition: 'abort' });
  });

  it('FAIL-CLOSED: margin < 4h on the timestamp-CLTV branch throws (abort)', async () => {
    await expect(assertRevealSafe(utxoClient(CTX), {
      role: 'initiator', theirChain: CHAIN, counterpartyRedeemScript: REDEEM,
      recordedOutpoint: outpoint(CTX), counterpartyLocktime: TIP_TIME + 1000, // 1000s < 14400s
    })).rejects.toMatchObject({ disposition: 'abort' });
  });

  it('FAIL-CLOSED: chain time unavailable (empty tip header) throws (rearm)', async () => {
    const client = utxoClient(CTX, { tipHeaderHex: '' });
    await expect(assertRevealSafe(client, {
      role: 'initiator', theirChain: CHAIN, counterpartyRedeemScript: REDEEM,
      recordedOutpoint: outpoint(CTX), counterpartyLocktime: CTX.tip + 100,
    })).rejects.toMatchObject({ disposition: 'rearm' });
  });

  it('RESPONDER (already-public secret) is NOT margin-blocked even with a near-expiry counterparty leg', async () => {
    const auth = await assertRevealSafe(utxoClient(CTX), {
      role: 'responder', theirChain: CHAIN, counterpartyRedeemScript: REDEEM,
      recordedOutpoint: outpoint(CTX), counterpartyLocktime: CTX.tip + 1, // would be far too tight for an initiator
    });
    expect(auth.marginBasis).toBe('none');
    expect(auth.role).toBe('responder');
  });
});

// ============================================================================
// (2) FUND-Y gate — assertLegBuriedForFunding -> FundProof
// ============================================================================
describe('assertLegBuriedForFunding (responder fund-Y gate)', () => {
  beforeEach(() => {
    __setSpvConfigForTests(CHAIN, CTX.params, CTX.checkpoint);
    __resetSpvCacheForTests();
  });

  it('HAPPY: leg-X buried + responder margin ok mints an OUTPOINT-BOUND FundProof', async () => {
    const proof = await assertLegBuriedForFunding(utxoClient(CTX), {
      theirChain: CHAIN, myChain: 'bch2', myChainIsEvm: false, counterpartyRedeemScript: REDEEM,
      recordedOutpoint: outpoint(CTX), counterpartyLocktime: CTX.tip + 200, // ÷K 60000s >= 43200+14400
    });
    expect(proof.leg).toBe('X');
    expect(proof.for).toBe('fundY');
    expect(proof.outpoint).toEqual({ tx_hash: CTX.fundTxid, tx_pos: 0 });
    expect(proof.role).toBe('responder');
  });

  it('FAIL-CLOSED: responder margin too tight (initiator leg expires too soon) throws (abort)', async () => {
    await expect(assertLegBuriedForFunding(utxoClient(CTX), {
      theirChain: CHAIN, myChain: 'bch2', myChainIsEvm: false, counterpartyRedeemScript: REDEEM,
      recordedOutpoint: outpoint(CTX), counterpartyLocktime: CTX.tip + 100, // ÷K 30000s < 57600s
    })).rejects.toMatchObject({ name: 'GateFailure', disposition: 'abort' });
  });

  it('FAIL-CLOSED: a vanished funding outpoint throws (rebuild) and mints nothing', async () => {
    await expect(assertLegBuriedForFunding(utxoClient(CTX, { utxos: [] }), {
      theirChain: CHAIN, myChain: 'bch2', myChainIsEvm: false, counterpartyRedeemScript: REDEEM,
      recordedOutpoint: outpoint(CTX), counterpartyLocktime: CTX.tip + 200,
    })).rejects.toMatchObject({ disposition: 'rebuild' });
  });

  it('FAIL-CLOSED (fix #4): a real-but-STALE tip fails the fund margin (rearm) — was silently minting before', async () => {
    // A locktime that PASSES the happy margin against the RAW tip (tip+200 => ÷K 60000s >= 57600s), so the ONLY
    // guard that can catch it is the spvVerifiedTipFresh under-report bound the reveal gate had but the fund gate
    // had dropped. Before fix #4 this MINTED a FundProof against a near-expiry counterparty leg.
    const stale = buildSynthChain({ anchorHeight: 100000, count: 4, spacing: 600, bits: 0x20010000, fundSpkHex: FUND_SPK, tipAgeSec: 3 * 3600 });
    __setSpvConfigForTests(CHAIN, stale.params, stale.checkpoint);
    __resetSpvCacheForTests();
    await expect(assertLegBuriedForFunding(utxoClient(stale), {
      theirChain: CHAIN, myChain: 'bch2', myChainIsEvm: false, counterpartyRedeemScript: REDEEM,
      recordedOutpoint: outpoint(stale), counterpartyLocktime: stale.tip + 200,
    })).rejects.toMatchObject({ name: 'GateFailure', disposition: 'rearm' });
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
// (3) ORDERING gate — assertOrderingSafe (pure initiator precondition assertion)
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
// (4) EVM fund gate — assertEvmLegBuriedForFunding -> FundProof
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
// (5) EVM reveal gate — assertEvmRevealSafe -> RevealAuthorization
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

  it('FAIL-CLOSED: gate#2 depth/binding fail (already claimed) throws (rearm), mints nothing', async () => {
    const claimed = makeSwap({ hashLock: HASHLOCK, recipient: RECIPIENT, token: ZERO_ADDRESS, amount: 1_000_000_000_000_000_000n, timeLock: 1_900_000_000n, claimed: true });
    await expect(assertEvmRevealSafe(evmRevealProvider({ swap: claimed }), base))
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
// (6) Pure EVM-margin helpers
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
// (7) Compile-time NON-INTERCHANGEABILITY (fix #1). Validated by `tsc --noEmit`, not the runtime (esbuild strips
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
