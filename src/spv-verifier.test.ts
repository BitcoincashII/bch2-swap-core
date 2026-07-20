import { describe, it, expect, beforeEach } from 'vitest';
import {
  verifyConfirmations, verifyFundingHeight, spvSupported, spvVerifiedTipFresh,
  getChainTimeSec, parseHeaderTimeSec,
  __resetSpvCacheForTests, __setSpvConfigForTests, __getVerifiedTipForTests,
} from './spv-verifier';
import { BCH2_MAINNET_ASERT, parseHeader, blockHashInternal, checkPoW, hash256, type AsertParams } from './spv';
import { hexToBytes, bytesToHex } from './htlc-builder';
import { MockElectrumClient, buildUtxoRawTx } from './test-mocks';

const fromHex = (h: string) => Uint8Array.from(h.match(/../g)!.map((b) => parseInt(b, 16)));
const toHexRev = (a: Uint8Array) => [...a].reverse().map((b) => b.toString(16).padStart(2, '0')).join('');
const mockClient = (headersByHeight: Record<number, string> = {}, extra: object = {}) =>
  new MockElectrumClient({ headersByHeight, ...extra });

// ============================================================================
// Real BCH2 mainnet headers 71097–71102 (same fixture as spv.test.ts).
// ============================================================================
const FIRST = 71097;
const REAL = [
  '0000002044be045689712b566dde9ef9a853fb39c77b6ebc109491f102000000000000004211ff648bd314aa56c537fcc9940f58560102af1226b3d20e547af8f95fde25da594c6a70ef04191d08bd38',
  '008027228e950c8566e6de6b126b0a22c85204aabaa5d8419431557201000000000000008b8df0d0d0c2e7242d9fa3e56072ac12f0556c6988d4663101916a94956d241f425a4c6a3fa104191b3da94d',
  '00a00120fa2f25170fc18ee4796838b8526dbc15afc1262700a65604000000000000000095a31c32d2d439bf6850f3a64b1164335b92f965ddee41c377ae0770396b3bf8a95a4c6a67350419ad909a05',
  '00000120a829134273bdb6c64d09f7cee860b81f4e7423e66c9ccd930000000000000000a890856478bca81a6b12768aa79809afcd820e71d5bd91c77ebe8b28c0b58e6a775b4c6a1fd303194953a996',
  '004098270eb697611cd36ca03ef9562ea73fcb1956210ea70bc22d1a0100000000000000f0c96905e81e4d0a391dbdef173e8b7db261bea93f6e146b660758945940af26025d4c6a908b03197674ff45',
  '00e0ff3fff05ee027d7d5aeca57c5d91fe459be6ddc8408d2a331cda02000000000000009ca74bba8f05948de78c108bf1828e10b2b2ad72658af0823ab26ba74cca0f68955d4c6a796803198ce29671',
];
const realByHeight = (): Record<number, string> => { const b: Record<number, string> = {}; REAL.forEach((h, i) => { b[FIRST + i] = h; }); return b; };

describe('spv-verifier — real BCH2 mainnet fixtures', () => {
  beforeEach(() => __resetSpvCacheForTests());

  it('spvSupported: all four UTXO mainnets covered (bch2, bch, btc, bc2); EVM not', () => {
    expect(spvSupported('bch2')).toBe(true);
    expect(spvSupported('bch')).toBe(true);
    expect(spvSupported('btc')).toBe(true);
    expect(spvSupported('bc2')).toBe(true);
    expect(spvSupported('eth')).toBe(false);
    expect(spvSupported('polygon')).toBe(false);
  });

  it('verifyConfirmations is fail-closed on out-of-scope inputs', async () => {
    const c = mockClient();
    const txid = 'a'.repeat(64);
    await expect(verifyConfirmations(c, 'btc', txid, 90000, '00', 95000)).rejects.toThrow();   // below btc checkpoint
    await expect(verifyConfirmations(c, 'bch2', txid, 53000, '00', 95000)).rejects.toThrow();  // pre-fork height
    await expect(verifyConfirmations(c, 'bch2', txid, 60000, '00', 95000)).rejects.toThrow();  // below checkpoint
    await expect(verifyConfirmations(c, 'bch2', txid, 95001, '00', 95000)).rejects.toThrow();  // above tip
    await expect(verifyConfirmations(c, 'nope', txid, 95000, '00', 95000)).rejects.toThrow();  // unsupported chain
  });

  it('extends + verifies a real header chain from an injected checkpoint', async () => {
    const H = REAL.map((h) => parseHeader(fromHex(h)));
    __setSpvConfigForTests('bch2', BCH2_MAINNET_ASERT, { height: FIRST, hashDisplay: toHexRev(blockHashInternal(H[0].raw)), time: H[0].time });
    __resetSpvCacheForTests();
    const tip = await __getVerifiedTipForTests(mockClient(realByHeight()), 'bch2', FIRST + 5);
    expect(tip).toBe(FIRST + 5);
  });

  it('rejects a chain whose headers do not link to the checkpoint', async () => {
    const H = REAL.map((h) => parseHeader(fromHex(h)));
    // checkpoint hash deliberately wrong → first fetched header cannot link
    __setSpvConfigForTests('bch2', BCH2_MAINNET_ASERT, { height: FIRST, hashDisplay: '11'.repeat(32), time: H[0].time });
    __resetSpvCacheForTests();
    await expect(__getVerifiedTipForTests(mockClient(realByHeight()), 'bch2', FIRST + 5)).rejects.toThrow();
  });

  describe('spvVerifiedTipFresh (timing/margin-gate height verification)', () => {
    function withRealChain() {
      const H = REAL.map((h) => parseHeader(fromHex(h)));
      __setSpvConfigForTests('bch2', BCH2_MAINNET_ASERT, { height: FIRST, hashDisplay: toHexRev(blockHashInternal(H[0].raw)), time: H[0].time });
      __resetSpvCacheForTests();
      return mockClient(realByHeight());
    }

    it('returns the PoW-verified tip when the tip is within the staleness window', async () => {
      const tenYears = 10 * 365 * 24 * 60 * 60;
      const tip = await spvVerifiedTipFresh(withRealChain(), 'bch2', FIRST + 5, tenYears);
      expect(tip).toBe(FIRST + 5);
    });

    it('FAIL-CLOSED: rejects a real-but-stale tip (under-report guard, default 2h window)', async () => {
      await expect(spvVerifiedTipFresh(withRealChain(), 'bch2', FIRST + 5)).rejects.toThrow(/stale|under-report/i);
    });

    it('FAIL-CLOSED: rejects an over-reported tip the proxy cannot supply PoW for', async () => {
      const tenYears = 10 * 365 * 24 * 60 * 60;
      await expect(spvVerifiedTipFresh(withRealChain(), 'bch2', FIRST + 50, tenYears)).rejects.toThrow();
    });

    it('FAIL-CLOSED on out-of-scope inputs (unsupported chain, at/below checkpoint, non-integer)', async () => {
      const c = withRealChain();
      await expect(spvVerifiedTipFresh(c, 'eth', FIRST + 5)).rejects.toThrow();       // no SPV for eth
      await expect(spvVerifiedTipFresh(c, 'bch2', FIRST)).rejects.toThrow();          // == checkpoint
      await expect(spvVerifiedTipFresh(c, 'bch2', FIRST - 10)).rejects.toThrow();     // below checkpoint
      await expect(spvVerifiedTipFresh(c, 'bch2', 71097.5 as number)).rejects.toThrow(); // non-integer
    });
  });

  it('verifyFundingHeight FAIL-CLOSED on out-of-scope + unsupplied heights', async () => {
    const H = REAL.map((h) => parseHeader(fromHex(h)));
    __setSpvConfigForTests('bch2', BCH2_MAINNET_ASERT, { height: FIRST, hashDisplay: toHexRev(blockHashInternal(H[0].raw)), time: H[0].time });
    __resetSpvCacheForTests();
    await expect(verifyFundingHeight(mockClient(), 'eth', FIRST + 1)).rejects.toThrow();       // unsupported
    await expect(verifyFundingHeight(mockClient(), 'bch2', FIRST)).rejects.toThrow();          // == checkpoint
    await expect(verifyFundingHeight(mockClient(realByHeight()), 'bch2', FIRST + 50)).rejects.toThrow(); // proxy can't supply PoW headers
  });
});

// ============================================================================
// Real BC2 (legacy 2016-retarget) chain — exercises extendVerifiedChain's cfg.mode==='legacy' branch.
// ============================================================================
describe('spv-verifier — real BC2 (legacy) chain from its boundary checkpoint', () => {
  beforeEach(() => __resetSpvCacheForTests());

  const bc2RangeHex = '00009b2c2f93bdd0aa23e1dc9445cff0037ae077a8b7a7c410db3c440000000000000000a0f32a3e461c9b3e2030ef0aeddcab4ac80e4f89e6a29fd2f49c336adb938a92aee4106a34af73184862de7a00400a23a0411e3369852ba3f41717c2805b740e4a83accfe04df06c0000000000000000ecf1626dde3eb6467d653861641ceec887632b0c0ced7411ac4a9eb8731659ccb4e4106a34af73182864a49a0040ea26cbd470a3967a0abcd55ec7ae68b43c2cd65d12e17ae8c1230000000000000000cd2e841b008f51dccb306126e1cce24853fc6d2ba8e447f334fee1aa9ac029dc49e5106ab6883e18523e81440080002007e94af42e82df453f318d6c2a14b5866d73c2bc22fa3a3000000000000000006e6bf4bd85a47b7e49554d4f22b258c99f983f66567c2fc036b35114391e8815a1f1106ab6883e18d7712e2d00a0062020763c7b242ae010d258b3a8fc0e943bf026b1ae453dab1600000000000000005e18c4fb312be5bbeefcef8ecbf0e2fec7428ae560492d7231d43f693f9e382a52f2106ab6883e18ab468a180000002a521dda97ebf24728a46d8eb676dd81e059be50c6fc604d2800000000000000009eaf1a2277d4c6dac61957fb98eabf727380b45dad088e4bd5af5cc55e86f7b59401116ab6883e18893f42c9';
  const bc2ByHeight = (): Record<number, string> => {
    const byH: Record<number, string> = {};
    for (const h of [56449, 56450, 56451]) { const i = h - 56446; byH[h] = bc2RangeHex.slice(i * 160, (i + 1) * 160); }
    return byH;
  };

  it('extends + verifies the real legacy chain (56449..56451) to its tip', async () => {
    const tip = await __getVerifiedTipForTests(mockClient(bc2ByHeight()), 'bc2', 56451);
    expect(tip).toBe(56451);
  });

  it('FAIL-CLOSED: a corrupted (non-linking) first header throws', async () => {
    __resetSpvCacheForTests();
    const byH = bc2ByHeight();
    const badFirst = byH[56449].slice(0, 8) + 'ff'.repeat(32) + byH[56449].slice(72);
    await expect(__getVerifiedTipForTests(mockClient({ ...byH, 56449: badFirst }), 'bc2', 56451)).rejects.toThrow();
  });
});

// ============================================================================
// Synthetic easy-difficulty PoW chain — lets the POSITIVE verifyConfirmations path (real Merkle proof +
// provenTxid binding) and the exact R175 `provenTxid !== txid` guard run fully OFFLINE (real BCH2/BCH/BTC/BC2
// mainnet difficulty is unmineable in a unit test). The trust model is IDENTICAL: verifyHeaderChain still
// enforces link+PoW+ASERT-nBits+future-time on every synthetic header; only the difficulty target is eased.
// ============================================================================
function u32le(dv: DataView, off: number, v: number) { dv.setUint32(off, v >>> 0, true); }

/**
 * Build + PoW-mine a synthetic ASERT chain of `count` blocks above an injected checkpoint. Timestamps run at
 * perfect `spacing`, so the ASERT-required target stays constant at `bits` (verifyHeaderChain's exact-nBits
 * check passes). anchorParentTime is set so the tip block time == ~now (keeps spvVerifiedTipFresh's freshness
 * bound satisfiable). The fund block (checkpoint+1) is a single-tx block: its merkle root == the funding txid,
 * so an empty-branch Merkle proof verifies. Returns everything the tests need.
 */
function buildSynthChain(opts: { anchorHeight: number; count: number; spacing: number; bits: number }) {
  const { anchorHeight, count, spacing, bits } = opts;
  const powLimit = 1n << 255n; // large enough that target(bits) <= powLimit; still a real PoW bound (~2^248 target)
  const nowSec = Math.floor(Date.now() / 1000);
  const anchorParentTime = nowSec - spacing * (count + 1); // => tip block time == nowSec
  const T = (height: number) => anchorParentTime + spacing * (height - anchorHeight + 1);
  const params: AsertParams = { anchorHeight, anchorBits: bits, anchorParentTime, spacing: BigInt(spacing), powLimit, halfLife: () => 172800n };

  // The funding tx for the fund block (checkpoint+1); its true txid + the block's single-leaf merkle root.
  const fundHeight = anchorHeight + 1;
  const fund = buildUtxoRawTx([{ value: 100000, scriptPubKeyHex: 'a914' + 'bb'.repeat(20) + '87' }]);
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
    u32le(dv, 0, 0x20000000);          // version
    raw.set(prevHashInternal, 4);      // prevHash (internal order)
    raw.set(merkle, 36);               // merkle root (internal order)
    u32le(dv, 68, T(height));          // time
    u32le(dv, 72, bits);               // bits
    let mined = false;
    for (let nonce = 0; nonce < 0xffffffff; nonce++) {
      u32le(dv, 76, nonce);
      if (checkPoW(raw, bits, powLimit)) { mined = true; break; }
    }
    if (!mined) throw new Error(`could not mine synthetic header at ${height}`);
    headersByHeight[height] = bytesToHex(raw);
    prevHashInternal = blockHashInternal(raw);
  }
  const tip = anchorHeight + count;
  return { params, checkpoint, headersByHeight, fundHeight, fundTxid: fund.txid, fundRawHex: fund.rawTxHex, tip, count, anchorHeight };
}

describe('spv-verifier — FAIL-CLOSED MATRIX (synthetic PoW chain)', () => {
  const CHAIN = 'synth';
  let ctx: ReturnType<typeof buildSynthChain>;

  beforeEach(() => {
    ctx = buildSynthChain({ anchorHeight: 100000, count: 4, spacing: 600, bits: 0x20010000 });
    __setSpvConfigForTests(CHAIN, ctx.params, ctx.checkpoint);
    __resetSpvCacheForTests();
  });

  // (d) DEEP + FRESH + VALID → verifies.
  it('POSITIVE: a deep+fresh+valid funding verifies and returns the exact SPV confirmation depth', async () => {
    const client = mockClient(ctx.headersByHeight, { merkleProof: { block_height: ctx.fundHeight, merkle: [], pos: 0 } });
    const conf = await verifyConfirmations(client, CHAIN, ctx.fundTxid, ctx.fundHeight, ctx.fundRawHex, ctx.tip);
    expect(conf).toBe(ctx.tip - ctx.fundHeight + 1); // == count (4)
    expect(conf).toBe(ctx.count);
    // spvVerifiedTipFresh on the same fresh chain returns the verified tip (freshness bound satisfied)
    expect(await spvVerifiedTipFresh(client, CHAIN, ctx.tip)).toBe(ctx.tip);
    // verifyFundingHeight on a real, PoW-backed height returns a tip >= the claim
    expect(await verifyFundingHeight(client, CHAIN, ctx.fundHeight)).toBeGreaterThanOrEqual(ctx.fundHeight);
  });

  // (c) MERKLE PROOF WHOSE DERIVED txid != EXPECTED txid → fail closed (the R175-CRITICAL binding guard).
  it('FAIL-CLOSED (c): a valid Merkle proof that proves a DIFFERENT txid than requested is rejected', async () => {
    // Proof folds to the fund block's real merkle root (so verifyMerkleInclusion PASSES), but we request a
    // different txid → provenTxid !== requested → throws. This is exactly the fabricated-depth vector R175 closes.
    const client = mockClient(ctx.headersByHeight, { merkleProof: { block_height: ctx.fundHeight, merkle: [], pos: 0 } });
    const wrongTxid = 'a'.repeat(64);
    await expect(verifyConfirmations(client, CHAIN, wrongTxid, ctx.fundHeight, ctx.fundRawHex, ctx.tip))
      .rejects.toThrow(/proven txid/i);
  });

  it('FAIL-CLOSED (c2): a fabricated Merkle proof that does not fold to the block merkle root is rejected', async () => {
    // Query a NON-funding block (height fundHeight+1, whose merkle root is filler); serve the funding tx's
    // bytes with an empty branch → reconstructed root != that block's real header merkle root → throws.
    const otherHeight = ctx.fundHeight + 1;
    const client = mockClient(ctx.headersByHeight, { merkleProof: { block_height: otherHeight, merkle: [], pos: 0 } });
    await expect(verifyConfirmations(client, CHAIN, ctx.fundTxid, otherHeight, ctx.fundRawHex, ctx.tip))
      .rejects.toThrow(/merkle/i);
  });

  // (a) SHORT / INSUFFICIENT DEPTH → fail closed. The proxy claims a tip it cannot supply PoW headers for, so the
  // claimed burial depth cannot be verified. extendVerifiedChain cannot reach the over-reported tip → throws.
  it('FAIL-CLOSED (a): an over-reported / unverifiable depth (tip beyond supplied headers) is rejected', async () => {
    const client = mockClient(ctx.headersByHeight, { merkleProof: { block_height: ctx.fundHeight, merkle: [], pos: 0 } });
    await expect(verifyConfirmations(client, CHAIN, ctx.fundTxid, ctx.fundHeight, ctx.fundRawHex, ctx.tip + 10))
      .rejects.toThrow();
    // and a funding claimed to sit ABOVE the tip is rejected outright (fabricated depth)
    await expect(verifyConfirmations(client, CHAIN, ctx.fundTxid, ctx.tip + 1, ctx.fundRawHex, ctx.tip))
      .rejects.toThrow(/above tip/i);
  });

  it('FAIL-CLOSED: a wrong proof block_height (proof for a different block than claimed) is rejected', async () => {
    const client = mockClient(ctx.headersByHeight, { merkleProof: { block_height: ctx.fundHeight + 1, merkle: [], pos: 0 } });
    await expect(verifyConfirmations(client, CHAIN, ctx.fundTxid, ctx.fundHeight, ctx.fundRawHex, ctx.tip))
      .rejects.toThrow(/proof height/i);
  });

  // (b) STALE TIP → fail closed. The synthetic chain is always anchored at ~now (needed for the POSITIVE case),
  // so the canonical real-but-stale tip is the genuinely years-old REAL BCH2 fixture: its header chain PoW-verifies
  // but its tip timestamp is far outside the 2h freshness bound → spvVerifiedTipFresh rejects (under-report guard).
  it('FAIL-CLOSED (b): a real-but-stale verified tip is rejected by the freshness bound', async () => {
    const H = REAL.map((h) => parseHeader(fromHex(h)));
    __setSpvConfigForTests('bch2', BCH2_MAINNET_ASERT, { height: FIRST, hashDisplay: toHexRev(blockHashInternal(H[0].raw)), time: H[0].time });
    __resetSpvCacheForTests();
    await expect(spvVerifiedTipFresh(mockClient(realByHeight()), 'bch2', FIRST + 5)).rejects.toThrow(/stale|under-report/i);
  });
});

// ============================================================================
// getChainTimeSec / parseHeaderTimeSec (fix #9 — chain-time source, ported from the app's SwapExecute.tsx).
// ============================================================================
describe('getChainTimeSec / parseHeaderTimeSec', () => {
  it('parseHeaderTimeSec reads the little-endian nTime field (offset 68) from a real header', () => {
    const h = REAL[0];
    expect(parseHeaderTimeSec(h)).toBe(parseHeader(fromHex(h)).time);
  });

  it('parseHeaderTimeSec returns null for a too-short / malformed header', () => {
    expect(parseHeaderTimeSec('00')).toBeNull();
    expect(parseHeaderTimeSec('')).toBeNull();
    expect(parseHeaderTimeSec(undefined as unknown as string)).toBeNull();
  });

  it('getChainTimeSec returns the tip header nTime from a headers.subscribe reply', async () => {
    const client = mockClient({}, { tipHeaderHex: REAL[5] });
    expect(await getChainTimeSec(client)).toBe(parseHeader(fromHex(REAL[5])).time);
  });

  it('getChainTimeSec returns null when the reply carries no usable header hex', async () => {
    const client = mockClient({}, { tipHeaderHex: '' });
    expect(await getChainTimeSec(client)).toBeNull();
  });
});
