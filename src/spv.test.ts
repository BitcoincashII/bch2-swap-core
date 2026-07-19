import { describe, it, expect } from 'vitest';
import {
  targetFromCompact, compactFromTarget, calculateASERT, getNextWorkRequiredASERT,
  BCH2_MAINNET_ASERT, BCH_MAINNET_ASERT, parseHeader, checkPoW, hash256, merkleRootFromBranch, verifyMerkleInclusion,
  blockHashInternal, verifyChainFromCheckpoint, getNextWorkRequiredLegacy, BTC_MAINNET_LEGACY, BC2_MAINNET_LEGACY, verifyLegacyChunk,
} from './spv';

const POW = BCH2_MAINNET_ASERT.powLimit;
const fromHex = (h: string) => Uint8Array.from(h.match(/../g)!.map((b) => parseInt(b, 16)));
const toHexRev = (a: Uint8Array) => [...a].reverse().map((b) => b.toString(16).padStart(2, '0')).join('');

// Real BCH2 MAINNET headers, heights 71097–71102, captured 2026-07-07 from electrum.bch2.org:50002.
// Permanent bit-exact regression guard for the ASERT port. Validated live at capture time: 120/120 nBits +
// PoW + links over heights 70982–71102. If this ever fails, the ASERT/compact math has drifted from consensus.
const REAL_FIRST_HEIGHT = 71097;
const REAL_HEADERS = [
  '0000002044be045689712b566dde9ef9a853fb39c77b6ebc109491f102000000000000004211ff648bd314aa56c537fcc9940f58560102af1226b3d20e547af8f95fde25da594c6a70ef04191d08bd38',
  '008027228e950c8566e6de6b126b0a22c85204aabaa5d8419431557201000000000000008b8df0d0d0c2e7242d9fa3e56072ac12f0556c6988d4663101916a94956d241f425a4c6a3fa104191b3da94d',
  '00a00120fa2f25170fc18ee4796838b8526dbc15afc1262700a65604000000000000000095a31c32d2d439bf6850f3a64b1164335b92f965ddee41c377ae0770396b3bf8a95a4c6a67350419ad909a05',
  '00000120a829134273bdb6c64d09f7cee860b81f4e7423e66c9ccd930000000000000000a890856478bca81a6b12768aa79809afcd820e71d5bd91c77ebe8b28c0b58e6a775b4c6a1fd303194953a996',
  '004098270eb697611cd36ca03ef9562ea73fcb1956210ea70bc22d1a0100000000000000f0c96905e81e4d0a391dbdef173e8b7db261bea93f6e146b660758945940af26025d4c6a908b03197674ff45',
  '00e0ff3fff05ee027d7d5aeca57c5d91fe459be6ddc8408d2a331cda02000000000000009ca74bba8f05948de78c108bf1828e10b2b2ad72658af0823ab26ba74cca0f68955d4c6a796803198ce29671',
];

describe('compact nBits ⇄ target round-trip (arith_uint256 parity)', () => {
  for (const bits of [0x1903a30c, 0x1d00ffff, 0x1802aee0, 0x1b0404cb]) {
    it(`0x${bits.toString(16)} round-trips`, () => {
      const { target, negative, overflow } = targetFromCompact(bits);
      expect(negative).toBe(false);
      expect(overflow).toBe(false);
      expect(compactFromTarget(target)).toBe(bits);
    });
  }
});

describe('CalculateASERT (parity with node bch2_pow_tests.cpp)', () => {
  const spacing = 600n, halfLife = 172800n;
  const refTarget = POW >> 4n;

  it('exponent 0 (perfect spacing) → target UNCHANGED, exactly', () => {
    // heightDiff=10, timeDiff = 600*(10+1) = 6600 → exponent 0 → factor 65536 → refTarget*65536>>16 === refTarget
    const r = calculateASERT(refTarget, spacing, 600n * 11n, 10n, POW, halfLife);
    expect(r).toBe(refTarget);
  });
  it('blocks twice as fast → harder (lower target)', () => {
    const r = calculateASERT(refTarget, spacing, (600n * 11n) / 2n, 10n, POW, halfLife);
    expect(r < refTarget).toBe(true);
  });
  it('blocks twice as slow → easier (higher target)', () => {
    const r = calculateASERT(refTarget, spacing, 600n * 11n * 2n, 10n, POW, halfLife);
    expect(r > refTarget).toBe(true);
  });
  it('very slow stays ≤ powLimit (node bch2_pow_tests parity)', () => {
    const r = calculateASERT(POW >> 1n, spacing, 600n * 2n * 100n, 1n, POW, halfLife);
    expect(r <= POW).toBe(true);
  });
  it('3 half-lives of delay (≈8×) from powLimit/2 → clamped exactly to powLimit', () => {
    const r = calculateASERT(POW >> 1n, spacing, halfLife * 3n + 600n * 2n, 1n, POW, halfLife);
    expect(r).toBe(POW);
  });
  it('~half-life slower doubles the target (≈2×, within polynomial error)', () => {
    // one half-life of extra delay beyond schedule ⇒ target ~2×
    const r = calculateASERT(refTarget, spacing, 600n * 11n + halfLife, 10n, POW, halfLife);
    const ratioTimes1000 = (r * 1000n) / refTarget;
    expect(ratioTimes1000 >= 1998n && ratioTimes1000 <= 2002n).toBe(true);
  });
});

describe('getNextWorkRequiredASERT (BCH2 wiring)', () => {
  it('anchor block returns anchorBits directly', () => {
    expect(getNextWorkRequiredASERT(BCH2_MAINNET_ASERT.anchorHeight - 1, 0, BCH2_MAINNET_ASERT)).toBe(BCH2_MAINNET_ASERT.anchorBits);
  });
  it('refuses pre-fork / fork-block heights (≤ 53200 = BC2, not ASERT)', () => {
    // nextHeight = 53200 (the fork block) → pre-fork, must throw
    expect(() => getNextWorkRequiredASERT(BCH2_MAINNET_ASERT.anchorHeight - 2, 0, BCH2_MAINNET_ASERT)).toThrow();
    // nextHeight = 53201 (the anchor, first BCH2 block) → allowed
    expect(() => getNextWorkRequiredASERT(BCH2_MAINNET_ASERT.anchorHeight - 1, 0, BCH2_MAINNET_ASERT)).not.toThrow();
  });
  it('half-life transition at 92736: block 92735 uses 1h, 92736 uses 2d', () => {
    expect(BCH2_MAINNET_ASERT.halfLife(92735)).toBe(3600n);
    expect(BCH2_MAINNET_ASERT.halfLife(92736)).toBe(172800n);
  });
  it('produces a valid within-powLimit nBits just after the anchor', () => {
    // parent = anchor (53201), perfect spacing → next target ≈ anchor target, well within powLimit
    const bits = getNextWorkRequiredASERT(53201, BCH2_MAINNET_ASERT.anchorParentTime + 600, BCH2_MAINNET_ASERT);
    const { target, negative, overflow } = targetFromCompact(bits);
    expect(negative || overflow).toBe(false);
    expect(target > 0n && target <= POW).toBe(true);
  });
});

describe('ASERT bit-exact vs real Bitcoin Cash mainnet headers (958556–958561)', () => {
  const BCH_FIRST = 958556;
  const BCH_HEADERS = [
    '000000341c29f2255b674f0562f1567e22b8e72a62721e6a13d9ea010000000000000000c921261744de3ad8cab62e34911d63b3420f0a5157f6dbe6b2faabb799655e1e30674c6aae290218adec99de',
    '0000002cd9e82a7bf22922254866eb201a600a4283437a396752ac0000000000000000001932ec605594d7adafdcc3404bb199fcf99e0583ab0e01490476a0bcc961470c13694c6a502902185421a409',
    '006099206a3e28452e852dd65359f0c22f1a5c2b2312590eaea122010000000000000000cd439ddeeab9cb01556fa8878a002980bafedd06dfbb7bc3c8ab66d6eebaea1858694c6a0e2902183e064ed6',
    '000000209ad6a0ef972b59219cdff1a686967c44ea8b49f6033e5101000000000000000088d74dfa2eaf2be8b24dd55046ec608e7ab1b1f682bd784d16a389309d974a8876694c6ae22702184d34bc9d',
    '00c0842a76fa47a4b00e6fa4895442caa9e74e7dd150cb3893bd7b010000000000000000dee105246852100bef9d0df8280324b7e5e503021a55f0104e876941b4703144e36a4c6a9f26021855b7ab66',
    '0060c32b56b45feb9b5746e549b283a712f957837b180be81fa59e0000000000000000002158007644441c2f9c261dc3e5ecb43d927b77a134e84c7f30b0056054e2df7f3b6b4c6a182602184c8cce70',
  ];
  const H = BCH_HEADERS.map((h) => parseHeader(fromHex(h)));
  it('reproduces every nBits, PoW holds, and the chain links', () => {
    for (let i = 1; i < H.length; i++) {
      expect(getNextWorkRequiredASERT(BCH_FIRST + i - 1, H[i - 1].time, BCH_MAINNET_ASERT)).toBe(H[i].bits);
      expect(checkPoW(H[i].raw, H[i].bits, BCH_MAINNET_ASERT.powLimit)).toBe(true);
      expect([...H[i].prevHash]).toEqual([...blockHashInternal(H[i - 1].raw)]);
    }
  });
});

describe('legacy retarget bit-exact vs real Bitcoin mainnet (boundary 955584)', () => {
  const first = parseHeader(fromHex('00e0ff3f5ddc01c0e95e627ca97a5280f77b86f4be6921e715b3010000000000000000007c5ead009231dadb996a9301f5150c8b1001f919965721e37d71a4d476bd20589df42d6ac3400217895e0357')); // block 953568 (boundary-2016)
  const RANGE_START = 955582;
  const rangeHex = '00e0ff3f309f0b0d067aa08d46918408602e9adde240c0c59d3801000000000000000000ae6fc171a642032f92c47372663f87d5a219c93932b77fc1dac69c8ed1b556d3f72c3f6ac3400217d5c2db5200000220c43add24191339285434dd150843196ff1a99ebf2a58000000000000000000008f4ae10c9cc4093a1bea417dea6f35082029f9cb4b88d39029df94bd4ee0b5832e2e3f6ac34002170cbd1d8e0020a734ef046b60fe5e17086e51e194ae193f6200f5655d041e000000000000000000007460c5f7eaa219119e04ae728c430e86fc2aaa5e9609069d25f99caf34f3ae53a72e3f6a421a02171a8e62f00080842011e078bfdfed49f221b9d6b4de47d37aa2e027c665e20100000000000000000089455ae1d0a75e1260b36568c2d7e1442efca172d9a82a28a11fd62e93710d77052f3f6a421a0217beab0a8f0040723bb553dd3a1ced97de73e7e63b65519772d913dae6d45401000000000000000000d4a2dd8741dfe53cf1c272b8d1a8a132d7e178cc5583b508c6b1a7a05fcee332762f3f6a421a02176c7927a3';
  const R = Array.from({ length: 5 }, (_, i) => parseHeader(fromHex(rangeHex.slice(i * 160, (i + 1) * 160)))); // 955582..955586
  it('reproduces the retarget block nBits and holds prev-bits on non-retarget blocks', () => {
    const [Bm2, Bm1, B, Bp1, Bp2] = R;
    // the retarget at 955584 recomputes from time[955583] and time[953568]
    expect(getNextWorkRequiredLegacy(955584, Bm1.bits, Bm1.time, first.time, BTC_MAINNET_LEGACY)).toBe(B.bits);
    // non-retarget blocks keep the previous nBits
    expect(getNextWorkRequiredLegacy(955583, Bm2.bits, Bm2.time, 0, BTC_MAINNET_LEGACY)).toBe(Bm1.bits);
    expect(getNextWorkRequiredLegacy(955585, B.bits, B.time, 0, BTC_MAINNET_LEGACY)).toBe(Bp1.bits);
    expect(getNextWorkRequiredLegacy(955586, Bp1.bits, Bp1.time, 0, BTC_MAINNET_LEGACY)).toBe(Bp2.bits);
    for (const h of [Bm1, B, Bp1]) expect(checkPoW(h.raw, h.bits, BTC_MAINNET_LEGACY.powLimit)).toBe(true);
  });

  it('verifyLegacyChunk verifies a chunk spanning a retarget boundary (uses the 2016-lookback)', () => {
    const [Bm2, Bm1, , Bp1] = R; // eslint-disable-line
    const chunk = [R[1].raw, R[2].raw, R[3].raw]; // 955583 (non-retarget), 955584 (retarget), 955585 (non-retarget)
    const getPriorTime = (h: number) => { if (h === 955584 - 2016) return first.time; throw new Error(`unexpected lookback ${h}`); };
    const NOW = 2_000_000_000; // trusted "now" well after the fixture header times
    const map = verifyLegacyChunk(chunk, 955583, blockHashInternal(Bm2.raw), Bm2.bits, Bm2.time, BTC_MAINNET_LEGACY, getPriorTime, NOW);
    expect(map.size).toBe(3);
    expect(map.get(955584)!.bits).toBe(R[2].bits);
    // a wrong lookback time (breaks the retarget nBits) must fail closed
    const badLookback = (h: number) => { if (h === 955584 - 2016) return first.time + 100000; throw new Error('x'); };
    expect(() => verifyLegacyChunk(chunk, 955583, blockHashInternal(Bm2.raw), Bm2.bits, Bm2.time, BTC_MAINNET_LEGACY, badLookback, NOW)).toThrow();
    // a broken link must fail closed
    expect(() => verifyLegacyChunk(chunk, 955583, new Uint8Array(32), Bm2.bits, Bm2.time, BTC_MAINNET_LEGACY, getPriorTime, NOW)).toThrow();
  });
});

// Real BitcoinII (BC2) MAINNET headers, captured 2026-07-10 from infra1.bitcoin-ii.org:50009. Permanent bit-exact
// regression guard for the BC2 legacy-DAA port AND for the BC2_MAINNET_CHECKPOINT (56448) constants. BC2 mainnet uses
// the classic Bitcoin 2016-block retarget (confirmed vs the fork node's pre-ASERT chainparams: 2-week timespan, 600s
// spacing, powLimit 00000000ffff…, no min-difficulty rule). If this fails, either the legacy math drifted or the
// hardcoded BC2 checkpoint is wrong — both would silently break (or falsely pass) SPV depth checks on BC2 legs.
describe('legacy retarget bit-exact vs real BitcoinII (BC2) mainnet (boundary 56448)', () => {
  const first = parseHeader(fromHex('00e0ff3fdd3d8b4da14637e6d7431e0c2a5a0429c4073321a370751300000000000000004aa6dad991e7307f2239c6538f6e47c2c5a34ab94c7b692609e0b104a6af8b5e92ea066a34af7318009ce46c')); // block 54432 (= 56448 - 2016, the retarget lookback)
  const rangeHex = '00009b2c2f93bdd0aa23e1dc9445cff0037ae077a8b7a7c410db3c440000000000000000a0f32a3e461c9b3e2030ef0aeddcab4ac80e4f89e6a29fd2f49c336adb938a92aee4106a34af73184862de7a00400a23a0411e3369852ba3f41717c2805b740e4a83accfe04df06c0000000000000000ecf1626dde3eb6467d653861641ceec887632b0c0ced7411ac4a9eb8731659ccb4e4106a34af73182864a49a0040ea26cbd470a3967a0abcd55ec7ae68b43c2cd65d12e17ae8c1230000000000000000cd2e841b008f51dccb306126e1cce24853fc6d2ba8e447f334fee1aa9ac029dc49e5106ab6883e18523e81440080002007e94af42e82df453f318d6c2a14b5866d73c2bc22fa3a3000000000000000006e6bf4bd85a47b7e49554d4f22b258c99f983f66567c2fc036b35114391e8815a1f1106ab6883e18d7712e2d00a0062020763c7b242ae010d258b3a8fc0e943bf026b1ae453dab1600000000000000005e18c4fb312be5bbeefcef8ecbf0e2fec7428ae560492d7231d43f693f9e382a52f2106ab6883e18ab468a180000002a521dda97ebf24728a46d8eb676dd81e059be50c6fc604d2800000000000000009eaf1a2277d4c6dac61957fb98eabf727380b45dad088e4bd5af5cc55e86f7b59401116ab6883e18893f42c9'; // 56446..56451
  const R = Array.from({ length: 6 }, (_, i) => parseHeader(fromHex(rangeHex.slice(i * 160, (i + 1) * 160)))); // 56446..56451

  it('reproduces the 56448 retarget nBits, holds prev-bits off-boundary, and matches the checkpoint constants', () => {
    const [Bm2, Bm1, B, Bp1, Bp2, Bp3] = R;
    // THE bit-exact retarget: at 56448 recompute from time[56447] and time[54432].
    expect(getNextWorkRequiredLegacy(56448, Bm1.bits, Bm1.time, first.time, BC2_MAINNET_LEGACY)).toBe(B.bits);
    // the real chain's 56448 block IS the hardcoded checkpoint (bits + hash).
    expect(B.bits).toBe(0x183e88b6); // == BC2_MAINNET_CHECKPOINT.bits
    expect(toHexRev(blockHashInternal(B.raw))).toBe('0000000000000000303afa22bcc2736d86b5142a6c8d313f45df822ef44ae907'); // == BC2_MAINNET_CHECKPOINT.hashDisplay
    // non-retarget blocks keep the previous nBits
    expect(getNextWorkRequiredLegacy(56449, B.bits, B.time, 0, BC2_MAINNET_LEGACY)).toBe(Bp1.bits);
    expect(getNextWorkRequiredLegacy(56450, Bp1.bits, Bp1.time, 0, BC2_MAINNET_LEGACY)).toBe(Bp2.bits);
    expect(getNextWorkRequiredLegacy(56451, Bp2.bits, Bp2.time, 0, BC2_MAINNET_LEGACY)).toBe(Bp3.bits);
    for (const h of R) expect(checkPoW(h.raw, h.bits, BC2_MAINNET_LEGACY.powLimit)).toBe(true);
    for (let i = 1; i < R.length; i++) expect([...R[i].prevHash]).toEqual([...blockHashInternal(R[i - 1].raw)]);
  });

  it('verifyLegacyChunk verifies a chunk spanning the 56448 retarget (uses the 2016-lookback)', () => {
    const [Bm2, , B] = R;
    const chunk = [R[1].raw, R[2].raw, R[3].raw]; // 56447 (non-retarget), 56448 (retarget), 56449 (non-retarget)
    const getPriorTime = (h: number) => { if (h === 56448 - 2016) return first.time; throw new Error(`unexpected lookback ${h}`); };
    const NOW = 2_000_000_000; // trusted "now" well after the fixture header times
    const map = verifyLegacyChunk(chunk, 56447, blockHashInternal(Bm2.raw), Bm2.bits, Bm2.time, BC2_MAINNET_LEGACY, getPriorTime, NOW);
    expect(map.size).toBe(3);
    expect(map.get(56448)!.bits).toBe(B.bits);
    // a wrong lookback time (breaks the retarget nBits) must fail closed
    const badLookback = (h: number) => { if (h === 56448 - 2016) return first.time + 100000; throw new Error('x'); };
    expect(() => verifyLegacyChunk(chunk, 56447, blockHashInternal(Bm2.raw), Bm2.bits, Bm2.time, BC2_MAINNET_LEGACY, badLookback, NOW)).toThrow();
    // a broken link must fail closed
    expect(() => verifyLegacyChunk(chunk, 56447, new Uint8Array(32), Bm2.bits, Bm2.time, BC2_MAINNET_LEGACY, getPriorTime, NOW)).toThrow();
  });
});

describe('header parse + PoW guards', () => {
  it('parses the 80-byte fields at correct offsets', () => {
    const raw = new Uint8Array(80);
    const dv = new DataView(raw.buffer);
    dv.setInt32(0, 0x20000000, true);            // version
    raw[4] = 0xaa;                               // prevHash[0]
    raw[36] = 0xbb;                              // merkleRoot[0]
    dv.setUint32(68, 1772649180, true);          // time
    dv.setUint32(72, 0x1903a30c, true);          // bits
    dv.setUint32(76, 12345, true);               // nonce
    const h = parseHeader(raw);
    expect(h.version).toBe(0x20000000);
    expect(h.prevHash[0]).toBe(0xaa);
    expect(h.merkleRoot[0]).toBe(0xbb);
    expect(h.time).toBe(1772649180);
    expect(h.bits).toBe(0x1903a30c);
    expect(h.nonce).toBe(12345);
  });
  it('rejects a non-80-byte header', () => { expect(() => parseHeader(new Uint8Array(79))).toThrow(); });
  it('checkPoW returns false for a target above powLimit / zero', () => {
    expect(checkPoW(new Uint8Array(80), 0x00000000, POW)).toBe(false); // target 0
    expect(checkPoW(new Uint8Array(80), 0x21ffffff, POW)).toBe(false); // target > powLimit
  });
});

describe('ASERT bit-exact vs real BCH2 mainnet headers (71097–71102)', () => {
  const H = REAL_HEADERS.map((h) => parseHeader(fromHex(h)));
  it('reproduces every nBits, PoW holds, and the chain links', () => {
    for (let i = 1; i < H.length; i++) {
      const height = REAL_FIRST_HEIGHT + i;
      // the consensus check: recomputed ASERT nBits === the real header's nBits
      expect(getNextWorkRequiredASERT(height - 1, H[i - 1].time, BCH2_MAINNET_ASERT)).toBe(H[i].bits);
      // the header's own PoW satisfies its target
      expect(checkPoW(H[i].raw, H[i].bits, POW)).toBe(true);
      // prevHash links to the real predecessor
      expect([...H[i].prevHash]).toEqual([...blockHashInternal(H[i - 1].raw)]);
    }
  });
  it('verifyChainFromCheckpoint accepts the real chain and rejects a broken link', () => {
    const cpHashDisplay = [...blockHashInternal(H[0].raw)].reverse().map((b) => b.toString(16).padStart(2, '0')).join('');
    const cp = { height: REAL_FIRST_HEIGHT, hashDisplay: cpHashDisplay, time: H[0].time };
    const rest = REAL_HEADERS.slice(1).map(fromHex);
    const map = verifyChainFromCheckpoint(rest, cp, BCH2_MAINNET_ASERT, 2_000_000_000);
    expect(map.size).toBe(rest.length);
    // a wrong checkpoint time (breaks ASERT nBits) must fail closed
    expect(() => verifyChainFromCheckpoint(rest, { ...cp, time: cp.time + 5000 }, BCH2_MAINNET_ASERT, 2_000_000_000)).toThrow();
  });

  // SPV-HEADER-TIME-001: without a future-time bound, a malicious proxy inflates a parent timestamp to collapse
  // the ASERT-required target to powLimit and mine a fake difficulty-1 fork. Verify the bound rejects future headers.
  it('rejects headers timestamped beyond trusted-now + 2h (fabricated-depth guard)', () => {
    const cpHashDisplay = [...blockHashInternal(H[0].raw)].reverse().map((b) => b.toString(16).padStart(2, '0')).join('');
    const cp = { height: REAL_FIRST_HEIGHT, hashDisplay: cpHashDisplay, time: H[0].time };
    const rest = REAL_HEADERS.slice(1).map(fromHex);
    // a sane wall clock (>= the latest header time) accepts the real chain
    const lastTime = H[H.length - 1].time;
    expect(verifyChainFromCheckpoint(rest, cp, BCH2_MAINNET_ASERT, lastTime).size).toBe(rest.length);
    // a wall clock set well before the header times → every header reads as >2h in the future → fail closed
    expect(() => verifyChainFromCheckpoint(rest, cp, BCH2_MAINNET_ASERT, H[0].time - 10_000)).toThrow(/exceeds trusted now/);
  });

  // Forgery-rejection (the over-report guard's actual teeth): a proxy that FABRICATES a header with a different
  // difficulty — to make a nonexistent block "verify" — must be rejected on the PoW/nBits check, not merely via the
  // absent-header path. Tamper the LAST header's nBits (no subsequent header → isolates the difficulty rejection from
  // the prevHash-link rejection). This is the negative that the live e2e's "over-report tip+1000" (which fires via the
  // benign no-headers branch) does NOT exercise.
  it('rejects a header with fabricated difficulty bits (forgery-rejection)', () => {
    const cpHashDisplay = [...blockHashInternal(H[0].raw)].reverse().map((b) => b.toString(16).padStart(2, '0')).join('');
    const cp = { height: REAL_FIRST_HEIGHT, hashDisplay: cpHashDisplay, time: H[0].time };
    // honest chain verifies
    expect(verifyChainFromCheckpoint(REAL_HEADERS.slice(1).map(fromHex), cp, BCH2_MAINNET_ASERT, 2_000_000_000).size).toBe(REAL_HEADERS.length - 1);
    // flip a byte inside the last header's 4-byte nBits field (offset 72..75) → nBits/PoW no longer consensus-valid
    const forged = REAL_HEADERS.slice(1).map(fromHex);
    forged[forged.length - 1][72] ^= 0xff;
    expect(() => verifyChainFromCheckpoint(forged, cp, BCH2_MAINNET_ASERT, 2_000_000_000)).toThrow();
  });
});

describe('Merkle inclusion (4-leaf tree)', () => {
  const t = [0, 1, 2, 3].map((i) => { const a = new Uint8Array(32); a.fill(i + 1); return a; });
  const h01 = hash256(new Uint8Array([...t[0], ...t[1]]));
  const h23 = hash256(new Uint8Array([...t[2], ...t[3]]));
  const root = hash256(new Uint8Array([...h01, ...h23]));

  it('reconstructs root for pos 0 (left-left)', () => {
    expect([...merkleRootFromBranch(t[0], [t[1], h23], 0)]).toEqual([...root]);
  });
  it('reconstructs root for pos 2 (right-left)', () => {
    expect([...merkleRootFromBranch(t[2], [t[3], h01], 2)]).toEqual([...root]);
  });
  it('verifyMerkleInclusion accepts a valid proof and rejects a tampered one', () => {
    // leaf tx = a 1-byte "raw tx"; its internal txid = hash256(rawtx)
    const rawTx = '00';
    const leaf = hash256(new Uint8Array([0]));
    const sib = new Uint8Array(32); sib.fill(9);
    const goodRoot = hash256(new Uint8Array([...leaf, ...sib])); // leaf at pos 0, one sibling on the right
    const merkleHexRev = [[...sib].reverse().map((b) => b.toString(16).padStart(2, '0')).join('')];
    // returns the DISPLAY txid of the proven leaf — this is what the verifier binds against the requested txid
    const expectedTxid = [...leaf].reverse().map((b) => b.toString(16).padStart(2, '0')).join('');
    expect(verifyMerkleInclusion(rawTx, merkleHexRev, 0, goodRoot)).toBe(expectedTxid);
    // a different raw tx yields a different proven txid (so the verifier's `provenTxid === txid` binding is meaningful)
    expect(verifyMerkleInclusion('01', merkleHexRev, 0, hash256(new Uint8Array([...hash256(new Uint8Array([1])), ...sib])))).not.toBe(expectedTxid);
    const badRoot = new Uint8Array(32); badRoot.fill(7);
    expect(() => verifyMerkleInclusion(rawTx, merkleHexRev, 0, badRoot)).toThrow();
  });
});

// Real BCH mainnet Merkle inclusion at pos>0 — the coinbase (pos=0) fixtures/live e2e only exercised the LEFT-concat
// branch (index & 1 == 0 at every level); this real tx at index 1 of a 147-tx block (height 959057, captured
// 2026-07-10 from the live proxy) reaches the RIGHT-sibling concat path (index & 1 == 1). Closes the audit's caveat (c).
describe('Merkle inclusion vs real BCH mainnet (pos>0 right-sibling branch)', () => {
  const TXID = '000dc757fe469f39067f448af764568fb288ed0f682a686f6d4359f26d885930';
  const RAWTX = '010000000106f2f1cc68ba1edbcd0009ddc0e4e8c0bc1803d4a373837cb1c63a5271916186010000006a473044022016874226b492b0547e85bbc8adc593e96df8c5112ae4c85f691202a79738525a022028419affb1aba5c3d977afd157e5b07992f119040764e36a96f45298c8679cc541210250f12d91944ec67c5c91093e6e8660d072775814f7cdf7703c5fca351d66456effffffff0400f2052a010000001976a9145ea3cfff9c69374d94e95b0838aea78549fb541a88ac00f2052a010000001976a9145ea3cfff9c69374d94e95b0838aea78549fb541a88ac00f2052a010000001976a9145ea3cfff9c69374d94e95b0838aea78549fb541a88acc594f573000000001976a9145ea3cfff9c69374d94e95b0838aea78549fb541a88ac00000000';
  const MERKLE = [
    '0e68f66fe1346ec1ccb7ab7e31ac21ab433a66b90639d315bd72bb9fd89ac02d',
    'fe2a43909e83ca0d218a44886e1716c9c9f2b55ac150156024de0a2fe3c7d890',
    '20b26bd3bc40b2de9d3995b068b4ff5889f41d1b4943fa56b3480f1c1138ac45',
    '0ac0f3890dfded2bc09ff67861a916ed80ec16bdff04e6c0e4abd8f107aa170e',
    'b7a9d453b456f5d3a9caf3cf0cc88179f7a12f632e04f0d35305c4996d45da55',
    '4a798a939263b6d1ea4e4f4d595eadca1ec3c72bc3972b1510fc978091ac347a',
    '91d5e7631d83e47fea3a677bdcb95c143b8fc3a921d39d7fdf96f69270388604',
    '97c57b23a1a4cbeb2bbbabdaef2b4f1d8ff297f88e90bf1e92fa52bbb0bb1b34',
  ];
  const POS = 1;
  const HEADER_HEX = '00200e2076f1d40566515f505f7646de72d519b6c6279165b611290000000000000000001a10847981c07dd2390891ef93cc13f19957dd686ccd753a562467179ae338fe83f0506a02210218657eaf28';

  it('reconstructs the real header merkle root from a pos>0 branch and rejects tampering', () => {
    const header = parseHeader(fromHex(HEADER_HEX));
    // honest: the proof reconstructs the header's merkle root and binds to the real txid
    expect(verifyMerkleInclusion(RAWTX, MERKLE, POS, header.merkleRoot)).toBe(TXID);
    // tampered sibling → reconstructed root differs → fail closed
    const bad = [...MERKLE]; bad[0] = (bad[0][0] === 'f' ? '0' : 'f') + bad[0].slice(1);
    expect(() => verifyMerkleInclusion(RAWTX, bad, POS, header.merkleRoot)).toThrow();
    // wrong position (flips which side each sibling concatenates) → fail closed
    expect(() => verifyMerkleInclusion(RAWTX, MERKLE, POS + 1, header.merkleRoot)).toThrow();
  });

  // R281-SEGWIT-003: a BTC/BC2 counterparty funding from SegWit UTXOs produces a BIP144-serialized funding tx whose
  // hash256 = WTXID != txid. verifyMerkleInclusion must strip the witness so the Merkle-tree leaf (the real txid) is
  // recovered — else SPV depth verification fails-closed on a real funding (liveness loss). Build the SegWit form of
  // this (1-input) legacy tx: marker+flag after nVersion + a witness stack before the trailing nLockTime.
  it('strips a SegWit (BIP144) serialization and still verifies inclusion (R281-SEGWIT-003)', () => {
    const header = parseHeader(fromHex(HEADER_HEX));
    const segwit = RAWTX.slice(0, 8) + '0001' + RAWTX.slice(8, -8) + '00' + RAWTX.slice(-8);
    expect(verifyMerkleInclusion(segwit, MERKLE, POS, header.merkleRoot)).toBe(TXID); // strips to the legacy txid
    // a SegWit marker without a valid flag is malformed → fail closed
    expect(() => verifyMerkleInclusion(RAWTX.slice(0, 8) + '0002' + RAWTX.slice(8), MERKLE, POS, header.merkleRoot)).toThrow();
  });
});
