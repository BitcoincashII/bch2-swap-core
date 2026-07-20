/**
 * FAIL-CLOSED matrix for src/swap-controller.ts (P1b step 4) — the headless SwapController skeleton +
 * prepare() + fundLegX() (the initiator funding its OWN UTXO leg X).
 *
 * Proves the four fund-safety invariants baked into step 4:
 *   (a) prepare() FAILS CLOSED on a non-hmac-v1 offer with no encrypted-at-rest durable S (fix #5).
 *   (b) prepare() authenticates S: it advances only when sha256(S) === offer.secretHash (a wrong hash throws).
 *   (c) fundLegX() with an INFLATED / unverifiable build height THROWS at the SPV verifyFundingHeight gate and
 *       broadcasts NOTHING (H1-LOCKTIME-PROXY-001 — an inflated height would push our refund CLTV ~forever).
 *   (d) the durable write-set is committed BEFORE the broadcast (ordered spy), and an injected commit-FAILURE
 *       ABORTS the broadcast — the funding tx is never sent (fix #4 durable-before-broadcast).
 *   (e) a SECOND concurrent fundLegX under the same mutex + durable sentinel does NOT double-broadcast (fix #3).
 *
 * The SPV gate runs over the same SYNTHETIC easy-difficulty PoW chain technique as gates.test.ts /
 * spv-verifier.test.ts so verifyFundingHeight executes fully offline. The signing key is a real secp256k1
 * pair so fundHTLC produces a genuine signed tx; broadcastTx is a zero-effect spy on MockElectrumClient.
 */

import { describe, it, expect, beforeEach } from 'vitest';
import * as secp256k1 from '@noble/secp256k1';
import {
  SwapController,
  type DurableSwapRecord,
  type SwapControllerDeps,
  type SeedVault,
  type SigningKeyPair,
  type SwapChainClient,
} from './swap-controller';
import {
  InMemoryDurableStore, InMemorySessionStore, InProcessMutex, type DurableStore,
} from './storage';
import { UtxoReservationRegistry } from './utxo-reservation';
import { MockElectrumClient, buildUtxoRawTx } from './test-mocks';
import { hexToBytes, bytesToHex, hash160, sha256, createHTLCRedeemScript } from './htlc-builder';
import { claimHTLC } from './swap-flow';
import { swapSecretFromKss } from './seed-secret';
import { __setSpvConfigForTests, __resetSpvCacheForTests } from './spv-verifier';
import { blockHashInternal, checkPoW, hash256, type AsertParams } from './spv';
import {
  assertRevealSafe as gateAssertRevealSafe,
  type GateChainClient, type FundProof, type RevealAuthorization,
} from './gates';
import type { SwapOffer, Chain } from './swap-types';

// ============================================================================
// Synthetic PoW chain (verbatim technique from gates.test.ts) — a real header chain from the checkpoint so
// verifyFundingHeight's PoW-header verification runs offline. fundLegX needs headers only (no Merkle proof).
// ============================================================================
const toHexRev = (a: Uint8Array) => [...a].reverse().map((b) => b.toString(16).padStart(2, '0')).join('');
function buildSynthChain(opts: { anchorHeight: number; count: number; spacing: number; bits: number }) {
  const { anchorHeight, count, spacing, bits } = opts;
  const powLimit = 1n << 255n;
  const nowSec = Math.floor(Date.now() / 1000);
  const anchorParentTime = nowSec - spacing * (count + 1);
  const T = (height: number) => anchorParentTime + spacing * (height - anchorHeight + 1);
  const params: AsertParams = { anchorHeight, anchorBits: bits, anchorParentTime, spacing: BigInt(spacing), powLimit, halfLife: () => 172800n };
  const checkpointHashInternal = hash256(new Uint8Array([0xc9, ...new Array(31).fill(0)]));
  const checkpoint = { height: anchorHeight, hashDisplay: toHexRev(checkpointHashInternal), time: T(anchorHeight) };
  const headersByHeight: Record<number, string> = {};
  let prevHashInternal = checkpointHashInternal;
  for (let i = 0; i < count; i++) {
    const height = anchorHeight + 1 + i;
    const merkle = hash256(new Uint8Array([height & 0xff, (height >> 8) & 0xff, 0x5a]));
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
  return { params, checkpoint, headersByHeight, tip: anchorHeight + count };
}

const CHAIN = 'bch2';           // not suspended; UTXO; avgBlockTimeSec 600; feePerByte 1
const THEIR_CHAIN = 'bch';
const CTX = buildSynthChain({ anchorHeight: 100000, count: 4, spacing: 600, bits: 0x20010000 });

// ── Real signing key + a K_ss so S = swapSecretFromKss(K_ss, nonce) authenticates against a real secretHash ──
const PRIV = hexToBytes('11'.repeat(32));
const PUB = secp256k1.getPublicKey(PRIV, true);
const KSS = hexToBytes('22'.repeat(32));
const NONCE = hexToBytes('33'.repeat(16)); // 16-byte swap nonce
const S = swapSecretFromKss(KSS, NONCE)!;
const SECRET_HASH_HEX = bytesToHex(sha256(S));
const CLAIM_PKH_HEX = 'aa'.repeat(20); // the taker's receive pkh on leg X (who may claim with the secret)

// ============================================================================
// Test doubles
// ============================================================================

class MockSeedVault implements SeedVault {
  disposed = false;
  constructor(private readonly kss: Uint8Array | null) {}
  async signingKey(): Promise<SigningKeyPair> {
    if (this.disposed) throw new Error('MockSeedVault disposed');
    return { privateKey: PRIV, publicKey: PUB };
  }
  async swapKss(): Promise<Uint8Array | null> {
    return this.disposed || !this.kss ? null : new Uint8Array(this.kss);
  }
  dispose(): void { this.disposed = true; }
}

function makeOffer(over: Partial<SwapOffer> = {}): SwapOffer {
  return {
    id: 'offer-1',
    sendChain: CHAIN,
    receiveChain: THEIR_CHAIN,
    sendAmount: 100000,   // sats the initiator locks on leg X
    receiveAmount: 100000,
    secretHash: SECRET_HASH_HEX,
    secretScheme: 'hmac-v1',
    secretNonce: bytesToHex(NONCE),
    initiatorSendAddress: 'addr-init-send',
    initiatorReceiveAddress: 'addr-init-recv',
    status: 'taken',
    createdAt: 1_700_000_000,
    expiresAt: 1_800_000_000,
    ...over,
  };
}

function makeRecord(over: Partial<DurableSwapRecord> = {}, offerOver: Partial<SwapOffer> = {}): DurableSwapRecord {
  return {
    id: over.id ?? 'offer-1',
    role: 'initiator',
    offer: makeOffer({ id: over.id ?? 'offer-1', ...offerOver }),
    phase: 'taken',
    counterpartyClaimPkh: CLAIM_PKH_HEX,
    ...over,
  };
}

interface DepsBundle extends SwapControllerDeps { client: MockElectrumClient; durable: DurableStore; }

function makeDeps(opts?: {
  height?: number;
  durable?: DurableStore;
  client?: MockElectrumClient;
  mutex?: InProcessMutex;
  reservation?: UtxoReservationRegistry;
}): DepsBundle {
  const client = opts?.client ?? new MockElectrumClient({
    headersByHeight: CTX.headersByHeight,
    height: opts?.height ?? CTX.tip,
    utxos: [{ tx_hash: '77'.repeat(32), tx_pos: 0, value: 200000, height: CTX.tip - 1 }],
    broadcastTxid: '99'.repeat(32),
  });
  const durable = opts?.durable ?? new InMemoryDurableStore();
  const mutex = opts?.mutex ?? new InProcessMutex({ store: durable, settle: () => Promise.resolve() });
  const reservation = opts?.reservation ?? new UtxoReservationRegistry();
  return {
    client,
    durable,
    chainClientFor: () => client as unknown as SwapChainClient,
    seedVault: new MockSeedVault(KSS),
    session: new InMemorySessionStore(),
    mutex,
    reservation,
    clock: () => 1_700_000_000_000,
  };
}

beforeEach(() => {
  __setSpvConfigForTests(CHAIN, CTX.params, CTX.checkpoint);
  __resetSpvCacheForTests();
});

// ============================================================================
// (a)+(b) prepare()
// ============================================================================
describe('SwapController.prepare()', () => {
  it('(a) FAILS CLOSED on a non-hmac-v1 offer with no encrypted-at-rest durable S (fix #5)', async () => {
    const deps = makeDeps();
    const rec = makeRecord({}, { secretScheme: 'random-v0', secretNonce: undefined });
    const ctrl = new SwapController(rec, deps);
    await expect(ctrl.prepare()).rejects.toThrow(/fix #5|not 'hmac-v1'|encrypted-at-rest/i);
    expect(ctrl.getState().phase).toBe('taken'); // never advanced
  });

  it('(a2) ADVANCES a non-hmac-v1 offer ONLY when an encrypted-at-rest durable S is present + authenticates', async () => {
    const deps = makeDeps();
    // Seed a durable S whose sha256 matches the offer's secretHash (the "encrypted-at-rest" survivor path).
    await deps.durable.set('bch2swap:encsecret:offer-1', bytesToHex(S));
    const rec = makeRecord({}, { secretScheme: 'random-v0', secretNonce: undefined });
    const ctrl = new SwapController(rec, deps);
    await ctrl.prepare();
    expect(ctrl.getState().phase).toBe('prepared');
  });

  it('(b) mints the derived S and advances ONLY when sha256(S) === secretHash', async () => {
    const deps = makeDeps();
    const ctrl = new SwapController(makeRecord(), deps);
    await ctrl.prepare();
    expect(ctrl.getState().phase).toBe('prepared');
  });

  it('(b2) THROWS when the offer secretHash does not match the derived S (tampered nonce / wrong hash)', async () => {
    const deps = makeDeps();
    const rec = makeRecord({}, { secretHash: 'bb'.repeat(32) }); // wrong hash
    const ctrl = new SwapController(rec, deps);
    await expect(ctrl.prepare()).rejects.toThrow(/does not hash to offer\.secretHash|fail closed/i);
    expect(ctrl.getState().phase).toBe('taken');
  });

  it('refuses a suspended pair (bc2) before deriving anything', async () => {
    const deps = makeDeps();
    const rec = makeRecord({}, { sendChain: 'bc2', receiveChain: 'bch' }); // bc2 is SUSPENDED
    const ctrl = new SwapController(rec, deps);
    await expect(ctrl.prepare()).rejects.toThrow(/suspended/i);
  });

  it('post-dispose prepare() throws (idempotent dispose)', async () => {
    const deps = makeDeps();
    const ctrl = new SwapController(makeRecord(), deps);
    ctrl.dispose();
    ctrl.dispose(); // idempotent
    await expect(ctrl.prepare()).rejects.toThrow(/disposed/i);
    expect((deps.seedVault as MockSeedVault).disposed).toBe(true);
  });
});

// ============================================================================
// (c) fundLegX — SPV verifyFundingHeight fail-closed
// ============================================================================
describe('SwapController.fundLegX() — SPV verifyFundingHeight gate (H1-LOCKTIME-PROXY-001)', () => {
  it('(c) an INFLATED / unverifiable build height THROWS and broadcasts NOTHING', async () => {
    const deps = makeDeps({ height: CTX.tip + 1000 }); // proxy claims a height with no PoW headers to back it
    const ctrl = new SwapController(makeRecord(), deps);
    await expect(ctrl.fundLegX()).rejects.toThrow(/SPV|headers|tip/i);
    expect(deps.client.broadcasts.length).toBe(0);      // never broadcast
    expect(await deps.durable.get('bch2swap:funded:offer-1')).toBeNull(); // no durable sentinel written
    expect(ctrl.getState().phase).toBe('taken');
  });

  it('HAPPY: a real SPV-verifiable build height funds leg X, sets the funded sentinel + phase', async () => {
    const deps = makeDeps();
    const ctrl = new SwapController(makeRecord(), deps);
    const { txid } = await ctrl.fundLegX();
    expect(deps.client.broadcasts.length).toBe(1);
    expect(await deps.durable.get('bch2swap:funded:offer-1')).toBe(txid);
    const snap = ctrl.getState();
    expect(snap.phase).toBe('initiator_funded');
    expect(snap.myFundingTxid).toBe(txid);
    expect(snap.fundLocktime).toBe(CTX.tip + 216); // buildHeight + LOCKTIME_BLOCKS.initiator
    expect(snap.myHTLC?.p2shAddress).toBeTruthy();
  });
});

// ============================================================================
// (d) durable-before-broadcast (fix #4)
// ============================================================================
describe('SwapController.fundLegX() — durable-before-broadcast (fix #4)', () => {
  it('(d) commits the durable write-set BEFORE the broadcast (ordered)', async () => {
    const order: string[] = [];
    class OrderDurable extends InMemoryDurableStore {
      async commit(entries: Array<[string, string]>): Promise<void> { order.push('commit'); return super.commit(entries); }
    }
    class OrderClient extends MockElectrumClient {
      async broadcastTx(rawTx: string): Promise<string> { order.push('broadcast'); return super.broadcastTx(rawTx); }
    }
    const durable = new OrderDurable();
    const client = new OrderClient({
      headersByHeight: CTX.headersByHeight, height: CTX.tip,
      utxos: [{ tx_hash: '77'.repeat(32), tx_pos: 0, value: 200000, height: CTX.tip - 1 }],
      broadcastTxid: '99'.repeat(32),
    });
    const deps = makeDeps({ durable, client });
    const ctrl = new SwapController(makeRecord(), deps);
    await ctrl.fundLegX();
    expect(order).toEqual(['commit', 'broadcast']); // durable write-set lands FIRST
    expect(client.broadcasts.length).toBe(1);
  });

  it('(d2) an injected commit FAILURE ABORTS the broadcast — no funding tx is sent', async () => {
    class FailCommitDurable extends InMemoryDurableStore {
      async commit(_entries: Array<[string, string]>): Promise<void> { throw new Error('injected atomic-commit failure (QuotaExceeded)'); }
    }
    const durable = new FailCommitDurable();
    const deps = makeDeps({ durable });
    const ctrl = new SwapController(makeRecord(), deps);
    await expect(ctrl.fundLegX()).rejects.toThrow(/commit failure|QuotaExceeded/i);
    expect(deps.client.broadcasts.length).toBe(0);      // fix #4: abort BEFORE broadcasting
    expect(ctrl.getState().phase).toBe('taken');
  });
});

// ============================================================================
// (e) single-flight (fix #3) — a second concurrent instance does not double-broadcast
// ============================================================================
describe('SwapController.fundLegX() — single-flight (fix #3)', () => {
  it('(e) two concurrent fundLegX under the same mutex + durable sentinel broadcast EXACTLY once', async () => {
    // Shared deps = two "tabs"/instances behind the SAME mutex, durable store, reservation, and chain client.
    const durable = new InMemoryDurableStore();
    const mutex = new InProcessMutex({ store: durable, settle: () => Promise.resolve() });
    const reservation = new UtxoReservationRegistry();
    const client = new MockElectrumClient({
      headersByHeight: CTX.headersByHeight, height: CTX.tip,
      utxos: [{ tx_hash: '77'.repeat(32), tx_pos: 0, value: 200000, height: CTX.tip - 1 }],
      broadcastTxid: '99'.repeat(32),
    });
    const shared = { durable, client, mutex, reservation };
    const depsA = makeDeps(shared);
    const depsB = makeDeps(shared);
    const ctrlA = new SwapController(makeRecord(), depsA);
    const ctrlB = new SwapController(makeRecord(), depsB);

    const [a, b] = await Promise.all([ctrlA.fundLegX(), ctrlB.fundLegX()]);

    expect(client.broadcasts.length).toBe(1);   // fix #3: exactly one broadcast across both instances
    expect(a.txid).toBe(b.txid);                 // the second ADOPTS the first's txid (deterministic)
    expect(ctrlA.getState().phase).toBe('initiator_funded');
    expect(ctrlB.getState().phase).toBe('initiator_funded');
    expect(ctrlB.getState().myHTLC?.p2shAddress).toBeTruthy(); // adopt path rehydrated myHTLC from durable
  });
});

// ============================================================================
// STEP 5 — counterparty-leg verify minters + the two irreversible actions + the responder claim side.
//
// A FUND-BEARING synthetic PoW chain (verbatim gates.test.ts technique): the fund block is single-tx so its
// merkleRoot == the funding txid and an empty-branch Merkle proof verifies, so the real R175 assertRevealSafe /
// assertLegBuriedForFunding (SPV depth + tip-freshness + margin) run FULLY OFFLINE. The funding output pays the
// P2SH of a REAL HTLC redeem script (recipient = hash160(PUB)) so buildSecretClaim can authenticate it + sign a
// genuine claim. The counterparty leg lives on 'btc' (not suspended; reqConf 2 <= fixture depth 4); the responder's
// own leg Y is funded on 'bch2' (reusing the headers-only CTX fixture the fundLegX suite already validates).
// ============================================================================
function buildFundSynthChain(opts: {
  anchorHeight: number; count: number; spacing: number; bits: number; fundSpkHex: string; tipAgeSec?: number;
}) {
  const { anchorHeight, count, spacing, bits, fundSpkHex, tipAgeSec = 0 } = opts;
  const powLimit = 1n << 255n;
  const nowSec = Math.floor(Date.now() / 1000);
  const anchorParentTime = nowSec - spacing * (count + 1) - tipAgeSec;
  const T = (h: number) => anchorParentTime + spacing * (h - anchorHeight + 1);
  const params: AsertParams = { anchorHeight, anchorBits: bits, anchorParentTime, spacing: BigInt(spacing), powLimit, halfLife: () => 172800n };
  const fundHeight = anchorHeight + 1;
  const fund = buildUtxoRawTx([{ value: 100000, scriptPubKeyHex: fundSpkHex }]);
  const fundRootInternal = hash256(hexToBytes(fund.rawTxHex));
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
  return { params, checkpoint, headersByHeight, fundHeight, fundTxid: fund.txid, fundRawHex: fund.rawTxHex, tip: anchorHeight + count };
}

// A REAL counterparty HTLC redeem script whose secretHash === sha256(S) and whose recipient is hash160(PUB) (the
// seed vault's key), so the SDK signs a genuine claim of it. Reused for leg X (fund/responder-claim) + leg Y (reveal).
const RECIP_PKH = hash160(PUB);
const CP_REDEEM = createHTLCRedeemScript({
  secretHash: sha256(S), recipientPubkeyHash: RECIP_PKH, refundPubkeyHash: hexToBytes('cc'.repeat(20)), locktime: 200150,
});
const CP_REDEEM_HEX = bytesToHex(CP_REDEEM);
const CP_P2SH_SPK = 'a914' + bytesToHex(hash160(CP_REDEEM)) + '87';
const FX = buildFundSynthChain({ anchorHeight: 200000, count: 4, spacing: 600, bits: 0x20010000, fundSpkHex: CP_P2SH_SPK });
const FX_OUTPOINT = { tx_hash: FX.fundTxid, tx_pos: 0 };

/** The btc counterparty-leg client backed by the FX fixture (deep + fresh + Merkle-provable funding of CP_REDEEM). */
function fxClient(): MockElectrumClient {
  return new MockElectrumClient({
    headersByHeight: FX.headersByHeight,
    merkleProof: { block_height: FX.fundHeight, merkle: [], pos: 0 },
    utxos: [{ tx_hash: FX.fundTxid, tx_pos: 0, value: 100000, height: FX.fundHeight }],
    rawTxByTxid: { [FX.fundTxid]: FX.fundRawHex },
    height: FX.tip,
    tipHeaderHex: FX.headersByHeight[FX.tip],
    broadcastTxid: '00'.repeat(31) + 'aa',
  });
}
/** The bch2 own-leg client (P2PKH inputs + CTX headers) the responder funds leg Y on. */
function bch2FundClient(): MockElectrumClient {
  return new MockElectrumClient({
    headersByHeight: CTX.headersByHeight, height: CTX.tip,
    utxos: [{ tx_hash: '88'.repeat(32), tx_pos: 0, value: 200000, height: CTX.tip - 1 }],
    broadcastTxid: '99'.repeat(32),
  });
}

/** Route each chain to its own client so a controller can read leg X on btc + fund leg Y on bch2 in one flow. */
function makeMultiDeps(
  clients: Partial<Record<Chain, MockElectrumClient>>,
  over?: { durable?: DurableStore; mutex?: InProcessMutex; reservation?: UtxoReservationRegistry },
): SwapControllerDeps {
  const durable = over?.durable ?? new InMemoryDurableStore();
  const mutex = over?.mutex ?? new InProcessMutex({ store: durable, settle: () => Promise.resolve() });
  const reservation = over?.reservation ?? new UtxoReservationRegistry();
  return {
    chainClientFor: (chain: Chain) => {
      const c = clients[chain];
      if (!c) throw new Error(`test: no client wired for chain ${chain}`);
      return c as unknown as SwapChainClient;
    },
    seedVault: new MockSeedVault(KSS),
    durable, session: new InMemorySessionStore(), mutex, reservation,
    clock: () => 1_700_000_000_000,
  };
}

const CP_HTLC = {
  redeemScript: CP_REDEEM_HEX, p2shAddress: 'p2sh-cp', secretHash: SECRET_HASH_HEX,
  recipientPkh: bytesToHex(RECIP_PKH), refundPkh: 'cc'.repeat(20), locktime: 0,
};

function revealRecord(over: Partial<DurableSwapRecord> = {}): DurableSwapRecord {
  return {
    id: over.id ?? 'reveal-1',
    role: 'initiator',
    offer: makeOffer({ id: over.id ?? 'reveal-1', sendChain: 'bch2', receiveChain: 'btc' }),
    phase: 'responder_funded',
    counterpartyClaimPkh: CLAIM_PKH_HEX,
    counterpartyHTLC: { ...CP_HTLC, locktime: FX.tip + 100 }, // margin ok for the initiator reveal (÷K 30000s >= 4h)
    counterpartyFundingOutpoint: FX_OUTPOINT,
    ...over,
  };
}

function fundRecord(over: Partial<DurableSwapRecord> = {}): DurableSwapRecord {
  return {
    id: over.id ?? 'fund-1',
    role: 'responder',
    offer: makeOffer({ id: over.id ?? 'fund-1', sendChain: 'btc', receiveChain: 'bch2' }),
    phase: 'taken',
    counterpartyClaimPkh: CLAIM_PKH_HEX,
    counterpartyHTLC: { ...CP_HTLC, locktime: FX.tip + 200 }, // margin ok for the responder fund gate (÷K 60000s)
    counterpartyFundingOutpoint: FX_OUTPOINT,
    ...over,
  };
}

// A genuine "initiator claim of leg Y" spend that reveals `secret` in its scriptSig; the responder watcher extracts it.
async function makeLegYClaimSpend(secret: Uint8Array): Promise<{ txid: string; rawTx: string }> {
  return claimHTLC({ tx_hash: 'ee'.repeat(32), tx_pos: 0, value: 100000, height: 10 }, CP_REDEEM, secret, PRIV, PUB, RECIP_PKH, 'bch2');
}

function watchRecord(over: Partial<DurableSwapRecord> = {}): DurableSwapRecord {
  return {
    id: over.id ?? 'watch-1',
    role: 'responder',
    offer: makeOffer({ id: over.id ?? 'watch-1', sendChain: 'btc', receiveChain: 'bch2' }),
    phase: 'responder_funded',
    counterpartyClaimPkh: CLAIM_PKH_HEX,
    myHTLC: { ...CP_HTLC, p2shAddress: 'p2sh-legy', locktime: 100076 },        // responder's own leg Y (watched)
    counterpartyHTLC: { ...CP_HTLC, p2shAddress: 'p2sh-legx', locktime: FX.tip + 200 }, // initiator leg X (claimed)
    counterpartyFundingOutpoint: FX_OUTPOINT,
    ...over,
  };
}

// Compile-time proof that fundLegY STRUCTURALLY requires a FundProof (validated by `tsc --noEmit`, not the runtime).
// If either directive becomes UNUSED (fundLegY drops the required proof / accepts the wrong brand) tsc FAILS.
async function _fundLegYCompileCheck(ctrl: SwapController, ra: RevealAuthorization): Promise<void> {
  // @ts-expect-error fundLegY requires a FundProof — a no-arg call must NOT compile (safe-by-default, design §4).
  await ctrl.fundLegY();
  // @ts-expect-error a RevealAuthorization is NOT a FundProof — the two brands are non-interchangeable (fix #1).
  await ctrl.fundLegY(ra);
}

// Compile-time proof that revealAndClaim STRUCTURALLY requires a RevealAuthorization (validated by `tsc --noEmit`).
// If either directive becomes UNUSED (revealAndClaim drops the required auth / accepts the wrong brand) tsc FAILS.
async function _revealAndClaimCompileCheck(ctrl: SwapController, fp: FundProof): Promise<void> {
  // @ts-expect-error revealAndClaim requires a RevealAuthorization — a no-arg call must NOT compile (fix #3 / §4).
  await ctrl.revealAndClaim();
  // @ts-expect-error a FundProof is NOT a RevealAuthorization — the two brands are non-interchangeable (fix #1).
  await ctrl.revealAndClaim(fp);
}

// ============================================================================
// (f) verifyCounterpartyLegForReveal + revealAndClaim — the initiator's single irreversible secret reveal
// ============================================================================
describe('SwapController.revealAndClaim() — the initiator secret reveal (fix #2/#3/#8)', () => {
  beforeEach(() => {
    __setSpvConfigForTests('btc', FX.params, FX.checkpoint);
    __resetSpvCacheForTests();
  });

  it('HAPPY: verifyCounterpartyLegForReveal mints an initiator auth; revealAndClaim broadcasts the secret-bearing claim ONCE', async () => {
    const btc = fxClient();
    const ctrl = new SwapController(revealRecord(), makeMultiDeps({ btc }));
    const auth = await ctrl.verifyCounterpartyLegForReveal();
    expect(auth.leg).toBe('Y');
    expect(auth.for).toBe('reveal');
    expect(auth.role).toBe('initiator');
    expect(auth.outpoint).toEqual(FX_OUTPOINT);
    const { txid } = await ctrl.revealAndClaim(auth);
    expect(btc.broadcasts.length).toBe(1);            // secret revealed exactly once
    expect(ctrl.getState().phase).toBe('claimed');
    expect(txid).toBeTruthy();
  });

  it('(fix #3) revealAndClaim with a RESPONDER-role authorization THROWS and broadcasts NOTHING', async () => {
    const btc = fxClient();
    const ctrl = new SwapController(revealRecord(), makeMultiDeps({ btc }));
    // A responder auth (marginBasis 'none' — SKIPS the 4h margin) minted via the gate directly: must NEVER drive the reveal.
    const responderAuth = await gateAssertRevealSafe(btc as unknown as GateChainClient, {
      role: 'responder', theirChain: 'btc', counterpartyRedeemScript: CP_REDEEM,
      recordedOutpoint: FX_OUTPOINT, counterpartyLocktime: FX.tip + 1, // far too tight for an initiator, allowed for a responder
    });
    expect(responderAuth.role).toBe('responder');
    await expect(ctrl.revealAndClaim(responderAuth)).rejects.toThrow(/fix #3|initiator/i);
    expect(btc.broadcasts.length).toBe(0);
  });

  it('(fix #8) revealAndClaim where the built claim spends a DIFFERENT outpoint than the auth THROWS + no broadcast', async () => {
    const btc = fxClient();
    const ctrl = new SwapController(revealRecord(), makeMultiDeps({ btc }));
    const auth = await ctrl.verifyCounterpartyLegForReveal(); // bound to FX_OUTPOINT (A)
    // A reorg re-mined the funding at a NEW outpoint B; the live UTXO set now shows ONLY B (still a valid HTLC output).
    const B = buildUtxoRawTx([{ value: 90000, scriptPubKeyHex: CP_P2SH_SPK }]);
    btc.opts.rawTxByTxid = { ...(btc.opts.rawTxByTxid ?? {}), [B.txid]: B.rawTxHex };
    btc.setUtxos([{ tx_hash: B.txid, tx_pos: 0, value: 90000, height: FX.fundHeight }]);
    await expect(ctrl.revealAndClaim(auth)).rejects.toThrow(/fix #8|different outpoint|reorg/i);
    expect(btc.broadcasts.length).toBe(0);
  });

  it('(R-REVEAL-FAILCLOSE) a cached claim tx LACKING .spent fails closed + no secret-bearing broadcast; the cache is discarded', async () => {
    const btc = fxClient();
    const durable = new InMemoryDurableStore();
    const ctrl = new SwapController(revealRecord(), makeMultiDeps({ btc }, { durable }));
    const auth = await ctrl.verifyCounterpartyLegForReveal();
    await durable.set('bch2swap:claimtx:reveal-1', JSON.stringify({ txid: 'ab'.repeat(32), rawTx: '00' })); // no `.spent`
    await expect(ctrl.revealAndClaim(auth)).rejects.toThrow(/R-REVEAL-FAILCLOSE|lacks|spent/i);
    expect(btc.broadcasts.length).toBe(0);
    expect(await durable.get('bch2swap:claimtx:reveal-1')).toBeNull(); // discarded before any reveal
  });

  it('(fix #2) a now-STALE / inflated tip at the broadcast choke point re-mint FAILS -> revealAndClaim throws + broadcasts.length===0', async () => {
    const btc = fxClient();
    const ctrl = new SwapController(revealRecord(), makeMultiDeps({ btc }));
    const auth = await ctrl.verifyCounterpartyLegForReveal(); // minted against the fresh, deep tip
    // Between verify and reveal the proxy now reports an INFLATED tip with no PoW headers to back it (SPV over-report).
    // The claim BUILDS fine (no depth check), but the choke-point re-mint SPV-fails -> abort before revealing S.
    btc.setHeight(FX.tip + 10);
    await expect(ctrl.revealAndClaim(auth)).rejects.toMatchObject({ name: 'GateFailure' });
    expect(btc.broadcasts.length).toBe(0);
    expect(ctrl.getState().phase).toBe('responder_funded'); // never advanced
  });
});

// ============================================================================
// (g) verifyCounterpartyLegForFunding + fundLegY — the responder funds leg Y (fix #2)
// ============================================================================
describe('SwapController.fundLegY() — the responder funds leg Y (fix #2)', () => {
  beforeEach(() => {
    __setSpvConfigForTests('btc', FX.params, FX.checkpoint); // leg X (counterparty) SPV fixture; bch2 == CTX (top-level)
    __resetSpvCacheForTests();
  });

  it('HAPPY: verifyCounterpartyLegForFunding mints a FundProof; fundLegY funds leg Y + re-mints, broadcasts ONCE', async () => {
    const btc = fxClient();
    const bch2 = bch2FundClient();
    const ctrl = new SwapController(fundRecord(), makeMultiDeps({ btc, bch2 }));
    const proof = await ctrl.verifyCounterpartyLegForFunding();
    expect(proof.leg).toBe('X');
    expect(proof.for).toBe('fundY');
    expect(proof.role).toBe('responder');
    const { txid } = await ctrl.fundLegY(proof);
    expect(bch2.broadcasts.length).toBe(1);           // the responder's own leg funded once
    expect(btc.broadcasts.length).toBe(0);            // leg X is READ-ONLY (never written)
    const snap = ctrl.getState();
    expect(snap.phase).toBe('responder_funded');
    expect(snap.myFundingTxid).toBe(txid);
    expect(snap.fundLocktime).toBe(CTX.tip + 72);     // buildHeight + LOCKTIME_BLOCKS.responder (~12h)
    expect(snap.myHTLC?.p2shAddress).toBeTruthy();
  });

  it('(fix #2) fundLegY re-mint FAILS (leg X vanished at the choke point) -> no broadcast, phase unchanged', async () => {
    const btc = fxClient();
    const bch2 = bch2FundClient();
    const ctrl = new SwapController(fundRecord(), makeMultiDeps({ btc, bch2 }));
    const proof = await ctrl.verifyCounterpartyLegForFunding(); // minted against the fresh leg X
    btc.setUtxos([]); // leg X double-spent / reorged away between the proof mint and the fund broadcast choke point
    await expect(ctrl.fundLegY(proof)).rejects.toMatchObject({ name: 'GateFailure' });
    expect(bch2.broadcasts.length).toBe(0);           // fix #2: the fresh re-mint throw ABORTS before broadcasting
    expect(ctrl.getState().phase).toBe('taken');
  });

  it('(fix #1 compile) fundLegY STRUCTURALLY requires a FundProof — the no-arg / wrong-brand calls do not compile', () => {
    expect(typeof _fundLegYCompileCheck).toBe('function');
  });

  it('(fix #1/#3 compile) revealAndClaim STRUCTURALLY requires a RevealAuthorization — no-arg / FundProof do not compile', () => {
    expect(typeof _revealAndClaimCompileCheck).toBe('function');
  });
});

// ============================================================================
// (h) watchForSecret + claimWithKnownSecret — the responder claim side
// ============================================================================
describe('SwapController.watchForSecret() + claimWithKnownSecret() — the responder claim side', () => {
  it('watchForSecret returns the secret + advances to claimed when the initiator reveals a VALID preimage', async () => {
    const spend = await makeLegYClaimSpend(S);
    const bch2 = new MockElectrumClient({ history: [{ tx_hash: spend.txid, height: 12 }], rawTxByTxid: { [spend.txid]: spend.rawTx } });
    const ctrl = new SwapController(watchRecord(), makeMultiDeps({ bch2 }));
    const { secret } = await ctrl.watchForSecret();
    expect(secret).not.toBeNull();
    expect(bytesToHex(secret!)).toBe(bytesToHex(S));
    expect(ctrl.getState().phase).toBe('claimed');
  });

  it('watchForSecret REJECTS a forged preimage (sha256(S) !== hashLock) and does NOT advance', async () => {
    const forged = await makeLegYClaimSpend(hexToBytes('ab'.repeat(32))); // a 32-byte value that is NOT the preimage
    const bch2 = new MockElectrumClient({ history: [{ tx_hash: forged.txid, height: 12 }], rawTxByTxid: { [forged.txid]: forged.rawTx } });
    const ctrl = new SwapController(watchRecord(), makeMultiDeps({ bch2 }));
    const { secret } = await ctrl.watchForSecret();
    expect(secret).toBeNull();
    expect(ctrl.getState().phase).toBe('responder_funded'); // never advanced on a forged reveal
  });

  it('watchForSecret does NOT throw on absence (empty history) — returns {secret:null}', async () => {
    const bch2 = new MockElectrumClient({ history: [] });
    const ctrl = new SwapController(watchRecord(), makeMultiDeps({ bch2 }));
    await expect(ctrl.watchForSecret()).resolves.toEqual({ secret: null });
  });

  it('claimWithKnownSecret claims leg X with the public secret (margin gate skipped), broadcasts ONCE -> completed', async () => {
    const spend = await makeLegYClaimSpend(S);
    const bch2 = new MockElectrumClient({ history: [{ tx_hash: spend.txid, height: 12 }], rawTxByTxid: { [spend.txid]: spend.rawTx } });
    const btc = fxClient();
    const durable = new InMemoryDurableStore();
    const ctrl = new SwapController(watchRecord(), makeMultiDeps({ bch2, btc }, { durable }));
    await ctrl.watchForSecret();                       // learn S from the on-chain reveal (sets the in-memory public secret)
    expect(ctrl.getState().phase).toBe('claimed');
    const { txid } = await ctrl.claimWithKnownSecret();
    expect(btc.broadcasts.length).toBe(1);
    expect(ctrl.getState().phase).toBe('completed');
    expect(txid).toBeTruthy();
  });

  it('claimWithKnownSecret REFUSES while a refund of the same HTLC is in flight (no broadcast)', async () => {
    const spend = await makeLegYClaimSpend(S);
    const bch2 = new MockElectrumClient({ history: [{ tx_hash: spend.txid, height: 12 }], rawTxByTxid: { [spend.txid]: spend.rawTx } });
    const btc = fxClient();
    const durable = new InMemoryDurableStore();
    const ctrl = new SwapController(watchRecord(), makeMultiDeps({ bch2, btc }, { durable }));
    await ctrl.watchForSecret();
    await durable.set('bch2swap:refundbroadcast:watch-1', '1'); // a refund of our own leg is in flight
    await expect(ctrl.claimWithKnownSecret()).rejects.toThrow(/refund/i);
    expect(btc.broadcasts.length).toBe(0);
  });
});
