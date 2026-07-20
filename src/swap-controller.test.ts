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
import { MockElectrumClient } from './test-mocks';
import { hexToBytes, bytesToHex, hash160, sha256 } from './htlc-builder';
import { swapSecretFromKss } from './seed-secret';
import { __setSpvConfigForTests, __resetSpvCacheForTests } from './spv-verifier';
import { blockHashInternal, checkPoW, hash256, type AsertParams } from './spv';
import type { SwapOffer } from './swap-types';

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
