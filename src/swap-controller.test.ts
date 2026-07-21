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

import { describe, it, expect, beforeEach, vi } from 'vitest';
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
import { MockElectrumClient, buildUtxoRawTx, MockEvmProvider, MockSigner, makeSwap, htlcInterface, ZERO_ADDRESS } from './test-mocks';
import { hexToBytes, bytesToHex, hash160, sha256, createHTLCRedeemScript } from './htlc-builder';
import { claimHTLC } from './swap-flow';
import { swapSecretFromKss } from './seed-secret';
import { __setSpvConfigForTests, __resetSpvCacheForTests } from './spv-verifier';
import { blockHashInternal, checkPoW, hash256, type AsertParams } from './spv';
import {
  assertRevealSafe as gateAssertRevealSafe,
  assertEvmLegBuriedForFunding as gateAssertEvmLegBuriedForFunding,
  assertEvmRevealSafe as gateAssertEvmRevealSafe,
  type GateChainClient, type FundProof, type RevealAuthorization,
} from './gates';
import { getEvmConfig } from './evm-config';
import { ethers, type Provider, type Signer } from 'ethers';
import type { SwapOffer, Chain } from './swap-types';
// FIX #6: the brand compile-check functions live in a NON-test file so `tsc --noEmit` actually compiles their
// @ts-expect-error directives (an unused directive / a brand regression fails typecheck). Imported here only so the
// smoke `it(typeof === 'function')` assertions keep them referenced.
import {
  _fundLegYCompileCheck, _revealAndClaimCompileCheck, _lockEvmCompileCheck, _revealAndClaimEvmCompileCheck,
} from './brand-compile-tests';

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
// (f0) fundLegX() — re-derivable-secret invariant on the FUNDING path (fix #5)
//
// prepare() refuses a non-hmac-v1 offer with no encrypted-at-rest durable S, and the file header claims fundLegX
// enforces the same. A caller invoking fundLegX() DIRECTLY from 'taken' (skipping prepare) must not be able to fund a
// swap whose secret a crash would strand.
// ============================================================================
describe('SwapController.fundLegX() — re-derivable-secret invariant on the funding path (fix #5)', () => {
  it('THROWS on a non-hmac-v1 offer with NO durable S and broadcasts nothing (even called directly from taken)', async () => {
    const deps = makeDeps();
    const rec = makeRecord({ phase: 'taken' }, { secretScheme: 'random-v0', secretNonce: undefined });
    const ctrl = new SwapController(rec, deps);
    await expect(ctrl.fundLegX()).rejects.toThrow(/fix #5|not 'hmac-v1'|encrypted-at-rest/i);
    expect(deps.client.broadcasts.length).toBe(0);                        // never funded
    expect(await deps.durable.get('bch2swap:funded:offer-1')).toBeNull(); // no durable sentinel
    expect(ctrl.getState().phase).toBe('taken');
  });

  it('an hmac-v1 offer still funds normally (the gate does not over-block)', async () => {
    const deps = makeDeps();
    const ctrl = new SwapController(makeRecord({ phase: 'taken' }), deps);
    const { txid } = await ctrl.fundLegX();
    expect(deps.client.broadcasts.length).toBe(1);
    expect(txid).toBeTruthy();
  });

  it('a non-hmac-v1 offer WITH an encrypted-at-rest durable S funds (parity with prepare)', async () => {
    const deps = makeDeps();
    await deps.durable.set('bch2swap:encsecret:offer-1', bytesToHex(S));
    const rec = makeRecord({ phase: 'taken' }, { secretScheme: 'random-v0', secretNonce: undefined });
    const ctrl = new SwapController(rec, deps);
    const { txid } = await ctrl.fundLegX();
    expect(deps.client.broadcasts.length).toBe(1);
    expect(txid).toBeTruthy();
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
// The counterparty leg's on-chain CLTV. The fund/reveal gates now require the recorded counterpartyLocktime to EQUAL
// the CLTV baked into the funded redeemScript (its hash160 IS the funded P2SH), so every record + direct gate call that
// re-verifies this leg must use CP_CLTV. Chosen = FX.tip + 200 (anchorHeight 200000 + count 4 + 200 = 200204): with the
// FX fresh tip at 200004 that leaves 200 blocks of runway, which clears BOTH the initiator reveal margin (>= 48 blocks:
// 200*600/2 >= 4h) AND the stricter responder fund margin (>= 192 blocks: 200*600/2 >= RESPONDER_LOCK_SEC + 4h).
const CP_CLTV = 200204;
const CP_REDEEM = createHTLCRedeemScript({
  secretHash: sha256(S), recipientPubkeyHash: RECIP_PKH, refundPubkeyHash: hexToBytes('cc'.repeat(20)), locktime: CP_CLTV,
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
    counterpartyHTLC: { ...CP_HTLC, locktime: CP_CLTV }, // == the funded redeemScript CLTV; runway clears the initiator reveal 4h margin
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
    counterpartyHTLC: { ...CP_HTLC, locktime: CP_CLTV }, // == the funded redeemScript CLTV; runway clears the responder fund margin
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

// FIX #6: the four brand compile-check functions moved to src/brand-compile-tests.ts (a NON-test file `tsc --noEmit`
// actually compiles — tsconfig excludes **/*.test.ts). The smoke `it(...)` assertions below keep them referenced.

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
      recordedOutpoint: FX_OUTPOINT, counterpartyLocktime: CP_CLTV, // == the funded CLTV (the responder auth SKIPS the margin regardless)
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

// ============================================================================
// (h2) claim broadcast — the poisoned-sentinel guard (fix #3)
//
// revealAndClaim / claimWithKnownSecret commit the claimbroadcast sentinel BEFORE the secret-bearing broadcast. If
// broadcastTx throws a DEFINITIVE pre-broadcast node rejection (the secret never entered any mempool), the sentinel
// must be CLEARED so a retry re-broadcasts — else a later call ADOPTS a claim that never happened and the swap wedges
// (refund also refuses via the R181 cross-guard). An AMBIGUOUS / timeout failure LEAVES the sentinel set (fail-safe).
// ============================================================================
describe('SwapController claim broadcast — poisoned-sentinel guard (fix #3)', () => {
  it('a DEFINITIVE pre-broadcast node rejection CLEARS the claimbroadcast sentinel so a retry can re-broadcast', async () => {
    const spend = await makeLegYClaimSpend(S);
    const bch2 = new MockElectrumClient({ history: [{ tx_hash: spend.txid, height: 12 }], rawTxByTxid: { [spend.txid]: spend.rawTx } });
    const btc = fxClient();
    btc.opts.broadcastThrows = true; // "broadcast rejected (broadcastThrows)" -> a definitive node-validation rejection
    const durable = new InMemoryDurableStore();
    const ctrl = new SwapController(watchRecord(), makeMultiDeps({ bch2, btc }, { durable }));
    await ctrl.watchForSecret();
    await expect(ctrl.claimWithKnownSecret()).rejects.toThrow(/reject/i);
    expect(await durable.get('bch2swap:claimbroadcast:watch-1')).toBeNull(); // fix #3: sentinel cleared for retry
    expect(btc.broadcasts.length).toBe(1);                                   // the broadcast was attempted once
  });

  it('an AMBIGUOUS (timeout) broadcast failure KEEPS the claimbroadcast sentinel (fail-safe, R201)', async () => {
    const spend = await makeLegYClaimSpend(S);
    const bch2 = new MockElectrumClient({ history: [{ tx_hash: spend.txid, height: 12 }], rawTxByTxid: { [spend.txid]: spend.rawTx } });
    class TimeoutBtc extends MockElectrumClient {
      async broadcastTx(rawTx: string): Promise<string> { this.broadcasts.push(rawTx); throw new Error('broadcast timed out after 30s — tx may still propagate'); }
    }
    const btc = new TimeoutBtc({
      headersByHeight: FX.headersByHeight,
      merkleProof: { block_height: FX.fundHeight, merkle: [], pos: 0 },
      utxos: [{ tx_hash: FX.fundTxid, tx_pos: 0, value: 100000, height: FX.fundHeight }],
      rawTxByTxid: { [FX.fundTxid]: FX.fundRawHex },
      height: FX.tip, tipHeaderHex: FX.headersByHeight[FX.tip], broadcastTxid: '00'.repeat(31) + 'aa',
    });
    const durable = new InMemoryDurableStore();
    const ctrl = new SwapController(watchRecord(), makeMultiDeps({ bch2, btc }, { durable }));
    await ctrl.watchForSecret();
    await expect(ctrl.claimWithKnownSecret()).rejects.toThrow(/timed out/i);
    expect(await durable.get('bch2swap:claimbroadcast:watch-1')).toBe('1'); // fix #3: sentinel KEPT (fail-safe)
  });
});

// ============================================================================
// STEP 6 — refund() + canRefund() + reorg-safe finalizers + resume() (fix #10). UTXO-only.
//
// OWN_* = a REAL "own funded HTLC" whose refund branch pubkeyhash is hash160(PUB) (the seed vault's key), so
// buildHTLCRefundTx signs a genuine refund, and whose funded output OWN_FUND pays its P2SH so the refund UTXO +
// the resume myHTLC authentication both self-authenticate against a real raw tx. RFX = a single-tx block containing
// a terminal (refund/claim) tx so the reorg-safe finalizer's SPV verifyConfirmations runs fully offline (verbatim
// buildFundSynthChain technique). All four finalizer + resume fund-safety invariants below are fail-closed.
// ============================================================================
const OWN_LOCKTIME = 100050; // a block-height CLTV
const OWN_REDEEM = createHTLCRedeemScript({
  secretHash: sha256(S), recipientPubkeyHash: hexToBytes('aa'.repeat(20)), refundPubkeyHash: hash160(PUB), locktime: OWN_LOCKTIME,
});
const OWN_REDEEM_HEX = bytesToHex(OWN_REDEEM);
const OWN_P2SH_SPK = 'a914' + bytesToHex(hash160(OWN_REDEEM)) + '87';
const OWN_FUND = buildUtxoRawTx([{ value: 200000, scriptPubKeyHex: OWN_P2SH_SPK }]);
const OWN_HTLC = {
  redeemScript: OWN_REDEEM_HEX, p2shAddress: 'p2sh-own', secretHash: SECRET_HASH_HEX,
  recipientPkh: 'aa'.repeat(20), refundPkh: bytesToHex(hash160(PUB)), locktime: OWN_LOCKTIME,
};
// A block whose single tx is the terminal (refund/claim) tx — merkleRoot == its txid so an empty-branch proof verifies.
const RFX = buildFundSynthChain({ anchorHeight: 300000, count: 4, spacing: 600, bits: 0x20010000, fundSpkHex: OWN_P2SH_SPK });

function refundableRecord(over: Partial<DurableSwapRecord> = {}): DurableSwapRecord {
  return {
    id: over.id ?? 'refund-1',
    role: 'initiator',
    offer: makeOffer({ id: over.id ?? 'refund-1', sendChain: 'bch2', receiveChain: 'btc' }),
    phase: 'initiator_funded',
    counterpartyClaimPkh: CLAIM_PKH_HEX,
    myHTLC: OWN_HTLC,
    myFundingTxid: OWN_FUND.txid,
    fundLocktime: OWN_LOCKTIME,
    ...over,
  };
}

/** The bch2 own-leg client for refund/resume: the funding UTXO is at the HTLC address + its raw tx self-authenticates. */
function refundClient(opts?: { height?: number; utxos?: Array<{ tx_hash: string; tx_pos: number; value: number; height: number }>; history?: Array<{ tx_hash: string; height: number }> }): MockElectrumClient {
  return new MockElectrumClient({
    height: opts?.height ?? 100100,
    utxos: opts?.utxos ?? [{ tx_hash: OWN_FUND.txid, tx_pos: 0, value: 200000, height: 100040 }],
    rawTxByTxid: { [OWN_FUND.txid]: OWN_FUND.rawTxHex },
    history: opts?.history ?? [],
    broadcastTxid: '99'.repeat(32),
  });
}

// ── canRefund() + refund() ──────────────────────────────────────────────────────────────────────────────────
describe('SwapController.canRefund() / refund() — recover own leg after the timelock (§9.7 / R280-H1 / fix #4)', () => {
  it('canRefund() is a pure predicate over isHtlcRefundAvailable(myHTLC.locktime, tip)', () => {
    const ctrl = new SwapController(refundableRecord(), makeMultiDeps({ bch2: refundClient() }));
    expect(ctrl.canRefund(OWN_LOCKTIME)).toBe(true);      // tip == locktime
    expect(ctrl.canRefund(OWN_LOCKTIME - 1)).toBe(false); // tip below locktime
    expect(ctrl.canRefund(null)).toBe(false);             // unknown tip
  });

  it('refund BEFORE the timelock throws (not available) + broadcasts nothing', async () => {
    const bch2 = refundClient({ height: OWN_LOCKTIME - 1 });
    const ctrl = new SwapController(refundableRecord(), makeMultiDeps({ bch2 }));
    await expect(ctrl.refund()).rejects.toThrow(/timelock has not passed|premature/i);
    expect(bch2.broadcasts.length).toBe(0);
    expect(ctrl.getState().phase).toBe('initiator_funded');
  });

  it('refund AFTER the timelock persists the refund tx + sentinel BEFORE the broadcast (ordered) -> phase refunded', async () => {
    const order: string[] = [];
    class OrderDurable extends InMemoryDurableStore {
      async commit(entries: Array<[string, string]>): Promise<void> { order.push('commit'); return super.commit(entries); }
    }
    class OrderClient extends MockElectrumClient {
      async broadcastTx(rawTx: string): Promise<string> { order.push('broadcast'); return super.broadcastTx(rawTx); }
    }
    const durable = new OrderDurable();
    const bch2 = new OrderClient({
      height: 100100, utxos: [{ tx_hash: OWN_FUND.txid, tx_pos: 0, value: 200000, height: 100040 }],
      rawTxByTxid: { [OWN_FUND.txid]: OWN_FUND.rawTxHex }, history: [], broadcastTxid: '99'.repeat(32),
    });
    const ctrl = new SwapController(refundableRecord(), makeMultiDeps({ bch2 }, { durable }));
    const { txid } = await ctrl.refund();
    expect(order).toEqual(['commit', 'broadcast']);       // durable-before-broadcast (fix #4 / R280-H1)
    expect(bch2.broadcasts.length).toBe(1);
    expect(await durable.get('bch2swap:refundtx:refund-1')).toBeTruthy();
    expect(await durable.get('bch2swap:refundbroadcast:refund-1')).toBe('1');
    expect(ctrl.getState().phase).toBe('refunded');
    expect(txid).toBeTruthy();
  });

  it('a commit FAILURE aborts the refund broadcast (fix #4) — no refund tx is sent', async () => {
    class FailCommitDurable extends InMemoryDurableStore {
      async commit(_e: Array<[string, string]>): Promise<void> { throw new Error('injected atomic-commit failure (QuotaExceeded)'); }
    }
    const durable = new FailCommitDurable();
    const bch2 = refundClient();
    const ctrl = new SwapController(refundableRecord(), makeMultiDeps({ bch2 }, { durable }));
    await expect(ctrl.refund()).rejects.toThrow(/commit failure|QuotaExceeded/i);
    expect(bch2.broadcasts.length).toBe(0);
    expect(ctrl.getState().phase).toBe('initiator_funded');
  });
});

// ── R181 claim <-> refund cross-guard (deferred from step 5) ──────────────────────────────────────────────────
describe('SwapController claim<->refund cross-guard (R181)', () => {
  beforeEach(() => { __setSpvConfigForTests('btc', FX.params, FX.checkpoint); __resetSpvCacheForTests(); });

  it('a claim in flight (claimbroadcast sentinel) BLOCKS refund + broadcasts nothing', async () => {
    const durable = new InMemoryDurableStore();
    await durable.set('bch2swap:claimbroadcast:refund-1', '1');
    const bch2 = refundClient();
    const ctrl = new SwapController(refundableRecord(), makeMultiDeps({ bch2 }, { durable }));
    await expect(ctrl.refund()).rejects.toThrow(/R181|claim/i);
    expect(bch2.broadcasts.length).toBe(0);
  });

  it('a refund in flight (refundbroadcast sentinel) BLOCKS the initiator revealAndClaim (vice-versa) + no secret reveal', async () => {
    const btc = fxClient();
    const durable = new InMemoryDurableStore();
    const ctrl = new SwapController(revealRecord(), makeMultiDeps({ btc }, { durable }));
    const auth = await ctrl.verifyCounterpartyLegForReveal();
    await durable.set('bch2swap:refundbroadcast:reveal-1', '1'); // a refund of the shared HTLC is in flight
    await expect(ctrl.revealAndClaim(auth)).rejects.toThrow(/refund/i);
    expect(btc.broadcasts.length).toBe(0);
    expect(ctrl.getState().phase).toBe('responder_funded'); // never revealed
  });
});

// ── reorg-safe finalizers — never wipe on doubt; wipe only at reorg-safe SPV depth (§9.6) ─────────────────────
function finalizeRefundRecord(over: Partial<DurableSwapRecord> = {}): DurableSwapRecord {
  return {
    id: over.id ?? 'fin-refund',
    role: 'initiator',
    offer: makeOffer({ id: over.id ?? 'fin-refund', sendChain: 'btc', receiveChain: 'bch2' }),
    phase: 'refunded',
    counterpartyClaimPkh: CLAIM_PKH_HEX,
    myHTLC: OWN_HTLC,
    myFundingTxid: OWN_FUND.txid,
    refundTx: { txid: RFX.fundTxid, rawTx: RFX.fundRawHex },
    ...over,
  };
}
function finalizeClaimRecord(over: Partial<DurableSwapRecord> = {}): DurableSwapRecord {
  return {
    id: over.id ?? 'fin-claim',
    role: 'initiator',
    offer: makeOffer({ id: over.id ?? 'fin-claim', sendChain: 'bch2', receiveChain: 'btc' }),
    phase: 'claimed',
    counterpartyClaimPkh: CLAIM_PKH_HEX,
    counterpartyHTLC: { ...CP_HTLC, locktime: RFX.tip + 100 },
    counterpartyFundingOutpoint: FX_OUTPOINT,
    myClaimTxid: RFX.fundTxid,
    claimTx: { txid: RFX.fundTxid, rawTx: RFX.fundRawHex, spent: { tx_hash: 'ee'.repeat(32), tx_pos: 0 } },
    ...over,
  };
}
/** btc client backed by RFX: a terminal tx in a single-tx block. Knobs to force 0-conf / short-depth / pruned reads. */
function finClient(opts?: { height?: number; entryHeight?: number; withMerkle?: boolean }): MockElectrumClient {
  const eh = opts?.entryHeight ?? RFX.fundHeight;
  const height = opts?.height ?? RFX.tip;
  return new MockElectrumClient({
    headersByHeight: RFX.headersByHeight,
    height,
    history: [{ tx_hash: RFX.fundTxid, height: eh }],
    merkleProof: opts?.withMerkle === false ? undefined : { block_height: RFX.fundHeight, merkle: [], pos: 0 },
    rawTxByTxid: { [RFX.fundTxid]: RFX.fundRawHex },
    tipHeaderHex: RFX.headersByHeight[height],
    broadcastTxid: '00'.repeat(31) + 'bb',
  });
}

describe('SwapController finalizers — never wipe on doubt, wipe only at reorg-safe SPV depth (§9.6)', () => {
  beforeEach(() => { __setSpvConfigForTests('btc', RFX.params, RFX.checkpoint); __resetSpvCacheForTests(); });

  async function armedRefund(): Promise<DurableStore> {
    const durable = new InMemoryDurableStore();
    await durable.set('bch2swap:refundtx:fin-refund', JSON.stringify({ txid: RFX.fundTxid, rawTx: RFX.fundRawHex, spent: { tx_hash: OWN_FUND.txid, tx_pos: 0 } }));
    await durable.set('bch2swap:refundbroadcast:fin-refund', '1');
    await durable.set('bch2swap:encsecret:fin-refund', bytesToHex(S));
    await durable.set('bch2swap:record:fin-refund', '{}');
    return durable;
  }

  it('confirmRefund KEEPS everything on 0-conf (refund broadcast but not yet mined)', async () => {
    const durable = await armedRefund();
    const btc = finClient({ entryHeight: 0 }); // in history at height 0 -> not "mined" -> keep
    const r = await new SwapController(finalizeRefundRecord(), makeMultiDeps({ btc }, { durable })).confirmRefund();
    expect(r.finalized).toBe(false);
    expect(await durable.get('bch2swap:refundtx:fin-refund')).toBeTruthy();
    expect(await durable.get('bch2swap:refundbroadcast:fin-refund')).toBe('1');
    expect(await durable.get('bch2swap:encsecret:fin-refund')).toBeTruthy();
  });

  it('confirmRefund KEEPS everything at a SHORT proxy depth (< reqConf)', async () => {
    const durable = await armedRefund();
    const btc = finClient({ height: RFX.fundHeight }); // tip == fundHeight -> depth 1 < btc reqConf 2
    const r = await new SwapController(finalizeRefundRecord(), makeMultiDeps({ btc }, { durable })).confirmRefund();
    expect(r.finalized).toBe(false);
    expect(await durable.get('bch2swap:refundtx:fin-refund')).toBeTruthy();
    expect(await durable.get('bch2swap:encsecret:fin-refund')).toBeTruthy();
  });

  it('confirmRefund KEEPS everything on a PRUNED / unprovable SPV read (deep proxy depth, no Merkle proof)', async () => {
    const durable = await armedRefund();
    const btc = finClient({ withMerkle: false }); // deep tip, but getMerkleProof throws -> SPV fail-closed
    const r = await new SwapController(finalizeRefundRecord(), makeMultiDeps({ btc }, { durable })).confirmRefund();
    expect(r.finalized).toBe(false);
    expect(await durable.get('bch2swap:refundtx:fin-refund')).toBeTruthy();
    expect(await durable.get('bch2swap:encsecret:fin-refund')).toBeTruthy();
  });

  it('confirmRefund WIPES the recovery material ONLY at >= reqConf SPV depth', async () => {
    const durable = await armedRefund();
    const btc = finClient(); // deep + Merkle-provable -> verifyConfirmations passes
    const ctrl = new SwapController(finalizeRefundRecord(), makeMultiDeps({ btc }, { durable }));
    const r = await ctrl.confirmRefund();
    expect(r.finalized).toBe(true);
    expect(await durable.get('bch2swap:refundtx:fin-refund')).toBeNull();
    expect(await durable.get('bch2swap:refundbroadcast:fin-refund')).toBeNull();
    expect(await durable.get('bch2swap:encsecret:fin-refund')).toBeNull(); // no claim in flight -> secret/state wiped
    expect(ctrl.getState().phase).toBe('refunded');
  });

  it('confirmClaim KEEPS the secret + claim cache at a SHORT depth and WIPES only at reorg-safe SPV depth', async () => {
    // KEEP (short depth)
    const durableK = new InMemoryDurableStore();
    await durableK.set('bch2swap:claimtx:fin-claim', JSON.stringify({ txid: RFX.fundTxid, rawTx: RFX.fundRawHex, spent: { tx_hash: 'ee'.repeat(32), tx_pos: 0 } }));
    await durableK.set('bch2swap:claimbroadcast:fin-claim', '1');
    await durableK.set('bch2swap:encsecret:fin-claim', bytesToHex(S));
    const rk = await new SwapController(finalizeClaimRecord(), makeMultiDeps({ btc: finClient({ height: RFX.fundHeight }) }, { durable: durableK })).confirmClaim();
    expect(rk.finalized).toBe(false);
    expect(await durableK.get('bch2swap:claimtx:fin-claim')).toBeTruthy();
    expect(await durableK.get('bch2swap:encsecret:fin-claim')).toBeTruthy();
    // WIPE (reorg-safe depth)
    const durableW = new InMemoryDurableStore();
    await durableW.set('bch2swap:claimtx:fin-claim', JSON.stringify({ txid: RFX.fundTxid, rawTx: RFX.fundRawHex, spent: { tx_hash: 'ee'.repeat(32), tx_pos: 0 } }));
    await durableW.set('bch2swap:claimbroadcast:fin-claim', '1');
    await durableW.set('bch2swap:encsecret:fin-claim', bytesToHex(S));
    const ctrlW = new SwapController(finalizeClaimRecord(), makeMultiDeps({ btc: finClient() }, { durable: durableW }));
    const rw = await ctrlW.confirmClaim();
    expect(rw.finalized).toBe(true);
    expect(await durableW.get('bch2swap:claimtx:fin-claim')).toBeNull();
    expect(await durableW.get('bch2swap:encsecret:fin-claim')).toBeNull();
    expect(ctrlW.getState().phase).toBe('completed');
  });
});

// ── trySettleIfBothLegsSpent() — §9.6 never-wipe: reorg-safe SPV proof before teardown (fix #1) ────────────────
// OUR OWN leg lives on 'btc' (RFX SPV fixture); their leg on 'bch2'. The wipe destroys the NON-RECOVERABLE secret +
// durable record, so a bare getUTXOs "both legs empty" read (a reorg / stale / lying proxy could show OUR still-funded
// leg as empty) must NOT trigger it: require the SPENDING of OUR OWN leg buried at reorg-safe SPV depth, and honor the
// fix #10 resume guard (irreversibleBlocked). PRE-FIX both-legs-empty alone wiped → these all fail against pre-fix code.
function settleRecord(over: Partial<DurableSwapRecord> = {}): DurableSwapRecord {
  return {
    id: over.id ?? 'settle-1',
    role: 'initiator',
    offer: makeOffer({ id: over.id ?? 'settle-1', sendChain: 'btc', receiveChain: 'bch2' }),
    phase: 'claimed',
    counterpartyClaimPkh: CLAIM_PKH_HEX,
    myHTLC: OWN_HTLC,                                              // our own leg X on 'btc'
    myFundingTxid: OWN_FUND.txid,
    counterpartyHTLC: { ...CP_HTLC, locktime: RFX.tip + 100 },
    counterpartyFundingOutpoint: FX_OUTPOINT,
    ...over,
  };
}

describe('SwapController.trySettleIfBothLegsSpent() — never wipe on doubt (§9.6 / fix #1)', () => {
  beforeEach(() => { __setSpvConfigForTests('btc', RFX.params, RFX.checkpoint); __resetSpvCacheForTests(); });

  it('WIPES the secret + record ONLY when OUR OWN leg spend is buried at reorg-safe SPV depth (both legs empty)', async () => {
    const durable = new InMemoryDurableStore();
    await durable.set('bch2swap:claimbroadcast:settle-wipe', '1');
    await durable.set('bch2swap:encsecret:settle-wipe', bytesToHex(S));
    await durable.set('bch2swap:record:settle-wipe', '{}');
    // OUR leg 'btc': getUTXOs empty + history=[RFX spend @ RFX.fundHeight], deep + Merkle-provable -> reorg-safe.
    const btc = finClient();
    const bch2 = new MockElectrumClient({ utxos: [] }); // their leg empty
    const ctrl = new SwapController(settleRecord({ id: 'settle-wipe' }), makeMultiDeps({ btc, bch2 }, { durable }));
    const settled = await ctrl.trySettleIfBothLegsSpent();
    expect(settled).toBe(true);
    expect(await durable.get('bch2swap:encsecret:settle-wipe')).toBeNull();      // secret wiped at reorg-safe depth
    expect(await durable.get('bch2swap:record:settle-wipe')).toBeNull();
    expect(await durable.get('bch2swap:claimbroadcast:settle-wipe')).toBeNull();
    expect(ctrl.getState().phase).toBe('completed');
  });

  it('KEEPS everything when OUR leg spend is only 0-conf (never wipe on a bare getUTXOs read)', async () => {
    const durable = new InMemoryDurableStore();
    await durable.set('bch2swap:claimbroadcast:settle-0conf', '1');
    await durable.set('bch2swap:encsecret:settle-0conf', bytesToHex(S));
    await durable.set('bch2swap:record:settle-0conf', '{}');
    const btc = finClient({ entryHeight: 0 }); // the spend is in history at height 0 -> not mined -> not reorg-safe
    const bch2 = new MockElectrumClient({ utxos: [] });
    const ctrl = new SwapController(settleRecord({ id: 'settle-0conf' }), makeMultiDeps({ btc, bch2 }, { durable }));
    const settled = await ctrl.trySettleIfBothLegsSpent();
    expect(settled).toBe(false);
    expect(await durable.get('bch2swap:encsecret:settle-0conf')).toBeTruthy(); // secret KEPT
    expect(await durable.get('bch2swap:record:settle-0conf')).toBeTruthy();
  });

  it('KEEPS everything at a SHORT SPV depth (< reqConf) even with both legs empty', async () => {
    const durable = new InMemoryDurableStore();
    await durable.set('bch2swap:claimbroadcast:settle-short', '1');
    await durable.set('bch2swap:encsecret:settle-short', bytesToHex(S));
    await durable.set('bch2swap:record:settle-short', '{}');
    const btc = finClient({ height: RFX.fundHeight }); // tip == fundHeight -> depth 1 < btc reqConf 2
    const bch2 = new MockElectrumClient({ utxos: [] });
    const ctrl = new SwapController(settleRecord({ id: 'settle-short' }), makeMultiDeps({ btc, bch2 }, { durable }));
    const settled = await ctrl.trySettleIfBothLegsSpent();
    expect(settled).toBe(false);
    expect(await durable.get('bch2swap:encsecret:settle-short')).toBeTruthy();
    expect(await durable.get('bch2swap:record:settle-short')).toBeTruthy();
  });

  it('(fix #10) KEEPS everything when a resume left irreversibleBlocked set (non-ok myHTLC auth)', async () => {
    const durable = new InMemoryDurableStore();
    await durable.set('bch2swap:claimbroadcast:settle-blocked', '1');
    await durable.set('bch2swap:encsecret:settle-blocked', bytesToHex(S));
    await durable.set('bch2swap:record:settle-blocked', '{}');
    // OUR leg 'btc': funding NOT unspent + getTx ambiguous + funding IS in history -> resume auth 'indeterminate'
    // -> irreversibleBlocked = true. Both legs read empty, so PRE-FIX would wipe the non-recoverable secret.
    const btc = new MockElectrumClient({ height: RFX.tip, utxos: [], history: [{ tx_hash: OWN_FUND.txid, height: 300002 }], getTxThrows: true });
    const bch2 = new MockElectrumClient({ utxos: [] });
    const ctrl = await SwapController.resume(settleRecord({ id: 'settle-blocked' }), makeMultiDeps({ btc, bch2 }, { durable }));
    expect(ctrl.getState().resumeAuth).toBe('indeterminate');
    const settled = await ctrl.trySettleIfBothLegsSpent();
    expect(settled).toBe(false);
    expect(await durable.get('bch2swap:encsecret:settle-blocked')).toBeTruthy(); // secret KEPT (irreversibleBlocked)
    expect(await durable.get('bch2swap:record:settle-blocked')).toBeTruthy();
  });
});

// ── resume() — rehydrate a stalled / crashed / new-device swap (fix #10) ──────────────────────────────────────
describe('SwapController.resume() — fix #10 + funding rebroadcast + S re-derivation + idempotent adopt', () => {
  beforeEach(() => { __setSpvConfigForTests('btc', FX.params, FX.checkpoint); __resetSpvCacheForTests(); });

  it('resume with an INDETERMINATE myHTLC auth does NOT broadcast (fix #10) and refuses any irreversible action', async () => {
    // funding NOT in the unspent set, getTx ambiguous, BUT the funding txid IS in our own HTLC scripthash history
    // -> authenticateMyHtlcAgainstFunding returns 'indeterminate' (WAIT only).
    const bch2 = new MockElectrumClient({
      height: 100100, utxos: [], history: [{ tx_hash: OWN_FUND.txid, height: 100040 }], getTxThrows: true,
    });
    const ctrl = await SwapController.resume(refundableRecord({ id: 'resume-ind' }), makeMultiDeps({ bch2 }, {}));
    expect(ctrl.getState().resumeAuth).toBe('indeterminate');
    expect(bch2.broadcasts.length).toBe(0);                       // fix #10: no irreversible broadcast on doubt
    await expect(ctrl.refund()).rejects.toThrow(/fix #10|DEFINITIVE|authentic/i); // WAIT only, even past the timelock
    expect(bch2.broadcasts.length).toBe(0);
  });

  it("resume with a 'funded' sentinel but no on-chain funding tx rebroadcasts the EXACT durable raw funding tx", async () => {
    const durable = new InMemoryDurableStore();
    await durable.set('bch2swap:funded:resume-rb', OWN_FUND.txid);
    await durable.set('bch2swap:fundedtx:resume-rb', OWN_FUND.rawTxHex);
    const bch2 = new MockElectrumClient({
      height: 100100, utxos: [], rawTxByTxid: { [OWN_FUND.txid]: OWN_FUND.rawTxHex }, history: [],
    });
    const ctrl = await SwapController.resume(refundableRecord({ id: 'resume-rb', myFundingTxid: OWN_FUND.txid }), makeMultiDeps({ bch2 }, { durable }));
    expect(ctrl.getState().resumeAuth).toBe('ok');               // funding self-authenticated via getTx
    expect(bch2.broadcasts.length).toBe(1);
    expect(bch2.broadcasts[0]).toBe(OWN_FUND.rawTxHex);          // idempotent rebroadcast of the durable raw funding tx
  });

  it('resume re-derives S (hmac-v1) and re-enters the correct gate from chain truth', async () => {
    const bch2 = bch2FundClient();
    const ctrl = await SwapController.resume(makeRecord({ id: 'resume-s', phase: 'taken' }), makeMultiDeps({ bch2 }, {}));
    expect(ctrl.getState().hasSecret).toBe(true);                // S re-derived from the seed (hmac-v1)
    expect(ctrl.getState().resumeAuth).toBe('skip');            // no myHTLC yet -> nothing to authenticate
    expect(ctrl.getState().resumeGate).toBe('pre-funding');    // not resumable -> route to the funding gate
    expect(ctrl.getState().phase).toBe('taken');
  });

  it('a post-confirm revealAndClaim re-call returns the prior txid (idempotent adopt) — no second reveal', async () => {
    const btc = fxClient();
    const durable = new InMemoryDurableStore();
    const ctrl = new SwapController(revealRecord(), makeMultiDeps({ btc }, { durable }));
    const auth = await ctrl.verifyCounterpartyLegForReveal();
    const first = await ctrl.revealAndClaim(auth);
    expect(btc.broadcasts.length).toBe(1);
    btc.setUtxos([]); // the counterparty leg-Y UTXO is now spent -> a rebuild would throw
    const again = await ctrl.revealAndClaim(auth);
    expect(again.txid).toBe(first.txid);                        // ADOPT the prior txid
    expect(btc.broadcasts.length).toBe(1);                      // no second secret-bearing broadcast
  });

  it('a post-confirm claimWithKnownSecret re-call returns the prior txid (idempotent adopt)', async () => {
    const spend = await makeLegYClaimSpend(S);
    const bch2 = new MockElectrumClient({ history: [{ tx_hash: spend.txid, height: 12 }], rawTxByTxid: { [spend.txid]: spend.rawTx } });
    const btc = fxClient();
    const durable = new InMemoryDurableStore();
    const ctrl = new SwapController(watchRecord(), makeMultiDeps({ bch2, btc }, { durable }));
    await ctrl.watchForSecret();
    const first = await ctrl.claimWithKnownSecret();
    expect(btc.broadcasts.length).toBe(1);
    btc.setUtxos([]); // leg X now spent
    const again = await ctrl.claimWithKnownSecret();
    expect(again.txid).toBe(first.txid);
    expect(btc.broadcasts.length).toBe(1);
  });
});

// ============================================================================
// STEP 7 — EVM parity: the EVM fund-critical half (the EVM reveal + the refund-race secret recovery).
//
// The EVM GATE minters (assertEvmLegBuriedForFunding / assertEvmRevealSafe) are driven over MockEvmProvider (+ leaf
// providers for the quorum chain-clock reads, mirroring gates.test.ts); the on-chain lock/claim/refund broadcasts go
// through the proven evm-client handlers with the injected MockSigner. Default MockSigner THROWS on any broadcast, so
// every fail-closed assertion is `broadcastCount === 0`; the ONE happy path (a genuine EVM refund) uses a `mode:'ok'`
// signer. The refund-race pivot recovers S from an on-chain `Claimed` event (staged via getLogs) and claims the OTHER
// (UTXO) leg with the now-public secret. No assertion is weakened — the default signer + the UTXO harness are unchanged.
// ============================================================================
const EVM_HASHLOCK = '0x' + SECRET_HASH_HEX;               // the on-chain hashLock the gates bind (== sha256(S))
const EVM_RECIP = '0x2222222222222222222222222222222222222222'; // OUR EVM address (recipient of the counterparty leg)
const EVM_CP_ADDR = '0x3333333333333333333333333333333333333333'; // the counterparty's EVM address (recipient of our lock)
const EVM_AMT = 1_000_000_000_000_000_000n;               // 1e18 wei — an 18-dec value that overflows Number()
const EVM_AMT_STR = '1000000000000000000';                // canonical base-unit STRING (fix #10 — never Number() this)
const EVM_CHAIN_NOW = 1_800_000_000;                      // the corroborated leaf block timestamp
const EVM_SWAP_ID = '0x' + 'ab'.repeat(32);
const ARB_HTLC = getEvmConfig(42161)!.htlcAddress;        // theirChain 'arb' deployed HTLC
const P = (x: MockEvmProvider) => x as unknown as Provider;
const G = (x: MockEvmProvider) => x as unknown as GateChainClient;
const SG = (x: MockSigner) => x as unknown as Signer;

/** An EVM counterparty-leg provider: a quorum (2-leaf) FallbackProvider-shaped mock with a `safe`-tag swap + a
 *  corroborated chain clock, mirroring gates.test.ts's evmFundProvider/evmRevealProvider. `single:true` drops the leaf
 *  set so the gate's quorum>=2 refusal (fix #7/#1) fires; `swap:null` makes the counterparty lock vanish. */
function evmLegProvider(over: { swap?: ReturnType<typeof makeSwap> | null; leafTs?: Array<number | null>; single?: boolean; logs?: unknown[] } = {}): MockEvmProvider {
  const swap = over.swap !== undefined ? over.swap : makeSwap({
    hashLock: EVM_HASHLOCK, recipient: EVM_RECIP, token: ZERO_ADDRESS, amount: EVM_AMT, timeLock: 1_900_000_000n,
  });
  if (over.single) return new MockEvmProvider({ safeSwap: swap, swap, blockNumber: 5000, block: { timestamp: EVM_CHAIN_NOW } });
  const ts = over.leafTs ?? [EVM_CHAIN_NOW, EVM_CHAIN_NOW];
  const leaves = ts.map((t) => new MockEvmProvider({ block: t === null ? null : { timestamp: t }, logs: over.logs }));
  return new MockEvmProvider({ safeSwap: swap, swap, leafProviders: leaves, blockNumber: 5000 });
}

function makeEvmDeps(opts: {
  evmProviderFor?: (chain: Chain) => Provider;
  evmSignerFor?: (chain: Chain) => Signer;
  clients?: Partial<Record<Chain, MockElectrumClient>>;
  durable?: DurableStore;
}): SwapControllerDeps {
  const durable = opts.durable ?? new InMemoryDurableStore();
  const mutex = new InProcessMutex({ store: durable, settle: () => Promise.resolve() });
  const reservation = new UtxoReservationRegistry();
  return {
    chainClientFor: (chain: Chain) => {
      const c = opts.clients?.[chain];
      if (!c) throw new Error(`test: no UTXO client wired for chain ${chain}`);
      return c as unknown as SwapChainClient;
    },
    seedVault: new MockSeedVault(KSS),
    durable, session: new InMemorySessionStore(), mutex, reservation,
    clock: () => 1_700_000_000_000,
    evmProviderFor: opts.evmProviderFor,
    evmSignerFor: opts.evmSignerFor,
  };
}

// responder (EVM↔EVM): leg X on 'arb' (initiator, verified), OUR leg Y on 'base' (locked).
function evmFundRecord(over: Partial<DurableSwapRecord> = {}): DurableSwapRecord {
  return {
    id: over.id ?? 'evmfund-1', role: 'responder',
    offer: makeOffer({ id: over.id ?? 'evmfund-1', sendChain: 'arb', receiveChain: 'base', sendAmount: EVM_AMT_STR, receiveAmount: EVM_AMT_STR, secretHash: SECRET_HASH_HEX }),
    phase: 'taken',
    counterpartyEvmSwapId: EVM_SWAP_ID,
    myEvmAddress: EVM_RECIP, counterpartyEvmAddress: EVM_CP_ADDR,
    myEvmToken: ZERO_ADDRESS, counterpartyEvmToken: ZERO_ADDRESS,
    ...over,
  };
}
// initiator (EVM↔EVM): OUR leg X on 'base', leg Y on 'arb' (responder, revealed against).
function evmRevealRecord(over: Partial<DurableSwapRecord> = {}): DurableSwapRecord {
  return {
    id: over.id ?? 'evmreveal-1', role: 'initiator',
    offer: makeOffer({ id: over.id ?? 'evmreveal-1', sendChain: 'base', receiveChain: 'arb', sendAmount: EVM_AMT_STR, receiveAmount: EVM_AMT_STR, secretHash: SECRET_HASH_HEX, secretScheme: 'hmac-v1', secretNonce: bytesToHex(NONCE) }),
    phase: 'responder_funded',
    counterpartyEvmSwapId: EVM_SWAP_ID,
    myEvmAddress: EVM_RECIP, counterpartyEvmAddress: EVM_CP_ADDR,
    myEvmToken: ZERO_ADDRESS, counterpartyEvmToken: ZERO_ADDRESS,
    ...over,
  };
}
const REVEAL_GATE_PARAMS = {
  chain: 'arb', htlcAddr: ARB_HTLC, swapId: EVM_SWAP_ID, requiredConfirmations: 30,
  hashLock: EVM_HASHLOCK, recipient: EVM_RECIP, minAmount: EVM_AMT, token: ZERO_ADDRESS,
};
const FUND_GATE_PARAMS = {
  chain: 'arb', htlcAddr: ARB_HTLC, swapId: EVM_SWAP_ID, requiredConfirmations: 30,
  hashLock: EVM_HASHLOCK, recipient: EVM_RECIP, minAmount: EVM_AMT, token: ZERO_ADDRESS,
};

// FIX #6: _lockEvmCompileCheck + _revealAndClaimEvmCompileCheck moved to src/brand-compile-tests.ts (imported above).

// ── (i) verifyEvmCounterpartyLeg* minters + the fix #7 single-leaf refusal ────────────────────────────────
describe('SwapController EVM verify minters (assertEvmLegBuriedForFunding / assertEvmRevealSafe)', () => {
  it('verifyEvmCounterpartyLegForFunding mints a swapId-bound FundProof over the quorum>=2 provider', async () => {
    const ctrl = new SwapController(evmFundRecord(), makeEvmDeps({ evmProviderFor: () => P(evmLegProvider()) }));
    const proof = await ctrl.verifyEvmCounterpartyLegForFunding();
    expect(proof.leg).toBe('X');
    expect(proof.for).toBe('fundY');
    expect(proof.role).toBe('responder');
    expect(proof.swapId).toBe(EVM_SWAP_ID);
    expect(proof.marginBasis).toBe('evm-timestamp');
  });

  it('verifyEvmCounterpartyLegForReveal mints an initiator RevealAuthorization over the quorum>=2 provider', async () => {
    const ctrl = new SwapController(evmRevealRecord(), makeEvmDeps({ evmProviderFor: () => P(evmLegProvider()) }));
    const auth = await ctrl.verifyEvmCounterpartyLegForReveal();
    expect(auth.leg).toBe('Y');
    expect(auth.for).toBe('reveal');
    expect(auth.role).toBe('initiator');
    expect(auth.swapId).toBe(EVM_SWAP_ID);
  });

  it('(fix #7) a SINGLE-LEAF EVM provider is REFUSED by the gate — quorum>=2 required, mints nothing', async () => {
    const ctrl = new SwapController(evmFundRecord(), makeEvmDeps({ evmProviderFor: () => P(evmLegProvider({ single: true })) }));
    await expect(ctrl.verifyEvmCounterpartyLegForFunding()).rejects.toMatchObject({ name: 'GateFailure' });
    const ctrl2 = new SwapController(evmRevealRecord(), makeEvmDeps({ evmProviderFor: () => P(evmLegProvider({ single: true })) }));
    await expect(ctrl2.verifyEvmCounterpartyLegForReveal()).rejects.toMatchObject({ name: 'GateFailure' });
  });

  it('verifyEvmCounterpartyLegForFunding is responder-only; verifyEvmCounterpartyLegForReveal is initiator-only', async () => {
    const asInit = new SwapController(evmFundRecord({ role: 'initiator', offer: makeOffer({ id: 'evmfund-1', sendChain: 'base', receiveChain: 'arb', sendAmount: EVM_AMT_STR, receiveAmount: EVM_AMT_STR, secretHash: SECRET_HASH_HEX }) }), makeEvmDeps({ evmProviderFor: () => P(evmLegProvider()) }));
    await expect(asInit.verifyEvmCounterpartyLegForFunding()).rejects.toThrow(/responder-only/i);
    const asResp = new SwapController(evmRevealRecord({ role: 'responder', offer: makeOffer({ id: 'evmreveal-1', sendChain: 'arb', receiveChain: 'base', sendAmount: EVM_AMT_STR, receiveAmount: EVM_AMT_STR, secretHash: SECRET_HASH_HEX }) }), makeEvmDeps({ evmProviderFor: () => P(evmLegProvider()) }));
    await expect(asResp.verifyEvmCounterpartyLegForReveal()).rejects.toThrow(/initiator-only/i);
  });
});

// ── (ii) lockEvm(proof) — the fix #2 re-mint at the broadcast choke point ─────────────────────────────────
describe('SwapController.lockEvm() — fix #2 re-mint FRESH at the choke point', () => {
  it('(fix #2) lockEvm re-mint FAILS (counterparty leg X vanished) -> NO lock tx broadcast, phase unchanged', async () => {
    const goodProof = await gateAssertEvmLegBuriedForFunding(P(evmLegProvider()), FUND_GATE_PARAMS);
    const signer = new MockSigner(new MockEvmProvider({}), EVM_RECIP); // throw-mode: any lock broadcast would throw
    const ctrl = new SwapController(evmFundRecord(), makeEvmDeps({
      // the choke-point re-mint reads a FRESH provider where the counterparty lock has vanished (safe=null) -> GateFailure
      evmProviderFor: () => P(evmLegProvider({ swap: null })),
      evmSignerFor: () => SG(signer),
    }));
    await expect(ctrl.lockEvm(goodProof)).rejects.toMatchObject({ name: 'GateFailure' });
    expect(signer.broadcastCount).toBe(0);              // fix #2: the fresh re-mint throw ABORTS before any lock tx
    expect(ctrl.getState().phase).toBe('taken');
  });

  it('(fix #5) lockEvm commits the lockpending recovery marker DURABLY + AWAITED BEFORE broadcast; a commit FAILURE aborts the lock', async () => {
    // A durable whose atomic commit() ALWAYS throws (e.g. QuotaExceeded). Because the lockpending marker commit is now
    // durable-BEFORE-broadcast + AWAITED, that throw ABORTS the lock. Crucially `broadcastCount === 0` proves the
    // failing commit ran STRICTLY BEFORE any lock broadcast: were the marker written only AFTER (the old fire-and-
    // forget onBroadcast path) the lock tx would already have broadcast (count 1) before the commit threw. So this one
    // test proves BOTH "marker committed before broadcast" AND "a commit failure aborts the lock" (fix #5).
    class FailCommitDurable extends InMemoryDurableStore {
      commits = 0;
      async commit(_e: Array<[string, string]>): Promise<void> { this.commits++; throw new Error('injected atomic-commit failure (QuotaExceeded)'); }
    }
    const goodProof = await gateAssertEvmLegBuriedForFunding(P(evmLegProvider()), FUND_GATE_PARAMS);
    const signer = new MockSigner(new MockEvmProvider({}), EVM_RECIP); // throw-mode: any lock broadcast would throw the sentinel
    const durable = new FailCommitDurable();
    const ctrl = new SwapController(evmFundRecord(), makeEvmDeps({
      evmProviderFor: () => P(evmLegProvider()), // healthy quorum -> the fix #2 choke-point re-mint passes
      evmSignerFor: () => SG(signer),
      durable,
    }));
    await expect(ctrl.lockEvm(goodProof)).rejects.toThrow(/commit failure|QuotaExceeded/i);
    expect(signer.broadcastCount).toBe(0);              // fix #5: NO lock tx broadcast without a durable recovery marker
    expect(durable.commits).toBe(1);                    // the aborting throw came from the FIRST (pre-broadcast) commit
    expect(ctrl.getState().phase).toBe('taken');        // never advanced
  });

  it('(fix #4) lockEvm ADOPTS a prior in-flight lock (lockpending/evmlocktx pre-set) instead of re-locking', async () => {
    // The funded sentinel is written only AFTER the lock resolves, but the lockpending/evmlocktx recovery markers are
    // written the instant the lock is broadcast. A re-call after the broadcast but before the funded sentinel lands
    // must ADOPT the prior lock (recoverLockFromTx over the recorded tx hash), NOT re-lock (which strands the first).
    const LOCK_TX_HASH = '0x' + 'cd'.repeat(32);
    const BASE_HTLC = getEvmConfig(84532)!.htlcAddress; // OUR own EVM leg ('base' == chainId 84532) deployed HTLC
    // Stage the on-chain Locked(id, initiator, recipient, token, amount, hashLock, timeLock) event the prior lock emitted.
    const lockedLog = htlcInterface.encodeEventLog('Locked', [EVM_SWAP_ID, EVM_RECIP, EVM_CP_ADDR, ZERO_ADDRESS, EVM_AMT, EVM_HASHLOCK, 1_900_000_000n]);
    const receipt = { status: 1, blockNumber: 10, logs: [{ address: BASE_HTLC, topics: lockedLog.topics, data: lockedLog.data }] };
    const baseQuorum = new MockEvmProvider({ leafProviders: [new MockEvmProvider({ receipt }), new MockEvmProvider({ receipt })], blockNumber: 5000 });
    const durable = new InMemoryDurableStore();
    await durable.set('bch2swap:lockpending:evmfund-1', LOCK_TX_HASH); // a prior lock is in-flight (broadcast; funded-key not yet written)
    await durable.set('bch2swap:evmlocktx:evmfund-1', LOCK_TX_HASH);
    const goodProof = await gateAssertEvmLegBuriedForFunding(P(evmLegProvider()), FUND_GATE_PARAMS);
    const signer = new MockSigner(new MockEvmProvider({}), EVM_RECIP); // throw-mode: a SECOND lock would broadcast + throw
    const ctrl = new SwapController(evmFundRecord(), makeEvmDeps({
      evmProviderFor: (chain) => P(chain === 'base' ? baseQuorum : evmLegProvider()),
      evmSignerFor: () => SG(signer),
      durable,
    }));
    const { swapId } = await ctrl.lockEvm(goodProof);
    expect(swapId).toBe(EVM_SWAP_ID);                        // adopted the prior lock's swapId
    expect(signer.broadcastCount).toBe(0);                   // fix #4: NO second lock broadcast
    expect((await durable.get('bch2swap:funded:evmfund-1'))?.toLowerCase()).toBe(EVM_SWAP_ID.toLowerCase()); // funded sentinel set
    expect(await durable.get('bch2swap:lockpending:evmfund-1')).toBeNull(); // pending marker cleared on adopt
    expect(ctrl.getState().phase).toBe('responder_funded');
  });

  it('(fix #1 compile) lockEvm STRUCTURALLY requires a FundProof — no-arg / RevealAuthorization do not compile', () => {
    expect(typeof _lockEvmCompileCheck).toBe('function');
  });
});

// ── (iii) revealAndClaimEvm(auth) — fix #3 role + fix #2 re-mint ──────────────────────────────────────────
describe('SwapController.revealAndClaimEvm() — the initiator EVM secret reveal (fix #2/#3)', () => {
  beforeEach(() => { __setSpvConfigForTests('btc', FX.params, FX.checkpoint); __resetSpvCacheForTests(); });

  it('(fix #3) revealAndClaimEvm with a RESPONDER-role authorization THROWS and reveals NOTHING', async () => {
    // A responder RevealAuthorization (marginBasis 'none' — SKIPS the 4h margin) can only come from the UTXO gate.
    const btc = fxClient();
    const responderAuth = await gateAssertRevealSafe(G(btc), {
      role: 'responder', theirChain: 'btc', counterpartyRedeemScript: CP_REDEEM,
      recordedOutpoint: FX_OUTPOINT, counterpartyLocktime: CP_CLTV,
    });
    expect(responderAuth.role).toBe('responder');
    const signer = new MockSigner(new MockEvmProvider({}), EVM_RECIP);
    const ctrl = new SwapController(evmRevealRecord(), makeEvmDeps({ evmProviderFor: () => P(evmLegProvider()), evmSignerFor: () => SG(signer) }));
    await expect(ctrl.revealAndClaimEvm(responderAuth)).rejects.toThrow(/fix #3|initiator/i);
    expect(signer.broadcastCount).toBe(0);
    expect(ctrl.getState().phase).toBe('responder_funded');
  });

  it('(fix #2) revealAndClaimEvm re-mint FAILS (fresh on-chain margin < 4h) -> NO claim, S NOT sent', async () => {
    const goodAuth = await gateAssertEvmRevealSafe(P(evmLegProvider()), REVEAL_GATE_PARAMS); // a valid initiator auth
    expect(goodAuth.role).toBe('initiator');
    // Between mint and reveal, the FRESH on-chain timeLock is now within the 4h claim margin -> assertEvmRevealSafe throws.
    const tight = makeSwap({ hashLock: EVM_HASHLOCK, recipient: EVM_RECIP, token: ZERO_ADDRESS, amount: EVM_AMT, timeLock: BigInt(EVM_CHAIN_NOW + 10_000) });
    const signer = new MockSigner(new MockEvmProvider({}), EVM_RECIP);
    const ctrl = new SwapController(evmRevealRecord(), makeEvmDeps({ evmProviderFor: () => P(evmLegProvider({ swap: tight })), evmSignerFor: () => SG(signer) }));
    await expect(ctrl.revealAndClaimEvm(goodAuth)).rejects.toMatchObject({ name: 'GateFailure' });
    expect(signer.broadcastCount).toBe(0);              // fix #2: S never reaches claim calldata
    expect(ctrl.getState().phase).toBe('responder_funded');
  });

  it('(fix #3) a PRE-broadcast claimSwap throw CLEARS the claimbroadcast sentinel so a retry can re-arm', async () => {
    // The choke-point re-mint PASSES (healthy quorum), the winning-claim sentinel is committed, then claimSwap throws a
    // PRE-broadcast chain-mismatch (the signer's provider is on chainId 8453, but theirChain 'arb' expects 42161) —
    // tagged preBroadcast=true, no secret in calldata. FIX #3: the sentinel we set must be CLEARED so a retry re-arms;
    // the OLD code left it set -> a later call ADOPTS a never-broadcast claim -> the swap is stuck (never reveals S).
    const goodAuth = await gateAssertEvmRevealSafe(P(evmLegProvider()), REVEAL_GATE_PARAMS);
    expect(goodAuth.role).toBe('initiator');
    const signer = new MockSigner(new MockEvmProvider({ chainId: 8453n }), EVM_RECIP); // wrong chain -> pre-broadcast throw
    const durable = new InMemoryDurableStore();
    const ctrl = new SwapController(evmRevealRecord(), makeEvmDeps({
      evmProviderFor: () => P(evmLegProvider()), // healthy quorum -> assertEvmRevealSafe re-mint passes
      evmSignerFor: () => SG(signer),
      durable,
    }));
    await expect(ctrl.revealAndClaimEvm(goodAuth)).rejects.toThrow(/chain mismatch/i);
    expect(signer.broadcastCount).toBe(0);                                       // S never broadcast (pre-flight threw)
    expect(await durable.get('bch2swap:claimbroadcast:evmreveal-1')).toBeNull(); // fix #3: sentinel cleared for retry
    expect(ctrl.getState().phase).toBe('responder_funded');                     // never advanced
  });

  it('(fix #1/#3 compile) revealAndClaimEvm STRUCTURALLY requires a RevealAuthorization — no-arg / FundProof do not compile', () => {
    expect(typeof _revealAndClaimEvmCompileCheck).toBe('function');
  });
});

// ── (iv) refundEvm() — happy + durable-before-broadcast + the refund-race pivot (fix #7) ──────────────────
describe('SwapController.refundEvm() — refund own EVM lock + the refund-race secret-recovery pivot (fix #7)', () => {
  beforeEach(() => { __setSpvConfigForTests('btc', FX.params, FX.checkpoint); __resetSpvCacheForTests(); });

  // OUR own EVM leg 'base' with role responder; leg X on 'btc' is the counterparty leg we may still claim.
  function refundEvmRecord(over: Partial<DurableSwapRecord> = {}): DurableSwapRecord {
    return {
      id: over.id ?? 'evmrefund-1', role: 'responder',
      offer: makeOffer({ id: over.id ?? 'evmrefund-1', sendChain: 'btc', receiveChain: 'base', sendAmount: EVM_AMT_STR, receiveAmount: EVM_AMT_STR, secretHash: SECRET_HASH_HEX, secretScheme: 'hmac-v1', secretNonce: bytesToHex(NONCE) }),
      phase: 'responder_funded',
      myEvmSwapId: EVM_SWAP_ID,
      myEvmAddress: EVM_RECIP, counterpartyEvmAddress: EVM_CP_ADDR,
      myEvmToken: ZERO_ADDRESS, counterpartyEvmToken: ZERO_ADDRESS,
      counterpartyHTLC: { ...CP_HTLC, locktime: FX.tip + 200 }, // leg X on btc (claimable with the recovered secret)
      counterpartyFundingOutpoint: FX_OUTPOINT,
      ...over,
    };
  }

  it('HAPPY: refundEvm after expiry broadcasts the refund ONCE and sets the durable refundbroadcast sentinel -> refunded', async () => {
    const okProvider = new MockEvmProvider({
      swap: makeSwap({ initiator: EVM_RECIP, claimed: false, refunded: false, timeLock: 1_699_000_000n, amount: EVM_AMT }),
      block: { timestamp: 1_700_000_000 }, blockNumber: 5000, chainId: 8453n,
    });
    const signer = new MockSigner(okProvider, EVM_RECIP, { mode: 'ok' });
    const durable = new InMemoryDurableStore();
    const ctrl = new SwapController(refundEvmRecord(), makeEvmDeps({ evmSignerFor: () => SG(signer), durable }));
    const { txHash } = await ctrl.refundEvm();
    expect(signer.broadcastCount).toBe(1);
    expect(await durable.get('bch2swap:refundbroadcast:evmrefund-1')).toBe('1'); // durable sentinel written (before the send)
    expect(ctrl.getState().phase).toBe('refunded');
    expect(txHash).toBe(EVM_SWAP_ID);
  });

  it('durable-before-broadcast (fix #4): a commit FAILURE aborts the refund — no refund tx broadcasts', async () => {
    class FailCommitDurable extends InMemoryDurableStore {
      async commit(_e: Array<[string, string]>): Promise<void> { throw new Error('injected atomic-commit failure (QuotaExceeded)'); }
    }
    const okProvider = new MockEvmProvider({ swap: makeSwap({ initiator: EVM_RECIP, timeLock: 1_699_000_000n, amount: EVM_AMT }), block: { timestamp: 1_700_000_000 }, blockNumber: 5000 });
    const signer = new MockSigner(okProvider, EVM_RECIP, { mode: 'ok' });
    const ctrl = new SwapController(refundEvmRecord(), makeEvmDeps({ evmSignerFor: () => SG(signer), durable: new FailCommitDurable() }));
    await expect(ctrl.refundEvm()).rejects.toThrow(/commit failure|QuotaExceeded/i);
    expect(signer.broadcastCount).toBe(0);
    expect(ctrl.getState().phase).toBe('responder_funded');
  });

  it('a claim in flight (claimbroadcast sentinel) BLOCKS refundEvm (R181 cross-guard) + no broadcast', async () => {
    const durable = new InMemoryDurableStore();
    await durable.set('bch2swap:claimbroadcast:evmrefund-1', '1');
    const signer = new MockSigner(new MockEvmProvider({}), EVM_RECIP, { mode: 'ok' });
    const ctrl = new SwapController(refundEvmRecord(), makeEvmDeps({ evmSignerFor: () => SG(signer), durable }));
    await expect(ctrl.refundEvm()).rejects.toThrow(/R181|claim/i);
    expect(signer.broadcastCount).toBe(0);
  });

  it('THE PIVOT (fix #7): refund reverts because the counterparty ALREADY CLAIMED -> recover S from the on-chain Claimed event, verify the hash, claim the OTHER (UTXO) leg -> made whole', async () => {
    // refundSwap pre-flight sees our lock ALREADY CLAIMED (initiator took it with S) -> throws 'already claimed'.
    const claimedProvider = new MockEvmProvider({
      swap: makeSwap({ initiator: EVM_RECIP, claimed: true, timeLock: 1_800_000_000n, amount: EVM_AMT }),
      block: { timestamp: 1_700_000_000 }, blockNumber: 5000,
    });
    const signer = new MockSigner(claimedProvider, EVM_RECIP); // throw-mode: refundSwap throws PRE-broadcast (no send)
    // The quorum>=2 read provider whose leaves both carry the on-chain Claimed(swapId, S) event (fix #7 corroboration).
    const claimedLog = htlcInterface.encodeEventLog('Claimed', [EVM_SWAP_ID, ethers.hexlify(S)]);
    const leaf = () => new MockEvmProvider({ logs: [{ topics: claimedLog.topics, data: claimedLog.data, blockNumber: 10 }] });
    const quorum = new MockEvmProvider({ leafProviders: [leaf(), leaf()], blockNumber: 5000 });
    const btc = fxClient(); // leg X on btc — claimable with the recovered public secret
    const durable = new InMemoryDurableStore();
    const ctrl = new SwapController(refundEvmRecord(), makeEvmDeps({
      evmSignerFor: () => SG(signer),
      evmProviderFor: (chain) => P(chain === 'base' ? quorum : evmLegProvider()),
      clients: { btc },
      durable,
    }));
    const { txHash } = await ctrl.refundEvm();
    expect(signer.broadcastCount).toBe(0);              // the EVM refund never broadcast (it reverted pre-flight)
    expect(btc.broadcasts.length).toBe(1);              // we CLAIMED the counterparty UTXO leg with the recovered S
    expect(ctrl.getState().hasSecret).toBe(true);       // S recovered + retained
    expect(ctrl.getState().phase).toBe('completed');    // made whole
    expect(txHash).toBeTruthy();
    // the refund sentinel was cleared (the refund did NOT execute) so the pivot claim was not blocked by the cross-guard
    expect(await durable.get('bch2swap:refundbroadcast:evmrefund-1')).toBeNull();
  });

  it('the pivot KEEPS retrying (does not abandon) when S is NOT yet extractable from the Claimed event', async () => {
    const claimedProvider = new MockEvmProvider({ swap: makeSwap({ initiator: EVM_RECIP, claimed: true, timeLock: 1_800_000_000n, amount: EVM_AMT }), block: { timestamp: 1_700_000_000 }, blockNumber: 5000 });
    const signer = new MockSigner(claimedProvider, EVM_RECIP);
    // Both leaves return NO Claimed log yet (a lagging/pruned view) -> readEvmClaimedSecret yields null -> retryable throw.
    const quorum = new MockEvmProvider({ leafProviders: [new MockEvmProvider({ logs: [] }), new MockEvmProvider({ logs: [] })], blockNumber: 5000 });
    const durable = new InMemoryDurableStore();
    const ctrl = new SwapController(refundEvmRecord(), makeEvmDeps({ evmSignerFor: () => SG(signer), evmProviderFor: () => P(quorum), clients: { btc: fxClient() }, durable }));
    await expect(ctrl.refundEvm()).rejects.toThrow(/never abandon|not yet corroborated|fix #7/i);
    // fail-safe: the refund sentinel is KEPT set (a co-running claim/refund cannot slip past while S may still surface)
    expect(await durable.get('bch2swap:refundbroadcast:evmrefund-1')).toBe('1');
    // fix #2: a durable refund-race-pending marker is ALSO set so a later refundEvm re-call RE-ENTERS recovery.
    expect(await durable.get('bch2swap:refundracepending:evmrefund-1')).toBe('1');
  });

  it('(fix #2) the pivot retry RE-ENTERS recovery via the durable marker (never a fresh refund / false-refunded) and recovers once S is extractable', async () => {
    // Attempt #1: our lock is already CLAIMED (refundSwap reverts pre-flight) but S is NOT yet extractable — both
    // leaves lag. recoverFromRefundRace persists the refund-race-pending marker + throws retryable.
    const claimedProvider = new MockEvmProvider({ swap: makeSwap({ initiator: EVM_RECIP, claimed: true, timeLock: 1_800_000_000n, amount: EVM_AMT }), block: { timestamp: 1_700_000_000 }, blockNumber: 5000 });
    const signer = new MockSigner(claimedProvider, EVM_RECIP); // throw-mode: refundSwap throws PRE-broadcast (no send)
    const leafA = new MockEvmProvider({ logs: [] });
    const leafB = new MockEvmProvider({ logs: [] });
    const quorum = new MockEvmProvider({ leafProviders: [leafA, leafB], blockNumber: 5000 });
    const btc = fxClient(); // leg X on btc — claimable with the recovered public secret
    const durable = new InMemoryDurableStore();
    const ctrl = new SwapController(refundEvmRecord(), makeEvmDeps({
      evmSignerFor: () => SG(signer),
      evmProviderFor: (chain) => P(chain === 'base' ? quorum : evmLegProvider()),
      clients: { btc },
      durable,
    }));
    await expect(ctrl.refundEvm()).rejects.toThrow(/never abandon|not yet corroborated|fix #7/i);
    expect(await durable.get('bch2swap:refundbroadcast:evmrefund-1')).toBe('1');
    expect(await durable.get('bch2swap:refundracepending:evmrefund-1')).toBe('1'); // marker persisted
    expect(btc.broadcasts.length).toBe(0);                                          // no claim yet

    // S becomes extractable on both leaves (the Claimed event surfaces).
    const claimedLog = htlcInterface.encodeEventLog('Claimed', [EVM_SWAP_ID, ethers.hexlify(S)]);
    const logEntry = { topics: claimedLog.topics, data: claimedLog.data, blockNumber: 10 };
    leafA.opts.logs = [logEntry];
    leafB.opts.logs = [logEntry];

    // Retry: the marker RE-ENTERS recovery (NOT a fresh refund, NOT an adopt-as-refunded) and makes us whole.
    const { txHash } = await ctrl.refundEvm();
    expect(signer.broadcastCount).toBe(0);              // fix #2: never sent a fresh EVM refund on the retry
    expect(btc.broadcasts.length).toBe(1);              // claimed the counterparty UTXO leg with the recovered public S
    expect(ctrl.getState().hasSecret).toBe(true);       // S recovered + retained
    expect(ctrl.getState().phase).toBe('completed');    // made whole (never falsely 'refunded')
    expect(txHash).toBeTruthy();
    // both markers cleared once S is recovered + the other leg is claimed
    expect(await durable.get('bch2swap:refundracepending:evmrefund-1')).toBeNull();
    expect(await durable.get('bch2swap:refundbroadcast:evmrefund-1')).toBeNull();
  });

  it('(fix #5) a TRANSIENT pre-broadcast failure in refundEvm CLEARS the refundbroadcast sentinel so a retry re-arms', async () => {
    // callThrows makes refundSwap's pre-flight getSwap read throw BEFORE htlc.refund() — a pre-broadcast failure the
    // message-based sentinel-clear allowlist does NOT match. refundSwap now tags it preBroadcast=true so refundEvm
    // clears the sentinel it set; PRE-FIX it stays set (the allowlist misses the message) and WEDGES the refund.
    const unreachable = new MockEvmProvider({ callThrows: true });
    const signer = new MockSigner(unreachable, EVM_RECIP, { mode: 'ok' }); // 'ok' -> only the pre-flight read fails it
    const durable = new InMemoryDurableStore();
    const ctrl = new SwapController(refundEvmRecord(), makeEvmDeps({ evmSignerFor: () => SG(signer), durable }));
    await expect(ctrl.refundEvm()).rejects.toThrow(/unreachable|callThrows|RPC/i);
    expect(signer.broadcastCount).toBe(0);                                        // never reached the refund broadcast
    expect(await durable.get('bch2swap:refundbroadcast:evmrefund-1')).toBeNull(); // fix #5: sentinel cleared for retry
  });

  it('(fix #5) a POST-broadcast / ambiguous refundEvm failure KEEPS the refundbroadcast sentinel (fail-safe)', async () => {
    // Healthy pre-flight (swap exists, initiator matches, timelock expired) so refundSwap REACHES the refund broadcast,
    // where the throw-mode signer throws at submission (ambiguous — the tx may have been submitted). Sentinel stays SET.
    const okProvider = new MockEvmProvider({
      swap: makeSwap({ initiator: EVM_RECIP, claimed: false, refunded: false, timeLock: 1_699_000_000n, amount: EVM_AMT }),
      block: { timestamp: 1_700_000_000 }, blockNumber: 5000, chainId: 8453n,
    });
    const signer = new MockSigner(okProvider, EVM_RECIP); // throw-mode: htlc.refund() submission throws (post broadcastReached)
    const durable = new InMemoryDurableStore();
    const ctrl = new SwapController(refundEvmRecord(), makeEvmDeps({ evmSignerFor: () => SG(signer), durable }));
    await expect(ctrl.refundEvm()).rejects.toThrow(/BROADCAST ATTEMPTED|sendTransaction/i);
    expect(await durable.get('bch2swap:refundbroadcast:evmrefund-1')).toBe('1'); // KEPT (fail-safe)
  });
});

// ── (v) watchForClaimEvm() — the responder watches its OWN EVM lock; hash is the authenticator ────────────
describe('SwapController.watchForClaimEvm() — responder watches its own EVM lock (hash-verified, quorum>=1)', () => {
  function watchEvmRecord(over: Partial<DurableSwapRecord> = {}): DurableSwapRecord {
    return {
      id: over.id ?? 'evmwatch-1', role: 'responder',
      offer: makeOffer({ id: over.id ?? 'evmwatch-1', sendChain: 'btc', receiveChain: 'base', sendAmount: EVM_AMT_STR, receiveAmount: EVM_AMT_STR, secretHash: SECRET_HASH_HEX }),
      phase: 'responder_funded',
      myEvmSwapId: EVM_SWAP_ID,
      myEvmAddress: EVM_RECIP, counterpartyEvmAddress: EVM_CP_ADDR,
      myEvmToken: ZERO_ADDRESS, counterpartyEvmToken: ZERO_ADDRESS,
      ...over,
    };
  }
  function claimedProviderFor(secretBytes: Uint8Array): MockEvmProvider {
    const log = htlcInterface.encodeEventLog('Claimed', [EVM_SWAP_ID, ethers.hexlify(secretBytes)]);
    return new MockEvmProvider({ logs: [{ topics: log.topics, data: log.data, blockNumber: 10 }] });
  }

  it('returns the secret + advances to claimed when the initiator reveals a VALID preimage', async () => {
    const ctrl = new SwapController(watchEvmRecord(), makeEvmDeps({ evmProviderFor: () => P(claimedProviderFor(S)) }));
    const { secret } = await ctrl.watchForClaimEvm();
    expect(secret).not.toBeNull();
    expect(bytesToHex(secret!)).toBe(bytesToHex(S));
    expect(ctrl.getState().phase).toBe('claimed');
    expect(ctrl.getState().hasSecret).toBe(true);
  });

  it('REJECTS a forged preimage (sha256(S) !== hashLock) and does NOT advance', async () => {
    const forged = hexToBytes('ab'.repeat(32)); // a 32-byte value that is NOT the preimage
    const ctrl = new SwapController(watchEvmRecord(), makeEvmDeps({ evmProviderFor: () => P(claimedProviderFor(forged)) }));
    const { secret } = await ctrl.watchForClaimEvm();
    expect(secret).toBeNull();
    expect(ctrl.getState().phase).toBe('responder_funded'); // never advanced on a forged reveal
  });

  it('does NOT throw on absence (no Claimed event) — returns {secret:null}', async () => {
    const ctrl = new SwapController(watchEvmRecord(), makeEvmDeps({ evmProviderFor: () => P(new MockEvmProvider({ logs: [] })) }));
    await expect(ctrl.watchForClaimEvm()).resolves.toEqual({ secret: null });
  });

  // FIX #1: a leaf modelling a REAL public RPC — it REJECTS any getLogs whose block range exceeds `maxRange`
  // ('range too large'), and it THROWS if the OLD unbounded `toBlock:'latest'` is ever used. It returns the Claimed
  // log only when its block falls inside the queried [from,to] window. Records every attempted range so the test can
  // prove the read is BOUNDED + WINDOWED (never one wide fromBlock..latest query).
  class RangeCappedLeaf extends MockEvmProvider {
    readonly maxRange: number;
    readonly claimedBlock: number;
    readonly claimed: { topics: readonly string[]; data: string; blockNumber: number };
    readonly ranges: Array<{ from: number; to: number | string }> = [];
    constructor(cfg: { tip: number; maxRange: number; claimedBlock: number; secret: Uint8Array }) {
      super({ blockNumber: cfg.tip });
      this.maxRange = cfg.maxRange;
      this.claimedBlock = cfg.claimedBlock;
      const log = htlcInterface.encodeEventLog('Claimed', [EVM_SWAP_ID, ethers.hexlify(cfg.secret)]);
      this.claimed = { topics: log.topics, data: log.data, blockNumber: cfg.claimedBlock };
    }
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    async getLogs(filter: any): Promise<unknown[]> {
      const from = Number(filter?.fromBlock);
      const toRaw = filter?.toBlock;
      this.ranges.push({ from, to: toRaw });
      if (toRaw === 'latest') throw new Error('query returned more than 10000 results (range too large)'); // OLD unbounded path
      const to = Number(toRaw);
      if (to - from + 1 > this.maxRange) throw new Error('query returned more than 10000 results (range too large)');
      return (this.claimedBlock >= from && this.claimedBlock <= to) ? [this.claimed] : [];
    }
  }

  it('(fix #1) recovers S with a BOUNDED, WINDOWED getLogs — a public RPC that rejects a wide range never strands S', async () => {
    // tip is ~12k blocks past the lock, but the RPC caps getLogs at 5000 blocks/query. A single unbounded
    // fromBlock..latest query (the OLD code) would THROW 'range too large' -> S stranded -> refund-race loser lost.
    // The windowed reader caps + slides + shrink-retries, so it still finds the Claimed event at block 11000.
    const leaf = new RangeCappedLeaf({ tip: 13000, maxRange: 5000, claimedBlock: 11000, secret: S });
    const ctrl = new SwapController(watchEvmRecord({ evmLockBlock: 1000 }), makeEvmDeps({ evmProviderFor: () => P(leaf) }));
    const { secret } = await ctrl.watchForClaimEvm();
    expect(secret).not.toBeNull();
    expect(bytesToHex(secret!)).toBe(bytesToHex(S));
    expect(ctrl.getState().phase).toBe('claimed');
    // The read was BOUNDED: multiple windows were queried (sliding), and NONE used the unbounded toBlock:'latest'.
    expect(leaf.ranges.length).toBeGreaterThan(1);
    expect(leaf.ranges.every((r) => r.to !== 'latest')).toBe(true);
    // And every SUCCESSFUL (non-throwing) window stayed within the RPC's range cap.
    expect(leaf.ranges.every((r) => typeof r.to === 'number' && (r.to - r.from + 1) <= 9000)).toBe(true);
  });
});

// ============================================================================
// v3 AUDIT BATCH-2 — additional fund-safety coverage for untested SwapController paths.
//
// Each test drives the SPECIFIC fail-closed behavior end to end (not just calls the method): the legacy per-input
// value authentication, greedy coin selection, the amount + build-height validators, the funded/lock/refund adopt
// short-circuits, the resume DEFINITIVE-mismatch block, the dropped-refund resubmit, and the broadcast-after-commit
// durability. Plain wording throughout ("authenticated value", "fail-closed", "a stale read").
// ============================================================================
describe('v3 audit batch-2 — additional fund-safety coverage', () => {
  // ── shared local helpers ──────────────────────────────────────────────────────────────────────────────────
  const P2PKH_SPK_HEX = '76a914' + bytesToHex(RECIP_PKH) + '88ac'; // OP_DUP OP_HASH160 <hash160(PUB)> OP_EQUALVERIFY OP_CHECKSIG

  /** A btc (useBip143=false → LEGACY) own-leg funding client backed by the headers-only CTX fixture so the SPV
   *  verifyFundingHeight gate passes, plus the P2PKH funding inputs the per-input authenticator re-derives. */
  function btcLegacyClient(opts: { utxos: Array<{ tx_hash: string; tx_pos: number; value: number; height: number }>; rawTxByTxid: Record<string, string>; getTxThrows?: boolean }): MockElectrumClient {
    return new MockElectrumClient({
      headersByHeight: CTX.headersByHeight, height: CTX.tip,
      utxos: opts.utxos, rawTxByTxid: opts.rawTxByTxid, getTxThrows: opts.getTxThrows,
      broadcastTxid: '99'.repeat(32),
    });
  }
  /** An initiator record whose OWN leg X is on 'btc' (the legacy, non-BIP143 chain). */
  function btcFundRecord(): DurableSwapRecord {
    return makeRecord({ id: 'btcfund' }, { sendChain: 'btc', receiveChain: 'bch' });
  }

  // Minimal little-endian varint + output-value parser for a signed non-witness (BCH-style) tx, used to prove the
  // funding tx was built from the AUTHENTICATED input value (not the proxy's inflated listunspent value).
  function readVarint(b: Uint8Array, o: number): [number, number] {
    const f = b[o];
    if (f < 0xfd) return [f, o + 1];
    if (f === 0xfd) return [b[o + 1] | (b[o + 2] << 8), o + 3];
    if (f === 0xfe) return [((b[o + 1] | (b[o + 2] << 8) | (b[o + 3] << 16) | (b[o + 4] << 24)) >>> 0), o + 5];
    let v = 0; for (let i = 0; i < 8; i++) v += b[o + 1 + i] * 2 ** (8 * i); return [v, o + 9];
  }
  function parseTxOutputValues(rawHex: string): number[] {
    const b = hexToBytes(rawHex);
    let o = 4; // version
    let vin: number; [vin, o] = readVarint(b, o);
    for (let i = 0; i < vin; i++) { o += 36; let sl: number; [sl, o] = readVarint(b, o); o += sl + 4; }
    let vout: number; [vout, o] = readVarint(b, o);
    const values: number[] = [];
    for (let i = 0; i < vout; i++) {
      let v = 0; for (let k = 0; k < 8; k++) v += b[o + k] * 2 ** (8 * k); o += 8;
      let sl: number; [sl, o] = readVarint(b, o); o += sl;
      values.push(v);
    }
    return values;
  }

  /** Captures the inputs greedySelect actually reserved (== its selection), so an ordering test can assert WHICH
   *  UTXOs were spent without decoding the signed tx. */
  class CapturingReservation extends UtxoReservationRegistry {
    reservedInputs: Array<{ tx_hash: string; tx_pos: number }> = [];
    reserveInputs(id: string, inputs: Array<{ tx_hash: string; tx_pos: number }>, now?: number): void {
      this.reservedInputs = inputs.map((u) => ({ tx_hash: u.tx_hash, tx_pos: u.tx_pos }));
      super.reserveInputs(id, inputs, now);
    }
  }

  // ────────────────────────────────────────────────────────────────────────────────────────────────────────────
  // (1) LEGACY own-leg funding (btc, useBip143=false): the per-input verifyAndAuthenticateP2pkhInput loop must drive
  //     the build from the AUTHENTICATED raw-tx value, never the proxy listunspent value (R260-INPUT-VALUE-AUTH-001).
  // ────────────────────────────────────────────────────────────────────────────────────────────────────────────
  describe('(1) LEGACY own-leg funding (btc) — per-input value authentication', () => {
    beforeEach(() => { __setSpvConfigForTests('btc', CTX.params, CTX.checkpoint); __resetSpvCacheForTests(); });

    it('FAILS CLOSED when the AUTHENTICATED input total is below the amount even though the proxy over-reports (no broadcast, reservation released)', async () => {
      const input = buildUtxoRawTx([{ value: 50000, scriptPubKeyHex: P2PKH_SPK_HEX }]); // REAL on-chain value = 50000
      const client = btcLegacyClient({
        utxos: [{ tx_hash: input.txid, tx_pos: 0, value: 200000, height: CTX.tip - 1 }], // proxy INFLATES to 200000 (passes greedySelect)
        rawTxByTxid: { [input.txid]: input.rawTxHex },
      });
      const deps = makeDeps({ client });
      const ctrl = new SwapController(btcFundRecord(), deps);
      await expect(ctrl.fundLegX()).rejects.toThrow(/authenticated input total is below the funding amount/i);
      expect(client.broadcasts.length).toBe(0);                                   // never signed / broadcast
      expect(await deps.durable.get('bch2swap:funded:btcfund')).toBeNull();       // no durable sentinel
      expect(ctrl.getState().phase).toBe('taken');
      // The reserved input was RELEASED on the failure, so a retry (another swap) sees it as spendable again.
      const cand = deps.reservation.candidateUtxos('other-swap', [{ tx_hash: input.txid, tx_pos: 0, value: 200000, height: CTX.tip - 1 }], 1_700_000_000_000);
      expect(cand.length).toBe(1);
    });

    it('FUNDS from the AUTHENTICATED value when the proxy over-reports but the real value still covers the amount (change sized off the real value, not the proxy value)', async () => {
      const input = buildUtxoRawTx([{ value: 200000, scriptPubKeyHex: P2PKH_SPK_HEX }]); // REAL value = 200000 (>= 100000 amount)
      const client = btcLegacyClient({
        utxos: [{ tx_hash: input.txid, tx_pos: 0, value: 999999, height: CTX.tip - 1 }], // proxy INFLATES to 999999
        rawTxByTxid: { [input.txid]: input.rawTxHex },
      });
      const deps = makeDeps({ client });
      const ctrl = new SwapController(btcFundRecord(), deps);
      const { txid } = await ctrl.fundLegX();
      expect(client.broadcasts.length).toBe(1);
      expect(txid).toBeTruthy();
      expect(ctrl.getState().phase).toBe('initiator_funded');
      const outs = parseTxOutputValues(client.broadcasts[0]);
      expect(outs).toContain(100000);                       // the HTLC output pays exactly the funding amount
      const total = outs.reduce((s, v) => s + v, 0);
      expect(total).toBeGreaterThan(100000);                // a real change output exists
      expect(total).toBeLessThan(200000);                   // change = 200000 - amount - fee (built from the AUTHENTICATED 200000, NOT the proxy 999999)
    });

    it('ABORTS when a per-input authentication read fails (getTx unreachable) — no broadcast, no sentinel', async () => {
      const input = buildUtxoRawTx([{ value: 200000, scriptPubKeyHex: P2PKH_SPK_HEX }]);
      const client = btcLegacyClient({
        utxos: [{ tx_hash: input.txid, tx_pos: 0, value: 200000, height: CTX.tip - 1 }],
        rawTxByTxid: { [input.txid]: input.rawTxHex },
        getTxThrows: true, // the per-input raw-tx fetch fails
      });
      const deps = makeDeps({ client });
      const ctrl = new SwapController(btcFundRecord(), deps);
      await expect(ctrl.fundLegX()).rejects.toThrow(/proxy unreachable|getTxThrows/i);
      expect(client.broadcasts.length).toBe(0);
      expect(await deps.durable.get('bch2swap:funded:btcfund')).toBeNull();
      expect(ctrl.getState().phase).toBe('taken');
    });
  });

  // ────────────────────────────────────────────────────────────────────────────────────────────────────────────
  // (2) greedySelect: insufficient candidates fail closed; selection is FIFO oldest-first with the newest (immature
  //     coinbase) spent last.
  // ────────────────────────────────────────────────────────────────────────────────────────────────────────────
  describe('(2) greedySelect + insufficient-UTXO fail-closed (bch2)', () => {
    function bch2Client(utxos: Array<{ tx_hash: string; tx_pos: number; value: number; height: number }>): MockElectrumClient {
      return new MockElectrumClient({ headersByHeight: CTX.headersByHeight, height: CTX.tip, utxos, broadcastTxid: '99'.repeat(32) });
    }

    it('THROWS on EMPTY candidates — no broadcast', async () => {
      const client = bch2Client([]);
      const deps = makeDeps({ client });
      const ctrl = new SwapController(makeRecord(), deps);
      await expect(ctrl.fundLegX()).rejects.toThrow(/insufficient spendable UTXOs/i);
      expect(client.broadcasts.length).toBe(0);
      expect(await deps.durable.get('bch2swap:funded:offer-1')).toBeNull();
    });

    it('THROWS when the candidate total is below amount + fee — no broadcast', async () => {
      const client = bch2Client([{ tx_hash: '12'.repeat(32), tx_pos: 0, value: 100, height: CTX.tip - 1 }]); // 100 sat « 100000 amount
      const deps = makeDeps({ client });
      const ctrl = new SwapController(makeRecord(), deps);
      await expect(ctrl.fundLegX()).rejects.toThrow(/insufficient spendable UTXOs/i);
      expect(client.broadcasts.length).toBe(0);
    });

    it('selects FIFO oldest-first and leaves the newest (immature coinbase) unspent', async () => {
      const A = { tx_hash: 'a1'.repeat(32), tx_pos: 0, value: 60000, height: CTX.tip - 100 }; // oldest
      const B = { tx_hash: 'b2'.repeat(32), tx_pos: 0, value: 60000, height: CTX.tip - 50 };  // next-oldest
      const C = { tx_hash: 'c3'.repeat(32), tx_pos: 0, value: 500000, height: CTX.tip };       // NEWEST = an immature coinbase, spent LAST
      const client = bch2Client([C, A, B]);
      const reservation = new CapturingReservation();
      const deps = makeDeps({ client, reservation });
      const ctrl = new SwapController(makeRecord(), deps);
      await ctrl.fundLegX();
      const spent = reservation.reservedInputs.map((u) => u.tx_hash);
      expect(spent).toContain(A.tx_hash);       // the two oldest cover the 100000 amount
      expect(spent).toContain(B.tx_hash);
      expect(spent).not.toContain(C.tx_hash);   // the newest (immature coinbase) is NOT spent, though it alone would suffice
    });
  });

  // ────────────────────────────────────────────────────────────────────────────────────────────────────────────
  // (3) invalid-amount validator: 0 / negative / NaN / non-integer amounts fail BEFORE any selection or broadcast.
  // ────────────────────────────────────────────────────────────────────────────────────────────────────────────
  describe('(3) invalid-amount validator (throws before selection)', () => {
    beforeEach(() => { __setSpvConfigForTests('btc', FX.params, FX.checkpoint); __resetSpvCacheForTests(); }); // for the fundLegY receiveAmount case

    for (const [label, amt] of [['zero', 0], ['negative', -100], ['NaN', NaN], ['non-integer', 100000.5]] as const) {
      it(`fundLegX THROWS before selection on a ${label} sendAmount — no broadcast`, async () => {
        const deps = makeDeps();
        const ctrl = new SwapController(makeRecord({}, { sendAmount: amt as number }), deps);
        await expect(ctrl.fundLegX()).rejects.toThrow(/invalid.*amount|refusing to build the funding tx/i);
        expect(deps.client.broadcasts.length).toBe(0);
        expect(ctrl.getState().phase).toBe('taken');
      });
    }

    it('fundLegY THROWS before selection on an invalid receiveAmount (legYAmountSats) — leg Y is never funded', async () => {
      const btc = fxClient();
      const bch2 = bch2FundClient();
      const rec = fundRecord({ offer: makeOffer({ id: 'fund-1', sendChain: 'btc', receiveChain: 'bch2', sendAmount: 100000, receiveAmount: 0, secretHash: SECRET_HASH_HEX }) });
      const ctrl = new SwapController(rec, makeMultiDeps({ btc, bch2 }));
      const proof = await ctrl.verifyCounterpartyLegForFunding(); // reads leg X only (not receiveAmount) — mints fine
      await expect(ctrl.fundLegY(proof)).rejects.toThrow(/invalid.*amount|refusing to build the funding tx/i);
      expect(bch2.broadcasts.length).toBe(0);
    });
  });

  // ────────────────────────────────────────────────────────────────────────────────────────────────────────────
  // (4) implausible build-height pre-check (H1-LOCKTIME-PROXY-001 coarse backstop) — DISTINCT from the SPV gate: a
  //     0 / negative / grossly-inflated proxy height is rejected before it can become an unrecoverable refund CLTV.
  // ────────────────────────────────────────────────────────────────────────────────────────────────────────────
  describe('(4) implausible build-height pre-check (distinct from the SPV gate)', () => {
    for (const [label, h] of [['zero', 0], ['negative', -5], ['grossly-inflated', 999_999_999]] as const) {
      it(`fundLegX THROWS on a ${label} proxy height — no broadcast, no sentinel, phase unchanged`, async () => {
        const deps = makeDeps({ height: h });
        const ctrl = new SwapController(makeRecord(), deps);
        await expect(ctrl.fundLegX()).rejects.toThrow(/implausible/i);
        expect(deps.client.broadcasts.length).toBe(0);
        expect(await deps.durable.get('bch2swap:funded:offer-1')).toBeNull();
        expect(ctrl.getState().phase).toBe('taken');
      });
    }
  });

  // ────────────────────────────────────────────────────────────────────────────────────────────────────────────
  // (5) funded-sentinel adopt when the durable fundedhtlc side-channel is MISSING: the second call adopts the prior
  //     txid + sets funded, but myHTLC stays undefined (a resume reconstructs it from chain truth later).
  // ────────────────────────────────────────────────────────────────────────────────────────────────────────────
  describe('(5) funded-sentinel adopt without the durable fundedhtlc side-channel', () => {
    it('adopts the pre-set funded txid (no second broadcast); funded/txid set but myHTLC stays undefined', async () => {
      const deps = makeDeps();
      const PRIOR = '55'.repeat(32);
      await deps.durable.set('bch2swap:funded:offer-1', PRIOR); // a peer/tab already funded; the fundedhtlc side-channel is absent
      const ctrl = new SwapController(makeRecord(), deps);
      const { txid } = await ctrl.fundLegX();
      expect(txid).toBe(PRIOR);
      expect(deps.client.broadcasts.length).toBe(0);          // adopted — no divergent second broadcast
      const snap = ctrl.getState();
      expect(snap.phase).toBe('initiator_funded');
      expect(snap.myFundingTxid).toBe(PRIOR);
      expect(snap.myHTLC).toBeUndefined();                    // no side-channel to rehydrate from → stays undefined until resume
    });
  });

  // ────────────────────────────────────────────────────────────────────────────────────────────────────────────
  // (6) EVM adopt short-circuits + the EVM<->EVM refund-race pivot.
  // ────────────────────────────────────────────────────────────────────────────────────────────────────────────
  describe('(6) EVM lockEvm/refundEvm adopt + the EVM<->EVM refund-race pivot', () => {
    beforeEach(() => { __setSpvConfigForTests('btc', FX.params, FX.checkpoint); __resetSpvCacheForTests(); });

    const EVM_SWAP_ID_2 = '0x' + 'cd'.repeat(32);
    const BASE_HTLC = getEvmConfig(84532)!.htlcAddress;

    /** Our own EVM leg on 'base' (role responder); the counterparty leg is ALSO EVM, on 'arb' (the EVM<->EVM topology, so
     *  the refund-race pivot must take the claimSwap-the-other-leg branch, NOT the UTXO claimWithKnownSecret branch). */
    function refundEvmRecordLocal(over: Partial<DurableSwapRecord> = {}): DurableSwapRecord {
      return {
        id: over.id ?? 'evmrefund-1', role: 'responder',
        offer: makeOffer({ id: over.id ?? 'evmrefund-1', sendChain: 'arb', receiveChain: 'base', sendAmount: EVM_AMT_STR, receiveAmount: EVM_AMT_STR, secretHash: SECRET_HASH_HEX, secretScheme: 'hmac-v1', secretNonce: bytesToHex(NONCE) }),
        phase: 'responder_funded',
        myEvmSwapId: EVM_SWAP_ID,
        myEvmAddress: EVM_RECIP, counterpartyEvmAddress: EVM_CP_ADDR,
        myEvmToken: ZERO_ADDRESS, counterpartyEvmToken: ZERO_ADDRESS,
        ...over,
      };
    }

    // A signer whose claim() SUCCEEDS: it decodes the claim calldata + stages a status-1 receipt carrying the exact
    // Claimed(swapId, secret) event claimSwap verifies (same receipt shape the e2e-lifecycle EVM signer uses).
    class EvmClaimOkSigner {
      readonly provider: MockEvmProvider;
      readonly address: string;
      readonly sendTransaction: ReturnType<typeof vi.fn>;
      constructor(provider: MockEvmProvider, address = EVM_RECIP) {
        this.provider = provider; this.address = address;
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        this.sendTransaction = vi.fn(async (tx: any) => {
          const desc = htlcInterface.parseTransaction({ data: tx?.data, value: tx?.value ?? 0n });
          let logs: unknown[] = [];
          if (desc?.name === 'claim') {
            const [id, secretHex] = desc.args as unknown as [string, string];
            const enc = htlcInterface.encodeEventLog('Claimed', [id, secretHex]);
            logs = [{ address: tx.to, topics: [...enc.topics], data: enc.data, blockNumber: this.provider.opts.blockNumber ?? 5000, index: 0, blockHash: '0x' + 'bc'.repeat(32), transactionHash: '0x' + 'ab'.repeat(32), transactionIndex: 0, removed: false }];
          }
          const hash = '0x' + 'ab'.repeat(32);
          const bn = this.provider.opts.blockNumber ?? 5000;
          this.provider.opts.receipt = { status: 1, logs, hash, blockNumber: bn, index: 0, to: tx?.to ?? null, from: this.address, contractAddress: null, blockHash: '0x' + 'bc'.repeat(32), logsBloom: '0x' + '00'.repeat(256), gasUsed: 21_000n, cumulativeGasUsed: 21_000n, blobGasUsed: null, gasPrice: 0n, blobGasPrice: null, type: 2, root: null };
          return { hash, blockNumber: null, blockHash: null, index: 0, type: 2, from: this.address, to: tx?.to ?? null, gasLimit: 250_000n, nonce: 0, data: tx?.data ?? '0x', value: tx?.value ?? 0n, gasPrice: 0n, maxPriorityFeePerGas: null, maxFeePerGas: null, maxFeePerBlobGas: null, chainId: this.provider.opts.chainId ?? 8453n, signature: null, accessList: null };
        });
      }
      async getAddress(): Promise<string> { return this.address; }
      get broadcastCount(): number { return this.sendTransaction.mock.calls.length; }
    }

    it('(fundedKey adopt) lockEvm ADOPTS a pre-set funded swapId sentinel — no second lock broadcast', async () => {
      const durable = new InMemoryDurableStore();
      await durable.set('bch2swap:funded:evmfund-1', EVM_SWAP_ID.toLowerCase()); // a prior lock already resolved (funded=swapId)
      const goodProof = await gateAssertEvmLegBuriedForFunding(P(evmLegProvider()), FUND_GATE_PARAMS);
      const signer = new MockSigner(new MockEvmProvider({}), EVM_RECIP); // throw-mode: a SECOND lock would broadcast + throw
      const ctrl = new SwapController(evmFundRecord(), makeEvmDeps({ evmProviderFor: () => P(evmLegProvider()), evmSignerFor: () => SG(signer), durable }));
      const { swapId } = await ctrl.lockEvm(goodProof);
      expect(swapId.toLowerCase()).toBe(EVM_SWAP_ID.toLowerCase()); // adopted the prior swapId
      expect(signer.broadcastCount).toBe(0);                        // no second on-chain lock
      expect(ctrl.getState().phase).toBe('responder_funded');
    });

    it('(fix #4 adopt) refundEvm ADOPTS a prior refund + FINALIZES to refunded ONLY when getSwap.refunded===true', async () => {
      const durable = new InMemoryDurableStore();
      await durable.set('bch2swap:refundbroadcast:evmrefund-1', '1');
      const provider = new MockEvmProvider({ swap: makeSwap({ initiator: EVM_RECIP, refunded: true, timeLock: 1_699_000_000n, amount: EVM_AMT }), block: { timestamp: 1_700_000_000 }, blockNumber: 5000, chainId: 8453n });
      const signer = new MockSigner(provider, EVM_RECIP); // throw-mode: an adopt must NOT broadcast a fresh refund
      const ctrl = new SwapController(refundEvmRecordLocal(), makeEvmDeps({ evmSignerFor: () => SG(signer), durable }));
      const { txHash } = await ctrl.refundEvm();
      expect(signer.broadcastCount).toBe(0);
      expect(ctrl.getState().phase).toBe('refunded');                                 // getSwap.refunded===true → finalized
      expect(await durable.get('bch2swap:refundbroadcast:evmrefund-1')).toBe('1');     // sentinel kept
      expect(txHash).toBe(EVM_SWAP_ID);
    });

    it('(fix #4 adopt) a prior refund NOT yet confirmed (getSwap.refunded===false) KEEPS the sentinel + does NOT flip to refunded', async () => {
      const durable = new InMemoryDurableStore();
      await durable.set('bch2swap:refundbroadcast:evmrefund-1', '1');
      const provider = new MockEvmProvider({ swap: makeSwap({ initiator: EVM_RECIP, refunded: false, timeLock: 1_699_000_000n, amount: EVM_AMT }), block: { timestamp: 1_700_000_000 }, blockNumber: 5000 });
      const signer = new MockSigner(provider, EVM_RECIP);
      const ctrl = new SwapController(refundEvmRecordLocal(), makeEvmDeps({ evmSignerFor: () => SG(signer), durable }));
      await ctrl.refundEvm();
      expect(signer.broadcastCount).toBe(0);
      expect(ctrl.getState().phase).toBe('responder_funded');                       // NOT flipped (an unconfirmed prior refund)
      expect(await durable.get('bch2swap:refundbroadcast:evmrefund-1')).toBe('1');   // kept for the reorg-safe finalizer
    });

    it('(fix #4 adopt) a getSwap READ ERROR fails closed to not-refunded — KEEPS the sentinel, no phase change', async () => {
      const durable = new InMemoryDurableStore();
      await durable.set('bch2swap:refundbroadcast:evmrefund-1', '1');
      const provider = new MockEvmProvider({ callThrows: true }); // getSwap read fails → a stale/unreadable view must never finalize a refund
      const signer = new MockSigner(provider, EVM_RECIP);
      const ctrl = new SwapController(refundEvmRecordLocal(), makeEvmDeps({ evmSignerFor: () => SG(signer), durable }));
      await ctrl.refundEvm();
      expect(signer.broadcastCount).toBe(0);
      expect(ctrl.getState().phase).toBe('responder_funded');
      expect(await durable.get('bch2swap:refundbroadcast:evmrefund-1')).toBe('1');
    });

    it('THE PIVOT (EVM<->EVM): our base lock was CLAIMED → recover S from the base Claimed event → claim the OTHER EVM leg on arb via claimSwap (NOT claimWithKnownSecret) → made whole', async () => {
      // Our own 'base' lock: refundSwap pre-flight sees it ALREADY CLAIMED (initiator took it with S) → throws pre-broadcast.
      const baseClaimedProvider = new MockEvmProvider({ swap: makeSwap({ initiator: EVM_RECIP, claimed: true, timeLock: 1_800_000_000n, amount: EVM_AMT }), block: { timestamp: 1_700_000_000 }, blockNumber: 5000, chainId: 8453n });
      const baseSigner = new MockSigner(baseClaimedProvider, EVM_RECIP); // throw-mode: the EVM refund reverts pre-flight (no send)
      // The quorum>=2 read of our base lock's Claimed(swapId, S) event.
      const claimedLog = htlcInterface.encodeEventLog('Claimed', [EVM_SWAP_ID, ethers.hexlify(S)]);
      const baseLeaf = () => new MockEvmProvider({ logs: [{ topics: claimedLog.topics, data: claimedLog.data, blockNumber: 10 }] });
      const baseQuorum = new MockEvmProvider({ leafProviders: [baseLeaf(), baseLeaf()], blockNumber: 5000 });
      // The counterparty leg on 'arb': claimSwap must SUCCEED (we are the recipient, sha256(S)===hashLock, future timelock).
      const arbProvider = new MockEvmProvider({ swap: makeSwap({ recipient: EVM_RECIP, hashLock: EVM_HASHLOCK, amount: EVM_AMT, timeLock: 1_800_000_000n, claimed: false, refunded: false }), block: { timestamp: 1_700_000_000 }, blockNumber: 5000, chainId: 42161n });
      const arbSigner = new EvmClaimOkSigner(arbProvider, EVM_RECIP);
      const durable = new InMemoryDurableStore();
      const ctrl = new SwapController(refundEvmRecordLocal({ counterpartyEvmSwapId: EVM_SWAP_ID_2 }), makeEvmDeps({
        evmProviderFor: (chain) => P(chain === 'base' ? baseQuorum : arbProvider),
        evmSignerFor: (chain) => (chain === 'base' ? SG(baseSigner) : (arbSigner as unknown as Signer)),
        durable,
      }));
      const { txHash } = await ctrl.refundEvm();
      expect(baseSigner.broadcastCount).toBe(0);   // the EVM refund never broadcast (it reverted pre-flight)
      expect(arbSigner.broadcastCount).toBe(1);    // we CLAIMED the OTHER EVM leg on arb with the recovered public S (the EVM<->EVM branch)
      expect(ctrl.getState().hasSecret).toBe(true);
      expect(ctrl.getState().phase).toBe('completed');
      expect(await durable.get('bch2swap:claimbroadcast:evmrefund-1')).toBe('1');       // the EVM claim sentinel is set
      expect(await durable.get('bch2swap:refundracepending:evmrefund-1')).toBeNull();   // recovery complete → cleared
      expect(await durable.get('bch2swap:refundbroadcast:evmrefund-1')).toBeNull();     // refund did not execute → cleared
      expect(txHash).toBeTruthy();
    });
  });

  // ────────────────────────────────────────────────────────────────────────────────────────────────────────────
  // (7) resume: a DEFINITIVE myHTLC 'mismatch' fails closed (irreversible actions throw the fix #10 error, broadcast
  //     nothing); and rebroadcastRefundIfDropped resubmits a dropped refund but never rebroadcasts on a read error.
  // ────────────────────────────────────────────────────────────────────────────────────────────────────────────
  describe('(7) resume DEFINITIVE mismatch + rebroadcastRefundIfDropped', () => {
    beforeEach(() => { __setSpvConfigForTests('btc', FX.params, FX.checkpoint); __resetSpvCacheForTests(); });

    it("a non-bare-hex myFundingTxid is a DEFINITIVE 'mismatch' → refund throws the fix #10 error, broadcasts nothing", async () => {
      const bch2 = refundClient();
      const ctrl = await SwapController.resume(refundableRecord({ id: 'resume-mm-hex', myFundingTxid: 'not-a-bare-hex-txid' }), makeMultiDeps({ bch2 }, {}));
      expect(ctrl.getState().resumeAuth).toBe('mismatch');
      expect(bch2.broadcasts.length).toBe(0);
      await expect(ctrl.refund()).rejects.toThrow(/fix #10|DEFINITIVE|authentication/i);
      expect(bch2.broadcasts.length).toBe(0);
      expect(ctrl.getState().phase).toBe('initiator_funded'); // never refunded
    });

    it("a funding output[0] that is NOT our HTLC P2SH is a DEFINITIVE 'mismatch' → refund throws fix #10, broadcasts nothing", async () => {
      const foreign = buildUtxoRawTx([{ value: 200000, scriptPubKeyHex: '76a914' + 'bb'.repeat(20) + '88ac' }]); // output[0] = a FOREIGN P2PKH, not our P2SH
      const bch2 = new MockElectrumClient({ height: 100100, utxos: [], history: [], rawTxByTxid: { [foreign.txid]: foreign.rawTxHex }, broadcastTxid: '99'.repeat(32) });
      const ctrl = await SwapController.resume(refundableRecord({ id: 'resume-mm-p2sh', myFundingTxid: foreign.txid }), makeMultiDeps({ bch2 }, {}));
      expect(ctrl.getState().resumeAuth).toBe('mismatch');
      await expect(ctrl.refund()).rejects.toThrow(/fix #10|DEFINITIVE|authentication/i);
      expect(bch2.broadcasts.length).toBe(0);
    });

    it("a DEFINITIVE 'mismatch' also blocks the initiator revealAndClaim (fix #10) — the secret is never revealed", async () => {
      const btc = fxClient();
      const bch2 = bch2FundClient();
      const rec: DurableSwapRecord = {
        id: 'resume-mm-reveal', role: 'initiator',
        offer: makeOffer({ id: 'resume-mm-reveal', sendChain: 'bch2', receiveChain: 'btc' }),
        phase: 'responder_funded',
        counterpartyClaimPkh: CLAIM_PKH_HEX,
        myHTLC: OWN_HTLC, myFundingTxid: 'not-a-bare-hex-txid', fundLocktime: OWN_LOCKTIME, // our leg X on bch2 with a tampered funding txid
        counterpartyHTLC: { ...CP_HTLC, locktime: CP_CLTV }, counterpartyFundingOutpoint: FX_OUTPOINT, // leg Y on btc (revealable)
      };
      const ctrl = await SwapController.resume(rec, makeMultiDeps({ bch2, btc }, {}));
      expect(ctrl.getState().resumeAuth).toBe('mismatch');
      const auth = await ctrl.verifyCounterpartyLegForReveal(); // a genuine initiator reveal authorization
      await expect(ctrl.revealAndClaim(auth)).rejects.toThrow(/fix #10|DEFINITIVE|authentication/i);
      expect(btc.broadcasts.length).toBe(0);
      expect(ctrl.getState().phase).toBe('responder_funded');
    });

    // rebroadcastRefundIfDropped is exercised directly: resume() reaches step (4b) only when a refund is in flight but
    // NOT via the refund-first short-circuit, so we drive the resubmit logic on the instance to prove its fail-closed
    // behavior. It resubmits the EXACT durable refund tx (idempotent) only when the refund dropped AND the funding is
    // still unspent; a read error never rebroadcasts blindly.
    const REFUND_TXID = 'dd'.repeat(32);
    const REFUND_RAW = 'aabbccddeeff';
    type Rebroadcastable = { rebroadcastRefundIfDropped(): Promise<void> };

    it('rebroadcastRefundIfDropped resubmits the EXACT durable refund tx when it dropped + the funding is still unspent', async () => {
      const durable = new InMemoryDurableStore();
      await durable.set('bch2swap:refundbroadcast:rb-drop', '1');
      await durable.set('bch2swap:refundtx:rb-drop', JSON.stringify({ txid: REFUND_TXID, rawTx: REFUND_RAW, spent: { tx_hash: OWN_FUND.txid, tx_pos: 0 } }));
      const bch2 = refundClient({ history: [], utxos: [{ tx_hash: OWN_FUND.txid, tx_pos: 0, value: 200000, height: 100040 }] }); // refund txid absent from history; funding STILL unspent
      const ctrl = new SwapController(refundableRecord({ id: 'rb-drop' }), makeMultiDeps({ bch2 }, { durable }));
      await (ctrl as unknown as Rebroadcastable).rebroadcastRefundIfDropped();
      expect(bch2.broadcasts).toContain(REFUND_RAW); // resubmitted the exact durable refund raw tx
    });

    it('rebroadcastRefundIfDropped does NOT rebroadcast on a history READ ERROR (fail-closed — cannot tell if dropped)', async () => {
      const durable = new InMemoryDurableStore();
      await durable.set('bch2swap:refundbroadcast:rb-err', '1');
      await durable.set('bch2swap:refundtx:rb-err', JSON.stringify({ txid: REFUND_TXID, rawTx: REFUND_RAW }));
      class ThrowHistoryClient extends MockElectrumClient {
        async getHistory(): Promise<never> { throw new Error('proxy unreachable (getHistory)'); }
      }
      const bch2 = new ThrowHistoryClient({ height: 100100, utxos: [{ tx_hash: OWN_FUND.txid, tx_pos: 0, value: 200000, height: 100040 }], rawTxByTxid: { [OWN_FUND.txid]: OWN_FUND.rawTxHex }, broadcastTxid: '99'.repeat(32) });
      const ctrl = new SwapController(refundableRecord({ id: 'rb-err' }), makeMultiDeps({ bch2 }, { durable }));
      await (ctrl as unknown as Rebroadcastable).rebroadcastRefundIfDropped();
      expect(bch2.broadcasts.length).toBe(0); // fail-closed: never rebroadcast blindly on a stale/unreadable view
    });
  });

  // ────────────────────────────────────────────────────────────────────────────────────────────────────────────
  // (8) broadcast fails AFTER the durable commit with an AMBIGUOUS (transport/timeout) error: the claim tx + the
  //     claimbroadcast sentinel must PERSIST so a retry / resume can rebroadcast the already-built secret-bearing tx.
  // ────────────────────────────────────────────────────────────────────────────────────────────────────────────
  describe('(8) broadcast-fail AFTER the durable commit — claim tx + sentinel persist', () => {
    beforeEach(() => { __setSpvConfigForTests('btc', FX.params, FX.checkpoint); __resetSpvCacheForTests(); });
    const HEX64_RE = /^[0-9a-f]{64}$/;

    function ambiguousBtc(msg: string): MockElectrumClient {
      class AmbiguousBtc extends MockElectrumClient {
        async broadcastTx(rawTx: string): Promise<string> { this.broadcasts.push(rawTx); throw new Error(msg); }
      }
      return new AmbiguousBtc({
        headersByHeight: FX.headersByHeight, merkleProof: { block_height: FX.fundHeight, merkle: [], pos: 0 },
        utxos: [{ tx_hash: FX.fundTxid, tx_pos: 0, value: 100000, height: FX.fundHeight }],
        rawTxByTxid: { [FX.fundTxid]: FX.fundRawHex }, height: FX.tip, tipHeaderHex: FX.headersByHeight[FX.tip], broadcastTxid: '00'.repeat(31) + 'aa',
      });
    }

    it('revealAndClaim: an AMBIGUOUS broadcast failure KEEPS the durable claim tx + the sentinel (retry/resume can rebroadcast)', async () => {
      const btc = ambiguousBtc('broadcast timed out after 30s — tx may still propagate');
      const durable = new InMemoryDurableStore();
      const ctrl = new SwapController(revealRecord(), makeMultiDeps({ btc }, { durable }));
      const auth = await ctrl.verifyCounterpartyLegForReveal();
      await expect(ctrl.revealAndClaim(auth)).rejects.toThrow(/timed out/i);
      expect(btc.broadcasts.length).toBe(1);                                     // the secret-bearing claim was attempted once
      expect(await durable.get('bch2swap:claimbroadcast:reveal-1')).toBe('1');   // sentinel KEPT (fail-safe over-protect)
      const cached = await durable.get('bch2swap:claimtx:reveal-1');
      expect(cached).toBeTruthy();                                               // the durable claim tx PERSISTS for a rebroadcast
      const parsed = JSON.parse(cached!) as { txid?: string; rawTx?: string; spent?: unknown };
      expect(HEX64_RE.test(String(parsed.txid).toLowerCase())).toBe(true);
      expect(typeof parsed.rawTx).toBe('string');
      expect(parsed.spent).toBeTruthy();                                         // carries the exact spent outpoint (fix #8 triangulation intact)
    });

    it('claimWithKnownSecret: an AMBIGUOUS broadcast failure KEEPS the durable claim tx + the sentinel', async () => {
      const spend = await makeLegYClaimSpend(S);
      const bch2 = new MockElectrumClient({ history: [{ tx_hash: spend.txid, height: 12 }], rawTxByTxid: { [spend.txid]: spend.rawTx } });
      const btc = ambiguousBtc('socket hang up');
      const durable = new InMemoryDurableStore();
      const ctrl = new SwapController(watchRecord(), makeMultiDeps({ bch2, btc }, { durable }));
      await ctrl.watchForSecret();
      await expect(ctrl.claimWithKnownSecret()).rejects.toThrow(/socket hang up/i);
      expect(btc.broadcasts.length).toBe(1);
      expect(await durable.get('bch2swap:claimbroadcast:watch-1')).toBe('1');    // sentinel KEPT
      const cached = await durable.get('bch2swap:claimtx:watch-1');
      expect(cached).toBeTruthy();                                              // the durable claim tx PERSISTS
      const parsed = JSON.parse(cached!) as { txid?: string; rawTx?: string };
      expect(HEX64_RE.test(String(parsed.txid).toLowerCase())).toBe(true);
      expect(typeof parsed.rawTx).toBe('string');
    });
  });
});
