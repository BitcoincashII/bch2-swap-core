/**
 * e2e-lifecycle.test.ts — P1b CULMINATION: TWO SwapControllers (initiator + responder), one per party,
 * interoperating through a SINGLE shared chain object per network, run through COMPLETE swaps.
 *
 * What this proves that the per-method unit suite (swap-controller.test.ts, 420 tests) never could: that the
 * methods COMPOSE and the two parties INTEROP. Each network's state is ONE object both parties' clients
 * read/write — a broadcast by party A (fundLegX / fundLegY / revealAndClaim / claimWithKnownSecret / lockEvm /
 * revealAndClaimEvm) mutates the shared UTXO set + history + (EVM) swap-struct/event-log so party B's
 * getUTXOs/getHistory/getTx/getSwap/getLogs SEE it. There is NO manual state injection between the controllers.
 *
 * GENUINENESS OF THE SECRET (the whole point): the secret S never crosses from the initiator controller to the
 * responder controller in memory. The responder learns S ONLY by extracting it from the initiator's on-chain
 * claim/Claimed-event that the shared chain carries — extractSecret over the real claim rawTx (UTXO) or
 * readEvmClaimedSecret over the real Claimed log (EVM). The two controllers use SEPARATE seed vaults (distinct
 * keys) and SEPARATE durable stores; only the initiator's vault can derive S from K_ss.
 *
 * SPV is REAL: verifyFundingHeight / verifyConfirmations / spvVerifiedTipFresh / getChainTimeSec run over a
 * synthetic easy-difficulty PoW header chain (the buildSynthChain technique from swap-controller.test.ts),
 * extended by mining fresh PoW headers as legs fund + bury. Every mined block that carries a tx sets its header
 * merkleRoot to hash256(rawTx), so the empty-branch Merkle proof verifies the funding/claim is really buried.
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
  type DurableHTLC,
} from './swap-controller';
import {
  InMemoryDurableStore, InMemorySessionStore, InProcessMutex, type DurableStore,
} from './storage';
import { UtxoReservationRegistry } from './utxo-reservation';
import {
  buildUtxoRawTx, MockEvmProvider, htlcInterface, GET_SWAP_SELECTOR, encodeSwap, ZERO_SWAP, ZERO_BYTES32,
  ZERO_ADDRESS, type SwapStruct,
} from './test-mocks';
import { hexToBytes, bytesToHex, hash160, sha256, htlcScripthash } from './htlc-builder';
import { extractSecret } from './swap-flow';
import { swapSecretFromKss } from './seed-secret';
import { __setSpvConfigForTests, __resetSpvCacheForTests } from './spv-verifier';
import { blockHashInternal, checkPoW, hash256, type AsertParams } from './spv';
import { getEvmConfig } from './evm-config';
import { ethers, type Provider, type Signer } from 'ethers';
import type { SwapOffer, Chain } from './swap-types';

// ============================================================================
// Two distinct parties' keys (the initiator + responder MUST have different signing keys, because a leg's HTLC
// recipient pkh (the claiming party) and refund pkh (the funding party) must differ — createHTLCRedeemScript
// rejects recipient == refund). Only the INITIATOR's vault carries K_ss (derives S); the responder learns S
// on-chain, never from its vault.
// ============================================================================
const PRIV_I = hexToBytes('11'.repeat(32));
const PUB_I = secp256k1.getPublicKey(PRIV_I, true);
const PKH_I = hash160(PUB_I);
const PRIV_R = hexToBytes('44'.repeat(32));
const PUB_R = secp256k1.getPublicKey(PRIV_R, true);
const PKH_R = hash160(PUB_R);
const KSS = hexToBytes('22'.repeat(32));
const NONCE = hexToBytes('33'.repeat(16));
const S = swapSecretFromKss(KSS, NONCE)!;              // the ONE secret; only the initiator can derive it
const SECRET_HASH_HEX = bytesToHex(sha256(S));
const SECRET_HASH_BYTES = sha256(S);

// EVM party addresses (scenario 4): the responder LOCKS the EVM leg (its initiator), the initiator is the recipient.
const INIT_EVM = '0x1111111111111111111111111111111111111111';
const RESP_EVM = '0x2222222222222222222222222222222222222222';

// ============================================================================
// Seed vault: configurable K_ss + signing key. The initiator gets K_ss (so recoverSecret derives S); the
// responder gets null K_ss (it never derives S — it extracts it from the initiator's on-chain claim).
// ============================================================================
class PartySeedVault implements SeedVault {
  disposed = false;
  constructor(private readonly kss: Uint8Array | null, private readonly priv: Uint8Array, private readonly pub: Uint8Array) {}
  async signingKey(): Promise<SigningKeyPair> {
    if (this.disposed) throw new Error('PartySeedVault disposed');
    return { privateKey: this.priv, publicKey: this.pub };
  }
  async swapKss(): Promise<Uint8Array | null> {
    return this.disposed || !this.kss ? null : new Uint8Array(this.kss);
  }
  dispose(): void { this.disposed = true; }
}

// ============================================================================
// Low-level byte helpers for the shared-chain tx parser + PoW header mining.
// ============================================================================
const rev = (a: Uint8Array): Uint8Array => { const b = new Uint8Array(a.length); for (let i = 0; i < a.length; i++) b[i] = a[a.length - 1 - i]; return b; };
const toHexRev = (a: Uint8Array): string => bytesToHex(rev(a));
const p2pkhSpkHex = (pkh: Uint8Array): string => '76a914' + bytesToHex(pkh) + '88ac';
const scripthashOf = (spkHex: string): string => bytesToHex(rev(sha256(hexToBytes(spkHex))));

function readVarInt(tx: Uint8Array, off: number): [number, number] {
  const b = tx[off];
  if (b < 0xfd) return [b, 1];
  if (b === 0xfd) return [tx[off + 1] | (tx[off + 2] << 8), 3];
  if (b === 0xfe) return [(tx[off + 1] | (tx[off + 2] << 8) | (tx[off + 3] << 16) | (tx[off + 4] << 24)) >>> 0, 5];
  let v = 0; for (let i = 0; i < 6; i++) v += tx[off + 1 + i] * 2 ** (8 * i); return [v, 9];
}
const readU32LE = (tx: Uint8Array, o: number): number => (tx[o] | (tx[o + 1] << 8) | (tx[o + 2] << 16) | (tx[o + 3] << 24)) >>> 0;
function readU64LE(tx: Uint8Array, o: number): number { let v = 0n; for (let i = 0; i < 8; i++) v |= BigInt(tx[o + i]) << BigInt(8 * i); return Number(v); }

interface ParsedTx { txid: string; inputs: Array<{ tx_hash: string; tx_pos: number }>; outputs: Array<{ value: number; spkHex: string }>; }
/** Parse a LEGACY (non-witness) raw tx — all bch2/bch/btc swap txs are legacy-serialized. */
function parseLegacyTx(rawHex: string): ParsedTx {
  const tx = hexToBytes(rawHex);
  let o = 4; // skip nVersion
  const [nIn, l1] = readVarInt(tx, o); o += l1;
  const inputs: Array<{ tx_hash: string; tx_pos: number }> = [];
  for (let i = 0; i < nIn; i++) {
    const prev = tx.slice(o, o + 32); o += 32;             // internal (LE) prevout hash
    const vout = readU32LE(tx, o); o += 4;
    const [ssLen, l2] = readVarInt(tx, o); o += l2 + ssLen; // scriptSig
    o += 4;                                                 // nSequence
    inputs.push({ tx_hash: bytesToHex(rev(prev)), tx_pos: vout }); // display txid = reverse(internal)
  }
  const [nOut, l3] = readVarInt(tx, o); o += l3;
  const outputs: Array<{ value: number; spkHex: string }> = [];
  for (let i = 0; i < nOut; i++) {
    const value = readU64LE(tx, o); o += 8;
    const [spkLen, l4] = readVarInt(tx, o); o += l4;
    const spkHex = bytesToHex(tx.slice(o, o + spkLen)); o += spkLen;
    outputs.push({ value, spkHex });
  }
  const txid = bytesToHex(rev(hash256(tx)));
  return { txid, inputs, outputs };
}

// ============================================================================
// SharedChain — ONE object per UTXO network. Both parties' clients read/write it, so a broadcast by party A is
// visible to party B. Carries a REAL synthetic PoW header chain that grows as legs fund + bury (so verifyFunding
// Height / verifyConfirmations / spvVerifiedTipFresh run for real).
// ============================================================================
interface ChainUtxo { tx_hash: string; tx_pos: number; value: number; height: number; spkHex: string; }
interface HistItem { scripthash: string; tx_hash: string; height: number; }

class SharedChain {
  readonly chain: Chain;
  readonly anchorHeight: number;
  readonly spacing: number;
  readonly bits: number;
  readonly powLimit = 1n << 255n;
  readonly anchorParentTime: number;
  readonly headersByHeight: Record<number, string> = {};
  readonly params: AsertParams;
  readonly checkpoint: { height: number; hashDisplay: string; time: number };
  tip: number;             // the real mined tip (has PoW headers)
  reportedTip: number;     // what getBlockHeight advertises (bumped past-CLTV in the refund path, no headers needed)
  private prevHashInternal: Uint8Array;
  private readonly utxos: ChainUtxo[] = [];
  readonly rawTxByTxid: Record<string, string> = {};
  private readonly historyRows: HistItem[] = [];
  private readonly merkleProofByTxid: Record<string, { block_height: number; merkle: string[]; pos: number }> = {};
  readonly broadcasts: string[] = [];
  private seedSeq = 0;

  constructor(chain: Chain, anchorHeight: number, initialCount: number, spacing = 120, bits = 0x20010000) {
    this.chain = chain; this.anchorHeight = anchorHeight; this.spacing = spacing; this.bits = bits;
    const nowSec = Math.floor(Date.now() / 1000);
    this.anchorParentTime = nowSec - spacing * (initialCount + 1); // -> tip time ~= now (fresh)
    this.params = { anchorHeight, anchorBits: bits, anchorParentTime: this.anchorParentTime, spacing: BigInt(spacing), powLimit: this.powLimit, halfLife: () => 172800n };
    const cpHashInternal = hash256(new Uint8Array([0xc9, ...new Array(31).fill(0)]));
    this.checkpoint = { height: anchorHeight, hashDisplay: toHexRev(cpHashInternal), time: this.T(anchorHeight) };
    this.prevHashInternal = cpHashInternal;
    this.tip = anchorHeight;
    for (let i = 0; i < initialCount; i++) this.mineBlock(hash256(new Uint8Array([i + 1, 0x5a])));
    this.reportedTip = this.tip;
  }

  private T(height: number): number { return this.anchorParentTime + this.spacing * (height - this.anchorHeight + 1); }

  /** Mine ONE PoW block at tip+1 with the given internal merkle root (easy bits => a few hundred nonce tries). */
  private mineBlock(merkleRootInternal: Uint8Array): number {
    const height = this.tip + 1;
    const raw = new Uint8Array(80);
    const dv = new DataView(raw.buffer);
    dv.setUint32(0, 0x20000000 >>> 0, true);
    raw.set(this.prevHashInternal, 4);
    raw.set(merkleRootInternal, 36);
    dv.setUint32(68, this.T(height) >>> 0, true);
    dv.setUint32(72, this.bits >>> 0, true);
    let mined = false;
    for (let nonce = 0; nonce < 0xffffffff; nonce++) {
      dv.setUint32(76, nonce >>> 0, true);
      if (checkPoW(raw, this.bits, this.powLimit)) { mined = true; break; }
    }
    if (!mined) throw new Error(`SharedChain(${this.chain}): could not mine header at ${height}`);
    this.headersByHeight[height] = bytesToHex(raw);
    this.prevHashInternal = blockHashInternal(raw);
    this.tip = height;
    this.reportedTip = height;
    return height;
  }

  /** Mine N empty blocks (bury a funding tx to the required confirmation depth). */
  mineEmptyBlocks(n: number): void {
    for (let i = 0; i < n; i++) this.mineBlock(hash256(new Uint8Array([this.tip & 0xff, (this.tip >> 8) & 0xff, 0xee])));
  }

  /** Advertise a higher height WITHOUT mining real headers — models "past the CLTV" for the refund availability
   *  check (getBlockHeight). confirmRefund's SPV finalizer then fails-closed (no headers) and KEEPS material. */
  setReportedTip(h: number): void { this.reportedTip = h; }

  /** Seed a confirmed P2PKH funding source for `pkh`, with a self-authenticating parent tx (needed by the btc/bc2
   *  legacy input-value authentication path). Returns nothing — the funder selects it via getUTXOs. */
  seedP2pkh(pkh: Uint8Array, value: number): void {
    const spkHex = p2pkhSpkHex(pkh);
    const parent = buildUtxoRawTx([{ value: value + 1000, scriptPubKeyHex: spkHex }, { value, scriptPubKeyHex: spkHex }]);
    // Use vout 1 so the (unused) vout-0 differs; both pay `pkh`. The chosen UTXO self-authenticates via its raw tx.
    this.rawTxByTxid[parent.txid] = parent.rawTxHex;
    const h = this.anchorHeight - 5 - (this.seedSeq++); // an old confirmed height (only matters for FIFO ordering)
    this.utxos.push({ tx_hash: parent.txid, tx_pos: 1, value, height: h, spkHex });
    this.historyRows.push({ scripthash: scripthashOf(spkHex), tx_hash: parent.txid, height: h });
  }

  // ── the read/write surface the clients delegate to ──────────────────────────────────────────────────────────
  getUtxos(scripthash: string): Array<{ tx_hash: string; tx_pos: number; value: number; height: number }> {
    return this.utxos
      .filter((u) => scripthashOf(u.spkHex) === scripthash)
      .map((u) => ({ tx_hash: u.tx_hash, tx_pos: u.tx_pos, value: u.value, height: u.height }));
  }
  getHistory(scripthash: string): Array<{ tx_hash: string; height: number }> {
    return this.historyRows.filter((r) => r.scripthash === scripthash).map((r) => ({ tx_hash: r.tx_hash, height: r.height }));
  }
  getTx(txid: string): string {
    const raw = this.rawTxByTxid[txid.toLowerCase()] ?? this.rawTxByTxid[txid];
    if (raw === undefined) throw new Error(`SharedChain(${this.chain}): no rawtx for ${txid}`);
    return raw;
  }
  getMerkleProof(txid: string): { block_height: number; merkle: string[]; pos: number } {
    const p = this.merkleProofByTxid[txid.toLowerCase()] ?? this.merkleProofByTxid[txid];
    if (!p) throw new Error(`SharedChain(${this.chain}): no merkle proof for ${txid}`);
    return p;
  }
  getBlockHeaders(start: number, count: number): { count: number; hex: string; max: number } {
    let hex = ''; let n = 0;
    for (let h = start; h < start + count && this.headersByHeight[h]; h++) { hex += this.headersByHeight[h]; n++; }
    return { count: n, hex, max: 500 };
  }
  tipHeaderHex(): string { return this.headersByHeight[this.tip]; }

  /** Broadcast: mine the tx into its own single-tx block (merkleRoot = hash256(rawTx)), update the UTXO set +
   *  history, register the raw tx + an empty-branch Merkle proof. Both parties see the result. */
  broadcast(rawHex: string): string {
    const p = parseLegacyTx(rawHex);
    const H = this.mineBlock(hash256(hexToBytes(rawHex)));
    // Spend inputs (record a spend-history row at each spent output's scripthash, then remove it).
    for (const inp of p.inputs) {
      const idx = this.utxos.findIndex((u) => u.tx_hash === inp.tx_hash && u.tx_pos === inp.tx_pos);
      if (idx >= 0) {
        this.historyRows.push({ scripthash: scripthashOf(this.utxos[idx].spkHex), tx_hash: p.txid, height: H });
        this.utxos.splice(idx, 1);
      }
    }
    // Create outputs.
    for (let i = 0; i < p.outputs.length; i++) {
      const out = p.outputs[i];
      this.utxos.push({ tx_hash: p.txid, tx_pos: i, value: out.value, height: H, spkHex: out.spkHex });
      this.historyRows.push({ scripthash: scripthashOf(out.spkHex), tx_hash: p.txid, height: H });
    }
    this.rawTxByTxid[p.txid] = rawHex;
    this.merkleProofByTxid[p.txid] = { block_height: H, merkle: [], pos: 0 };
    this.broadcasts.push(rawHex);
    return p.txid;
  }
}

/** Both parties talk to the SAME SharedChain through this client (a superset of SwapChainClient). */
class SharedChainClient {
  constructor(private readonly c: SharedChain) {}
  async getUTXOs(scripthash: string): Promise<Array<{ tx_hash: string; tx_pos: number; value: number; height: number }>> { return this.c.getUtxos(scripthash); }
  async getBalance(): Promise<{ confirmed: number; unconfirmed: number }> { return { confirmed: 0, unconfirmed: 0 }; }
  async getTx(txid: string): Promise<string> { return this.c.getTx(txid); }
  async broadcastTx(rawTx: string): Promise<string> { return this.c.broadcast(rawTx); }
  async get_history(scripthash: string): Promise<Array<{ tx_hash: string; height: number }>> { return this.c.getHistory(scripthash); }
  async getHistory(scripthash: string): Promise<Array<{ tx_hash: string; height: number }>> { return this.c.getHistory(scripthash); }
  async getBlockHeaders(start: number, count: number): Promise<{ count: number; hex: string; max: number }> { return this.c.getBlockHeaders(start, count); }
  async getMerkleProof(txid: string): Promise<{ block_height: number; merkle: string[]; pos: number }> { return this.c.getMerkleProof(txid); }
  async request<T = unknown>(method: string): Promise<T> {
    if (method === 'blockchain.headers.subscribe') return { height: this.c.reportedTip, hex: this.c.tipHeaderHex() } as T;
    throw new Error(`SharedChainClient: unexpected request ${method}`);
  }
  async getBlockHeight(): Promise<[number, () => void]> { return [this.c.reportedTip, () => {}]; }
  async subscribeAddress(): Promise<() => void> { return () => {}; }
}

// ============================================================================
// SharedEvmChain (scenario 4) — ONE object modelling the EVM HTLC contract state: a swapId -> struct map + an
// event log. The responder's lock WRITES a struct + Locked event; the initiator's claim flips claimed + writes a
// Claimed(swapId, S) event; the initiator's read provider READS the struct; the responder's watch READS the log.
// The secret S flows ONLY through the claim calldata -> Claimed event -> responder (never injected).
// ============================================================================
interface EvmLogRow { address: string; topics: string[]; data: string; blockNumber: number; index: number; blockHash: string; transactionHash: string; transactionIndex: number; removed: boolean; }
class SharedEvmChain {
  readonly swaps = new Map<string, SwapStruct>();
  readonly logs: EvmLogRow[] = [];
  tip = 5000;
  nowSec = Math.floor(Date.now() / 1000);
  private idSeq = 0;
  private logSeq = 0;

  private mkLog(address: string, enc: { topics: ReadonlyArray<string>; data: string }): EvmLogRow {
    const n = ++this.logSeq;
    const row: EvmLogRow = {
      address, topics: [...enc.topics], data: enc.data, blockNumber: this.tip, index: n,
      blockHash: '0x' + 'cc'.repeat(32), transactionHash: '0x' + n.toString(16).padStart(64, '0'),
      transactionIndex: 0, removed: false,
    };
    this.logs.push(row); // append to the shared on-chain log so watchForClaimEvm's getLogs scan SEES it
    return row;
  }
  lock(htlcAddr: string, initiator: string, recipient: string, token: string, amount: bigint, hashLock: string, timeLock: bigint): { swapId: string; log: EvmLogRow } {
    const swapId = ethers.keccak256(ethers.toBeHex(BigInt(++this.idSeq), 32));
    this.swaps.set(swapId.toLowerCase(), { initiator, recipient, token, amount, hashLock, timeLock, claimed: false, refunded: false });
    const enc = htlcInterface.encodeEventLog('Locked', [swapId, initiator, recipient, token, amount, hashLock, timeLock]);
    return { swapId, log: this.mkLog(htlcAddr, enc) };
  }
  claim(htlcAddr: string, swapId: string, secretHex: string): { log: EvmLogRow } {
    const s = this.swaps.get(swapId.toLowerCase()); if (s) s.claimed = true;
    const enc = htlcInterface.encodeEventLog('Claimed', [swapId, secretHex]);
    return { log: this.mkLog(htlcAddr, enc) };
  }
  refund(htlcAddr: string, swapId: string): { log: EvmLogRow } {
    const s = this.swaps.get(swapId.toLowerCase()); if (s) s.refunded = true;
    const enc = htlcInterface.encodeEventLog('Refunded', [swapId]);
    return { log: this.mkLog(htlcAddr, enc) };
  }
  getSwap(swapId: string): SwapStruct | null { return this.swaps.get(swapId.toLowerCase()) ?? null; }
  queryLogs(filter: { address?: string; topics?: Array<string | null>; fromBlock?: number | string; toBlock?: number | string }): EvmLogRow[] {
    const from = Number(filter.fromBlock ?? 0);
    const to = filter.toBlock === 'latest' || filter.toBlock === undefined ? this.tip : Number(filter.toBlock);
    const addr = filter.address?.toLowerCase();
    const topics = filter.topics ?? [];
    return this.logs.filter((l) =>
      (!addr || l.address.toLowerCase() === addr) &&
      l.blockNumber >= from && l.blockNumber <= to &&
      topics.every((t, i) => t == null || (l.topics[i] !== undefined && l.topics[i].toLowerCase() === String(t).toLowerCase())),
    );
  }
}

/** Read provider over a SharedEvmChain. `quorum` exposes >=2 leaves (the EVM gates refuse a single-leaf provider). */
class SharedEvmProvider extends MockEvmProvider {
  constructor(private readonly evm: SharedEvmChain, private readonly cfg: { chainId: bigint; quorum?: boolean }) { super({}); }
  get __leafProviders(): MockEvmProvider[] | undefined {
    if (!this.cfg.quorum) return undefined;
    return [new SharedEvmProvider(this.evm, { chainId: this.cfg.chainId }), new SharedEvmProvider(this.evm, { chainId: this.cfg.chainId })];
  }
  async getBlockNumber(): Promise<number> { return this.evm.tip; }
  async getBlock(): Promise<{ timestamp: number; number: number }> { return { timestamp: this.evm.nowSec, number: this.evm.tip }; }
  async getNetwork(): Promise<{ chainId: bigint }> { return { chainId: this.cfg.chainId }; }
  async getCode(): Promise<string> { return '0x60006000'; }
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  async call(tx: any): Promise<string> {
    const data: string | undefined = tx?.data;
    if (typeof data === 'string' && data.toLowerCase().startsWith(GET_SWAP_SELECTOR.toLowerCase())) {
      const [id] = htlcInterface.decodeFunctionData('getSwap', data) as unknown as [string];
      const s = this.evm.getSwap(id);
      return encodeSwap(s ?? ZERO_SWAP);
    }
    return ZERO_BYTES32;
  }
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  async getLogs(filter: any): Promise<unknown[]> { return this.evm.queryLogs(filter); }
}

/** Signer over a SharedEvmChain: decodes the lock/claim/refund calldata, mutates the shared state, stages a
 *  receipt whose logs carry the corresponding on-chain event (so lockETH extracts the real swapId + claimSwap's
 *  Claimed event carries the REAL secret the initiator passed). */
class SharedEvmSigner {
  readonly provider: SharedEvmProvider;
  readonly address: string;
  readonly sendTransaction: ReturnType<typeof vi.fn>;
  constructor(evm: SharedEvmChain, provider: SharedEvmProvider, address: string) {
    this.provider = provider; this.address = address;
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    this.sendTransaction = vi.fn(async (tx: any) => {
      const desc = htlcInterface.parseTransaction({ data: tx.data, value: tx.value ?? 0n });
      if (!desc) throw new Error('SharedEvmSigner: undecodable calldata');
      const hash = '0x' + (this.provider === provider ? (++localHashSeq).toString(16) : '0').padStart(64, '0');
      let logs: EvmLogRow[] = [];
      if (desc.name === 'lock') {
        const [recipient, token, amount, hashLock, timeLock] = desc.args as unknown as [string, string, bigint, string, bigint];
        logs = [evm.lock(tx.to, this.address, recipient, token, amount, hashLock, timeLock).log];
      } else if (desc.name === 'claim') {
        const [id, secretHex] = desc.args as unknown as [string, string];
        logs = [evm.claim(tx.to, id, secretHex).log];
      } else if (desc.name === 'refund') {
        const [id] = desc.args as unknown as [string];
        logs = [evm.refund(tx.to, id).log];
      }
      const bn = evm.tip;
      this.provider.opts.receipt = {
        status: 1, logs, hash, blockNumber: bn, index: 0, to: tx.to ?? null, from: this.address,
        contractAddress: null, blockHash: '0x' + 'bc'.repeat(32), logsBloom: '0x' + '00'.repeat(256),
        gasUsed: 21_000n, cumulativeGasUsed: 21_000n, blobGasUsed: null, gasPrice: 0n, blobGasPrice: null, type: 2, root: null,
      };
      return {
        hash, blockNumber: null, blockHash: null, index: 0, type: 2, from: this.address, to: tx.to ?? null,
        gasLimit: 300_000n, nonce: 0, data: tx.data ?? '0x', value: tx.value ?? 0n, gasPrice: 0n,
        maxPriorityFeePerGas: null, maxFeePerGas: null, maxFeePerBlobGas: null, chainId: this.cfgChainId(), signature: null, accessList: null,
      };
    });
  }
  private cfgChainId(): bigint { return (this.provider as unknown as { cfg: { chainId: bigint } }).cfg.chainId; }
  async getAddress(): Promise<string> { return this.address; }
  get broadcastCount(): number { return this.sendTransaction.mock.calls.length; }
}
let localHashSeq = 0;

// ============================================================================
// Offer + record + deps builders.
// ============================================================================
function makeOffer(over: Partial<SwapOffer> = {}): SwapOffer {
  return {
    id: 'e2e-offer',
    sendChain: 'bch2', receiveChain: 'btc',
    sendAmount: 100_000, receiveAmount: 100_000,
    secretHash: SECRET_HASH_HEX, secretScheme: 'hmac-v1', secretNonce: bytesToHex(NONCE),
    initiatorSendAddress: 'addr-init-send', initiatorReceiveAddress: 'addr-init-recv',
    status: 'taken', createdAt: 1_700_000_000, expiresAt: 1_800_000_000,
    ...over,
  };
}

interface DepsOpts {
  clients: Partial<Record<Chain, SharedChainClient>>;
  seedVault: SeedVault;
  durable: DurableStore;
  evmProviderFor?: (c: Chain) => Provider;
  evmSignerFor?: (c: Chain) => Signer;
}
function buildDeps(o: DepsOpts): SwapControllerDeps {
  const mutex = new InProcessMutex({ store: o.durable, settle: () => Promise.resolve() });
  return {
    chainClientFor: (chain: Chain) => {
      const c = o.clients[chain];
      if (!c) throw new Error(`e2e: no UTXO client wired for chain ${chain}`);
      return c as unknown as SwapChainClient;
    },
    seedVault: o.seedVault,
    durable: o.durable,
    session: new InMemorySessionStore(),
    mutex,
    reservation: new UtxoReservationRegistry(),
    clock: () => Date.now(),
    evmProviderFor: o.evmProviderFor,
    evmSignerFor: o.evmSignerFor,
  };
}

/** Observe a counterparty leg on the shared chain: the exact funding outpoint the funder created (on-chain fact). */
function observeOutpoint(chain: SharedChain, htlc: DurableHTLC): { tx_hash: string; tx_pos: number } {
  const sh = htlcScripthash(hexToBytes(htlc.redeemScript));
  const u = chain.getUtxos(sh);
  if (u.length !== 1) throw new Error(`observeOutpoint: expected 1 HTLC utxo, saw ${u.length}`);
  return { tx_hash: u[0].tx_hash, tx_pos: u[0].tx_pos };
}

const BASE_CHAIN_ID = 84532n;
const BASE_HTLC = getEvmConfig(84532)!.htlcAddress;
const EVM_AMT_STR = '1000000000000000000'; // 1e18 base units (an 18-dec value; never Number()'d)

// ============================================================================
// SCENARIO 1 — HAPPY UTXO<->UTXO. sendChain=bch2 (initiator leg X, reqConf 6), receiveChain=btc (responder leg Y,
// reqConf 2). initiator funds X + reveals; responder verifies X, funds Y (re-minting against the on-chain leg X),
// watches its own leg Y for the initiator's claim, EXTRACTS S, and claims leg X with it.
// ============================================================================
describe('e2e — HAPPY UTXO<->UTXO (two controllers, one shared chain per network)', () => {
  let bch2: SharedChain; let btc: SharedChain; let bch2Cli: SharedChainClient; let btcCli: SharedChainClient;
  beforeEach(() => {
    bch2 = new SharedChain('bch2', 100_000, 3);
    btc = new SharedChain('btc', 200_000, 3);
    bch2.seedP2pkh(PKH_I, 1_000_000); // initiator funds leg X on bch2 from its own P2PKH
    btc.seedP2pkh(PKH_R, 1_000_000);  // responder funds leg Y on btc from its own P2PKH
    bch2Cli = new SharedChainClient(bch2);
    btcCli = new SharedChainClient(btc);
    __setSpvConfigForTests('bch2', bch2.params, bch2.checkpoint);
    __setSpvConfigForTests('btc', btc.params, btc.checkpoint);
    __resetSpvCacheForTests();
  });

  it('completes: X funded+buried, Y funded against on-chain X, S revealed by the initiator claim + EXTRACTED by the responder, both legs spent', async () => {
    const offer = makeOffer({ sendChain: 'bch2', receiveChain: 'btc' });

    // ── INITIATOR: prepare + fund leg X on bch2 ──
    const initDurable = new InMemoryDurableStore();
    const initVault = new PartySeedVault(KSS, PRIV_I, PUB_I);
    const initDeps = buildDeps({ clients: { bch2: bch2Cli, btc: btcCli }, seedVault: initVault, durable: initDurable });
    const initFund = new SwapController(
      { id: offer.id, role: 'initiator', offer, phase: 'taken', counterpartyClaimPkh: bytesToHex(PKH_R) },
      initDeps,
    );
    await initFund.prepare();
    const { txid: legXTxid } = await initFund.fundLegX();
    bch2.mineEmptyBlocks(5); // bury leg X to depth 6 (bch2 reqConf) so the responder's fund gate can verify it
    const legXHtlc = initFund.getState().myHTLC!;
    const legXOutpoint = observeOutpoint(bch2, legXHtlc); // the responder OBSERVES the funding outpoint on-chain
    expect(legXOutpoint.tx_hash).toBe(legXTxid);

    // ── RESPONDER: verify the on-chain leg X, fund leg Y on btc (re-minting against leg X at the choke point) ──
    const respDurable = new InMemoryDurableStore();
    const respVault = new PartySeedVault(null, PRIV_R, PUB_R); // NO K_ss — the responder cannot derive S
    const respDeps = buildDeps({ clients: { bch2: bch2Cli, btc: btcCli }, seedVault: respVault, durable: respDurable });
    const responder = new SwapController(
      {
        id: offer.id, role: 'responder', offer, phase: 'taken',
        counterpartyClaimPkh: bytesToHex(PKH_I), // the initiator claims leg Y
        counterpartyHTLC: legXHtlc,              // the maker's published leg-X HTLC (public)
        counterpartyFundingOutpoint: legXOutpoint,
      },
      respDeps,
    );
    const fundProof = await responder.verifyCounterpartyLegForFunding();
    const { txid: legYTxid } = await responder.fundLegY(fundProof);
    btc.mineEmptyBlocks(1); // bury leg Y to depth 2 (btc reqConf) so the initiator's reveal gate can verify it
    const legYHtlc = responder.getState().myHTLC!;
    const legYOutpoint = observeOutpoint(btc, legYHtlc);
    expect(legYOutpoint.tx_hash).toBe(legYTxid);

    // ASSERT the funded leg X the responder verified == the leg X the initiator funded (params/hashLock/outpoint).
    expect(responder.getState().phase).toBe('responder_funded');
    // GENUINE cross-party binding (not a self-compare): the FundProof the responder minted is bound to the
    // initiator's ACTUAL on-chain leg-X outpoint. The gate re-verified counterpartyHTLC.redeemScript against the
    // funding AT that outpoint (reverifyBuriedOutpoint does getUTXOs on the redeemScript's P2SH scripthash and
    // requires the exact recorded outpoint) — a redeemScript that did NOT match the on-chain funding would have had
    // no funded UTXO under its scripthash and the gate would have thrown, minting nothing.
    expect(fundProof.outpoint).toEqual(legXOutpoint);
    expect(legXHtlc.secretHash).toBe(SECRET_HASH_HEX);

    // ── INITIATOR: rehydrate with the OBSERVED counterparty leg Y + reveal (claim leg Y, revealing S on-chain) ──
    const initReveal = new SwapController(
      {
        id: offer.id, role: 'initiator', offer, phase: 'responder_funded',
        counterpartyClaimPkh: bytesToHex(PKH_R),
        myHTLC: legXHtlc, myFundingTxid: legXTxid, fundLocktime: legXHtlc.locktime, funded: true,
        counterpartyHTLC: legYHtlc,                 // the responder's published leg-Y HTLC (public)
        counterpartyFundingOutpoint: legYOutpoint,  // observed on-chain
      },
      buildDeps({ clients: { bch2: bch2Cli, btc: btcCli }, seedVault: new PartySeedVault(KSS, PRIV_I, PUB_I), durable: initDurable }),
    );
    const revealAuth = await initReveal.verifyCounterpartyLegForReveal();
    expect(revealAuth.role).toBe('initiator');
    expect(revealAuth.outpoint).toEqual(legYOutpoint);
    const { txid: initClaimTxid } = await initReveal.revealAndClaim(revealAuth);
    expect(initReveal.getState().phase).toBe('claimed');
    expect(btc.broadcasts.length).toBeGreaterThan(0);

    // The initiator's on-chain claim of leg Y carries S in its scriptSig (independent proof of the on-chain reveal).
    const onChainClaimRaw = btc.rawTxByTxid[initClaimTxid];
    expect(bytesToHex(extractSecret(onChainClaimRaw, SECRET_HASH_BYTES)!)).toBe(bytesToHex(S));

    // ── RESPONDER: watch its OWN leg Y, EXTRACT S from the initiator's on-chain claim, then claim leg X with it ──
    expect(responder.getState().hasSecret).toBe(false); // never had S before observing the claim
    const { secret } = await responder.watchForSecret();
    expect(secret).not.toBeNull();
    expect(bytesToHex(secret!)).toBe(bytesToHex(S));    // S EXTRACTED on-chain == the secret prepare() derived
    expect(responder.getState().hasSecret).toBe(true);
    expect(responder.getState().phase).toBe('claimed');

    const { txid: respClaimTxid } = await responder.claimWithKnownSecret();
    expect(responder.getState().phase).toBe('completed');
    expect(respClaimTxid).toBeTruthy();

    // ── ASSERT both legs end spent by the correct party ──
    expect(bch2.getUtxos(htlcScripthash(hexToBytes(legXHtlc.redeemScript)))).toHaveLength(0); // leg X claimed by responder
    expect(btc.getUtxos(htlcScripthash(hexToBytes(legYHtlc.redeemScript)))).toHaveLength(0);  // leg Y claimed by initiator
    // The responder's claim of leg X spent exactly the outpoint the initiator funded.
    const respClaim = parseLegacyTx(bch2.rawTxByTxid[respClaimTxid]);
    expect(respClaim.inputs).toContainEqual({ tx_hash: legXTxid, tx_pos: legXOutpoint.tx_pos });
  });
});

// ============================================================================
// SCENARIO 2 — REFUND. initiator funds leg X; the responder NEVER funds leg Y -> advance past leg X's CLTV ->
// initiator.refund() recovers X (persist-before-broadcast, reachable).
// ============================================================================
describe('e2e — REFUND (initiator recovers leg X after its CLTV; responder never funded)', () => {
  let bch2: SharedChain; let bch2Cli: SharedChainClient;
  beforeEach(() => {
    bch2 = new SharedChain('bch2', 100_000, 3);
    bch2.seedP2pkh(PKH_I, 1_000_000);
    bch2Cli = new SharedChainClient(bch2);
    __setSpvConfigForTests('bch2', bch2.params, bch2.checkpoint);
    __resetSpvCacheForTests();
  });

  it('funds X, then after leg X CLTV refunds X back to the initiator (durable-before-broadcast)', async () => {
    const offer = makeOffer({ sendChain: 'bch2', receiveChain: 'btc' });
    const durable = new InMemoryDurableStore();
    const deps = buildDeps({ clients: { bch2: bch2Cli }, seedVault: new PartySeedVault(KSS, PRIV_I, PUB_I), durable });
    const ctrl = new SwapController(
      { id: offer.id, role: 'initiator', offer, phase: 'taken', counterpartyClaimPkh: bytesToHex(PKH_R) },
      deps,
    );
    await ctrl.prepare();
    const { txid: legXTxid } = await ctrl.fundLegX();
    const legX = ctrl.getState().myHTLC!;
    expect(ctrl.canRefund(legX.locktime - 1)).toBe(false); // not yet at the timelock

    // Advance the advertised height past leg X's CLTV (buildHeight + 216). The refund availability check is a plain
    // height compare; confirmRefund's SPV finalizer then fails-closed (no real headers up there) and KEEPS material.
    bch2.setReportedTip(legX.locktime + 2);
    expect(ctrl.canRefund(bch2.reportedTip)).toBe(true);

    const { txid: refundTxid } = await ctrl.refund();
    expect(ctrl.getState().phase).toBe('refunded');
    // Persist-before-broadcast: the durable refund tx + sentinel landed before the irreversible broadcast.
    const refundRec = JSON.parse((await durable.get(`bch2swap:refundtx:${offer.id}`))!);
    expect(await durable.get(`bch2swap:refundbroadcast:${offer.id}`)).toBe('1');
    expect(refundRec.spent).toEqual({ tx_hash: legXTxid, tx_pos: 0 }); // the refund spends leg X's outpoint

    // The refund spent leg X back to the initiator's own key (refund pkh = hash160(PUB_I)); leg X is now gone.
    expect(bch2.getUtxos(htlcScripthash(hexToBytes(legX.redeemScript)))).toHaveLength(0);
    const refundTx = parseLegacyTx(bch2.rawTxByTxid[refundTxid]);
    expect(refundTx.inputs).toContainEqual({ tx_hash: legXTxid, tx_pos: 0 });
    expect(refundTx.outputs[0].spkHex).toBe(p2pkhSpkHex(PKH_I)); // swept back to the initiator
  });
});

// ============================================================================
// SCENARIO 3 — RESUME. initiator funds X; a FRESH SwapController.resume(durableRecord, deps) rehydrates from the
// SAME durable store + shared chain, re-enters the correct gate, and can still refund (reachable). No material lost.
// ============================================================================
describe('e2e — RESUME (fresh controller rehydrates from the durable record + shared chain)', () => {
  let bch2: SharedChain; let bch2Cli: SharedChainClient;
  beforeEach(() => {
    bch2 = new SharedChain('bch2', 100_000, 3);
    bch2.seedP2pkh(PKH_I, 1_000_000);
    bch2Cli = new SharedChainClient(bch2);
    __setSpvConfigForTests('bch2', bch2.params, bch2.checkpoint);
    __resetSpvCacheForTests();
  });

  it('rehydrates (auth ok, S re-derived, post-funding gate), loses no recovery material, and can refund', async () => {
    const offer = makeOffer({ sendChain: 'bch2', receiveChain: 'btc' });
    const durable = new InMemoryDurableStore();

    // Session A: fund leg X, then discard the controller (simulate a crash / new device).
    const ctrlA = new SwapController(
      { id: offer.id, role: 'initiator', offer, phase: 'taken', counterpartyClaimPkh: bytesToHex(PKH_R) },
      buildDeps({ clients: { bch2: bch2Cli }, seedVault: new PartySeedVault(KSS, PRIV_I, PUB_I), durable }),
    );
    await ctrlA.prepare();
    await ctrlA.fundLegX();
    const fundedHtlc = ctrlA.getState().myHTLC!;
    const fundedTxid = ctrlA.getState().myFundingTxid!;

    // Session B: rehydrate from the SAME durable record + the SAME shared chain via resume().
    const durableRecord: DurableSwapRecord = JSON.parse((await durable.get(`bch2swap:record:${offer.id}`))!);
    const ctrlB = await SwapController.resume(
      durableRecord,
      buildDeps({ clients: { bch2: bch2Cli }, seedVault: new PartySeedVault(KSS, PRIV_I, PUB_I), durable }),
    );

    // Rehydrated correctly, no recovery material lost.
    const snap = ctrlB.getState();
    expect(snap.resumeAuth).toBe('ok');           // myHTLC authenticated against the LIVE on-chain funding output
    expect(snap.resumeGate).toBe('post-funding'); // re-entered the correct gate from CHAIN truth
    expect(snap.hasSecret).toBe(true);            // S re-derived from the seed (never lost)
    expect(snap.myHTLC?.redeemScript).toBe(fundedHtlc.redeemScript);
    expect(snap.myFundingTxid).toBe(fundedTxid);
    expect(bch2.broadcasts.length).toBe(1);       // funding already on-chain -> no blind rebroadcast

    // The rehydrated controller can still complete OR refund: drive the refund to prove reachability.
    bch2.setReportedTip(fundedHtlc.locktime + 2);
    const { txid: refundTxid } = await ctrlB.refund();
    expect(ctrlB.getState().phase).toBe('refunded');
    expect(bch2.getUtxos(htlcScripthash(hexToBytes(fundedHtlc.redeemScript)))).toHaveLength(0);
    const refundTx = parseLegacyTx(bch2.rawTxByTxid[refundTxid]);
    expect(refundTx.inputs).toContainEqual({ tx_hash: fundedTxid, tx_pos: 0 });
  });
});

// ============================================================================
// SCENARIO 4 — HAPPY UTXO<->EVM. sendChain=btc (initiator leg X, UTXO), receiveChain=base (responder leg Y, EVM,
// quorum>=2). initiator funds X (UTXO) + reveals by claiming the EVM leg (revealAndClaimEvm, revealing S in the
// Claimed event); responder locks the EVM leg, watches its OWN lock (watchForClaimEvm) to LEARN S, then claims the
// UTXO leg X with the now-public S.
// ============================================================================
describe('e2e — HAPPY UTXO<->EVM (cross-chain secret flow through the on-chain Claimed event)', () => {
  let btc: SharedChain; let btcCli: SharedChainClient; let evm: SharedEvmChain;
  beforeEach(() => {
    btc = new SharedChain('btc', 200_000, 3);
    btc.seedP2pkh(PKH_I, 1_000_000); // initiator funds leg X on btc
    btcCli = new SharedChainClient(btc);
    evm = new SharedEvmChain();
    __setSpvConfigForTests('btc', btc.params, btc.checkpoint);
    __resetSpvCacheForTests();
  });

  it('completes: initiator funds X, responder locks EVM Y, initiator claims Y revealing S, responder EXTRACTS S from the Claimed event + claims X', async () => {
    const offer = makeOffer({ sendChain: 'btc', receiveChain: 'base', sendAmount: 100_000, receiveAmount: EVM_AMT_STR });

    // ── INITIATOR: prepare + fund leg X on btc ──
    const initDurable = new InMemoryDurableStore();
    const initFund = new SwapController(
      { id: offer.id, role: 'initiator', offer, phase: 'taken', counterpartyClaimPkh: bytesToHex(PKH_R) },
      buildDeps({ clients: { btc: btcCli }, seedVault: new PartySeedVault(KSS, PRIV_I, PUB_I), durable: initDurable }),
    );
    await initFund.prepare();
    const { txid: legXTxid } = await initFund.fundLegX();
    btc.mineEmptyBlocks(1); // bury leg X to depth 2 (btc reqConf) so the responder's fund gate can verify it
    const legXHtlc = initFund.getState().myHTLC!;
    const legXOutpoint = observeOutpoint(btc, legXHtlc);

    // ── RESPONDER: verify the on-chain leg X, LOCK the EVM leg Y (quorum>=2 read provider + node signer) ──
    const respDurable = new InMemoryDurableStore();
    const respEvmProvider = new SharedEvmProvider(evm, { chainId: BASE_CHAIN_ID, quorum: true });
    const respEvmSigner = new SharedEvmSigner(evm, new SharedEvmProvider(evm, { chainId: BASE_CHAIN_ID }), RESP_EVM);
    const responder = new SwapController(
      {
        id: offer.id, role: 'responder', offer, phase: 'taken',
        counterpartyClaimPkh: bytesToHex(PKH_I),
        counterpartyHTLC: legXHtlc, counterpartyFundingOutpoint: legXOutpoint,
        myEvmAddress: RESP_EVM, counterpartyEvmAddress: INIT_EVM,
        myEvmToken: ZERO_ADDRESS, counterpartyEvmToken: ZERO_ADDRESS,
      },
      buildDeps({
        clients: { btc: btcCli }, seedVault: new PartySeedVault(null, PRIV_R, PUB_R), durable: respDurable,
        evmProviderFor: () => respEvmProvider as unknown as Provider,
        evmSignerFor: () => respEvmSigner as unknown as Signer,
      }),
    );
    const fundProof = await responder.verifyCounterpartyLegForFunding();
    const { swapId } = await responder.lockEvm(fundProof);
    expect(responder.getState().phase).toBe('responder_funded');
    // R-EVMLOCKBLOCK-001: lockEvm captured the lock block as the scan floor (was never written before → the
    // counterparty-secret scan fell back to the tip-anchored [tip-90000, tip] window that misses an early claim).
    expect(responder.getState().evmLockBlock).toBeGreaterThan(0);
    expect(respEvmSigner.broadcastCount).toBe(1);
    expect(evm.getSwap(swapId)?.claimed).toBe(false);

    // ── INITIATOR: rehydrate with the OBSERVED EVM lock swapId + reveal (claim the EVM leg, revealing S) ──
    const initEvmProvider = new SharedEvmProvider(evm, { chainId: BASE_CHAIN_ID, quorum: true });
    const initEvmSigner = new SharedEvmSigner(evm, new SharedEvmProvider(evm, { chainId: BASE_CHAIN_ID }), INIT_EVM);
    const initReveal = new SwapController(
      {
        id: offer.id, role: 'initiator', offer, phase: 'responder_funded',
        counterpartyClaimPkh: bytesToHex(PKH_R),
        myHTLC: legXHtlc, myFundingTxid: legXTxid, fundLocktime: legXHtlc.locktime, funded: true,
        counterpartyEvmSwapId: swapId,             // observed on-chain (the responder's lock swapId)
        myEvmAddress: INIT_EVM, counterpartyEvmAddress: RESP_EVM,
        myEvmToken: ZERO_ADDRESS, counterpartyEvmToken: ZERO_ADDRESS,
      },
      buildDeps({
        clients: { btc: btcCli }, seedVault: new PartySeedVault(KSS, PRIV_I, PUB_I), durable: initDurable,
        evmProviderFor: () => initEvmProvider as unknown as Provider,
        evmSignerFor: () => initEvmSigner as unknown as Signer,
      }),
    );
    const revealAuth = await initReveal.verifyEvmCounterpartyLegForReveal();
    expect(revealAuth.role).toBe('initiator');
    expect(revealAuth.swapId).toBe(swapId);
    await initReveal.revealAndClaimEvm(revealAuth);
    expect(initReveal.getState().phase).toBe('claimed');
    expect(evm.getSwap(swapId)?.claimed).toBe(true); // the EVM leg Y settled (claimed with S)

    // ── RESPONDER: watch its OWN EVM lock, EXTRACT S from the on-chain Claimed event, then claim leg X ──
    expect(responder.getState().hasSecret).toBe(false); // never had S before observing the Claimed event
    const { secret } = await responder.watchForClaimEvm();
    expect(secret).not.toBeNull();
    expect(bytesToHex(secret!)).toBe(bytesToHex(S));    // S EXTRACTED from the Claimed event == the derived secret
    expect(responder.getState().hasSecret).toBe(true);
    expect(responder.getState().phase).toBe('claimed');

    const { txid: respClaimTxid } = await responder.claimWithKnownSecret();
    expect(responder.getState().phase).toBe('completed');

    // ── ASSERT both legs settled ──
    expect(evm.getSwap(swapId)?.claimed).toBe(true);                                        // EVM leg Y claimed
    expect(btc.getUtxos(htlcScripthash(hexToBytes(legXHtlc.redeemScript)))).toHaveLength(0); // UTXO leg X claimed
    const respClaim = parseLegacyTx(btc.rawTxByTxid[respClaimTxid]);
    expect(respClaim.inputs).toContainEqual({ tx_hash: legXTxid, tx_pos: legXOutpoint.tx_pos });
  });
});
