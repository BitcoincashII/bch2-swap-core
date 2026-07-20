/**
 * TRIMMED fault-injection mock harness for the bch2-swap-core SDK test suite.
 *
 * This is a dependency-light subset of the frontend app's shared mock harness
 * (bch2-swap/src/test/mocks/index.ts). It re-implements ONLY the UTXO helpers that
 * the proven htlc-builder + swap-flow test suites import:
 *   - MockElectrumClient   (caller-facing subset of ElectrumProxyClient with lying knobs)
 *   - buildUtxoRawTx       (build a valid non-witness tx + its true txid)
 *   - p2shScriptPubKeyHex  (OP_HASH160 <h160> OP_EQUAL)
 *
 * Every EVM/ethers/proxy-client dependency from the frontend harness has been stripped.
 * The only functional change from the verbatim source is that buildUtxoRawTx's txid
 * computation is repointed off `ethers` onto the SDK-available @noble/hashes sha256 +
 * htlc-builder hex helpers (identical math: txid = reverse(double-SHA256(rawTx))).
 */

import { sha256 } from '@noble/hashes/sha256';
import { hexToBytes, bytesToHex } from './htlc-builder';
import { ethers } from 'ethers';
import { vi } from 'vitest';
import { HTLC_ABI } from './evm-client';

// ============================================================================
// Electrum value types (verbatim from src/electrum/proxy-client.ts) — inlined here
// because the SDK does not ship the proxy-client. Type-only, no runtime dependency.
// ============================================================================

export interface ElectrumBalance {
  confirmed: number;
  unconfirmed: number;
}

export interface ElectrumUtxo {
  tx_hash: string;
  tx_pos: number;
  value: number;
  height: number;
}

// ============================================================================
// MockElectrumClient — caller-facing subset of ElectrumProxyClient with lying knobs
// ============================================================================

export interface HistoryEntry {
  tx_hash: string;
  height: number;
}

export interface MockElectrumOpts {
  /** listunspent result — fabricated UTXOs. */
  utxos?: ElectrumUtxo[];
  /** get_balance result. */
  balance?: ElectrumBalance;
  /** headers.subscribe current height — fabricated tip. */
  height?: number;
  /** Honest map: txid -> raw tx hex (whose double-sha256 DOES equal the txid). */
  rawTxByTxid?: Record<string, string>;
  /**
   * When set, getTx() returns THIS regardless of the requested txid — used to feed
   * verifyAndAuthenticateUtxo a rawtx whose double-sha256 does NOT equal the requested
   * txid, proving the txid-binding fail-closed (swap-flow.ts / htlc-builder.ts).
   */
  lyingRawTx?: string;
  /** get_history result — a LYING history (e.g. claims a spend/confirmations that never happened). */
  history?: HistoryEntry[];
  /** broadcastTx() ack txid. */
  broadcastTxid?: string;
  /** When true broadcastTx() throws (simulate proxy reject). */
  broadcastThrows?: boolean;
  /** When true getTx() throws (simulate unreachable proxy). */
  getTxThrows?: boolean;
  /**
   * R175-SPV: 80-byte block headers (160-hex each) keyed by height. getBlockHeaders() concatenates the
   * CONTIGUOUS run starting at `start` (verbatim from the app's spv-verifier.test.ts inline mockClient) —
   * a gap makes the batch short, which the SPV verifier treats as "proxy cannot supply headers" (fail-closed).
   */
  headersByHeight?: Record<number, string>;
  /** R175-SPV: fabricated Merkle proofs keyed by txid — a lying proxy's transaction.get_merkle answer. */
  merkleProofByTxid?: Record<string, { block_height: number; merkle: string[]; pos: number }>;
  /** R175-SPV: single Merkle proof returned for ANY txid (when merkleProofByTxid has no entry). */
  merkleProof?: { block_height: number; merkle: string[]; pos: number };
  /** getChainTimeSec: the tip header returned for a raw `blockchain.headers.subscribe` request. */
  tipHeaderHex?: string;
}

/**
 * Implements the caller-facing subset of src/electrum/proxy-client.ts used by the swap
 * engine: getUTXOs / getBalance / getTx / broadcastTx / get_history / getBlockHeight /
 * subscribeAddress. Every method is knob-driven so a test can simulate a malicious/MITM
 * proxy returning fabricated UTXOs, height, rawtx, or history.
 */
export class MockElectrumClient {
  opts: MockElectrumOpts;
  /** Every rawTx passed to broadcastTx() — assert `.length === 0` on fail-closed paths. */
  public readonly broadcasts: string[] = [];
  /** Registered header callbacks (fired by pushBlock). */
  private headerCbs: Array<(height: number) => void> = [];
  /** Registered address callbacks (fired by pushAddress). */
  private addressCbs: Array<(scripthash: string, status: string | null) => void> = [];

  constructor(opts: MockElectrumOpts = {}) {
    this.opts = opts;
  }

  setUtxos(u: ElectrumUtxo[]): this {
    this.opts.utxos = u;
    return this;
  }
  setHeight(h: number): this {
    this.opts.height = h;
    return this;
  }
  setLyingRawTx(hex: string): this {
    this.opts.lyingRawTx = hex;
    return this;
  }
  setHistory(h: HistoryEntry[]): this {
    this.opts.history = h;
    return this;
  }

  async getUTXOs(_scripthash: string, _scriptHex?: string): Promise<ElectrumUtxo[]> {
    return this.opts.utxos ?? [];
  }

  async getBalance(_scripthash: string, _scriptHex?: string): Promise<ElectrumBalance> {
    return this.opts.balance ?? { confirmed: 0, unconfirmed: 0 };
  }

  async getTx(txid: string): Promise<string> {
    if (this.opts.getTxThrows) throw new Error('MockElectrumClient: proxy unreachable (getTxThrows)');
    if (this.opts.lyingRawTx !== undefined) return this.opts.lyingRawTx;
    const hit = this.opts.rawTxByTxid?.[txid];
    if (hit !== undefined) return hit;
    throw new Error(`MockElectrumClient: no rawtx configured for ${txid}`);
  }

  async broadcastTx(rawTx: string): Promise<string> {
    this.broadcasts.push(rawTx);
    if (this.opts.broadcastThrows) throw new Error('MockElectrumClient: broadcast rejected (broadcastThrows)');
    return (this.opts.broadcastTxid ?? '00'.repeat(32)).toLowerCase();
  }

  /** blockchain.scripthash.get_history — a lying proxy can fabricate confirmations here. */
  async get_history(_scripthash: string): Promise<HistoryEntry[]> {
    return this.opts.history ?? [];
  }

  /** ElectrumProxyClient.getHistory — the camelCase alias the SwapController's secret-watcher calls. */
  async getHistory(_scripthash: string, _scriptHex?: string, _timeoutMs?: number): Promise<HistoryEntry[]> {
    return this.opts.history ?? [];
  }

  /**
   * R175-SPV: blockchain.block.headers — a batch of contiguous 80-byte headers (concatenated hex). Serves the
   * CONTIGUOUS run from `start` out of opts.headersByHeight; a missing height ends the run (short batch), which
   * the SPV verifier fails-closed on. Behaviour copied from the app's spv-verifier.test.ts inline mockClient.
   */
  async getBlockHeaders(start: number, count: number): Promise<{ count: number; hex: string; max: number }> {
    const byH = this.opts.headersByHeight ?? {};
    let hex = ''; let n = 0;
    for (let h = start; h < start + count && byH[h]; h++) { hex += byH[h]; n++; }
    return { count: n, hex, max: 500 };
  }

  /**
   * R175-SPV: blockchain.transaction.get_merkle — the proxy's (untrusted) Merkle inclusion proof. A test can
   * fabricate one per-txid (merkleProofByTxid) or one for all txids (merkleProof); with neither set it throws
   * (as the app's inline mock does for the "merkle not exercised" paths).
   */
  async getMerkleProof(txid: string, _height: number): Promise<{ block_height: number; merkle: string[]; pos: number }> {
    const byTxid = this.opts.merkleProofByTxid?.[txid];
    if (byTxid) return byTxid;
    if (this.opts.merkleProof) return this.opts.merkleProof;
    throw new Error(`MockElectrumClient: no merkle proof configured for ${txid}`);
  }

  /**
   * Raw Electrum JSON-RPC — routes only `blockchain.headers.subscribe` (used by getChainTimeSec) to a
   * fabricated tip header {height, hex}. Any other method throws (nothing else in the SPV layer uses request()).
   */
  async request<T = unknown>(method: string, _params: unknown[]): Promise<T> {
    if (method === 'blockchain.headers.subscribe') {
      return { height: this.opts.height ?? 0, hex: this.opts.tipHeaderHex ?? '' } as T;
    }
    throw new Error(`MockElectrumClient: unexpected request method ${method}`);
  }

  /** Mirrors proxy-client.getBlockHeight: returns [height, unsubscribe]; fabricated tip via opts.height. */
  async getBlockHeight(onNewBlock?: (height: number) => void): Promise<[number, () => void]> {
    if (onNewBlock) this.headerCbs.push(onNewBlock);
    const unsub = () => {
      if (onNewBlock) this.headerCbs = this.headerCbs.filter((c) => c !== onNewBlock);
    };
    return [this.opts.height ?? 0, unsub];
  }

  /** Mirrors proxy-client.subscribeAddress: returns unsubscribe; notifications via pushAddress. */
  async subscribeAddress(
    _scripthash: string,
    callback: (scripthash: string, status: string | null) => void,
    _scriptHex?: string,
  ): Promise<() => void> {
    this.addressCbs.push(callback);
    return () => {
      this.addressCbs = this.addressCbs.filter((c) => c !== callback);
    };
  }

  /** Inject a fabricated new-block notification (headers.subscribe push). */
  pushBlock(height: number): void {
    for (const cb of this.headerCbs) cb(height);
  }

  /** Inject a fabricated scripthash-status notification. */
  pushAddress(scripthash: string, status: string | null): void {
    for (const cb of this.addressCbs) cb(scripthash, status);
  }
}

// ============================================================================
// Raw-tx builder — construct a valid non-witness funding tx + its TRUE txid.
// Lets sibling tests feed verifyAndAuthenticateUtxo an HONEST rawtx (txid matches)
// or corrupt one byte to prove the txid-binding fail-closed.
// ============================================================================

function toLEHex(value: bigint, bytes: number): string {
  let hex = '';
  let v = value;
  for (let i = 0; i < bytes; i++) {
    hex += (v & 0xffn).toString(16).padStart(2, '0');
    v >>= 8n;
  }
  return hex;
}

function varIntHex(n: number): string {
  if (n < 0xfd) return n.toString(16).padStart(2, '0');
  if (n <= 0xffff) return 'fd' + toLEHex(BigInt(n), 2);
  if (n <= 0xffffffff) return 'fe' + toLEHex(BigInt(n), 4);
  return 'ff' + toLEHex(BigInt(n), 8);
}

export interface TxOutputSpec {
  value: number; // satoshis
  scriptPubKeyHex: string; // hex, no 0x
}

/**
 * Build a minimal valid non-witness transaction (1 dummy input, the given outputs) and
 * return its raw hex plus its authentic txid (= reverse(double-SHA256(rawTx)), matching
 * htlc-builder.ts). Use it to construct honest getTx entries or, by corrupting the
 * returned hex, a mismatched-txid rawtx for the fail-closed test.
 */
export function buildUtxoRawTx(outputs: TxOutputSpec[]): { rawTxHex: string; txid: string } {
  let hex = '';
  hex += '01000000'; // version 1 (LE)
  hex += '01'; // input count
  hex += '00'.repeat(32); // prevout txid (32 bytes)
  hex += 'ffffffff'; // prevout vout
  hex += '00'; // scriptSig length 0
  hex += 'ffffffff'; // sequence
  hex += varIntHex(outputs.length); // output count
  for (const o of outputs) {
    hex += toLEHex(BigInt(o.value), 8); // 8-byte LE value
    const spk = o.scriptPubKeyHex.replace(/^0x/, '');
    hex += varIntHex(spk.length / 2); // scriptPubKey length
    hex += spk;
  }
  hex += '00000000'; // locktime

  // txid = reverse(sha256(sha256(rawTx))) — repointed off `ethers` onto @noble/hashes
  // sha256 + htlc-builder hex helpers; identical math to the frontend harness.
  const bytes = hexToBytes(hex);
  const d1 = sha256(bytes);
  const d2 = sha256(d1);
  const reversed = new Uint8Array(d2.length);
  for (let i = 0; i < d2.length; i++) reversed[i] = d2[d2.length - 1 - i];
  const txid = bytesToHex(reversed);
  return { rawTxHex: hex, txid };
}

/** OP_HASH160 <20-byte hash160> OP_EQUAL — the HTLC P2SH funded-output scriptPubKey. */
export function p2shScriptPubKeyHex(hash160Hex: string): string {
  const h = hash160Hex.replace(/^0x/, '');
  if (h.length !== 40) throw new Error('p2shScriptPubKeyHex: hash160 must be 20 bytes');
  return 'a914' + h + '87';
}

// ============================================================================
// (1) encodeSwap / makeHashLock — ABI-correct getSwap return encoder
// ============================================================================

/** One ethers.Interface built from the SAME HTLC_ABI the SUT uses (no test/source drift). */
export const htlcInterface = new ethers.Interface(HTLC_ABI);

/** Selector for getSwap(bytes32) — used by MockEvmProvider.call() to route reads. */
export const GET_SWAP_SELECTOR = htlcInterface.getFunction('getSwap')!.selector;

export const ZERO_ADDRESS = '0x0000000000000000000000000000000000000000';
export const ZERO_BYTES32 = '0x' + '0'.repeat(64);

/**
 * The getSwap struct, in the EXACT tuple order the contract returns
 * (evm-client.ts:30 / :1143-1165):
 *   (initiator, recipient, token, amount, hashLock, timeLock, claimed, refunded)
 */
export interface SwapStruct {
  initiator: string;
  recipient: string;
  token: string;
  amount: bigint;
  hashLock: string;
  timeLock: bigint;
  claimed: boolean;
  refunded: boolean;
}

/** A zero-initialised struct — getSwap() decodes this to `null` (initiator == ZeroAddress). */
export const ZERO_SWAP: SwapStruct = {
  initiator: ZERO_ADDRESS,
  recipient: ZERO_ADDRESS,
  token: ZERO_ADDRESS,
  amount: 0n,
  hashLock: ZERO_BYTES32,
  timeLock: 0n,
  claimed: false,
  refunded: false,
};

/**
 * Encode a getSwap() return value as ABI-correct hex, exactly as a real HTLC node
 * would return from `eth_call`. Feed this out of MockEvmProvider.call().
 */
export function encodeSwap(s: SwapStruct): string {
  return htlcInterface.encodeFunctionResult('getSwap', [
    s.initiator,
    s.recipient,
    s.token,
    s.amount,
    s.hashLock,
    s.timeLock,
    s.claimed,
    s.refunded,
  ]);
}

/** Build a well-formed swap struct with sensible defaults, overridable per-field. */
export function makeSwap(over: Partial<SwapStruct> = {}): SwapStruct {
  const base: SwapStruct = {
    initiator: '0x1111111111111111111111111111111111111111',
    recipient: '0x2222222222222222222222222222222222222222',
    token: ZERO_ADDRESS,
    amount: 1_000_000_000_000_000_000n, // 1 ETH
    hashLock: '0x' + '11'.repeat(32),
    timeLock: 1_800_000_000n, // plausible unix ts (~2027), passes claimSwap R138b guard
    claimed: false,
    refunded: false,
  };
  return { ...base, ...over };
}

/** hashLock = sha256(secretHex) — matches OP_SHA256 on the UTXO side + evm-client hashPreimage. */
export function makeHashLock(secretHex: string): string {
  return ethers.sha256(secretHex);
}

// ============================================================================
// (2) MockEvmProvider — a valid ethers v6 ContractRunner returning fabricated bytes
// ============================================================================

export interface MockEvmProviderOpts {
  /** Struct returned for a `latest` (no blockTag) getSwap call. `null` => encode ZERO_SWAP (getSwap -> null). */
  swap?: SwapStruct | null;
  /** Struct returned when the call carries `blockTag === 'safe'` (R143 depth gate). */
  safeSwap?: SwapStruct | null;
  /** Struct returned for a NUMERIC blockTag (historical/depth read). Overrides `swap` when set. */
  numericSwap?: SwapStruct | null;
  /** Per-tag resolver (highest precedence). Return a struct, `null` (ZERO_SWAP), or `undefined` to fall through. */
  swapByBlockTag?: (tag: number | string | undefined) => SwapStruct | null | undefined;
  /** When true, call() throws — simulate an unreachable / erroring RPC. */
  callThrows?: boolean;
  /** Result of getBlock(): `{timestamp}` | null (missing) | `{timestamp: NaN}` (stale/garbage). */
  block?: { timestamp: number } | null;
  /** getBlockNumber() result. */
  blockNumber?: number;
  /** getNetwork().chainId (bigint). */
  chainId?: bigint;
  /** getCode() result — '0x' means undeployed; default is deployed bytecode. */
  code?: string;
  /** getLogs() result. */
  logs?: unknown[];
  /** getTransactionReceipt() result. */
  receipt?: unknown | null;
  /** getTransaction() result. */
  transaction?: unknown | null;
  /** Leaf providers for the FallbackProvider quorum path (recoverLockFromTx.__leafProviders). */
  leafProviders?: MockEvmProvider[];
}

/**
 * A minimal but valid ethers v6 ContractRunner. `new Contract(addr, HTLC_ABI, provider)`
 * routes view calls to `runner.call(tx)`; this returns ABI-correct bytes so getSwap()
 * decodes a struct we control — including an INFLATED timeLock, a stale/missing block,
 * a blockTag-routed 'safe' vs numeric disagreement, or an unreachable RPC.
 */
export class MockEvmProvider {
  opts: MockEvmProviderOpts;
  /** Records every call()'s blockTag so a test can assert routing. */
  public readonly callLog: Array<{ blockTag: number | string | undefined; data: string | undefined }> = [];

  constructor(opts: MockEvmProviderOpts = {}) {
    this.opts = opts;
  }

  /** ethers ContractRunner.provider — self-reference so getRunner(runner,'call') resolves. */
  get provider(): MockEvmProvider {
    return this;
  }

  /** Exposed for recoverLockFromTx's `(provider as any).__leafProviders` multi-leaf quorum scan. */
  get __leafProviders(): MockEvmProvider[] | undefined {
    return this.opts.leafProviders;
  }

  setSwap(s: SwapStruct | null): this {
    this.opts.swap = s;
    return this;
  }
  setSafeSwap(s: SwapStruct | null): this {
    this.opts.safeSwap = s;
    return this;
  }
  setBlock(b: { timestamp: number } | null): this {
    this.opts.block = b;
    return this;
  }
  setCallThrows(v: boolean): this {
    this.opts.callThrows = v;
    return this;
  }

  private resolveSwap(blockTag: number | string | undefined): SwapStruct | null {
    if (this.opts.swapByBlockTag) {
      const r = this.opts.swapByBlockTag(blockTag);
      if (r !== undefined) return r;
    }
    if (blockTag === 'safe') {
      return this.opts.safeSwap !== undefined ? this.opts.safeSwap : (this.opts.swap ?? null);
    }
    if (typeof blockTag === 'number') {
      return this.opts.numericSwap !== undefined ? this.opts.numericSwap : (this.opts.swap ?? null);
    }
    return this.opts.swap ?? null;
  }

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  async call(tx: any): Promise<string> {
    const blockTag = tx?.blockTag;
    const data: string | undefined = tx?.data;
    this.callLog.push({ blockTag, data });
    if (this.opts.callThrows) {
      throw new Error('MockEvmProvider: RPC unreachable (callThrows)');
    }
    // Route getSwap by selector; any other read returns a single zero word (balanceOf/allowance = 0).
    if (typeof data === 'string' && data.toLowerCase().startsWith(GET_SWAP_SELECTOR.toLowerCase())) {
      const s = this.resolveSwap(blockTag);
      return encodeSwap(s ?? ZERO_SWAP);
    }
    return ZERO_BYTES32;
  }

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  async getBlock(_tag?: any): Promise<{ timestamp: number } | null> {
    return this.opts.block !== undefined ? this.opts.block : { timestamp: 1_700_000_000 };
  }

  async getBlockNumber(): Promise<number> {
    return this.opts.blockNumber ?? 1_000;
  }

  async getNetwork(): Promise<{ chainId: bigint }> {
    return { chainId: this.opts.chainId ?? 8453n };
  }

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  async getCode(_addr?: any): Promise<string> {
    return this.opts.code ?? '0x60006000';
  }

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  async getLogs(_filter?: any): Promise<unknown[]> {
    return this.opts.logs ?? [];
  }

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  async getTransactionReceipt(_hash?: any): Promise<unknown | null> {
    return this.opts.receipt !== undefined ? this.opts.receipt : null;
  }

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  async getTransaction(_hash?: any): Promise<unknown | null> {
    return this.opts.transaction !== undefined ? this.opts.transaction : null;
  }

  /** ethers may call resolveName when encoding an ENS-shaped address arg; pass hex through. */
  async resolveName(name: string): Promise<string> {
    return name;
  }
}

// ============================================================================
// (3) MockSigner — wraps a MockEvmProvider; sendTransaction is a zero-broadcast SPY
// ============================================================================

/** Sentinel thrown by MockSigner.sendTransaction — asserts NO broadcast on a fail-closed path. */
export const SENDTX_SENTINEL = 'MockSigner.sendTransaction — BROADCAST ATTEMPTED (test fail-closed violation)';

/**
 * A valid ethers v6 ContractRunner+Signer. `new Contract(addr, HTLC_ABI, signer)` routes
 * state-changing calls (lock/claim/refund) to `runner.sendTransaction` — here a vi.fn() SPY
 * that THROWS. The core fund-safety assertion across the suite is `signer.sendTransaction`
 * has ZERO calls on every fail-closed path (the secret is never revealed, funds never move).
 */
export class MockSigner {
  provider: MockEvmProvider;
  address: string;
  /** 'throw' (DEFAULT — the fail-closed spy) throws SENDTX_SENTINEL on any broadcast; 'ok' broadcasts SUCCESSFULLY
   *  (used ONLY by the deliberate happy-path tests, e.g. a genuine EVM refund). The default is unchanged so every
   *  existing fail-closed assertion (`broadcastCount === 0` / `.rejects.toThrow(SENDTX_SENTINEL)`) still holds. */
  readonly mode: 'throw' | 'ok';
  /** vi.fn() spy — throws the sentinel (default) or, in 'ok' mode, returns a valid tx response + stages a status-1
   *  receipt on the provider so ethers' ContractTransactionResponse.wait() resolves. */
  public readonly sendTransaction: ReturnType<typeof vi.fn>;

  constructor(provider: MockEvmProvider, address = '0x2222222222222222222222222222222222222222', opts?: { mode?: 'throw' | 'ok' }) {
    this.provider = provider;
    this.address = address;
    this.mode = opts?.mode ?? 'throw';
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    this.sendTransaction = vi.fn((tx?: any) => {
      if (this.mode === 'throw') throw new Error(SENDTX_SENTINEL);
      const hash = '0x' + 'ab'.repeat(32);
      const bn = this.provider.opts.blockNumber ?? 1_000;
      // Stage the status-1 receipt the (mock) provider returns for tx.wait() -> getTransactionReceipt(hash).
      this.provider.opts.receipt = {
        status: 1, logs: [], hash, blockNumber: bn, index: 0,
        to: tx?.to ?? null, from: this.address, contractAddress: null,
        blockHash: '0x' + 'bc'.repeat(32), logsBloom: '0x' + '00'.repeat(256),
        gasUsed: 21_000n, cumulativeGasUsed: 21_000n, blobGasUsed: null,
        gasPrice: 0n, blobGasPrice: null, type: 2, root: null,
      };
      // A TransactionResponse-shaped object ethers wraps in a ContractTransactionResponse; .wait() reads the receipt above.
      return {
        hash, blockNumber: null, blockHash: null, index: 0, type: 2,
        from: this.address, to: tx?.to ?? null, gasLimit: 21_000n, nonce: 0,
        data: tx?.data ?? '0x', value: tx?.value ?? 0n, gasPrice: 0n,
        maxPriorityFeePerGas: null, maxFeePerGas: null, maxFeePerBlobGas: null,
        chainId: this.provider.opts.chainId ?? 8453n, signature: null, accessList: null,
      };
    });
  }

  async getAddress(): Promise<string> {
    return this.address;
  }

  /** Number of broadcast attempts — assert === 0 on fail-closed paths. */
  get broadcastCount(): number {
    return this.sendTransaction.mock.calls.length;
  }
}
