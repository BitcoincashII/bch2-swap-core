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
