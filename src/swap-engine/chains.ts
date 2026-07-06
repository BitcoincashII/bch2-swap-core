/**
 * UTXO chain client interface and in-memory mock for tests.
 *
 * Direct port of swapengine/chains.go.
 */

import { ErrOutputNotFound } from './state';

/**
 * Abstract interface over a UTXO chain (BCH2, BCH, BTC, BC2).
 * Production implementations query Electrum or a block explorer.
 */
export interface UTXOChainClient {
  /**
   * Returns the satoshi amount and confirmation count for a specific P2SH
   * output in the given transaction.
   * Throws ErrOutputNotFound if the output does not exist.
   */
  getP2SHOutput(txid: string, scriptHash: Uint8Array): Promise<{ satoshis: number; confs: number }>;

  /**
   * Scans the chain/mempool for a UTXO paying exactly expectedSat to the given
   * P2SH script hash. Returns the funding txid when found, '' when not found,
   * throws on error.
   *
   * expectedSat is required so the probe matches THIS swap's HTLC and not a
   * different concurrent swap that happens to use the same P2SH script.
   */
  scanForHTLC(scriptHash: Uint8Array, expectedSat: number): Promise<string>;
}

function toHex(b: Uint8Array): string {
  return Array.from(b).map(v => v.toString(16).padStart(2, '0')).join('');
}

interface MockOutput {
  satoshis: number;
  confs:    number;
}

/**
 * In-memory mock UTXO chain for testing.
 * Port of MockUTXOChain in swapengine/chains.go.
 */
export class MockUTXOChain implements UTXOChainClient {
  private outputs   = new Map<string, MockOutput>();
  private scanError: Error | null = null;

  /** Add a P2SH output keyed by txid + script hash. */
  addOutput(txid: string, scriptHash: Uint8Array, satoshis: number, confs: number): void {
    this.outputs.set(`${txid}|${toHex(scriptHash)}`, { satoshis, confs });
  }

  /** Update the confirmation count on an existing output. */
  setConfirmations(txid: string, scriptHash: Uint8Array, confs: number): void {
    const key = `${txid}|${toHex(scriptHash)}`;
    const out = this.outputs.get(key);
    if (!out) throw new Error(`MockUTXOChain: no output for key ${key}`);
    this.outputs.set(key, { ...out, confs });
  }

  /** Force scanForHTLC to return an error (simulates a probe failure). */
  setScanError(err: Error | null): void {
    this.scanError = err;
  }

  async getP2SHOutput(txid: string, scriptHash: Uint8Array): Promise<{ satoshis: number; confs: number }> {
    const key = `${txid}|${toHex(scriptHash)}`;
    const out = this.outputs.get(key);
    if (!out) throw new ErrOutputNotFound(`txid=${txid} scriptHash=${toHex(scriptHash)}`);
    return { satoshis: out.satoshis, confs: out.confs };
  }

  async scanForHTLC(scriptHash: Uint8Array, expectedSat: number): Promise<string> {
    if (this.scanError) throw this.scanError;
    const shHex = toHex(scriptHash);
    for (const [key, out] of this.outputs.entries()) {
      const [txid, sh] = key.split('|');
      if (sh === shHex && out.satoshis === expectedSat) return txid;
    }
    return '';
  }
}
