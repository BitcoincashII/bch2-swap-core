/**
 * Electrum adapter implementing UTXOChainClient.
 *
 * Maps ElectrumProxyClient.getUtxosByScripthash() to the UTXOChainClient interface.
 * The P2SH script hash from the engine (20-byte hash160) is converted to the
 * Electrum scripthash (SHA256(scriptPubKey) reversed) for the query.
 *
 * getP2SHOutput: fetches UTXOs paying to the P2SH script, finds the target txid.
 * scanForHTLC:   returns the txid of the UTXO paying exactly expectedSat to that
 *                P2SH script (mempool or confirmed); filters by amount so concurrent
 *                swaps sharing the same script cannot shadow each other.
 */

import { sha256 } from '@noble/hashes/sha256';
import { ErrOutputNotFound } from './state';
import type { UTXOChainClient } from './chains';
/** Minimal interface required by ElectrumHTLCChain — implemented by ElectrumProxyClient. */
export interface ElectrumLike {
  getUtxosByScripthash(scripthash: string): Promise<{ tx_hash: string; value: number; height: number }[]>;
  getBlockHeight(): Promise<number>;
}

function toHex(b: Uint8Array): string {
  return Array.from(b).map(v => v.toString(16).padStart(2, '0')).join('');
}

/** Build `OP_HASH160 <scriptHash> OP_EQUAL` scriptPubKey from a 20-byte hash. */
function p2shScriptPubKey(scriptHash: Uint8Array): Uint8Array {
  const s = new Uint8Array(23);
  s[0] = 0xa9; // OP_HASH160
  s[1] = 0x14; // push 20 bytes
  s.set(scriptHash, 2);
  s[22] = 0x87; // OP_EQUAL
  return s;
}

/** Electrum scripthash = SHA256(scriptPubKey) in byte-reversed LE order, hex-encoded. */
function toElectrumScripthash(scriptPubKey: Uint8Array): string {
  const h = sha256(scriptPubKey);
  const rev = new Uint8Array(h.length);
  for (let i = 0; i < h.length; i++) rev[i] = h[h.length - 1 - i];
  return toHex(rev);
}

export class ElectrumHTLCChain implements UTXOChainClient {
  constructor(private readonly client: ElectrumLike) {}

  async getP2SHOutput(txid: string, scriptHash: Uint8Array): Promise<{ satoshis: number; confs: number }> {
    const eSH = toElectrumScripthash(p2shScriptPubKey(scriptHash));
    const [utxos, height] = await Promise.all([
      this.client.getUtxosByScripthash(eSH),
      this.client.getBlockHeight(),
    ]);
    const utxo = utxos.find(u => u.tx_hash === txid);
    if (!utxo) throw new ErrOutputNotFound(`txid=${txid} scriptHash=${toHex(scriptHash)}`);
    const confs = utxo.height > 0 ? height - utxo.height + 1 : 0;
    return { satoshis: utxo.value, confs };
  }

  async scanForHTLC(scriptHash: Uint8Array, expectedSat: number): Promise<string> {
    const eSH = toElectrumScripthash(p2shScriptPubKey(scriptHash));
    const utxos = await this.client.getUtxosByScripthash(eSH);
    const match = utxos.find(u => u.value === expectedSat);
    return match ? match.tx_hash : '';
  }
}
