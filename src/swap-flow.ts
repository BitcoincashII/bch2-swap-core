/**
 * swap-flow.ts — swap construction helpers (createHTLC, fund, claim, extract-secret).
 *
 * Provides HTLC construction, funding, claiming, and secret utilities
 * used by SwapCreate and SwapExecute. Delegates to htlc-builder.ts for
 * all cryptographic primitives so there is a single implementation.
 */

import type { Chain, HTLCDetails, HTLCParams, SwapState, Utxo } from './swap-types';
import {
  createHTLC,
  htlcScripthash,
  buildHTLCFundingTx,
  buildHTLCClaimTx,
  extractSecretFromClaimTx,
  parseAuthenticatedOutput,
  hash160,
  hexToBytes,
  sha256,
} from './htlc-builder';
import { LOCKTIME_BLOCKS, chainConfigs } from './chain-config';

/**
 * Verify a proxy-supplied UTXO against the SELF-AUTHENTICATED on-chain funding tx
 * before signing a claim/refund (PROXY-TRUST-UTXO-VALUE-001). Returns a UTXO whose
 * `value` is taken from the authenticated raw tx (NOT the proxy's listunspent), and
 * whose funded output's scriptPubKey is verified to be the HTLC P2SH. Throws on any
 * mismatch so the caller aborts the spend without signing over an unverified value.
 *
 * @param fetchRawTx async fn returning raw tx hex for a txid (caller supplies it so
 *                   this module stays free of the WS client; wrap with a timeout).
 */
export async function verifyAndAuthenticateUtxo(
  proxyUtxo: Utxo,
  redeemScript: Uint8Array,
  fetchRawTx: (txid: string) => Promise<string>,
): Promise<Utxo> {
  if (!proxyUtxo || typeof proxyUtxo.tx_hash !== 'string' || !/^[0-9a-f]{64}$/.test(proxyUtxo.tx_hash)) {
    throw new Error('verifyAndAuthenticateUtxo: malformed UTXO tx_hash from proxy');
  }
  if (!Number.isInteger(proxyUtxo.tx_pos) || proxyUtxo.tx_pos < 0) {
    throw new Error('verifyAndAuthenticateUtxo: malformed UTXO tx_pos from proxy');
  }
  const rawTx = await fetchRawTx(proxyUtxo.tx_hash);
  const { value, scriptPubKey } = parseAuthenticatedOutput(rawTx, proxyUtxo.tx_hash, proxyUtxo.tx_pos);
  // Expected funded-output spk: OP_HASH160 <hash160(redeemScript)> OP_EQUAL (23 bytes).
  const expectedSpk = new Uint8Array([0xa9, 0x14, ...hash160(redeemScript), 0x87]);
  if (scriptPubKey.length !== expectedSpk.length || !scriptPubKey.every((b, i) => b === expectedSpk[i])) {
    throw new Error(
      'verifyAndAuthenticateUtxo: funded output scriptPubKey does not match the HTLC P2SH — ' +
      'the proxy pointed at the wrong output (possible malicious/compromised proxy)',
    );
  }
  if (Number.isFinite(proxyUtxo.value) && proxyUtxo.value !== value) {
    console.warn(
      `[swap-flow] proxy listunspent value ${proxyUtxo.value} != authenticated value ${value} ` +
      `for ${proxyUtxo.tx_hash}:${proxyUtxo.tx_pos} — using authenticated value`,
    );
  }
  return { ...proxyUtxo, value };
}

/**
 * R260-INPUT-VALUE-AUTH-001 (MEGASWEEP-1 server-io HIGH): authenticate a funding-INPUT (own P2PKH) UTXO's VALUE
 * against its self-derived raw tx before signing. On LEGACY non-BIP143 chains (btc/bc2: useBip143=false) the sighash
 * does NOT commit the input value, so a lying/MITM proxy returning a wrong listunspent `value` yields a VALID signature
 * the node accepts as long as outputs <= the real input sum -> the wallet computes too little change -> the user
 * silently burns the difference to miner fees. (BIP143 chains commit the value in the preimage, so a lie -> invalid
 * sig -> node reject = DoS only, no loss.) Mirrors verifyAndAuthenticateUtxo but expects the caller's OWN-ADDRESS
 * P2PKH spk (OP_DUP OP_HASH160 <pubkeyHash20> OP_EQUALVERIFY OP_CHECKSIG = 25 bytes). Returns the UTXO with the
 * AUTHENTICATED value; THROWS on any txid / scriptPubKey mismatch so the caller aborts the spend (use the
 * authenticated value, NEVER the proxy's, to drive totalIn/fee/change).
 */
export async function verifyAndAuthenticateP2pkhInput(
  proxyUtxo: Utxo,
  expectedPubkeyHash: Uint8Array,
  fetchRawTx: (txid: string) => Promise<string>,
): Promise<Utxo> {
  if (!proxyUtxo || typeof proxyUtxo.tx_hash !== 'string' || !/^[0-9a-f]{64}$/.test(proxyUtxo.tx_hash)) {
    throw new Error('verifyAndAuthenticateP2pkhInput: malformed UTXO tx_hash from proxy');
  }
  if (!Number.isInteger(proxyUtxo.tx_pos) || proxyUtxo.tx_pos < 0) {
    throw new Error('verifyAndAuthenticateP2pkhInput: malformed UTXO tx_pos from proxy');
  }
  if (!(expectedPubkeyHash instanceof Uint8Array) || expectedPubkeyHash.length !== 20) {
    throw new Error('verifyAndAuthenticateP2pkhInput: expectedPubkeyHash must be 20 bytes');
  }
  const rawTx = await fetchRawTx(proxyUtxo.tx_hash);
  const { value, scriptPubKey } = parseAuthenticatedOutput(rawTx, proxyUtxo.tx_hash, proxyUtxo.tx_pos);
  // Expected own-address P2PKH spk: OP_DUP OP_HASH160 <pubkeyHash20> OP_EQUALVERIFY OP_CHECKSIG (25 bytes).
  const expectedSpk = new Uint8Array([0x76, 0xa9, 0x14, ...expectedPubkeyHash, 0x88, 0xac]);
  if (scriptPubKey.length !== expectedSpk.length || !scriptPubKey.every((b, i) => b === expectedSpk[i])) {
    throw new Error(
      'verifyAndAuthenticateP2pkhInput: input scriptPubKey does not match the expected own-address P2PKH — ' +
      'the proxy supplied a wrong/foreign input value (possible malicious/compromised proxy)',
    );
  }
  return { ...proxyUtxo, value };
}

function assertUtxoChain(chain: Chain): void {
  if ((chainConfigs[chain] as { isEvm?: boolean }).isEvm) {
    throw new Error(`HTLC UTXO construction not supported for EVM chain '${chain}' — use evm-client.ts`);
  }
}

// ============================================================================
// Secret generation
// ============================================================================

/** Generate a 32-byte random secret (preimage). */
export function generateSecret(): Uint8Array {
  const secret = new Uint8Array(32);
  crypto.getRandomValues(secret);
  return secret;
}

/** SHA-256 hash of the secret preimage (= hashLock). */
export function hashSecret(secret: Uint8Array): Uint8Array {
  return sha256(secret);
}

// ============================================================================
// HTLC construction
// ============================================================================

/**
 * Build the initiator's HTLC on sendChain.
 *
 *   recipient = responder's receive address on sendChain (responder claims)
 *   refund    = initiator's refund address on sendChain
 *   locktime  = currentHeight + LOCKTIME_BLOCKS.initiator
 */
export function createInitiatorHTLC(
  state: SwapState,
  currentHeight: number,
  recipientPubkeyHash: Uint8Array,
  refundPubkeyHash: Uint8Array,
): HTLCDetails {
  assertUtxoChain(state.offer.sendChain);
  const locktime = currentHeight + LOCKTIME_BLOCKS.initiator;
  const params: HTLCParams = {
    secretHash: state.secretHash,
    recipientPubkeyHash,
    refundPubkeyHash,
    locktime,
  };
  return createHTLC(params, state.offer.sendChain);
}

/**
 * Build the responder's HTLC on receiveChain.
 *
 *   recipient = initiator's receive address on receiveChain (initiator claims)
 *   refund    = responder's refund address on receiveChain
 *   locktime  = currentHeight + LOCKTIME_BLOCKS.responder
 *
 * Responder locktime is well below the initiator's (R-TIMELOCK-K: initiator >= K*(responder+claimMargin), so ~8h vs
 * ~30h), so the initiator always has time to claim before the responder can refund — with enough margin that a
 * K-fold block-rate acceleration on minority-hashrate BCH2 still can't invert the effective ordering.
 */
export function createResponderHTLC(
  state: SwapState,
  currentHeight: number,
  initiatorPubkeyHash: Uint8Array,
  refundPubkeyHash: Uint8Array,
  explicitLocktime?: number, // R167: when the counterparty leg is EVM, the caller passes a TIMESTAMP CLTV
                             // anchored to the trusted EVM expiry (not the proxy-supplied height) so a malicious
                             // proxy cannot inflate the responder's UTXO refund maturity. Falls back to the
                             // height-based locktime for all other (UTXO-counterparty) topologies.
): HTLCDetails {
  assertUtxoChain(state.offer.receiveChain);
  const locktime = explicitLocktime ?? (currentHeight + LOCKTIME_BLOCKS.responder);
  const params: HTLCParams = {
    secretHash: state.secretHash,
    recipientPubkeyHash: initiatorPubkeyHash,
    refundPubkeyHash,
    locktime,
  };
  return createHTLC(params, state.offer.receiveChain);
}

// ============================================================================
// HTLC scripthash (Electrum format)
// ============================================================================

/**
 * Compute the reversed-SHA256 scripthash used to query Electrum.
 * This is the P2SH scripthash (OP_HASH160 <hash> OP_EQUAL), reversed.
 */
export function getHTLCScripthash(redeemScript: Uint8Array): string {
  return htlcScripthash(redeemScript);
}

// ============================================================================
// Fund / Claim helpers
// ============================================================================

/**
 * Build a signed funding transaction to the HTLC P2SH address.
 *
 * @param htlc       - The HTLC details (contains P2SH scriptPubKey)
 * @param utxos      - Selected UTXOs to spend (greedy selection by caller)
 * @param privateKey - Signing key for the input UTXOs
 * @param publicKey  - Corresponding public key
 * @param p2pkhScript - The P2PKH scriptPubKey of the input address (for change)
 * @param amount     - Exact amount to lock in the HTLC (satoshis)
 * @param chain      - Chain being funded
 */
export async function fundHTLC(
  htlc: HTLCDetails,
  utxos: Utxo[],
  privateKey: Uint8Array,
  publicKey: Uint8Array,
  p2pkhScript: Uint8Array,
  amount: number,
  chain: Chain,
  feeRate?: number, // FEE-DEADLINE-FIX: live sat/vByte forwarded to the funding builder
): Promise<{ txid: string; rawTx: string; fee: number }> {
  assertUtxoChain(chain);
  const inputs = utxos.map(utxo => ({
    utxo,
    privateKey,
    publicKey,
    scriptPubKey: p2pkhScript,
  }));

  return buildHTLCFundingTx(
    inputs,
    htlc.p2shScriptPubKey,
    amount,
    p2pkhScript, // change back to same address
    chain,
    feeRate,
  );
}

/**
 * Build a signed claim transaction to sweep the HTLC to a P2PKH address.
 *
 * @param utxo             - The HTLC UTXO to spend
 * @param redeemScript     - The HTLC redeem script
 * @param secret           - The preimage (32 bytes)
 * @param privateKey       - Recipient's private key (signs the claim)
 * @param publicKey        - Recipient's public key
 * @param destPubkeyHash   - 20-byte hash of the destination address
 * @param chain            - Chain to claim on
 */
export async function claimHTLC(
  utxo: Utxo,
  redeemScript: Uint8Array,
  secret: Uint8Array,
  privateKey: Uint8Array,
  publicKey: Uint8Array,
  destPubkeyHash: Uint8Array,
  chain: Chain,
  feeRate?: number, // FEE-DEADLINE-FIX: live sat/vByte forwarded to the claim builder
): Promise<{ txid: string; rawTx: string }> {
  assertUtxoChain(chain);
  if (secret.length !== 32) throw new Error(`HTLC secret must be exactly 32 bytes; got ${secret.length}`);
  // Note: 32-byte data pushes use opcode 0x20 (minimal for 32 bytes) regardless of content.
  // MINIMALDATA only affects numeric pushes (≤4 bytes); a leading 0x00 in a 32-byte secret is valid.
  if (destPubkeyHash.length !== 20) throw new Error('destPubkeyHash must be exactly 20 bytes');
  const destP2PKH = new Uint8Array([0x76, 0xa9, 0x14, ...destPubkeyHash, 0x88, 0xac]);
  return buildHTLCClaimTx(utxo, redeemScript, secret, privateKey, publicKey, destP2PKH, chain, feeRate);
}

/**
 * Extract the HTLC secret preimage from a raw claim transaction (hex).
 * Returns null if the transaction is not a valid HTLC claim.
 * R23-HTLC-001: pass expectedSecretHash so the validation added in R22 is actually exercised.
 */
export function extractSecret(rawTxHex: string, expectedSecretHash?: Uint8Array | string): Uint8Array | null {
  return extractSecretFromClaimTx(rawTxHex, expectedSecretHash);
}

// ============================================================================
// Re-exports used elsewhere in the swap app
// ============================================================================

export { hash160, hexToBytes, sha256 };
