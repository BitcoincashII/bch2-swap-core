import { U as Utxo, C as Chain, b as SwapState, H as HTLCDetails } from './swap-types-CbNzOsAe.js';
export { hash160, hexToBytes } from './htlc-builder.js';
export { sha256 } from '@noble/hashes/sha256';

/**
 * swap-flow.ts — swap construction helpers (createHTLC, fund, claim, extract-secret).
 *
 * Provides HTLC construction, funding, claiming, and secret utilities
 * used by SwapCreate and SwapExecute. Delegates to htlc-builder.ts for
 * all cryptographic primitives so there is a single implementation.
 */

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
declare function verifyAndAuthenticateUtxo(proxyUtxo: Utxo, redeemScript: Uint8Array, fetchRawTx: (txid: string) => Promise<string>): Promise<Utxo>;
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
declare function verifyAndAuthenticateP2pkhInput(proxyUtxo: Utxo, expectedPubkeyHash: Uint8Array, fetchRawTx: (txid: string) => Promise<string>): Promise<Utxo>;
/** Generate a 32-byte random secret (preimage). */
declare function generateSecret(): Uint8Array;
/** SHA-256 hash of the secret preimage (= hashLock). */
declare function hashSecret(secret: Uint8Array): Uint8Array;
/**
 * Build the initiator's HTLC on sendChain.
 *
 *   recipient = responder's receive address on sendChain (responder claims)
 *   refund    = initiator's refund address on sendChain
 *   locktime  = currentHeight + LOCKTIME_BLOCKS.initiator
 */
declare function createInitiatorHTLC(state: SwapState, currentHeight: number, recipientPubkeyHash: Uint8Array, refundPubkeyHash: Uint8Array): HTLCDetails;
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
declare function createResponderHTLC(state: SwapState, currentHeight: number, initiatorPubkeyHash: Uint8Array, refundPubkeyHash: Uint8Array, explicitLocktime?: number): HTLCDetails;
/**
 * Compute the reversed-SHA256 scripthash used to query Electrum.
 * This is the P2SH scripthash (OP_HASH160 <hash> OP_EQUAL), reversed.
 */
declare function getHTLCScripthash(redeemScript: Uint8Array): string;
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
declare function fundHTLC(htlc: HTLCDetails, utxos: Utxo[], privateKey: Uint8Array, publicKey: Uint8Array, p2pkhScript: Uint8Array, amount: number, chain: Chain, feeRate?: number): Promise<{
    txid: string;
    rawTx: string;
    fee: number;
}>;
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
declare function claimHTLC(utxo: Utxo, redeemScript: Uint8Array, secret: Uint8Array, privateKey: Uint8Array, publicKey: Uint8Array, destPubkeyHash: Uint8Array, chain: Chain, feeRate?: number): Promise<{
    txid: string;
    rawTx: string;
}>;
/**
 * Extract the HTLC secret preimage from a raw claim transaction (hex).
 * Returns null if the transaction is not a valid HTLC claim.
 * R23-HTLC-001: pass expectedSecretHash so the validation added in R22 is actually exercised.
 */
declare function extractSecret(rawTxHex: string, expectedSecretHash?: Uint8Array | string): Uint8Array | null;

export { claimHTLC, createInitiatorHTLC, createResponderHTLC, extractSecret, fundHTLC, generateSecret, getHTLCScripthash, hashSecret, verifyAndAuthenticateP2pkhInput, verifyAndAuthenticateUtxo };
