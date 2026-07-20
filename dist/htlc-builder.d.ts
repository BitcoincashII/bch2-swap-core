export { sha256 } from '@noble/hashes/sha256';
import { U as Utxo, C as Chain, c as HTLCParams, H as HTLCDetails } from './swap-types-CbNzOsAe.js';

/**
 * HTLC (Hash Time-Locked Contract) Builder
 *
 * Constructs HTLC redeem scripts and spending transactions for atomic swaps.
 * Supports BCH2, BCH (BIP143/FORKID), BTC, BC2 (legacy sighash).
 */

declare function hexToBytes(hex: string): Uint8Array;
declare function bytesToHex(bytes: Uint8Array): string;
declare function hash160(data: Uint8Array): Uint8Array;
declare function concat(...arrays: Uint8Array[]): Uint8Array;
declare function pushData(data: Uint8Array): Uint8Array;
/**
 * Create an HTLC redeem script.
 *
 * Script:
 *   OP_IF
 *     OP_SHA256 <secretHash> OP_EQUALVERIFY
 *     OP_DUP OP_HASH160 <recipientPubkeyHash>
 *   OP_ELSE
 *     <locktime> OP_CHECKLOCKTIMEVERIFY OP_DROP
 *     OP_DUP OP_HASH160 <refundPubkeyHash>
 *   OP_ENDIF
 *   OP_EQUALVERIFY OP_CHECKSIG
 */
declare const LOCKTIME_HEIGHT_MAX = 500000000;
declare const LOCKTIME_TS_MIN = 1500000000;
declare const LOCKTIME_TS_MAX = 2147483648;
declare function isTimestampLocktime(locktime: number): boolean;
declare function isValidLocktime(locktime: number): boolean;
declare function maxPlausibleBlockHeight(nowSec?: number): number;
declare function createHTLCRedeemScript(params: HTLCParams): Uint8Array;
/**
 * Compute the P2SH address for an HTLC redeem script.
 */
declare function htlcToP2SHAddress(redeemScript: Uint8Array, chain: Chain): string;
/**
 * Create full HTLC details including address and scriptPubKey.
 */
declare function createHTLC(params: HTLCParams, chain: Chain): HTLCDetails;
/**
 * Compute Electrum scripthash for an HTLC P2SH address (for monitoring).
 */
declare function htlcScripthash(redeemScript: Uint8Array): string;
/**
 * R146-FEE-FLOOR-001: the minimum UTXO-HTLC amount that is guaranteed CLAIMABLE (and therefore also
 * refundable) after fees on a given chain. The old funding floor was a flat dustThreshold*5, whose comment
 * assumed 1 sat/B — but a chain like BTC at feePerByte=10 has a claim fee (~3.9k sat) far above that floor,
 * so amounts in roughly [dustThreshold*5, claimFee+dust] funded successfully yet could NEVER be claimed
 * (buildHTLCClaimTx throws fee>=value) and partly never refunded — stranding funds / enabling asymmetric
 * griefing. This computes a fee-aware floor: a worst-case claim tx (representative ~110B HTLC redeemScript,
 * P2PKH destination) must pay its fee AND leave a non-dust output, mirroring buildHTLCClaimTx's size formula.
 * Kept >= the historical dustThreshold*5 lower bound. The claim floor exceeds the (smaller) refund floor, so
 * satisfying it guarantees both legs are recoverable. UTXO chains only — do not call for EVM chains.
 */
declare function minClaimableHtlcAmount(chain: Chain): number;
/**
 * Build a funding transaction that sends funds to the HTLC P2SH address.
 * This is a regular P2PKH -> P2SH transaction.
 */
declare function buildHTLCFundingTx(inputs: Array<{
    utxo: Utxo;
    privateKey: Uint8Array;
    publicKey: Uint8Array;
    scriptPubKey: Uint8Array;
}>, htlcScriptPubKey: Uint8Array, amount: number, changeScriptPubKey: Uint8Array | null, chain: Chain, feeRate?: number): Promise<{
    txid: string;
    rawTx: string;
    fee: number;
}>;
/**
 * Build a P2SH HTLC claim transaction (single input).
 *
 * NOTE: Only one UTXO is claimed per call. If the HTLC address received multiple
 * funding transactions, call once per UTXO — each uses the same secret.
 * The swap engine enforces single-UTXO funding (rejecting offers with split UTXOs)
 * to avoid this scenario. TODO: add multi-input claim support if split-payment
 * HTLCs are ever needed.
 */
declare function buildHTLCClaimTx(utxo: Utxo, redeemScript: Uint8Array, secret: Uint8Array, recipientPrivateKey: Uint8Array, recipientPublicKey: Uint8Array, destinationScriptPubKey: Uint8Array, chain: Chain, feeRate?: number): Promise<{
    txid: string;
    rawTx: string;
}>;
/**
 * Build a refund transaction: initiator reclaims after timelock expires.
 */
declare function buildHTLCRefundTx(utxo: Utxo, redeemScript: Uint8Array, locktime: number, refundPrivateKey: Uint8Array, refundPublicKey: Uint8Array, destinationScriptPubKey: Uint8Array, chain: Chain, feeRate?: number): Promise<{
    txid: string;
    rawTx: string;
}>;
/**
 * Extract the secret preimage from a claim transaction's scriptSig.
 * The scriptSig format is: <sig> <pubkey> <secret> <OP_1 (0x51)> <redeemScript>
 *
 * Parse order: sig → pubkey → secret (32 bytes). Stop after reading secret;
 * the next byte is 0x51 (OP_1, claim-branch selector), not consumed here. (R104-HTLC-001)
 */
declare function extractSecretFromClaimTx(rawTxHex: string, expectedSecretHash?: Uint8Array | string): Uint8Array | null;
/**
 * Parse and SELF-AUTHENTICATE a funding transaction, returning the value and
 * scriptPubKey of a specific output (PROXY-TRUST-UTXO-VALUE-001).
 *
 * The proxy/Electrum layer supplies UTXO value+tx_pos via listunspent, but for
 * legacy (non-BIP143) chains (btc, bc2) the signature does NOT commit the input
 * value, so a lying/compromised proxy could induce a malformed/under/over-fee
 * claim/refund, or point tx_pos at the wrong output. We re-derive the txid from
 * the raw bytes (double-SHA256 + byte-reversal) and require it to equal
 * expectedTxid — the proxy cannot forge bytes that hash to a txid we already
 * trust. Returns the AUTHENTICATED { value, scriptPubKey } at index voutIndex.
 * Throws on any verification failure (caller MUST abort the spend).
 *
 * The funding txs in this app are always non-witness (no SegWit on these chains;
 * the app can only sign legacy P2PKH inputs), so a single linear parse covers all
 * chains and hash256(rawBytes)===txid holds.
 */
declare function parseAuthenticatedOutput(rawTxHex: string, expectedTxid: string, voutIndex: number): {
    value: number;
    scriptPubKey: Uint8Array;
};

export { LOCKTIME_HEIGHT_MAX, LOCKTIME_TS_MAX, LOCKTIME_TS_MIN, buildHTLCClaimTx, buildHTLCFundingTx, buildHTLCRefundTx, bytesToHex, concat, createHTLC, createHTLCRedeemScript, extractSecretFromClaimTx, hash160, hexToBytes, htlcScripthash, htlcToP2SHAddress, isTimestampLocktime, isValidLocktime, maxPlausibleBlockHeight, minClaimableHtlcAmount, parseAuthenticatedOutput, pushData };
