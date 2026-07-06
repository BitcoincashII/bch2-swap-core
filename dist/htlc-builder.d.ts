/**
 * HTLC transaction construction for BCH2/BCH/BTC/BC2 atomic swaps (Path A).
 *
 * Direct port of bch2htlc/htlc.go + funding.go.
 *
 * Signing: ECDSA DER on all four chains — NOT Schnorr.
 * BCH2/BCH: BIP143 sighash + SIGHASH_FORKID (0x41)
 * BTC/BC2:  legacy P2SH sighash + SIGHASH_ALL (0x01)
 */
/** Block-based relative timelock for BCH2↔ERC-20 HTLCs. */
declare const HTLC_CSV_BLOCKS = 288;
/** SIGHASH_ALL | SIGHASH_FORKID — BCH/BCH2 replay-protection flag. */
declare const SIGHASH_ALL_FORKID = 65;
/** Plain SIGHASH_ALL — BTC/BC2. */
declare const SIGHASH_ALL = 1;
declare const DUST_SATOSHIS = 546;
declare const DEFAULT_FEE_SATOSHIS = 500;
/** BIP68 bit-22: time-based relative locktime. */
declare const SEQ_LOCKTIME_TYPE_FLAG = 4194304;
/** 1 << 9 = 512 seconds per BIP68 time unit. */
declare const SEQ_LOCKTIME_GRANULARITY = 9;
declare const BCH_SWAP_BCH2_CSV_NSEQUENCE: number;
declare const BCH_SWAP_BCH_CSV_NSEQUENCE: number;
declare const MAINNET_BCH_SWAP_BCH2_CSV: number;
declare const MAINNET_BCH_SWAP_BCH_CSV: number;
declare const MAINNET_BTC_SWAP_BCH2_CSV: number;
declare const MAINNET_BTC_SWAP_BTC_CSV: number;
declare const MAINNET_BC2_SWAP_BCH2_CSV: number;
declare const MAINNET_BC2_SWAP_BC2_CSV: number;
/**
 * Build the HTLC redeem script:
 *   OP_IF OP_SHA256 <hashLock> OP_EQUALVERIFY <buyerPubKey> OP_CHECKSIG
 *   OP_ELSE <csvNSequence> OP_CSV OP_DROP <sellerPubKey> OP_CHECKSIG OP_ENDIF
 *
 * OP_CHECKSIG validates ECDSA (not Schnorr) on all chains.
 * csvNSequence should carry SEQ_LOCKTIME_TYPE_FLAG for time-based locks.
 * The spending tx nSequence must equal this value (BIP112 type-match rule).
 */
declare function buildRedeemScript(buyerPubKey: Uint8Array, sellerPubKey: Uint8Array, csvNSequence: number, hashLock: Uint8Array): Uint8Array;
/** OP_HASH160 <hash160(redeemScript)> OP_EQUAL */
declare function p2shScriptPubKey(redeemScript: Uint8Array): Uint8Array;
/** OP_DUP OP_HASH160 <hash160(pubKey)> OP_EQUALVERIFY OP_CHECKSIG */
declare function p2pkhScriptPubKey(pubKey: Uint8Array): Uint8Array;
/**
 * Build a claim transaction (IF branch) that reveals secret s.
 *   scriptSig: <DER-sig> <secret> OP_1 <redeemScript>
 *   nSequence:  0xFFFFFFFF (no CSV on claim branch)
 *
 * sighashType: SIGHASH_ALL_FORKID (0x41) for BCH/BCH2; SIGHASH_ALL (0x01) for BTC/BC2.
 * Signing uses ECDSA DER on all chains (NOT Schnorr).
 */
declare function buildClaimTx(prevTxID: Uint8Array, // 32 bytes, internal (natural) byte order
prevVout: number, htlcSatoshis: number, redeemScript: Uint8Array, buyerPrivKey: Uint8Array, // zeroed after use
buyerPubKey: Uint8Array, secret: Uint8Array, sighashType: number): Promise<Uint8Array>;
/**
 * Build a refund transaction (ELSE branch) for the seller.
 *   scriptSig: <DER-sig> OP_0 <redeemScript>
 *   nSequence:  csvNSequence (must equal OP_CSV operand — BIP68/BIP112 enforcement)
 *
 * sighashType: SIGHASH_ALL_FORKID (0x41) for BCH/BCH2; SIGHASH_ALL (0x01) for BTC/BC2.
 */
declare function buildRefundTx(prevTxID: Uint8Array, prevVout: number, htlcSatoshis: number, redeemScript: Uint8Array, sellerPrivKey: Uint8Array, // zeroed after use
sellerPubKey: Uint8Array, csvNSequence: number, sighashType: number): Promise<Uint8Array>;
/**
 * Build a funding transaction: spend one P2PKH UTXO to create the HTLC + change.
 *   Output 0: P2SH HTLC  (htlcSatoshis)
 *   Output 1: P2PKH change (inputSatoshis - htlcSatoshis - feeSatoshis)
 *
 * sighashType: SIGHASH_ALL_FORKID (0x41) for BCH/BCH2; SIGHASH_ALL (0x01) for BTC/BC2.
 */
declare function buildFundingTx(prevTxID: Uint8Array, prevVout: number, inputSatoshis: number, funderPrivKey: Uint8Array, // zeroed after use
funderPubKey: Uint8Array, htlcRedeemScript: Uint8Array, htlcSatoshis: number, feeSatoshis: number, sighashType: number): Promise<Uint8Array>;
/**
 * Extract the 32-byte preimage s from a P2SH claim scriptSig.
 * Layout: <sigLen> <sig> <0x20> <secret(32B)> 0x51 <redeemScript...>
 */
declare function extractSecretFromScriptSig(scriptSig: Uint8Array): Uint8Array;
/**
 * Minimal script data push.
 *  len == 0       → [0x00]
 *  len 1-75       → [len, ...data]
 *  len 76-255     → [0x4c, len, ...data]   OP_PUSHDATA1
 *  len 256-65535  → [0x4d, lo, hi, ...data] OP_PUSHDATA2
 */
declare function pushData(data: Uint8Array): Uint8Array;
/**
 * Encode a BIP68 nSequence as a minimal script push for OP_CSV.
 *
 * Block-based values 1-16 → OP_1..OP_16 (MINIMALDATA-compliant; both BCH and BCH2
 * reject non-minimal single-byte integer pushes at mempool accept time).
 * All other values (including time-based: SEQ_LOCKTIME_TYPE_FLAG always set, value > 16)
 * → minimal CScriptNum encoding via pushScriptInt.
 */
declare function encodeCSV(nSequence: number): Uint8Array;
/**
 * Pre-BIP143 ("legacy") sighash for a single-input, single-output P2SH spend.
 * Used for BTC/BC2 HTLC claim/refund inputs.
 *
 * Preimage: version(4) | vinCount(1) | prevTxID(32) | prevVout(4) |
 *           scriptCode(var) | sequence(4) | voutCount(1) |
 *           outputAmount(8) | outputScript(var) | locktime(4) | sighashType(4)
 */
declare function legacySighashSingle(prevTxID: Uint8Array, prevVout: number, sequence: number, scriptCode: Uint8Array, outputAmount: number, outputScript: Uint8Array, locktime: number, sighashType: number): Uint8Array;
/**
 * Pre-BIP143 legacy sighash for a single-input, multi-output transaction.
 * Used for BTC/BC2 P2PKH funding inputs.
 */
declare function legacySighashOutputs(prevTxID: Uint8Array, prevVout: number, sequence: number, scriptCode: Uint8Array, outputs: TxOutput[], locktime: number, sighashType: number): Uint8Array;
/**
 * BIP143 sighash for BCH2/BCH (SIGHASH_FORKID) single-output spend.
 * scriptCode is the full redeemScript for P2SH; inputAmount is the HTLC value.
 */
declare function bip143Sighash(prevTxID: Uint8Array, prevVout: number, sequence: number, scriptCode: Uint8Array, inputAmount: number, outputScript: Uint8Array, outputAmount: number, locktime: number, sighashType: number): Uint8Array;
/**
 * BIP143 sighash for BCH2/BCH multi-output (funding) transaction.
 */
declare function bip143SighashOutputs(prevTxID: Uint8Array, prevVout: number, sequence: number, scriptCode: Uint8Array, inputAmount: number, outputs: TxOutput[], locktime: number, sighashType: number): Uint8Array;
interface TxOutput {
    amount: number;
    script: Uint8Array;
}

export { BCH_SWAP_BCH2_CSV_NSEQUENCE, BCH_SWAP_BCH_CSV_NSEQUENCE, DEFAULT_FEE_SATOSHIS, DUST_SATOSHIS, HTLC_CSV_BLOCKS, MAINNET_BC2_SWAP_BC2_CSV, MAINNET_BC2_SWAP_BCH2_CSV, MAINNET_BCH_SWAP_BCH2_CSV, MAINNET_BCH_SWAP_BCH_CSV, MAINNET_BTC_SWAP_BCH2_CSV, MAINNET_BTC_SWAP_BTC_CSV, SEQ_LOCKTIME_GRANULARITY, SEQ_LOCKTIME_TYPE_FLAG, SIGHASH_ALL, SIGHASH_ALL_FORKID, type TxOutput, bip143Sighash, bip143SighashOutputs, buildClaimTx, buildFundingTx, buildRedeemScript, buildRefundTx, encodeCSV, extractSecretFromScriptSig, legacySighashOutputs, legacySighashSingle, p2pkhScriptPubKey, p2shScriptPubKey, pushData };
