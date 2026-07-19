/**
 * Unit tests for HTLC builder — validates script construction,
 * address generation, sighash computation, and transaction building.
 */

import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import {
  createHTLCRedeemScript,
  htlcToP2SHAddress,
  createHTLC,
  htlcScripthash,
  buildHTLCClaimTx,
  buildHTLCRefundTx,
  buildHTLCFundingTx,
  extractSecretFromClaimTx,
  parseAuthenticatedOutput,
  hexToBytes,
  bytesToHex,
  hash160,
  minClaimableHtlcAmount,
  isValidLocktime,
  isTimestampLocktime,
  LOCKTIME_HEIGHT_MAX,
  LOCKTIME_TS_MIN,
  LOCKTIME_TS_MAX,
} from './htlc-builder';
import { sha256 } from '@noble/hashes/sha256';
import * as secp256k1 from '@noble/secp256k1';
import type { HTLCParams, Utxo } from './swap-types';
import {
  createHTLC as createHTLCFull,
  htlcToP2SHAddress as htlcToP2SHAddressFn,
} from './htlc-builder';
import {
  verifyAndAuthenticateUtxo,
  verifyAndAuthenticateP2pkhInput,
} from './swap-flow';
import { MockElectrumClient, buildUtxoRawTx, p2shScriptPubKeyHex } from './test-mocks';

// ============================================================================
// Test fixtures
// ============================================================================

const SECRET = new Uint8Array(32).fill(0x42);
const SECRET_HASH = sha256(SECRET);
const RECIPIENT_HASH = new Uint8Array(20).fill(0xaa);
const REFUND_HASH = new Uint8Array(20).fill(0xbb);
const LOCKTIME = 54000;

function makeParams(): HTLCParams {
  return {
    secretHash: SECRET_HASH,
    recipientPubkeyHash: RECIPIENT_HASH,
    refundPubkeyHash: REFUND_HASH,
    locktime: LOCKTIME,
  };
}

// ============================================================================
// Redeem Script Tests
// ============================================================================

describe('createHTLCRedeemScript', () => {
  it('produces a valid redeem script with correct opcodes', () => {
    const script = createHTLCRedeemScript(makeParams());

    // Should start with OP_IF (0x63)
    expect(script[0]).toBe(0x63);

    // OP_SHA256 (0xa8) follows
    expect(script[1]).toBe(0xa8);

    // 0x20 = push 32 bytes (secret hash)
    expect(script[2]).toBe(0x20);

    // Check secret hash is embedded
    const embeddedHash = script.slice(3, 35);
    expect(bytesToHex(embeddedHash)).toBe(bytesToHex(SECRET_HASH));

    // OP_EQUALVERIFY (0x88)
    expect(script[35]).toBe(0x88);

    // OP_DUP OP_HASH160 (0x76, 0xa9)
    expect(script[36]).toBe(0x76);
    expect(script[37]).toBe(0xa9);

    // 0x14 = push 20 bytes (recipient pubkey hash)
    expect(script[38]).toBe(0x14);
    const embeddedRecipient = script.slice(39, 59);
    expect(bytesToHex(embeddedRecipient)).toBe(bytesToHex(RECIPIENT_HASH));

    // OP_ELSE (0x67)
    expect(script[59]).toBe(0x67);

    // Should end with OP_ENDIF (0x68) OP_EQUALVERIFY (0x88) OP_CHECKSIG (0xac)
    const tail = script.slice(-3);
    expect(tail[0]).toBe(0x68); // OP_ENDIF
    expect(tail[1]).toBe(0x88); // OP_EQUALVERIFY
    expect(tail[2]).toBe(0xac); // OP_CHECKSIG
  });

  it('throws on invalid secretHash length', () => {
    const params = makeParams();
    params.secretHash = new Uint8Array(16);
    expect(() => createHTLCRedeemScript(params)).toThrow('secretHash must be 32 bytes');
  });

  it('throws on invalid pubkey hash length', () => {
    const params = makeParams();
    params.recipientPubkeyHash = new Uint8Array(16);
    expect(() => createHTLCRedeemScript(params)).toThrow('recipientPubkeyHash must be 20 bytes');
  });

  it('encodes locktime correctly', () => {
    const params = makeParams();
    const script = createHTLCRedeemScript(params);
    const hex = bytesToHex(script);

    // Locktime 54000 = 0xD2F0 → little-endian bytes: F0 D2 00
    // encodeScriptNum(54000) → [0xf0, 0xd2, 0x00] (3 bytes, last byte 0x00 because high bit set)
    expect(hex).toContain('f0d200');
  });

  it('produces different scripts for different parameters', () => {
    const params1 = makeParams();
    const params2 = makeParams();
    params2.locktime = 55000;

    const script1 = createHTLCRedeemScript(params1);
    const script2 = createHTLCRedeemScript(params2);

    expect(bytesToHex(script1)).not.toBe(bytesToHex(script2));
  });
});

// ============================================================================
// P2SH Address Tests
// ============================================================================

describe('htlcToP2SHAddress', () => {
  it('generates CashAddr for BCH2', () => {
    const script = createHTLCRedeemScript(makeParams());
    const address = htlcToP2SHAddress(script, 'bch2');
    expect(address).toMatch(/^bitcoincashii:p/);
  });

  it('generates CashAddr for BCH', () => {
    const script = createHTLCRedeemScript(makeParams());
    const address = htlcToP2SHAddress(script, 'bch');
    expect(address).toMatch(/^bitcoincash:p/);
  });

  it('generates Base58 for BTC', () => {
    const script = createHTLCRedeemScript(makeParams());
    const address = htlcToP2SHAddress(script, 'btc');
    // BTC P2SH starts with '3'
    expect(address).toMatch(/^3/);
  });

  it('generates Base58 for BC2', () => {
    const script = createHTLCRedeemScript(makeParams());
    const address = htlcToP2SHAddress(script, 'bc2');
    expect(address).toMatch(/^3/);
  });

  it('same script produces same address', () => {
    const script = createHTLCRedeemScript(makeParams());
    const addr1 = htlcToP2SHAddress(script, 'bch2');
    const addr2 = htlcToP2SHAddress(script, 'bch2');
    expect(addr1).toBe(addr2);
  });
});

// ============================================================================
// createHTLC Tests
// ============================================================================

describe('createHTLC', () => {
  it('returns complete HTLC details', () => {
    const htlc = createHTLC(makeParams(), 'bch2');

    expect(htlc.redeemScript).toBeInstanceOf(Uint8Array);
    expect(htlc.p2shAddress).toBeTruthy();
    expect(htlc.p2shScriptPubKey).toBeInstanceOf(Uint8Array);
    expect(htlc.params).toEqual(makeParams());
  });

  it('p2shScriptPubKey is OP_HASH160 <hash> OP_EQUAL', () => {
    const htlc = createHTLC(makeParams(), 'btc');

    expect(htlc.p2shScriptPubKey[0]).toBe(0xa9); // OP_HASH160
    expect(htlc.p2shScriptPubKey[1]).toBe(0x14); // push 20 bytes
    expect(htlc.p2shScriptPubKey[22]).toBe(0x87); // OP_EQUAL
    expect(htlc.p2shScriptPubKey.length).toBe(23);

    // The embedded hash should be HASH160 of the redeem script
    const expectedHash = hash160(htlc.redeemScript);
    const embeddedHash = htlc.p2shScriptPubKey.slice(2, 22);
    expect(bytesToHex(embeddedHash)).toBe(bytesToHex(expectedHash));
  });
});

// ============================================================================
// Scripthash Tests
// ============================================================================

describe('htlcScripthash', () => {
  it('produces 64-char hex string (32-byte reversed SHA256)', () => {
    const script = createHTLCRedeemScript(makeParams());
    const sh = htlcScripthash(script);
    expect(sh).toMatch(/^[0-9a-f]{64}$/);
  });

  it('is consistent (same script → same scripthash)', () => {
    const script = createHTLCRedeemScript(makeParams());
    expect(htlcScripthash(script)).toBe(htlcScripthash(script));
  });

  it('different scripts → different scripthashes', () => {
    const params1 = makeParams();
    const params2 = makeParams();
    params2.locktime = 99999;
    const sh1 = htlcScripthash(createHTLCRedeemScript(params1));
    const sh2 = htlcScripthash(createHTLCRedeemScript(params2));
    expect(sh1).not.toBe(sh2);
  });
});

// ============================================================================
// Claim/Refund Transaction Tests
// ============================================================================

describe('buildHTLCClaimTx', () => {
  // Use a real keypair for signing
  const privKey = new Uint8Array(32);
  privKey[31] = 1; // minimal valid private key
  const pubKey = secp256k1.getPublicKey(privKey, true);
  const pubkeyHash = hash160(pubKey);

  const params: HTLCParams = {
    secretHash: SECRET_HASH,
    recipientPubkeyHash: pubkeyHash,
    refundPubkeyHash: REFUND_HASH,
    locktime: LOCKTIME,
  };

  const redeemScript = createHTLCRedeemScript(params);

  const utxo: Utxo = {
    tx_hash: 'a'.repeat(64),
    tx_pos: 0,
    value: 100000,
    height: 50000,
  };

  it('produces a valid claim transaction for BCH2 (BIP143)', async () => {
    const result = await buildHTLCClaimTx(
      utxo, redeemScript, SECRET, privKey, pubKey,
      new Uint8Array([0x76, 0xa9, 0x14, ...pubkeyHash, 0x88, 0xac]),
      'bch2',
    );

    expect(result.txid).toMatch(/^[0-9a-f]{64}$/);
    expect(result.rawTx).toBeTruthy();
    expect(result.rawTx.length).toBeGreaterThan(100);
  });

  it('produces a valid claim transaction for BTC (legacy sighash)', async () => {
    const result = await buildHTLCClaimTx(
      utxo, redeemScript, SECRET, privKey, pubKey,
      new Uint8Array([0x76, 0xa9, 0x14, ...pubkeyHash, 0x88, 0xac]),
      'btc',
    );

    expect(result.txid).toMatch(/^[0-9a-f]{64}$/);
    expect(result.rawTx).toBeTruthy();
  });

  it('extracted secret matches the original', async () => {
    const result = await buildHTLCClaimTx(
      utxo, redeemScript, SECRET, privKey, pubKey,
      new Uint8Array([0x76, 0xa9, 0x14, ...pubkeyHash, 0x88, 0xac]),
      'bch2',
    );

    const extracted = extractSecretFromClaimTx(result.rawTx);
    expect(extracted).not.toBeNull();
    expect(bytesToHex(extracted!)).toBe(bytesToHex(SECRET));
  });

  // R281-SEGWIT-002: a BTC/BC2 counterparty can SegWit-serialize (BIP144) their claim tx (e.g. by adding a P2WPKH
  // fee input). The preimage still lives in the P2SH input's scriptSig, so extractSecretFromClaimTx must still
  // recover it — else the responder never learns the secret and loses the funded BTC/BC2 leg. Simulate by splicing
  // the marker(0x00)+flag(0x01) right after nVersion of a legacy claim tx (the app only ever serializes legacy).
  it('recovers the secret from a SegWit-serialized (BIP144) claim tx (R281-SEGWIT-002)', async () => {
    const result = await buildHTLCClaimTx(
      utxo, redeemScript, SECRET, privKey, pubKey,
      new Uint8Array([0x76, 0xa9, 0x14, ...pubkeyHash, 0x88, 0xac]),
      'btc',
    );
    const legacy = result.rawTx;
    const segwit = legacy.slice(0, 8) + '0001' + legacy.slice(8); // nVersion(4B=8hex) || marker || flag || rest
    const extracted = extractSecretFromClaimTx(segwit);
    expect(extracted).not.toBeNull();
    expect(bytesToHex(extracted!)).toBe(bytesToHex(SECRET));
    // a marker (0x00) NOT followed by a valid flag (0x01) is malformed → null (not a false-positive extraction)
    expect(extractSecretFromClaimTx(legacy.slice(0, 8) + '0002' + legacy.slice(8))).toBeNull();
  });
});

describe('buildHTLCRefundTx', () => {
  const privKey = new Uint8Array(32);
  privKey[31] = 1;
  const pubKey = secp256k1.getPublicKey(privKey, true);
  const pubkeyHash = hash160(pubKey);

  const params: HTLCParams = {
    secretHash: SECRET_HASH,
    recipientPubkeyHash: RECIPIENT_HASH,
    refundPubkeyHash: pubkeyHash,
    locktime: LOCKTIME,
  };

  const redeemScript = createHTLCRedeemScript(params);

  const utxo: Utxo = {
    tx_hash: 'b'.repeat(64),
    tx_pos: 1,
    value: 100000,
    height: 50000,
  };

  it('produces a valid refund transaction', async () => {
    const result = await buildHTLCRefundTx(
      utxo, redeemScript, LOCKTIME, privKey, pubKey,
      new Uint8Array([0x76, 0xa9, 0x14, ...pubkeyHash, 0x88, 0xac]),
      'bch2',
    );

    expect(result.txid).toMatch(/^[0-9a-f]{64}$/);
    expect(result.rawTx).toBeTruthy();
  });

  it('refund tx does not contain the secret (returns null from extract)', async () => {
    const result = await buildHTLCRefundTx(
      utxo, redeemScript, LOCKTIME, privKey, pubKey,
      new Uint8Array([0x76, 0xa9, 0x14, ...pubkeyHash, 0x88, 0xac]),
      'bch2',
    );

    const extracted = extractSecretFromClaimTx(result.rawTx);
    // Refund tx has OP_FALSE (0x00) where secret would be, so extractSecret should return null
    expect(extracted).toBeNull();
  });
});

// ============================================================================
// buildHTLCFundingTx — fee-band regression (R125-HTLC-FUND-001)
// ============================================================================

describe('buildHTLCFundingTx fee band (R125-HTLC-FUND-001)', () => {
  const privKey = new Uint8Array(32);
  privKey[31] = 1;
  const pubKey = secp256k1.getPublicKey(privKey, true);
  const pubkeyHash = hash160(pubKey);
  const p2pkh = new Uint8Array([0x76, 0xa9, 0x14, ...pubkeyHash, 0x88, 0xac]); // 25-byte P2PKH
  const htlcScriptPubKey = new Uint8Array([0xa9, 0x14, ...new Uint8Array(20).fill(0xcc), 0x87]); // 23-byte P2SH
  // 'bc2': dustThreshold 546, feePerByte 1, legacy sighash. With 1 input:
  //   fee2 (2 outputs) = (148 + 2*34 + 10) = 226 ;  fee1 (1 output) = (148 + 34 + 10) = 192
  // FEE-DEADLINE-FIX: AMOUNT must clear bc2's minClaimableHtlcAmount floor (now 8426, sized at maxFeeRate).
  // fee1(192)/fee2(226) are 1-input constants independent of AMOUNT, so the fee-band boundary logic is unchanged.
  const AMOUNT = 9000;
  const mkInput = (value: number) => [{
    utxo: { tx_hash: 'a'.repeat(64), tx_pos: 0, value, height: 50000 } as Utxo,
    privateKey: privKey, publicKey: pubKey, scriptPubKey: p2pkh,
  }];

  it('builds a 1-output funding tx when totalIn is in the [1-output, 2-output] fee band (was falsely "Insufficient funds")', async () => {
    // totalIn = AMOUNT+210 sits in [AMOUNT+fee1(192), AMOUNT+fee2(226)): 2-output change is NEGATIVE
    // (210-226 = -16) so the old `change > 0` guard skipped the 1-output recalc and threw. Now it builds
    // with fee1 and absorbs the 18-sat leftover into the fee (actual fee = totalIn - amount = 210).
    const result = await buildHTLCFundingTx(mkInput(AMOUNT + 210), htlcScriptPubKey, AMOUNT, p2pkh, 'bc2');
    expect(result.txid).toMatch(/^[0-9a-f]{64}$/);
    expect(result.fee).toBe(210); // single HTLC output, leftover absorbed into fee
  });

  it('builds at the exact 1-output boundary (totalIn = amount + fee1)', async () => {
    const result = await buildHTLCFundingTx(mkInput(AMOUNT + 192), htlcScriptPubKey, AMOUNT, p2pkh, 'bc2');
    expect(result.fee).toBe(192);
  });

  it('still throws "Insufficient funds" when totalIn cannot cover even the 1-output fee', async () => {
    await expect(
      buildHTLCFundingTx(mkInput(AMOUNT + 191), htlcScriptPubKey, AMOUNT, p2pkh, 'bc2'),
    ).rejects.toThrow(/Insufficient funds/);
  });
});

// ============================================================================
// buildHTLCFundingTx — dual-use recipient shape guard (R132-HTLC-RECIP-001)
// ============================================================================
// The builder funds EITHER a P2SH HTLC (swap, 23B) OR a P2PKH plain send (25B). The prior strict
// `length !== 23` guard (R114-HTLC-003) broke EVERY plain UTXO send (Holdings/WalletPortfolio.sendUtxo
// pass a 25-byte P2PKH). The fix accepts both standard shapes while still rejecting corrupt scripts.
describe('buildHTLCFundingTx recipient shape (R132-HTLC-RECIP-001)', () => {
  const privKey = new Uint8Array(32); privKey[31] = 1;
  const pubKey = secp256k1.getPublicKey(privKey, true);
  const pubkeyHash = hash160(pubKey);
  const p2pkh = new Uint8Array([0x76, 0xa9, 0x14, ...pubkeyHash, 0x88, 0xac]);          // 25-byte P2PKH
  const p2sh  = new Uint8Array([0xa9, 0x14, ...new Uint8Array(20).fill(0xcc), 0x87]);   // 23-byte P2SH
  const AMOUNT = 9000; // FEE-DEADLINE-FIX: clears bc2's maxFeeRate-sized minClaimableHtlcAmount floor (8426)
  const mkInput = (value: number) => [{
    utxo: { tx_hash: 'c'.repeat(64), tx_pos: 0, value, height: 50000 } as Utxo,
    privateKey: privKey, publicKey: pubKey, scriptPubKey: p2pkh,
  }];

  it('accepts a 25-byte P2PKH recipient (plain wallet send — the R132 regression fix)', async () => {
    const r = await buildHTLCFundingTx(mkInput(AMOUNT + 100000), p2pkh, AMOUNT, p2pkh, 'bc2');
    expect(r.txid).toMatch(/^[0-9a-f]{64}$/);
  });

  it('accepts a 23-byte P2SH recipient (swap HTLC funding — preserved)', async () => {
    const r = await buildHTLCFundingTx(mkInput(AMOUNT + 100000), p2sh, AMOUNT, p2pkh, 'bc2');
    expect(r.txid).toMatch(/^[0-9a-f]{64}$/);
  });

  it('rejects a 23-byte script with a corrupt opcode shape (not a real P2SH)', async () => {
    const corrupt = new Uint8Array([0x00, 0x14, ...new Uint8Array(20).fill(0xcc), 0x87]); // wrong leading opcode
    await expect(buildHTLCFundingTx(mkInput(AMOUNT + 100000), corrupt, AMOUNT, p2pkh, 'bc2'))
      .rejects.toThrow(/standard P2SH .* or P2PKH/);
  });

  it('rejects a 25-byte script with a corrupt opcode shape (not a real P2PKH)', async () => {
    const corrupt = new Uint8Array([0x76, 0xa9, 0x14, ...pubkeyHash, 0x88, 0x00]); // wrong trailing opcode
    await expect(buildHTLCFundingTx(mkInput(AMOUNT + 100000), corrupt, AMOUNT, p2pkh, 'bc2'))
      .rejects.toThrow(/standard P2SH .* or P2PKH/);
  });

  it('rejects a non-standard length recipient script (e.g. 22 bytes)', async () => {
    const weird = new Uint8Array(22).fill(0xaa);
    await expect(buildHTLCFundingTx(mkInput(AMOUNT + 100000), weird, AMOUNT, p2pkh, 'bc2'))
      .rejects.toThrow(/got 22 bytes/);
  });
});

// ============================================================================
// parseAuthenticatedOutput — proxy-trust self-authentication (PROXY-TRUST-UTXO-VALUE-001)
// ============================================================================

describe('parseAuthenticatedOutput (PROXY-TRUST-UTXO-VALUE-001)', () => {
  const privKey = new Uint8Array(32);
  privKey[31] = 1;
  const pubKey = secp256k1.getPublicKey(privKey, true);
  const pubkeyHash = hash160(pubKey);
  const p2pkh = new Uint8Array([0x76, 0xa9, 0x14, ...pubkeyHash, 0x88, 0xac]);
  const htlcScriptPubKey = new Uint8Array([0xa9, 0x14, ...new Uint8Array(20).fill(0xcc), 0x87]); // 23-byte P2SH
  const AMOUNT = 50000;
  const mkInput = (value: number) => [{
    utxo: { tx_hash: 'b'.repeat(64), tx_pos: 0, value, height: 50000 } as Utxo,
    privateKey: privKey, publicKey: pubKey, scriptPubKey: p2pkh,
  }];

  it('authenticates a real funding tx and returns the exact output value + scriptPubKey', async () => {
    // 2 outputs: HTLC (vout 0) + change (vout 1). Authenticate vout 0.
    const funding = await buildHTLCFundingTx(mkInput(AMOUNT + 100000), htlcScriptPubKey, AMOUNT, p2pkh, 'bc2');
    const out = parseAuthenticatedOutput(funding.rawTx, funding.txid, 0);
    expect(out.value).toBe(AMOUNT);
    expect(bytesToHex(out.scriptPubKey)).toBe(bytesToHex(htlcScriptPubKey));
  });

  it('rejects tampered raw bytes (txid no longer matches)', async () => {
    const funding = await buildHTLCFundingTx(mkInput(AMOUNT + 100000), htlcScriptPubKey, AMOUNT, p2pkh, 'bc2');
    // Flip the last byte of the raw tx hex (a value/locktime byte) → different bytes → different txid.
    const tampered = funding.rawTx.slice(0, -2) + (funding.rawTx.slice(-2) === 'ff' ? '00' : 'ff');
    expect(() => parseAuthenticatedOutput(tampered, funding.txid, 0)).toThrow(/txid mismatch/);
  });

  it('rejects a wrong expectedTxid', async () => {
    const funding = await buildHTLCFundingTx(mkInput(AMOUNT + 100000), htlcScriptPubKey, AMOUNT, p2pkh, 'bc2');
    expect(() => parseAuthenticatedOutput(funding.rawTx, 'a'.repeat(64), 0)).toThrow(/txid mismatch/);
  });

  it('rejects an out-of-range voutIndex', async () => {
    const funding = await buildHTLCFundingTx(mkInput(AMOUNT + 100000), htlcScriptPubKey, AMOUNT, p2pkh, 'bc2');
    expect(() => parseAuthenticatedOutput(funding.rawTx, funding.txid, 99)).toThrow(/out of range/);
  });

  it('rejects malformed inputs (bad hex / bad txid / negative vout)', () => {
    expect(() => parseAuthenticatedOutput('', 'a'.repeat(64), 0)).toThrow(/empty/);
    expect(() => parseAuthenticatedOutput('zz', 'a'.repeat(64), 0)).toThrow();
    expect(() => parseAuthenticatedOutput('00', 'xyz', 0)).toThrow(/invalid expectedTxid/);
  });
});

// ============================================================================
// extractSecretFromClaimTx Tests
// ============================================================================

describe('extractSecretFromClaimTx', () => {
  it('returns null for empty input', () => {
    expect(extractSecretFromClaimTx('')).toBeNull();
  });

  it('returns null for garbage data', () => {
    expect(extractSecretFromClaimTx('deadbeef')).toBeNull();
  });
});

// ============================================================================
// Helper function tests
// ============================================================================

describe('hexToBytes / bytesToHex roundtrip', () => {
  it('roundtrips correctly', () => {
    const hex = 'deadbeef0123456789abcdef';
    const bytes = hexToBytes(hex);
    expect(bytesToHex(bytes)).toBe(hex);
  });

  it('handles empty', () => {
    expect(bytesToHex(hexToBytes(''))).toBe('');
  });
});

describe('hash160', () => {
  it('produces 20-byte output', () => {
    const result = hash160(new Uint8Array([1, 2, 3]));
    expect(result.length).toBe(20);
  });

  it('is deterministic', () => {
    const data = new Uint8Array([1, 2, 3, 4, 5]);
    expect(bytesToHex(hash160(data))).toBe(bytesToHex(hash160(data)));
  });
});

// ============================================================================
// R167 — timestamp CLTV locktime (responder EVM-counterparty UTXO leg)
// ============================================================================

describe('R167 timestamp CLTV locktime', () => {
  const TS_LOCKTIME = 1_900_000_000; // a Unix timestamp (~year 2030)
  const GAP_LOCKTIME = 1_000_000_000; // ambiguous gap [5e8, 1.5e9) — must be rejected
  const HEIGHT_LOCKTIME = 800_000; // a normal block height — must still work

  const privKey = new Uint8Array(32);
  privKey[31] = 7;
  const pubKey = secp256k1.getPublicKey(privKey, true);
  const pubkeyHash = hash160(pubKey);

  function paramsWith(locktime: number): HTLCParams {
    return { secretHash: SECRET_HASH, recipientPubkeyHash: RECIPIENT_HASH, refundPubkeyHash: pubkeyHash, locktime };
  }

  const utxo: Utxo = { tx_hash: 'c'.repeat(64), tx_pos: 0, value: 100000, height: 50000 };
  const destSpk = new Uint8Array([0x76, 0xa9, 0x14, ...pubkeyHash, 0x88, 0xac]);

  it('createHTLCRedeemScript accepts a unix-timestamp locktime', () => {
    expect(() => createHTLCRedeemScript(paramsWith(TS_LOCKTIME))).not.toThrow();
  });

  it('createHTLCRedeemScript still accepts a block-height locktime', () => {
    expect(() => createHTLCRedeemScript(paramsWith(HEIGHT_LOCKTIME))).not.toThrow();
  });

  it('createHTLCRedeemScript rejects the ambiguous gap [5e8, 1.5e9)', () => {
    expect(() => createHTLCRedeemScript(paramsWith(GAP_LOCKTIME))).toThrow();
  });

  it('createHTLCRedeemScript rejects 0 and negative locktimes', () => {
    expect(() => createHTLCRedeemScript(paramsWith(0))).toThrow();
    expect(() => createHTLCRedeemScript(paramsWith(-1))).toThrow();
  });

  it('buildHTLCRefundTx with a timestamp locktime sets nLockTime=timestamp and nSequence=0xfffffffe', async () => {
    const redeemScript = createHTLCRedeemScript(paramsWith(TS_LOCKTIME));
    const { rawTx } = await buildHTLCRefundTx(utxo, redeemScript, TS_LOCKTIME, privKey, pubKey, destSpk, 'bch2');
    // nLockTime is the final 4 bytes of the tx, little-endian. 1_900_000_000 = 0x713FB300 -> "00b33f71".
    expect(rawTx.slice(-8)).toBe('00b33f71');
    // nSequence 0xfffffffe little-endian appears in the input.
    expect(rawTx).toContain('feffffff');
  });

  it('buildHTLCRefundTx rejects the ambiguous gap locktime', async () => {
    const redeemScript = createHTLCRedeemScript(paramsWith(HEIGHT_LOCKTIME));
    await expect(buildHTLCRefundTx(utxo, redeemScript, GAP_LOCKTIME, privKey, pubKey, destSpk, 'bch2')).rejects.toThrow();
  });
});

// ============================================================================
// FAULT INJECTION — proxy-cannot-forge txid trust anchor
//   parseAuthenticatedOutput + swap-engine.verifyAndAuthenticateUtxo
//   Protects: htlc-builder.ts:926-933 (self-auth) + swap-engine.ts:44-53.
// The proxy supplies the UTXO's value/tx_pos and the raw parent tx. The ONLY thing
// the client already trusts is the txid (it derived the HTLC scripthash + saw the txid
// on-chain). Re-deriving txid = reverse(double-SHA256(rawTx)) and requiring it to equal
// the claimed txid means a lying proxy CANNOT hand back fabricated bytes (inflated value,
// wrong output) without breaking the hash — the code must FAIL CLOSED (throw), never sign.
// ============================================================================

describe('proxy-cannot-forge: verifyAndAuthenticateUtxo (swap-engine.ts:44 / htlc-builder.ts:928)', () => {
  // A real self-authenticating funding tx built by the SUT, funding an HTLC P2SH at vout=0.
  const privKey = new Uint8Array(32); privKey[31] = 1;
  const pubKey = secp256k1.getPublicKey(privKey, true);
  const pubkeyHash = hash160(pubKey);
  const p2pkh = new Uint8Array([0x76, 0xa9, 0x14, ...pubkeyHash, 0x88, 0xac]);

  const htlcParams: HTLCParams = {
    secretHash: SECRET_HASH,
    recipientPubkeyHash: new Uint8Array(20).fill(0x33),
    refundPubkeyHash: new Uint8Array(20).fill(0x44),
    locktime: LOCKTIME,
  };
  const htlc = createHTLCFull(htlcParams, 'bc2'); // redeemScript + 23-byte P2SH scriptPubKey
  const AMOUNT = 50000;

  async function makeFunding() {
    // vout 0 = HTLC P2SH (AMOUNT), vout 1 = change back to our own P2PKH.
    return buildHTLCFundingTx(
      [{ utxo: { tx_hash: 'e'.repeat(64), tx_pos: 0, value: AMOUNT + 100000, height: 50000 } as Utxo,
         privateKey: privKey, publicKey: pubKey, scriptPubKey: p2pkh }],
      htlc.p2shScriptPubKey, AMOUNT, p2pkh, 'bc2',
    );
  }

  it('authenticates an HONEST proxy: returns the UTXO with the on-chain-authenticated value', async () => {
    const funding = await makeFunding();
    const proxy = new MockElectrumClient({ rawTxByTxid: { [funding.txid]: funding.rawTx } });
    const proxyUtxo: Utxo = { tx_hash: funding.txid, tx_pos: 0, value: AMOUNT, height: 50000 };

    const authed = await verifyAndAuthenticateUtxo(proxyUtxo, htlc.redeemScript, (t) => proxy.getTx(t));
    expect(authed.value).toBe(AMOUNT);
    expect(authed.tx_hash).toBe(funding.txid);
    expect(authed.tx_pos).toBe(0);
  });

  it('FAILS CLOSED when a lying proxy returns rawtx whose double-SHA256 != the claimed txid', async () => {
    const funding = await makeFunding();
    // A DIFFERENT but internally-valid tx (different amount → different bytes → different txid),
    // returned by the proxy REGARDLESS of the requested txid (the classic MITM substitution).
    const other = await buildHTLCFundingTx(
      [{ utxo: { tx_hash: 'f'.repeat(64), tx_pos: 0, value: AMOUNT + 999 + 100000, height: 50000 } as Utxo,
         privateKey: privKey, publicKey: pubKey, scriptPubKey: p2pkh }],
      htlc.p2shScriptPubKey, AMOUNT + 999, p2pkh, 'bc2',
    );
    const proxy = new MockElectrumClient().setLyingRawTx(other.rawTx);
    const proxyUtxo: Utxo = { tx_hash: funding.txid, tx_pos: 0, value: 9_999_999, height: 50000 };

    await expect(verifyAndAuthenticateUtxo(proxyUtxo, htlc.redeemScript, (t) => proxy.getTx(t)))
      .rejects.toThrow(/txid mismatch/);
  });

  it('FAILS CLOSED when the proxy flips a single byte of the honest rawtx (bit-flip → txid breaks)', async () => {
    const funding = await makeFunding();
    const tampered = funding.rawTx.slice(0, -2) + (funding.rawTx.slice(-2) === 'ff' ? '00' : 'ff');
    const proxy = new MockElectrumClient().setLyingRawTx(tampered);
    const proxyUtxo: Utxo = { tx_hash: funding.txid, tx_pos: 0, value: AMOUNT, height: 50000 };

    await expect(verifyAndAuthenticateUtxo(proxyUtxo, htlc.redeemScript, (t) => proxy.getTx(t)))
      .rejects.toThrow(/txid mismatch/);
  });

  it('FAILS CLOSED when the txid matches but the funded output is NOT the expected HTLC P2SH (wrong tx_pos)', async () => {
    // Point tx_pos at the CHANGE output (vout 1, a P2PKH) instead of the HTLC (vout 0).
    // Self-auth (txid) passes, but swap-engine.ts:48 rejects the scriptPubKey mismatch.
    const funding = await makeFunding();
    const proxy = new MockElectrumClient({ rawTxByTxid: { [funding.txid]: funding.rawTx } });
    const proxyUtxo: Utxo = { tx_hash: funding.txid, tx_pos: 1, value: 0, height: 50000 };

    await expect(verifyAndAuthenticateUtxo(proxyUtxo, htlc.redeemScript, (t) => proxy.getTx(t)))
      .rejects.toThrow(/does not match the HTLC P2SH/);
  });

  it('FAILS CLOSED on a malformed proxy tx_hash (rejected before any network read)', async () => {
    const proxy = new MockElectrumClient().setLyingRawTx('00'); // never even consulted
    const proxyUtxo = { tx_hash: 'NOT-A-TXID', tx_pos: 0, value: AMOUNT, height: 50000 } as unknown as Utxo;
    await expect(verifyAndAuthenticateUtxo(proxyUtxo, htlc.redeemScript, (t) => proxy.getTx(t)))
      .rejects.toThrow(/malformed UTXO tx_hash/);
  });

  it('FAILS CLOSED on a malformed proxy tx_pos (negative / non-integer)', async () => {
    const proxy = new MockElectrumClient().setLyingRawTx('00');
    const bad: Utxo = { tx_hash: 'a'.repeat(64), tx_pos: -1, value: AMOUNT, height: 50000 };
    await expect(verifyAndAuthenticateUtxo(bad, htlc.redeemScript, (t) => proxy.getTx(t)))
      .rejects.toThrow(/malformed UTXO tx_pos/);
  });

  it('FAILS CLOSED when the proxy is unreachable (getTx throws — no value ever authenticated)', async () => {
    const proxy = new MockElectrumClient({ getTxThrows: true });
    const proxyUtxo: Utxo = { tx_hash: 'a'.repeat(64), tx_pos: 0, value: AMOUNT, height: 50000 };
    await expect(verifyAndAuthenticateUtxo(proxyUtxo, htlc.redeemScript, (t) => proxy.getTx(t)))
      .rejects.toThrow(/unreachable/);
  });
});

// ============================================================================
// FAULT INJECTION — verifyAndAuthenticateP2pkhInput (swap-engine.ts:74-98)
//   Legacy (btc/bc2, useBip143=false) sighash does NOT commit the input value, so a
//   lying listunspent value → a VALID sig that silently burns the difference to fees.
//   This authenticates the funding-INPUT value against its own parent tx. Must FAIL CLOSED.
// ============================================================================

describe('verifyAndAuthenticateP2pkhInput (R260-INPUT-VALUE-AUTH-001, swap-engine.ts:74)', () => {
  const privKey = new Uint8Array(32); privKey[31] = 1;
  const pubKey = secp256k1.getPublicKey(privKey, true);
  const ownHash = hash160(pubKey);
  const ownP2pkh = new Uint8Array([0x76, 0xa9, 0x14, ...ownHash, 0x88, 0xac]);
  const AMOUNT = 40000;

  async function makeParentPayingSelf() {
    // A parent tx whose vout 0 pays OUR own P2PKH (the input we later spend). Self-authenticating.
    return buildHTLCFundingTx(
      [{ utxo: { tx_hash: '1'.repeat(64), tx_pos: 0, value: AMOUNT + 100000, height: 50000 } as Utxo,
         privateKey: privKey, publicKey: pubKey, scriptPubKey: ownP2pkh }],
      ownP2pkh, AMOUNT, ownP2pkh, 'bc2', // recipient (vout0) = own 25-byte P2PKH
    );
  }

  it('authenticates the input value against the parent tx (HONEST proxy)', async () => {
    const parent = await makeParentPayingSelf();
    const proxy = new MockElectrumClient({ rawTxByTxid: { [parent.txid]: parent.rawTx } });
    // Proxy LIES about the value (claims 9,999,999) — the function must return the AUTHENTICATED value.
    const proxyUtxo: Utxo = { tx_hash: parent.txid, tx_pos: 0, value: 9_999_999, height: 50000 };
    const authed = await verifyAndAuthenticateP2pkhInput(proxyUtxo, ownHash, (t) => proxy.getTx(t));
    expect(authed.value).toBe(AMOUNT); // NOT the proxy's inflated 9,999,999
  });

  it('FAILS CLOSED when the parent output is NOT our own P2PKH (wrong pubkeyHash / foreign input)', async () => {
    const parent = await makeParentPayingSelf();
    const proxy = new MockElectrumClient({ rawTxByTxid: { [parent.txid]: parent.rawTx } });
    const proxyUtxo: Utxo = { tx_hash: parent.txid, tx_pos: 0, value: AMOUNT, height: 50000 };
    const foreignHash = new Uint8Array(20).fill(0x99);
    await expect(verifyAndAuthenticateP2pkhInput(proxyUtxo, foreignHash, (t) => proxy.getTx(t)))
      .rejects.toThrow(/does not match the expected own-address P2PKH/);
  });

  it('FAILS CLOSED on a lying rawtx (txid mismatch)', async () => {
    const parent = await makeParentPayingSelf();
    const other = await makeParentPayingSelf(); // NOTE: identical bytes → same txid; force a mismatch instead
    const proxy = new MockElectrumClient().setLyingRawTx(other.rawTx.slice(0, -2) + 'ab');
    const proxyUtxo: Utxo = { tx_hash: parent.txid, tx_pos: 0, value: AMOUNT, height: 50000 };
    await expect(verifyAndAuthenticateP2pkhInput(proxyUtxo, ownHash, (t) => proxy.getTx(t)))
      .rejects.toThrow(/txid mismatch|not valid hex/);
  });

  it('FAILS CLOSED on a non-20-byte expectedPubkeyHash (caller-supplied invariant)', async () => {
    const parent = await makeParentPayingSelf();
    const proxy = new MockElectrumClient({ rawTxByTxid: { [parent.txid]: parent.rawTx } });
    const proxyUtxo: Utxo = { tx_hash: parent.txid, tx_pos: 0, value: AMOUNT, height: 50000 };
    await expect(verifyAndAuthenticateP2pkhInput(proxyUtxo, new Uint8Array(19), (t) => proxy.getTx(t)))
      .rejects.toThrow(/must be 20 bytes/);
  });
});

// ============================================================================
// parseAuthenticatedOutput — vout selection + R278 #13 segwit-parent KNOWN GAP
//   htlc-builder.ts:903-991. Documents the current fail-closed behavior on a
//   witness-serialized parent tx (a real risk for BTC legs).
// ============================================================================

describe('parseAuthenticatedOutput vout selection + segwit-parent gap (R278 #13)', () => {
  // Build a lightweight self-authenticating raw tx directly with the mock helper so we
  // control the exact output layout, then authenticate specific vouts.
  const spk0 = p2shScriptPubKeyHex('aa'.repeat(20)); // vout 0: P2SH
  const spk1 = '76a914' + 'bb'.repeat(20) + '88ac';   // vout 1: P2PKH
  const built = buildUtxoRawTx([
    { value: 12345, scriptPubKeyHex: spk0 },
    { value: 67890, scriptPubKeyHex: spk1 },
  ]);

  it('returns the exact value+scriptPubKey for vout 0', () => {
    const out = parseAuthenticatedOutput(built.rawTxHex, built.txid, 0);
    expect(out.value).toBe(12345);
    expect(bytesToHex(out.scriptPubKey)).toBe(spk0);
  });

  it('returns the exact value+scriptPubKey for vout 1 (index selection is honored)', () => {
    const out = parseAuthenticatedOutput(built.rawTxHex, built.txid, 1);
    expect(out.value).toBe(67890);
    expect(bytesToHex(out.scriptPubKey)).toBe(spk1);
  });

  // R281-SEGWIT-001 (was R278 #13, previously a KNOWN GAP): a real SegWit-serialized parent tx now authenticates
  // against the TXID computed over the stripped legacy serialization — NOT the wtxid. Fixture is a real BitcoinII
  // (BC2) regtest funding parent (673 inputs, 2 outputs, BIP144 marker/flag 0x0001) whose txid 65d84b25… differs
  // from its wtxid 0f16b69f… . This is the exact tx that produced the live "txid mismatch" before the fix.
  const segwitHex   = readFileSync(new URL('./fixtures/bc2-segwit-parent.hex', import.meta.url), 'utf8').trim();
  const segwitTxid  = '65d84b25e5962c1f296270d8f75bb569f66b82f1510d7196b2f3a5e7925bf3d2';
  const segwitWtxid = '0f16b69f93ac0e19a8d14c99aaae9c636a21d0258a22db8cf0783e7767821e1a';

  it('R281 #13 FIXED: SegWit parent — vout 0 value+spk authenticate against the txid (not the wtxid)', () => {
    const out = parseAuthenticatedOutput(segwitHex, segwitTxid, 0);
    expect(out.value).toBe(76737520);
    expect(bytesToHex(out.scriptPubKey)).toBe('76a91494d8fe9208124e7bc83bce134e5fc66e443448be88ac');
  });

  it('R281 #13 FIXED: SegWit parent — vout 1 (index selection honored on witness-serialized tx)', () => {
    const out = parseAuthenticatedOutput(segwitHex, segwitTxid, 1);
    expect(out.value).toBe(40700000000);
    expect(bytesToHex(out.scriptPubKey)).toBe('76a914114021694a504946237c6441816c915e1454388888ac');
  });

  it('R281: passing the wtxid (what the OLD code hashed to) is still REJECTED — guarantee binds to the txid', () => {
    expect(() => parseAuthenticatedOutput(segwitHex, segwitWtxid, 0)).toThrow(/txid mismatch/);
  });

  it('R281: a SegWit marker without a valid flag byte is rejected as malformed', () => {
    // version || marker 0x00 || flag 0x02 (invalid) || ...
    expect(() => parseAuthenticatedOutput('0100000000020100000000', 'a'.repeat(64), 0))
      .toThrow(/SegWit marker.*without a valid flag/);
  });
});

// ============================================================================
// R277 — createHTLCRedeemScript INJECTIVITY (a tampered param can't collide the P2SH)
//   htlc-builder.ts:259-298 + :303 (htlcToP2SHAddress) + :331 (p2shScriptPubKey).
//   Load-bearing property behind R277: the P2SH commits to EVERY HTLC parameter, so an
//   attacker cannot swap in a different secretHash/recipient/refund/locktime and still hit
//   the SAME on-chain address the counterparty funded.
// ============================================================================

describe('R277 createHTLCRedeemScript injectivity (P2SH commits to every param)', () => {
  const base: HTLCParams = {
    secretHash: new Uint8Array(32).fill(0x11),
    recipientPubkeyHash: new Uint8Array(20).fill(0x22),
    refundPubkeyHash: new Uint8Array(20).fill(0x33),
    locktime: 600_000,
  };

  const p2shHexOf = (p: HTLCParams) => bytesToHex(createHTLCFull(p, 'bc2').p2shScriptPubKey);
  const addrOf = (p: HTLCParams) => htlcToP2SHAddressFn(createHTLCRedeemScript(p), 'bch2');

  const variants: Array<[string, HTLCParams]> = [
    ['secretHash', { ...base, secretHash: new Uint8Array(32).fill(0x12) }],
    ['recipientPubkeyHash', { ...base, recipientPubkeyHash: new Uint8Array(20).fill(0x23) }],
    ['refundPubkeyHash', { ...base, refundPubkeyHash: new Uint8Array(20).fill(0x34) }],
    ['locktime', { ...base, locktime: 600_001 }],
  ];

  const baseScript = bytesToHex(createHTLCRedeemScript(base));
  const baseP2SH = p2shHexOf(base);
  const baseAddr = addrOf(base);

  for (const [field, mutated] of variants) {
    it(`differs in redeemScript, P2SH scriptPubKey AND address when only ${field} changes`, () => {
      expect(bytesToHex(createHTLCRedeemScript(mutated))).not.toBe(baseScript);
      expect(p2shHexOf(mutated)).not.toBe(baseP2SH);
      expect(addrOf(mutated)).not.toBe(baseAddr);
    });
  }

  it('a single-bit flip in secretHash yields a different P2SH (no near-collision)', () => {
    const flipped = { ...base, secretHash: base.secretHash.slice() };
    flipped.secretHash[31] ^= 0x01;
    expect(p2shHexOf(flipped)).not.toBe(baseP2SH);
  });

  it('identical params reproduce the SAME P2SH (determinism — the honest-funding path)', () => {
    expect(p2shHexOf({ ...base })).toBe(baseP2SH);
    expect(addrOf({ ...base })).toBe(baseAddr);
  });
});

// ============================================================================
// buildHTLCClaimTx / buildHTLCRefundTx — nLockTime/nSequence + fee-vs-output invariants
//   htlc-builder.ts:595-632 (claim), :715-751 (refund).
//   The claim branch must NOT set CLTV (nSequence=0xffffffff, nLockTime=0); the refund
//   branch MUST (nSequence=0xfffffffe, nLockTime=locktime). And every spend output must be
//   strictly less than the UTXO value (fee is really deducted) yet still above dust.
// ============================================================================

describe('claim/refund nLockTime + nSequence + fee-vs-output invariants', () => {
  const privKey = new Uint8Array(32); privKey[31] = 1;
  const pubKey = secp256k1.getPublicKey(privKey, true);
  const pubkeyHash = hash160(pubKey);
  const destSpk = new Uint8Array([0x76, 0xa9, 0x14, ...pubkeyHash, 0x88, 0xac]);

  const params: HTLCParams = {
    secretHash: SECRET_HASH,
    recipientPubkeyHash: pubkeyHash,
    refundPubkeyHash: new Uint8Array(20).fill(0xbb),
    locktime: LOCKTIME, // 54000 (block height)
  };
  const redeemScript = createHTLCRedeemScript(params);
  const utxo: Utxo = { tx_hash: 'a'.repeat(64), tx_pos: 0, value: 100000, height: 50000 };

  it('CLAIM sets nLockTime=0 and the spend output < UTXO value (fee deducted, > dust)', async () => {
    const { rawTx, txid } = await buildHTLCClaimTx(utxo, redeemScript, SECRET, privKey, pubKey, destSpk, 'bch2');
    expect(rawTx.slice(-8)).toBe('00000000'); // nLockTime = 0
    expect(rawTx).toContain('ffffffff');       // claim nSequence = 0xffffffff (no CLTV opt-in)
    const out = parseAuthenticatedOutput(rawTx, txid, 0);
    expect(out.value).toBeGreaterThan(0);
    expect(out.value).toBeLessThan(utxo.value); // fee really came out of the UTXO
  });

  const refundParams: HTLCParams = {
    secretHash: SECRET_HASH,
    recipientPubkeyHash: new Uint8Array(20).fill(0xcc),
    refundPubkeyHash: pubkeyHash,
    locktime: LOCKTIME,
  };
  const refundRedeem = createHTLCRedeemScript(refundParams);
  const refundUtxo: Utxo = { tx_hash: 'b'.repeat(64), tx_pos: 0, value: 100000, height: 50000 };

  it('REFUND sets nLockTime=locktime and nSequence=0xfffffffe (CLTV-enforcing)', async () => {
    const { rawTx, txid } = await buildHTLCRefundTx(refundUtxo, refundRedeem, LOCKTIME, privKey, pubKey, destSpk, 'bch2');
    // 54000 = 0x0000D2F0 → LE last 4 bytes "f0d20000"
    expect(rawTx.slice(-8)).toBe('f0d20000');
    expect(rawTx).toContain('feffffff'); // nSequence 0xfffffffe
    const out = parseAuthenticatedOutput(rawTx, txid, 0);
    expect(out.value).toBeGreaterThan(0);
    expect(out.value).toBeLessThan(refundUtxo.value);
  });

  it('CLAIM refuses to build when the fee would exceed the UTXO value (fee-vs-value guard)', async () => {
    const tiny: Utxo = { tx_hash: 'a'.repeat(64), tx_pos: 0, value: 100, height: 50000 };
    await expect(buildHTLCClaimTx(tiny, redeemScript, SECRET, privKey, pubKey, destSpk, 'bch2'))
      .rejects.toThrow(/exceed UTXO value|too small/);
  });

  it('REFUND refuses to build when the fee would exceed the UTXO value', async () => {
    const tiny: Utxo = { tx_hash: 'b'.repeat(64), tx_pos: 0, value: 100, height: 50000 };
    await expect(buildHTLCRefundTx(tiny, refundRedeem, LOCKTIME, privKey, pubKey, destSpk, 'bch2'))
      .rejects.toThrow(/exceed UTXO value|too small/);
  });

  it('CLAIM clamps a too-high fee rate DOWN to what a below-floor utxo can afford, instead of throwing (review #1)', async () => {
    // A legacy leg funded below the new maxFeeRate-sized floor: value 5000 sat with a ramped 100 sat/vB rate
    // would compute fee ≫ value and throw fee>=value forever. The affordability clamp caps the rate so it still
    // builds a VALID, non-dust claim (confirming at a lower fee beats a claim that can never build).
    const small: Utxo = { tx_hash: 'a'.repeat(64), tx_pos: 0, value: 5000, height: 50000 };
    const { rawTx, txid } = await buildHTLCClaimTx(small, redeemScript, SECRET, privKey, pubKey, destSpk, 'bch2', 100);
    const out = parseAuthenticatedOutput(rawTx, txid, 0);
    expect(out.value).toBeGreaterThanOrEqual(182); // >= bch2 dust: the clamp built a valid tx instead of throwing
    expect(out.value).toBeLessThan(small.value);   // a real fee was deducted
  });

  it('REFUND clamps a too-high fee rate DOWN for a below-floor utxo (mirror of claim, review #1)', async () => {
    const small: Utxo = { tx_hash: 'b'.repeat(64), tx_pos: 0, value: 5000, height: 50000 };
    const { rawTx, txid } = await buildHTLCRefundTx(small, refundRedeem, LOCKTIME, privKey, pubKey, destSpk, 'bch2', 100);
    const out = parseAuthenticatedOutput(rawTx, txid, 0);
    expect(out.value).toBeGreaterThanOrEqual(182);
    expect(out.value).toBeLessThan(small.value);
  });

  it('CLAIM rejects a non-32-byte secret (a truncated/forged preimage never signs)', async () => {
    await expect(buildHTLCClaimTx(utxo, redeemScript, new Uint8Array(31), privKey, pubKey, destSpk, 'bch2'))
      .rejects.toThrow(/secret must be exactly 32 bytes/);
  });
});

// ============================================================================
// extractSecretFromClaimTx — round-trip + hash-binding fault injection
//   htlc-builder.ts:760-884. The watcher extracts the counterparty's secret from
//   their broadcast claim; a wrong expectedSecretHash MUST reject (never leak a false secret).
// ============================================================================

describe('extractSecretFromClaimTx round-trip + hash binding', () => {
  const privKey = new Uint8Array(32); privKey[31] = 1;
  const pubKey = secp256k1.getPublicKey(privKey, true);
  const pubkeyHash = hash160(pubKey);
  const destSpk = new Uint8Array([0x76, 0xa9, 0x14, ...pubkeyHash, 0x88, 0xac]);
  const params: HTLCParams = {
    secretHash: SECRET_HASH,
    recipientPubkeyHash: pubkeyHash,
    refundPubkeyHash: new Uint8Array(20).fill(0xbb),
    locktime: LOCKTIME,
  };
  const redeemScript = createHTLCRedeemScript(params);
  const utxo: Utxo = { tx_hash: 'a'.repeat(64), tx_pos: 0, value: 100000, height: 50000 };

  it('extracts the secret from a real claim tx and it hashes to the HTLC secretHash', async () => {
    const { rawTx } = await buildHTLCClaimTx(utxo, redeemScript, SECRET, privKey, pubKey, destSpk, 'bch2');
    const got = extractSecretFromClaimTx(rawTx);
    expect(got).not.toBeNull();
    expect(bytesToHex(got!)).toBe(bytesToHex(SECRET));
    expect(bytesToHex(sha256(got!))).toBe(bytesToHex(SECRET_HASH));
  });

  it('accepts the secret when the expectedSecretHash matches', async () => {
    const { rawTx } = await buildHTLCClaimTx(utxo, redeemScript, SECRET, privKey, pubKey, destSpk, 'bch2');
    const got = extractSecretFromClaimTx(rawTx, bytesToHex(SECRET_HASH));
    expect(got).not.toBeNull();
    expect(bytesToHex(got!)).toBe(bytesToHex(SECRET));
  });

  it('REJECTS (returns null) when expectedSecretHash does not match — no false secret leaked', async () => {
    const { rawTx } = await buildHTLCClaimTx(utxo, redeemScript, SECRET, privKey, pubKey, destSpk, 'bch2');
    const wrongHash = new Uint8Array(32).fill(0x00);
    expect(extractSecretFromClaimTx(rawTx, wrongHash)).toBeNull();
  });

  it('returns null (not a throw) for a malformed expectedSecretHash hex — honors the null-on-failure contract', async () => {
    const { rawTx } = await buildHTLCClaimTx(utxo, redeemScript, SECRET, privKey, pubKey, destSpk, 'bch2');
    expect(extractSecretFromClaimTx(rawTx, 'zz')).toBeNull(); // odd/non-hex → rejected, not thrown
  });
});

// ============================================================================
// FAULT INJECTION — parseAuthenticatedOutput INTERNAL parse guards (self-auth passes)
//   htlc-builder.ts:935-990. Every one of these malformed raw-tx shapes has a VALID
//   self-authenticating txid (we hash the exact crafted bytes), so the txid check on
//   :928 passes — proving the parse itself FAILS CLOSED on structurally broken bytes a
//   compromised proxy could hand back INSTEAD of relying on the txid gate alone.
// ============================================================================

describe('parseAuthenticatedOutput internal parse guards (htlc-builder.ts:935-990)', () => {
  // Compute the TRUE txid (reverse(double-SHA256)) over arbitrary crafted bytes so the
  // self-auth on :928 always passes and we reach the internal structural guards.
  const selfTxid = (hex: string) => bytesToHex(sha256(sha256(hexToBytes(hex))).slice().reverse());
  const authThrow = (hex: string, re: RegExp) =>
    expect(() => parseAuthenticatedOutput(hex, selfTxid(hex), 0)).toThrow(re);

  it('rejects an implausible input count (>100000) — :944', () => {
    // version || varint 0xfe 200000 (LE 400d0300) || pad. inCount = 200000 > 100000.
    authThrow('02000000' + 'fe400d0300' + '00', /implausible input count/);
  });

  it('rejects a truncated input-count varint (0xff with no following bytes) — :939', () => {
    // 0xff signals an 8-byte varint but readVarInt returns null for it → truncated input count.
    authThrow('02000000' + 'ff' + '0000000000', /truncated input count/);
  });

  it('rejects a truncated output count (input parsed, then tx ends) — :956', () => {
    // version + inCount=1 + one empty-scriptSig input + NO output-count byte.
    authThrow('02000000' + '01' + '00'.repeat(36) + '00' + 'ffffffff', /truncated output count/);
  });

  it('rejects a truncated output value (outCount=1 but < 8 value bytes) — :966', () => {
    authThrow('02000000' + '01' + '00'.repeat(36) + '00' + 'ffffffff' + '01', /truncated output value/);
  });

  it('rejects an output value that exceeds MAX_SAFE_INTEGER (8×0xff) — :972', () => {
    authThrow(
      '02000000' + '01' + '00'.repeat(36) + '00' + 'ffffffff' + '01' + 'ffffffffffffffff' + '00',
      /exceeds MAX_SAFE_INTEGER/,
    );
  });

  it('rejects a scriptPubKey length that overruns the tx (claims 5 bytes, supplies 1) — :978', () => {
    authThrow(
      '02000000' + '01' + '00'.repeat(36) + '00' + 'ffffffff' + '01' + 'e803000000000000' + '05' + '01',
      /scriptPubKey overruns tx/,
    );
  });

  it('rejects a well-formed tx whose selected output has a non-positive (zero) value — :988', () => {
    const spk = p2shScriptPubKeyHex('cc'.repeat(20));
    const built = buildUtxoRawTx([{ value: 0, scriptPubKeyHex: spk }]);
    expect(() => parseAuthenticatedOutput(built.rawTxHex, built.txid, 0)).toThrow(/non-positive value/);
  });

  it('rejects raw tx bytes shorter than the 10-byte minimum — :924', () => {
    // 8 hex = 4 bytes < 10; self-auth passes (we hash those 4 bytes) then the length guard fires.
    authThrow('02000000', /too short/);
  });

  it('accepts an UPPERCASE expectedTxid (self-auth is case-insensitive) — :928', () => {
    const spk = p2shScriptPubKeyHex('ab'.repeat(20));
    const built = buildUtxoRawTx([{ value: 4321, scriptPubKeyHex: spk }]);
    const out = parseAuthenticatedOutput(built.rawTxHex, built.txid.toUpperCase(), 0);
    expect(out.value).toBe(4321);
    expect(bytesToHex(out.scriptPubKey)).toBe(spk);
  });
});

// ============================================================================
// FAULT INJECTION — verifyAndAuthenticateUtxo IGNORES the proxy's claimed value
//   swap-engine.ts:45-60. The load-bearing anti-fee-burn property for the HTLC leg:
//   even when the proxy INFLATES (or deflates) listunspent `value`, the returned UTXO
//   carries the ON-CHAIN-AUTHENTICATED value parsed from the honest raw tx, NOT the
//   proxy's number. (On legacy chains the sighash does not commit the input value, so
//   trusting the proxy's value would silently burn the difference to fees.)
// ============================================================================

describe('verifyAndAuthenticateUtxo uses the authenticated value, not the proxy value (swap-engine.ts:45)', () => {
  const privKey = new Uint8Array(32); privKey[31] = 1;
  const pubKey = secp256k1.getPublicKey(privKey, true);
  const pubkeyHash = hash160(pubKey);
  const p2pkh = new Uint8Array([0x76, 0xa9, 0x14, ...pubkeyHash, 0x88, 0xac]);
  const htlc = createHTLCFull({
    secretHash: SECRET_HASH,
    recipientPubkeyHash: new Uint8Array(20).fill(0x33),
    refundPubkeyHash: new Uint8Array(20).fill(0x44),
    locktime: LOCKTIME,
  }, 'bc2');
  const AMOUNT = 50000;
  const makeFunding = () => buildHTLCFundingTx(
    [{ utxo: { tx_hash: 'e'.repeat(64), tx_pos: 0, value: AMOUNT + 100000, height: 50000 } as Utxo,
       privateKey: privKey, publicKey: pubKey, scriptPubKey: p2pkh }],
    htlc.p2shScriptPubKey, AMOUNT, p2pkh, 'bc2',
  );

  it('returns the on-chain value even when the proxy INFLATES listunspent value (fee-burn defense)', async () => {
    const funding = await makeFunding();
    const proxy = new MockElectrumClient({ rawTxByTxid: { [funding.txid]: funding.rawTx } });
    const proxyUtxo: Utxo = { tx_hash: funding.txid, tx_pos: 0, value: 9_999_999, height: 50000 };
    const authed = await verifyAndAuthenticateUtxo(proxyUtxo, htlc.redeemScript, (t) => proxy.getTx(t));
    expect(authed.value).toBe(AMOUNT);          // authenticated, NOT the proxy's 9,999,999
    expect(authed.value).not.toBe(9_999_999);
  });

  it('returns the on-chain value even when the proxy DEFLATES listunspent value', async () => {
    const funding = await makeFunding();
    const proxy = new MockElectrumClient({ rawTxByTxid: { [funding.txid]: funding.rawTx } });
    const proxyUtxo: Utxo = { tx_hash: funding.txid, tx_pos: 0, value: 1, height: 50000 };
    const authed = await verifyAndAuthenticateUtxo(proxyUtxo, htlc.redeemScript, (t) => proxy.getTx(t));
    expect(authed.value).toBe(AMOUNT);
  });
});

// ============================================================================
// createHTLCRedeemScript — degenerate same-party guard (R72-HT-001, htlc-builder.ts:266)
//   If recipientPubkeyHash === refundPubkeyHash, ONE party can satisfy BOTH branches
//   (claim without the secret AND refund), collapsing the atomicity of the swap. Must throw.
// ============================================================================

describe('createHTLCRedeemScript degenerate same-party guard (R72-HT-001)', () => {
  it('throws when recipientPubkeyHash === refundPubkeyHash', () => {
    const same = new Uint8Array(20).fill(0x77);
    expect(() => createHTLCRedeemScript({
      secretHash: SECRET_HASH,
      recipientPubkeyHash: same,
      refundPubkeyHash: same.slice(), // equal bytes, distinct object
      locktime: LOCKTIME,
    })).toThrow(/must differ/);
  });

  it('accepts recipient/refund that differ by a single byte', () => {
    const a = new Uint8Array(20).fill(0x77);
    const b = a.slice(); b[19] ^= 0x01;
    expect(() => createHTLCRedeemScript({
      secretHash: SECRET_HASH, recipientPubkeyHash: a, refundPubkeyHash: b, locktime: LOCKTIME,
    })).not.toThrow();
  });
});

// ============================================================================
// isValidLocktime / isTimestampLocktime — exact boundary table (R167, htlc-builder.ts:249-257)
//   Direct unit coverage of the height/timestamp classifier the redeem-script + refund
//   builders both gate on. The ambiguous gap [5e8, 1.5e9) and the 2^31 ceiling must reject.
// ============================================================================

describe('isValidLocktime / isTimestampLocktime boundaries (R167)', () => {
  it('accepts block heights in (0, LOCKTIME_HEIGHT_MAX)', () => {
    expect(isValidLocktime(1)).toBe(true);
    expect(isValidLocktime(LOCKTIME_HEIGHT_MAX - 1)).toBe(true);
  });

  it('rejects the ambiguous gap [LOCKTIME_HEIGHT_MAX, LOCKTIME_TS_MIN)', () => {
    expect(isValidLocktime(LOCKTIME_HEIGHT_MAX)).toBe(false);       // 5e8 — neither height nor ts
    expect(isValidLocktime(LOCKTIME_TS_MIN - 1)).toBe(false);       // just under the ts floor
  });

  it('accepts Unix timestamps in [LOCKTIME_TS_MIN, LOCKTIME_TS_MAX)', () => {
    expect(isValidLocktime(LOCKTIME_TS_MIN)).toBe(true);
    expect(isValidLocktime(LOCKTIME_TS_MAX - 1)).toBe(true);
  });

  it('rejects the 2^31 ceiling and above (clean uint32 CScriptNum cap)', () => {
    expect(isValidLocktime(LOCKTIME_TS_MAX)).toBe(false);
  });

  it('rejects zero, negatives, and non-integers', () => {
    expect(isValidLocktime(0)).toBe(false);
    expect(isValidLocktime(-1)).toBe(false);
    expect(isValidLocktime(1.5)).toBe(false);
    expect(isValidLocktime(NaN)).toBe(false);
    expect(isValidLocktime(Infinity)).toBe(false);
  });

  it('isTimestampLocktime classifies at the 5e8 threshold', () => {
    expect(isTimestampLocktime(LOCKTIME_HEIGHT_MAX - 1)).toBe(false);
    expect(isTimestampLocktime(LOCKTIME_HEIGHT_MAX)).toBe(true);
    expect(isTimestampLocktime(LOCKTIME_TS_MIN)).toBe(true);
  });
});

// ============================================================================
// buildHTLCFundingTx — input/amount fault injection + fee-aware floor (R146-FEE-FLOOR-001)
//   htlc-builder.ts:362-425. Malformed amounts and empty inputs must FAIL CLOSED before any
//   signing, and an amount below the CLAIMABLE floor must be rejected (never fund an HTLC that
//   can be funded but never claimed — the asymmetric-griefing / stranded-funds class).
// ============================================================================

describe('buildHTLCFundingTx input/amount fault injection + fee floor (R146-FEE-FLOOR-001)', () => {
  const privKey = new Uint8Array(32); privKey[31] = 1;
  const pubKey = secp256k1.getPublicKey(privKey, true);
  const pubkeyHash = hash160(pubKey);
  const p2pkh = new Uint8Array([0x76, 0xa9, 0x14, ...pubkeyHash, 0x88, 0xac]);
  const p2sh = new Uint8Array([0xa9, 0x14, ...new Uint8Array(20).fill(0xcc), 0x87]);
  const mkInput = (value: number) => [{
    utxo: { tx_hash: 'a'.repeat(64), tx_pos: 0, value, height: 50000 } as Utxo,
    privateKey: privKey, publicKey: pubKey, scriptPubKey: p2pkh,
  }];

  it('throws when no inputs are provided (no spendable UTXOs) — :389', async () => {
    await expect(buildHTLCFundingTx([], p2sh, 5000, p2pkh, 'bc2'))
      .rejects.toThrow(/no inputs provided/);
  });

  it('throws on a NaN / Infinity / negative / zero amount — :394', async () => {
    for (const bad of [NaN, Infinity, -1, 0, 1.5]) {
      await expect(buildHTLCFundingTx(mkInput(100000), p2sh, bad, p2pkh, 'bc2'))
        .rejects.toThrow(/amount must be a positive integer/);
    }
  });

  it('throws when the amount is below the fee-aware claimable floor — :420', async () => {
    const floor = minClaimableHtlcAmount('bc2');
    await expect(buildHTLCFundingTx(mkInput(floor + 100000), p2sh, floor - 1, p2pkh, 'bc2'))
      .rejects.toThrow(/below the minimum claimable/);
  });

  it('builds at exactly the claimable floor (boundary is inclusive)', async () => {
    const floor = minClaimableHtlcAmount('bc2');
    const r = await buildHTLCFundingTx(mkInput(floor + 100000), p2sh, floor, p2pkh, 'bc2');
    expect(r.txid).toMatch(/^[0-9a-f]{64}$/);
  });
});

describe('minClaimableHtlcAmount fee-aware floor (R146-FEE-FLOOR-001)', () => {
  it('bc2 floor is sized at maxFeeRate (worst-case claim fee, 20 sat/B → 8426), above the old dustThreshold*5', () => {
    // FEE-DEADLINE-FIX: the floor now guarantees claimability even when the claim fee ramps to maxFeeRate,
    // so it exceeds the historical flat dustThreshold*5 (2730) even on a 1-sat/B chain.
    expect(minClaimableHtlcAmount('bc2')).toBe(8426);
    expect(minClaimableHtlcAmount('bc2')).toBeGreaterThan(546 * 5);
  });

  it('btc (10 sat/B) floor rises above the bc2 floor (claim fee dominates)', () => {
    expect(minClaimableHtlcAmount('btc')).toBeGreaterThan(minClaimableHtlcAmount('bc2'));
    expect(minClaimableHtlcAmount('btc')).toBeGreaterThan(546 * 5);
  });

  it('is a positive integer on every UTXO chain', () => {
    for (const c of ['bch2', 'bch', 'btc', 'bc2'] as const) {
      const f = minClaimableHtlcAmount(c);
      expect(Number.isInteger(f)).toBe(true);
      expect(f).toBeGreaterThan(0);
    }
  });
});
