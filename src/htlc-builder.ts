/**
 * HTLC (Hash Time-Locked Contract) Builder
 *
 * Constructs HTLC redeem scripts and spending transactions for atomic swaps.
 * Supports BCH2, BCH (BIP143/FORKID), BTC, BC2 (legacy sighash).
 */

import * as secp256k1 from '@noble/secp256k1';
import { sha256 } from '@noble/hashes/sha256';
import { ripemd160 } from '@noble/hashes/ripemd160';
import type { Chain, HTLCParams, HTLCDetails, Utxo } from './swap-types';
import { getChainConfig, maxFeeRate } from './chain-config';

// ============================================================================
// Helpers
// ============================================================================

function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) throw new Error('Invalid hex: odd length');
  if (!/^[0-9a-fA-F]*$/.test(hex)) throw new Error('Invalid hex: non-hex characters');
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
  }
  return bytes;
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

function reverseBytes(bytes: Uint8Array): Uint8Array {
  const r = new Uint8Array(bytes.length);
  for (let i = 0; i < bytes.length; i++) r[i] = bytes[bytes.length - 1 - i];
  return r;
}

function hash256(data: Uint8Array): Uint8Array {
  return sha256(sha256(data));
}

function hash160(data: Uint8Array): Uint8Array {
  return ripemd160(sha256(data));
}

function writeVarInt(n: number): Uint8Array {
  if (n < 0xfd) return new Uint8Array([n]);
  if (n <= 0xffff) return new Uint8Array([0xfd, n & 0xff, (n >> 8) & 0xff]);
  return new Uint8Array([0xfe, n & 0xff, (n >> 8) & 0xff, (n >> 16) & 0xff, (n >> 24) & 0xff]);
}

function readVarInt(data: Uint8Array, offset: number): { value: number; bytesRead: number } | null {
  if (offset >= data.length) return null;
  const first = data[offset];
  if (first < 0xfd) return { value: first, bytesRead: 1 };
  if (first === 0xfd) {
    if (offset + 2 >= data.length) return null;
    return { value: data[offset + 1] | (data[offset + 2] << 8), bytesRead: 3 };
  }
  if (first === 0xfe) {
    if (offset + 4 >= data.length) return null;
    return { value: (data[offset + 1] | (data[offset + 2] << 8) | (data[offset + 3] << 16) | (data[offset + 4] << 24)) >>> 0, bytesRead: 5 };
  }
  return null; // 0xff = 8-byte, not needed for script lengths
}

function writeUInt32LE(n: number): Uint8Array {
  return new Uint8Array([n & 0xff, (n >> 8) & 0xff, (n >> 16) & 0xff, (n >> 24) & 0xff]);
}

function writeUInt64LE(n: number): Uint8Array {
  if (n < 0 || n > Number.MAX_SAFE_INTEGER) {
    throw new Error(`writeUInt64LE: value out of safe range: ${n}`);
  }
  const low = n >>> 0;
  // R30-HTLC-003: use BigInt shift to avoid floating-point imprecision for amounts > 2^32 sat
  const high = Number(BigInt(n) >> 32n) >>> 0;
  return new Uint8Array([
    low & 0xff, (low >> 8) & 0xff, (low >> 16) & 0xff, (low >> 24) & 0xff,
    high & 0xff, (high >> 8) & 0xff, (high >> 16) & 0xff, (high >> 24) & 0xff,
  ]);
}

function concat(...arrays: Uint8Array[]): Uint8Array {
  const totalLen = arrays.reduce((s, a) => s + a.length, 0);
  const result = new Uint8Array(totalLen);
  let offset = 0;
  for (const arr of arrays) {
    result.set(arr, offset);
    offset += arr.length;
  }
  return result;
}

// Push data with proper length encoding for Bitcoin Script
function pushData(data: Uint8Array): Uint8Array {
  if (data.length < 76) {
    return concat(new Uint8Array([data.length]), data);
  } else if (data.length < 256) {
    return concat(new Uint8Array([0x4c, data.length]), data); // OP_PUSHDATA1
  } else {
    return concat(new Uint8Array([0x4d, data.length & 0xff, (data.length >> 8) & 0xff]), data); // OP_PUSHDATA2
  }
}

// Encode locktime as minimal CScript number for OP_CHECKLOCKTIMEVERIFY
function encodeScriptNum(n: number): Uint8Array {
  // Return empty array for 0: in Script, OP_0 pushes an empty stack item (not the integer 0).
  // Callers that use the returned length as a push opcode would emit a 0-byte push (OP_0 = empty
  // stack item). The HTLC builder guards against locktime=0 at a higher level, but this makes
  // encodeScriptNum safe as a standalone utility.
  if (n === 0) return new Uint8Array(0); // OP_0 — caller must handle explicitly
  const neg = n < 0;
  let abs = Math.abs(n);
  const bytes: number[] = [];
  while (abs > 0) {
    bytes.push(abs & 0xff);
    abs = Math.floor(abs / 256);
  }
  // If high bit set, add an extra byte for sign
  if (bytes[bytes.length - 1] & 0x80) {
    bytes.push(neg ? 0x80 : 0x00);
  } else if (neg) {
    bytes[bytes.length - 1] |= 0x80;
  }
  return new Uint8Array(bytes);
}

// DER encode ECDSA signature
function compactToDER(compact: Uint8Array): Uint8Array {
  const r = compact.slice(0, 32);
  const s = compact.slice(32, 64);

  function encodeInt(bytes: Uint8Array): Uint8Array {
    let start = 0;
    while (start < bytes.length - 1 && bytes[start] === 0) start++;
    const trimmed = bytes.slice(start);
    if (trimmed[0] & 0x80) return new Uint8Array([0, ...trimmed]);
    return trimmed;
  }

  const rEnc = encodeInt(r);
  const sEnc = encodeInt(s);
  const totalLen = 2 + rEnc.length + 2 + sEnc.length;
  const der = new Uint8Array(2 + totalLen);
  let pos = 0;
  der[pos++] = 0x30;
  der[pos++] = totalLen;
  der[pos++] = 0x02;
  der[pos++] = rEnc.length;
  der.set(rEnc, pos); pos += rEnc.length;
  der[pos++] = 0x02;
  der[pos++] = sEnc.length;
  der.set(sEnc, pos);
  return der;
}

// ============================================================================
// CashAddr encoding (for BCH2 and BCH P2SH addresses)
// ============================================================================

const CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';

function cashAddrPolymod(values: number[]): bigint {
  const GENERATORS = [0x98f2bc8e61n, 0x79b76d99e2n, 0xf33e5fb3c4n, 0xae2eabe2a8n, 0x1e4f43e470n];
  let chk = 1n;
  for (const value of values) {
    const top = chk >> 35n;
    chk = ((chk & 0x07ffffffffn) << 5n) ^ BigInt(value);
    for (let i = 0; i < 5; i++) {
      if ((top >> BigInt(i)) & 1n) chk ^= GENERATORS[i];
    }
  }
  return chk;
}

function packAddrData(hash: Uint8Array, type: number): number[] {
  const encodedSize = hash.length === 20 ? 0 : 3; // 20 bytes = 0, 32 bytes = 3
  const versionByte = (type << 3) | encodedSize;
  const payload: number[] = [];
  let acc = versionByte;
  let bits = 8;
  for (let i = 0; i < hash.length; i++) {
    acc = (acc << 8) | hash[i];
    bits += 8;
    while (bits >= 5) { bits -= 5; payload.push((acc >> bits) & 0x1f); }
  }
  if (bits > 0) payload.push((acc << (5 - bits)) & 0x1f);
  return payload;
}

function encodeCashAddr(prefix: string, type: number, hash: Uint8Array): string {
  const prefixValues: number[] = [];
  for (let i = 0; i < prefix.length; i++) prefixValues.push(prefix.charCodeAt(i) & 0x1f);
  prefixValues.push(0);
  const payload = packAddrData(hash, type);
  const checksumInput = [...prefixValues, ...payload, 0, 0, 0, 0, 0, 0, 0, 0];
  const polymod = cashAddrPolymod(checksumInput) ^ 1n;
  const checksumArray: number[] = [];
  for (let i = 0; i < 8; i++) checksumArray.push(Number((polymod >> BigInt(5 * (7 - i))) & 0x1fn));
  const combined = [...payload, ...checksumArray];
  let result = prefix + ':';
  for (const value of combined) result += CHARSET[value];
  return result;
}

// Base58Check encoding (for BTC/BC2 P2SH addresses)
const BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

function encodeBase58(data: Uint8Array): string {
  let num = 0n;
  for (let i = 0; i < data.length; i++) num = num * 256n + BigInt(data[i]);
  let result = '';
  while (num > 0n) { result = BASE58_ALPHABET[Number(num % 58n)] + result; num = num / 58n; }
  for (let i = 0; i < data.length && data[i] === 0; i++) result = '1' + result;
  return result;
}

// ============================================================================
// HTLC Redeem Script Construction
// ============================================================================

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
// R167: an HTLC locktime is EITHER a block height in (0, 500_000_000) OR a Unix timestamp in
// [1_500_000_000, 10_000_000_000). OP_CHECKLOCKTIMEVERIFY (BIP65) interprets values >= 500_000_000 as Unix
// timestamps. The RESPONDER's UTXO leg uses a TIMESTAMP CLTV (anchored to the trusted EVM expiry, NOT the
// proxy-supplied block height) in the EVM-counterparty topology, so a malicious/MITM proxy cannot inflate the
// block height to push the responder's refund maturity past the initiator's EVM expiry and steal both legs
// (R167-UTXO-RESP-LOCKTIME-PROXY-001). Timestamp locktimes are enforced on-chain via median-time-past, and the
// refund tx sets nSequence=0xfffffffe (CLTV-enforcing). The gap [500_000_000, 1_500_000_000) is rejected as
// ambiguous (neither a plausible block height nor a plausible recent Unix timestamp).
export const LOCKTIME_HEIGHT_MAX = 500_000_000;
export const LOCKTIME_TS_MIN = 1_500_000_000;
// R167 gate NIT: cap at 2^31 so any timestamp locktime is a clean 4-byte/uint32 CScriptNum (no 5-byte
// sign-extension edge), matching the server's responder_locktime cap (2^31-1). now+12h (~1.78e9) is well below.
export const LOCKTIME_TS_MAX = 2_147_483_648;
export function isTimestampLocktime(locktime: number): boolean {
  return locktime >= LOCKTIME_HEIGHT_MAX;
}
export function isValidLocktime(locktime: number): boolean {
  if (!Number.isInteger(locktime)) return false;
  if (locktime > 0 && locktime < LOCKTIME_HEIGHT_MAX) return true; // block height
  if (locktime >= LOCKTIME_TS_MIN && locktime < LOCKTIME_TS_MAX) return true; // Unix timestamp
  return false;
}

// H1-LOCKTIME-PROXY-001 (coarse backstop): the largest block height that could PLAUSIBLY exist on any of these
// ~10-min UTXO chains, none of which predates the Bitcoin genesis (2009-01-03). Rejects a grossly-inflated proxy
// height before it becomes a UTXO HTLC refund CLTV (see SwapExecute buildHTLC). Deliberately loose (30 s/block =>
// ~20x real height): the SPV verifyFundingHeight() PoW check is the TIGHT guard on the four mainnet chains — this
// only backstops regtest / any future non-SPV chain and the extreme near-500,000,000 (BIP65) boundary. A tight
// wall-clock bound is impossible without false-rejecting honest tips (fast-block streaks + ~2h timestamp drift), so
// this stays coarse by design. Fail-closed: heights above it must never fund.
const BITCOIN_GENESIS_SEC = 1_231_006_505; // 2009-01-03T18:15:05Z
const MIN_PLAUSIBLE_BLOCK_INTERVAL_SEC = 30;
export function maxPlausibleBlockHeight(nowSec: number = Math.floor(Date.now() / 1000)): number {
  return Math.floor((nowSec - BITCOIN_GENESIS_SEC) / MIN_PLAUSIBLE_BLOCK_INTERVAL_SEC);
}

export function createHTLCRedeemScript(params: HTLCParams): Uint8Array {
  const { secretHash, recipientPubkeyHash, refundPubkeyHash, locktime } = params;

  if (secretHash.length !== 32) throw new Error('secretHash must be 32 bytes');
  if (recipientPubkeyHash.length !== 20) throw new Error('recipientPubkeyHash must be 20 bytes');
  if (refundPubkeyHash.length !== 20) throw new Error('refundPubkeyHash must be 20 bytes');
  // R72-HT-001: degenerate script guard — same hash means same party can both claim and refund
  if (recipientPubkeyHash.every((b, i) => b === refundPubkeyHash[i])) {
    throw new Error('recipientPubkeyHash and refundPubkeyHash must differ — same key used for both parties?');
  }
  // R48-HTLC-001 / R167: block height in (0,5e8) OR Unix timestamp in [1.5e9,1e10) — see isValidLocktime.
  if (!isValidLocktime(locktime)) {
    throw new Error(`locktime must be a block height in (0, ${LOCKTIME_HEIGHT_MAX}) or a Unix timestamp in [${LOCKTIME_TS_MIN}, ${LOCKTIME_TS_MAX}) (got ${locktime})`);
  }

  const locktimeBytes = encodeScriptNum(locktime);

  return new Uint8Array([
    0x63,                         // OP_IF
    0xa8,                         // OP_SHA256
    0x20, ...secretHash,          // push 32 bytes: secret hash
    0x88,                         // OP_EQUALVERIFY
    0x76,                         // OP_DUP
    0xa9,                         // OP_HASH160
    0x14, ...recipientPubkeyHash, // push 20 bytes: recipient pubkey hash
    0x67,                         // OP_ELSE
    // R30-HTLC-002: use pushData() instead of raw length byte — raw byte would be misinterpreted
    // as OP_PUSHDATA1 by script interpreter if locktimeBytes.length >= 76 (0x4c). Block heights
    // up to ~134M fit in 4 bytes (safe today), but pushData() is correct for all future values.
    ...pushData(locktimeBytes),   // push N bytes: locktime (safe for all possible encoded lengths)
    0xb1,                         // OP_CHECKLOCKTIMEVERIFY
    0x75,                         // OP_DROP
    0x76,                         // OP_DUP
    0xa9,                         // OP_HASH160
    0x14, ...refundPubkeyHash,    // push 20 bytes: refund pubkey hash
    0x68,                         // OP_ENDIF
    0x88,                         // OP_EQUALVERIFY
    0xac,                         // OP_CHECKSIG
  ]);
}

/**
 * Compute the P2SH address for an HTLC redeem script.
 */
export function htlcToP2SHAddress(redeemScript: Uint8Array, chain: Chain): string {
  const scriptHash = hash160(redeemScript);
  const config = getChainConfig(chain);

  if (config.addressPrefix) {
    // CashAddr P2SH (type 1)
    return encodeCashAddr(config.addressPrefix, 1, scriptHash);
  } else {
    // Base58Check P2SH
    const versioned = new Uint8Array([config.p2shVersionByte ?? 0x05, ...scriptHash]);
    const checksum = hash256(versioned).slice(0, 4);
    return encodeBase58(new Uint8Array([...versioned, ...checksum]));
  }
}

/**
 * Create full HTLC details including address and scriptPubKey.
 */
export function createHTLC(params: HTLCParams, chain: Chain): HTLCDetails {
  const redeemScript = createHTLCRedeemScript(params);
  // R117-HTLC-001: BIP16 P2SH redeemScript limit is 520 bytes. Current template is ~98 bytes, but
  // a future refactor adding extra script elements could silently produce an unspendable P2SH output
  // without this guard. buildHTLCClaimTx/buildHTLCRefundTx each validate independently, but those
  // are not called on every HTLC creation path (e.g. address display, amount verification).
  if (redeemScript.length > 520) {
    throw new Error(`createHTLC: redeemScript is ${redeemScript.length} bytes — exceeds BIP16 P2SH limit of 520`);
  }
  const scriptHash = hash160(redeemScript);
  const p2shScriptPubKey = new Uint8Array([0xa9, 0x14, ...scriptHash, 0x87]); // OP_HASH160 <hash> OP_EQUAL
  const p2shAddress = htlcToP2SHAddress(redeemScript, chain);

  return { redeemScript, p2shAddress, p2shScriptPubKey, params };
}

/**
 * Compute Electrum scripthash for an HTLC P2SH address (for monitoring).
 */
export function htlcScripthash(redeemScript: Uint8Array): string {
  const scriptHash = hash160(redeemScript);
  const p2shScript = new Uint8Array([0xa9, 0x14, ...scriptHash, 0x87]);
  const hash = sha256(p2shScript);
  return bytesToHex(reverseBytes(hash));
}

// ============================================================================
// HTLC Transaction Building
// ============================================================================

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
export function minClaimableHtlcAmount(chain: Chain): number {
  const config = getChainConfig(chain);
  const dustThreshold = config.dustThreshold ?? 546;
  // FEE-DEADLINE-FIX: size the floor at the WORST-CASE (deadline-scaled) fee, not the static rate, so any
  // HTLC that funds stays claimable even when fees spike and the claim/refund fee ramps to maxFeeRate.
  const feePerByte = maxFeeRate(chain);
  const useBip143 = config.useBip143 ?? false;
  const RS_LEN = 110; // representative HTLC redeemScript length (bytes); real scripts are ~92–110B
  const rsPushOverhead = RS_LEN < 76 ? 1 : RS_LEN < 256 ? 2 : 3;
  const scriptSigEstimate = 74 + 34 + 33 + 1 + rsPushOverhead + RS_LEN; // sig + (1+33 pubkey) + secret(32+2) + OP_1 + redeemScript push
  const outputSize = 8 + 1 + 25; // P2PKH dest: value(8) + scriptPubKeyLen varint(1) + scriptPubKey(25)
  const claimTxSize = (90 - 34 + outputSize) + scriptSigEstimate + (useBip143 ? 0 : 50); // mirrors buildHTLCClaimTx
  const estClaimFee = claimTxSize * feePerByte;
  return Math.max(dustThreshold * 5, estClaimFee + dustThreshold);
}

/**
 * FEE-DEADLINE-FIX: resolve the effective sat/vByte for a builder — prefer the live / deadline-scaled
 * feeRate, fall back to the chain's static config rate, and CLAMP to maxFeeRate(chain) so a claim/refund can
 * never pay more than the funding floor (minClaimableHtlcAmount, sized at maxFeeRate) guaranteed was
 * affordable. NaN / Infinity pass through UNCLAMPED so each builder's finite/positive guard still rejects them.
 */
function resolveClampedFeeRate(feeRate: number | undefined, configRate: number | undefined, chain: Chain): number {
  const r = feeRate ?? configRate ?? 1;
  return Number.isFinite(r) ? Math.min(r, maxFeeRate(chain)) : r;
}

/**
 * Build a funding transaction that sends funds to the HTLC P2SH address.
 * This is a regular P2PKH -> P2SH transaction.
 */
export async function buildHTLCFundingTx(
  inputs: Array<{ utxo: Utxo; privateKey: Uint8Array; publicKey: Uint8Array; scriptPubKey: Uint8Array }>,
  htlcScriptPubKey: Uint8Array,
  amount: number,
  changeScriptPubKey: Uint8Array | null,
  chain: Chain,
  feeRate?: number, // FEE-DEADLINE-FIX: live sat/vByte; falls back to config, clamped to maxFeeRate(chain)
): Promise<{ txid: string; rawTx: string; fee: number }> {
  // R73-HT-001: empty inputs means no UTXOs available — would produce a tx with zero inputs
  // that nodes reject as structurally invalid; surface a clear error instead.
  if (inputs.length === 0) {
    throw new Error('buildHTLCFundingTx: no inputs provided — wallet has no spendable UTXOs');
  }
  // R74-HT-001: NaN/Infinity/non-integer amount propagates silently past the dust check and throws
  // a cryptic BigInt conversion error at serialization time; catch it early with a clear message.
  if (!Number.isInteger(amount) || !Number.isFinite(amount) || amount <= 0) {
    throw new Error(`buildHTLCFundingTx: amount must be a positive integer (satoshis); got ${amount}`);
  }
  const config = getChainConfig(chain);
  const hashType = config.sighashType ?? 0x01;
  // R30-HTLC-001: assert SIGHASH_FORKID is set for BIP143 chains — a config regression would produce
  // invalid signatures that the node rejects, permanently locking all new HTLC funds.
  // R63-HT-006: use config.useBip143 (not chain name) so new BIP143 chains are automatically covered.
  if ((config.useBip143 ?? false) && !(hashType & 0x40)) {
    throw new Error(`SIGHASH_FORKID (0x40) required for ${chain} but hashType is 0x${hashType.toString(16)}`);
  }
  const feePerByte = resolveClampedFeeRate(feeRate, config.feePerByte, chain);
  // R38-HTLC-001: reject zero or negative feePerByte before any calculation — a zero fee
  // produces a zero-fee transaction that nodes reject as below min-relay-fee, and a negative
  // value silently inflates the HTLC output amount above totalIn, causing an underflow panic.
  // R47-HTLC-001: also reject Infinity — !Infinity is false and Infinity <= 0 is false, so
  // Infinity passes the old guard and propagates to fee calculations as Infinity/-Infinity.
  if (!feePerByte || !Number.isFinite(feePerByte) || feePerByte <= 0) {
    throw new Error(`feePerByte must be a finite positive number, got ${feePerByte}`);
  }
  const dustThreshold = config.dustThreshold ?? 546;

  // R146-FEE-FLOOR-001: fee-aware funding floor. The old flat dustThreshold*5 assumed 1 sat/B and let
  // higher-fee chains (e.g. BTC at 10 sat/B) fund HTLCs that could never be claimed (claim fee > value).
  // minClaimableHtlcAmount derives the floor from the chain's actual feePerByte + worst-case claim tx.
  const p2shDustFloor = minClaimableHtlcAmount(chain);
  if (amount < p2shDustFloor) {
    throw new Error(
      `HTLC amount ${amount} sat is below the minimum claimable amount (${p2shDustFloor} sat) on ${chain} ` +
      `after fees. Increase the swap amount.`
    );
  }

  // Calculate fee (estimate ~148 bytes/input + 34 bytes/output + 10 overhead)
  const totalIn = inputs.reduce((s, i) => s + i.utxo.value, 0);

  // First estimate with change output
  let numOutputs = changeScriptPubKey ? 2 : 1;
  let estimatedSize = inputs.length * 148 + numOutputs * 34 + 10;
  let fee = estimatedSize * feePerByte;
  let change = totalIn - amount - fee;

  // If change would be below dust, recalculate fee without change output.
  // This avoids silently losing sub-dust change to miners.
  // R125-HTLC-FUND-001: also enter this branch when `change` is NEGATIVE. With a change output the
  // fee is fee2 (2 outputs); when totalIn falls in [amount+fee1, amount+fee2) the 2-output change is
  // negative even though a 1-output tx (fee1) IS affordable. The old `change > 0` guard skipped the
  // recalc and the function wrongly threw 'Insufficient funds'. Dropping `change > 0` lets the body
  // recompute the 1-output fee; line 444 then only throws when the 1-output change is still < 0
  // (genuinely insufficient — cannot cover even the 1-output fee).
  if (change <= dustThreshold && changeScriptPubKey) {
    if (change > 0) console.warn(`[htlc-builder] Sub-dust change (${change} sat) absorbed into miner fee`);
    numOutputs = 1;
    estimatedSize = inputs.length * 148 + numOutputs * 34 + 10;
    fee = estimatedSize * feePerByte;
    change = totalIn - amount - fee;
    if (change > dustThreshold) {
      numOutputs = 2;
      estimatedSize = inputs.length * 148 + 2 * 34 + 10;
      fee = estimatedSize * feePerByte;
      change = totalIn - amount - fee;
    }
    // Second-pass sub-dust guard
    if (change > 0 && change <= dustThreshold) {
      console.warn(`[htlc-builder] Second sub-dust change (${change} sat) absorbed into fee`);
      numOutputs = 1;
      const estimatedSize2 = inputs.length * 148 + 1 * 34 + 10;
      fee = estimatedSize2 * feePerByte;
      change = totalIn - amount - fee;
    }
  }

  // R35-HTLC-001: Final reconciliation — after the sub-dust loop, numOutputs may be 1 while
  // change has climbed back above dustThreshold (e.g. second pass over-reduced fee). Ensure
  // numOutputs always reflects the output count that will actually be emitted below.
  // R42-CORE-004: guard against changeScriptPubKey === null — without this guard, numOutputs
  // would be set to 2 (fee computed for 2 outputs) but only 1 output would be emitted below,
  // causing the HTLC output to receive an overcalculated fee deduction.
  if (change >= dustThreshold && numOutputs === 1 && changeScriptPubKey) {
    const sizeWith2 = inputs.length * 148 + 2 * 34 + 10;
    fee = sizeWith2 * feePerByte;
    change = totalIn - amount - fee;
    numOutputs = change >= dustThreshold ? 2 : 1;
    if (change < 0) throw new Error('Insufficient funds after fee reconciliation');
  }

  // R69-HT-002: HTLC output MUST be at vout=0. The claim/refund side uses `utxo.tx_pos`
  // from the Electrum UTXO scan to identify the HTLC output, which expects it at index 0.
  // Any change to this ordering (e.g., change-first for privacy) requires updating the
  // claim-side UTXO selection logic — silent reorder causes permanently invalid signatures.
  // R114-HTLC-003 / R132-HTLC-RECIP-001: this builder is dual-use. The recipient output (vout=0) is
  // EITHER a P2SH HTLC for swap funding (23 bytes: OP_HASH160 <0x14 push 20> OP_EQUAL) OR a standard
  // P2PKH for a plain wallet send via sendUtxo (25 bytes: OP_DUP OP_HASH160 <0x14 push 20>
  // OP_EQUALVERIFY OP_CHECKSIG). Validate the EXACT shape of each so a corrupt/wrong-length script
  // still throws (the original R114 corruption-detection intent) — but do NOT reject the legitimate
  // 25-byte P2PKH plain-send case, which the prior strict `!== 23` length guard broke for EVERY UTXO
  // send (Holdings.sendUtxo + WalletPortfolio.sendUtxo both pass a 25-byte p2pkhScript here).
  const sp = htlcScriptPubKey;
  const isP2SH  = sp.length === 23 && sp[0] === 0xa9 && sp[1] === 0x14 && sp[22] === 0x87;
  const isP2PKH = sp.length === 25 && sp[0] === 0x76 && sp[1] === 0xa9 && sp[2] === 0x14 && sp[23] === 0x88 && sp[24] === 0xac;
  if (!isP2SH && !isP2PKH) {
    throw new Error(`buildHTLCFundingTx: recipient scriptPubKey must be a standard P2SH (23B) or P2PKH (25B); got ${sp.length} bytes`);
  }
  const outputs: Array<{ scriptPubKey: Uint8Array; value: number }> = [
    { scriptPubKey: htlcScriptPubKey, value: amount }, // vout=0 — REQUIRED for claim/refund
  ];

  if (change >= dustThreshold && changeScriptPubKey) {
    if (changeScriptPubKey.length < 1 || changeScriptPubKey.length > 520) {
      throw new Error(`buildHTLCFundingTx: changeScriptPubKey invalid length (${changeScriptPubKey.length})`);
    }
    outputs.push({ scriptPubKey: changeScriptPubKey, value: change }); // vout=1 — change
  } else if (change < 0) {
    throw new Error('Insufficient funds');
  }

  return buildSignedTx(inputs, outputs, hashType, config.useBip143 ?? false, chain);
}

/**
 * Build a P2SH HTLC claim transaction (single input).
 *
 * NOTE: Only one UTXO is claimed per call. If the HTLC address received multiple
 * funding transactions, call once per UTXO — each uses the same secret.
 * The swap engine enforces single-UTXO funding (rejecting offers with split UTXOs)
 * to avoid this scenario. TODO: add multi-input claim support if split-payment
 * HTLCs are ever needed.
 */
export async function buildHTLCClaimTx(
  utxo: Utxo,
  redeemScript: Uint8Array,
  secret: Uint8Array,
  recipientPrivateKey: Uint8Array,
  recipientPublicKey: Uint8Array,
  destinationScriptPubKey: Uint8Array,
  chain: Chain,
  feeRate?: number, // FEE-DEADLINE-FIX: live sat/vByte; falls back to config, clamped to maxFeeRate(chain)
): Promise<{ txid: string; rawTx: string }> {
  if (secret.length !== 32) throw new Error(`HTLC secret must be exactly 32 bytes; got ${secret.length}`);
  // R24-HTLC-008c: reject empty or oversized redeemScript (max P2SH limit is 520 bytes)
  if (redeemScript.length === 0 || redeemScript.length > 520) {
    throw new Error(`redeemScript invalid length (${redeemScript.length}; must be 1–520 bytes)`);
  }

  const config = getChainConfig(chain);
  const hashType = config.sighashType ?? 0x01;
  // R30-HTLC-001 / R63-HT-006: assert SIGHASH_FORKID for BIP143 chains (use config, not chain name)
  if ((config.useBip143 ?? false) && !(hashType & 0x40)) {
    throw new Error(`SIGHASH_FORKID (0x40) required for ${chain} claim but hashType is 0x${hashType.toString(16)}`);
  }
  const useBip143 = config.useBip143 ?? false;
  const feePerByte = resolveClampedFeeRate(feeRate, config.feePerByte, chain);
  // R46-HTLC-001: ?? returns 0 when config.feePerByte is explicitly 0 (unlike ||, which would fall back to 1)
  // R47-HTLC-001: also reject Infinity — passes the old guard and makes fee computations produce Infinity.
  if (!feePerByte || !Number.isFinite(feePerByte) || feePerByte <= 0) {
    throw new Error(`feePerByte must be a finite positive number, got ${feePerByte}`);
  }
  const dustThreshold = config.dustThreshold ?? 546;

  // R114-HTLC-001: validate destinationScriptPubKey BEFORE accessing .length for fee estimation —
  // a null/undefined passed at JS boundary throws TypeError: Cannot read properties of null
  // rather than the structured error message from the later guard.
  if (!destinationScriptPubKey || destinationScriptPubKey.length < 1 || destinationScriptPubKey.length > 520) {
    throw new Error(`destinationScriptPubKey invalid length (${destinationScriptPubKey?.length ?? 0}); must be 1–520 bytes`);
  }

  // R95-HTLC-001: compute fee using actual redeemScript.length — fixed 350B constant seriously
  // underestimates fee when redeemScript approaches 520B (P2SH max), causing min-relay-fee rejection.
  // scriptSig breakdown: pushData(sig ~73B) + 34B (1-push + 33-pubkey) + pushData(secret 32B) + OP_1 (1B) + pushData(redeemScript)
  const rsLen = redeemScript.length;
  const rsPushOverhead = rsLen < 76 ? 1 : rsLen < 256 ? 2 : 3; // OP_PUSH / OP_PUSHDATA1 / OP_PUSHDATA2
  const scriptSigEstimate = 74 + 34 + 33 + 1 + rsPushOverhead + rsLen;
  // R105-HTLC-002: include 1-byte varint for the scriptSig length field in the serialized input.
  // scriptSig < 253 bytes → varint is 1 byte; 253–65535 bytes → 3 bytes. Typical HTLC claim
  // scriptSigs are ~180–250 bytes (< 253), so varint = 1 byte. Omitting it caused a 1-byte undercount.
  // R107-HTLC-001: scriptSigVarIntLen (1B varint for scriptSig length field) is already accounted
  // for in the 90B base constant and must NOT be added separately — doing so double-counts it.
  // R106-HTLC-001: compute output size dynamically — fixed 34B (8+1+25 P2PKH) underestimates fee
  // for non-P2PKH destinations (e.g. P2SH at 32B scriptPubKey → outputSize=41). The base of 90
  // already budgets 34B for the output; subtract it and add the actual size.
  const destScriptLen = destinationScriptPubKey.length;
  const destScriptVarIntLen = destScriptLen < 253 ? 1 : 3;
  const outputSize = 8 + destScriptVarIntLen + destScriptLen; // value(8) + varint(scriptPubKeyLen) + scriptPubKey
  // R107-HTLC-001: removed separate scriptSigVarIntLen — the 90B base constant already accounts
  // for the 1-byte varint in the input's scriptSig length field; adding it again was a double-count.
  const claimTxSize = (90 - 34 + outputSize) + scriptSigEstimate + (useBip143 ? 0 : 50); // 90-34 = tx framing without output; +50 margin for non-BIP143
  // FEE-DEADLINE-FIX (fund-safety, review #1): never let the dynamic / deadline-ramped rate make a FUNDABLE
  // utxo unbuildable. Clamp the rate DOWN to what this utxo can afford while leaving a non-dust output —
  // confirming at a lower fee is strictly better than a claim that throws fee>=value forever (which would
  // strand a leg funded below the new floor before this change). Too-small utxos still fail the guards below.
  const affordableClaimRate = Math.floor((utxo.value - dustThreshold) / claimTxSize);
  const effectiveClaimFeePerByte = Math.max(1, Math.min(feePerByte, affordableClaimRate));
  const fee = claimTxSize * effectiveClaimFeePerByte;
  // R23-HTLC-003: reject non-positive value before BIP143 sighash computation to avoid silent invalid tx
  if (!Number.isInteger(utxo.value) || utxo.value <= 0) {
    throw new Error(`claimUtxo.value must be a positive integer; got ${utxo.value}. Refresh UTXO from Electrum.`);
  }
  if (fee >= utxo.value) {
    throw new Error(`Claim fee (${fee} sat) would exceed UTXO value (${utxo.value} sat). Swap amount is too small.`);
  }
  const outputValue = utxo.value - fee;

  if (outputValue < dustThreshold) {
    throw new Error('HTLC value too small to claim after fees');
  }

  const outputs = [{ scriptPubKey: destinationScriptPubKey, value: outputValue }];

  // R105-HTLC-001: claim tx has NO CLTV requirement (only the refund branch uses OP_CHECKLOCKTIMEVERIFY).
  // nSequence must be 0xFFFFFFFF for claim: BIP65 §2 requires nSequence < 0xFFFFFFFF ONLY when the
  // tx uses CLTV. The claim branch does not use CLTV, so 0xFFFFFFFF is correct. BCH2/BCH do not
  // implement BIP125 RBF, so there is no reason to opt-in with 0xFFFFFFFD.
  // nSequence must be identical in both computeSighash and serializeTx or the signature will be invalid.
  const claimNSequence = 0xffffffff;

  // Compute sighash with redeemScript as scriptCode
  const sighash = computeSighash(
    [{ utxo, scriptCode: redeemScript }],
    outputs,
    0,
    hashType,
    useBip143,
    0, // nLockTime = 0 for claim
    claimNSequence,
  );

  // Sign with ECDSA (cross-chain compatible)
  // R58-HTB-007: explicitly request low-s signatures; BCH2 nodes enforce SCRIPT_VERIFY_LOW_S
  const signature = await secp256k1.signAsync(sighash, recipientPrivateKey, { lowS: true });
  const sigDer = compactToDER(signature.toCompactRawBytes());
  const sigWithType = concat(sigDer, new Uint8Array([hashType]));

  // ScriptSig: <sig> <pubkey> <secret> <OP_1> <redeemScript>
  const scriptSig = concat(
    pushData(sigWithType),
    pushData(recipientPublicKey),
    pushData(secret),
    new Uint8Array([0x51]), // OP_1 — MINIMALDATA-compliant encoding of integer 1 for BCH2 (R103-HTLC-001)
    pushData(redeemScript),
  );

  return serializeTx(
    [{ utxo, scriptSig, nSequence: claimNSequence }],
    outputs,
    0, // nLockTime
  );
}

/**
 * Build a refund transaction: initiator reclaims after timelock expires.
 */
export async function buildHTLCRefundTx(
  utxo: Utxo,
  redeemScript: Uint8Array,
  locktime: number,
  refundPrivateKey: Uint8Array,
  refundPublicKey: Uint8Array,
  destinationScriptPubKey: Uint8Array,
  chain: Chain,
  feeRate?: number, // FEE-DEADLINE-FIX: live sat/vByte; falls back to config, clamped to maxFeeRate(chain)
): Promise<{ txid: string; rawTx: string }> {
  // R24-HTLC-001: same guards as buildHTLCClaimTx — missing here in the original
  // R64-HT-004 / R167: accept a block height in (0,5e8) OR a Unix timestamp in [1.5e9,1e10) — must match
  // createHTLCRedeemScript. A timestamp locktime (responder EVM-counterparty leg) is enforced on-chain via MTP;
  // nLockTime is set to the locktime exactly below and nSequence=0xfffffffe keeps CLTV enforced.
  if (!isValidLocktime(locktime)) {
    throw new Error(`locktime must be a block height in (0, ${LOCKTIME_HEIGHT_MAX}) or a Unix timestamp in [${LOCKTIME_TS_MIN}, ${LOCKTIME_TS_MAX}); got ${locktime}`);
  }
  if (redeemScript.length === 0 || redeemScript.length > 520) {
    throw new Error(`redeemScript invalid length (${redeemScript.length}; must be 1–520 bytes)`);
  }
  if (!Number.isInteger(utxo.value) || utxo.value <= 0) {
    throw new Error(`refundUtxo.value must be a positive integer; got ${utxo.value}. Refresh UTXO from Electrum.`);
  }

  const config = getChainConfig(chain);
  const hashType = config.sighashType ?? 0x01;
  // R30-HTLC-001 / R63-HT-006: assert SIGHASH_FORKID for BIP143 chains (use config, not chain name)
  if ((config.useBip143 ?? false) && !(hashType & 0x40)) {
    throw new Error(`SIGHASH_FORKID (0x40) required for ${chain} refund but hashType is 0x${hashType.toString(16)}`);
  }
  const useBip143 = config.useBip143 ?? false;
  const feePerByte = resolveClampedFeeRate(feeRate, config.feePerByte, chain);
  // R46-HTLC-001: ?? returns 0 when config.feePerByte is explicitly 0 (unlike ||, which would fall back to 1)
  // R47-HTLC-001: also reject Infinity — passes the old guard and makes fee computations produce Infinity.
  if (!feePerByte || !Number.isFinite(feePerByte) || feePerByte <= 0) {
    throw new Error(`feePerByte must be a finite positive number, got ${feePerByte}`);
  }
  const dustThreshold = config.dustThreshold ?? 546;

  // R114-HTLC-001: validate destinationScriptPubKey BEFORE accessing .length for fee estimation —
  // a null/undefined passed at JS boundary throws TypeError rather than the structured error below.
  if (!destinationScriptPubKey || destinationScriptPubKey.length < 1 || destinationScriptPubKey.length > 520) {
    throw new Error(`destinationScriptPubKey invalid length (${destinationScriptPubKey?.length ?? 0}); must be 1–520 bytes`);
  }

  // R98-HTLC-001: use actual redeemScript.length for fee estimation, mirroring R95-HTLC-001 on the
  // claim path. Fixed constants (280/330) underestimated for scripts > ~130B, causing node rejection.
  // R100-HTLC-001: corrected coefficients — each pushed item includes its 1-byte length prefix:
  //   sig: 1 (push) + 73 (DER sig + hashType) = 74B
  //   pubkey: 1 (push) + 33 (compressed) = 34B
  //   OP_FALSE: 1B (no push prefix — OP_0 = 0x00)
  //   redeemScript: rsPushOverhead + rsLen
  const rsLen = redeemScript.length;
  const rsPushOverhead = rsLen < 76 ? 1 : rsLen < 256 ? 2 : 3;
  const refundScriptSig = 74 + 34 + 1 + rsPushOverhead + rsLen;
  // R105-HTLC-002: include varint for the scriptSig length field, same fix as claim path.
  // R107-HTLC-001: refundScriptSigVarIntLen (1B varint for the scriptSig length field) is already
  // included in the 41B input skeleton (txid=32 + vout=4 + scriptSigLen_varint=1 + nSequence=4).
  // R106-HTLC-001: compute output size dynamically — fixed 34B underestimates for non-P2PKH destinations
  const refundDestScriptLen = destinationScriptPubKey.length;
  const refundDestScriptVarIntLen = refundDestScriptLen < 253 ? 1 : 3;
  const refundOutputSize = 8 + refundDestScriptVarIntLen + refundDestScriptLen; // value(8) + varint(scriptPubKeyLen) + scriptPubKey
  // R107-HTLC-001: removed separate refundScriptSigVarIntLen — the 41B input skeleton already
  // includes the scriptSig length varint byte (txid=32 + vout=4 + scriptSigLen_varint=1 + nSequence=4 = 41).
  // Adding refundScriptSigVarIntLen on top was a double-count that over-estimated fee by 1–3 bytes.
  const refundTxSize = useBip143 ? (10 + 41 + refundScriptSig + refundOutputSize) : (10 + 41 + refundScriptSig + refundOutputSize + 50);
  // FEE-DEADLINE-FIX (fund-safety, review #1): clamp the rate to what this utxo can afford (see claim path) so
  // a legacy leg funded below the new floor can still be refunded rather than throwing fee>=value forever.
  const affordableRefundRate = Math.floor((utxo.value - dustThreshold) / refundTxSize);
  const effectiveRefundFeePerByte = Math.max(1, Math.min(feePerByte, affordableRefundRate));
  const fee = refundTxSize * effectiveRefundFeePerByte;
  if (fee >= utxo.value) {
    throw new Error(`Refund fee (${fee} sat) would exceed UTXO value (${utxo.value} sat). Swap amount is too small.`);
  }
  const outputValue = utxo.value - fee;

  if (outputValue < dustThreshold) {
    throw new Error('HTLC value too small to refund after fees');
  }

  const outputs = [{ scriptPubKey: destinationScriptPubKey, value: outputValue }];

  // R65-HT-002: nSequence MUST be < 0xFFFFFFFF for OP_CHECKLOCKTIMEVERIFY to pass (BIP65 §2).
  // A value of 0xffffffff disables CLTV entirely, making the refund claimable before locktime.
  // 0xfffffffe is the standard choice: disables RBF (not 0xfffffffd) while satisfying CLTV.
  const nSequence = 0xfffffffe;

  const sighash = computeSighash(
    [{ utxo, scriptCode: redeemScript }],
    outputs,
    0,
    hashType,
    useBip143,
    locktime, // nLockTime must be >= HTLC locktime
    nSequence,
  );

  // R58-HTB-007: explicitly request low-s signatures
  const signature = await secp256k1.signAsync(sighash, refundPrivateKey, { lowS: true });
  const sigDer = compactToDER(signature.toCompactRawBytes());
  const sigWithType = concat(sigDer, new Uint8Array([hashType]));

  // ScriptSig: <sig> <pubkey> <OP_FALSE> <redeemScript>
  const scriptSig = concat(
    pushData(sigWithType),
    pushData(refundPublicKey),
    new Uint8Array([0x00]), // OP_FALSE (empty push for OP_ELSE branch)
    pushData(redeemScript),
  );

  // nLockTime must equal the HTLC locktime exactly (NOT locktime-1):
  // BIP65 OP_CLTV requires nLockTime >= the script's locktime value.
  // Setting locktime-1 would cause OP_CLTV to fail: (locktime-1) < locktime.
  return serializeTx(
    [{ utxo, scriptSig, nSequence }],
    outputs,
    locktime,
  );
}

/**
 * Extract the secret preimage from a claim transaction's scriptSig.
 * The scriptSig format is: <sig> <pubkey> <secret> <OP_1 (0x51)> <redeemScript>
 *
 * Parse order: sig → pubkey → secret (32 bytes). Stop after reading secret;
 * the next byte is 0x51 (OP_1, claim-branch selector), not consumed here. (R104-HTLC-001)
 */
export function extractSecretFromClaimTx(rawTxHex: string, expectedSecretHash: Uint8Array | string): Uint8Array | null {
  // R-EXTRACTSECRET-REQHASH-001: the committed secretHash is REQUIRED. Without it there is no discriminator between
  // a decoy 32-byte push placed on an earlier input and the real preimage, so an omitted hash could hand back
  // attacker-chosen bytes as "the secret" (a footgun on the published SDK surface). Parse it ONCE and fail closed if
  // it is missing/malformed — a preimage is only ever returned when it hashes to this value.
  let _expectedHashBytes: Uint8Array | null;
  if (typeof expectedSecretHash === 'string') {
    try { _expectedHashBytes = hexToBytes(expectedSecretHash.replace(/^0x/, '')); } catch { _expectedHashBytes = null; }
  } else {
    _expectedHashBytes = expectedSecretHash ?? null;
  }
  if (!_expectedHashBytes || _expectedHashBytes.length === 0) return null;
  if (!rawTxHex || rawTxHex.length < 20) return null; // too short to be a valid tx

  let tx: Uint8Array;
  try {
    tx = hexToBytes(rawTxHex);
  } catch {
    return null;
  }

  // Minimum valid tx: 4 (version) + 1 (input count) + 32+4+1+1+4 (one input) + 1 (output count) + 4 (locktime) = 52
  if (tx.length < 52) return null;

  let offset = 4; // skip version

  // R281-SEGWIT-002 (sibling of the parseAuthenticatedOutput R281-SEGWIT-001 fix @946): a BTC/BC2 counterparty may
  // SegWit-serialize (BIP144: marker 0x00 + flag 0x01 right after nVersion) their HTLC-claim tx — trivially, by
  // adding one P2WPKH fee input, or just by using a generic SegWit wallet. The revealed preimage STILL lives in the
  // P2SH input's scriptSig (the HTLC output is P2SH, not P2WSH), so we only skip marker+flag and scan the inputs as
  // usual; the witness section trails the outputs and the scan returns on the first HTLC match before reaching it.
  // Without this, tx[4]=0x00 makes readVarInt below read inputCount=0 → return null → the responder never recovers
  // the secret → cannot claim the counter-leg → the initiator refunds it and keeps BOTH legs (fund-loss on the
  // BTC/BC2 pairs, incl. the default bch2→btc direction). bch2/bch are non-SegWit so their claims are unaffected.
  if (tx[offset] === 0x00) {
    if (tx[offset + 1] !== 0x01) return null; // SegWit marker without a valid flag → malformed
    offset += 2;
  }

  // Read input count (varint)
  const inputCountV = readVarInt(tx, offset);
  if (!inputCountV || inputCountV.value === 0) return null;
  // R54-HTLC-004: cap inputCount — a legitimate HTLC claim tx has ≤3 inputs; 100 is a safe
  // upper bound that prevents O(n) linear scan on crafted inputs with a high varint value.
  const inputCount = Math.min(inputCountV.value, 100);
  offset += inputCountV.bytesRead;

  // R53-HTLC-001: loop all inputs — a counterparty may prepend a non-HTLC input (e.g. for
  // consolidation), placing the HTLC input at position ≥ 1. Only checking input[0] would
  // silently return null, causing watchForSecret to skip the tx and time out.
  for (let inputIdx = 0; inputIdx < inputCount; inputIdx++) {
    offset += 32 + 4; // skip txid + vout
    if (offset >= tx.length) return null;

    // Read scriptSig length (varint — can exceed 252 bytes for HTLC claims)
    const scriptSigLenV = readVarInt(tx, offset);
    if (!scriptSigLenV) return null;
    offset += scriptSigLenV.bytesRead;
    const scriptSigLen = scriptSigLenV.value;
    if (offset + scriptSigLen > tx.length) return null;
    const scriptSig = tx.slice(offset, offset + scriptSigLen);
    offset += scriptSigLen;
    offset += 4; // skip nSequence

    // Skip inputs that are too short to contain an HTLC scriptSig (sig+pubkey+secret+redeem ≥ 100 bytes)
    if (scriptSigLen < 100) continue;

    // Parse scriptSig: <sig> <pubkey> <secret(32)> <0x51 (OP_1, claim-branch selector)> <redeemScript>
    let pos = 0;

    // Helper to read a push data length (handles OP_PUSHDATA1/2).
    // Returns null for opcodes that are not data pushes (e.g. OP_FALSE=0x00, OP_1=0x51 and above).
    function readPushLen(): number | null {
      if (pos >= scriptSig.length) return null;
      const b = scriptSig[pos++];
      if (b === 0x00) return null; // OP_FALSE — not a data push; caller checks refund branch separately
      if (b === 0x4c) { // OP_PUSHDATA1
        if (pos >= scriptSig.length) return null;
        return scriptSig[pos++];
      }
      if (b === 0x4d) { // OP_PUSHDATA2
        if (pos + 1 >= scriptSig.length) return null;
        const len = (scriptSig[pos] | (scriptSig[pos + 1] << 8)) >>> 0; // R56-HTB-001: >>> 0 for unsigned
        pos += 2;
        return len;
      }
      if (b === 0x4e) { // OP_PUSHDATA4: 4-byte LE length follows
        if (pos + 3 >= scriptSig.length) return null;
        const len = (scriptSig[pos]) | (scriptSig[pos+1] << 8) | (scriptSig[pos+2] << 16) | (scriptSig[pos+3] << 24);
        pos += 4;
        const ulen = len >>> 0;
        // R63-HT-003: cap at 520 bytes (script element size limit); a larger PUSHDATA4 value
        // is invalid in any standard scriptSig and could spoof an 80-byte "secret" from garbage bytes.
        if (ulen > 520) return null;
        return ulen;
      }
      // R62-HT-001: 0x4f=OP_1NEGATE, 0x50=OP_RESERVED, 0x51-0x60=OP_1..OP_16,
      // 0x61-0xff=flow/arithmetic/crypto opcodes — ALL are non-data-push. Direct push opcodes
      // are ONLY 0x01–0x4b. R65-HT-001: expanded comment to cover full 0x61-0xff range so
      // a future edit doesn't truncate the guard thinking 0x60 is the ceiling.
      if (b >= 0x4f) return null;
      return b; // direct push: b bytes follow (0x01–0x4b)
    }

    // 1. Skip signature (DER-encoded ECDSA + sighash byte, typically 71-73 bytes)
    const sigLen = readPushLen();
    if (sigLen === null || sigLen < 8 || sigLen > 80) continue;
    if (pos + sigLen > scriptSig.length) continue;
    pos += sigLen;

    // 2. Skip pubkey (compressed, 33 bytes)
    const pubkeyLen = readPushLen();
    if (pubkeyLen === null || pubkeyLen !== 33) continue;
    if (pos + pubkeyLen > scriptSig.length) continue;
    pos += pubkeyLen;

    // 3. Read secret — must be exactly 32 bytes.
    //    OP_FALSE (0x00) at this position means this is a refund tx, not a claim.
    if (pos >= scriptSig.length) continue;
    if (scriptSig[pos] === 0x00) continue; // OP_FALSE = refund branch
    const secretLen = readPushLen();
    if (secretLen !== 32) continue;
    if (pos + 32 > scriptSig.length) continue;
    const secret = scriptSig.slice(pos, pos + 32);
    // R22-HTLC-001 / R-EXTRACTSECRET-REQHASH-001: validate the extracted secret against the REQUIRED committed
    // secretHash (parsed once at the top) — defends against a scriptSig with extra/decoy pushdata that shifts the
    // read position to attacker-chosen bytes. Only a preimage that hashes to the committed value is ever returned.
    const actualHash = sha256(secret);
    if (actualHash.length !== _expectedHashBytes.length) continue;
    let hashMatch = true;
    for (let k = 0; k < actualHash.length; k++) {
      if (actualHash[k] !== _expectedHashBytes[k]) { hashMatch = false; break; }
    }
    if (!hashMatch) continue;
    return secret;
    // Note: next byte after secret is 0x51 (OP_1, claim-branch selector) — not parsed here.
  }
  return null;
}

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
export function parseAuthenticatedOutput(
  rawTxHex: string,
  expectedTxid: string,
  voutIndex: number,
): { value: number; scriptPubKey: Uint8Array } {
  if (!rawTxHex || typeof rawTxHex !== 'string') {
    throw new Error('parseAuthenticatedOutput: empty raw transaction');
  }
  if (!/^[0-9a-fA-F]{64}$/.test(expectedTxid)) {
    throw new Error(`parseAuthenticatedOutput: invalid expectedTxid: ${expectedTxid}`);
  }
  if (!Number.isInteger(voutIndex) || voutIndex < 0) {
    throw new Error(`parseAuthenticatedOutput: invalid voutIndex: ${voutIndex}`);
  }

  let tx: Uint8Array;
  try {
    tx = hexToBytes(rawTxHex);
  } catch {
    throw new Error('parseAuthenticatedOutput: raw transaction is not valid hex');
  }
  if (tx.length < 10) throw new Error('parseAuthenticatedOutput: raw transaction too short');

  // R281-SEGWIT-001 (review #13): BitcoinII/BTC funding parents can be SegWit-serialized (BIP144: marker 0x00 +
  // flag 0x01 right after nVersion). hash256(full witness bytes) = the WTXID, NOT the txid — so the txid must be
  // computed over the STRIPPED legacy serialization (nVersion | inputs | outputs | nLockTime; dropping marker/flag
  // and every witness stack). We never parse the witness data: nLockTime is always the trailing 4 bytes, and the
  // inputs+outputs region is bounded by parsing inputs then outputs. This preserves the anti-forgery guarantee —
  // the txid commits every input, output, and value; the witness (signatures only) does not affect the txid or
  // the output value we authenticate. Parse first (bounds-checked, untrusted), verify the txid, THEN trust value.
  const segwit = tx[4] === 0x00; // a real non-witness tx has >=1 input, so inCount at offset 4 is never 0x00
  if (segwit && tx[5] !== 0x01) {
    throw new Error('parseAuthenticatedOutput: SegWit marker (0x00) without a valid flag (0x01) — malformed tx');
  }
  const inputsStart = segwit ? 6 : 4; // skip nVersion(4) [+ marker(1) + flag(1) when SegWit]
  let offset = inputsStart;

  const inCountV = readVarInt(tx, offset);
  if (!inCountV) throw new Error('parseAuthenticatedOutput: truncated input count');
  const inCount = inCountV.value;
  if (inCount === 0) throw new Error('parseAuthenticatedOutput: zero inputs (malformed tx)');
  if (inCount > 100_000) throw new Error('parseAuthenticatedOutput: implausible input count');
  offset += inCountV.bytesRead;

  for (let i = 0; i < inCount; i++) {
    offset += 36; // prevout: 32-byte txid + 4-byte vout
    const ssLenV = readVarInt(tx, offset);
    if (!ssLenV) throw new Error('parseAuthenticatedOutput: truncated scriptSig length');
    offset += ssLenV.bytesRead + ssLenV.value + 4; // scriptSig + nSequence(4)
    if (offset > tx.length) throw new Error('parseAuthenticatedOutput: input overruns tx');
  }

  const outCountV = readVarInt(tx, offset);
  if (!outCountV) throw new Error('parseAuthenticatedOutput: truncated output count');
  const outCount = outCountV.value;
  offset += outCountV.bytesRead;
  if (voutIndex >= outCount) {
    throw new Error(`parseAuthenticatedOutput: voutIndex ${voutIndex} out of range (tx has ${outCount} outputs)`);
  }

  let value = 0;
  let scriptPubKey = new Uint8Array(0);
  for (let i = 0; i < outCount; i++) {
    if (offset + 8 > tx.length) throw new Error('parseAuthenticatedOutput: truncated output value');
    // 8-byte LE value (NOT a varint) → read via BigInt to avoid 2^32 overflow.
    let v = 0n;
    for (let b = 0; b < 8; b++) v |= BigInt(tx[offset + b]) << BigInt(8 * b);
    offset += 8;
    if (v > BigInt(Number.MAX_SAFE_INTEGER)) {
      throw new Error('parseAuthenticatedOutput: output value exceeds MAX_SAFE_INTEGER');
    }
    const spkLenV = readVarInt(tx, offset);
    if (!spkLenV) throw new Error('parseAuthenticatedOutput: truncated scriptPubKey length');
    offset += spkLenV.bytesRead;
    if (offset + spkLenV.value > tx.length) {
      throw new Error('parseAuthenticatedOutput: scriptPubKey overruns tx');
    }
    if (i === voutIndex) {
      value = Number(v);
      scriptPubKey = tx.slice(offset, offset + spkLenV.value);
    }
    offset += spkLenV.value;
  }
  const outputsEnd = offset;
  if (tx.length < outputsEnd + 4) throw new Error('parseAuthenticatedOutput: tx too short for nLockTime');

  // SELF-AUTHENTICATE against the STRIPPED (legacy) serialization: for a non-witness tx that is the full bytes
  // (txid == wtxid); for a SegWit tx it is nVersion + [inputs..outputs] + trailing nLockTime(4).
  let stripped: Uint8Array;
  if (segwit) {
    const ver = tx.slice(0, 4), body = tx.slice(inputsStart, outputsEnd), lt = tx.slice(tx.length - 4);
    stripped = new Uint8Array(ver.length + body.length + lt.length);
    stripped.set(ver, 0); stripped.set(body, ver.length); stripped.set(lt, ver.length + body.length);
  } else {
    stripped = tx;
  }
  const computedTxid = bytesToHex(reverseBytes(hash256(stripped)));
  if (computedTxid !== expectedTxid.toLowerCase()) {
    throw new Error(
      `parseAuthenticatedOutput: txid mismatch — proxy returned bytes for ${computedTxid} ` +
      `but expected ${expectedTxid.toLowerCase()} (possible malicious/compromised proxy)`,
    );
  }

  if (!Number.isInteger(value) || value <= 0) {
    throw new Error(`parseAuthenticatedOutput: output ${voutIndex} has non-positive value ${value}`);
  }
  return { value, scriptPubKey };
}

// ============================================================================
// Internal: Sighash computation
// ============================================================================

function computeSighash(
  inputs: Array<{ utxo: Utxo; scriptCode: Uint8Array }>,
  outputs: Array<{ scriptPubKey: Uint8Array; value: number }>,
  inputIndex: number,
  hashType: number,
  useBip143: boolean,
  nLockTime: number,
  nSequence: number,
): Uint8Array {
  // R114-HTLC-002: bounds-check inputIndex — out-of-range dereference produces an opaque TypeError
  if (inputIndex < 0 || inputIndex >= inputs.length) {
    throw new Error(`computeSighash: inputIndex ${inputIndex} out of range (inputs.length=${inputs.length})`);
  }
  // R114-HTLC-004: validate nLockTime fits in uint32 — writeUInt32LE silently truncates values > 0xFFFFFFFF
  if (!Number.isInteger(nLockTime) || nLockTime < 0 || nLockTime > 0xFFFFFFFF) {
    throw new Error(`computeSighash: nLockTime must be a uint32 [0, 0xFFFFFFFF]; got ${nLockTime}`);
  }
  const version = writeUInt32LE(2);
  const locktime = writeUInt32LE(nLockTime);

  if (useBip143) {
    // BIP143 sighash (BCH2, BCH)
    // R64-HT-002: honour SIGHASH_ANYONECANPAY (0x80) — per BIP143 both hashPrevouts and
    // hashSequence must be 32 zero bytes when this flag is set. Omitting this produced an
    // invalid sighash for any future caller passing 0x81/0x82/0x83 hashTypes.
    const anyoneCanPay = (hashType & 0x80) !== 0;
    const prevoutsData: Uint8Array[] = [];
    for (const { utxo } of inputs) {
      prevoutsData.push(reverseBytes(hexToBytes(utxo.tx_hash)));
      prevoutsData.push(writeUInt32LE(utxo.tx_pos));
    }
    const hashPrevouts = anyoneCanPay ? new Uint8Array(32) : hash256(concat(...prevoutsData));

    const sequenceData: Uint8Array[] = [];
    for (let i = 0; i < inputs.length; i++) {
      sequenceData.push(writeUInt32LE(nSequence));
    }
    // Determine base sighash type (strip FORKID bit 0x40 for BCH2/BCH)
    // Moved before hashSequence: BIP143 §4 requires hashSequence = 32 zero bytes for SIGHASH_NONE/SINGLE
    const baseHashType = hashType & 0x1f;
    // R76-HB-001: BIP143 §4 — hashSequence must be 32 zero bytes for SIGHASH_NONE and SIGHASH_SINGLE,
    // not just for ANYONECANPAY. Latent: no current chain config uses these types.
    const hashSequence = (anyoneCanPay || baseHashType === 0x02 || baseHashType === 0x03)
      ? new Uint8Array(32)
      : hash256(concat(...sequenceData));
    let hashOutputs: Uint8Array;
    if (baseHashType === 0x03) { // SIGHASH_SINGLE
      if (inputIndex < outputs.length) {
        const o = outputs[inputIndex];
        hashOutputs = hash256(concat(
          writeUInt64LE(o.value),
          writeVarInt(o.scriptPubKey.length),
          o.scriptPubKey
        ));
      } else {
        // R74-HT-002: BIP143 §4 specifies hashOutputs = 32 zero bytes (not hash256(empty)) for
        // SIGHASH_SINGLE when inputIndex >= outputs.length. hash256(empty) is a different value
        // and produces invalid signatures. Latent — no current config uses SIGHASH_SINGLE.
        hashOutputs = new Uint8Array(32);
      }
    } else if (baseHashType === 0x02) { // SIGHASH_NONE
      // R75-HT-001: BIP143 §4 specifies hashOutputs = 32 zero bytes for SIGHASH_NONE,
      // not hash256(empty) which produces a non-zero SHA256d value.
      hashOutputs = new Uint8Array(32);
    } else { // SIGHASH_ALL (0x01) — default
      const outputsData: Uint8Array[] = [];
      for (const output of outputs) {
        outputsData.push(
          writeUInt64LE(output.value),
          writeVarInt(output.scriptPubKey.length),
          output.scriptPubKey
        );
      }
      hashOutputs = hash256(concat(...outputsData));
    }

    const input = inputs[inputIndex];
    const preimage = concat(
      version,
      hashPrevouts,
      hashSequence,
      reverseBytes(hexToBytes(input.utxo.tx_hash)),
      writeUInt32LE(input.utxo.tx_pos),
      writeVarInt(input.scriptCode.length),
      input.scriptCode,
      writeUInt64LE(input.utxo.value),
      writeUInt32LE(nSequence),
      hashOutputs,
      locktime,
      writeUInt32LE(hashType),
    );

    return hash256(preimage);
  } else {
    // Legacy sighash (BTC, BC2)
    const parts: Uint8Array[] = [version, writeVarInt(inputs.length)];

    // R44-HTLC-003: per legacy sighash spec, non-signing inputs must have nSequence=0
    // for SIGHASH_NONE (0x02) and SIGHASH_SINGLE (0x03). Only the signing input (i===inputIndex)
    // and SIGHASH_ALL (0x01) use the actual nSequence value.
    const baseHashType = hashType & 0x1f;
    // R130-LEGACY-SINGLE-001: this app only ever signs SIGHASH_ALL HTLC spends. The legacy
    // SIGHASH_NONE/SINGLE branches below are unreachable in practice and the SINGLE branch does NOT
    // implement Bitcoin Core's `return uint256(1)` edge case (inputIndex >= outputs.length), so it
    // would silently produce an invalid sighash. Fail loud if a future config regression ever selects
    // a non-ALL legacy type, rather than producing rejected signatures.
    if (baseHashType === 0x02 || baseHashType === 0x03) {
      throw new Error(`legacy SIGHASH_NONE/SINGLE (0x${baseHashType.toString(16)}) not supported — only SIGHASH_ALL`);
    }
    for (let i = 0; i < inputs.length; i++) {
      const { utxo } = inputs[i];
      parts.push(reverseBytes(hexToBytes(utxo.tx_hash)));
      parts.push(writeUInt32LE(utxo.tx_pos));
      if (i === inputIndex) {
        parts.push(writeVarInt(inputs[i].scriptCode.length));
        parts.push(inputs[i].scriptCode);
      } else {
        parts.push(new Uint8Array([0]));
      }
      const seqForInput = (i === inputIndex || baseHashType === 0x01)
        ? nSequence
        : 0x00000000;
      parts.push(writeUInt32LE(seqForInput));
    }

    // R77-HB-004: legacy sighash — SIGHASH_NONE serializes no outputs; SIGHASH_SINGLE serializes
    // only the output at inputIndex (placeholder -1/empty for prior outputs). Per Bitcoin Core.
    if (baseHashType === 0x02) { // SIGHASH_NONE: empty output list
      parts.push(writeVarInt(0));
    } else if (baseHashType === 0x03) { // SIGHASH_SINGLE: outputs up to and including inputIndex
      if (inputIndex < outputs.length) {
        parts.push(writeVarInt(inputIndex + 1));
        for (let i = 0; i < inputIndex; i++) {
          // placeholder: value=-1 (0xffffffffffffffff), empty scriptPubKey
          parts.push(new Uint8Array([0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]));
          parts.push(writeVarInt(0));
        }
        parts.push(writeUInt64LE(outputs[inputIndex].value));
        parts.push(writeVarInt(outputs[inputIndex].scriptPubKey.length));
        parts.push(outputs[inputIndex].scriptPubKey);
      } else {
        // inputIndex >= outputs.length: per legacy spec, serialize 0 outputs (same as NONE)
        parts.push(writeVarInt(0));
      }
    } else { // SIGHASH_ALL: all outputs
      parts.push(writeVarInt(outputs.length));
      for (const output of outputs) {
        parts.push(writeUInt64LE(output.value));
        parts.push(writeVarInt(output.scriptPubKey.length));
        parts.push(output.scriptPubKey);
      }
    }

    parts.push(locktime);
    parts.push(writeUInt32LE(hashType));

    return hash256(concat(...parts));
  }
}

// ============================================================================
// Internal: Transaction building
// ============================================================================

async function buildSignedTx(
  inputs: Array<{ utxo: Utxo; privateKey: Uint8Array; publicKey: Uint8Array; scriptPubKey: Uint8Array }>,
  outputs: Array<{ scriptPubKey: Uint8Array; value: number }>,
  hashType: number,
  useBip143: boolean,
  chain: Chain,
): Promise<{ txid: string; rawTx: string; fee: number }> {
  const scriptCodeInputs = inputs.map(i => ({ utxo: i.utxo, scriptCode: i.scriptPubKey }));

  const signatures: Uint8Array[] = [];
  for (let i = 0; i < inputs.length; i++) {
    const sighash = computeSighash(scriptCodeInputs, outputs, i, hashType, useBip143, 0, 0xffffffff);
    // R58-HTB-007: explicitly request low-s signatures
    const sig = await secp256k1.signAsync(sighash, inputs[i].privateKey, { lowS: true });
    const sigDer = compactToDER(sig.toCompactRawBytes());
    signatures.push(concat(sigDer, new Uint8Array([hashType])));
  }

  const txInputs = inputs.map((inp, i) => {
    const scriptSig = concat(
      pushData(signatures[i]),
      pushData(inp.publicKey),
    );
    return { utxo: inp.utxo, scriptSig, nSequence: 0xffffffff };
  });

  const { txid, rawTx } = serializeTx(txInputs, outputs, 0);
  const totalIn = inputs.reduce((s, i) => s + i.utxo.value, 0);
  const totalOut = outputs.reduce((s, o) => s + o.value, 0);
  return { txid, rawTx, fee: totalIn - totalOut };
}

function serializeTx(
  inputs: Array<{ utxo: Utxo; scriptSig: Uint8Array; nSequence: number }>,
  outputs: Array<{ scriptPubKey: Uint8Array; value: number }>,
  nLockTime: number,
): { txid: string; rawTx: string } {
  // R114-HTLC-004: validate nLockTime fits in uint32 — writeUInt32LE silently truncates larger values
  if (!Number.isInteger(nLockTime) || nLockTime < 0 || nLockTime > 0xFFFFFFFF) {
    throw new Error(`serializeTx: nLockTime must be a uint32 [0, 0xFFFFFFFF]; got ${nLockTime}`);
  }
  const parts: Uint8Array[] = [
    writeUInt32LE(2), // version
    writeVarInt(inputs.length),
  ];

  for (const { utxo, scriptSig, nSequence } of inputs) {
    parts.push(reverseBytes(hexToBytes(utxo.tx_hash)));
    parts.push(writeUInt32LE(utxo.tx_pos));
    parts.push(writeVarInt(scriptSig.length));
    parts.push(scriptSig);
    parts.push(writeUInt32LE(nSequence));
  }

  parts.push(writeVarInt(outputs.length));
  for (const { scriptPubKey, value } of outputs) {
    parts.push(writeUInt64LE(value));
    parts.push(writeVarInt(scriptPubKey.length));
    parts.push(scriptPubKey);
  }

  parts.push(writeUInt32LE(nLockTime));

  const rawTxBytes = concat(...parts);
  const txid = bytesToHex(reverseBytes(hash256(rawTxBytes)));
  return { txid, rawTx: bytesToHex(rawTxBytes) };
}

// ============================================================================
// Exports: helper functions needed by swap engine
// ============================================================================

export { hexToBytes, bytesToHex, hash160, sha256, concat, pushData };
