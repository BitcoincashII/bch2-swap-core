import { describe, it, expect } from 'vitest';
import { sha256 } from '@noble/hashes/sha256';
import { deriveSwapSecret, deriveSwapKss, swapSecretFromKss, deriveMakerIdPub, generateSwapNonce, SWAP_NONCE_BYTES, signMakerIdentity, verifyMakerIdentity, deriveApiAuthPub, signApiRequest, buildApiAuthPreimage } from './seed-secret';
import { createPublicKey, verify as cryptoVerify } from 'node:crypto';

// ── FROZEN canonical vectors (DECISION A, 2026-07-08) ────────────────────────────────────────────
// These lock the derivation forever. A change to seed-secret.ts's paths/domain/primitive that alters
// any real swap secret will FAIL here. Independently verified against @scure/bip32 + ethers and
// @noble/hashes + node:crypto before freezing. DO NOT update these expected values to "fix" a failure —
// a failure means the derivation changed, which would strand funds.
const hex = (u: Uint8Array) => Array.from(u).map((b) => b.toString(16).padStart(2, '0')).join('');
const fromHex = (s: string) => Uint8Array.from(s.match(/../g)!.map((h) => parseInt(h, 16)));

const TEST_MNEMONIC = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
const TEST_NONCE = fromHex('00112233445566778899aabbccddeeff'); // 16 bytes, public
const VEC = {
  S: 'b0c55e261b5e9a95866e2214aa4051ba47cb51152a628a7f393d6101be4b3136', // preimage
  H: '8475d1e9396d7e63e4c0afffba0ad373eaf9b5928c5554966ebc351fd375d84d', // SHA256(S) = hashLock
  idPub: '032a4e44b87858d7fd45c462a1cd5bbc130a3c9fe545081e1c6c3b9ae7723d8afe',
};

describe('seed-secret FROZEN vectors — DECISION A (do not change)', () => {
  it('deriveSwapSecret reproduces the canonical preimage S', () => {
    expect(hex(deriveSwapSecret(TEST_MNEMONIC, TEST_NONCE)!)).toBe(VEC.S);
  });
  it('SHA256(S) reproduces the canonical hashLock H (the on-chain HTLC hashlock)', () => {
    expect(hex(sha256(deriveSwapSecret(TEST_MNEMONIC, TEST_NONCE)!))).toBe(VEC.H);
  });
  it('deriveMakerIdPub reproduces the canonical identity pubkey', () => {
    expect(deriveMakerIdPub(TEST_MNEMONIC)).toBe(VEC.idPub);
  });

  it('is deterministic — same (mnemonic, nonce) always yields the same secret (recovery)', () => {
    expect(hex(deriveSwapSecret(TEST_MNEMONIC, TEST_NONCE)!)).toBe(hex(deriveSwapSecret(TEST_MNEMONIC, TEST_NONCE)!));
  });
  it('different nonce → different secret', () => {
    const other = deriveSwapSecret(TEST_MNEMONIC, fromHex('ffffffffffffffffffffffffffffffff'))!;
    expect(hex(other)).not.toBe(VEC.S);
  });
  it('returns a 32-byte secret', () => {
    expect(deriveSwapSecret(TEST_MNEMONIC, TEST_NONCE)!.length).toBe(32);
  });

  it('rejects an invalid mnemonic', () => {
    expect(deriveSwapSecret('not a valid bip39 mnemonic at all', TEST_NONCE)).toBeNull();
    expect(deriveMakerIdPub('not a valid bip39 mnemonic at all')).toBeNull();
  });
  it('rejects a wrong-length nonce (fail-closed)', () => {
    expect(deriveSwapSecret(TEST_MNEMONIC, new Uint8Array(8))).toBeNull();
    expect(deriveSwapSecret(TEST_MNEMONIC, new Uint8Array(32))).toBeNull();
  });
  it('generateSwapNonce is 16 bytes and never all-zero', () => {
    for (let i = 0; i < 50; i++) {
      const n = generateSwapNonce();
      expect(n.length).toBe(SWAP_NONCE_BYTES);
      expect(n.every((b) => b === 0)).toBe(false);
    }
  });
});

// ── deriveSwapKss + swapSecretFromKss (the cached-key two-step path) ─────────────────────────────
// deriveSwapSecret = deriveSwapKss(mnemonic) then swapSecretFromKss(kss, nonce). The wallet caches K_ss at
// unlock and re-derives the preimage with swapSecretFromKss at fund/claim time (mnemonic already wiped), so the
// two-step path must match the frozen vector exactly and each half must fail closed (null) on bad input.
describe('deriveSwapKss + swapSecretFromKss (cached-key path)', () => {
  it('deriveSwapKss returns a 32-byte key for a valid mnemonic, null for an invalid one', () => {
    const kss = deriveSwapKss(TEST_MNEMONIC);
    expect(kss).not.toBeNull();
    expect(kss!.length).toBe(32);
    expect(deriveSwapKss('not a valid bip39 mnemonic at all')).toBeNull();
  });

  it('swapSecretFromKss(deriveSwapKss, nonce) reproduces the canonical preimage S (two-step == one-step)', () => {
    const kss = deriveSwapKss(TEST_MNEMONIC)!;
    expect(hex(swapSecretFromKss(kss, TEST_NONCE)!)).toBe(VEC.S);
    // identical to the one-step deriveSwapSecret (the wallet's fund-time path must equal the post-time path)
    expect(hex(swapSecretFromKss(kss, TEST_NONCE)!)).toBe(hex(deriveSwapSecret(TEST_MNEMONIC, TEST_NONCE)!));
  });

  it('is deterministic and returns a fresh 32-byte buffer (does not alias / mutate K_ss)', () => {
    const kss = deriveSwapKss(TEST_MNEMONIC)!;
    const kssBefore = hex(kss);
    const s1 = swapSecretFromKss(kss, TEST_NONCE)!;
    const s2 = swapSecretFromKss(kss, TEST_NONCE)!;
    expect(hex(s1)).toBe(hex(s2));          // determinism
    expect(s1.length).toBe(32);
    expect(s1).not.toBe(kss);               // a separate buffer, not the key itself
    s1.fill(0);                             // mutating the output must not touch K_ss
    expect(hex(kss)).toBe(kssBefore);
  });

  it('null on a wrong-length or non-Uint8Array K_ss (fail-closed)', () => {
    expect(swapSecretFromKss(new Uint8Array(31), TEST_NONCE)).toBeNull();
    expect(swapSecretFromKss(new Uint8Array(33), TEST_NONCE)).toBeNull();
    expect(swapSecretFromKss('deadbeef' as unknown as Uint8Array, TEST_NONCE)).toBeNull();
  });

  it('null on a wrong-length or non-Uint8Array nonce (fail-closed)', () => {
    const kss = deriveSwapKss(TEST_MNEMONIC)!;
    expect(swapSecretFromKss(kss, new Uint8Array(8))).toBeNull();
    expect(swapSecretFromKss(kss, new Uint8Array(SWAP_NONCE_BYTES + 1))).toBeNull();
    expect(swapSecretFromKss(kss, '00112233445566778899aabbccddeeff' as unknown as Uint8Array)).toBeNull();
  });
});

describe('maker-identity signature — Phase 2 own-offer authorship', () => {
  const SH = VEC.H; // any valid 64-hex secretHash
  const FROZEN_SIG = '68b8d5be7779d92238b6f98d8ba13d29d34ba06a1a9dce2c8e773d5259180a8f12ea2bab9d770085d86401e0522474a02b18c659695d609501f6edcf068a5bf6';

  it('produces the frozen deterministic signature (RFC6979 low-S)', async () => {
    expect(await signMakerIdentity(TEST_MNEMONIC, SH)).toBe(FROZEN_SIG);
  });
  it('sign -> verify roundtrip succeeds against the derived pubkey', async () => {
    const sig = await signMakerIdentity(TEST_MNEMONIC, SH);
    expect(verifyMakerIdentity(deriveMakerIdPub(TEST_MNEMONIC)!, SH, sig!)).toBe(true);
  });
  it('rejects a wrong secretHash — the sig is offer-specific (no cross-offer replay)', async () => {
    const sig = await signMakerIdentity(TEST_MNEMONIC, SH);
    expect(verifyMakerIdentity(deriveMakerIdPub(TEST_MNEMONIC)!, 'ff'.repeat(32), sig!)).toBe(false);
  });
  it("rejects a different (attacker) pubkey — can't impersonate the maker identity", async () => {
    const sig = await signMakerIdentity(TEST_MNEMONIC, SH);
    expect(verifyMakerIdentity('02' + '11'.repeat(32), SH, sig!)).toBe(false);
  });
  it('rejects a tampered signature', async () => {
    const sig = (await signMakerIdentity(TEST_MNEMONIC, SH))!;
    const tampered = sig.slice(0, -2) + (sig.slice(-2) === '00' ? '01' : '00');
    expect(verifyMakerIdentity(deriveMakerIdPub(TEST_MNEMONIC)!, SH, tampered)).toBe(false);
  });
  it('verify FAILS CLOSED on malformed input (never throws, returns false => offer shown, never force-hidden)', () => {
    expect(verifyMakerIdentity('', SH, '')).toBe(false);
    expect(verifyMakerIdentity('garbage', SH, 'garbage')).toBe(false);
    expect(verifyMakerIdentity(deriveMakerIdPub(TEST_MNEMONIC)!, 'nothex', 'ab')).toBe(false);
    expect(verifyMakerIdentity(deriveMakerIdPub(TEST_MNEMONIC)!, SH, '')).toBe(false);
  });
  it('signMakerIdentity returns null on invalid mnemonic or secretHash', async () => {
    expect(await signMakerIdentity('not a valid bip39 mnemonic', SH)).toBeNull();
    expect(await signMakerIdentity(TEST_MNEMONIC, 'nothex')).toBeNull();
  });
});

describe('API request auth — Phase 4 (m/83\'/2\'/0\', proxy verifies via node:crypto)', () => {
  const PRE = buildApiAuthPreimage({ method: 'PATCH', path: '/api/orders/abc123/status', id: 'abc123', timestamp: 1783100000 });
  const AUTH_PUB = '03134f351973a0f279877af647782ead0a88ebc99b0be3077a90cbf5f9b1e1a12d';
  const FROZEN_SIG = '211294ff3cda0a1f16342c644344514e68ae7f2d0b757efe9ec855f62ae855523bc355971191f0469a9997f199b60dd888cb4af4077643dd4d0d05b3854a49fe';
  // Exactly how the PROXY verifies: SPKI-wrap the 33-byte compressed pubkey, node crypto.verify with ieee-p1363.
  const SPKI_PREFIX = Buffer.from('3036301006072a8648ce3d020106052b8104000a032200', 'hex');
  const proxyVerify = (pubHex: string, preimage: string, sig64: string): boolean => {
    try {
      const key = createPublicKey({ key: Buffer.concat([SPKI_PREFIX, Buffer.from(pubHex, 'hex')]), type: 'spki', format: 'der' });
      return cryptoVerify('sha256', Buffer.from(preimage, 'utf8'), { key, dsaEncoding: 'ieee-p1363' }, Buffer.from(sig64, 'hex'));
    } catch { return false; }
  };

  it('deriveApiAuthPub matches the frozen m/83\'/2\'/0\' pubkey', () => {
    expect(deriveApiAuthPub(TEST_MNEMONIC)).toBe(AUTH_PUB);
  });
  it('signApiRequest produces the frozen deterministic signature', async () => {
    expect(await signApiRequest(TEST_MNEMONIC, PRE)).toBe(FROZEN_SIG);
  });
  it('the proxy node:crypto verify ACCEPTS a genuine client signature (cross-impl contract)', async () => {
    const sig = (await signApiRequest(TEST_MNEMONIC, PRE))!;
    expect(proxyVerify(deriveApiAuthPub(TEST_MNEMONIC)!, PRE, sig)).toBe(true);
  });
  it('proxy verify REJECTS a tampered preimage, wrong pubkey, and cross-order / cross-timestamp replay', async () => {
    const sig = (await signApiRequest(TEST_MNEMONIC, PRE))!;
    expect(proxyVerify(AUTH_PUB, PRE + 'x', sig)).toBe(false);
    expect(proxyVerify('02' + '11'.repeat(32), PRE, sig)).toBe(false);
    // sig for order abc123 must not verify against a different order id/path
    expect(proxyVerify(AUTH_PUB, buildApiAuthPreimage({ method: 'PATCH', path: '/api/orders/OTHER/status', id: 'OTHER', timestamp: 1783100000 }), sig)).toBe(false);
    // nor against a different timestamp (the proxy's ~120s window bounds replay)
    expect(proxyVerify(AUTH_PUB, buildApiAuthPreimage({ method: 'PATCH', path: '/api/orders/abc123/status', id: 'abc123', timestamp: 1783100999 }), sig)).toBe(false);
  });
  it('signApiRequest returns null on an invalid mnemonic', async () => {
    expect(await signApiRequest('not a valid bip39 mnemonic', PRE)).toBeNull();
  });
});
