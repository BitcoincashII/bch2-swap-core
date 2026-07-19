/**
 * FAULT-INJECTION tests for src/core/evm-client.ts — the EVM/HTLC secret-reveal trust boundary.
 *
 * Every function here decides, from data a possibly-compromised RPC returns (getSwap struct,
 * getBlock timestamp, chainId, block height), whether to BROADCAST an on-chain tx. The claim tx
 * carries the 32-byte preimage in its calldata; the instant it hits the mempool the secret is
 * public and the counterparty can sweep the other leg. So the fund-safety invariant tested across
 * this whole file is:
 *
 *     on EVERY fail-closed path, MockSigner.sendTransaction has ZERO calls
 *     (the secret NEVER reaches calldata; no funds move).
 *
 * The MockSigner.sendTransaction spy THROWS the sentinel, so a POSITIVE CONTROL — valid, honest
 * data — proves the guard chain actually lets a broadcast through (spy called EXACTLY once); this
 * rules out a test that "passes" only because some earlier guard always throws.
 *
 * Locks in this session's fixes:
 *   - R278-CLAIM-EXPIRY-FAILCLOSED-001 (#45, evm-client.ts:796-807) — claimSwap fails CLOSED when
 *     chain time (getBlock) is null / NaN / rejected; previously nowSec===undefined fell OPEN and
 *     broadcast the secret on a possibly-expired swap.
 *   - refundSwap unreadable-block fail-closed (evm-client.ts:1018-1020).
 *   - isEvmLockAtSafeDepth 'safe'-tag + numeric-depth fallback + invariant gate (evm-client.ts:1182-1216).
 *
 * All mocks come from the shared harness (src/test/mocks/index.ts), self-tested in harness.test.ts.
 */
import { describe, it, expect } from 'vitest';
import type { Provider, Signer } from 'ethers';
import { ethers } from 'ethers';
import { claimSwap, refundSwap, isEvmLockAtSafeDepth } from './evm-client';
import {
  makeSwap,
  makeHashLock,
  ZERO_SWAP,
  MockEvmProvider,
  MockSigner,
  SENDTX_SENTINEL,
} from './test-mocks';

const HTLC_ADDR = '0x00000000000000000000000000000000000000AA';
const INITIATOR = '0x1111111111111111111111111111111111111111';
const RECIPIENT = '0x2222222222222222222222222222222222222222';
const OTHER = '0x3333333333333333333333333333333333333333';
const DEFAULT_CHAIN = 8453n;

/** Fresh 32-byte secret per test (claimSwap zeroes its input buffer after submit). */
function freshSecret(fill = 7): Uint8Array {
  return new Uint8Array(32).fill(fill);
}
/** Distinct bytes32 swapId per test so the module-level _claimInFlight guard can never bleed. */
let _idCounter = 0;
function nextSwapId(): string {
  _idCounter += 1;
  return '0x' + _idCounter.toString(16).padStart(64, '0');
}

// A signer whose address == the HTLC recipient, on the default chain, wrapping the given provider.
function recipientSigner(provider: MockEvmProvider): MockSigner {
  return new MockSigner(provider, RECIPIENT);
}

// ============================================================================
// claimSwap — R278-CLAIM-EXPIRY-FAILCLOSED-001 (#45) + all pre-broadcast guards
// ============================================================================

describe('claimSwap FAIL-CLOSED: the secret never reaches calldata on any fault (evm-client.ts:684-956)', () => {
  it('POSITIVE CONTROL: valid honest data broadcasts sendTransaction EXACTLY once (secret reaches calldata)', async () => {
    // Prove the guard chain is passable: a swap that matches hashLock+recipient, is unexpired, and
    // whose chain time is readable reaches htlc.claim() -> signer.sendTransaction (spy throws sentinel).
    const secret = freshSecret();
    const hashLock = makeHashLock(ethers.hexlify(secret));
    const provider = new MockEvmProvider({
      swap: makeSwap({ recipient: RECIPIENT, hashLock, timeLock: 1_800_000_000n }),
      block: { timestamp: 1_700_000_000 }, // < timeLock -> unexpired
      chainId: DEFAULT_CHAIN,
    });
    const signer = recipientSigner(provider);
    await expect(
      claimSwap(HTLC_ADDR, nextSwapId(), secret, signer as unknown as Signer),
    ).rejects.toThrow(SENDTX_SENTINEL);
    // The ONLY test in this describe where the spy fires: valid data => exactly one broadcast attempt.
    expect(signer.broadcastCount).toBe(1);
  });

  it('null getBlock -> R278 fails closed, NO broadcast (evm-client.ts:792-807)', async () => {
    const secret = freshSecret();
    const hashLock = makeHashLock(ethers.hexlify(secret));
    const provider = new MockEvmProvider({
      swap: makeSwap({ recipient: RECIPIENT, hashLock, timeLock: 1_800_000_000n }),
      block: null, // R278: chain time unreadable
      chainId: DEFAULT_CHAIN,
    });
    const signer = recipientSigner(provider);
    await expect(
      claimSwap(HTLC_ADDR, nextSwapId(), secret, signer as unknown as Signer),
    ).rejects.toThrow(/could not read chain time/i);
    expect(signer.broadcastCount).toBe(0);
  });

  it('NaN-timestamp getBlock -> R278 fails closed, NO broadcast (Number.isFinite guard, evm-client.ts:792)', async () => {
    const secret = freshSecret();
    const hashLock = makeHashLock(ethers.hexlify(secret));
    const provider = new MockEvmProvider({
      swap: makeSwap({ recipient: RECIPIENT, hashLock, timeLock: 1_800_000_000n }),
      block: { timestamp: NaN }, // stale/garbage block time
      chainId: DEFAULT_CHAIN,
    });
    const signer = recipientSigner(provider);
    await expect(
      claimSwap(HTLC_ADDR, nextSwapId(), secret, signer as unknown as Signer),
    ).rejects.toThrow(/could not read chain time/i);
    expect(signer.broadcastCount).toBe(0);
  });

  it('rejected getBlock -> R278 fails closed, NO broadcast (catch leaves nowSec undefined, evm-client.ts:793-807)', async () => {
    const secret = freshSecret();
    const hashLock = makeHashLock(ethers.hexlify(secret));
    const provider = new MockEvmProvider({
      swap: makeSwap({ recipient: RECIPIENT, hashLock, timeLock: 1_800_000_000n }),
      chainId: DEFAULT_CHAIN,
    });
    // Simulate an RPC that ERRORS on eth_getBlockByNumber.
    provider.getBlock = async () => { throw new Error('RPC getBlock unreachable'); };
    const signer = recipientSigner(provider);
    await expect(
      claimSwap(HTLC_ADDR, nextSwapId(), secret, signer as unknown as Signer),
    ).rejects.toThrow(/could not read chain time/i);
    expect(signer.broadcastCount).toBe(0);
  });

  it('already-expired swap (now >= timeLock) -> aborts, NO broadcast (evm-client.ts:808-813)', async () => {
    const secret = freshSecret();
    const hashLock = makeHashLock(ethers.hexlify(secret));
    const provider = new MockEvmProvider({
      swap: makeSwap({ recipient: RECIPIENT, hashLock, timeLock: 1_800_000_000n }),
      block: { timestamp: 1_900_000_000 }, // > timeLock -> expired; claim() would revert & leak secret
      chainId: DEFAULT_CHAIN,
    });
    const signer = recipientSigner(provider);
    await expect(
      claimSwap(HTLC_ADDR, nextSwapId(), secret, signer as unknown as Signer),
    ).rejects.toThrow(/timelock expired/i);
    expect(signer.broadcastCount).toBe(0);
  });

  it('recipient mismatch (HTLC is for someone else) -> aborts, NO broadcast (evm-client.ts:754-759)', async () => {
    const secret = freshSecret();
    const hashLock = makeHashLock(ethers.hexlify(secret));
    const provider = new MockEvmProvider({
      // A compromised RPC returns a struct whose recipient is NOT our signer.
      swap: makeSwap({ recipient: OTHER, hashLock, timeLock: 1_800_000_000n }),
      block: { timestamp: 1_700_000_000 },
      chainId: DEFAULT_CHAIN,
    });
    const signer = recipientSigner(provider); // signer is RECIPIENT, struct says OTHER
    await expect(
      claimSwap(HTLC_ADDR, nextSwapId(), secret, signer as unknown as Signer),
    ).rejects.toThrow(/recipient mismatch/i);
    expect(signer.broadcastCount).toBe(0);
  });

  it('wrong secret vs hashLock -> aborts before reveal, NO broadcast (evm-client.ts:817-825)', async () => {
    const secret = freshSecret();
    // Struct carries a hashLock that is NOT sha256(secret) -> claim() would revert & expose wrong value.
    const provider = new MockEvmProvider({
      swap: makeSwap({ recipient: RECIPIENT, hashLock: '0x' + 'de'.repeat(32), timeLock: 1_800_000_000n }),
      block: { timestamp: 1_700_000_000 },
      chainId: DEFAULT_CHAIN,
    });
    const signer = recipientSigner(provider);
    await expect(
      claimSwap(HTLC_ADDR, nextSwapId(), secret, signer as unknown as Signer),
    ).rejects.toThrow(/does not match hashLock/i);
    expect(signer.broadcastCount).toBe(0);
  });

  it('already-claimed swap -> aborts, NO broadcast (evm-client.ts:739-741)', async () => {
    const secret = freshSecret();
    const hashLock = makeHashLock(ethers.hexlify(secret));
    const provider = new MockEvmProvider({
      swap: makeSwap({ recipient: RECIPIENT, hashLock, timeLock: 1_800_000_000n, claimed: true }),
      block: { timestamp: 1_700_000_000 },
      chainId: DEFAULT_CHAIN,
    });
    const signer = recipientSigner(provider);
    await expect(
      claimSwap(HTLC_ADDR, nextSwapId(), secret, signer as unknown as Signer),
    ).rejects.toThrow(/already claimed/i);
    expect(signer.broadcastCount).toBe(0);
  });

  it('already-refunded swap -> aborts, NO broadcast (evm-client.ts:742-744)', async () => {
    const secret = freshSecret();
    const hashLock = makeHashLock(ethers.hexlify(secret));
    const provider = new MockEvmProvider({
      swap: makeSwap({ recipient: RECIPIENT, hashLock, timeLock: 1_800_000_000n, refunded: true }),
      block: { timestamp: 1_700_000_000 },
      chainId: DEFAULT_CHAIN,
    });
    const signer = recipientSigner(provider);
    await expect(
      claimSwap(HTLC_ADDR, nextSwapId(), secret, signer as unknown as Signer),
    ).rejects.toThrow(/already refunded/i);
    expect(signer.broadcastCount).toBe(0);
  });

  it('chainId mismatch -> aborts before any read, NO broadcast (evm-client.ts:711-722)', async () => {
    const secret = freshSecret();
    const hashLock = makeHashLock(ethers.hexlify(secret));
    const provider = new MockEvmProvider({
      swap: makeSwap({ recipient: RECIPIENT, hashLock, timeLock: 1_800_000_000n }),
      block: { timestamp: 1_700_000_000 },
      chainId: DEFAULT_CHAIN, // wallet on 8453...
    });
    const signer = recipientSigner(provider);
    await expect(
      claimSwap(HTLC_ADDR, nextSwapId(), secret, signer as unknown as Signer, 1), // ...but caller expects 1
    ).rejects.toThrow(/chain mismatch/i);
    expect(signer.broadcastCount).toBe(0);
  });

  it('unfunded / non-existent swap (getSwap -> null) -> aborts, NO broadcast (evm-client.ts:736-738)', async () => {
    const secret = freshSecret();
    const provider = new MockEvmProvider({
      swap: ZERO_SWAP, // zero initiator -> getSwap decodes to null
      block: { timestamp: 1_700_000_000 },
      chainId: DEFAULT_CHAIN,
    });
    const signer = recipientSigner(provider);
    await expect(
      claimSwap(HTLC_ADDR, nextSwapId(), secret, signer as unknown as Signer),
    ).rejects.toThrow(/not found or unfunded/i);
    expect(signer.broadcastCount).toBe(0);
  });
});

// ============================================================================
// refundSwap — unreadable-block fail-closed + pre-broadcast guards (evm-client.ts:959-1116)
// ============================================================================

describe('refundSwap FAIL-CLOSED: no refund tx broadcasts on any fault (evm-client.ts:959-1116)', () => {
  // A signer that IS the HTLC initiator (refund is initiator-only).
  function initiatorSigner(provider: MockEvmProvider): MockSigner {
    return new MockSigner(provider, INITIATOR);
  }

  it('POSITIVE CONTROL: an expired, initiator-owned, unclaimed swap reaches htlc.refund -> spy fires once', async () => {
    const provider = new MockEvmProvider({
      swap: makeSwap({ initiator: INITIATOR, timeLock: 1_800_000_000n }),
      block: { timestamp: 1_900_000_000 }, // now > timeLock -> refundable
      chainId: DEFAULT_CHAIN,
    });
    const signer = initiatorSigner(provider);
    await expect(
      refundSwap(HTLC_ADDR, nextSwapId(), signer as unknown as Signer),
    ).rejects.toThrow(SENDTX_SENTINEL);
    expect(signer.broadcastCount).toBe(1);
  });

  it('unreadable block (null) -> fails closed, NO refund broadcast (evm-client.ts:1018-1020)', async () => {
    const provider = new MockEvmProvider({
      swap: makeSwap({ initiator: INITIATOR, timeLock: 1_800_000_000n }),
      block: null, // cannot verify expiry
      chainId: DEFAULT_CHAIN,
    });
    const signer = initiatorSigner(provider);
    await expect(
      refundSwap(HTLC_ADDR, nextSwapId(), signer as unknown as Signer),
    ).rejects.toThrow(/could not read latest block timestamp/i);
    expect(signer.broadcastCount).toBe(0);
  });

  it('unreadable block (NaN timestamp) -> fails closed, NO refund broadcast (evm-client.ts:1018)', async () => {
    const provider = new MockEvmProvider({
      swap: makeSwap({ initiator: INITIATOR, timeLock: 1_800_000_000n }),
      block: { timestamp: NaN },
      chainId: DEFAULT_CHAIN,
    });
    const signer = initiatorSigner(provider);
    await expect(
      refundSwap(HTLC_ADDR, nextSwapId(), signer as unknown as Signer),
    ).rejects.toThrow(/could not read latest block timestamp/i);
    expect(signer.broadcastCount).toBe(0);
  });

  it('premature refund (now <= timeLock) -> rejected, NO broadcast (evm-client.ts:1022-1027)', async () => {
    const provider = new MockEvmProvider({
      swap: makeSwap({ initiator: INITIATOR, timeLock: 1_800_000_000n }),
      block: { timestamp: 1_700_000_000 }, // now < timeLock -> not yet refundable
      chainId: DEFAULT_CHAIN,
    });
    const signer = initiatorSigner(provider);
    await expect(
      refundSwap(HTLC_ADDR, nextSwapId(), signer as unknown as Signer),
    ).rejects.toThrow(/timelock has not expired/i);
    expect(signer.broadcastCount).toBe(0);
  });

  it('caller is NOT the initiator -> rejected, NO broadcast (evm-client.ts:986-991)', async () => {
    const provider = new MockEvmProvider({
      swap: makeSwap({ initiator: INITIATOR, timeLock: 1_800_000_000n }),
      block: { timestamp: 1_900_000_000 },
      chainId: DEFAULT_CHAIN,
    });
    // Signer is OTHER, but the HTLC initiator is INITIATOR.
    const signer = new MockSigner(provider, OTHER);
    await expect(
      refundSwap(HTLC_ADDR, nextSwapId(), signer as unknown as Signer),
    ).rejects.toThrow(/not the HTLC initiator/i);
    expect(signer.broadcastCount).toBe(0);
  });

  it('already-claimed swap -> rejected (secret is on-chain), NO broadcast (evm-client.ts:992)', async () => {
    const provider = new MockEvmProvider({
      swap: makeSwap({ initiator: INITIATOR, timeLock: 1_800_000_000n, claimed: true }),
      block: { timestamp: 1_900_000_000 },
      chainId: DEFAULT_CHAIN,
    });
    const signer = initiatorSigner(provider);
    await expect(
      refundSwap(HTLC_ADDR, nextSwapId(), signer as unknown as Signer),
    ).rejects.toThrow(/already claimed/i);
    expect(signer.broadcastCount).toBe(0);
  });

  it('already-refunded swap -> rejected, NO broadcast (evm-client.ts:993)', async () => {
    const provider = new MockEvmProvider({
      swap: makeSwap({ initiator: INITIATOR, timeLock: 1_800_000_000n, refunded: true }),
      block: { timestamp: 1_900_000_000 },
      chainId: DEFAULT_CHAIN,
    });
    const signer = initiatorSigner(provider);
    await expect(
      refundSwap(HTLC_ADDR, nextSwapId(), signer as unknown as Signer),
    ).rejects.toThrow(/already refunded/i);
    expect(signer.broadcastCount).toBe(0);
  });

  it('swap not found (getSwap -> null) -> rejected, NO broadcast (evm-client.ts:979)', async () => {
    const provider = new MockEvmProvider({
      swap: ZERO_SWAP,
      block: { timestamp: 1_900_000_000 },
      chainId: DEFAULT_CHAIN,
    });
    const signer = initiatorSigner(provider);
    await expect(
      refundSwap(HTLC_ADDR, nextSwapId(), signer as unknown as Signer),
    ).rejects.toThrow(/not found/i);
    expect(signer.broadcastCount).toBe(0);
  });
});

// ============================================================================
// isEvmLockAtSafeDepth — depth gate that guards an irreversible UTXO fund-commit
// (evm-client.ts:1182-1216). Pure read: returns boolean, must FAIL CLOSED (false).
// ============================================================================

describe('isEvmLockAtSafeDepth FAIL-CLOSED depth/invariant gate (evm-client.ts:1182-1216)', () => {
  const SWAP_ID = '0x' + 'ab'.repeat(32);
  const HASHLOCK = makeHashLock('0x' + '9'.repeat(64));

  /** Wrap a provider so the 'safe' block tag THROWS (RPC does not serve it) -> exercise numeric fallback. */
  function noSafeTag(provider: MockEvmProvider): MockEvmProvider {
    const orig = provider.call.bind(provider);
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    provider.call = async (tx: any) => {
      if (tx?.blockTag === 'safe') throw new Error("RPC does not serve the 'safe' block tag");
      return orig(tx);
    };
    return provider;
  }

  it("HAPPY: 'safe'-tag lock matching all invariants -> true (evm-client.ts:1192-1215)", async () => {
    const provider = new MockEvmProvider({
      safeSwap: makeSwap({ hashLock: HASHLOCK, recipient: RECIPIENT, amount: 1_000n }),
    });
    const ok = await isEvmLockAtSafeDepth(HTLC_ADDR, SWAP_ID, provider as unknown as Provider, 12, {
      hashLock: HASHLOCK,
      recipient: RECIPIENT,
      minAmount: 1_000n,
    });
    expect(ok).toBe(true);
  });

  it('NUMERIC FALLBACK: no safe tag -> reads at tip-(reqConf-1); matching lock -> true (evm-client.ts:1197-1209)', async () => {
    const provider = noSafeTag(new MockEvmProvider({
      swap: makeSwap({ hashLock: HASHLOCK, recipient: RECIPIENT, amount: 1_000n }),
      blockNumber: 1_000, // tip > requiredConfirmations
    }));
    const ok = await isEvmLockAtSafeDepth(HTLC_ADDR, SWAP_ID, provider as unknown as Provider, 12, {
      hashLock: HASHLOCK,
      recipient: RECIPIENT,
      minAmount: 1_000n,
    });
    expect(ok).toBe(true);
  });

  it('hashLock mismatch (lying/replaced lock reuses swapId) -> false (evm-client.ts:1212)', async () => {
    const provider = new MockEvmProvider({
      safeSwap: makeSwap({ hashLock: '0x' + 'de'.repeat(32), recipient: RECIPIENT, amount: 1_000n }),
    });
    const ok = await isEvmLockAtSafeDepth(HTLC_ADDR, SWAP_ID, provider as unknown as Provider, 12, {
      hashLock: HASHLOCK,
    });
    expect(ok).toBe(false);
  });

  it('recipient mismatch (same-nonce replacement redirects funds) -> false (evm-client.ts:1213)', async () => {
    const provider = new MockEvmProvider({
      safeSwap: makeSwap({ hashLock: HASHLOCK, recipient: OTHER, amount: 1_000n }),
    });
    const ok = await isEvmLockAtSafeDepth(HTLC_ADDR, SWAP_ID, provider as unknown as Provider, 12, {
      hashLock: HASHLOCK,
      recipient: RECIPIENT,
    });
    expect(ok).toBe(false);
  });

  it('amount below agreed minimum (under-funded lock) -> false (evm-client.ts:1214)', async () => {
    const provider = new MockEvmProvider({
      safeSwap: makeSwap({ hashLock: HASHLOCK, recipient: RECIPIENT, amount: 999n }),
    });
    const ok = await isEvmLockAtSafeDepth(HTLC_ADDR, SWAP_ID, provider as unknown as Provider, 12, {
      hashLock: HASHLOCK,
      recipient: RECIPIENT,
      minAmount: 1_000n,
    });
    expect(ok).toBe(false);
  });

  it('claimed/refunded at the safe point -> false (evm-client.ts:1211)', async () => {
    const provider = new MockEvmProvider({
      safeSwap: makeSwap({ hashLock: HASHLOCK, recipient: RECIPIENT, amount: 1_000n, claimed: true }),
    });
    const ok = await isEvmLockAtSafeDepth(HTLC_ADDR, SWAP_ID, provider as unknown as Provider, 12, {
      hashLock: HASHLOCK,
    });
    expect(ok).toBe(false);
  });

  it('lock absent at the safe point (getSwap -> null) -> false (evm-client.ts:1210)', async () => {
    const provider = new MockEvmProvider({ safeSwap: ZERO_SWAP });
    const ok = await isEvmLockAtSafeDepth(HTLC_ADDR, SWAP_ID, provider as unknown as Provider, 12, {
      hashLock: HASHLOCK,
    });
    expect(ok).toBe(false);
  });

  it('FAIL-CLOSED: unreadable RPC (all reads throw) -> false, never true (evm-client.ts:1206-1208)', async () => {
    const provider = new MockEvmProvider({ callThrows: true, blockNumber: 1_000 });
    const ok = await isEvmLockAtSafeDepth(HTLC_ADDR, SWAP_ID, provider as unknown as Provider, 12, {
      hashLock: HASHLOCK,
    });
    expect(ok).toBe(false);
  });

  it('FAIL-CLOSED: too-shallow tip cannot prove depth -> false (evm-client.ts:1204)', async () => {
    // 'safe' not served -> numeric fallback; tip (5) <= requiredConfirmations (12) -> cannot prove depth.
    const provider = noSafeTag(new MockEvmProvider({
      swap: makeSwap({ hashLock: HASHLOCK, recipient: RECIPIENT, amount: 1_000n }),
      blockNumber: 5,
    }));
    const ok = await isEvmLockAtSafeDepth(HTLC_ADDR, SWAP_ID, provider as unknown as Provider, 12, {
      hashLock: HASHLOCK,
    });
    expect(ok).toBe(false);
  });
});
