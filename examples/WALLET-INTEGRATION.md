# Wallet integration guide — the signing boundary for `@bch2/swap-core` v3

This is the guide for embedding the SDK **inside a wallet**. It explains the one boundary that matters:
**the SDK never holds your raw seed.** The wallet keeps custody of key material and exposes a narrow
*capability* — the `SeedVault` — that derives what a swap needs, on demand. The `SwapController` owns the
fund-safety gates (SPV depth, timelock ordering, the secret lifecycle, single-flight, durable-before-
broadcast); the wallet only injects I/O + signing and, optionally, a per-signature approval prompt.

> Read alongside [PROTOCOL.md](../PROTOCOL.md), especially
> [§9 fund-safety invariants](../PROTOCOL.md#9-fund-safety-invariants-must-not-violate). A wallet that
> undermines a §9 invariant turns a safe swap into a fund-loss bug. The interfaces cited below are the
> real ones in [`src/swap-controller.ts`](../src/swap-controller.ts) and [`src/storage.ts`](../src/storage.ts).

---

## 1. The trust boundary

```
   ┌─────────────────────────── your wallet ───────────────────────────┐
   │  keystore (seed, HW device, secure enclave)  ── user approval ──┐  │
   │        │                                                        │  │
   │        ▼                                                        ▼  │
   │   SeedVault  ────────────┐         DurableStore / SessionStore     │
   │  (derive on demand)      │         Mutex   (wallet storage + locks)│
   └──────────────────────────┼────────────────────┼───────────────────┘
                              ▼                     ▼
                     ┌───────────────────────────────────────┐
                     │            SwapController               │
                     │  owns the fund-safety gates (§9)        │
                     │  the raw seed NEVER enters this box     │
                     └───────────────────────────────────────┘
```

The controller is injected with a `SwapControllerDeps` bundle. Every capability the wallet controls is one
field of it:

```ts
export interface SwapControllerDeps {
  chainClientFor(chain: Chain): SwapChainClient; // untrusted chain transport (SPV verifies against it)
  seedVault: SeedVault;                          // ← the signing boundary (this document)
  durable: DurableStore;                         // ← persist recovery material to wallet storage
  session: SessionStore;                         // ← ephemeral per-session values
  mutex: Mutex;                                  // ← single-flight, fails CLOSED
  reservation: UtxoReservationRegistry;
  clock: () => number;                           // liveness/UX only — margins anchor to CHAIN time
  evmProviderFor?: (chain: Chain) => Provider;   // EVM legs only (quorum >= 2 read provider)
  evmSignerFor?:  (chain: Chain) => Signer;      // EVM legs only (a Node ethers signer from the seed)
}
```

The wallet's job is to satisfy those seams **without** ever giving the controller — or anything it calls —
the raw seed, a derived private key on a global, or `S` in plaintext.

---

## 2. The `SeedVault` capability

This is the whole signing boundary. It is exactly:

```ts
export interface SeedVault {
  /** A UTXO signing key for `chain` (optionally at an explicit HD path). Derived ON DEMAND. */
  signingKey(chain: Chain, hdPath?: string): Promise<SigningKeyPair>; // { privateKey, publicKey }
  /** K_ss = seed → m/83'/0'/0' (the swap-secret key). `null` when locked / unavailable. */
  swapKss(): Promise<Uint8Array | null>;
  /** Zeroize all cached key material. Idempotent. Called by SwapController.dispose(). */
  dispose(): void;
}
```

Three properties the wallet must preserve:

- **On demand, never up front.** The controller calls `signingKey(chain)` at the moment it signs a funding,
  claim, or refund tx, and `swapKss()` only to re-derive the swap secret `S`. Nothing is handed the seed;
  the vault derives the *one* value asked for and returns it. The controller copies out what it needs and
  the caller owns/zeroes the returned buffers.
- **The SDK never sees the seed.** `signingKey`/`swapKss` return derived material, not the mnemonic. A leak
  of `K_ss` exposes neither the seed nor any spending key (it is a hardened, coin-type-independent path).
- **`dispose()` zeroizes.** `SwapController.dispose()` forwards to `seedVault.dispose()`. See §5 for why a
  wallet must **not** call this (or auto-lock) *mid-swap*.

### 2a. The default vault (`MnemonicSeedVault`)

The SDK ships a reference vault over a host-held mnemonic. It derives `K_ss` through the frozen seed-secret
path and delegates UTXO signing to a wallet-supplied per-chain signer, so the SDK does not hard-wire an HD
wallet:

```ts
import { MnemonicSeedVault } from '@bch2/swap-core';
import { deriveKeyForSigning } from '@bch2/swap-core/wallet-core';

const seedVault = new MnemonicSeedVault(mnemonic, async (chain, mnemonic) => {
  const k = deriveKeyForSigning(mnemonic, chain);      // wallet-core owns the HD derivation
  return { privateKey: k.privateKey, publicKey: k.publicKey };
});
```

`MnemonicSeedVault.dispose()` drops the mnemonic reference (JS strings are immutable, so the real
zeroization guarantee is on the *derived* buffers the signer returns — keep those short-lived).

### 2b. A wallet-backed vault (keystore + per-signature approval)

A real wallet does **not** hand a mnemonic to a constructor. It implements `SeedVault` directly over its own
keystore (or a hardware device) and can gate **each** signature behind user approval:

```ts
class WalletSeedVault implements SeedVault {
  constructor(private keystore: WalletKeystore, private ui: ApprovalUI) {}

  async signingKey(chain: Chain, hdPath?: string): Promise<SigningKeyPair> {
    if (this.keystore.isLocked()) throw new Error('wallet locked'); // fail closed
    // Optional: require the user to approve THIS signature. Show the swap id + leg + amount.
    await this.ui.approveSignature({ chain, hdPath });
    // Derive inside the keystore / secure enclave; never export the seed.
    return this.keystore.deriveSigningKey(chain, hdPath); // { privateKey, publicKey }
  }

  async swapKss(): Promise<Uint8Array | null> {
    if (this.keystore.isLocked()) return null;            // controller fails closed on a null K_ss
    return this.keystore.deriveSwapKss();                 // m/83'/0'/0'
  }

  dispose(): void { /* zeroize any cached derived buffers; do NOT wipe the persistent keystore */ }
}
```

Notes for the approval path:

- Returning `null` from `swapKss()` (locked wallet) makes the controller **fail closed** — `prepare()` will
  not advance a swap whose secret it cannot re-derive. That is the correct, safe behavior for a locked wallet
  **before** a leg is funded.
- A **hardware wallet** backs `signingKey` by asking the device to sign; the device holds the key. This works
  for UTXO legs (BCH2/BCH/BTC ECDSA). Some devices cannot expose a raw private key — if yours signs whole
  transactions only, back the vault with your device's tx-signing flow rather than the byte-level path the
  reference signer uses.
- **Do not** prompt for approval in a way that can be *dismissed to lock the wallet mid-swap* once a leg is
  funded — see §5.

---

## 3. The durable / session / mutex seams the wallet provides

These make "durable-before-broadcast" and "single instance per swap" **structural**, not developer
discipline. Back them with the wallet's own storage.

### 3a. `DurableStore` — recovery material, atomic

```ts
export interface DurableStore {
  get(key: string): Promise<string | null>;
  set(key: string, value: string): Promise<void>;
  remove(key: string): Promise<void>;
  commit(entries: Array<[string, string]>): Promise<void>; // all-or-nothing
}
```

The controller writes the funding/claim/refund recovery record here **before** every irreversible broadcast.
`commit` **must** be atomic: on any write failure it must **throw** (never swallow), it must **read back**
each key to verify it landed, and it must leave **no partial write** (roll every touched key back). A store
that cannot guarantee this is unfit for mainnet — a failed commit that looked like success would let funds
move without a recovery record.

- **Browser wallet:** use the shipped `LocalStorageDurableStore` (localStorage-backed, honors the atomic
  commit contract with read-back + rollback).
- **Native / server wallet:** implement `DurableStore` over your file/SQLite/KV. Persist it to durable
  storage the user cannot casually clear. The keys are namespaced `bch2swap:*` and are byte-identical to the
  DEX's, so a browser↔native migration interops.

The values are **public** material (signed txs, sentinels, the re-derivable secret *scheme* — never `S` in
plaintext), so they are safe to persist. Preserving them is a §9.6 invariant (see §5).

### 3b. `SessionStore` — ephemeral

`InMemorySessionStore` (Node) or `WindowSessionStore` (browser, per-tab). Kept **distinct** from
`DurableStore` so an ephemeral session value can never be confused with recovery material.

### 3c. `Mutex` — single-flight that fails closed

```ts
export interface Mutex {
  withLock<T>(name: string, fn: () => Promise<T> | T): Promise<T>; // MUST throw if a peer holds it
}
```

`withLock` **must never** silently run `fn` without the lock. It serializes the select/reserve/build/commit/
broadcast of a fund, and the build/commit/broadcast of a claim/refund, so a swap cannot double-fund an input,
double-lock an EVM swap, or reveal twice across tabs/instances (§9.9).

- **Browser wallet, multiple tabs:** use `BrowserMutex` (Web Locks API, or a localStorage compare-and-set
  fallback that fails closed when no lock medium exists).
- **Native / multi-process wallet:** use `InProcessMutex({ store })` **backed by the same `DurableStore`** so
  its cross-process compare-and-set backstop can refuse a second holder in another process. Without a shared
  durable store the CAS backstop is inactive (in-process serialization only) — inject one for the mainnet
  single-flight guarantee.

---

## 4. EVM legs (only if a leg is an EVM chain)

When one leg is EVM, the wallet also provides `evmProviderFor` (a **quorum ≥ 2** read provider — the EVM
gates refuse a single-leaf provider) and `evmSignerFor` (a Node `ethers` signer derived from the seed).
The seed still never leaves the wallet: derive the EVM key in your keystore and construct the signer there.
MetaMask/browser-injected providers are **not** on the trusted path — the gates verify chain facts through
your quorum read provider, not the wallet's RPC.

---

## 5. What the host MUST NOT undermine (the §9 invariants that are the wallet's job)

The SwapController enforces the SPV/timelock/single-flight gates. Four §9 invariants are only as strong as
the **host** behind them:

1. **Never drop the signing capability mid-swap (§9.8).** This is the number-one wallet pitfall. Once a leg
   is funded, the claim/refund keys must stay derivable for the swap's whole lifetime. A wallet that
   **auto-locks on tab-hide / idle / background** and, in doing so, disposes the vault or wipes `K_ss` can
   strand a funded swap: the initiator never reveals `S`, or a party can no longer sign its own refund. Do
   **not** call `SwapController.dispose()` or lock the vault while a swap is between "funded" and
   "settled/refunded at reorg-safe depth." If you must lock, persist enough that `SwapController.resume()`
   can cleanly rehydrate and re-derive on unlock.
2. **Preserve recovery material until settled or refunded (§9.6).** Never clear the `bch2swap:*` durable keys,
   the durable record, or the re-derivable secret scheme on a network blip, an inconclusive/pruned read, or a
   "clean up storage" sweep. The controller's finalizers wipe non-recoverable material **only** at reorg-safe
   SPV depth — the wallet must not pre-empt them. A `DurableStore` whose backing the user can casually clear
   (a private-tab localStorage, an app cache the OS evicts) is a fund-loss hazard for a swap in flight.
3. **Never transmit / log / globalize / plaintext-store the seed, a derived key, or `S` (§9.5).** Do not put a
   derived private key on `window`/a global, log it, send it to your telemetry, or persist `S` in plaintext.
   The vault returns short-lived buffers; zeroize them. `S` is revealed exactly once, on-chain, by the
   initiator — never before.
4. **Single-flight, fail closed (§9.9).** Provide a real `Mutex` (and, cross-process, a shared durable store
   for its CAS backstop). Never substitute a no-op mutex that "just runs `fn`" — that re-opens the
   double-fund / double-reveal class.

The controller owns invariants §9.1–§9.4 (never fund leg Y / reveal `S` without an SPV-verified branded
proof; never trust the proxy; verify `sha256(S) == hashLock`). The wallet's obligation there is simply **not
to route around them** — drive the swap through the `SwapController` (the `verifyCounterpartyLeg*` gates mint
the `FundProof` / `RevealAuthorization` that `fundLegY` / `revealAndClaim` require), rather than driving the
lower-level primitives yourself.

---

## 6. Wallet integration checklist

- [ ] Implement `SeedVault` over your keystore/HW device; the raw seed never leaves it.
- [ ] `swapKss()` returns `null` when locked (controller fails closed pre-fund); `signingKey()` throws when locked.
- [ ] Optional per-signature user approval shows swap id + leg + amount; it cannot be used to lock a **funded** swap.
- [ ] `DurableStore` is atomic (throw + read-back + rollback) and persisted to storage the user won't casually clear.
- [ ] `Mutex` fails closed; cross-process installs share the durable store for the CAS backstop.
- [ ] Never auto-lock / dispose the vault between "funded" and "settled/refunded"; if you must, `resume()` on unlock.
- [ ] Never clear `bch2swap:*` durable keys or the durable record until the swap finalizes at reorg-safe depth.
- [ ] Never log/globalize/plaintext-store the seed, a derived key, or `S`; zeroize returned buffers.
- [ ] EVM legs: `evmProviderFor` is quorum ≥ 2; `evmSignerFor` is seed-derived in the wallet, not MetaMask.

See [`examples/reference-bot.mjs`](./reference-bot.mjs) for the full method sequence a host drives, and
[PROTOCOL.md §9](../PROTOCOL.md#9-fund-safety-invariants-must-not-violate) for the authoritative contract.
