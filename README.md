# @bch2/swap-core

**The SDK for building bots on the [BCH2 Swap DEX](https://swap.bch2.org)** — a non-custodial, cross-chain atomic-swap exchange between BCH2 (and other UTXO chains) and EVM chains.

The centerpiece is the **`SwapController`**: the validated swap driver. It encapsulates the full
fund-safety protocol — SPV depth gates, cross-domain (wall-clock) timelock ordering, the secret
lifecycle, reorg recovery, and deadline-aware fees — so an integrator **structurally cannot** run a
swap unsafely. The irreversible actions (fund the second leg, reveal the secret) are gated behind
**branded proofs** that only a verified-depth check can mint: you cannot call `revealAndClaim` without
a `RevealAuthorization`, and you cannot call `fundLegY` without a `FundProof`. There is no unguarded path.

> ### Status — new in v3, honestly scoped
>
> The `SwapController` is **new in v3.0.0**. It is extracted from the DEX's proven React orchestration
> and is covered by **424 tests**, including a **two-party, full-lifecycle end-to-end suite**
> ([`src/e2e-lifecycle.test.ts`](./src/e2e-lifecycle.test.ts)) that runs two controllers — one per
> party — through complete swaps over a shared synthetic chain with **real SPV**: UTXO↔UTXO, UTXO↔EVM,
> refund, and resume. Each fund-critical step is adversarially verified.
>
> **What is not yet done:** the controller has **not yet run in the production web app**, nor been
> exercised **end-to-end against mainnet**. Real-app integration and a mainnet e2e are the remaining
> validation. Treat **[PROTOCOL.md](./PROTOCOL.md)** — especially its **[§9 fund-safety
> invariants](./PROTOCOL.md#9-fund-safety-invariants-must-not-violate)** — as the authoritative contract,
> and **test on testnet before risking mainnet funds.**

Keys never leave your process — the server only coordinates orders and proxies (untrusted) chain reads;
it never holds funds.

- **Swap controller** — the validated, gate-sequenced driver for a complete swap (UTXO + EVM legs)
- **Order book** — list, post, take, and cancel resting swap offers
- **Gates** — the SPV/timelock checks that mint the branded `FundProof` / `RevealAuthorization`
- **HTLC builder** — build/sign CashTokens HTLCs (BCH2/BCH/BC2/BTC) and read EVM HTLC contracts
- **Wallet core** — BIP39/BIP32 mnemonic + multi-chain key/address derivation (BCH2, BCH, BC2, BTC, EVM)
- **Address codec** — CashAddr, Base58, Bech32/Bech32m, WIF
- **Key encryption** — AES-256-GCM + PBKDF2 mnemonic encryption

## Install

```bash
npm install github:BitcoincashII/bch2-swap-core
```

Ships prebuilt (ESM + type declarations). Node ≥ 18. Runtime deps (`viem`, `ethers`, `@noble/*`, `@scure/*`) install automatically.

## Running a swap with the `SwapController`

A swap has two parties. The **initiator** (maker) funds leg X first, holds the secret `S`, and reveals
it. The **responder** (taker) funds leg Y only after verifying leg X, then learns `S` from the
initiator's on-chain claim. **A single bot instance plays one role.** The method sequence below is drawn
straight from the two-party e2e ([`src/e2e-lifecycle.test.ts`](./src/e2e-lifecycle.test.ts) — the
canonical, runnable reference).

### 1. Inject the host seams

The controller owns no I/O — you inject it. In Node use the in-process/in-memory adapters; in a browser
swap `LocalStorageDurableStore` / `WindowSessionStore` / `BrowserMutex`.

```ts
import {
  SwapController, MnemonicSeedVault,
  InMemoryDurableStore,   // browser: LocalStorageDurableStore
  InMemorySessionStore,   // browser: WindowSessionStore
  InProcessMutex,         // browser: BrowserMutex
  UtxoReservationRegistry,
  type SwapControllerDeps, type DurableSwapRecord, type SwapChainClient, type SigningKeyPair,
} from '@bch2/swap-core';
import { deriveKeyForSigning } from '@bch2/swap-core/wallet-core';

const durable = new InMemoryDurableStore();

const deps: SwapControllerDeps = {
  // Your untrusted chain transport (an Electrum/proxy client). The SPV layer verifies against it —
  // it must satisfy SwapChainClient (the gate read surface + broadcastTx + getHistory).
  chainClientFor: (chain): SwapChainClient => makeChainClient(chain),

  // Derives keys ON DEMAND; the raw seed never leaves the vault. Back it with wallet-core.
  seedVault: new MnemonicSeedVault(MNEMONIC, async (chain, mnemonic) => {
    const k = deriveKeyForSigning(mnemonic, chain);
    return { privateKey: k.privateKey, publicKey: k.publicKey } satisfies SigningKeyPair;
  }),

  durable,
  session: new InMemorySessionStore(),
  mutex: new InProcessMutex({ store: durable, settle: () => Promise.resolve() }),
  reservation: new UtxoReservationRegistry(),
  clock: () => Date.now(),          // liveness/UX only — anti-theft margins anchor to CHAIN time

  // EVM legs only: a quorum≥2 read provider + a Node ethers signer.
  // evmProviderFor: (chain) => myQuorumProvider(chain),
  // evmSignerFor:   (chain) => myEthersWallet(chain),
};
```

### 2a. Initiator — fund leg X, then reveal

```ts
const record: DurableSwapRecord = {
  id: order.id, role: 'initiator', offer, phase: 'taken',
  counterpartyClaimPkh,        // who may claim YOUR leg X with S (the taker's receive pkh on your send chain)
};
const swap = new SwapController(record, deps);

await swap.prepare();          // derive per-swap keys; RE-DERIVE + authenticate S against offer.secretHash (fail-closed)
await swap.fundLegX();         // SPV funding-height gate → single-flight select/reserve/build → durable-before-broadcast

// … coordinate via the order book + observe the responder's leg-Y funding on-chain
//    (populate record.counterpartyHTLC + record.counterpartyFundingOutpoint — host wiring) …

const auth = await swap.verifyCounterpartyLegForReveal(); // mints a RevealAuthorization ONLY if leg Y is SPV-buried AND the margin is safe
await swap.revealAndClaim(auth);                          // reveals S on-chain by claiming leg Y — REQUIRES `auth`
```

### 2b. Responder — verify leg X, fund leg Y, then claim

```ts
const record: DurableSwapRecord = {
  id: order.id, role: 'responder', offer, phase: 'taken',
  counterpartyClaimPkh,           // who may claim YOUR leg Y with S (the maker's receive pkh on your receive chain)
  counterpartyHTLC,               // the maker's published leg-X HTLC (public)
  counterpartyFundingOutpoint,    // the exact leg-X funding outpoint you observed on-chain
};
const swap = new SwapController(record, deps);

const proof = await swap.verifyCounterpartyLegForFunding(); // mints a FundProof ONLY if leg X is SPV-buried AND timelock ordering is safe
await swap.fundLegY(proof);                                 // REQUIRES `proof` — the re-mint runs again at the broadcast choke point

const { secret } = await swap.watchForSecret();  // learns S by EXTRACTING it from the initiator's on-chain claim (verified sha256(S)==hashLock)
await swap.claimWithKnownSecret();               // claims leg X with the now-public S
```

**The safe-by-default point.** `fundLegY(proof: FundProof)` and `revealAndClaim(auth: RevealAuthorization)`
take **branded** arguments whose *only* producers are the `verifyCounterpartyLeg*` gates. Those gates
mint a proof **only** after proving — from a PoW/ASERT header chain, a Merkle inclusion proof, and a
tip-freshness bound — that the relevant leg is buried to reorg-safe depth and the timelock margin holds;
they mint **nothing** on any failure or uncertainty. So a bot **cannot** fund the second leg or reveal
the secret without a verified-depth proof in hand — the unsafe path does not typecheck. (`fundLegY`
additionally re-mints the proof from a fresh read at the broadcast choke point, so a leg X that reorged
or drifted past the margin *after* the proof was minted still aborts the fund.)

### Refund and resume

```ts
// Counterparty went dark? After your leg's timelock elapses, recover 100% of principal (minus fee):
if (swap.canRefund(currentHeight)) await swap.refund();  // durable-before-broadcast, deadline-aware fee, rebroadcast on drop

// Crash / refresh / new device? Rehydrate from the durable record + chain truth — no material lost:
const resumed = await SwapController.resume(durableRecord, deps);
// resumed.getState().resumeAuth === 'ok'  →  the funded HTLC re-authenticated against the LIVE on-chain output;
// resumed.getState().resumeGate           →  the gate it re-entered, computed from CHAIN truth (not server status).
```

### EVM legs

When one leg is an EVM chain, wire `evmProviderFor` (a **quorum ≥ 2** read provider) + `evmSignerFor` (a
Node `ethers` signer) and use the EVM-parity methods: `verifyEvmCounterpartyLegForFunding` → `lockEvm`,
`verifyEvmCounterpartyLegForReveal` → `revealAndClaimEvm`, `watchForClaimEvm`, and `refundEvm`. The secret
still flows only through the on-chain `Claimed` event — never in memory. See scenario 4 of
[`src/e2e-lifecycle.test.ts`](./src/e2e-lifecycle.test.ts) for the full UTXO↔EVM run.

## The order book (discovery)

The order book is the coordination layer — it never holds funds. Post, discover, take, and cancel resting
offers; then drive settlement with a `SwapController`.

```ts
import { CentralizedOrderBook } from '@bch2/swap-core/order-book';

// In Node you MUST pass an absolute baseUrl.
const book = new CentralizedOrderBook({ baseUrl: 'https://swap.bch2.org' });

const open = await book.queryOrders({ offerChain: 'BCH2' });
for (const o of open) console.log(o.id, o.proposal.initiatorAmountSat, '→', o.wantChain);

// React to the book in real time (polls every 3s; returns an unsubscribe fn):
const stop = book.subscribeToOrders({}, orders => console.log(`book: ${orders.length} open`));
```

See **[API.md](./API.md)** for the full REST/WebSocket transport reference (endpoints, request/response
shapes, the ownership/auth model, rate limits), and **[examples/](./examples/)** for runnable code.

## Modules

The root `@bch2/swap-core` re-exports the driver, gate results, storage adapters, UTXO reservation,
order-book client, address codec, and key encryption. Everything else is a subpath.

| Import | What it gives you |
| --- | --- |
| `@bch2/swap-core` | The `SwapController` + `MnemonicSeedVault`, the gate result types, the storage/mutex adapters, `UtxoReservationRegistry`, the order-book client, address codec, key encryption |
| `@bch2/swap-core/swap-controller` | `SwapController`, `SwapControllerDeps`, `SeedVault`, `DurableSwapRecord`, `DurableHTLC`, `SwapSnapshot`, `SwapChainClient`, events |
| `@bch2/swap-core/gates` | `assertLegBuriedForFunding` / `assertRevealSafe` (+ EVM), the branded `FundProof` / `RevealAuthorization`, `GateFailure` — the SPV/timelock proofs the controller consumes |
| `@bch2/swap-core/storage` | `InMemoryDurableStore` / `LocalStorageDurableStore`, `InMemorySessionStore` / `WindowSessionStore`, `InProcessMutex` / `BrowserMutex` — the injected host seams |
| `@bch2/swap-core/utxo-reservation` | `UtxoReservationRegistry` — instance-scoped input reservation (no double-spend across concurrent funds) |
| `@bch2/swap-core/order-book` | `CentralizedOrderBook`, `MockOrderBook`, `SwapProposal`, `SwapOrder`, `TakeOrderResult`, `OrderStatus` |
| `@bch2/swap-core/htlc-builder` | `buildRedeemScript`, `buildFundingTx`, `buildClaimTx`, `buildRefundTx`, `extractSecretFromScriptSig` |
| `@bch2/swap-core/swap-flow` | Swap construction helpers from the live path: `createInitiatorHTLC` / `createResponderHTLC`, `fundHTLC`, `claimHTLC`, `extractSecret` |
| `@bch2/swap-core/spv` | SPV header-chain + Merkle-inclusion verifier (ASERT/legacy PoW, checkpoints) |
| `@bch2/swap-core/spv-verifier` | `verifyConfirmations` / `verifyFundingHeight` — the anti-lying-proxy depth gate from [PROTOCOL.md](./PROTOCOL.md) §4 |
| `@bch2/swap-core/chain-config` | Per-chain params: required confirmations, timelocks, fee caps, address prefixes, Electrum servers |
| `@bch2/swap-core/timelock-gates` | Cross-domain (wall-clock) timelock ordering + margin gates — §3 |
| `@bch2/swap-core/fee-rate` | Deadline-aware fee estimation + affordability clamp for claim/refund — §7 |
| `@bch2/swap-core/seed-secret` | Seed-derived swap secret (HMAC-v1), maker identity, API-auth signing preimage — §5/§8 |
| `@bch2/swap-core/wallet-core` | `generateMnemonic`, `deriveAddresses`, `deriveKeyForSigning` |
| `@bch2/swap-core/address-codec` | CashAddr / Base58 / Bech32 / WIF encode+decode |
| `@bch2/swap-core/key-encryption` | `encryptMnemonic`, `decryptMnemonic`, `validatePassword` |
| `@bch2/swap-core/evm` | EVM HTLC contract address, ABI, and events |

## Safety

- **The fund-safety contract is [PROTOCOL.md](./PROTOCOL.md).** Any client — bot, wallet, or pool — MUST satisfy every [§9 invariant](./PROTOCOL.md#9-fund-safety-invariants-must-not-violate). The `SwapController` is built to satisfy them; if you drive the primitives yourself, that contract is on you.
- **Non-custodial.** The server never sees your keys or seed. Guard your mnemonic.
- **Use a dedicated wallet.** Fund it with only the swap amount plus a small fee buffer.
- **Atomic swaps are irreversible.** Verify amounts, chains, and timelocks before you fund. Always keep enough of a fee buffer to broadcast a refund if a counterparty goes dark.

## Build from source

```bash
git clone https://github.com/BitcoincashII/bch2-swap-core
cd bch2-swap-core && npm install && npm run build && npm test
```

## License

MIT
