# Running a real swap with the reference bot — testnet first

This is the operator runbook for driving an **actual on-chain atomic swap** through
[`reference-bot.mjs`](./reference-bot.mjs) + the `SwapController`. Atomic swaps are **irreversible** — do a
small-value run on a chain you can afford to lose before any mainnet value.

> **What's already proven vs what this closes.** The SDK's fund-safety *verification* path is validated against
> real BCH2 mainnet data (`npm run verify:live` — real ASERT headers, a real Merkle proof, fail-closed on a fake
> txid). What a real swap additionally exercises is the **write path** — building, signing, and broadcasting the
> funding / claim / refund transactions, and the two parties handing off on-chain. That's what this runbook drives.

## 0. Prerequisites

- Node ≥ 18, this package built (`npm run build`).
- **Two dedicated wallets**, one per party (maker + taker) — or two machines. Fund **only** the trade amount plus a
  fee buffer on each party's *send* chain. Use fresh mnemonics you can throw away.
- The pair's two chains reachable: the UTXO leg via an Electrum server (the defaults in `chain-config.ts`, e.g.
  `electrum.bch2.org:50002`); an EVM leg needs an RPC + a small gas balance.
- The order-book/proxy origin (`BCH2_SWAP_URL`, default `https://swap.bch2.org`).

Start with a **UTXO↔UTXO** pair (e.g. `bch2`↔`bch`) — no EVM gas or RPC to wire, and both legs settle the same way.

## 1. Dry-validate (connects and broadcasts NOTHING)

With no mnemonic, the bot prints its setup plan and exits — nothing is connected or sent:

```bash
node examples/reference-bot.mjs make bch2 bch 100000
```

Confirm it names the two chains, the amount, and the coordination seams. Then set a funded mnemonic but **leave
the live gate off** — it will derive your addresses and print the plan only:

```bash
export BCH2_SWAP_MNEMONIC="<maker's dedicated seed>"
node examples/reference-bot.mjs make bch2 bch 100000        # still no broadcast (BCH2_SWAP_LIVE unset)
```

Send the printed **maker receive address** its funding? No — *fund the send-chain wallet*, i.e. the address the
bot spends *from*. The plan output tells you which.

## 2. The two parties

A swap is two roles; run them as two processes (two terminals / two machines), each with its **own** mnemonic.

**Maker (initiator)** — posts the offer, funds leg X first, reveals the secret:

```bash
export BCH2_SWAP_MNEMONIC="<maker seed>"
BCH2_SWAP_LIVE=1 node examples/reference-bot.mjs make bch2 bch 100000
# → posts an order, prints the ORDER ID, funds leg X, waits for the taker, then reveals + claims leg Y
```

**Taker (responder)** — takes that order id, funds leg Y after verifying leg X, learns the secret on-chain,
claims leg X:

```bash
export BCH2_SWAP_MNEMONIC="<taker seed>"
export BCH2_SWAP_CP_CLAIM_PUBKEY="<the maker's 66-hex receive pubkey on leg X>"   # out-of-band seam
BCH2_SWAP_LIVE=1 node examples/reference-bot.mjs take <ORDER_ID>
```

### The out-of-band seams (why they exist, and that they fail closed)

`swap-core` owns the fund-safety gates but **not** the discovery/coordination channel. Two facts the order book's
single-pubkey-per-party model can't fully carry must reach each party out of band, and the bot **stops before any
irreversible action** if they're missing (fund-safe by construction):

- `BCH2_SWAP_CP_HTLC` — the counterparty's published HTLC (a JSON `DurableHTLC`), when the on-chain scan can't
  reconstruct it. The controller still SPV-re-verifies that outpoint inside the gate — this is a convenience input,
  not a trust input.
- `BCH2_SWAP_CP_CLAIM_PUBKEY` — the pubkey whose PKH may claim your funded leg.

For a first end-to-end run, the simplest setup is **both roles under your control** (two seeds you own), so you can
supply both seams and watch the whole lifecycle.

## 3. What you should see (and verify on a block explorer)

The bot logs `phase` / `status` / `error` events per stage. A healthy swap walks:

`prepared → initiator_funded → responder_funded → claimed → completed`

Cross-check on-chain: the maker's leg-X funding tx, the taker's leg-Y funding tx, the maker's claim of leg Y (its
scriptSig **reveals the 32-byte secret** — that's the atomicity), and the taker's claim of leg X *using that secret*.
Both HTLC addresses end with **zero** unspent outputs.

## 4. The refund path (deliberately trigger it once)

Recovery is the other half of "safe". Have the taker **not** fund leg Y; after the maker's leg-X timelock elapses,
the maker's process (or a re-run resuming from `bch2swap:record:<id>`) calls `refund()` and sweeps leg X back. Verify
the refund tx spends the funding outpoint back to the maker's own key. Then repeat with the roles reversed.

## 5. Resume after a crash

Kill the maker mid-swap (after `initiator_funded`). Re-run the **same** command: `SwapController.resume()` rehydrates
from the durable record + live chain, re-authenticates the funded HTLC on-chain, and re-enters the correct gate —
no recovery material lost, no double-fund (idempotent rebroadcast).

## 6. Production hardening (do NOT skip for real value)

The reference bot uses `InMemoryDurableStore` + `InProcessMutex`, which **do not survive a process restart**. A
production bot MUST inject:

- a **file / SQLite `DurableStore`** so the durable-before-broadcast recovery material (secret scheme, funded HTLC,
  CLTV, claim/refund txs) survives a crash, and
- a **cross-process `Mutex`** (file lock / Redis / DB row-lock) so a multi-worker pool can't double-fund an input or
  double-lock an EVM swap.

Both are seams (`SwapControllerDeps.durable` / `.mutex`) — see the audit fixes #3/#4 and
[WALLET-INTEGRATION.md](./WALLET-INTEGRATION.md).

## Safety checklist before mainnet value

- [ ] Ran a full UTXO↔UTXO swap on testnet/small-value: fund → reveal → both claim, both HTLCs empty.
- [ ] Ran the **refund** path (counterparty dark) and recovered the principal.
- [ ] Ran the **resume** path (kill + restart) with no lost recovery material.
- [ ] Replaced the in-memory durable store + mutex with durable, cross-process ones.
- [ ] Used a dedicated wallet funded with only the trade amount + fee buffer.
