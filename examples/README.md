# Examples

Runnable references for building on the BCH2 Swap DEX. They import `@bch2/swap-core` exactly as your own project would.

## Setup

```bash
npm install github:BitcoincashII/bch2-swap-core
```

Node ≥ 18 (uses global `fetch`). Optional env: `BCH2_SWAP_URL` (default `https://swap.bch2.org`), `BCH2_MNEMONIC` (a **dedicated** swap wallet seed).

## `quickstart.mjs` — read-only

```bash
node examples/quickstart.mjs
```

Derives a wallet, connects to the live order book, prints open orders + prices, and live-subscribes for 15 seconds. Posts/signs nothing — safe to run.

## `market-maker.mjs` — resting-order loop (coordination half)

```bash
DRY_RUN=1 node examples/market-maker.mjs     # log only, posts nothing (default)
```

Shows the maker coordination loop: prepare a proposal, post resting offers, keep them fresh, cancel on exit.

> ⚠️ **Settlement is not automated in this file.** When an offer is taken you must complete the swap safely. The SDK's validated driver for that is the **`SwapController`** (from `@bch2/swap-core`), which gates every irreversible action (fund the second leg, reveal the secret) behind an SPV-verified branded proof. The canonical, runnable end-to-end reference is [`../src/e2e-lifecycle.test.ts`](../src/e2e-lifecycle.test.ts) (two controllers, one shared chain, UTXO↔UTXO + UTXO↔EVM + refund + resume), and the fund-safety contract is [PROTOCOL.md](../PROTOCOL.md) (esp. §9). Running the maker without a `SwapController`-driven settlement loop will strand takers and risk your funds.

## `reference-bot.mjs` — full maker/taker settlement bot (SwapController-driven)

```bash
node examples/reference-bot.mjs make bch2 btc 100000     # dry validate (no mnemonic/LIVE → prints setup, connects nothing)
```

The runnable REFERENCE bot. It drives a real swap end-to-end through the `SwapController` — the exact
maker (initiator) and taker (responder) method sequences from [`../src/e2e-lifecycle.test.ts`](../src/e2e-lifecycle.test.ts),
wired to the live order book + the Electrum transport in [`electrum-node-client.mjs`](./electrum-node-client.mjs).
It is **safe by default**: with no `BCH2_SWAP_MNEMONIC`, or without `BCH2_SWAP_LIVE=1`, it validates and
prints the plan but connects/broadcasts nothing. Fund-safety lives inside the controller; the coordination
seams (counterparty HTLC exchange, order-book↔proxy contract) are marked and fail closed. **Test on testnet first.**

## `WALLET-INTEGRATION.md` — the signing-boundary guide

How a wallet embeds the SDK: the `SeedVault` capability (the SDK never holds the raw seed), the durable/
session/mutex seams a host provides, and the [§9](../PROTOCOL.md#9-fund-safety-invariants-must-not-violate)
invariants a host must not undermine (never auto-lock/drop keys mid-swap; keep recovery material until
settled/refunded). Grounded in the real `SeedVault` / `SwapControllerDeps` interfaces.

## Safety

Use a dedicated wallet funded with only what you'll trade, keep a fee buffer for refunds, and never commit your seed. Atomic swaps are irreversible.
