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

> ⚠️ **Settlement is not automated in this file.** When an offer is taken you must complete the swap (fund your HTLC, watch the counterparty, claim, or refund) with `@bch2/swap-core/swap-engine` + `/htlc-builder` — see [§6 of API.md](../API.md#6-the-full-swap-lifecycle-mapped-to-the-sdk). Running the maker without a settlement loop will strand takers and risk your funds.

## Safety

Use a dedicated wallet funded with only what you'll trade, keep a fee buffer for refunds, and never commit your seed. Atomic swaps are irreversible.
