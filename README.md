# @bch2/swap-core

**The SDK for building bots on the [BCH2 Swap DEX](https://swap.bch2.org)** — a non-custodial, cross-chain atomic-swap exchange between BCH2 (and other UTXO chains) and EVM chains.

This package gives you everything the DEX's own UI uses: HTLC construction and signing, the swap state engine, wallet/key derivation, address codecs, and a client for the order-book API. Keys never leave your process — the server only coordinates orders, it never holds funds.

- **Order book** — list, post, take, and cancel resting swap offers
- **Swap engine** — the state machine that drives a swap from funded → claimed, with verify/persist/recover
- **HTLC builder** — build/sign CashTokens (BCH2/BCH/BC2/BTC) and read EVM HTLC contracts
- **Wallet core** — BIP39/BIP32 mnemonic + multi-chain key/address derivation (BCH2, BCH, BC2, BTC, EVM)
- **Address codec** — CashAddr, Base58, Bech32/Bech32m, WIF
- **Key encryption** — AES-256-GCM + PBKDF2 mnemonic encryption

## Install

```bash
npm install github:BitcoincashII/bch2-swap-core
```

Ships prebuilt (ESM + type declarations). Node ≥ 18. Runtime deps (`viem`, `@noble/*`, `@scure/*`) install automatically.

## Quick start

```ts
import { deriveAddresses, deriveKeyForSigning, generateMnemonic } from '@bch2/swap-core/wallet-core';
import { CentralizedOrderBook } from '@bch2/swap-core/order-book';

// 1. A dedicated swap wallet (use a fresh mnemonic funded with only what you'll trade)
const mnemonic = generateMnemonic();               // or bring your own 12/24 words
const addrs = deriveAddresses(mnemonic);
console.log(addrs.bch2, addrs.evm);                // bitcoincashii:… , 0x…

// 2. Connect to the DEX order book. In Node you MUST pass an absolute baseUrl.
const book = new CentralizedOrderBook({ baseUrl: 'https://swap.bch2.org' });

// 3. See what's on the book
const open = await book.queryOrders({ offerChain: 'BCH2' });
for (const o of open) console.log(o.id, o.offerAmount, '→', o.wantAmount);

// 4. React to the book in real time (polls every 3s; returns an unsubscribe fn)
const stop = book.subscribeToOrders({}, orders => console.log(`book: ${orders.length} open`));
```

## The swap lifecycle (what a bot must do)

A swap is non-custodial, so completing one means doing the crypto yourself — the order book only coordinates:

1. **Maker** posts an offer → `book.postOrder(...)` (returns an order id + admin token).
2. **Taker** takes it → `book.takeOrder(id, takerPubKey)` returns a `TakeOrderResult` with both parties' details.
3. **Both** fund their leg: build + sign + broadcast an HTLC locked to a shared hashlock/timelock — `htlc-builder` (`buildRedeemScript`, `buildFundingTx`) for UTXO legs, the EVM HTLC contract (`@bch2/swap-core/evm`) for EVM legs.
4. **Engine** watches for the counterparty to fund/claim and advances state — `Engine` from `@bch2/swap-core/swap-engine` (inject a `MemorySwapStorage` or your own file-backed `SwapStorage` in Node).
5. **Claim**: the initiator reveals the secret by claiming; the responder extracts it on-chain (`extractSecretFromScriptSig`) and claims their leg (`buildClaimTx`). If it stalls past the timelock, **refund** (`buildRefundTx`).

See **[API.md](./API.md)** for the full REST/WebSocket reference (endpoints, request/response shapes, the admin-token auth model, rate limits) and every SDK call mapped to each step, and **[examples/](./examples/)** for a runnable reference bot.

## Modules

| Import | What it gives you |
| --- | --- |
| `@bch2/swap-core` | Everything below re-exported (except `wallet-core`, `evm`) |
| `@bch2/swap-core/order-book` | `CentralizedOrderBook`, `MockOrderBook`, order/offer types |
| `@bch2/swap-core/swap-engine` | `Engine`, swap state, verify, persist, recover |
| `@bch2/swap-core/htlc-builder` | `buildRedeemScript`, `buildFundingTx`, `buildClaimTx`, `buildRefundTx`, `extractSecretFromScriptSig` |
| `@bch2/swap-core/wallet-core` | `generateMnemonic`, `deriveAddresses`, `deriveKeyForSigning` |
| `@bch2/swap-core/address-codec` | CashAddr / Base58 / Bech32 / WIF encode+decode |
| `@bch2/swap-core/key-encryption` | `encryptMnemonic`, `decryptMnemonic`, `validatePassword` |
| `@bch2/swap-core/evm` | EVM HTLC contract address, ABI, and events |

## Safety

- **Non-custodial.** The server never sees your keys or seed. Guard your mnemonic.
- **Use a dedicated wallet.** Fund it with only the swap amount plus a small fee buffer.
- **Atomic swaps are irreversible.** Verify amounts, chains, and timelocks before you fund. Always keep enough of a fee buffer to broadcast a refund if a counterparty goes dark.

## Build from source

```bash
git clone https://github.com/BitcoincashII/bch2-swap-core
cd bch2-swap-core && npm install && npm run build
```

## License

MIT
