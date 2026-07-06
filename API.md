# BCH2 Swap DEX — API Reference

Everything needed to build a bot against the BCH2 Swap DEX. The DEX is **non-custodial**: this HTTP/WebSocket API is a *coordination + chain-access* layer only. It never holds funds or keys. Completing a swap means doing the HTLC crypto yourself with [`@bch2/swap-core`](./README.md) (mapped to each step below).

- **Base URL (production):** `https://swap.bch2.org`
- **Response envelope:** every JSON response is `{ "success": true, "data": T }` or `{ "success": false, "error": string }`. A non-2xx status always carries `success: false`.
- **Content type:** `application/json` for all request bodies.

---

## 1. Auth model

There are no accounts or API keys. Ownership of an **order** is proven two ways:

- **`makerPubKey`** — the maker's 66-hex-char compressed pubkey (the `proposal.initiatorPubKey`). Passed in the body of privileged calls (e.g. cancel) to prove you posted the order.
- **Admin token** — a secret string minted when you `POST /api/orders`, stored server-side as the order's `admin_token`. Recover it with `GET /api/orders/:id/my-token` (rate-limited, see below). Used to authorize status transitions on your own order.

Keep both secret. Anyone with your order's admin token can drive its server-side status.

## 2. Rate limits & caps

| Limit | Value |
| --- | --- |
| Open orders per IP | **10** concurrent |
| `PATCH /status` per order | 20 / min |
| `PATCH /status` global per IP | 200 / min |
| `GET /my-token` per order | 3 / 10 min (brute-force cap) |
| Body size | 1 KB (status), larger caps on tx broadcast |

Exceeding a limit returns HTTP `429 { success:false, error:"Too many requests" }`. Running a market-maker at scale requires the operator to raise the per-IP order cap for your address — coordinate before you deploy.

---

## 3. Order book endpoints

Wire shapes are the exported SDK types (`@bch2/swap-core/order-book`): `SwapOrder`, `PostOrderRequest`, `TakeOrderResult`, `OrderStatus`, `Chain`.

### `GET /api/orders`
List orders. Query params (all optional): `offerChain`, `wantChain`, `status`.
→ `data: SwapOrder[]`. **SDK:** `book.queryOrders(filter)`.

### `GET /api/orders/:id`
One order by id. → `data: SwapOrder`.

### `POST /api/orders`
Post an offer. Body = `PostOrderRequest` (`{ proposal, offerChain, wantChain, ttlSeconds? }`) — `proposal` comes from `engine.prepare()` (establishes the hashlock + makerPubKey without broadcasting). → `data: string` (the new order id). **SDK:** `book.postOrder(req)`.

### `POST /api/orders/:id/take`
Take an open order. Body `{ takerPubKey }` (66 hex chars). Atomically locks the order so exactly one taker wins. → `data: TakeOrderResult` (`{ orderId, proposal, takerPubKey, offerChain, wantChain }`). **SDK:** `book.takeOrder(id, takerPubKey)`. Throws if not open.

### `PATCH /api/orders/:id/status`
Advance your swap's server-side status (so the counterparty and a resumed session can follow along). Body (whitelisted): `{ status, txid?, chain?, locktime?, evmSwapId?, responderEvmSwapId? }`. `txid` must be 64 hex chars (optional `0x`). `status` ∈ `open | taken | completed | cancelled | expired` (plus internal funding/claim states).

### `DELETE /api/orders/:id`
Cancel an open order. Body `{ makerPubKey }` (proves ownership). → `data: null`. **SDK:** `book.cancelOrder(id, makerPubKey)`.

### `GET /api/orders/:id/my-token`
Recover your order's admin token (maker only; brute-force capped 3 / 10 min).

---

## 4. Chain-access endpoints

Read balances/UTXOs and broadcast signed transactions the SDK builds. The server proxies your BCH2 node / EVM RPC — it never signs.

| Endpoint | Purpose |
| --- | --- |
| `GET /api/balance/utxo?chain=BCH2&address=…` | Confirmed UTXO balance (satoshis) |
| `GET /api/utxos?chain=BCH2&address=…` | Spendable UTXO set for building a tx |
| `POST /api/broadcast/utxo` | Broadcast a signed raw UTXO tx (`{ rawTx }`) |
| `GET /api/balance/evm?chainId=…&address=…&token=…` | ERC-20 token balance |
| `GET /api/balance/evm/native?chainId=…&address=…` | Native (ETH) balance |
| `POST /api/broadcast/evm` | Broadcast a signed EVM tx |
| `GET /api/prices` | Reference prices (USD) for sizing/quoting |
| `GET /api/chart` | Historical price series |
| `GET /api/health` | Liveness probe |

`chain` ∈ `BCH2 | BCH | BTC | BC2`. EVM `chainId`: Base Sepolia `84532`, Arbitrum Sepolia `421614`.

---

## 5. WebSocket relay (chain watching)

For watching funding/claims and block height in real time, connect to the Electrum relay:

```
wss://swap.bch2.org/ws?chain=BCH2
```

JSON-RPC methods relayed: `blockchain.headers.subscribe` (block height), `blockchain.script.register` (register a script/HTLC to watch by scripthash), `blockchain.scripthash.get_history` / `get_balance`, `blockchain.transaction.broadcast`, `blockchain.transaction.get`. The SDK's swap engine (`@bch2/swap-core/swap-engine`, `electrum-chain`) drives this for you — you supply the WS URL.

---

## 6. The full swap lifecycle (mapped to the SDK)

A swap between a UTXO leg and an EVM leg, non-custodially:

1. **Prepare (maker).** `engine.prepare()` for the Initiator role → a `SwapProposal` (hashlock + makerPubKey + terms). Nothing is broadcast.
2. **Post.** `book.postOrder({ proposal, offerChain, wantChain, ttlSeconds })` → order id (+ admin token). It's now a resting offer.
3. **Discover / take.** A taker finds it (`queryOrders`/`subscribeToOrders`) and calls `book.takeOrder(id, takerPubKey)` → `TakeOrderResult`. The maker reads `takerPubKey` and sets it as their counterparty (`engine.setCounterPubKey`).
4. **Fund both legs.** Each side locks their asset to the shared hashlock + a timelock:
   - **UTXO leg:** `buildRedeemScript(...)` → `buildFundingTx(...)`, sign, `POST /api/broadcast/utxo`.
   - **EVM leg:** call the HTLC contract (`@bch2/swap-core/evm`: address, ABI) via `viem`, `POST /api/broadcast/evm`.
   - `PATCH /status` after each fund so the other side can follow.
5. **Watch.** The `Engine` (with an `electrum-chain` bound to the WS URL, and a `SwapStorage` — use `MemorySwapStorage` or your own file-backed impl in Node) advances state as it sees each leg funded.
6. **Claim.** The initiator claims first, revealing the secret. The responder reads it off-chain (`extractSecretFromScriptSig` for UTXO, or the EVM claim event) and claims their leg (`buildClaimTx` / EVM claim). `PATCH /status` → `completed`.
7. **Refund (safety).** If a counterparty goes dark and your timelock elapses, reclaim your own funds: `buildRefundTx(...)` (UTXO) or the EVM contract's refund. **Always keep a fee buffer to broadcast a refund.**

See [`examples/`](./examples/) for runnable code.

---

## 7. Errors

Every failure is `{ success:false, error }` with an HTTP status: `400` bad input, `404` unknown order, `409` order not open (take race lost), `413` body too large, `429` rate-limited, `5xx` upstream node/RPC error. Bots should treat `409` on take as "someone beat me to it" and move on, and retry `5xx`/timeouts with backoff.
