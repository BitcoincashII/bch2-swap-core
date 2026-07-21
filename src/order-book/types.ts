/**
 * OrderBook interface — the swappable seam between client and discovery layer.
 *
 * The client talks exclusively to this interface. The centralized server
 * implementation (CentralizedOrderBook) can be replaced by a decentralized
 * relay/P2P implementation without changing any client code.
 *
 * Seam discipline mirrors UTXOChainClient in the swap engine: no implementation
 * details (server URLs, HTTP methods, poll interval, WebSocket protocol) leak
 * through to the caller. A DecentralizedOrderBook implementing this interface
 * is a drop-in replacement — the client would not change.
 *
 * How matching works with the swap:
 *   1. Maker posts an offer → postOrder(proposal, chains) → order ID.
 *   2. Taker browses via queryOrders / subscribeToOrders.
 *   3. Taker calls takeOrder(id, takerPubKey) → TakeOrderResult.
 *   4. Both parties drive settlement with a `SwapController` (see swap-controller.ts + PROTOCOL.md):
 *      prepare → fund → verifyCounterpartyLeg → reveal/claim → refund/resume. The order book only
 *      COORDINATES discovery + params; the fund-safety gates run INSIDE the controller, fed by these
 *      params, never around them.
 *
 * Transport vs execution model:
 *   The shapes below (SwapProposal / SwapOrder) are the order-book's ON-THE-WIRE discovery/transport
 *   contract — they mirror EXACTLY what the live proxy returns from GET /api/orders. The swap-EXECUTION
 *   model is `SwapOffer` (../swap-types), which the `SwapController` consumes. Convert between the two with
 *   the adapter in ./adapter (`proposalToOffer` / `orderToOffer` / `offerToProposal`).
 */

import type { EvmSwapInfo } from '../swap-types';

/**
 * A maker's swap proposal — the public parameters an order advertises.
 *
 * This is the REAL shape the live proxy returns inside each order's `proposal` field (verified against
 * swap.bch2.org/api/orders). All amounts are decimal STRINGS of the chain's BASE UNIT — sats for a UTXO chain,
 * wei / token base units for an EVM chain — NOT human units. (E.g. a BCH2 amount of "1290788219" is 12.90788219
 * BCH2.) The adapter carries them through verbatim; the SwapController consumes base units directly.
 *
 * `hashLock` is the HTLC hash lock and equals `secretHash` (both sha256(secret)); the proxy carries both
 * names. `refundAddress`/`receiveAddress` are the initiator's refund (offerChain) / claim (wantChain)
 * addresses, duplicated by `initiatorSendAddress`/`initiatorReceiveAddress` in the proxy payload.
 */
export interface SwapProposal {
  offerChain:              Chain;   // chain the maker sells from (chain code, e.g. "POLY")
  wantChain:               Chain;   // chain the maker buys into
  sendAmount:              string;  // base-unit amount (sats for UTXO, wei/token base units for EVM) as a decimal string
  receiveAmount:           string;  // base-unit amount (sats for UTXO, wei/token base units for EVM) as a decimal string
  secretHash:              string;  // hex, sha256 of the initiator's secret
  secretNonce:             string;  // 32-hex — public nonce for the SEED-DERIVED hmac-v1 secret
  secretScheme:            string;  // e.g. 'hmac-v1' (S re-derivable from the seed)
  makerIdPub:              string;  // 66-hex seed-derived maker-identity pubkey (own-offer detection only)
  makerSig:                string;  // 128-hex ECDSA authorship signature over the secretHash
  authPub:                 string;  // 66-hex seed-derived API-auth pubkey (initiator's) — authenticates PATCH/DELETE
  refundAddress:           string;  // initiator's refund address on offerChain
  receiveAddress:          string;  // initiator's receive address on wantChain
  initiatorSendAddress:    string;  // initiator's address on offerChain (refund) — mirrors refundAddress
  initiatorReceiveAddress: string;  // initiator's address on wantChain (claim) — mirrors receiveAddress
  evmInfo?:                EvmSwapInfo; // present when either leg is an EVM chain
  evmAddress?:             string;  // the EVM address (0x…) that will send/receive tokens
  hashLock:                string;  // hex — the HTLC hash lock (== secretHash)
}

/** Order-book TRANSPORT chain codes (UPPERCASE) as the proxy emits them. The swap-EXECUTION model
 *  (SwapOffer, ../swap-types) uses the lowercase equivalents; ./adapter maps between the two. */
export type Chain = 'BCH2' | 'BCH' | 'BTC' | 'BC2' | 'ETH' | 'BASE' | 'ARB' | 'POLY';

export type OrderStatus =
  | 'open'       // accepting takers
  | 'taken'      // matched; settling in progress
  | 'completed'  // swap finished
  | 'cancelled'  // maker withdrew before taken
  | 'expired';   // TTL elapsed before taken

/**
 * An order posted by a maker advertising a swap — the REAL top-level shape the live proxy returns from
 * GET /api/orders (each element of `{ success, data: SwapOrder[] }`).
 *
 * The nested `proposal` carries the maker's hashLock + terms + addresses. The top-level fields carry the
 * order's lifecycle + the responder's coordinates (set once the order is taken). No funds touch the order
 * book; the order is an advertisement + coordination record only.
 */
export interface SwapOrder {
  id:                       string;
  offerChain:               Chain;        // chain the maker is selling from
  wantChain:                Chain;        // chain the maker is buying into
  status:                   OrderStatus;
  createdAt:                number;        // unix ms
  expiresAt:                number;        // unix ms — server refuses to match past this
  takenAt?:                 number;        // unix ms — set when taken
  responderLocktime?:       number;        // responder-leg CLTV, set once the responder funds
  evmSwapId?:               string;        // bytes32 hex — the EVM HTLC swapId, when a leg is EVM
  initiatorTxid?:           string;        // funding txid of the initiator (leg X) HTLC
  responderTxid?:           string;        // funding txid of the responder (leg Y) HTLC
  responderSendAddress?:    string;        // responder's address on wantChain (its refund)
  responderReceiveAddress?: string;        // responder's address on offerChain (where it claims leg X)
  takerAuthPub?:            string;        // 66-hex responder seed-derived API-auth pubkey — present once taken
  proposal:                 SwapProposal;  // maker's advertised proposal (hashLock + terms + addresses)
}

/**
 * Request body for postOrder.
 * The maker builds the proposal (hashLock + terms + addresses) from its SwapOffer via
 * `offerToProposal` (./adapter), which establishes the hashLock without broadcasting anything.
 */
export interface PostOrderRequest {
  proposal:    SwapProposal;    // built from a SwapOffer via offerToProposal()
  offerChain:  Chain;
  wantChain:   Chain;
  ttlSeconds?: number;          // validity window; default 3600 (1 hour)
}

/**
 * Filter for queryOrders / subscribeToOrders.
 * All fields optional — omitting a field means "match any".
 */
export interface OrderFilter {
  offerChain?: Chain;
  wantChain?:  Chain;
  status?:     OrderStatus;
}

/**
 * Result of takeOrder — everything both parties need to begin the swap:
 *
 *   Taker (Responder): construct the responder SwapOffer from proposal via proposalToOffer/orderToOffer
 *   Maker (Initiator): read the taker's coordinates from the polled order (responderReceiveAddress + takerAuthPub)
 *
 * From here the full verify→fund→claim flow takes over inside the SwapController. The order book's job is
 * done; it hands off to the controller and does not touch settlement.
 */
export interface TakeOrderResult {
  orderId:     string;
  proposal:    SwapProposal;   // maker's proposal (taker constructs its responder offer from this)
  takerPubKey: string;         // 66 hex chars — the identity the taker presented to takeOrder
  offerChain:  Chain;
  wantChain:   Chain;
}

/**
 * The discovery-layer interface.
 *
 * Implementations:
 *   CentralizedOrderBook — HTTP REST + polling (this repo, first implementation)
 *   DecentralizedOrderBook — relay/P2P broadcast (future; same interface, no client changes)
 */
export interface OrderBook {
  /** Maker advertises a swap. Returns the assigned order ID. */
  postOrder(req: PostOrderRequest): Promise<string>;

  /** Returns all orders matching the filter (snapshot). */
  queryOrders(filter: OrderFilter): Promise<SwapOrder[]>;

  /**
   * Live subscription to book updates.
   * Calls callback immediately with current matching orders, then on each change.
   * Returns an unsubscribe function; caller must invoke it on unmount / cleanup.
   */
  subscribeToOrders(filter: OrderFilter, callback: (orders: SwapOrder[]) => void): () => void;

  /**
   * Maker withdraws an open order.
   * makerPubKey must match the order's proposal.authPub (proves ownership; the proxy authenticates DELETE
   * against the maker's seed-derived API-auth pubkey).
   */
  cancelOrder(orderId: string, makerPubKey: string): Promise<void>;

  /**
   * Taker claims an order, atomically locking it so exactly one taker succeeds.
   * Returns the matched terms for both parties to begin the swap.
   * Throws if the order is not open (already taken, cancelled, or expired).
   */
  takeOrder(orderId: string, takerPubKey: string): Promise<TakeOrderResult>;
}
