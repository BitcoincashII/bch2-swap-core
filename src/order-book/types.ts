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
 * How matching works with the swap engine:
 *   1. Maker calls engine.prepare() → gets SwapProposal (hashLock + makerPubKey)
 *   2. Maker calls postOrder(proposal, chains) → order ID
 *   3. Taker browses via queryOrders / subscribeToOrders
 *   4. Taker calls takeOrder(id, takerPubKey) → TakeOrderResult
 *   5a. Taker constructs Responder engine from result.proposal + takerPubKey
 *   5b. Maker receives takerPubKey (via subscribeToOrders polling), calls
 *       engine.setCounterPubKey(takerPubKey) on their existing engine
 *   6. Both parties proceed through the standard verify→fund→claim flow.
 *      The verification gate runs identically — the order book feeds params
 *      into the gate, never around it.
 */

import type { SwapProposal } from '../swap-engine';

export type Chain = 'BCH2' | 'BCH' | 'BTC' | 'BC2';

export type OrderStatus =
  | 'open'       // accepting takers
  | 'taken'      // matched; settling in progress
  | 'completed'  // swap finished
  | 'cancelled'  // maker withdrew before taken
  | 'expired';   // TTL elapsed before taken

/**
 * An order posted by a maker advertising a swap.
 *
 * The proposal field is the output of engine.prepare() for the Initiator role.
 * It contains the maker's hashLock and pubKey — everything a taker needs to
 * construct their Responder SwapParams. No funds touch the order book; the order
 * is an advertisement only.
 */
export interface SwapOrder {
  id:           string;
  proposal:     SwapProposal;   // maker's prepared proposal (hashLock + makerPubKey + terms)
  offerChain:   Chain;          // chain the maker is selling from
  wantChain:    Chain;          // chain the maker is buying into
  status:       OrderStatus;
  createdAt:    number;         // unix ms
  expiresAt:    number;         // unix ms — server refuses to match past this
  takenAt?:     number;         // unix ms — set when taken
  takerPubKey?: string;         // 66 hex chars — set when taken; maker reads this to set counterPubKey
}

/**
 * Request body for postOrder.
 * The maker generates the proposal by running engine.prepare() first,
 * which establishes the hashLock and makerPubKey without broadcasting anything.
 */
export interface PostOrderRequest {
  proposal:    SwapProposal;    // from engine.prepare()
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
 *   Taker (Responder): construct SwapParams from proposal + takerPubKey
 *   Maker (Initiator): call engine.setCounterPubKey(fromHex(takerPubKey))
 *
 * From here the full verify→fund→claim flow takes over. The order book's job
 * is done; it hands off to the engine and does not touch settlement.
 */
export interface TakeOrderResult {
  orderId:     string;
  proposal:    SwapProposal;   // maker's proposal (taker constructs Responder params from this)
  takerPubKey: string;         // 66 hex chars (maker sets this as their counterPubKey)
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
   * makerPubKey must match the order's proposal.initiatorPubKey (proves ownership).
   */
  cancelOrder(orderId: string, makerPubKey: string): Promise<void>;

  /**
   * Taker claims an order, atomically locking it so exactly one taker succeeds.
   * Returns the matched terms for both parties to begin the swap.
   * Throws if the order is not open (already taken, cancelled, or expired).
   */
  takeOrder(orderId: string, takerPubKey: string): Promise<TakeOrderResult>;
}
