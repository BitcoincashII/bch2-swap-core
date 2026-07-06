import { j as SwapProposal } from '../params-B0_XTQP-.js';

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

type Chain = 'BCH2' | 'BCH' | 'BTC' | 'BC2';
type OrderStatus = 'open' | 'taken' | 'completed' | 'cancelled' | 'expired';
/**
 * An order posted by a maker advertising a swap.
 *
 * The proposal field is the output of engine.prepare() for the Initiator role.
 * It contains the maker's hashLock and pubKey — everything a taker needs to
 * construct their Responder SwapParams. No funds touch the order book; the order
 * is an advertisement only.
 */
interface SwapOrder {
    id: string;
    proposal: SwapProposal;
    offerChain: Chain;
    wantChain: Chain;
    status: OrderStatus;
    createdAt: number;
    expiresAt: number;
    takenAt?: number;
    takerPubKey?: string;
}
/**
 * Request body for postOrder.
 * The maker generates the proposal by running engine.prepare() first,
 * which establishes the hashLock and makerPubKey without broadcasting anything.
 */
interface PostOrderRequest {
    proposal: SwapProposal;
    offerChain: Chain;
    wantChain: Chain;
    ttlSeconds?: number;
}
/**
 * Filter for queryOrders / subscribeToOrders.
 * All fields optional — omitting a field means "match any".
 */
interface OrderFilter {
    offerChain?: Chain;
    wantChain?: Chain;
    status?: OrderStatus;
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
interface TakeOrderResult {
    orderId: string;
    proposal: SwapProposal;
    takerPubKey: string;
    offerChain: Chain;
    wantChain: Chain;
}
/**
 * The discovery-layer interface.
 *
 * Implementations:
 *   CentralizedOrderBook — HTTP REST + polling (this repo, first implementation)
 *   DecentralizedOrderBook — relay/P2P broadcast (future; same interface, no client changes)
 */
interface OrderBook {
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

/**
 * In-memory OrderBook implementation for tests.
 *
 * Implements the full OrderBook interface without any network calls.
 * Tests can inspect internals via getOrder() and store().
 */

declare class MockOrderBook implements OrderBook {
    private orders;
    private subs;
    private notify;
    private _query;
    postOrder(req: PostOrderRequest): Promise<string>;
    queryOrders(filter: OrderFilter): Promise<SwapOrder[]>;
    subscribeToOrders(filter: OrderFilter, callback: (orders: SwapOrder[]) => void): () => void;
    cancelOrder(orderId: string, makerPubKey: string): Promise<void>;
    takeOrder(orderId: string, takerPubKey: string): Promise<TakeOrderResult>;
    /** Test helper — get order by id. */
    getOrder(id: string): SwapOrder | undefined;
    /** Test helper — number of orders in the book. */
    size(): number;
}

/**
 * CentralizedOrderBook — HTTP adapter implementing the OrderBook interface.
 *
 * Talks exclusively to the proxy-server REST API at /api/orders/*.
 * All implementation details (URL, HTTP verbs, polling interval) are
 * contained here — nothing leaks to callers through the OrderBook interface.
 *
 * subscribeToOrders uses polling (3 s interval). SSE / WebSocket push
 * is a drop-in replacement within this file whenever needed.
 */

declare class CentralizedOrderBook implements OrderBook {
    private readonly base;
    /**
     * @param opts.baseUrl Absolute origin of the proxy (e.g. "https://swap.bch2.org") — REQUIRED for Node /
     *   bot use, where a relative fetch has no origin. Omit in the browser to hit the same-origin path.
     */
    constructor(opts?: {
        baseUrl?: string;
    });
    postOrder(req: PostOrderRequest): Promise<string>;
    queryOrders(filter: OrderFilter): Promise<SwapOrder[]>;
    subscribeToOrders(filter: OrderFilter, callback: (orders: SwapOrder[]) => void): () => void;
    cancelOrder(orderId: string, makerPubKey: string): Promise<void>;
    takeOrder(orderId: string, takerPubKey: string): Promise<TakeOrderResult>;
}

export { CentralizedOrderBook, type Chain, MockOrderBook, type OrderBook, type OrderFilter, type OrderStatus, type PostOrderRequest, type SwapOrder, type TakeOrderResult };
