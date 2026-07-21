import { d as EvmSwapInfo, C as Chain$1, S as SwapOffer } from '../swap-types-CsSbca8_.js';

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
interface SwapProposal {
    offerChain: Chain;
    wantChain: Chain;
    sendAmount: string;
    receiveAmount: string;
    secretHash: string;
    secretNonce: string;
    secretScheme: string;
    makerIdPub: string;
    makerSig: string;
    authPub: string;
    refundAddress: string;
    receiveAddress: string;
    initiatorSendAddress: string;
    initiatorReceiveAddress: string;
    evmInfo?: EvmSwapInfo;
    evmAddress?: string;
    hashLock: string;
}
/** Order-book TRANSPORT chain codes (UPPERCASE) as the proxy emits them. The swap-EXECUTION model
 *  (SwapOffer, ../swap-types) uses the lowercase equivalents; ./adapter maps between the two. */
type Chain = 'BCH2' | 'BCH' | 'BTC' | 'BC2' | 'ETH' | 'BASE' | 'ARB' | 'POLY';
type OrderStatus = 'open' | 'taken' | 'completed' | 'cancelled' | 'expired';
/**
 * An order posted by a maker advertising a swap — the REAL top-level shape the live proxy returns from
 * GET /api/orders (each element of `{ success, data: SwapOrder[] }`).
 *
 * The nested `proposal` carries the maker's hashLock + terms + addresses. The top-level fields carry the
 * order's lifecycle + the responder's coordinates (set once the order is taken). No funds touch the order
 * book; the order is an advertisement + coordination record only.
 */
interface SwapOrder {
    id: string;
    offerChain: Chain;
    wantChain: Chain;
    status: OrderStatus;
    createdAt: number;
    expiresAt: number;
    takenAt?: number;
    responderLocktime?: number;
    evmSwapId?: string;
    initiatorTxid?: string;
    responderTxid?: string;
    responderSendAddress?: string;
    responderReceiveAddress?: string;
    takerAuthPub?: string;
    proposal: SwapProposal;
}
/**
 * Request body for postOrder.
 * The maker builds the proposal (hashLock + terms + addresses) from its SwapOffer via
 * `offerToProposal` (./adapter), which establishes the hashLock without broadcasting anything.
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
 *   Taker (Responder): construct the responder SwapOffer from proposal via proposalToOffer/orderToOffer
 *   Maker (Initiator): read the taker's coordinates from the polled order (responderReceiveAddress + takerAuthPub)
 *
 * From here the full verify→fund→claim flow takes over inside the SwapController. The order book's job is
 * done; it hands off to the controller and does not touch settlement.
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

/**
 * Adapter — the documented bridge between the order-book TRANSPORT model (SwapProposal / SwapOrder, the
 * exact shape the live proxy returns) and the swap-EXECUTION model (SwapOffer, ../swap-types — what the
 * `SwapController` consumes).
 *
 * The two models describe the same swap in different vocabularies:
 *   transport (proxy)          execution (SwapOffer)
 *   ─────────────────          ──────────────────────
 *   offerChain  "POLY"    ⇄    sendChain     "poly"      (chain codes are UPPER ⇄ lower)
 *   wantChain   "BCH2"    ⇄    receiveChain  "bch2"
 *   sendAmount  "1290788219"  ⇄  sendAmount  "1290788219"  (base-unit decimal STRINGS — sats/wei — carried through)
 *   receiveAmount         ⇄    receiveAmount
 *   secretHash / hashLock ⇄    secretHash                (hashLock == secretHash)
 *   secretNonce           ⇄    secretNonce
 *   secretScheme          ⇄    secretScheme
 *   makerIdPub/makerSig   ⇄    makerIdPub/makerSig
 *   authPub               ⇄    authPub
 *   refundAddress /            initiatorSendAddress       (refundAddress mirrors initiatorSendAddress)
 *     initiatorSendAddress ⇄
 *   receiveAddress /           initiatorReceiveAddress    (receiveAddress mirrors initiatorReceiveAddress)
 *     initiatorReceiveAddress ⇄
 *   evmInfo/evmAddress    ⇄    evmInfo/evmAddress
 *
 * The order-level fields (id, status, timestamps, taker coordinates) live on `SwapOrder`, not on the
 * proposal, so `orderToOffer` (not `proposalToOffer`) is what carries them onto the SwapOffer.
 */

/** Map a transport chain CODE (e.g. "POLY", case-insensitive) to the SwapOffer chain value ("poly").
 *  Fails closed on an unknown code rather than silently forwarding a bad chain into fund logic. */
declare function bookChainToOffer(code: string): Chain$1;
/** Map a SwapOffer chain value ("poly") to the transport chain CODE ("POLY"). Fails closed on an unknown chain. */
declare function offerChainToBook(chain: string): Chain;
/**
 * Map a transport `SwapProposal` to the execution `SwapOffer`.
 *
 * The proposal has no id / status / timestamps (those are order-level, on `SwapOrder`) — this fills neutral
 * placeholders (id '', status 'open', createdAt/expiresAt 0). Use `orderToOffer` when you hold the full order,
 * or pass `overrides` to supply them here.
 */
declare function proposalToOffer(proposal: SwapProposal, overrides?: Partial<SwapOffer>): SwapOffer;
/**
 * Map a full transport `SwapOrder` to the execution `SwapOffer`, carrying the order-level fields
 * (id, status, timestamps, taker coordinates) that the bare proposal lacks. This is what a taker/maker uses
 * to turn a live order off the book into a `SwapController` offer.
 */
declare function orderToOffer(order: SwapOrder, overrides?: Partial<SwapOffer>): SwapOffer;
/**
 * Map an execution `SwapOffer` to a transport `SwapProposal` (e.g. for `postOrder`).
 *
 * Amounts are coerced to decimal strings. `hashLock` and the mirrored `refundAddress`/`receiveAddress` are
 * derived from the offer's `secretHash` and `initiatorSend/ReceiveAddress`. Pass `overrides` to supply
 * transport-only fields the offer lacks (e.g. a freshly-computed makerSig/authPub).
 */
declare function offerToProposal(offer: SwapOffer, overrides?: Partial<SwapProposal>): SwapProposal;

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

export { CentralizedOrderBook, type Chain, MockOrderBook, type OrderBook, type OrderFilter, type OrderStatus, type PostOrderRequest, type SwapOrder, type SwapProposal, type TakeOrderResult, bookChainToOffer, offerChainToBook, offerToProposal, orderToOffer, proposalToOffer };
