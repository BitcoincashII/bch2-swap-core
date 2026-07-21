/**
 * In-memory OrderBook implementation for tests.
 *
 * Implements the full OrderBook interface without any network calls.
 * Tests can inspect internals via getOrder() and store().
 */

import type {
  OrderBook, SwapOrder, PostOrderRequest, OrderFilter, TakeOrderResult,
} from './types';

let _nextId = 1;
function nextId(): string {
  return `mock-order-${(_nextId++).toString().padStart(4, '0')}`;
}

function matches(order: SwapOrder, filter: OrderFilter): boolean {
  if (filter.offerChain && order.offerChain !== filter.offerChain) return false;
  if (filter.wantChain  && order.wantChain  !== filter.wantChain)  return false;
  if (filter.status     && order.status     !== filter.status)     return false;
  return true;
}

export class MockOrderBook implements OrderBook {
  private orders  = new Map<string, SwapOrder>();
  private subs:   Array<{ filter: OrderFilter; cb: (orders: SwapOrder[]) => void }> = [];

  private notify(): void {
    for (const { filter, cb } of this.subs) {
      cb(this._query(filter));
    }
  }

  private _query(filter: OrderFilter): SwapOrder[] {
    return Array.from(this.orders.values()).filter(o => matches(o, filter));
  }

  async postOrder(req: PostOrderRequest): Promise<string> {
    const id  = nextId();
    const now = Date.now();
    const order: SwapOrder = {
      id,
      proposal:   req.proposal,
      offerChain: req.offerChain,
      wantChain:  req.wantChain,
      status:     'open',
      createdAt:  now,
      expiresAt:  now + (req.ttlSeconds ?? 3600) * 1000,
    };
    this.orders.set(id, order);
    this.notify();
    return id;
  }

  async queryOrders(filter: OrderFilter): Promise<SwapOrder[]> {
    return this._query(filter);
  }

  subscribeToOrders(
    filter: OrderFilter,
    callback: (orders: SwapOrder[]) => void,
  ): () => void {
    const entry = { filter, cb: callback };
    this.subs.push(entry);
    // Immediate snapshot
    callback(this._query(filter));
    return () => {
      this.subs = this.subs.filter(s => s !== entry);
    };
  }

  async cancelOrder(orderId: string, makerPubKey: string): Promise<void> {
    const order = this.orders.get(orderId);
    if (!order) throw new Error(`order-book: order not found: ${orderId}`);
    if (order.proposal.authPub !== makerPubKey) {
      throw new Error('order-book: cancelOrder: pubKey does not match order maker');
    }
    if (order.status !== 'open') {
      throw new Error(`order-book: cancelOrder: order is not open (status=${order.status})`);
    }
    this.orders.set(orderId, { ...order, status: 'cancelled' });
    this.notify();
  }

  async takeOrder(orderId: string, takerPubKey: string): Promise<TakeOrderResult> {
    const order = this.orders.get(orderId);
    if (!order) throw new Error(`order-book: order not found: ${orderId}`);
    if (order.status !== 'open') {
      throw new Error(`order-book: takeOrder: order is not open (status=${order.status})`);
    }
    const now = Date.now();
    if (now > order.expiresAt) {
      this.orders.set(orderId, { ...order, status: 'expired' });
      this.notify();
      throw new Error(`order-book: takeOrder: order has expired`);
    }
    this.orders.set(orderId, {
      ...order,
      status:       'taken',
      takerAuthPub: takerPubKey,   // the identity presented to takeOrder (real proxy field)
      takenAt:      now,
    });
    this.notify();
    return {
      orderId,
      proposal:    order.proposal,
      takerPubKey: takerPubKey,
      offerChain:  order.offerChain,
      wantChain:   order.wantChain,
    };
  }

  /** Test helper — get order by id. */
  getOrder(id: string): SwapOrder | undefined {
    return this.orders.get(id);
  }

  /** Test helper — number of orders in the book. */
  size(): number {
    return this.orders.size;
  }
}
