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

import type {
  OrderBook, SwapOrder, PostOrderRequest, OrderFilter, TakeOrderResult,
} from './types';

const ORDER_BOOK_PATH = '/api/orders';
const POLL_INTERVAL_MS = 3000;

function filterToParams(filter: OrderFilter): string {
  const p = new URLSearchParams();
  if (filter.offerChain) p.set('offerChain', filter.offerChain);
  if (filter.wantChain)  p.set('wantChain',  filter.wantChain);
  if (filter.status)     p.set('status',      filter.status);
  const s = p.toString();
  return s ? `?${s}` : '';
}

async function apiFetch<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(path, {
    ...init,
    headers: {
      'Content-Type': 'application/json',
      ...(init?.headers ?? {}),
    },
  });
  const body = await res.json() as { success: boolean; data?: T; error?: string };
  if (!res.ok || !body.success) {
    throw new Error(body.error ?? `order-book: HTTP ${res.status}`);
  }
  return body.data as T;
}

export class CentralizedOrderBook implements OrderBook {
  private readonly base: string;

  /**
   * @param opts.baseUrl Absolute origin of the proxy (e.g. "https://swap.bch2.org") — REQUIRED for Node /
   *   bot use, where a relative fetch has no origin. Omit in the browser to hit the same-origin path.
   */
  constructor(opts?: { baseUrl?: string }) {
    this.base = (opts?.baseUrl?.replace(/\/+$/, '') ?? '') + ORDER_BOOK_PATH;
  }

  async postOrder(req: PostOrderRequest): Promise<string> {
    return apiFetch<string>(this.base, {
      method: 'POST',
      body:   JSON.stringify(req),
    });
  }

  async queryOrders(filter: OrderFilter): Promise<SwapOrder[]> {
    return apiFetch<SwapOrder[]>(this.base + filterToParams(filter));
  }

  subscribeToOrders(
    filter: OrderFilter,
    callback: (orders: SwapOrder[]) => void,
  ): () => void {
    let alive = true;

    const poll = async () => {
      try {
        const orders = await this.queryOrders(filter);
        if (alive) callback(orders);
      } catch { /* swallow poll errors; retry on next interval */ }
    };

    // Immediate snapshot, then poll
    poll();
    const timer = setInterval(() => { if (alive) poll(); }, POLL_INTERVAL_MS);

    return () => {
      alive = false;
      clearInterval(timer);
    };
  }

  async cancelOrder(orderId: string, makerPubKey: string): Promise<void> {
    await apiFetch<null>(`${this.base}/${encodeURIComponent(orderId)}`, {
      method: 'DELETE',
      body:   JSON.stringify({ makerPubKey }),
    });
  }

  async takeOrder(orderId: string, takerPubKey: string): Promise<TakeOrderResult> {
    return apiFetch<TakeOrderResult>(
      `${this.base}/${encodeURIComponent(orderId)}/take`,
      {
        method: 'POST',
        body:   JSON.stringify({ takerPubKey }),
      },
    );
  }
}
