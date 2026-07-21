// src/order-book/adapter.ts
var BOOK_TO_OFFER = {
  BCH2: "bch2",
  BCH: "bch",
  BTC: "btc",
  BC2: "bc2",
  ETH: "eth",
  BASE: "base",
  ARB: "arb",
  POLY: "poly"
};
var OFFER_TO_BOOK = {
  bch2: "BCH2",
  bch: "BCH",
  btc: "BTC",
  bc2: "BC2",
  eth: "ETH",
  base: "BASE",
  arb: "ARB",
  poly: "POLY"
};
function bookChainToOffer(code) {
  const upper = String(code).toUpperCase();
  const mapped = BOOK_TO_OFFER[upper];
  if (!mapped) throw new Error(`bookChainToOffer: unknown order-book chain code '${code}'`);
  return mapped;
}
function offerChainToBook(chain) {
  const lower = String(chain).toLowerCase();
  const mapped = OFFER_TO_BOOK[lower];
  if (!mapped) throw new Error(`offerChainToBook: unknown SwapOffer chain '${chain}'`);
  return mapped;
}
function proposalToOffer(proposal, overrides) {
  const offer = {
    id: "",
    sendChain: bookChainToOffer(proposal.offerChain),
    receiveChain: bookChainToOffer(proposal.wantChain),
    sendAmount: proposal.sendAmount,
    // base-unit decimal string (sats/wei), carried through verbatim
    receiveAmount: proposal.receiveAmount,
    secretHash: proposal.secretHash,
    secretNonce: proposal.secretNonce || void 0,
    secretScheme: proposal.secretScheme || void 0,
    makerIdPub: proposal.makerIdPub || void 0,
    makerSig: proposal.makerSig || void 0,
    authPub: proposal.authPub || void 0,
    // initiator (maker) addresses: prefer the explicit fields, fall back to the mirrored refund/receive names
    initiatorSendAddress: proposal.initiatorSendAddress || proposal.refundAddress || "",
    initiatorReceiveAddress: proposal.initiatorReceiveAddress || proposal.receiveAddress || "",
    status: "open",
    createdAt: 0,
    expiresAt: 0
  };
  if (proposal.evmInfo !== void 0) offer.evmInfo = proposal.evmInfo;
  if (proposal.evmAddress !== void 0) offer.evmAddress = proposal.evmAddress;
  return overrides ? { ...offer, ...overrides } : offer;
}
function orderToOffer(order, overrides) {
  const base = proposalToOffer(order.proposal, {
    id: order.id,
    status: order.status,
    createdAt: order.createdAt,
    expiresAt: order.expiresAt,
    // chains come from the proposal, but the order-level codes are authoritative if they ever diverge
    sendChain: bookChainToOffer(order.offerChain),
    receiveChain: bookChainToOffer(order.wantChain)
  });
  if (order.takerAuthPub !== void 0) base.takerAuthPub = order.takerAuthPub;
  return overrides ? { ...base, ...overrides } : base;
}
function offerToProposal(offer, overrides) {
  const proposal = {
    offerChain: offerChainToBook(offer.sendChain),
    wantChain: offerChainToBook(offer.receiveChain),
    sendAmount: String(offer.sendAmount),
    receiveAmount: String(offer.receiveAmount),
    secretHash: offer.secretHash,
    secretNonce: offer.secretNonce ?? "",
    secretScheme: offer.secretScheme ?? "",
    makerIdPub: offer.makerIdPub ?? "",
    makerSig: offer.makerSig ?? "",
    authPub: offer.authPub ?? "",
    refundAddress: offer.initiatorSendAddress,
    receiveAddress: offer.initiatorReceiveAddress,
    initiatorSendAddress: offer.initiatorSendAddress,
    initiatorReceiveAddress: offer.initiatorReceiveAddress,
    hashLock: offer.secretHash
    // the HTLC hash lock is the secret hash
  };
  if (offer.evmInfo !== void 0) proposal.evmInfo = offer.evmInfo;
  if (offer.evmAddress !== void 0) proposal.evmAddress = offer.evmAddress;
  return overrides ? { ...proposal, ...overrides } : proposal;
}

// src/order-book/mock.ts
var _nextId = 1;
function nextId() {
  return `mock-order-${(_nextId++).toString().padStart(4, "0")}`;
}
function matches(order, filter) {
  if (filter.offerChain && order.offerChain !== filter.offerChain) return false;
  if (filter.wantChain && order.wantChain !== filter.wantChain) return false;
  if (filter.status && order.status !== filter.status) return false;
  return true;
}
var MockOrderBook = class {
  constructor() {
    this.orders = /* @__PURE__ */ new Map();
    this.subs = [];
  }
  notify() {
    for (const { filter, cb } of this.subs) {
      cb(this._query(filter));
    }
  }
  _query(filter) {
    return Array.from(this.orders.values()).filter((o) => matches(o, filter));
  }
  async postOrder(req) {
    const id = nextId();
    const now = Date.now();
    const order = {
      id,
      proposal: req.proposal,
      offerChain: req.offerChain,
      wantChain: req.wantChain,
      status: "open",
      createdAt: now,
      expiresAt: now + (req.ttlSeconds ?? 3600) * 1e3
    };
    this.orders.set(id, order);
    this.notify();
    return id;
  }
  async queryOrders(filter) {
    return this._query(filter);
  }
  subscribeToOrders(filter, callback) {
    const entry = { filter, cb: callback };
    this.subs.push(entry);
    callback(this._query(filter));
    return () => {
      this.subs = this.subs.filter((s) => s !== entry);
    };
  }
  async cancelOrder(orderId, makerPubKey) {
    const order = this.orders.get(orderId);
    if (!order) throw new Error(`order-book: order not found: ${orderId}`);
    if (order.proposal.authPub !== makerPubKey) {
      throw new Error("order-book: cancelOrder: pubKey does not match order maker");
    }
    if (order.status !== "open") {
      throw new Error(`order-book: cancelOrder: order is not open (status=${order.status})`);
    }
    this.orders.set(orderId, { ...order, status: "cancelled" });
    this.notify();
  }
  async takeOrder(orderId, takerPubKey) {
    const order = this.orders.get(orderId);
    if (!order) throw new Error(`order-book: order not found: ${orderId}`);
    if (order.status !== "open") {
      throw new Error(`order-book: takeOrder: order is not open (status=${order.status})`);
    }
    const now = Date.now();
    if (now > order.expiresAt) {
      this.orders.set(orderId, { ...order, status: "expired" });
      this.notify();
      throw new Error(`order-book: takeOrder: order has expired`);
    }
    this.orders.set(orderId, {
      ...order,
      status: "taken",
      takerAuthPub: takerPubKey,
      // the identity presented to takeOrder (real proxy field)
      takenAt: now
    });
    this.notify();
    return {
      orderId,
      proposal: order.proposal,
      takerPubKey,
      offerChain: order.offerChain,
      wantChain: order.wantChain
    };
  }
  /** Test helper — get order by id. */
  getOrder(id) {
    return this.orders.get(id);
  }
  /** Test helper — number of orders in the book. */
  size() {
    return this.orders.size;
  }
};

// src/order-book/centralized.ts
var ORDER_BOOK_PATH = "/api/orders";
var POLL_INTERVAL_MS = 3e3;
function filterToParams(filter) {
  const p = new URLSearchParams();
  if (filter.offerChain) p.set("offerChain", filter.offerChain);
  if (filter.wantChain) p.set("wantChain", filter.wantChain);
  if (filter.status) p.set("status", filter.status);
  const s = p.toString();
  return s ? `?${s}` : "";
}
async function apiFetch(path, init) {
  const res = await fetch(path, {
    ...init,
    headers: {
      "Content-Type": "application/json",
      ...init?.headers ?? {}
    }
  });
  const body = await res.json();
  if (!res.ok || !body.success) {
    throw new Error(body.error ?? `order-book: HTTP ${res.status}`);
  }
  return body.data;
}
var CentralizedOrderBook = class {
  /**
   * @param opts.baseUrl Absolute origin of the proxy (e.g. "https://swap.bch2.org") — REQUIRED for Node /
   *   bot use, where a relative fetch has no origin. Omit in the browser to hit the same-origin path.
   */
  constructor(opts) {
    this.base = (opts?.baseUrl?.replace(/\/+$/, "") ?? "") + ORDER_BOOK_PATH;
  }
  async postOrder(req) {
    return apiFetch(this.base, {
      method: "POST",
      body: JSON.stringify(req)
    });
  }
  async queryOrders(filter) {
    return apiFetch(this.base + filterToParams(filter));
  }
  subscribeToOrders(filter, callback) {
    let alive = true;
    const poll = async () => {
      try {
        const orders = await this.queryOrders(filter);
        if (alive) callback(orders);
      } catch {
      }
    };
    poll();
    const timer = setInterval(() => {
      if (alive) poll();
    }, POLL_INTERVAL_MS);
    return () => {
      alive = false;
      clearInterval(timer);
    };
  }
  async cancelOrder(orderId, makerPubKey) {
    await apiFetch(`${this.base}/${encodeURIComponent(orderId)}`, {
      method: "DELETE",
      body: JSON.stringify({ makerPubKey })
    });
  }
  async takeOrder(orderId, takerPubKey) {
    return apiFetch(
      `${this.base}/${encodeURIComponent(orderId)}/take`,
      {
        method: "POST",
        body: JSON.stringify({ takerPubKey })
      }
    );
  }
};

export { CentralizedOrderBook, MockOrderBook, bookChainToOffer, offerChainToBook, offerToProposal, orderToOffer, proposalToOffer };
