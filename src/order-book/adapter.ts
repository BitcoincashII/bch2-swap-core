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

import type { SwapProposal, SwapOrder, Chain } from './types';
import type { SwapOffer, Chain as OfferChain } from '../swap-types';

// ── Chain-code mapping (UPPER transport ⇄ lower execution) ──────────────────────────────────────────────
const BOOK_TO_OFFER: Record<Chain, OfferChain> = {
  BCH2: 'bch2', BCH: 'bch', BTC: 'btc', BC2: 'bc2', ETH: 'eth', BASE: 'base', ARB: 'arb', POLY: 'poly',
};
const OFFER_TO_BOOK: Record<OfferChain, Chain> = {
  bch2: 'BCH2', bch: 'BCH', btc: 'BTC', bc2: 'BC2', eth: 'ETH', base: 'BASE', arb: 'ARB', poly: 'POLY',
};

/** Map a transport chain CODE (e.g. "POLY", case-insensitive) to the SwapOffer chain value ("poly").
 *  Fails closed on an unknown code rather than silently forwarding a bad chain into fund logic. */
export function bookChainToOffer(code: string): OfferChain {
  const upper = String(code).toUpperCase() as Chain;
  const mapped = BOOK_TO_OFFER[upper];
  if (!mapped) throw new Error(`bookChainToOffer: unknown order-book chain code '${code}'`);
  return mapped;
}

/** Map a SwapOffer chain value ("poly") to the transport chain CODE ("POLY"). Fails closed on an unknown chain. */
export function offerChainToBook(chain: string): Chain {
  const lower = String(chain).toLowerCase() as OfferChain;
  const mapped = OFFER_TO_BOOK[lower];
  if (!mapped) throw new Error(`offerChainToBook: unknown SwapOffer chain '${chain}'`);
  return mapped;
}

/**
 * Map a transport `SwapProposal` to the execution `SwapOffer`.
 *
 * The proposal has no id / status / timestamps (those are order-level, on `SwapOrder`) — this fills neutral
 * placeholders (id '', status 'open', createdAt/expiresAt 0). Use `orderToOffer` when you hold the full order,
 * or pass `overrides` to supply them here.
 */
export function proposalToOffer(proposal: SwapProposal, overrides?: Partial<SwapOffer>): SwapOffer {
  const offer: SwapOffer = {
    id: '',
    sendChain: bookChainToOffer(proposal.offerChain),
    receiveChain: bookChainToOffer(proposal.wantChain),
    sendAmount: proposal.sendAmount,          // base-unit decimal string (sats/wei), carried through verbatim
    receiveAmount: proposal.receiveAmount,
    secretHash: proposal.secretHash,
    secretNonce: proposal.secretNonce || undefined,
    secretScheme: proposal.secretScheme || undefined,
    makerIdPub: proposal.makerIdPub || undefined,
    makerSig: proposal.makerSig || undefined,
    authPub: proposal.authPub || undefined,
    // initiator (maker) addresses: prefer the explicit fields, fall back to the mirrored refund/receive names
    initiatorSendAddress: proposal.initiatorSendAddress || proposal.refundAddress || '',
    initiatorReceiveAddress: proposal.initiatorReceiveAddress || proposal.receiveAddress || '',
    status: 'open',
    createdAt: 0,
    expiresAt: 0,
  };
  if (proposal.evmInfo !== undefined) offer.evmInfo = proposal.evmInfo;
  if (proposal.evmAddress !== undefined) offer.evmAddress = proposal.evmAddress;
  return overrides ? { ...offer, ...overrides } : offer;
}

/**
 * Map a full transport `SwapOrder` to the execution `SwapOffer`, carrying the order-level fields
 * (id, status, timestamps, taker coordinates) that the bare proposal lacks. This is what a taker/maker uses
 * to turn a live order off the book into a `SwapController` offer.
 */
export function orderToOffer(order: SwapOrder, overrides?: Partial<SwapOffer>): SwapOffer {
  const base = proposalToOffer(order.proposal, {
    id: order.id,
    status: order.status,
    createdAt: order.createdAt,
    expiresAt: order.expiresAt,
    // chains come from the proposal, but the order-level codes are authoritative if they ever diverge
    sendChain: bookChainToOffer(order.offerChain),
    receiveChain: bookChainToOffer(order.wantChain),
  });
  if (order.takerAuthPub !== undefined) base.takerAuthPub = order.takerAuthPub;
  return overrides ? { ...base, ...overrides } : base;
}

/**
 * Map an execution `SwapOffer` to a transport `SwapProposal` (e.g. for `postOrder`).
 *
 * Amounts are coerced to decimal strings. `hashLock` and the mirrored `refundAddress`/`receiveAddress` are
 * derived from the offer's `secretHash` and `initiatorSend/ReceiveAddress`. Pass `overrides` to supply
 * transport-only fields the offer lacks (e.g. a freshly-computed makerSig/authPub).
 */
export function offerToProposal(offer: SwapOffer, overrides?: Partial<SwapProposal>): SwapProposal {
  const proposal: SwapProposal = {
    offerChain: offerChainToBook(offer.sendChain),
    wantChain: offerChainToBook(offer.receiveChain),
    sendAmount: String(offer.sendAmount),
    receiveAmount: String(offer.receiveAmount),
    secretHash: offer.secretHash,
    secretNonce: offer.secretNonce ?? '',
    secretScheme: offer.secretScheme ?? '',
    makerIdPub: offer.makerIdPub ?? '',
    makerSig: offer.makerSig ?? '',
    authPub: offer.authPub ?? '',
    refundAddress: offer.initiatorSendAddress,
    receiveAddress: offer.initiatorReceiveAddress,
    initiatorSendAddress: offer.initiatorSendAddress,
    initiatorReceiveAddress: offer.initiatorReceiveAddress,
    hashLock: offer.secretHash,   // the HTLC hash lock is the secret hash
  };
  if (offer.evmInfo !== undefined) proposal.evmInfo = offer.evmInfo;
  if (offer.evmAddress !== undefined) proposal.evmAddress = offer.evmAddress;
  return overrides ? { ...proposal, ...overrides } : proposal;
}
