/**
 * market-maker.mjs — a resting-order market-maker LOOP skeleton.
 *
 *   DRY_RUN=1 node examples/market-maker.mjs      # default: log only, post nothing
 *   DRY_RUN=0 BCH2_MNEMONIC="…" node examples/market-maker.mjs
 *
 * Demonstrates the real coordination API a maker bot drives: derive wallet →
 * prepare a proposal → post resting offers → keep them fresh → cancel on exit.
 *
 * ⚠️ SETTLEMENT IS NOT AUTOMATED HERE. When one of your offers is taken you MUST
 * complete the swap (fund your HTLC leg, watch for the counterparty, claim, or
 * refund if they vanish) using @bch2/swap-core/swap-engine + /htlc-builder — see
 * §6 of ../API.md. Running this without a settlement loop will strand a taker and
 * risk your funds. Treat this file as the coordination half of a bot, not a
 * complete, unattended trader.
 */
import { deriveAddresses } from '@bch2/swap-core/wallet-core';
import { CentralizedOrderBook } from '@bch2/swap-core/order-book';

const BASE_URL = process.env.BCH2_SWAP_URL ?? 'https://swap.bch2.org';
const DRY_RUN = process.env.DRY_RUN !== '0';
const REFRESH_MS = 60_000;

if (!process.env.BCH2_MNEMONIC && !DRY_RUN) {
  console.error('Set BCH2_MNEMONIC (a funded, DEDICATED swap wallet) or run with DRY_RUN=1.');
  process.exit(1);
}
const mnemonic = process.env.BCH2_MNEMONIC ?? 'test test test test test test test test test test test junk';
const addrs = deriveAddresses(mnemonic);
const book = new CentralizedOrderBook({ baseUrl: BASE_URL });

console.log(`Market maker for ${addrs.bch2}  (DRY_RUN=${DRY_RUN})`);

const live = new Map(); // orderId -> { adminToken }

// Your quoting strategy: what resting offers to keep on the book right now.
// Real bots price these off /api/prices + inventory. Kept abstract here.
function desiredQuotes() {
  return [
    { offerChain: 'BCH2', wantChain: 'BTC', /* amounts, rate, ttl… */ ttlSeconds: 3600 },
  ];
}

async function reconcile() {
  const quotes = desiredQuotes();
  for (const q of quotes) {
    if (DRY_RUN) { console.log('  [dry-run] would post', q); continue; }

    // A real maker first builds a proposal with the swap engine:
    //   const proposal = engine.prepare(/* Initiator role, terms */);
    // then posts it. postOrder returns the new order id; recover the admin
    // token via GET /api/orders/:id/my-token to manage the order later.
    //   const id = await book.postOrder({ proposal, offerChain: q.offerChain, wantChain: q.wantChain, ttlSeconds: q.ttlSeconds });
    //   live.set(id, {});
    console.log('  post skipped: wire up engine.prepare() → book.postOrder() (see ../API.md §6).');
  }
}

async function shutdown() {
  console.log('\nCancelling open orders…');
  for (const [id] of live) {
    try { await book.cancelOrder(id, /* makerPubKey */ ''); } catch (e) { console.error('cancel', id, e.message); }
  }
  process.exit(0);
}
process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);

await reconcile();
setInterval(reconcile, REFRESH_MS);
console.log(`Reconciling every ${REFRESH_MS / 1000}s. Ctrl-C to cancel orders and exit.`);
