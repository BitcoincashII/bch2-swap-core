/**
 * market-maker.mjs — a resting-order market-maker LOOP skeleton (the COORDINATION half).
 *
 *   DRY_RUN=1 node examples/market-maker.mjs      # default: log only, post nothing
 *   DRY_RUN=0 BCH2_MNEMONIC="…" node examples/market-maker.mjs
 *
 * Demonstrates the real coordination API a maker bot drives: derive wallet →
 * prepare a proposal → post resting offers → keep them fresh → cancel on exit.
 *
 * ⚠️ SETTLEMENT IS NOT AUTOMATED HERE. When one of your offers is taken you MUST
 * complete the swap safely, and the SDK's validated driver for that is the
 * `SwapController` (from `@bch2/swap-core`): it gates every irreversible action
 * (fund the second leg, reveal the secret) behind an SPV-verified branded proof.
 * The canonical, runnable end-to-end reference is ../src/e2e-lifecycle.test.ts
 * (two controllers, one shared chain, UTXO↔UTXO + UTXO↔EVM + refund + resume), and
 * the fund-safety contract is ../PROTOCOL.md (esp. §9). Running this coordination
 * loop WITHOUT a SwapController-driven settlement loop will strand a taker and risk
 * your funds. Treat this file as the coordination half of a bot, not a complete trader.
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

    // A real maker builds a SwapProposal (hashLock + makerPubKey + terms) for the offer, then posts it.
    // The hashLock commits to a SEED-DERIVED secret (see @bch2/swap-core/seed-secret + PROTOCOL.md §5) so the
    // secret is re-derivable on any device — nothing is broadcast at post time.
    //   const proposal = buildProposal(/* your terms + seed-derived hashLock */);
    //   const id = await book.postOrder({ proposal, offerChain: q.offerChain, wantChain: q.wantChain, ttlSeconds: q.ttlSeconds });
    //   live.set(id, {});
    // When the offer is taken, drive settlement with a SwapController as the INITIATOR (prepare → fundLegX →
    // verifyCounterpartyLegForReveal → revealAndClaim; refund if the taker vanishes). See ../src/e2e-lifecycle.test.ts.
    console.log('  post skipped: wire up buildProposal() → book.postOrder(), then settle with a SwapController (see ../PROTOCOL.md + ../src/e2e-lifecycle.test.ts).');
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
