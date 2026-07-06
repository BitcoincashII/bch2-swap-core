/**
 * quickstart.mjs — a fully runnable, READ-ONLY intro bot.
 *
 *   node examples/quickstart.mjs
 *
 * Derives a throwaway wallet, connects to the live BCH2 Swap DEX order book,
 * prints the current book + reference prices, and live-subscribes for 15s.
 * It never posts, funds, or signs anything — safe to run as-is.
 */
import { generateMnemonic, deriveAddresses } from '@bch2/swap-core/wallet-core';
import { CentralizedOrderBook } from '@bch2/swap-core/order-book';

const BASE_URL = process.env.BCH2_SWAP_URL ?? 'https://swap.bch2.org';

// 1. Wallet (a fresh demo seed — for a real bot, load your funded dedicated-wallet seed from env/secret store)
const mnemonic = process.env.BCH2_MNEMONIC ?? generateMnemonic();
const addrs = deriveAddresses(mnemonic);
console.log('Wallet:');
console.log('  BCH2:', addrs.bch2);
console.log('  EVM :', addrs.evm);

// 2. Connect to the order book (Node REQUIRES an absolute baseUrl)
const book = new CentralizedOrderBook({ baseUrl: BASE_URL });

// 3. Snapshot the current book
const orders = await book.queryOrders({});
console.log(`\nOpen orders (${orders.length}):`);
for (const o of orders.slice(0, 10)) {
  console.log(`  ${o.id}  ${o.offerChain} → ${o.wantChain}  status=${o.status}  expires=${new Date(o.expiresAt).toISOString()}`);
}

// 4. Reference prices (for quoting / sizing)
try {
  const res = await fetch(`${BASE_URL}/api/prices`);
  const body = await res.json();
  if (body.success) console.log('\nPrices (USD):', body.data);
} catch { /* prices are best-effort */ }

// 5. Live subscription (polls every 3s). Returns an unsubscribe fn.
console.log('\nSubscribing to the book for 15s…');
const stop = book.subscribeToOrders({}, (os) => {
  console.log(`  [${new Date().toLocaleTimeString()}] book: ${os.length} open`);
});
setTimeout(() => { stop(); console.log('Done.'); process.exit(0); }, 15_000);
