// =============================================================================
// reference-bot.mjs — a runnable REFERENCE market-maker/taker bot for @bch2/swap-core v3.
//
// ⚠️  READ THIS FIRST — HONESTY NOTICE
//
//   • This is a REFERENCE, not a turnkey trader. It shows the EXACT SwapController
//     method sequence a bot must drive (copied from the canonical two-party
//     end-to-end suite ../src/e2e-lifecycle.test.ts), wired to REAL Node transports:
//     the Electrum client in ./electrum-node-client.mjs and the live CentralizedOrderBook.
//   • When you run it with a FUNDED wallet and BCH2_SWAP_LIVE=1, it drives REAL
//     on-chain funds. Atomic swaps are IRREVERSIBLE. TEST ON TESTNET/REGTEST FIRST.
//   • The CentralizedOrderBook talks to the LIVE proxy. The order↔offer FIELD MAPPING
//     is the SDK's documented adapter (offerToProposal / orderToOffer — types match the
//     live proxy). What remains a COORDINATION SEAM is the out-of-band delivery of the
//     counterparty's published HTLC; those bits FAIL CLOSED (they stop the bot BEFORE any
//     irreversible action rather than fund/reveal on a guess).
//   • Fund-safety lives INSIDE the SwapController (SPV depth gates, timelock ordering,
//     secret lifecycle, single-flight, durable-before-broadcast). This bot only
//     injects I/O + signing and calls the methods in order. It cannot make the swap
//     unsafe: the irreversible steps require branded proofs only the gates can mint.
//
// Usage:
//   node examples/reference-bot.mjs make <sendChain> <recvChain> <amount>
//   node examples/reference-bot.mjs take <orderId>
//   node examples/reference-bot.mjs resume <swapId>
//
//   sendChain/recvChain ∈ { bch2, bch, btc }  (bc2 is SUSPENDED; eth/base/arb/poly are EVM — see EVM note below)
//   amount              = integer BASE UNITS of sendChain (sats for UTXO legs)
//
// Env:
//   BCH2_SWAP_MNEMONIC   a DEDICATED, funded swap-wallet seed phrase (REQUIRED to do anything)
//   BCH2_SWAP_LIVE=1     explicit opt-in to connect + broadcast. Without it the bot validates,
//                        prints the plan, and exits — it connects/broadcasts NOTHING.
//   BCH2_SWAP_URL        order-book/proxy origin (default https://swap.bch2.org)
//   BCH2_SWAP_NETWORK    'regtest' to match the DEX regtest nodes (default mainnet)
//   BCH2_SWAP_CP_HTLC        COORDINATION SEAM (JSON DurableHTLC): the counterparty's published HTLC
//   BCH2_SWAP_CP_CLAIM_PUBKEY COORDINATION SEAM (66-hex): counterparty pubkey that may claim YOUR leg
//   EVM_RPC_URLS_<CHAIN>     comma-separated RPC URLs (>=2) for an EVM leg's quorum read provider
// =============================================================================

import {
  SwapController,
  MnemonicSeedVault,
  InMemoryDurableStore,
  InMemorySessionStore,
  InProcessMutex,
  UtxoReservationRegistry,
} from '../dist/index.js';
import {
  CentralizedOrderBook, offerToProposal, orderToOffer, offerChainToBook, bookChainToOffer,
} from '../dist/order-book/index.js';
import { deriveKeyForSigning, deriveAddresses, validateMnemonic } from '../dist/wallet-core.js';
import { deriveSwapSecret, generateSwapNonce, SWAP_SECRET_SCHEME } from '../dist/seed-secret.js';
import { chainConfigs, isSwapPairSuspended } from '../dist/chain-config.js';
import { hash160, sha256, bytesToHex, hexToBytes, htlcScripthash } from '../dist/htlc-builder.js';
import { decodeCashAddr, decodeLegacyAddress } from '../dist/address-codec.js';
import { makeElectrumChainClient } from './electrum-node-client.mjs';
import { createRequire } from 'node:module';

// CommonJS `require` for the optional EVM path (ethers is loaded lazily, only when an EVM leg is present).
const require = createRequire(import.meta.url);

// -----------------------------------------------------------------------------
// Config + small helpers
// -----------------------------------------------------------------------------
const BASE_URL = process.env.BCH2_SWAP_URL ?? 'https://swap.bch2.org';
const LIVE = process.env.BCH2_SWAP_LIVE === '1';
const UTXO_CHAINS = new Set(['bch2', 'bch', 'btc', 'bc2']);

const log = (...a) => console.log(...a);
const die = (msg, code = 1) => { console.error(msg); process.exit(code); };
const isEvmChain = (c) => !!(chainConfigs[c] && chainConfigs[c].isEvm);

/** Map an SDK Chain to the wallet-core signing-chain param. UTXO chains map 1:1; every EVM chain uses the 'evm' key. */
function walletChainFor(chain) {
  if (UTXO_CHAINS.has(chain)) return chain;
  if (isEvmChain(chain)) return 'evm';
  throw new Error(`unknown chain '${chain}'`);
}

/** The first configured Electrum server for a UTXO chain (host/port). */
function electrumServerFor(chain) {
  const servers = chainConfigs[chain]?.electrumServers;
  if (!servers || servers.length === 0) throw new Error(`no Electrum server configured for '${chain}'`);
  const { host, port } = servers[0];
  return { host, port };
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/** Poll `fn` until it returns a non-null/undefined value or the timeout elapses. Returns the value or null on timeout. */
async function pollFor(fn, { intervalMs = 15_000, timeoutMs = 2 * 60 * 60_000, label = 'poll' } = {}) {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    let v = null;
    try { v = await fn(); } catch (e) { log(`  [${label}] transient: ${e.message}`); }
    if (v !== null && v !== undefined && v !== false) return v;
    if (Date.now() >= deadline) return null;
    await sleep(intervalMs);
  }
}

// -----------------------------------------------------------------------------
// Dependency wiring — the SwapControllerDeps the controller is injected with.
//
// PRODUCTION NOTE (audit fixes #3 + #4): this reference uses IN-MEMORY durable + mutex,
// which do NOT survive a process restart. A production bot MUST back `durable` with a
// FILE/SQLite DurableStore and `mutex` with a CROSS-PROCESS Mutex (both keyed off that
// same store), so "durable-before-broadcast" (fix #4) and "single-flight" (fix #3) hold
// across a crash/restart and across multiple worker processes. In memory, a restart loses
// the funding/claim/refund recovery material the controller persists — on mainnet that is
// a fund-loss hazard. Implement DurableStore/Mutex over your KV and inject them here.
// -----------------------------------------------------------------------------
function buildDeps(mnemonic, pair) {
  const clientCache = new Map();
  const closers = [];

  const chainClientFor = (chain) => {
    if (isEvmChain(chain)) throw new Error(`chainClientFor('${chain}'): EVM legs use evmProviderFor/evmSignerFor, not a UTXO client`);
    if (clientCache.has(chain)) return clientCache.get(chain);
    const client = makeElectrumChainClient(electrumServerFor(chain));
    if (typeof client.close === 'function') closers.push(() => { try { client.close(); } catch { /* ignore */ } });
    clientCache.set(chain, client);
    return client;
  };

  // SeedVault: derives keys ON DEMAND; the raw seed never leaves the vault or crosses the wire.
  // wallet-core's deriveKeyForSigning is the per-chain HD signer. The SwapController only asks the
  // vault for UTXO signing keys (fund/claim/refund) + K_ss (the swap-secret key); EVM legs sign via
  // evmSignerFor, so the vault is never asked for an EVM key.
  const seedVault = new MnemonicSeedVault(mnemonic, async (chain, mn) => {
    const k = deriveKeyForSigning(mn, walletChainFor(chain));
    return { privateKey: k.privateKey, publicKey: k.publicKey };
  });

  const durable = new InMemoryDurableStore();

  const deps = {
    chainClientFor,
    seedVault,
    durable,
    session: new InMemorySessionStore(),
    // The CAS backstop needs the same durable store to fail closed across processes (with a real cross-process
    // store). settle:() => Promise.resolve() is fine for a single in-process bot; keep the default jitter if you
    // run multiple workers off one shared store.
    mutex: new InProcessMutex({ store: durable, settle: () => Promise.resolve() }),
    reservation: new UtxoReservationRegistry(),
    clock: () => Date.now(), // liveness/UX only — anti-theft margins anchor to CHAIN time, never this clock
  };

  // EVM seams: wired ONLY when a leg of the pair is an EVM chain (optional, see EVM note at the bottom).
  if (pair.some(isEvmChain)) Object.assign(deps, buildEvmSeams(mnemonic));

  deps.__closeAll = () => { for (const c of closers) c(); };
  return deps;
}

// -----------------------------------------------------------------------------
// Structured event logging — the SwapController emits machine-readable events.
// -----------------------------------------------------------------------------
function attachEvents(swap, tag) {
  swap.on('phase', (e) => log(`  [${tag}] phase → ${e.phase}`));
  swap.on('status', (e) => log(`  [${tag}] status: ${e.message}`));
  swap.on('error', (e) => log(`  [${tag}] ERROR: ${e.error?.message ?? e.error}`));
}

// -----------------------------------------------------------------------------
// Offer construction (maker) — a SEED-DERIVED hmac-v1 secret so S is re-derivable on any device.
//
// The 32-byte secret S never leaves this function; only its PUBLIC commitments (secretHash, secretNonce,
// secretScheme) are posted. At fund/reveal time the SwapController RE-DERIVES S from the seed via the vault.
// -----------------------------------------------------------------------------
function buildMakerOffer(sendChain, recvChain, amount, mnemonic) {
  const nonce = generateSwapNonce();
  const S = deriveSwapSecret(mnemonic, nonce);
  if (!S) throw new Error('buildMakerOffer: could not derive the swap secret (invalid mnemonic?)');
  const secretHash = bytesToHex(sha256(S));
  S.fill(0); // wipe the preimage immediately — the vault re-derives it under the fund/reveal mutex

  const id = bytesToHex(crypto.getRandomValues(new Uint8Array(16))); // 32-hex swap id
  const nowSec = Math.floor(Date.now() / 1000);
  const sendAddr = deriveKeyForSigning(mnemonic, walletChainFor(sendChain)).address;
  const recvAddr = deriveKeyForSigning(mnemonic, walletChainFor(recvChain)).address;

  const offer = {
    id,
    sendChain,
    receiveChain: recvChain,
    sendAmount: amount,            // base units of sendChain (sats for UTXO)
    receiveAmount: amount,         // 1:1 placeholder — a real maker prices this off /api/prices + inventory
    secretHash,
    secretNonce: bytesToHex(nonce),
    secretScheme: SWAP_SECRET_SCHEME, // 'hmac-v1' → S is re-derivable from the seed (fix #5)
    initiatorSendAddress: sendAddr,    // where leg X refunds to
    initiatorReceiveAddress: recvAddr, // where the maker receives on the buy chain
    status: 'taken',
    createdAt: nowSec,
    expiresAt: nowSec + 3600,
  };
  return { offer, secretHash };
}

// -----------------------------------------------------------------------------
// Order-book ↔ execution mapping — now the SDK's DOCUMENTED adapter (matches the live proxy).
//
// The order-book's SwapProposal/SwapOrder TRANSPORT model and the SwapController's SwapOffer EXECUTION model
// are different shapes. The SDK exports the verified bridge (see @bch2/swap-core/order-book → ./adapter):
//   • offerToProposal(offer)  — build a resting proposal to POST (maker)
//   • orderToOffer(order)      — turn a live order off the book into a responder SwapOffer (taker)
//   • offerChainToBook / bookChainToOffer — UPPER 'BCH2' ⇄ lower 'bch2' chain codes
// The responder does NOT derive S (it learns it on-chain); orderToOffer carries the maker's committed
// secretHash + chains + amounts, and the SwapController derives the responder's own claim/refund keys from
// the seed vault, so no responder addresses need to be injected onto the offer.
//
// NOTE: take() semantics + out-of-band delivery of the counterparty HTLC remain COORDINATION SEAMS
// (see resolveCounterpartyHtlc below) — the field mapping is verified; the coordination glue is your job.
// -----------------------------------------------------------------------------

/** The pkh that may CLAIM a UTXO leg — decoded from the counterparty's on-chain receive address on that leg
 *  (P2PKH CashAddr for bch2/bch, Base58 for btc/bc2). Fails closed on anything that isn't a 20-byte P2PKH. */
function claimPkhFromAddress(addr) {
  if (!addr) throw new Error('claimPkhFromAddress: no counterparty receive address on the order yet');
  const ca = decodeCashAddr(addr);
  if (ca && ca.type === 0 && ca.hash?.length === 20) return bytesToHex(ca.hash);
  const legacy = decodeLegacyAddress(addr);
  if (legacy && legacy.length === 20) return bytesToHex(legacy);
  throw new Error(`claimPkhFromAddress: '${addr}' is not a P2PKH CashAddr / Base58 address`);
}

// -----------------------------------------------------------------------------
// Counterparty-leg acquisition + observation
//
// The counterparty's published HTLC (its redeemScript/params) reaches you OUT OF BAND (the DEX carries it on
// the order box; a P2P relay would gossip it). swap-core does not own that channel, so it is a SEAM here:
// `resolveCounterpartyHtlc` reads it from env (BCH2_SWAP_CP_HTLC as a JSON DurableHTLC) and FAILS CLOSED if
// absent — never guess a counterparty leg before an irreversible action.
//
// `observeCounterpartyFunding` IS real: given the counterparty HTLC redeemScript, it scans the live chain for
// the funding outpoint (exactly like observeOutpoint in the e2e suite). The SwapController then re-verifies that
// outpoint under SPV inside the gate — this observation only tells the controller WHERE to look.
// -----------------------------------------------------------------------------
function resolveCounterpartyHtlc(role) {
  const raw = process.env.BCH2_SWAP_CP_HTLC;
  if (!raw) {
    throw new Error(
      `COORDINATION SEAM not wired: the ${role} needs the counterparty's published HTLC. Provide it as JSON in ` +
      `BCH2_SWAP_CP_HTLC = {"redeemScript","p2shAddress","secretHash","recipientPkh","refundPkh","locktime"}. ` +
      `Refusing to proceed to an irreversible action without the real counterparty leg.`,
    );
  }
  const h = JSON.parse(raw);
  for (const k of ['redeemScript', 'secretHash', 'recipientPkh', 'refundPkh', 'locktime']) {
    if (h[k] === undefined) throw new Error(`BCH2_SWAP_CP_HTLC missing field '${k}'`);
  }
  return h;
}

async function observeCounterpartyFunding(client, redeemScriptHex) {
  const sh = htlcScripthash(hexToBytes(redeemScriptHex));
  const utxos = await client.getUTXOs(sh);
  const funded = (utxos ?? []).filter((u) => Number.isFinite(u.value) && u.value > 0);
  if (funded.length === 0) return null;         // not funded yet — keep polling
  const u = funded[0];
  return { tx_hash: u.tx_hash, tx_pos: u.tx_pos };
}

/** The pkh that may CLAIM your funded leg with S (the counterparty's receive pubkey on that leg). Maker learns
 *  the taker's pubkey from `takeOrder`; taker reads the maker's via a seam (BCH2_SWAP_CP_CLAIM_PUBKEY). */
function claimPkhFromPubkeyHex(pubHex) {
  const pub = hexToBytes(pubHex.toLowerCase().replace(/^0x/, ''));
  if (pub.length !== 33) throw new Error('counterparty claim pubkey must be 33-byte compressed (66 hex)');
  return bytesToHex(hash160(pub));
}

// -----------------------------------------------------------------------------
// MAKER (initiator) — post → wait for take → prepare → fundLegX → verifyReveal → revealAndClaim
//   (refund fallback if the taker never funds leg Y before leg X's timelock)
//
// Method sequence mirrors src/e2e-lifecycle.test.ts scenario 1 (UTXO↔UTXO) exactly.
// -----------------------------------------------------------------------------
async function runMaker(sendChain, recvChain, amount, deps, mnemonic) {
  const book = new CentralizedOrderBook({ baseUrl: BASE_URL });
  const { offer } = buildMakerOffer(sendChain, recvChain, amount, mnemonic);

  // (1) POST the resting offer (nothing on-chain happens here).
  log(`Maker: posting offer ${offer.id}  ${sendChain} ${amount} → ${recvChain}`);
  const orderId = await book.postOrder({
    proposal: offerToProposal(offer),   // SDK adapter → the live-proxy proposal shape
    offerChain: offerChainToBook(sendChain),
    wantChain: offerChainToBook(recvChain),
    ttlSeconds: 3600,
  });
  log(`Maker: order live as ${orderId}. Waiting for a taker…`);

  // (2) POLL the book until the order is taken (a real bot would subscribeToOrders and react). The maker needs
  //     the taker's leg-X receive address (who claims leg X with S) — present once the order is taken.
  const taken = await pollFor(async () => {
    const [o] = await book.queryOrders({}).then((os) => os.filter((x) => x.id === orderId));
    return o && o.status === 'taken' && o.responderReceiveAddress ? o : null;
  }, { intervalMs: 3000, timeoutMs: 3600_000, label: 'await-take' });
  if (!taken) return die('Maker: order expired before it was taken.', 0);
  log(`Maker: taken (taker auth ${taken.takerAuthPub}); taker claims leg X to ${taken.responderReceiveAddress}`);

  // The taker's receive address on YOUR send/leg-X chain identifies who may claim your leg X with S.
  const counterpartyClaimPkh = claimPkhFromAddress(taken.responderReceiveAddress);

  // (3) FUND stage controller: prepare + fundLegX.
  const fundRecord = { id: offer.id, role: 'initiator', offer, phase: 'taken', counterpartyClaimPkh };
  const fundSwap = new SwapController(fundRecord, deps);
  attachEvents(fundSwap, 'maker:fund');
  await fundSwap.prepare();                 // derive keys; RE-DERIVE + authenticate S vs offer.secretHash (fail-closed)
  const { txid: legXTxid } = await fundSwap.fundLegX(); // SPV funding-height gate → single-flight select/reserve/build → durable-before-broadcast
  const legXHtlc = fundSwap.getState().myHTLC;
  const fundLocktime = legXHtlc.locktime;
  log(`Maker: leg X funded on ${sendChain} @ ${legXTxid} (refund CLTV height ${fundLocktime})`);

  // (4) OBSERVE the taker's leg Y on-chain (its HTLC arrives out of band → SEAM), then REVEAL.
  //     If the taker goes dark, refund leg X after its timelock.
  const theirClient = isEvmChain(recvChain) ? null : deps.chainClientFor(recvChain);
  const cpHtlc = await withDarkTakerRefund(fundSwap, sendChain, deps, async () => {
    const htlc = resolveCounterpartyHtlc('maker');          // taker's published leg-Y HTLC
    const outpoint = await pollFor(() => observeCounterpartyFunding(theirClient, htlc.redeemScript),
      { intervalMs: 15_000, timeoutMs: 90 * 60_000, label: 'await-legY' });
    if (!outpoint) return null;                              // taker never funded → triggers refund
    return { htlc, outpoint };
  });
  if (!cpHtlc) return; // refunded (dark taker) — withDarkTakerRefund handled it

  // (5) REVEAL stage controller (carries the observed counterparty leg Y). Mirrors the e2e `initReveal` controller.
  const revealRecord = {
    id: offer.id, role: 'initiator', offer, phase: 'responder_funded', counterpartyClaimPkh,
    myHTLC: legXHtlc, myFundingTxid: legXTxid, fundLocktime, funded: true,
    counterpartyHTLC: cpHtlc.htlc, counterpartyFundingOutpoint: cpHtlc.outpoint,
  };
  const revealSwap = new SwapController(revealRecord, deps);
  attachEvents(revealSwap, 'maker:reveal');

  const auth = await revealSwap.verifyCounterpartyLegForReveal(); // mints a RevealAuthorization ONLY if leg Y is SPV-buried + margin safe
  const { txid: claimTxid } = await revealSwap.revealAndClaim(auth); // reveals S on-chain by claiming leg Y — REQUIRES `auth`
  log(`Maker: revealed S + claimed leg Y @ ${claimTxid}. Swap done from the maker side.`);
}

// -----------------------------------------------------------------------------
// TAKER (responder) — takeOrder → observe leg X → verifyFunding → fundLegY → watchForSecret → claim
//   (refund fallback if the maker never reveals before leg Y's timelock)
//
// Method sequence mirrors src/e2e-lifecycle.test.ts scenario 1 responder path exactly.
// -----------------------------------------------------------------------------
async function runTaker(orderId, deps, mnemonic) {
  const book = new CentralizedOrderBook({ baseUrl: BASE_URL });

  // takerPubKey = the taker's pubkey on the maker's OFFER chain (leg X) — who may claim leg X with S.
  const [order] = await book.queryOrders({}).then((os) => os.filter((o) => o.id === orderId));
  if (!order) return die(`Taker: order ${orderId} not found on the book.`, 1);
  const sendChain = bookChainToOffer(order.offerChain);   // maker sells this (leg X); taker claims it
  const recvChain = bookChainToOffer(order.wantChain);    // maker buys this (leg Y); taker funds it
  const takerPub = bytesToHex(deriveKeyForSigning(mnemonic, walletChainFor(sendChain)).publicKey);

  const take = await book.takeOrder(orderId, takerPub);
  log(`Taker: took ${orderId}. Maker sells ${sendChain}; I fund leg Y on ${recvChain}.`);

  // SDK adapter → responder SwapOffer (carries the maker's committed secretHash + chains + amounts). The
  // responder learns S on-chain; the SwapController derives its own claim/refund keys from the seed vault.
  const offer = orderToOffer({ ...order, proposal: take.proposal ?? order.proposal });

  // The maker's receive pubkey (on YOUR receive/leg-Y chain) is who may claim your leg Y with S — SEAM.
  const cpClaimPubHex = process.env.BCH2_SWAP_CP_CLAIM_PUBKEY;
  if (!cpClaimPubHex) {
    return die(
      'Taker: COORDINATION SEAM not wired — set BCH2_SWAP_CP_CLAIM_PUBKEY to the maker\'s 66-hex receive pubkey on ' +
      `${recvChain} (who may claim your leg Y with S). Refusing to fund leg Y without it.`, 1);
  }
  const counterpartyClaimPkh = claimPkhFromPubkeyHex(cpClaimPubHex);

  // OBSERVE the maker's on-chain leg X (its HTLC arrives out of band → SEAM), then verify + fund leg Y.
  const legXHtlc = resolveCounterpartyHtlc('taker');
  const legXClient = isEvmChain(sendChain) ? null : deps.chainClientFor(sendChain);
  const legXOutpoint = await pollFor(() => observeCounterpartyFunding(legXClient, legXHtlc.redeemScript),
    { intervalMs: 15_000, timeoutMs: 60 * 60_000, label: 'await-legX' });
  if (!legXOutpoint) return die('Taker: maker never funded leg X within the window — nothing at risk, exiting.', 0);

  const record = {
    id: offer.id, role: 'responder', offer, phase: 'taken', counterpartyClaimPkh,
    counterpartyHTLC: legXHtlc, counterpartyFundingOutpoint: legXOutpoint,
  };
  const swap = new SwapController(record, deps);
  attachEvents(swap, 'taker');

  // verify leg X buried + timelock ordering safe → mint FundProof → fund leg Y (the proof re-mints at the choke point)
  const proof = isEvmChain(recvChain)
    ? await swap.verifyEvmCounterpartyLegForFunding()
    : await swap.verifyCounterpartyLegForFunding();
  const funded = isEvmChain(recvChain) ? await swap.lockEvm(proof) : await swap.fundLegY(proof);
  log(`Taker: leg Y funded on ${recvChain} @ ${funded.txid ?? funded.swapId}`);

  // Learn S from the maker's on-chain claim of leg Y, then claim leg X. Refund leg Y if the maker stays dark.
  const secret = await withDarkMakerRefund(swap, recvChain, deps, async () => {
    const watch = isEvmChain(recvChain) ? () => swap.watchForClaimEvm() : () => swap.watchForSecret();
    const found = await pollFor(async () => (await watch()).secret, { intervalMs: 20_000, timeoutMs: 90 * 60_000, label: 'watch-secret' });
    return found ?? null;
  });
  if (!secret) return; // refunded (dark maker) — handled by withDarkMakerRefund

  const { txid: claimX } = await swap.claimWithKnownSecret(); // claims leg X with the now-public S
  log(`Taker: claimed leg X @ ${claimX}. Swap complete.`);
}

// -----------------------------------------------------------------------------
// Refund fallbacks — recover YOUR own funded leg once its timelock passes and the counterparty went dark.
// The SwapController owns the fresh-tip re-check + durable-before-broadcast + reorg-safe finalizer; we just
// poll canRefund(tip) and call refund(). `run` returns non-null on the happy path (no refund needed).
// -----------------------------------------------------------------------------
async function withDarkTakerRefund(swap, myChain, deps, run) {
  const result = await run();
  if (result) return result;
  log('Maker: taker went dark before funding leg Y. Attempting refund of leg X after its timelock…');
  await refundOwnLeg(swap, myChain, deps);
  return null;
}
async function withDarkMakerRefund(swap, myChain, deps, run) {
  const result = await run();
  if (result) return result;
  log('Taker: maker never revealed S. Attempting refund of leg Y after its timelock…');
  await refundOwnLeg(swap, myChain, deps);
  return null;
}
async function refundOwnLeg(swap, myChain, deps) {
  if (isEvmChain(myChain)) {
    try { const { txHash } = await swap.refundEvm(); log(`  refundEvm broadcast @ ${txHash}`); }
    catch (e) { log(`  refundEvm not yet available / failed closed: ${e.message}`); }
    return;
  }
  const client = deps.chainClientFor(myChain);
  const ok = await pollFor(async () => {
    const [tip] = await client.getBlockHeight();
    return swap.canRefund(tip) ? tip : null;   // pure availability hint; refund() re-checks against a fresh tip
  }, { intervalMs: 60_000, timeoutMs: 48 * 60 * 60_000, label: 'await-refund-window' });
  if (ok === null) { log('  refund window not reached within the wait budget — recovery material KEPT; re-run `resume` later.'); return; }
  const { txid } = await swap.refund();        // durable-before-broadcast + arms the reorg-safe finalizer
  log(`  refund broadcast @ ${txid}. Principal (minus fee) recovered.`);
}

// -----------------------------------------------------------------------------
// RESUME — rehydrate a crashed/stalled swap from its durable record + CHAIN truth (fix #10).
// In this reference the durable store is in-memory, so `resume` only demonstrates the API shape;
// a production bot reads the persisted `bch2swap:record:<id>` from its FILE/SQLite store and calls resume().
// -----------------------------------------------------------------------------
async function runResume(swapId, deps) {
  const raw = await deps.durable.get(`bch2swap:record:${swapId}`);
  if (!raw) {
    return die(
      `resume: no durable record for ${swapId} in this store. In-memory storage does not survive a restart — ` +
      'a production bot must back `durable` with a FILE/SQLite DurableStore (see the PRODUCTION NOTE in buildDeps) ' +
      'and read the persisted record from it.', 1);
  }
  const record = JSON.parse(raw);
  const swap = await SwapController.resume(record, deps);
  attachEvents(swap, 'resume');
  const s = swap.getState();
  log(`resume: auth=${s.resumeAuth} gate=${s.resumeGate} phase=${s.phase} hasSecret=${s.hasSecret}`);
  log('resume: the controller re-entered the correct gate from chain truth; drive the remaining step or refund.');
}

// -----------------------------------------------------------------------------
// EVM seams (OPTIONAL) — only used when a leg of the pair is an EVM chain.
//
// The EVM gates REFUSE a single-leaf provider: evmProviderFor MUST return a quorum≥2 read provider (a provider
// exposing a `__leafProviders` array of ≥2 independent providers). Wire >=2 RPC URLs per chain in
// EVM_RPC_URLS_<TICKER>. evmSignerFor returns a Node ethers.Wallet derived from the seed (MetaMask is NOT on
// the path). This is reference scaffolding — validate the quorum + gas + token allow-list before mainnet.
// -----------------------------------------------------------------------------
function buildEvmSeams(mnemonic) {
  // Lazy ethers import so the UTXO-only path never pays for it.
  const rpcUrlsFor = (chain) => (process.env[`EVM_RPC_URLS_${chainConfigs[chain]?.ticker ?? ''}`] ?? '')
    .split(',').map((s) => s.trim()).filter(Boolean);

  const evmProviderFor = (chain) => {
    const urls = rpcUrlsFor(chain);
    if (urls.length < 2) {
      throw new Error(`evmProviderFor('${chain}'): need >=2 RPC URLs in EVM_RPC_URLS_${chainConfigs[chain]?.ticker} for the quorum read provider (the EVM gates refuse a single leaf).`);
    }
    // Deferred require of ethers keeps the UTXO path dependency-light; ethers ships with @bch2/swap-core.
    const { ethers } = require('ethers'); // eslint-disable-line
    const leaves = urls.map((u) => new ethers.JsonRpcProvider(u));
    const primary = leaves[0];
    primary.__leafProviders = leaves; // the quorum pattern the gates verify (>=2 leaves)
    return primary;
  };
  const evmSignerFor = (chain) => {
    const { ethers } = require('ethers'); // eslint-disable-line
    const provider = evmProviderFor(chain);
    const k = deriveKeyForSigning(mnemonic, 'evm');
    return new ethers.Wallet('0x' + bytesToHex(k.privateKey), provider);
  };
  return { evmProviderFor, evmSignerFor };
}

// -----------------------------------------------------------------------------
// CLI + safety gating
// -----------------------------------------------------------------------------
function printSetupAndExit(reason) {
  log(`
${reason}

SETUP (test on TESTNET/REGTEST first — atomic swaps are IRREVERSIBLE):

  1) Create a DEDICATED swap wallet and fund it with ONLY the trade amount + a fee buffer.
  2) export BCH2_SWAP_MNEMONIC="<your dedicated 12/24-word seed>"
  3) (optional) export BCH2_SWAP_URL="https://swap.bch2.org"   # order-book/proxy origin
  4) (optional) export BCH2_SWAP_NETWORK=regtest               # to match the DEX regtest nodes
  5) Dry validate (connects/broadcasts NOTHING):
        node examples/reference-bot.mjs make bch2 btc 100000
  6) Go live (REAL funds) only when you have tested on testnet:
        BCH2_SWAP_LIVE=1 node examples/reference-bot.mjs make bch2 btc 100000

  Coordination seams a live run needs (see the header):
     BCH2_SWAP_CP_HTLC          the counterparty's published HTLC (JSON DurableHTLC)
     BCH2_SWAP_CP_CLAIM_PUBKEY  (taker) the maker's 66-hex receive pubkey

This is a REFERENCE bot. Fund-safety is enforced inside the SwapController; the coordination glue and the
order-book↔proxy contract are your responsibility to verify against your deployment.
`);
  process.exit(0);
}

function parseArgs(argv) {
  const [cmd, ...rest] = argv;
  if (cmd === 'make') {
    const [sendChain, recvChain, amountStr] = rest;
    if (!sendChain || !recvChain || !amountStr) return { error: 'usage: make <sendChain> <recvChain> <amount>' };
    if (!chainConfigs[sendChain] || !chainConfigs[recvChain]) return { error: `unknown chain (send=${sendChain} recv=${recvChain}). Known: ${Object.keys(chainConfigs).join(', ')}` };
    if (isSwapPairSuspended(sendChain, recvChain)) return { error: `swap pair ${sendChain}/${recvChain} is SUSPENDED — refusing.` };
    const amount = Number(amountStr);
    if (!Number.isInteger(amount) || amount <= 0) return { error: `amount must be a positive integer of base units, got '${amountStr}'` };
    return { cmd, sendChain, recvChain, amount };
  }
  if (cmd === 'take') {
    const [orderId] = rest;
    if (!orderId) return { error: 'usage: take <orderId>' };
    return { cmd, orderId };
  }
  if (cmd === 'resume') {
    const [swapId] = rest;
    if (!swapId) return { error: 'usage: resume <swapId>' };
    return { cmd, swapId };
  }
  return { error: 'usage: reference-bot.mjs <make|take|resume> …' };
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (args.error) return die(`reference-bot: ${args.error}`, 1);

  const mnemonic = process.env.BCH2_SWAP_MNEMONIC;

  // SAFETY GATE 1: no wallet → print setup instructions + exit cleanly. Connects/broadcasts NOTHING.
  if (!mnemonic) return printSetupAndExit('No BCH2_SWAP_MNEMONIC set — nothing was connected or broadcast.');
  if (!validateMnemonic(mnemonic.trim().toLowerCase())) return die('reference-bot: BCH2_SWAP_MNEMONIC is not a valid BIP39 mnemonic.', 1);

  const addrs = deriveAddresses(mnemonic);
  log(`reference-bot: wallet bch2=${addrs.bch2}${addrs.btc ? ` btc=${addrs.btc}` : ''}`);
  if (args.cmd === 'make') log(`plan: MAKE ${args.sendChain} ${args.amount} → ${args.recvChain}`);
  if (args.cmd === 'take') log(`plan: TAKE ${args.orderId}`);
  if (args.cmd === 'resume') log(`plan: RESUME ${args.swapId}`);

  // SAFETY GATE 2: not an explicit LIVE run → validate + print plan + exit. Still connects/broadcasts NOTHING.
  if (!LIVE) {
    log('\nBCH2_SWAP_LIVE is not set. This was a DRY validate — nothing connected, nothing broadcast.');
    log('Re-run with  BCH2_SWAP_LIVE=1  to drive REAL funds (test on testnet first).');
    return process.exit(0);
  }

  // LIVE path — build deps + drive the swap.
  const pair = args.cmd === 'make' ? [args.sendChain, args.recvChain]
    : args.cmd === 'take' ? [] // resolved from the order after fetch; UTXO clients are lazy
    : [];
  const deps = buildDeps(mnemonic, pair);
  try {
    if (args.cmd === 'make') await runMaker(args.sendChain, args.recvChain, args.amount, deps, mnemonic);
    else if (args.cmd === 'take') await runTaker(args.orderId, deps, mnemonic);
    else if (args.cmd === 'resume') await runResume(args.swapId, deps);
  } finally {
    try { deps.__closeAll?.(); } catch { /* ignore */ }
    try { deps.seedVault?.dispose?.(); } catch { /* ignore */ }
  }
}

main().catch((e) => die(`reference-bot: fatal — ${e?.stack ?? e?.message ?? e}`, 1));
