// @bch2/swap-core — the SDK for building safe atomic-swap clients (bots / wallets / pools).
//
// The `SwapController` is the validated swap driver: it encapsulates the full fund-safety protocol
// (SPV depth gates, cross-domain timelock ordering, secret lifecycle, reorg recovery, deadline-aware fees)
// so an integrator STRUCTURALLY cannot run a swap unsafely. See PROTOCOL.md for the fund-safety contract
// and its §9 invariants. Lower-level primitives are available via subpaths (e.g. @bch2/swap-core/htlc-builder,
// /spv, /gates, /swap-flow, /chain-config) for advanced use.

// ── The swap driver + its host contract ──────────────────────────────────────────────────────────────────
export { SwapController, MnemonicSeedVault } from './swap-controller';
export type {
  SwapControllerDeps, SeedVault, SigningKeyPair, DurableSwapRecord, DurableHTLC, Outpoint,
  SwapPhase, RecordPhase, SwapControllerEvent, SwapEventType, SwapSnapshot, Scheduler, SwapChainClient,
} from './swap-controller';

// ── Safe-by-default gate results (the branded proofs a caller passes into fundLegY / revealAndClaim) ──────
export { GateFailure } from './gates';
export type { FundProof, RevealAuthorization, GateDisposition } from './gates';

// ── Injected storage + single-flight seams (with in-process defaults + browser adapters) ─────────────────
export {
  InMemoryDurableStore, LocalStorageDurableStore, InMemorySessionStore, WindowSessionStore,
  InProcessMutex, BrowserMutex, MutexBusyError,
} from './storage';
export type { DurableStore, SessionStore, Mutex, StorageLike, WebLocksLike } from './storage';

// ── UTXO reservation (instance-scoped) ───────────────────────────────────────────────────────────────────
export { UtxoReservationRegistry } from './utxo-reservation';

// ── Order book (discovery: list / post / take / cancel resting offers) ───────────────────────────────────
export * from './order-book/index';

// ── Address codec (CashAddr / Base58 / Bech32 / WIF) + mnemonic key-encryption ───────────────────────────
export * from './address-codec';
export * from './key-encryption';
