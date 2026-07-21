# Changelog

## 3.1.4

### Fixed (fund-safety — HIGH, found by the no-stone-unturned gates review)
- **R-CLTV-DISCRIMINATOR** (`gates.ts` assertRevealSafe): the reveal-margin height-vs-timestamp CLTV split used
  `1_500_000_000`, but BIP65 OP_CHECKLOCKTIMEVERIFY (and this codebase's own `isHtlcRefundAvailable` /
  `isValidLocktime`) treat ANY locktime `>= 500_000_000` as a unix TIMESTAMP. A malicious responder could fund the
  counterparty leg with a CLTV in the gap `[5e8, 1.5e9)` — a past timestamp on-chain (already refundable) — which
  the gate mis-routed to the HEIGHT branch, computing a huge block "remaining" that passed the 4h margin. The
  initiator would then reveal the secret against an already-refundable leg → the responder refunds AND claims with
  the leaked secret → initiator loses BOTH legs. The fund gate's `maxLock` upper bound already rejected this; the
  reveal gate had only the lower-bound margin. Fixed: split at `500_000_000` to match BIP65 + the rest of the
  codebase, so a gap CLTV routes to the timestamp branch and fails closed. Regression test added.

## 3.1.3

### Fixed (fund-safety — two HIGH, found by a no-stone-unturned audit)
- **R-TRYSETTLE-RECV-001** (`swap-controller.ts` trySettleIfBothLegsSpent): the wipe of the RECEIVE-leg claim
  material (secret + claimTx) proved reorg-safety only for OUR FUNDED leg, gating the receive leg on a bare 1-conf
  `getUTXOs` emptiness read. A resume in the mined-but-not-reorg-safe window + a shallow reorg on the receive leg
  then stranded our re-claim (lost the leg we were owed). Now ALSO requires OUR claim of the receive leg to be
  buried at reorg-safe SPV depth before wiping (new `claimBuriedReorgSafe`, mirrors confirmClaim); fail closed.
- **R-EVMLOCKBLOCK-001** (`swap-controller.ts` lockEvm): `rec.evmLockBlock` was declared + read but NEVER written,
  so the counterparty-secret scan (`readEvmClaimedSecret`) fell back to a tip-anchored `[tip-90000, tip]` window —
  only ~6-7h on a sub-second chain (Arbitrum), well under the 36h claim horizon. A responder with a monitoring gap
  could slide past an early `Claimed` event and never recover the public secret → lose the initiator leg. lockEvm
  now captures the lock block (`getBlock('latest').number`) so the scan anchors on a lossless floor. `evmLockBlock`
  is also exposed on the state snapshot. Regression tests added for both.

## 3.1.2

### Fixed (fund-safety — reveal margin)
- **R-CHAINTIME-DEFLATE-001**: the initiator's TIMESTAMP-CLTV reveal margin anchored to an UNVERIFIED proxy tip
  header time (`getChainTimeSec`, range-checked only), while the height-CLTV branch already SPV-verifies + staleness-
  guards its tip. A proxy that deflated the tip `nTime` could overstate the responder's remaining refund runway and
  let the initiator reveal the secret inside the real danger window — losing BOTH legs. The timestamp branch now
  anchors to the SPV/PoW-verified tip's `nTime` (new `spvVerifiedTipTimeSec`, same under-report/staleness guard as
  the height branch) for SPV-supported counterparty chains, and fails closed (rearm) if it can't be verified.
  Regression test added (a 3h-stale tip that would have passed now throws). Found by a post-deploy adversarial audit.

## 3.1.1

### Fixed (order-book client ↔ live proxy)
- The `CentralizedOrderBook` client's **types now match the live proxy** (`GET /api/orders` →
  `{ success, data: SwapOrder[] }`). The stale `SwapProposal` (`swapID`/`initiatorPubKey`/`initiatorAmountSat`/…,
  a shape the proxy never returned) is replaced by the REAL proposal shape — `offerChain`/`wantChain` chain codes,
  base-unit (sats/wei) `sendAmount`/`receiveAmount`, `secretHash`/`secretNonce`/`secretScheme`, `makerIdPub`/`makerSig`/
  `authPub`, the initiator addresses, `evmInfo`/`evmAddress`, and `hashLock`. `SwapOrder` now carries the real
  top-level lifecycle + responder-coordination fields (`takenAt`, `responderLocktime`, `evmSwapId`,
  `initiatorTxid`/`responderTxid`, `responderSendAddress`/`responderReceiveAddress`, `takerAuthPub`). Runtime
  behavior is unchanged (the client always parsed dynamically); the TYPES no longer mislead a TS integrator.
- **New documented `SwapOffer` adapter** (`@bch2/swap-core/order-book` → `./adapter`): `offerToProposal(offer)`,
  `proposalToOffer(proposal)` / `orderToOffer(order)`, and the `offerChainToBook` / `bookChainToOffer` chain-code
  mappers (UPPER `'BCH2'` ⇄ lower `'bch2'`). This makes the transport ⇄ execution mapping explicit and tested
  (round-trip), replacing the reference bot's ad-hoc, not-proxy-verified bridge. The reference bot
  (`examples/reference-bot.mjs`) now uses the exported adapter to map a live order to a `SwapOffer`.
- **Amount-unit docs corrected**: `SwapProposal.sendAmount`/`receiveAmount` are documented as the chain's
  BASE UNIT (sats for a UTXO chain, wei/token base units for EVM) as decimal strings — NOT human units. The
  live proxy returns e.g. a BCH2 `"1290788219"` (= 12.90788219 BCH2), and `SwapController` consumes base
  units directly; the prior "human unit (e.g. 1.5)" comment would have mis-sized an integrator's amount.

### Added
- **`examples/TESTNET-SWAP.md`** — the operator runbook for driving a REAL on-chain swap through the reference
  bot + `SwapController` (testnet/small-value first): dry-validate → two parties → verify on a block explorer →
  refund path → resume-after-crash → the production durable-store/mutex hardening + a pre-mainnet checklist.


## 3.1.0

### Added (integration surface, P2)
- **`examples/electrum-node-client.mjs`** — a Node.js ElectrumX transport (TLS) that satisfies `SwapChainClient`;
  the untrusted chain transport a Node bot injects via `chainClientFor`.
- **`scripts/verify-live-spv.mjs`** (`npm run verify:live`) — runs the SDK's SPV verifier against **live BCH2
  mainnet** (real ASERT header chain from the checkpoint + a real Merkle proof; fails closed on a fabricated
  txid). Read-only. Closes the read-side real-data validation gap the unit tests (synthetic PoW) leave open.
- **`examples/reference-bot.mjs`** — a runnable maker/taker reference bot driving the `SwapController` over the
  live transport + order book, with refund/resume fallbacks. Double-gated (`BCH2_SWAP_MNEMONIC` + `BCH2_SWAP_LIVE=1`)
  so it connects/broadcasts nothing until an operator explicitly opts in; test on testnet first.
- **`examples/WALLET-INTEGRATION.md`** — the signing-boundary guide: the wallet keeps the seed, injects a narrow
  `SeedVault` capability (optionally per-signature approval), and must not undermine the §9 fund-safety invariants.


## 3.0.1

### Fixed (fund-safety audit)
A full test-completeness audit of the v3 SwapController surface found and closed 8 confirmed fund-safety
bugs (the SwapController was new in v3.0.0 with no adopters):
- **trySettleIfBothLegsSpent** no longer wipes non-recoverable recovery material on a bare 0-conf read — it
  now requires an SPV-verified reorg-safe depth on our own leg's spend, and respects the resume auth block.
- **fundLegX** now enforces the re-derivable-secret gate (previously only `prepare()` did), so a swap whose
  secret a crash would strand cannot be funded.
- The UTXO claim path no longer poisons its durable sentinel on a rejected broadcast (definitive-vs-ambiguous
  classifier that errs safe); **lockEvm** adopts a prior lock instead of double-locking; **refundEvm** no
  longer wedges on a transient pre-broadcast RPC timeout; **InProcessMutex** renews its lock (no steal);
  **BrowserMutex** fails closed; **LocalStorageDurableStore** surfaces an inconsistent-state error.

### Hardened
- The timelock margin now cross-checks the caller-supplied locktime against the CLTV parsed from the
  authenticated redeem script (a malformed record can't feed a wrong anti-theft margin).
- Resume now resubmits a dropped refund (§9.7 refund-reachability is no longer one-shot).

### Tests
- 582 tests (up from 424): the full legacy-chain funding path, the EVM lock/claim/refund/pivot branches, the
  finalizer + resume branches, the gate fail-closed matrix, and a new chain-config param-pinning suite.


## 3.0.0

### Breaking
- **Removed the stale `swap-engine` `Engine`** and its `./swap-engine` subpath export. It was a
  Go-port reference state machine the live DEX never actually ran, and it lacked the app's fund-safety
  fixes — keeping it published invited bot authors to build on an unvalidated path. Any
  `@bch2/swap-core/swap-engine` import must move to the `SwapController` (see below).

### Added
- **The `SwapController` — the SDK's validated swap driver** (exported at the package root and at
  `./swap-controller`). Extracted from the DEX's proven React orchestration, it encapsulates the full
  fund-safety protocol — SPV depth gates, cross-domain (wall-clock) timelock ordering, the secret
  lifecycle, reorg recovery, and deadline-aware fees — across **both UTXO and EVM legs**. Irreversible
  actions are gated behind branded proofs (`FundProof` for `fundLegY`, `RevealAuthorization` for
  `revealAndClaim`) that only a verified-depth check can mint, so a caller **structurally cannot** fund
  the second leg or reveal the secret unsafely. Covered by **424 tests**, including a **two-party,
  full-lifecycle end-to-end suite** (`src/e2e-lifecycle.test.ts`: UTXO↔UTXO, UTXO↔EVM, refund, resume,
  with real SPV over a synthetic PoW chain); each fund-critical step is adversarially verified.
- **New subpath exports:** `./swap-controller`, `./gates`, `./storage`, `./utxo-reservation`,
  `./spv-verifier`, `./chain-client`, `./timelock-gates`, `./fee-rate`, `./swap-flow`, `./seed-secret`
  (plus the existing `./spv`, `./chain-config`, `./htlc-builder`, `./order-book`, `./wallet-core`,
  `./address-codec`, `./key-encryption`, `./evm`, `./evm-config`).

### Changed
- The order-book `SwapProposal` type was relocated in-package (it previously lived in the removed
  swap-engine); it is now defined in `./order-book`. **No API change** to the order-book client.

### Status (honest scope)
- The `SwapController` is **new in this release**. It has **not yet run in the production web app** nor
  been exercised **end-to-end against mainnet** — real-app integration and a mainnet e2e are the remaining
  validation. It is extensively tested (unit + full-lifecycle e2e); until the mainnet e2e lands, treat
  `PROTOCOL.md` §9 as the authoritative fund-safety contract and test on testnet before risking mainnet funds.

## 2.0.0

### Breaking (semver only — no migration needed)
- **BCH2 derivation path** corrected from coin type `145` (BCH's) to `20145`
  (`m/44'/20145'/0'/0/0`), matching the BCH2 Swap DEX, so SDK-derived BCH2 addresses
  now match the DEX and BCH2/BCH keys no longer collide. Flagged as a major bump for
  semver correctness; v1.0.0 had no adopters, so there are no old `145`-derived
  addresses in the wild and nothing to migrate. (BCH stays on 145.)

### Fixed
- `buildFundingTx` now enforces a **claimability floor** and validates amounts: it
  rejects an HTLC funded below `fee + dust` (1046 sat). Such an HTLC would confirm
  on-chain but be spendable by **neither** the claim nor the refund branch, stranding
  the funds. Amounts must now be positive integers.

## 1.0.0
- Initial release: atomic-swap SDK for BCH2 Swap DEX bots — HTLC builder, EVM/UTXO
  wallet, order-book client, a reference swap-state engine, REST/WS API.
