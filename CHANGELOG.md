# Changelog

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
