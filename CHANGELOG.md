# Changelog

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
  wallet, order-book + swap-engine clients, REST/WS API.
