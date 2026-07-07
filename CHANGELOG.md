# Changelog

## 2.0.0

### Breaking
- **BCH2 derivation path** changed from coin type `145` to `20145`
  (`m/44'/20145'/0'/0/0`), matching the BCH2 Swap DEX. Addresses derived under the
  old `145` path (BCH's coin type) will differ. This aligns SDK-derived BCH2
  addresses with the DEX and stops BCH2/BCH key reuse. **If you hold funds under an
  old `145`-derived BCH2 address, sweep them before upgrading.** (BCH stays on 145.)

### Fixed
- `buildFundingTx` now enforces a **claimability floor** and validates amounts: it
  rejects an HTLC funded below `fee + dust` (1046 sat). Such an HTLC would confirm
  on-chain but be spendable by **neither** the claim nor the refund branch, stranding
  the funds. Amounts must now be positive integers.

## 1.0.0
- Initial release: atomic-swap SDK for BCH2 Swap DEX bots — HTLC builder, EVM/UTXO
  wallet, order-book + swap-engine clients, REST/WS API.
