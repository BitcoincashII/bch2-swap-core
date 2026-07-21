# Changelog

## 3.1.15

### Fixed (fund-safety — HIGH, audit round 10 — fix #5 parity)
- **R-EVMLOCK-SECRETGATE-001** (HIGH): `lockEvm` omitted the fix #5 secret-re-derivability gate that `fundOwnLeg`
  (leg X, UTXO) and `prepare()` enforce. For an initiator, `lockEvm` locks `offer.sendAmount` and targets
  `initiator_funded`, yet did not require the swap secret to be re-derivable — so an initiator EVM own-leg lock on a
  non-hmac-v1 offer with no encrypted-at-rest durable S would lock funds it can never claim from (`loadInitiatorSecret`
  returns null at `revealAndClaimEvm` → stranded until the timelocked `refundEvm`). Fix: replicate `fundOwnLeg`'s gate
  in `lockEvm`, keyed on `this.role === 'initiator'` (the responder learns S on-chain and stays exempt) — refuse unless
  `offer.secretScheme === SWAP_SECRET_SCHEME` OR a durable S is present, before any on-chain action. Regression tests
  added (initiator throws + broadcasts nothing; responder is not blocked). Reachability note: `lockEvm` requires a
  `FundProof` whose only minters are responder-only, so an initiator reaches this path only via an intended EVM-initiator
  flow or a directly-minted proof (bot-author surface) — this restores parity with the reachable `fundOwnLeg` gate and
  closes the strand at the SDK boundary regardless.

## 3.1.14

### Fixed (fund-safety — HIGH, audit round 9 — EVM resume/recovery parity)
- **R-EVMLOCK-RESUME-001** (HIGH): resume had no reconstruction for a CRASHED EVM own-leg lock. `lockEvm` commits
  `lockpending`+`evmlocktx` the instant the lock broadcasts, but `funded`+`record.myEvmSwapId` are set only after
  `tx.wait` resolves — a crash in that (up to 120s) window left the leg LOCKED on-chain with the record unable to
  refund or watch it (`refundEvm`/`watchForClaimEvm` both require `myEvmSwapId`), and every resume path bailed
  (`rebroadcastFundingIfMissing`/`rebroadcastRefundIfDropped` are UTXO-only; the refund/claim sentinels were unset).
  The UTXO fund path self-heals via `reconstructMyHtlc` (it commits `fundedHtlcKey` BEFORE the broadcast); the EVM leg
  had no equivalent. Fix: new `recoverEvmLockOnResume()` adopts the on-chain lock via `recoverLockFromTx` (reusing
  `lockEvm`'s quorum-corroborated logic) and reconstructs `myEvmSwapId`/`funded` — no host re-lock, no counterparty
  re-verification; fail-closed on `blocked`/`safe`/read error. Wired into resume. Regression test added.
- **R-EVMCLAIM-RESUME-S-001** (HIGH — completeness gap in the round-6 `confirmClaimEvm` add): the orphaned-claim
  re-drive (`reBroadcastOrphanedEvmClaim`) sourced S for a responder from the in-memory `this.secret`, which is null on
  a fresh-process resume (S is never persisted). So an EVM↔EVM responder whose leg-X claim was reorg-orphaned could not
  re-drive it after a restart. But S is PUBLIC in the responder's OWN leg Y (`myEvmSwapId`) on-chain Claimed event (the
  initiator claimed leg Y). Fix: when `this.secret` is null on the responder path, re-extract S via
  `readEvmClaimedSecret` over the leg-Y (myChain) provider (mirrors `recoverEvmRefundRaceOnResume`/`watchForClaimEvm`)
  before re-broadcasting. Regression test added.

## 3.1.13

### Fixed (fund-safety — HIGH, audit round 8 — UTXO↔EVM recovery parity)
- **R-UTXO-CLAIM-REDRIVE-001** (HIGH): the UTXO receive-leg claim had no analogue of `confirmClaimEvm`'s orphan
  re-drive. A UTXO claim broadcast then PERMANENTLY dropped (mempool eviction under fee pressure / a restrictive-policy
  reorg that doesn't re-admit it) was never re-sent — `confirmClaim` found the txid absent and returned not-finalized
  without re-broadcasting, and `priorClaimTxid` adopted the never-confirmed txid on the local sentinel alone. The claim
  never landed and, after leg X's longer refund timelock, the counterparty refunded it (receive-leg-value loss, S
  already public). Fix: new `rebroadcastClaimIfDropped()` — on resume, when OUR claim txid is absent from leg X's
  history AND leg X is still unspent (proving the claim dropped, not landed), re-broadcast the durable claim rawTx
  idempotently; fail-closed (no re-send on a read error, if the claim is present, or if leg X is already spent). Wired
  into resume's UTXO claim branch. Regression test added.
- **R-EVM-REFUND-RESUBMIT-001** (HIGH — liveness/recoverability): the EVM own-leg refund had no analogue of
  `rebroadcastRefundIfDropped`. A `refundEvm` that committed the `refundbroadcast` sentinel then dropped its refund tx
  (mempool eviction / crash during `tx.wait`) with the counterparty NEVER claiming was permanently stuck — every resume
  path bails for an EVM own leg (`confirmRefund`, `recoverUtxoRefundRace`, `rebroadcastRefundIfDropped`),
  `recoverEvmRefundRaceOnResume` covers only the CLAIMED (race) case, and a manual `refundEvm` re-call adopted the
  sentinel and reported a false `refund-pending` — the own EVM funds stayed locked past expiry. Fix: new
  `finalizeOrResubmitEvmRefund()` — on resume, `getSwap.refunded` ⇒ finalize (`refunded`); `exists && !claimed &&
  !refunded` ⇒ re-invoke `refundSwap` (re-verifies expiry/initiator on-chain, idempotent) and finalize on a confirmed
  re-refund; fail-closed otherwise. Wired into resume's refund-first branch. Regression tests added.

## 3.1.12

### Fixed (fund-safety — CRITICAL, audit round 8)
- **R-CPRECIP-001** (CRITICAL — SDK-boundary): the UTXO counterparty-leg gates authenticated only that the funding
  output is locked to the RECORDED redeemScript — they never bound the script's CONTENTS to our identity. A malicious
  counterparty could fund a self-consistent HTLC naming THEIR OWN pkh as the recipient (or a different secretHash):
  depth / exact-outpoint / CLTV / value all pass, we fund/reveal our own full leg, they claim it with S, and OUR claim
  of that leg is script-invalid (needs their key / a different preimage) — deterministic whole-leg theft, no race or
  reorg. The EVM sibling already binds both (`isEvmLockAtSafeDepth`: `lock.recipient===inv.recipient` +
  `lock.hashLock===inv.hashLock`); only the UTXO gate was left trusting the recorded script's contents. (The live app
  is NOT affected — it reconstructs the counterparty HTLC with our own pkh + the offer secretHash and accepts funding
  only at that exact P2SH; this restores the same bind in the SDK, which reads the counterparty script verbatim.) Fix:
  `FundGateParams`/`RevealSafeParams` gain `expectedRecipientPkh` (hash160 of our claim key on that leg's chain — exactly
  what `buildSecretClaim` sweeps to) + `expectedSecretHash` (the offer secretHash); `reverifyBuriedOutpoint` parses the
  script's recipient pkh (bytes 39..59) + secretHash (bytes 3..35) and fails closed (`abort`) on any mismatch. Enforced
  in `verifyCounterpartyLegForFunding`, `verifyCounterpartyLegForReveal`, and the `revealAndClaim` broadcast-choke
  re-mint. Regression tests added (a substituted-recipient and a substituted-secretHash leg both ABORT).

## 3.1.11

### Fixed (fund-safety — HIGH, audit round 7)
- **R-EVM-REFUNDRACE-RESUME-001** (HIGH): the parity sibling of the v3.1.9 UTXO refund-race fix — the EVM-own-leg
  refund-race recovery was never wired into `resume()`. `recoverFromRefundRace` was only reachable from inside
  `refundEvm`; `recoverUtxoRefundRace` (wired into resume) bails for an EVM own leg. So a RESPONDER whose own EVM leg Y
  was CLAIMED by the initiator (S now public) — after committing the `refundbroadcast` sentinel but crashing before
  `refundEvm`'s synchronous pivot cleared it — was permanently wedged on resume: `confirmRefund`,
  `recoverUtxoRefundRace`, and `rebroadcastRefundIfDropped` ALL bail for an EVM own leg, so resume short-circuited at
  `refund-in-flight` with the sentinel stuck, and `claimWithKnownSecret` was blocked by the refund cross-guard — the
  responder forfeited leg X (still claimable with the public S) while the initiator netted both legs. Its UTXO-own-leg
  twin recovers on resume and is tested; the EVM twin was neither. Fix: new `recoverEvmRefundRaceOnResume()` (reads
  `getSwap` for our own EVM swapId; if `claimed && !refunded`, drives `recoverFromRefundRace` — recovers S from the
  Claimed event, clears the sentinel, claims leg X), wired into `resume()`'s refund-first branch right after the UTXO
  pivot. Plus a defense-in-depth pre-mutex check in `refundEvm` so a MANUAL re-call also pivots (a set sentinel with
  the lock claimed-but-not-refunded routes to recovery instead of a false `refund-pending`). Fail-closed throughout.
  Regression test added (resume-driven end-to-end recovery for the EVM-own-leg / UTXO-counterparty topology).

## 3.1.10

### Fixed (fund-safety — HIGH, audit round 6)
- **R-EVMCLAIM-REORG-001** (HIGH): the EVM receive-leg claim finalized `phase='claimed'` at 1 confirmation, discarded
  the block number `claimSwap` returns for reorg-deferral, and its adopt-guards reported "adopted" success on the local
  `claimbroadcast` sentinel ALONE — with no `getSwap.claimed` corroboration. If a deep-reorg chain (e.g. Polygon,
  `requiredConfirmations=128`) orphaned the 1-conf claim, the lock reverted to funded (`claimed=false`) but the SDK
  never re-broadcast: any re-drive of `revealAndClaimEvm` / `claimEvmCounterpartyWithPublicSecret` falsely adopted, and
  `resume()` only reported `claim-in-flight` because `confirmClaim` + `trySettleIfBothLegsSpent` both bail for EVM. The
  counterparty (holding the now-public S) would take the other leg — initiator loses both. Its sibling `refundEvm`
  already finalizes only on the on-chain `getSwap.refunded` anchor; the claim path had no equivalent. Fix:
  - New `evmSwapIsClaimed` (the claim-side analogue of `evmSwapIsRefunded`, reading `getSwap.claimed`, fail-closed).
  - The adopt-guards in `revealAndClaimEvm` + `claimEvmCounterpartyWithPublicSecret` now adopt ONLY when
    `getSwap.claimed` is true; otherwise they clear the sentinel and re-drive the claim (S is already public, so
    re-revealing leaks nothing).
  - New `confirmClaimEvm` reorg-safe finalizer, wired into `resume()`'s claim branch for an EVM `theirChain`: reads
    `getSwap.claimed` at a reorg-safe depth (`tip - requiredConfirmations + 1`) and either finalizes
    (`'claimed'`→`'completed'`) or, on an orphaned claim (`claimed=false` + lock still funded), re-broadcasts it. A
    spurious re-broadcast at worst reverts on-chain (the contract enforces single-claim) — never a loss. Regression
    tests added (corroborated adopt, reorg-safe finalize, and orphaned-claim auto re-broadcast on resume).

## 3.1.9

### Fixed (fund-safety — HIGH, audit round 6)
- **R-UTXO-REFUNDRACE-001** (HIGH): the UTXO refund path had no analogue of the EVM `recoverFromRefundRace`, so a
  RESPONDER that broadcast a refund of its own leg Y but LOST the race to the initiator's secret-revealing claim of
  that same outpoint was permanently wedged — it could never claim leg X (still claimable with the now-public S until
  its longer timelock), forfeiting its entire funded leg while the initiator netted both legs. Two converging triggers,
  both fixed:
  - **(B1) definitive broadcast rejection**: `refund()` broadcast the refund with a bare `broadcastTx`, so a definitive
    `bad-txns-inputs-missingorspent` (the counterparty already claimed the outpoint) threw with the `refundbroadcast`
    sentinel stuck at `'1'` — permanently blocking `claimWithKnownSecret`. Now routed through a new
    `broadcastRefundWithSentinelGuard` (symmetric with the claim path): a definitive rejection clears the sentinel; an
    ambiguous/timeout failure keeps it (fail-safe).
  - **(B2) lost mining race after a successful broadcast**: the refund entered the mempool (phase set to `'refunded'`)
    then was orphaned when the initiator's claim won. New `recoverUtxoRefundRace()` (the UTXO analogue of
    `recoverFromRefundRace`): on resume it detects leg Y's outpoint spent by a tx that is NOT our refund and that
    reveals a preimage of our secretHash, recovers S, clears the refund sentinel, resets phase to `'claimed'`, and
    drives `claimWithKnownSecret` on leg X. Fail-closed — pivots ONLY on a confirmed-public S; otherwise keeps all
    recovery material. Wired into `resume()`'s refund-first branch. Regression tests added (definitive-clear,
    ambiguous-keep, and a full resume-driven end-to-end recovery).

## 3.1.8

### Fixed (fund-safety — CRITICAL, audit round 6)
- **R-UNDERFUND-001** (CRITICAL): the UTXO counterparty-leg gates never bound the on-chain funded value to the offer
  amount. `reverifyBuriedOutpoint` (shared by the responder fund gate `assertLegBuriedForFunding` and the initiator
  reveal gate `assertRevealSafe`) authenticated the funding output's value but asserted only `value > 0` — neither
  `FundGateParams` nor `RevealSafeParams` carried an expected-amount field, and the controller never passed
  `offer.sendAmount`/`receiveAmount`. A malicious maker/responder could dust-fund the counterparty leg (a REAL,
  buried, correct-outpoint, CLTV-consistent HTLC holding e.g. ~20k sats instead of the advertised 50 BCH2); every
  other check passed, so the victim funded/revealed its OWN full leg and could only ever claim back dust — a whole
  receive-leg loss requiring NO race or reorg. The EVM sibling path already binds this (`isEvmLockAtSafeDepth` rejects
  `lock.amount < inv.minAmount`, with an explicit comment that omitting it lets a party reveal against an under-funded
  lock); the guard was dropped only on the UTXO path. (The live app is NOT affected — `SwapExecute.tsx` binds the
  expected amount at its poll/reveal sites; this restores the same bind in the SDK.) Fix: `FundGateParams` and
  `RevealSafeParams` gain `expectedFundedValueSats`; `reverifyBuriedOutpoint` fails closed (`abort`) unless the
  authenticated value of the exact recorded outpoint the claim spends is `>=` it (also covers split-UTXO funding). The
  controller passes `offer.sendAmount` for the responder fund gate (claims leg X) and `offer.receiveAmount` for the
  initiator reveal gate + the broadcast-choke re-mint (claims leg Y). Regression tests added to `gates.test.ts` (both
  gates ABORT when the authenticated value is one sat below the required amount).

## 3.1.7

### Fixed (fund-safety — audit round 5)
- **R-EVMTOKEN-ALLOWLIST-001** (HIGH — SDK-boundary): the SDK never validated an offer's EVM token against the
  trusted config allowlist. `offer.evmInfo.tokenAddress`/`tokenSymbol` come from the untrusted order-book box, and
  the on-chain finality gate (`isEvmLockAtSafeDepth`) binds `lock.token === inv.token` where `inv.token` IS that same
  offer field — a self-referential check. `myEvmToken`/`counterpartyEvmToken` are set only in tests, so in production
  the token always fell through to the offer field, validated by `ethers.isAddress()` alone. A maker who both
  advertises AND locks an attacker-chosen token (worthless self-minted with a spoofed 'USDC' symbol, or a
  fee-on-transfer / rebasing / ERC-777 token) passed the gate; a bot author relying on this SDK as their fund-safety
  boundary could be induced to fund a real leg against a leg that pays back a worthless/short token. (The live app is
  NOT affected — its `offer-ingest.ts` already excludes any offer whose `tokenAddress` isn't the canonical address for
  its claimed symbol; this ports that same canonical symbol↔address binding into the SDK.) Fix: new
  `assertCanonicalEvmToken(chainId, tokenAddress, tokenSymbol)` (evm-config.ts), enforced in BOTH `counterpartyEvmLeg`
  (verify/claim side) and `lockEvm` (lock side) — native (zero-addr) allowed only when the chain has a configured
  native entry; a non-native token must carry a symbol AND equal `EVM_CHAINS[chainId].tokens[symbol].address`. This
  rejects both an unrecognized token and the "advertise USDC, lock USDT" mismatch. Regression tests added.
- **R-EVMTOKEN-ALLOWANCE-001** (MEDIUM — fails closed, no fund loss): `SwapController.lockEvm` dropped the ERC-20
  `approve` step the UI's `handleEvmFund` performs, so `lockTokens` → `transferFrom` reverted on every fresh-signer
  stablecoin lock — the SDK's documented USDC/USDT EVM path never worked, and it emitted a misleading "allowance
  race, retry" message for a permanently-zero allowance. Fix: call the already-hardened `ensureAllowance` before the
  non-native lock, placed BEFORE the `lockpending` recovery sentinel so an approve failure leaves a clean retry state
  (never wedged as "lock in-flight").
- **R-EXTRACTSECRET-REQHASH-001** (LOW — API footgun on the published surface): `extractSecretFromClaimTx` /
  `extractSecret` treated the committed `expectedSecretHash` as OPTIONAL. Omitting it made the parser return the first
  structurally-valid 32-byte push, which an attacker can control via a decoy input carrying a trailing 32-byte push —
  handing back attacker-chosen bytes as "the secret". The sole in-tree caller always passes the hash (product safe),
  but the export is a footgun for bot authors. Fix: the hash is now REQUIRED — parsed once up front (fail closed if
  missing/malformed) and validated on every candidate, so only a preimage that hashes to the committed value is ever
  returned. Regression added (omitting the hash returns null; a decoy push is skipped when the hash is passed).

## 3.1.6

### Fixed (fund-safety — HIGH, audit round 4)
- **R-RECOVER-SWAPID-QUORUM-001** (`evm-client.ts` recoverLockFromTx): the EVM lock-recovery path adopted the
  `swapId` from a SINGLE quorum leaf. The R239 receipt check authenticated only the PUBLIC Locked-event fields
  (hashLock / recipient / amount) — not the `swapId` it commits (the on-chain id is keccak256(sender, nonce),
  unconstrained by those public fields) — and `getTransactionReceipt` does no Merkle verification of `receipt.logs`.
  So a single lying/MITM RPC leaf could fabricate a Locked log with our public params but an attacker-chosen swapId;
  the `'locked'` verdict took the first single leaf (unlike `'safe'`, which is unanimity-gated). On a reload during
  the pending-lock window the responder would commit `fundedKey`/`myEvmSwapId` = the wrong id, then its claim-watch
  filters the wrong indexed id (never recovers the secret) and refund targets a nonexistent swap → owed leg lost,
  silently. Fix: cross-verify each candidate swapId via `getSwap` over the aggregating (quorum) provider — a
  fabricated id does not exist on-chain (getSwap → null), so it is skipped; adopt only a quorum-corroborated id, and
  iterate all candidates so a hostile leaf ordered first cannot mask the real lock. Regression tests added (adopt a
  corroborated id; reject a fabricated one).

## 3.1.5

### Fixed (fund-safety — audit round 3)
- **R-FEE-DEADLINE-001** (HIGH; MEDIUM for a BCH2↔EVM-only deployment): the deadline-aware fee module
  (`fee-rate.ts`) was inert dead code — `buildSecretClaim` + the refund path called `claimHTLC`/`buildHTLCRefundTx`
  with NO `feeRate`, so both built at the STATIC config rate, while `index.ts` advertised "deadline-aware fees" as
  a delivered property. On a fee-volatile UTXO chain (BTC/BCH) during a sustained spike, the secret-revealing claim
  could enter the mempool (secret public) but not confirm inside the reveal margin → the counterparty refunds one
  leg and claims the other = initiator double-loss. Now wired: a live `fetchFeeRate` base (proxy `blockchain.estimatefee`,
  floored to config + clamped, fail-safe) scaled UP by `deadlineAwareFeeRate` as the leg's runway approaches the
  claim margin, threaded into the claim + refund builders. The advertised property is now real. Regression added.
- **R-MUTEX-HB-001** (LOW): the InProcessMutex CAS heartbeat's in-flight renew tick (a fire-and-forget async IIFE)
  could complete its `store.set` AFTER `release()`, resurrecting the lock sentinel and stranding a peer instance for
  up to `ttlMs` (240s). The finally now drains the in-flight tick before releasing, so the release is the last write.
  Availability only (no fund impact — a durable single-flight sentinel already prevents double-fund/lock).

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
