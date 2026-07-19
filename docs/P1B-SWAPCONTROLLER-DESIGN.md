# P1b — Headless `SwapController` design & build spec

> Blueprint for extracting the proven `SwapExecute.tsx` orchestration (10,230 lines) into a
> framework-agnostic `SwapController` in `@bch2/swap-core`, so a bot/wallet/pool **structurally cannot**
> run a swap unsafely. Derived from a grounded understand→design→critique pass over the live code.
> The fund-safety contract is [PROTOCOL.md](../PROTOCOL.md) §9. **Every "GATE" below is a hard build
> requirement — a miss is fund loss.**

## 0. What's already done (P1a)
The fund-safety *primitives* are extracted + diff-verified byte-identical in the SDK: `spv` (primitives),
`seed-secret`, `chain-config`, `timelock-gates`, `fee-rate`, `htlc-builder` (CLTV), `swap-flow`,
`evm-client`, `evm-config`. 270 tests green. P1b moves the **orchestration + gate-sequencing** that is
still fused into React.

## 1. `SwapController` public API
Constructor-injected deps (see §2). Methods:

- `static async resume(record, deps)` — rehydrate a stalled/crashed/new-device swap from durable state;
  re-derive S, re-authenticate `myHTLC` against the live on-chain P2SH, re-enter the correct gate from
  **chain truth, not persisted status**; finalizers-first.
- `async prepare()` — derive per-swap keys from the injected SeedVault (signing key, `K_ss` = `deriveSwapKss(m/83'/0'/0')`, `S` = `swapSecretFromKss(K_ss, nonce)`). **GATE (fix #5):** fail closed unless the offer is `hmac-v1` (S re-derivable) **or** an encrypted-at-rest durable S exists. Also require `S.length===32 && sha256(S)===offer.secretHash`; refuse a suspended pair.
- `async fundLegX()` — initiator funds its own leg. **GATE:** `verifyFundingHeight` SPV PoW gate on the build height; UTXO-reservation mutex; durable-before-broadcast atomic write; cross-instance CAS single-flight.
- `async verifyCounterpartyLegForFunding(): FundProof` — **the only minter of `FundProof`.** SPV depth (`verifyConfirmations` with `provenTxid===txid`) + `spvVerifiedTipFresh` + ordering gates on leg X. Throws (mints nothing) on any failure/uncertainty.
- `async verifyCounterpartyLegForReveal(): RevealAuthorization` — **the only minter of `RevealAuthorization`.** SPV depth on leg **Y** + `>= CLAIM_MARGIN_SEC` (4h) runway + the outpoint binding. Distinct predicate from the fund proof.
- `async fundLegY(proof: FundProof)` — responder funds leg Y. Requires a `FundProof` (compile-time). **GATE (fix #2):** re-fetch height/UTXO/depth/margin **unconditionally** at the broadcast choke point and re-mint from scratch — zero reuse window.
- `async revealAndClaim(auth: RevealAuthorization)` — initiator's single irreversible reveal of S. Requires a `RevealAuthorization` (compile-time). **GATE (fix #8):** triangulate `auth.outpoint === claimTx.spent === still-confirmed-≥reqConf (SPV)` at broadcast; if `claimTx.spent` absent → fail closed, discard cache, rebuild, re-enter gate. Re-mint at the choke point (fix #2). S is never emitted on any failure.
- `async watchForSecret(): {secret}` — responder watches its **own** leg for the initiator's spend; `extractSecret` verifies `sha256(S)===hashLock` before returning (§9.4). Never abandons on an empty counterparty listunspent.
- `async claimWithKnownSecret()` — responder claims leg X with the now-public S (reveal-gate deliberately skipped: no margin risk on an already-public secret); single-flight; refuse if a refund is in flight.
- `async refund()` — refund own leg after timelock; re-check `isHtlcRefundAvailable` against a **fresh tip**; persist raw refund tx before broadcast; arm reorg-safe finalizer. **EVM:** on refund-revert-because-already-claimed, **pivot** to recover S from the on-chain `Claimed` event and claim the counterparty leg (fund-loss-critical, not an error).
- `canRefund(): boolean` — pure predicate for the host to render an affordance.
- `async tick()` — scheduler-driven step replacing the ~20 React effects; advances the machine + drives finalizers. **GATE (§9.6):** finalizers require `verifyConfirmations >= requiredConfirmations` (SPV) before deleting any non-recoverable secret/state; keep everything on 0-conf/timeout/inconclusive/pruned/proxy-terminal.
- `on(event,cb)` / `getState()` / `dispose()` — typed events (replace `setStatusMsg`/i18n), immutable snapshot, and `dispose()` = abort + **zeroize** key material (the only zeroization path).

## 2. Injected dependencies (no browser assumption)
`ChainClient` factory (the untrusted proxy the SPV layer verifies against; Node injects proxyUrl + `ws`),
`EvmProviderFactory` (quorum read-side, not one leaf) + `EvmSigner` (a Node `ethers.Wallet` from the
seed-derived key — **MetaMask is NOT on the path**, `connectMetaMask` is dead surface), `SeedVault`
(derives on demand + zeroizes; raw seed never globalized/on-wire), `DurableStore` (atomic KV — see fix #4),
`SessionStore` (ephemeral, kept distinct so recovery material is never confused with a session value),
`Mutex/LockProvider` (see fix #3), `Clock.now()` (**liveness/UX only** — anti-theft margins anchor to
chain time, never this clock; fix #9), `SpvTrustAnchor` (see fix #6), `OrdersApiClient` (advisory only —
re-derive fund truth from chain), `Scheduler`, `UtxoReservationRegistry` (instance-scoped).

## 3. Durable state — `DurableSwapRecord`
One record per swap id, written **atomically inside the broadcast mutex BEFORE any irreversible broadcast
returns** (durable-before-broadcast). Holds: role; offer (with `secretScheme`+`secretNonce` so S is
re-derivable, **never plaintext-stored**); phase enum; `myHTLC {redeemScript,p2shAddress,secretHash,
recipientPkh,refundPkh,locktime}`; counterparty HTLC / EVM swapId + `counterpartyEvmTimeLock`;
`myFundingTxid`; `fundLocktime` (the only durable copy of a height CLTV); `respLocktime` (R167 EVM-timestamp
CLTV); `claimTx {txid,rawTx,spent:{tx_hash,tx_pos}}` (`.spent` is load-bearing for the pre-reveal
double-spend re-check + CASE-B rebuild); `refundTx`; durable sentinels. **Never wiped** until SPV-verified
settled at reorg-safe depth or fully refunded.

## 4. Safe-by-default mechanism (the crux)
`fundLegY`/`revealAndClaim` accept **branded opaque proof types** (private brand symbol, no public
constructor) — not booleans/heights. The **only** minters are the `verifyCounterpartyLeg*` methods, which
return a proof exclusively after the SPV depth (`provenTxid===txid` Merkle+PoW binding) + tip-freshness +
timelock gates all pass, and throw otherwise. So §9.1/§9.2 are enforced by the type system, not developer
discipline — **with the two mandatory corrections below.**

## 5. HARD build requirements (from the adversarial critique — bake in, don't defer)
1. **Two non-interchangeable proof brands** (fix #1): `FundProof{leg:'X',for:'fundY'}` vs
   `RevealAuthorization{leg:'Y',for:'reveal'}` — fund-Y and reveal check *different* predicates (ordering +
   RESPONDER margin vs 4h CLAIM_MARGIN on leg Y + outpoint binding). One brand = the compile-time guarantee
   is a mirage. Each carries leg id + role + margin basis.
2. **Zero proof-reuse window** (fix #2, R175): `fundLegY`/`revealAndClaim` must **unconditionally re-fetch
   height/UTXO/depth/margin and re-mint at the broadcast choke point**. `capturedAtChainSec` may only ever
   *fail* a proof (staleness), never license skipping the re-read. Test: a stale proof is rejected.
3. **Multi-process single-flight fails closed** (fix #3, §9.9): with the default in-process mutex, **refuse
   to run a second concurrent instance**; back the CAS + UTXO reservation with a **durable cross-process
   compare-and-set keyed on outpoint/swapId** so a wrong injected Mutex is still backstopped. No advisory
   warning as the only guard.
4. **Durable-before-broadcast is truly atomic** (fix #4): the commit must **throw (never swallow)** on
   partial/failed write; `fundLegX` aborts the broadcast if it throws; **read-back-verify** the write-set
   landed before broadcasting; preserve the R202/R207 survivor-key defense for load-bearing singletons
   (`fundLocktime`, `respLocktime`). A `DurableStore` that can't guarantee atomicity is **unfit for mainnet**.
5. **Refuse a non-re-derivable secret** (fix #5): `prepare()`/`fundLegX` throw unless `hmac-v1` (re-derivable)
   or an encrypted-at-rest durable S is present. Never fund a secret a crash would strand.
6. **SPV trust anchor is hardcoded** (fix #6): ship mainnet checkpoints + ASERT/legacy params as SDK
   constants; **refuse any runtime-supplied anchor for mainnet chains** (injection only for regtest/test).
7. **EVM refund-race secret recovery at quorum ≥ 2** (fix #7): corroborate the `Claimed` log across ≥2
   leaves; keep the recovery guard set + retrying — never conclude "safe to abandon" while S may still be
   extractable from an honest leaf.
8. **Outpoint triangulation on reveal** (fix #8): `auth.outpoint === claimTx.spent === still-confirmed-≥reqConf`
   at broadcast; absent `.spent` → fail closed + rebuild.
9. **Freshness bound + chain-time non-overridable** (fix #9): port `spvVerifiedTipFresh`/`getChainTimeSec`
   with the staleness bound intact (bounds proxy **under**-report); keep the anti-theft chain-time source
   structurally non-overridable by `Clock.now()`. Test the stale-tip fail-closed matrix.
10. **Resume: indeterminate auth may WAIT only** (fix #10): a network-blip-indeterminate `myHTLC`
    authentication must **not** authorize any irreversible broadcast until authentication is DEFINITIVE.
    Read `counterpartyEvmTimeLock` from on-chain `getSwap` at quorum ≥ 2 (never the offer/server); carry
    EVM amounts as **base-unit strings** (never `Number()` an 18-dec value).

## 6. Build order (each step ends GREEN — SDK + app + tests)
1. Bring the `spv-verifier` high-level wrappers (`verifyConfirmations`/`verifyFundingHeight`/
   `spvVerifiedTipFresh`/`getChainTimeSec`/`spvSupported`) into the SDK as pure fns over the injected
   `ChainClient`; unit-test the fail-closed matrix (short depth / stale tip / `provenTxid!=txid`). Repoint
   the app to import them from the SDK. **Green: `spv.test.ts` + app tsc + app tests, zero behavior change.**
2. Add `gates.ts`: the two branded proof types + `assertLegBuried()`/`assertOrderingSafe()`/
   `assertRevealSafe()` minters (fixes #1, #2, #9). Unit-test each boundary: forged/short/stale ⇒ throws &
   mints nothing; deep+fresh+ordered ⇒ mints an outpoint-bound proof. App untouched.
3. Instance-scope `utxo-reservation` (drop the module singleton); define `DurableStore`/`SessionStore`/
   `Mutex` interfaces with an in-process default + browser adapter; durable cross-process CAS (fixes #3, #4).
4. `SwapController` skeleton + `prepare()` + `fundLegX()` (fixes #4, #5); durable-before-broadcast through
   `DurableStore` + CAS mutex. Mock test proves no unguarded broadcast.
5. `verifyCounterpartyLeg*()` → proofs, `fundLegY(proof)`, `revealAndClaim(auth)` with the choke-point
   re-verify + 4-part reveal gate + triangulation (fixes #2, #8). Test: `revealAndClaim` **without** a proof
   fails to compile; the fail-closed matrix passes.
6. `refund()` + `canRefund()` + finalizers + `resume()`/reconstruct (fix #10). Test crash-resume, reorg
   CASE-B, never-wipe-on-doubt.
7. EVM parity: `verifyEvmCounterpartyLeg()` (quorum 2), `lockEvm`, `revealAndClaimEvm`, `refundEvm` incl. the
   refund-race pivot at quorum ≥ 2 (fix #7), driven by the injected Node signer + quorum provider.
8. Rewire `SwapExecute.tsx` onto the controller (browser adapters); delete each orchestration fn as its
   method replaces it; run the regtest e2e (fund→claim→settle + refund + resume) after each cutover.
9. Delete the stale `swap-engine/engine.ts` Go-port; export `SwapController` + gates; rewrite the README;
   **bump v3.0.0** (task #60).

## 7. Verification discipline
Every extracted proven module is diff-verified byte-identical to its app original (only import-path +
documented env changes allowed), and every new seam (`gates.ts`, the controller methods, the store/mutex
adapters) gets an explicit **fail-closed test matrix**. Nothing is deployed to the live frontend until the
full regtest e2e passes on the SDK-driven path.
