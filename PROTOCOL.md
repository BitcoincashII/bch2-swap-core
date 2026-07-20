# BCH2 Atomic Swap — Protocol Specification

> Status: **DRAFT / normative-intent.** This is the canonical description of the safe cross-chain
> atomic-swap protocol implemented by the bch2-swap frontend and encapsulated by the `@bch2/swap-core`
> `SwapController`. Any client — wallet, market-maker bot, or pool server — that posts, takes, funds,
> claims, or refunds a swap **MUST** satisfy every invariant in [§9](#9-fund-safety-invariants-must-not-violate).
> Violating one is a **fund-loss** bug, not a style issue.

Grounded in: `bch2-swap/src/components/SwapExecute.tsx`, `bch2-swap/src/core/*`, `bch2-swap/proxy-server/server.ts`.

---

## 1. Overview

A swap exchanges value across two chains with no trusted third party. One leg is always **BCH2** (the
hub); the other is a UTXO chain (BCH, BTC — BC2 is currently **suspended**) or an EVM chain (Polygon 137,
Arbitrum 42161), native coin or an allow-listed ERC-20 (USDC/USDT).

Two parties:

| Role | Also called | Holds the secret? | Funds first | Timelock |
|---|---|---|---|---|
| **Initiator** | maker | **Yes** — generates `S`, reveals it | Yes (leg X) | **Longer** (outlasts responder) |
| **Responder** | taker | No — learns `S` from the initiator's on-chain claim | Second (leg Y), only after verifying X | **Shorter** |

Each leg is a **Hash-Time-Locked Contract (HTLC)**: spendable either by (a) presenting `S` such that
`H(S)` equals the committed `hashLock` (the *claim* branch), or (b) the funding party after a
`timeLock` elapses (the *refund* branch). UTXO legs use a P2SH HTLC script; EVM legs use the
`TokenHTLCSwap` contract (Polygon `0x405A…`, Arbitrum `0x141F…`).

The **atomicity guarantee**: the initiator can only take the responder's leg by revealing `S`
on-chain, which hands the responder exactly what they need to take the initiator's leg. Either both
legs settle, or both refund. **Never one-sided** — provided every party obeys §9.

---

## 2. The swap state machine

Server-tracked status (the source of truth for coordination; the on-chain state is the source of truth
for funds):

```
open ──take──▶ taken ──initiator funds X──▶ initiator_funded ──responder verifies X + funds Y──▶ responder_funded
                                                                                                        │
                                                    initiator claims Y (reveals S) ──▶ claimed ─────────┘
                                                                                          │
                                                    responder claims X (using S) ──▶ completed
```

Failure/abort transitions (any state): `cancelled` (pre-fund, maker cancels an open order),
`expired` (order TTL), `refunded` (a funded leg recovered via its timelock after the counterparty
went dark).

**Who transitions, and the precondition each MUST check before advancing:**

| Transition | Actor | MUST verify first |
|---|---|---|
| `open → taken` | responder | order open, not suspended, not self-take (`isOwnOffer`) |
| `taken → initiator_funded` | initiator | (funds leg X) — record the funding txid/swapId locally BEFORE broadcast |
| `initiator_funded → responder_funded` | responder | **X is buried to reorg-safe depth, SPV-verified** (§4) AND timelock ordering holds (§3) — only then fund Y |
| `responder_funded → claimed` | initiator | **Y is buried to reorg-safe depth, SPV-verified** — only then broadcast the claim of Y (which reveals `S`) |
| `claimed → completed` | responder | extract `S` from the initiator's on-chain claim, verify `sha256(S) == hashLock`, then claim X |

Status is *advisory coordination*; a client MUST re-derive truth from the chain (a lying/lagging
server MUST NOT be able to induce an unsafe action — see §4, §9).

---

## 3. Timelock ordering (the anti-theft invariant)

The initiator's leg **MUST** remain refundable strictly **after** the responder's leg — enough later
that a party can never claim one leg and still refund the other in the same window.

- Block-height CLTV legs: `LOCKTIME_BLOCKS.initiator = 216` (~36 h), `.responder = 72` (~12 h).
- EVM timestamp legs: `RESPONDER_LOCK_SEC` + `EVM_CLAIM_MARGIN_SEC`, with the initiator strictly longer.

**Cross-domain rule (R228):** the two legs live in *different height domains* (BCH2 ~72 k vs BTC ~957 k
vs BCH ~959 k vs an EVM Unix timestamp). Ordering **MUST** be compared in **wall-clock seconds**, never
raw block heights. Convert height deltas via `minSecondsUntilRefund(blocksRemaining, avgBlockTimeSec)`,
which additionally deflates the runway by a conservatism factor `TIMELOCK_SAFETY_K = 2` so a K-fold
block-rate acceleration cannot invert the ordering (minority-hashrate BCH2).

Gate predicates a client MUST apply before committing the irreversible action (fund Y / reveal S):
`marginTooTight`, `claimWindowTooTight`, `orderingUnsafe` (see `src/core/timelock-gates.ts`). A claim
that would start with < `CLAIM_MARGIN_SEC` (4 h) of runway against the counterparty CLTV **MUST NOT**
reveal the secret.

---

## 4. SPV depth gates (the anti-lying-proxy trust model)

A client reads chain data through a proxy/RPC it does **not** fully trust. Before any **irreversible**
action, it MUST prove the relevant on-chain fact itself, not take the proxy's word:

- **Secret-reveal gate (initiator):** before broadcasting the claim of leg Y, `verifyConfirmations`
  MUST prove — from a PoW/ASERT (or legacy-2016) header chain anchored at a hardcoded checkpoint, a
  Merkle inclusion proof, and `provenTxid === txid` — that the responder's funding is buried
  ≥ `requiredConfirmations`. Fail-closed on a fabricated/short/stale depth.
- **Responder pre-lock gate:** before funding leg Y, re-verify the initiator's leg X to reorg-safe
  depth the same way (UTXO: `verifyConfirmations`; EVM: `isEvmLockAtSafeDepth` — binds hashLock,
  recipient, amount, timeLock, **and** token at the `safe`/128-deep tag under quorum ≥ 2).
- **Funding-height gate (`verifyFundingHeight`):** before funding your OWN HTLC, SPV-prove the
  proxy-reported build height is a real PoW block — an inflated height would push your refund CLTV
  ~forever and strand the coins.
- **Tip-freshness bound:** margin decisions MUST bound *both* proxy lies — over-report (via the PoW
  chain) and under-report (via a 2-h tip-timestamp freshness bound), so a stale-but-real tip cannot
  deflate "blocks remaining."

`requiredConfirmations`: BCH2 = 6, BCH = 6, BTC = 2, BC2 = 3; EVM Polygon = 128, Arbitrum = 30.

---

## 5. Secret lifecycle

- `S` is 32 bytes. `hashLock = sha256(S)` (UTXO) / the contract's hash (EVM). Committed at post time
  as `secretHash`.
- **Derivation (preferred, `hmac-v1`):** `S = HMAC-SHA256(K_ss, DOMAIN || nonce)` where
  `K_ss` is a hardened seed path (`m/83'/0'/0'`) and `nonce` is a public 16-byte CSPRNG value posted
  with the offer (`secretNonce`). This makes `S` **re-derivable** from the seed on any device — a
  refresh/new-session/new-device does not strand the initiator. Legacy random secrets fall back to a
  `sessionStorage` value and are **not** re-derivable (durability hazard).
- **`S` is revealed exactly once**, on-chain, by the **initiator** claiming leg Y. The responder
  extracts it from that claim's scriptSig / calldata and **MUST verify `sha256(S) == hashLock`**
  before using it (a proxy cannot forge a secret past this check).
- `S` **MUST NEVER** be transmitted to the server/proxy before the on-chain reveal, logged, placed on
  a global, or stored in plaintext.

---

## 6. Reorg handling

- **CASE B (orphaned claim):** if a broadcast claim is orphaned by a reorg, the client MUST clear the
  stale txid, **rebuild** the claim against the fresh funding outpoint, and re-enter the SPV depth gate
  — it MUST NOT mark the swap `done` or delete recovery material on a network blip mistaken for a reorg.
- **Pre-reveal double-spend:** before revealing `S`, the exact recorded funding outpoint
  (`tx_hash:tx_pos`) MUST still be confirmed at the required depth AND SPV-verified. A reorg/double-spend
  of a 0-conf funding MUST fail-close the reveal and re-arm the watcher, so the secret never leaks
  against a vanished funding.
- **Finalizers** (confirmClaim / resume-verify) MUST re-verify claim depth via SPV before wiping the
  non-recoverable secret/state; a lying-then-reorged proxy MUST NOT trigger an early teardown.

---

## 7. Refund (recovering funds when a counterparty goes dark)

If the counterparty never advances, each party recovers their own funded leg via its timelock:

- **Precondition:** the leg's `timeLock` has elapsed on-chain (`isHtlcRefundAvailable(locktime, tip)`),
  re-verified against a fresh tip. UTXO: nSequence enables CLTV (`0xfffffffe`), nLockTime = locktime.
- Build + broadcast the refund, **persist the raw refund tx + recovery record BEFORE broadcast**, arm
  the reorg-safe/SPV-finalize monitor, and rebroadcast on mempool-drop.
- The refund carries **no secret** and recovers 100% of principal (minus fee).
- **Fee-deadline safety:** a refund (or claim) MUST be priced at a live, deadline-aware feerate so it
  confirms *before* the timelock window is contested. The fee is clamped so a fundable UTXO can always
  afford *some* valid confirming tx (the affordability clamp), and the funding floor is sized at the
  worst-case feerate so anything that funds is always recoverable.

---

## 8. Order API + auth (integration surface)

REST (`/api/orders …`) + a per-chain WebSocket Electrum relay (`/ws?chain=…`). See `INTEGRATION.md`
(to be written) for shapes. Order-mutating calls (PATCH status, DELETE) authenticate with a **seed-
derived signature**: `Authorization: Bearer <ECDSA sig>` + `X-Swap-Ts`, signed with a hardened auth
path (`m/83'/2'/0'`); only the public sig + timestamp + auth pubkey go on the wire, never a private key.
Reads are public. Post/take carry the maker/taker seed-derived auth pubkey so the order is bound to its
owner.

---

## 9. Fund-safety invariants (MUST NOT violate)

A conforming client — **including any bot, wallet, or pool integration** — MUST guarantee all of:

1. **Never fund leg Y** until leg X is SPV-verified buried to `requiredConfirmations` **and** the
   timelock ordering gates pass. (§3, §4)
2. **Never reveal `S`** (never broadcast the claim of leg Y) until leg Y is SPV-verified buried to
   reorg-safe depth **and** ≥ `CLAIM_MARGIN_SEC` runway remains against the counterparty CLTV. (§4, §3)
3. **Never trust the proxy** for any irreversible decision — over- and under-report are both bounded by
   your own SPV + tip-freshness checks. Fail **closed** on any uncertainty. (§4)
4. **Verify `sha256(S) == hashLock`** before using an extracted secret. (§5)
5. **Never transmit / log / globalize / plaintext-store** the seed, a derived private key, or `S`
   before its on-chain reveal.
6. **Preserve recovery material** (secret, refund tx, funding keys, durable state) until the swap is
   settled at reorg-safe depth or fully refunded — never wipe on an inconclusive/pruned read or a
   network blip. (§6)
7. **Refund is always reachable** after the timelock, at a fee that confirms in time; the amount that
   funded is always claimable/refundable at the worst-case feerate. (§7)
8. **Do not auto-lock / drop the signing capability mid-swap** — a persistent host MUST keep the
   claim/refund keys derivable for the swap's whole lifetime (or resume cleanly).
9. **Idempotent, single-flight actions** — never double-fund an input, double-lock an EVM swap, or
   reveal twice across tabs/instances (cross-tab/cross-instance mutex + durable sentinels).

---

## 10. Reference

The `@bch2/swap-core` `SwapController` (`src/swap-controller.ts`) is the SDK's encapsulation of this
protocol: it sequences the irreversible-action gates (`src/gates.ts` + the SPV verifier) so that the
safe path is the only path — the branded `FundProof` / `RevealAuthorization` cannot be produced except
by a verified-depth check. It is extracted from the DEX frontend's proven orchestration
(`bch2-swap/src/components/SwapExecute.tsx`) and its supporting modules — `swap-flow`, `timelock-gates`,
`fee-rate`, `seed-secret`, `spv-verifier`, and `evm-client`. Integrate against this spec via the
`SwapController`; if you drive the lower-level primitives yourself instead, this spec — especially
§9 — is the contract you MUST satisfy.
