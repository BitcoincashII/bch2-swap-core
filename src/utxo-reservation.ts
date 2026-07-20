// Parallel-funding UTXO reservation registry (parallel maker execution — Inc 1).
//
// PROBLEM: to fund many taken offers in parallel, several fundings draw from the SAME maker wallet UTXO set at once.
// Coin selection is greedy FIFO (SwapExecute.tsx), so two concurrent fundings would pick the SAME inputs → the second
// broadcast is a double-spend the node rejects → that swap silently fails to fund → its take expires. Worse, a 0-conf
// funding's inputs are still SPENT in the mempool but its change output is NOT yet visible to the proxy's scantxoutset,
// so "serialize + re-fetch getUTXOs" does not fix it (the next funding sees the just-spent inputs as still available and
// can't see the fresh change).
//
// FIX: a registry that, guarded by a small async mutex around select+reserve:
//   - RESERVES the inputs of every in-flight (built/broadcast, unconfirmed) funding so concurrent fundings pick DISJOINT
//     inputs, and
//   - tracks each in-flight funding's CHANGE output (which the client knows from the tx it just built, even though
//     scantxoutset can't see it yet) so a single-UTXO maker chains fundings through their own change with NO confirmation
//     wait.
//
// NO-OP FOR A SINGLE SWAP: a swap releases its own prior reservation before re-selecting, and with only one funding in
// flight nothing else is reserved and knownChange is empty — so candidateUtxos returns exactly the chain UTXOs. This is
// the ONLY new fund-critical code for parallel execution; everything else reuses the already-audited swap flow.
//
// P1b (fix #3): the module-level `reservedBy`/`knownChange` Maps + `mutexTail` singletons are now INSTANCE fields of
// `UtxoReservationRegistry`, so a bot/wallet/pool constructs one registry per SwapController rather than sharing hidden
// process-global state. The reservation SEMANTICS are a verbatim port (ukey, TTL sweep, reservedByOther filter, the
// change-chaining dedupe). The former localStorage cross-tab persist side-effect is now an OPTIONAL injected
// `ReservationMirror` hook (default: none = in-memory, per-instance). The browser adapter that reproduces the audited
// R-RESPERSIST cross-tab exclusion is `LocalStorageReservationMirror` below.

export interface ResUtxo { tx_hash: string; tx_pos: number; value: number; height: number; }
const ukey = (u: { tx_hash: string; tx_pos: number }): string => `${u.tx_hash}:${u.tx_pos}`;

// 60 min — far beyond funding confirmation; bounds map growth and self-heals a leaked reservation (worst case a leaked
// reservation only DENIES an input to selection; the node's mempool is the ultimate double-spend guard regardless).
const TTL_MS = 60 * 60_000;

interface Entry<T> { v: T; ts: number; owner: string; }

// ── Optional cross-instance / cross-tab mirror hook ───────────────────────────────────────────────────────────────
// A registry is per-instance, so on its own it does NOT coordinate with a second tab / process that keeps its own
// registry. Inject a `ReservationMirror` to MIRROR just this registry's INPUT reservations (never knownChange —
// chaining from another holder's not-yet-broadcast 0-conf change would reintroduce a phantom) to shared storage, and to
// UNION every OTHER holder's reserved outpoints into candidateUtxos' exclusion set. This only NARROWS the race window —
// the node's mempool stays the ultimate double-spend guard, so a residual race (both holders select before either
// persists) still merely gets one broadcast node-rejected, never a fund loss.
export interface ReservationMirror {
  // Union of every OTHER holder's non-stale reserved outpoints (owner ≠ this registry). Best-effort: any failure must
  // degrade to the empty set (returns whatever it gathered).
  readOtherReserved(now: number): Set<string>;
  // Write-through THIS registry's current input reservations as [outpointKey, ts][] so other holders can exclude them.
  // Each row carries its reservation's OWN ts (not a call-time now) so peers age each entry independently.
  persistReserved(rows: Array<[string, number]>): void;
}

export class UtxoReservationRegistry {
  private readonly reservedBy = new Map<string, Entry<true>>();     // input key -> in-flight funding that spends it
  private readonly knownChange = new Map<string, Entry<ResUtxo>>(); // input key -> 0-conf change spendable before it confirms
  private mutexTail: Promise<unknown> = Promise.resolve();
  private readonly mirror?: ReservationMirror;

  constructor(mirror?: ReservationMirror) { this.mirror = mirror; }

  private prune(now: number): void {
    for (const [k, e] of this.reservedBy) if (now - e.ts > TTL_MS) this.reservedBy.delete(k);
    for (const [k, e] of this.knownChange) if (now - e.ts > TTL_MS) this.knownChange.delete(k);
  }

  // Mirror this instance's INPUT reservations (each with its own ts) so a peer would exclude them.
  private persist(): void {
    if (!this.mirror) return;
    const rows: Array<[string, number]> = [];
    for (const [k, e] of this.reservedBy) rows.push([k, e.ts]);
    try { this.mirror.persistReserved(rows); } catch { /* best-effort — degrade to in-memory only */ }
  }

  // Tiny async mutex: makes each funding's release→candidate→select→reserve sequence atomic, closing the TOCTOU where
  // two fundings could both select before either reserves. A throwing fn does NOT wedge the chain (tail swallows).
  withUtxoLock<T>(fn: () => Promise<T> | T): Promise<T> {
    const run = this.mutexTail.then(fn, fn);
    this.mutexTail = run.then(() => {}, () => {});
    return run as Promise<T>;
  }

  // Candidate inputs for `swapId`: (chain UTXOs minus inputs reserved by OTHER swaps) ∪ (0-conf change not re-spent by
  // another), deduped by outpoint. Call INSIDE withUtxoLock, after releaseSwap(swapId).
  candidateUtxos(swapId: string, chainUtxos: ResUtxo[], now: number = Date.now()): ResUtxo[] {
    this.prune(now);
    const otherTabReserved = this.mirror ? this.mirror.readOtherReserved(now) : new Set<string>(); // outpoints reserved by OTHER holders
    const reservedByOther = (k: string): boolean => {
      const r = this.reservedBy.get(k);
      if (r && r.owner !== swapId) return true;      // an in-flight OTHER funding in THIS registry already spends this input
      return otherTabReserved.has(k);                // …or an in-flight funding in ANOTHER holder does
    };
    const out = new Map<string, ResUtxo>();
    for (const u of chainUtxos) {
      if (reservedByOther(ukey(u))) continue;
      out.set(ukey(u), u);
    }
    for (const [k, e] of this.knownChange) {
      if (reservedByOther(k)) continue;              // this 0-conf change is already re-spent by another funding
      if (!out.has(k)) out.set(k, e.v);              // 0-conf change the scan can't see yet (dedupe vs a now-confirmed copy)
    }
    return [...out.values()];
  }

  // Reserve `swapId`'s selected inputs. Call INSIDE withUtxoLock, immediately after a successful (sufficient) selection.
  reserveInputs(swapId: string, inputs: Array<{ tx_hash: string; tx_pos: number }>, now: number = Date.now()): void {
    for (const u of inputs) this.reservedBy.set(ukey(u), { v: true, ts: now, owner: swapId });
    this.persist(); // mirror to shared storage so other holders exclude these inputs
  }

  // Record `swapId`'s funding change output so a later funding may spend it before it confirms.
  recordChange(swapId: string, change: ResUtxo, now: number = Date.now()): void {
    if (change.value > 0) this.knownChange.set(ukey(change), { v: change, ts: now, owner: swapId });
  }

  // Release everything `swapId` holds. Call before re-selecting (retry-safe) and on ANY funding failure / unmount so a
  // non-broadcast selection never strands its inputs. Idempotent.
  releaseSwap(swapId: string): void {
    for (const [k, e] of this.reservedBy) if (e.owner === swapId) this.reservedBy.delete(k);
    for (const [k, e] of this.knownChange) if (e.owner === swapId) this.knownChange.delete(k);
    this.persist(); // drop the released inputs from the shared mirror
  }

  // Test-only: wipe all in-memory state (the injected mirror, if any, owns its own storage).
  reset(): void {
    this.reservedBy.clear(); this.knownChange.clear(); this.mutexTail = Promise.resolve();
    this.persist();
  }
}

// ── Browser adapter: R-RESPERSIST cross-tab exclusion via per-tab localStorage keys ───────────────────────────────
// Ported verbatim from the app's module-level _persistReserved / _readOtherReserved / _makeTabId. We MIRROR just this
// tab's INPUT reservations under a PER-TAB localStorage key, and readOtherReserved UNIONS every OTHER live tab's
// reserved outpoints. Per-tab keys mean no tab clobbers another's entries. Best-effort: any storage failure degrades to
// the prior in-memory-only behavior.
const _RES_KEY_PREFIX = 'bch2swap:utxores:';

interface StorageLike { getItem(k: string): string | null; setItem(k: string, v: string): void; removeItem(k: string): void; readonly length: number; key(i: number): string | null; }

export class LocalStorageReservationMirror implements ReservationMirror {
  private readonly ls: StorageLike | null;
  private readonly persistKey: string;

  constructor(opts?: { localStorage?: StorageLike | null; sessionStorage?: StorageLike | null }) {
    this.ls = opts?.localStorage ?? (typeof localStorage !== 'undefined' ? (localStorage as unknown as StorageLike) : null);
    const ss = opts?.sessionStorage ?? (typeof sessionStorage !== 'undefined' ? (sessionStorage as unknown as StorageLike) : null);
    this.persistKey = _RES_KEY_PREFIX + LocalStorageReservationMirror._makeTabId(ss);
  }

  // Per-tab id, STABLE across a reload of the same tab (sessionStorage survives F5 but is unique per tab), so a reload
  // does NOT orphan this tab's own reservation key and then wrongly exclude its own reserved inputs from itself. Falls
  // back to a fresh random id if sessionStorage is unavailable (SSR/tests). Math.random is app-code-safe (not a workflow).
  private static _makeTabId(ss: StorageLike | null): string {
    const rnd = (): string => Math.random().toString(36).slice(2) + Math.random().toString(36).slice(2);
    try {
      if (ss) {
        const k = 'bch2swap:restabid';
        let id = ss.getItem(k);
        if (!id) { id = rnd(); ss.setItem(k, id); }
        return id;
      }
    } catch { /* fall through to a fresh random id */ }
    return rnd();
  }

  // Write-through this tab's current input reservations as [outpointKey, ts][] so other tabs can exclude them.
  persistReserved(rows: Array<[string, number]>): void {
    const s = this.ls; if (!s) return;
    try {
      if (rows.length === 0) { s.removeItem(this.persistKey); return; }
      s.setItem(this.persistKey, JSON.stringify(rows));
    } catch { /* quota / unavailable — degrade to in-memory only */ }
  }

  // Union of every OTHER live tab's non-stale reserved outpoints. Prunes whole peer keys that are entirely stale/corrupt
  // (a live peer rewrites its key on its next mutation, so deleting an all-stale key is safe).
  readOtherReserved(now: number): Set<string> {
    const s = this.ls; const out = new Set<string>(); if (!s) return out;
    try {
      const stale: string[] = [];
      for (let i = 0; i < s.length; i++) {
        const key = s.key(i);
        if (!key || !key.startsWith(_RES_KEY_PREFIX) || key === this.persistKey) continue;
        let anyFresh = false;
        try {
          const rows = JSON.parse(s.getItem(key) ?? '[]') as Array<[string, number]>;
          if (!Array.isArray(rows)) { stale.push(key); continue; }
          for (const row of rows) {
            if (!Array.isArray(row) || typeof row[0] !== 'string' || typeof row[1] !== 'number') continue;
            if (now - row[1] > TTL_MS) continue;
            out.add(row[0]); anyFresh = true;
          }
        } catch { stale.push(key); continue; }
        if (!anyFresh) stale.push(key);
      }
      for (const k of stale) { try { s.removeItem(k); } catch { /* ignore */ } }
    } catch { /* ignore — return whatever we gathered */ }
    return out;
  }
}
