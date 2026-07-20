// src/utxo-reservation.ts
var ukey = (u) => `${u.tx_hash}:${u.tx_pos}`;
var TTL_MS = 60 * 6e4;
var UtxoReservationRegistry = class {
  constructor(mirror) {
    this.reservedBy = /* @__PURE__ */ new Map();
    // input key -> in-flight funding that spends it
    this.knownChange = /* @__PURE__ */ new Map();
    // input key -> 0-conf change spendable before it confirms
    this.mutexTail = Promise.resolve();
    this.mirror = mirror;
  }
  prune(now) {
    for (const [k, e] of this.reservedBy) if (now - e.ts > TTL_MS) this.reservedBy.delete(k);
    for (const [k, e] of this.knownChange) if (now - e.ts > TTL_MS) this.knownChange.delete(k);
  }
  // Mirror this instance's INPUT reservations (each with its own ts) so a peer would exclude them.
  persist() {
    if (!this.mirror) return;
    const rows = [];
    for (const [k, e] of this.reservedBy) rows.push([k, e.ts]);
    try {
      this.mirror.persistReserved(rows);
    } catch {
    }
  }
  // Tiny async mutex: makes each funding's release→candidate→select→reserve sequence atomic, closing the TOCTOU where
  // two fundings could both select before either reserves. A throwing fn does NOT wedge the chain (tail swallows).
  withUtxoLock(fn) {
    const run = this.mutexTail.then(fn, fn);
    this.mutexTail = run.then(() => {
    }, () => {
    });
    return run;
  }
  // Candidate inputs for `swapId`: (chain UTXOs minus inputs reserved by OTHER swaps) ∪ (0-conf change not re-spent by
  // another), deduped by outpoint. Call INSIDE withUtxoLock, after releaseSwap(swapId).
  candidateUtxos(swapId, chainUtxos, now = Date.now()) {
    this.prune(now);
    const otherTabReserved = this.mirror ? this.mirror.readOtherReserved(now) : /* @__PURE__ */ new Set();
    const reservedByOther = (k) => {
      const r = this.reservedBy.get(k);
      if (r && r.owner !== swapId) return true;
      return otherTabReserved.has(k);
    };
    const out = /* @__PURE__ */ new Map();
    for (const u of chainUtxos) {
      if (reservedByOther(ukey(u))) continue;
      out.set(ukey(u), u);
    }
    for (const [k, e] of this.knownChange) {
      if (reservedByOther(k)) continue;
      if (!out.has(k)) out.set(k, e.v);
    }
    return [...out.values()];
  }
  // Reserve `swapId`'s selected inputs. Call INSIDE withUtxoLock, immediately after a successful (sufficient) selection.
  reserveInputs(swapId, inputs, now = Date.now()) {
    for (const u of inputs) this.reservedBy.set(ukey(u), { v: true, ts: now, owner: swapId });
    this.persist();
  }
  // Record `swapId`'s funding change output so a later funding may spend it before it confirms.
  recordChange(swapId, change, now = Date.now()) {
    if (change.value > 0) this.knownChange.set(ukey(change), { v: change, ts: now, owner: swapId });
  }
  // Release everything `swapId` holds. Call before re-selecting (retry-safe) and on ANY funding failure / unmount so a
  // non-broadcast selection never strands its inputs. Idempotent.
  releaseSwap(swapId) {
    for (const [k, e] of this.reservedBy) if (e.owner === swapId) this.reservedBy.delete(k);
    for (const [k, e] of this.knownChange) if (e.owner === swapId) this.knownChange.delete(k);
    this.persist();
  }
  // Test-only: wipe all in-memory state (the injected mirror, if any, owns its own storage).
  reset() {
    this.reservedBy.clear();
    this.knownChange.clear();
    this.mutexTail = Promise.resolve();
    this.persist();
  }
};
var _RES_KEY_PREFIX = "bch2swap:utxores:";
var LocalStorageReservationMirror = class _LocalStorageReservationMirror {
  constructor(opts) {
    this.ls = opts?.localStorage ?? (typeof localStorage !== "undefined" ? localStorage : null);
    const ss = opts?.sessionStorage ?? (typeof sessionStorage !== "undefined" ? sessionStorage : null);
    this.persistKey = _RES_KEY_PREFIX + _LocalStorageReservationMirror._makeTabId(ss);
  }
  // Per-tab id, STABLE across a reload of the same tab (sessionStorage survives F5 but is unique per tab), so a reload
  // does NOT orphan this tab's own reservation key and then wrongly exclude its own reserved inputs from itself. Falls
  // back to a fresh random id if sessionStorage is unavailable (SSR/tests). Math.random is app-code-safe (not a workflow).
  static _makeTabId(ss) {
    const rnd = () => Math.random().toString(36).slice(2) + Math.random().toString(36).slice(2);
    try {
      if (ss) {
        const k = "bch2swap:restabid";
        let id = ss.getItem(k);
        if (!id) {
          id = rnd();
          ss.setItem(k, id);
        }
        return id;
      }
    } catch {
    }
    return rnd();
  }
  // Write-through this tab's current input reservations as [outpointKey, ts][] so other tabs can exclude them.
  persistReserved(rows) {
    const s = this.ls;
    if (!s) return;
    try {
      if (rows.length === 0) {
        s.removeItem(this.persistKey);
        return;
      }
      s.setItem(this.persistKey, JSON.stringify(rows));
    } catch {
    }
  }
  // Union of every OTHER live tab's non-stale reserved outpoints. Prunes whole peer keys that are entirely stale/corrupt
  // (a live peer rewrites its key on its next mutation, so deleting an all-stale key is safe).
  readOtherReserved(now) {
    const s = this.ls;
    const out = /* @__PURE__ */ new Set();
    if (!s) return out;
    try {
      const stale = [];
      for (let i = 0; i < s.length; i++) {
        const key = s.key(i);
        if (!key || !key.startsWith(_RES_KEY_PREFIX) || key === this.persistKey) continue;
        let anyFresh = false;
        try {
          const rows = JSON.parse(s.getItem(key) ?? "[]");
          if (!Array.isArray(rows)) {
            stale.push(key);
            continue;
          }
          for (const row of rows) {
            if (!Array.isArray(row) || typeof row[0] !== "string" || typeof row[1] !== "number") continue;
            if (now - row[1] > TTL_MS) continue;
            out.add(row[0]);
            anyFresh = true;
          }
        } catch {
          stale.push(key);
          continue;
        }
        if (!anyFresh) stale.push(key);
      }
      for (const k of stale) {
        try {
          s.removeItem(k);
        } catch {
        }
      }
    } catch {
    }
    return out;
  }
};

export { LocalStorageReservationMirror, UtxoReservationRegistry };
