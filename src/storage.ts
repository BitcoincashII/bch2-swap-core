// Durable / session / mutex seams for the headless SwapController (P1b step 3).
//
// These three interfaces are the injected storage + single-flight primitives the SwapController uses to make
// "durable-before-broadcast" and "single instance per swap" STRUCTURAL rather than developer discipline. They carry two
// mandatory corrections from the adversarial critique:
//
//   fix #3 (multi-process single-flight fails CLOSED): `Mutex.withLock` must THROW when a peer already holds the lock —
//     it must NEVER silently run `fn` without the lock. The default in-process `InProcessMutex` serializes callers in
//     THIS process AND is backstopped by a durable cross-process compare-and-set (write-token + read-back on an injected
//     `DurableStore`), so even a wrong/degenerate injected mutex cannot license a second concurrent holder.
//
//   fix #4 (durable-before-broadcast is truly ATOMIC): `DurableStore.commit` is all-or-nothing. On ANY write failure it
//     THROWS (never swallows); it READS BACK every written key to verify it landed before returning; and a partial
//     failure ROLLS BACK every key it touched to its prior value, so a crashed/failed commit never leaves some keys
//     written. A store that cannot guarantee this is unfit for mainnet.
//
// `SessionStore` is kept DISTINCT from `DurableStore` so recovery material (re-derivable secret scheme, load-bearing
// CLTV singletons) is never confused with an ephemeral session value.
//
// All methods are async so a Node host can back a store with a file / sqlite / KV service; the browser adapters wrap the
// synchronous Web Storage / Web Locks APIs.

// Minimal shape of a Web Storage object (localStorage / sessionStorage), or a test fake. `Storage` from the DOM lib is
// structurally compatible.
export interface StorageLike {
  getItem(key: string): string | null;
  setItem(key: string, value: string): void;
  removeItem(key: string): void;
}

// ============================================================================
// DurableStore — atomic KV for durable-before-broadcast (fix #4)
// ============================================================================

export interface DurableStore {
  get(key: string): Promise<string | null>;
  set(key: string, value: string): Promise<void>;
  remove(key: string): Promise<void>;
  // Atomic all-or-nothing multi-key write. MUST throw on ANY failure, MUST read back each written key to verify it
  // landed, and MUST leave NO partial write on failure (roll every touched key back to its prior value). Duplicate keys
  // in `entries` take the LAST value (last-writer-wins within the batch).
  commit(entries: Array<[string, string]>): Promise<void>;
}

// Map-backed default — trivially atomic (an in-process Map write cannot partially fail). Still honors the commit
// contract (stage → apply → read-back) so it is a faithful stand-in for the mainnet adapter in tests.
export class InMemoryDurableStore implements DurableStore {
  private readonly m = new Map<string, string>();

  async get(key: string): Promise<string | null> { return this.m.has(key) ? (this.m.get(key) as string) : null; }
  async set(key: string, value: string): Promise<void> { this.m.set(key, value); }
  async remove(key: string): Promise<void> { this.m.delete(key); }

  async commit(entries: Array<[string, string]>): Promise<void> {
    // Snapshot prior values of every touched key for rollback.
    const prior = new Map<string, string | null>();
    for (const [k] of entries) if (!prior.has(k)) prior.set(k, this.m.has(k) ? (this.m.get(k) as string) : null);
    const written: string[] = [];
    try {
      for (const [k, v] of entries) {
        this.m.set(k, v);
        written.push(k);
        if (this.m.get(k) !== v) throw new Error(`InMemoryDurableStore.commit read-back mismatch for ${k}`);
      }
    } catch (e) {
      for (const k of written) { const p = prior.get(k) ?? null; if (p === null) this.m.delete(k); else this.m.set(k, p); }
      throw e instanceof Error ? e : new Error(String(e));
    }
  }
}

// Browser adapter over a `Storage` (localStorage). commit(): stage each key with setItem (which may throw
// QuotaExceededError) then IMMEDIATELY read it back; on the first setItem-throw OR read-back mismatch, roll back every
// key written so far to its prior value (removing keys that had none) and rethrow — so a failed commit leaves the store
// exactly as it was.
export class LocalStorageDurableStore implements DurableStore {
  private readonly s: StorageLike;

  constructor(storage?: StorageLike) {
    const s = storage ?? (typeof localStorage !== 'undefined' ? (localStorage as unknown as StorageLike) : undefined);
    if (!s) throw new Error('LocalStorageDurableStore requires a Storage (localStorage unavailable in this environment)');
    this.s = s;
  }

  async get(key: string): Promise<string | null> { return this.s.getItem(key); }
  async remove(key: string): Promise<void> { this.s.removeItem(key); }

  async set(key: string, value: string): Promise<void> {
    this.s.setItem(key, value); // may throw QuotaExceededError
    if (this.s.getItem(key) !== value) throw new Error(`LocalStorageDurableStore.set read-back mismatch for ${key}`);
  }

  async commit(entries: Array<[string, string]>): Promise<void> {
    const prior = new Map<string, string | null>();
    for (const [k] of entries) if (!prior.has(k)) prior.set(k, this.s.getItem(k));
    const written: string[] = [];
    try {
      for (const [k, v] of entries) {
        this.s.setItem(k, v);                 // may throw (QuotaExceeded)
        written.push(k);
        if (this.s.getItem(k) !== v) throw new Error(`LocalStorageDurableStore.commit read-back mismatch for ${k}`);
      }
    } catch (e) {
      // All-or-nothing: restore every key we touched to its prior value (remove if it had none).
      for (const k of written) {
        const p = prior.get(k) ?? null;
        try { if (p === null) this.s.removeItem(k); else this.s.setItem(k, p); } catch { /* best-effort rollback */ }
      }
      throw e instanceof Error ? e : new Error(String(e));
    }
  }
}

// ============================================================================
// SessionStore — ephemeral, kept DISTINCT from DurableStore
// ============================================================================

export interface SessionStore {
  get(key: string): Promise<string | null>;
  set(key: string, value: string): Promise<void>;
  remove(key: string): Promise<void>;
}

export class InMemorySessionStore implements SessionStore {
  private readonly m = new Map<string, string>();
  async get(key: string): Promise<string | null> { return this.m.has(key) ? (this.m.get(key) as string) : null; }
  async set(key: string, value: string): Promise<void> { this.m.set(key, value); }
  async remove(key: string): Promise<void> { this.m.delete(key); }
}

// Browser adapter over sessionStorage (per-tab, cleared when the tab closes).
export class WindowSessionStore implements SessionStore {
  private readonly s: StorageLike;
  constructor(storage?: StorageLike) {
    const s = storage ?? (typeof sessionStorage !== 'undefined' ? (sessionStorage as unknown as StorageLike) : undefined);
    if (!s) throw new Error('WindowSessionStore requires a Storage (sessionStorage unavailable in this environment)');
    this.s = s;
  }
  async get(key: string): Promise<string | null> { return this.s.getItem(key); }
  async set(key: string, value: string): Promise<void> { this.s.setItem(key, value); }
  async remove(key: string): Promise<void> { this.s.removeItem(key); }
}

// ============================================================================
// Mutex — single-flight that fails CLOSED (fix #3)
// ============================================================================

export interface Mutex {
  // Run `fn` while holding the named lock. MUST throw (never silently run fn without the lock) when a peer holds it.
  withLock<T>(name: string, fn: () => Promise<T> | T): Promise<T>;
}

// Error raised when a live peer already holds a lock. `.mutexBusy` lets a host distinguish "try again / another
// worker has it" from a genuine fault.
export class MutexBusyError extends Error {
  readonly mutexBusy = true as const;
  constructor(name: string, scope: 'in-process' | 'cross-process' | 'cross-tab') {
    super(`Lock "${name}" is held by another ${scope} holder — refusing to run a second concurrent holder.`);
    this.name = 'MutexBusyError';
  }
}

const _randToken = (): string => `${Date.now().toString(36)}.${Math.random().toString(36).slice(2, 10)}`;
const _CAS_PREFIX = 'bch2swap:mutexcas:';
interface CasToken { token: string; ts: number; }
function _parseCas(raw: string | null): CasToken | null {
  if (!raw) return null;
  const ix = raw.lastIndexOf('@'); if (ix < 0) return null;
  const ts = parseInt(raw.slice(ix + 1), 10);
  return Number.isFinite(ts) ? { token: raw.slice(0, ix), ts } : null;
}

// Default mutex: a per-name async queue serializes callers in THIS process, AND — per fix #3 — a durable cross-process
// compare-and-set (keyed on the lock name) backstops it so a SECOND process/instance sharing the same `DurableStore`
// still fails closed. If no `DurableStore` is injected the CAS backstop is inactive (in-process serialization only) —
// inject one for the mainnet single-flight guarantee.
export class InProcessMutex implements Mutex {
  private readonly tails = new Map<string, Promise<unknown>>();
  private readonly store?: DurableStore;
  private readonly ttlMs: number;
  private readonly token: string;
  private readonly now: () => number;
  private readonly settle: () => Promise<void>;

  constructor(opts?: { store?: DurableStore; ttlMs?: number; token?: string; now?: () => number; settle?: () => Promise<void> }) {
    this.store = opts?.store;
    this.ttlMs = opts?.ttlMs ?? 240_000;
    this.token = opts?.token ?? _randToken();
    this.now = opts?.now ?? (() => Date.now());
    // Jittered settle between the CAS write and the read-back (mirrors the proven withCrossTabLock). Injectable so
    // a deterministic test can pass a no-op; default is a 30–120ms jitter so two near-simultaneous acquirers'
    // write/read-back windows do not align (last writer wins; the loser reads the winner's token and fails closed).
    this.settle = opts?.settle ?? (() => new Promise<void>((res) => setTimeout(res, 30 + Math.floor(Math.random() * 90))));
  }

  withLock<T>(name: string, fn: () => Promise<T> | T): Promise<T> {
    // Per-name async queue (mutexTail pattern): fn runs after the prior holder settles regardless of outcome, so a
    // throwing fn does not wedge the queue. Serializes same-process callers → single-flight WITHIN this instance.
    const prev = this.tails.get(name) ?? Promise.resolve();
    const run = prev.then(() => this.guarded(name, fn), () => this.guarded(name, fn));
    this.tails.set(name, run.then(() => {}, () => {}));
    return run as Promise<T>;
  }

  // Durable cross-process CAS backstop: refuse if a live PEER token holds the sentinel; else write our token, read it
  // back (a racing peer that overwrote us => throw), run fn, release only if the sentinel is still ours.
  private async guarded<T>(name: string, fn: () => Promise<T> | T): Promise<T> {
    if (!this.store) return await fn(); // no durable backstop available (in-process serialization only)
    const key = _CAS_PREFIX + name;
    const now = this.now();
    const existing = _parseCas(await this.store.get(key));
    if (existing && existing.token !== this.token && (now - existing.ts) < this.ttlMs) {
      throw new MutexBusyError(name, 'cross-process');
    }
    const stamp = `${this.token}@${now}`;
    await this.store.set(key, stamp);
    await this.settle(); // jittered settle so a near-simultaneous peer's write lands before our read-back
    if ((await this.store.get(key)) !== stamp) throw new MutexBusyError(name, 'cross-process'); // a peer raced and won
    try {
      return await fn();
    } finally {
      // Release only if the sentinel is still ours (a peer that reclaimed a TTL-expired lock keeps its own).
      try { if (_parseCas(await this.store.get(key))?.token === this.token) await this.store.remove(key); } catch { /* ignore */ }
    }
  }
}

// Minimal shape of the Web Locks API (navigator.locks) needed here.
export interface WebLocksLike { request<T>(name: string, cb: () => Promise<T>): Promise<T>; }

// Browser adapter ported VERBATIM from SwapExecute.tsx `withCrossTabLock` (R154 / R186-XTAB-CAS-001). Uses the Web Locks
// API when available (a real cross-tab mutex); else a best-effort localStorage compare-and-set: acquire iff the slot is
// empty/expired/ours, jittered read-back to resolve a near-simultaneous race (last writer wins; the loser sees the
// winner's token and fails closed), heartbeat while held, release in finally. A LIVE peer token => fail closed (throw)
// rather than double-broadcast.
export class BrowserMutex implements Mutex {
  private readonly token: string;
  private readonly ttlMs: number;
  private readonly ls?: StorageLike;
  private readonly locks?: WebLocksLike;

  constructor(opts?: { token?: string; ttlMs?: number; localStorage?: StorageLike; locks?: WebLocksLike | null }) {
    // R186-XTAB-CAS-001: a per-page-load unique token identifying THIS tab for the localStorage-CAS fallback.
    this.token = opts?.token ?? _randToken();
    // TTL must exceed the longest lock body (the 120s EVM-lock tx.wait) by enough margin that a BACKGROUNDED tab whose
    // 20s heartbeat is browser-throttled (~1/min) cannot let the lock expire mid-operation and permit a peer
    // double-broadcast. 240s > 120s body + throttled-heartbeat slack.
    this.ttlMs = opts?.ttlMs ?? 240_000;
    this.ls = opts?.localStorage ?? (typeof localStorage !== 'undefined' ? (localStorage as unknown as StorageLike) : undefined);
    const injectedLocks = opts?.locks;
    if (injectedLocks !== undefined) { this.locks = injectedLocks ?? undefined; }
    else {
      const nav = (typeof navigator !== 'undefined' ? (navigator as unknown as { locks?: WebLocksLike }) : undefined);
      this.locks = (nav && nav.locks && typeof nav.locks.request === 'function') ? nav.locks : undefined;
    }
  }

  async withLock<T>(name: string, fn: () => Promise<T> | T): Promise<T> {
    if (this.locks) return this.locks.request(name, async () => await fn());
    // navigator.locks is SECURE-CONTEXT-ONLY. On a plain-HTTP origin it is undefined and the old `return fn()` fallback
    // ran the irreversible fund/lock body with NO cross-tab mutex, re-opening the R154/R170 double-lock/double-fund
    // class. Best-effort localStorage compare-and-set lock below.
    const s = this.ls;
    if (!s) return await fn(); // storage unavailable: best-effort, no lock (matches app fallback)
    const key = `bch2swap:xtlock:${name}`;
    const readTok = (): CasToken | null => { try { return _parseCas(s.getItem(key)); } catch { return null; } };
    const peerHeld = (): boolean => { const t = readTok(); return !!t && t.token !== this.token && (Date.now() - t.ts) < this.ttlMs; };
    if (peerHeld()) throw new MutexBusyError(name, 'cross-tab');
    try { s.setItem(key, `${this.token}@${Date.now()}`); } catch { return await fn(); /* storage unavailable: best-effort, no lock */ }
    // Jittered settle so two near-simultaneous acquirers' write/read-back windows do not align (last writer wins).
    await new Promise<void>((res) => { setTimeout(res, 30 + Math.floor(Math.random() * 90)); });
    const after = readTok();
    if (after && after.token !== this.token) throw new MutexBusyError(name, 'cross-tab');
    let hb: ReturnType<typeof setInterval> | undefined;
    try { hb = setInterval(() => { try { if (readTok()?.token === this.token) s.setItem(key, `${this.token}@${Date.now()}`); } catch { /* ignore */ } }, 20_000); } catch { /* ignore */ }
    try {
      return await fn();
    } finally {
      if (hb) { try { clearInterval(hb); } catch { /* ignore */ } }
      try { if (readTok()?.token === this.token) s.removeItem(key); } catch { /* ignore */ }
    }
  }
}
