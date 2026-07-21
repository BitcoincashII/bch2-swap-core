import { describe, it, expect, vi } from 'vitest';
import {
  InMemoryDurableStore,
  LocalStorageDurableStore,
  InMemorySessionStore,
  WindowSessionStore,
  InProcessMutex,
  BrowserMutex,
  MutexBusyError,
  MutexUnavailableError,
  DurableStoreInconsistentError,
  type DurableStore,
  type StorageLike,
} from './storage';

// A configurable fake Web Storage: can throw on the Nth setItem (QuotaExceeded) or SILENTLY DROP a key (forces a
// read-back mismatch). Tracks the raw map so tests can assert exactly which keys survived.
function makeFakeStorage(opts?: { throwOnNthSet?: number; dropKey?: string }) {
  const m = new Map<string, string>();
  let sets = 0;
  const s: StorageLike & { _m: Map<string, string> } = {
    _m: m,
    getItem(k: string) { return m.has(k) ? (m.get(k) as string) : null; },
    setItem(k: string, v: string) {
      sets++;
      if (opts?.throwOnNthSet && sets === opts.throwOnNthSet) throw new Error('QuotaExceededError');
      if (opts?.dropKey === k) return; // silently drop → read-back will mismatch
      m.set(k, String(v));
    },
    removeItem(k: string) { m.delete(k); },
  };
  return s;
}

const present = (s: { _m: Map<string, string> }, batch: Array<[string, string]>) => batch.filter(([k]) => s._m.has(k)).map(([k]) => k);

// ============================================================================
// (b) DurableStore.commit — atomic, throw + read-back, no partial write (fix #4)
// ============================================================================

describe('DurableStore.commit — atomic all-or-nothing (fix #4)', () => {
  it('InMemoryDurableStore: a clean commit lands every key (read-back verified)', async () => {
    const store = new InMemoryDurableStore();
    await store.commit([['a', '1'], ['b', '2'], ['c', '3']]);
    expect(await store.get('a')).toBe('1');
    expect(await store.get('b')).toBe('2');
    expect(await store.get('c')).toBe('3');
  });

  it('LocalStorageDurableStore: a clean commit lands every key', async () => {
    const fake = makeFakeStorage();
    const store = new LocalStorageDurableStore(fake);
    const batch: Array<[string, string]> = [['k1', 'v1'], ['k2', 'v2'], ['k3', 'v3']];
    await store.commit(batch);
    expect(present(fake, batch).sort()).toEqual(['k1', 'k2', 'k3']);
  });

  it('THROWS + leaves NO partial write when the 2nd setItem throws (QuotaExceeded); already-written key rolled back', async () => {
    const fake = makeFakeStorage({ throwOnNthSet: 2 });
    const store = new LocalStorageDurableStore(fake);
    const batch: Array<[string, string]> = [['k1', 'v1'], ['k2', 'v2'], ['k3', 'v3']];
    await expect(store.commit(batch)).rejects.toThrow(/QuotaExceeded/);
    expect(present(fake, batch)).toEqual([]); // k1 written then rolled back; k2/k3 never written
  });

  it('THROWS + rolls back on a read-back MISMATCH (a silently-dropped key)', async () => {
    const fake = makeFakeStorage({ dropKey: 'k2' });
    const store = new LocalStorageDurableStore(fake);
    const batch: Array<[string, string]> = [['k1', 'v1'], ['k2', 'v2'], ['k3', 'v3']];
    await expect(store.commit(batch)).rejects.toThrow(/read-back mismatch/);
    expect(present(fake, batch)).toEqual([]); // k1 rolled back; k2 dropped; k3 never reached
  });

  it('rollback RESTORES a prior value (not just removes) when a key pre-existed', async () => {
    const fake = makeFakeStorage({ throwOnNthSet: 2 });
    fake.setItem('k1', 'OLD'); // k1 already has a durable value before the commit
    const store = new LocalStorageDurableStore(fake);
    await expect(store.commit([['k1', 'NEW'], ['k2', 'v2']])).rejects.toThrow(/QuotaExceeded/);
    expect(fake.getItem('k1')).toBe('OLD'); // restored to its prior value, not left as NEW nor removed
    expect(fake.getItem('k2')).toBeNull();
  });

  it('rollback failure is OBSERVABLE: forward set throws AND the restore set throws too -> commit rejects signalling the inconsistent state (fix #3)', async () => {
    // A store where the forward write of k2 throws (QuotaExceeded) AND the rollback restore of k1 -> "OLD" ALSO throws.
    // Pre-fix the catch swallowed the restore throw and rethrew the ORIGINAL commit error, so the caller saw a plain
    // QuotaExceeded and could not tell the store was left partially written (k1 still holds NEW, not OLD).
    const m = new Map<string, string>();
    let phase: 'pre' | 'commit' = 'pre';
    const s: StorageLike & { _m: Map<string, string> } = {
      _m: m,
      getItem(k: string) { return m.has(k) ? (m.get(k) as string) : null; },
      setItem(k: string, v: string) {
        if (phase === 'commit') {
          if (k === 'k2') throw new Error('QuotaExceededError');            // forward write fails partway
          if (k === 'k1' && v === 'OLD') throw new Error('restore write also failed'); // rollback restore fails too
        }
        m.set(k, String(v));
      },
      removeItem(k: string) { m.delete(k); },
    };
    s.setItem('k1', 'OLD'); // durable prior value, written before the commit
    phase = 'commit';
    const store = new LocalStorageDurableStore(s);
    const err = await store.commit([['k1', 'NEW'], ['k2', 'v2']]).catch((e) => e);
    expect(err).toBeInstanceOf(DurableStoreInconsistentError);
    expect((err as DurableStoreInconsistentError).storeInconsistent).toBe(true);
    expect((err as DurableStoreInconsistentError).rollbackErrors.map((r) => r.key)).toEqual(['k1']);
    // The store really IS inconsistent: k1 could not be restored to OLD and still holds the half-committed NEW.
    expect(s.getItem('k1')).toBe('NEW');
  });

  it('LocalStorageDurableStore.set read-back-verifies a single write (throws on a dropped key)', async () => {
    const store = new LocalStorageDurableStore(makeFakeStorage({ dropKey: 'x' }));
    await expect(store.set('x', 'v')).rejects.toThrow(/read-back mismatch/);
  });

  it('constructor throws when no Storage is available (no silent no-op store)', () => {
    expect(() => new LocalStorageDurableStore(undefined)).toThrow(/requires a Storage/);
  });
});

// ============================================================================
// SessionStore — distinct ephemeral seam
// ============================================================================

describe('SessionStore', () => {
  it('InMemorySessionStore round-trips + removes', async () => {
    const s = new InMemorySessionStore();
    await s.set('a', '1');
    expect(await s.get('a')).toBe('1');
    await s.remove('a');
    expect(await s.get('a')).toBeNull();
  });

  it('WindowSessionStore wraps an injected sessionStorage', async () => {
    const fake = makeFakeStorage();
    const s = new WindowSessionStore(fake);
    await s.set('k', 'v');
    expect(await s.get('k')).toBe('v');
    expect(fake._m.get('k')).toBe('v');
  });
});

// ============================================================================
// (c) Mutex — single-flight that fails CLOSED + durable-CAS backstop (fix #3)
// ============================================================================

describe('InProcessMutex — single-flight (fix #3)', () => {
  it('serializes concurrent holders of the same name (never two concurrent bodies)', async () => {
    const mutex = new InProcessMutex({ store: new InMemoryDurableStore() });
    let active = 0, maxActive = 0;
    const body = async () => {
      active++; maxActive = Math.max(maxActive, active);
      await new Promise((r) => setTimeout(r, 10));
      active--;
      return true;
    };
    await Promise.all([mutex.withLock('s', body), mutex.withLock('s', body), mutex.withLock('s', body)]);
    expect(maxActive).toBe(1); // the queue admits exactly one holder at a time
  });

  it('a throwing body does NOT wedge the queue (next holder still runs)', async () => {
    const mutex = new InProcessMutex({ store: new InMemoryDurableStore() });
    await expect(mutex.withLock('s', async () => { throw new Error('boom'); })).rejects.toThrow('boom');
    expect(await mutex.withLock('s', async () => 'ok')).toBe('ok');
  });

  it('DURABLE-CAS BACKSTOP: throws when a LIVE peer token already holds the sentinel', async () => {
    const FIXED = 1_000_000;
    const store = new InMemoryDurableStore();
    await store.set('bch2swap:mutexcas:myswap', `peerToken@${FIXED}`); // a peer holds it, fresh
    const mutex = new InProcessMutex({ store, token: 'meToken', now: () => FIXED, ttlMs: 240_000 });
    let ran = false;
    await expect(mutex.withLock('myswap', async () => { ran = true; })).rejects.toBeInstanceOf(MutexBusyError);
    expect(ran).toBe(false); // fn NEVER runs without the lock
  });

  it('DURABLE-CAS BACKSTOP: a STALE peer token (past TTL) is reclaimable — does not block', async () => {
    const FIXED = 1_000_000;
    const store = new InMemoryDurableStore();
    await store.set('bch2swap:mutexcas:myswap', `peerToken@${FIXED - 300_000}`); // > 240s old
    const mutex = new InProcessMutex({ store, token: 'meToken', now: () => FIXED, ttlMs: 240_000 });
    expect(await mutex.withLock('myswap', async () => 'ok')).toBe('ok');
  });

  it('CROSS-INSTANCE: while instance A holds the lock, instance B (sharing the store) fails closed', async () => {
    const store = new InMemoryDurableStore();
    const a = new InProcessMutex({ store, token: 'A' });
    const b = new InProcessMutex({ store, token: 'B' });
    let release!: () => void;
    const held = new Promise<void>((r) => { release = r; });
    const aRun = a.withLock('x', async () => { await held; return 'a-done'; });
    await new Promise((r) => setTimeout(r, 15)); // let A write + hold its sentinel
    await expect(b.withLock('x', async () => 'b')).rejects.toBeInstanceOf(MutexBusyError);
    release();
    expect(await aRun).toBe('a-done');
    // After A releases the sentinel, B can acquire it.
    expect(await b.withLock('x', async () => 'b-later')).toBe('b-later');
  });

  it('LIVE-HOLDER HEARTBEAT: a body that OUTLASTS ttlMs stays un-stealable by a peer instance (renews the stamp) (fix #1)', async () => {
    vi.useFakeTimers();
    try {
      const store = new InMemoryDurableStore();
      let clock = 1_000_000;
      const now = () => clock;
      const settle = () => Promise.resolve();
      const ttlMs = 300; // heartbeat fires every ttlMs/3 = 100ms
      const a = new InProcessMutex({ store, token: 'A', ttlMs, now, settle });

      // A acquires and holds a body that runs far longer than ttlMs.
      let releaseA!: () => void;
      const held = new Promise<void>((r) => { releaseA = r; });
      const aRun = a.withLock('x', async () => { await held; return 'a-done'; });

      // Flush microtasks so A writes + reads back its stamp and starts its heartbeat, then advance the clock 600ms
      // (2x ttlMs) in lockstep with the fake timer so the heartbeat keeps renewing the stamp with a fresh timestamp.
      await vi.advanceTimersByTimeAsync(0);
      for (let i = 0; i < 6; i++) { clock += 100; await vi.advanceTimersByTimeAsync(100); }

      // Peer B (same store) tries to acquire at the current clock. Without renewal the stamp's ts would be 600ms stale
      // (> ttlMs) and B would steal it; WITH the heartbeat the stamp is fresh so B sees a LIVE peer and fails closed.
      const b = new InProcessMutex({ store, token: 'B', ttlMs, now, settle });
      let ranB = false;
      await expect(b.withLock('x', async () => { ranB = true; return 'b'; })).rejects.toBeInstanceOf(MutexBusyError);
      expect(ranB).toBe(false);

      releaseA();
      expect(await aRun).toBe('a-done');
    } finally {
      vi.useRealTimers();
    }
  });

  it('the MutexBusyError carries a .mutexBusy flag for host handling', async () => {
    const store = new InMemoryDurableStore();
    await store.set('bch2swap:mutexcas:z', `peer@${Date.now()}`);
    const mutex = new InProcessMutex({ store, token: 'me' });
    const err = await mutex.withLock('z', async () => 0).catch((e) => e);
    expect((err as MutexBusyError).mutexBusy).toBe(true);
  });
});

describe('BrowserMutex — ported cross-tab CAS (fix #3)', () => {
  it('uses navigator.locks when available (runs fn under the Web Lock)', async () => {
    let requested = '';
    const locks = { request: <T,>(name: string, cb: () => Promise<T>) => { requested = name; return cb(); } };
    const mutex = new BrowserMutex({ locks });
    expect(await mutex.withLock('n', async () => 42)).toBe(42);
    expect(requested).toBe('n');
  });

  it('localStorage-CAS fallback: FAILS CLOSED against a LIVE peer token (throws crossTabBusy)', async () => {
    const fake = makeFakeStorage();
    fake.setItem('bch2swap:xtlock:fund:offer1', `peerTok@${Date.now()}`); // a live peer holds it
    const mutex = new BrowserMutex({ locks: null, localStorage: fake, token: 'meTok' });
    let ran = false;
    const err = await mutex.withLock('fund:offer1', async () => { ran = true; }).catch((e) => e);
    expect(err).toBeInstanceOf(MutexBusyError);
    expect((err as MutexBusyError).mutexBusy).toBe(true);
    expect(ran).toBe(false);
  });

  it('localStorage-CAS fallback: acquires when free, runs fn, and releases the slot', async () => {
    const fake = makeFakeStorage();
    const mutex = new BrowserMutex({ locks: null, localStorage: fake, token: 'meTok' });
    const out = await mutex.withLock('fund:offer2', async () => 'done');
    expect(out).toBe('done');
    expect(fake.getItem('bch2swap:xtlock:fund:offer2')).toBeNull(); // released in finally
  });

  it('localStorage-CAS fallback: a STALE peer token (past TTL) does not block acquisition', async () => {
    const fake = makeFakeStorage();
    fake.setItem('bch2swap:xtlock:fund:offer3', `peerTok@${Date.now() - 300_000}`); // > 240s old
    const mutex = new BrowserMutex({ locks: null, localStorage: fake, token: 'meTok' });
    expect(await mutex.withLock('fund:offer3', async () => 'ok')).toBe('ok');
  });

  it('FAILS CLOSED when NO cross-tab lock medium is available (no Web Locks + no localStorage) — does NOT run fn (fix #2)', async () => {
    // A plain-HTTP origin with storage disabled: navigator.locks is undefined AND localStorage is unavailable. The old
    // fallback ran the irreversible fund/lock body with NO cross-tab lock; it must now throw instead.
    const mutex = new BrowserMutex({ locks: null, localStorage: undefined });
    let ran = false;
    const err = await mutex.withLock('fund:offer4', async () => { ran = true; return 'x'; }).catch((e) => e);
    expect(err).toBeInstanceOf(MutexUnavailableError);
    expect((err as MutexUnavailableError).mutexUnavailable).toBe(true);
    expect(ran).toBe(false);
  });

  it('FAILS CLOSED when the acquiring setItem throws (storage unusable) — does NOT run fn (fix #2)', async () => {
    // localStorage is present but every setItem throws (e.g. QuotaExceeded / disabled cookies). The old catch ran fn
    // with no lock; it must now throw instead.
    const throwingLs: StorageLike = {
      getItem() { return null; },              // slot reads empty -> no live peer, proceeds to acquire
      setItem() { throw new Error('setItem disabled'); },
      removeItem() { /* no-op */ },
    };
    const mutex = new BrowserMutex({ locks: null, localStorage: throwingLs, token: 'meTok' });
    let ran = false;
    const err = await mutex.withLock('fund:offer5', async () => { ran = true; return 'x'; }).catch((e) => e);
    expect(err).toBeInstanceOf(MutexUnavailableError);
    expect((err as MutexUnavailableError).mutexUnavailable).toBe(true);
    expect(ran).toBe(false);
  });
});

// A trivial compile-time check that the exported interface is what callers depend on.
const _typecheck: DurableStore = new InMemoryDurableStore();
void _typecheck;
