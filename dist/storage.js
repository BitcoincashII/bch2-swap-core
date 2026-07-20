// src/storage.ts
var InMemoryDurableStore = class {
  constructor() {
    this.m = /* @__PURE__ */ new Map();
  }
  async get(key) {
    return this.m.has(key) ? this.m.get(key) : null;
  }
  async set(key, value) {
    this.m.set(key, value);
  }
  async remove(key) {
    this.m.delete(key);
  }
  async commit(entries) {
    const prior = /* @__PURE__ */ new Map();
    for (const [k] of entries) if (!prior.has(k)) prior.set(k, this.m.has(k) ? this.m.get(k) : null);
    const written = [];
    try {
      for (const [k, v] of entries) {
        this.m.set(k, v);
        written.push(k);
        if (this.m.get(k) !== v) throw new Error(`InMemoryDurableStore.commit read-back mismatch for ${k}`);
      }
    } catch (e) {
      for (const k of written) {
        const p = prior.get(k) ?? null;
        if (p === null) this.m.delete(k);
        else this.m.set(k, p);
      }
      throw e instanceof Error ? e : new Error(String(e));
    }
  }
};
var LocalStorageDurableStore = class {
  constructor(storage) {
    const s = storage ?? (typeof localStorage !== "undefined" ? localStorage : void 0);
    if (!s) throw new Error("LocalStorageDurableStore requires a Storage (localStorage unavailable in this environment)");
    this.s = s;
  }
  async get(key) {
    return this.s.getItem(key);
  }
  async remove(key) {
    this.s.removeItem(key);
  }
  async set(key, value) {
    this.s.setItem(key, value);
    if (this.s.getItem(key) !== value) throw new Error(`LocalStorageDurableStore.set read-back mismatch for ${key}`);
  }
  async commit(entries) {
    const prior = /* @__PURE__ */ new Map();
    for (const [k] of entries) if (!prior.has(k)) prior.set(k, this.s.getItem(k));
    const written = [];
    try {
      for (const [k, v] of entries) {
        this.s.setItem(k, v);
        written.push(k);
        if (this.s.getItem(k) !== v) throw new Error(`LocalStorageDurableStore.commit read-back mismatch for ${k}`);
      }
    } catch (e) {
      for (const k of written) {
        const p = prior.get(k) ?? null;
        try {
          if (p === null) this.s.removeItem(k);
          else this.s.setItem(k, p);
        } catch {
        }
      }
      throw e instanceof Error ? e : new Error(String(e));
    }
  }
};
var InMemorySessionStore = class {
  constructor() {
    this.m = /* @__PURE__ */ new Map();
  }
  async get(key) {
    return this.m.has(key) ? this.m.get(key) : null;
  }
  async set(key, value) {
    this.m.set(key, value);
  }
  async remove(key) {
    this.m.delete(key);
  }
};
var WindowSessionStore = class {
  constructor(storage) {
    const s = storage ?? (typeof sessionStorage !== "undefined" ? sessionStorage : void 0);
    if (!s) throw new Error("WindowSessionStore requires a Storage (sessionStorage unavailable in this environment)");
    this.s = s;
  }
  async get(key) {
    return this.s.getItem(key);
  }
  async set(key, value) {
    this.s.setItem(key, value);
  }
  async remove(key) {
    this.s.removeItem(key);
  }
};
var MutexBusyError = class extends Error {
  constructor(name, scope) {
    super(`Lock "${name}" is held by another ${scope} holder \u2014 refusing to run a second concurrent holder.`);
    this.mutexBusy = true;
    this.name = "MutexBusyError";
  }
};
var _randToken = () => `${Date.now().toString(36)}.${Math.random().toString(36).slice(2, 10)}`;
var _CAS_PREFIX = "bch2swap:mutexcas:";
function _parseCas(raw) {
  if (!raw) return null;
  const ix = raw.lastIndexOf("@");
  if (ix < 0) return null;
  const ts = parseInt(raw.slice(ix + 1), 10);
  return Number.isFinite(ts) ? { token: raw.slice(0, ix), ts } : null;
}
var InProcessMutex = class {
  constructor(opts) {
    this.tails = /* @__PURE__ */ new Map();
    this.store = opts?.store;
    this.ttlMs = opts?.ttlMs ?? 24e4;
    this.token = opts?.token ?? _randToken();
    this.now = opts?.now ?? (() => Date.now());
    this.settle = opts?.settle ?? (() => new Promise((res) => setTimeout(res, 30 + Math.floor(Math.random() * 90))));
  }
  withLock(name, fn) {
    const prev = this.tails.get(name) ?? Promise.resolve();
    const run = prev.then(() => this.guarded(name, fn), () => this.guarded(name, fn));
    this.tails.set(name, run.then(() => {
    }, () => {
    }));
    return run;
  }
  // Durable cross-process CAS backstop: refuse if a live PEER token holds the sentinel; else write our token, read it
  // back (a racing peer that overwrote us => throw), run fn, release only if the sentinel is still ours.
  async guarded(name, fn) {
    if (!this.store) return await fn();
    const key = _CAS_PREFIX + name;
    const now = this.now();
    const existing = _parseCas(await this.store.get(key));
    if (existing && existing.token !== this.token && now - existing.ts < this.ttlMs) {
      throw new MutexBusyError(name, "cross-process");
    }
    const stamp = `${this.token}@${now}`;
    await this.store.set(key, stamp);
    await this.settle();
    if (await this.store.get(key) !== stamp) throw new MutexBusyError(name, "cross-process");
    try {
      return await fn();
    } finally {
      try {
        if (_parseCas(await this.store.get(key))?.token === this.token) await this.store.remove(key);
      } catch {
      }
    }
  }
};
var BrowserMutex = class {
  constructor(opts) {
    this.token = opts?.token ?? _randToken();
    this.ttlMs = opts?.ttlMs ?? 24e4;
    this.ls = opts?.localStorage ?? (typeof localStorage !== "undefined" ? localStorage : void 0);
    const injectedLocks = opts?.locks;
    if (injectedLocks !== void 0) {
      this.locks = injectedLocks ?? void 0;
    } else {
      const nav = typeof navigator !== "undefined" ? navigator : void 0;
      this.locks = nav && nav.locks && typeof nav.locks.request === "function" ? nav.locks : void 0;
    }
  }
  async withLock(name, fn) {
    if (this.locks) return this.locks.request(name, async () => await fn());
    const s = this.ls;
    if (!s) return await fn();
    const key = `bch2swap:xtlock:${name}`;
    const readTok = () => {
      try {
        return _parseCas(s.getItem(key));
      } catch {
        return null;
      }
    };
    const peerHeld = () => {
      const t = readTok();
      return !!t && t.token !== this.token && Date.now() - t.ts < this.ttlMs;
    };
    if (peerHeld()) throw new MutexBusyError(name, "cross-tab");
    try {
      s.setItem(key, `${this.token}@${Date.now()}`);
    } catch {
      return await fn();
    }
    await new Promise((res) => {
      setTimeout(res, 30 + Math.floor(Math.random() * 90));
    });
    const after = readTok();
    if (after && after.token !== this.token) throw new MutexBusyError(name, "cross-tab");
    let hb;
    try {
      hb = setInterval(() => {
        try {
          if (readTok()?.token === this.token) s.setItem(key, `${this.token}@${Date.now()}`);
        } catch {
        }
      }, 2e4);
    } catch {
    }
    try {
      return await fn();
    } finally {
      if (hb) {
        try {
          clearInterval(hb);
        } catch {
        }
      }
      try {
        if (readTok()?.token === this.token) s.removeItem(key);
      } catch {
      }
    }
  }
};

export { BrowserMutex, InMemoryDurableStore, InMemorySessionStore, InProcessMutex, LocalStorageDurableStore, MutexBusyError, WindowSessionStore };
