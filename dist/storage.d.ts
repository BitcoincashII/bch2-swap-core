interface StorageLike {
    getItem(key: string): string | null;
    setItem(key: string, value: string): void;
    removeItem(key: string): void;
}
interface DurableStore {
    get(key: string): Promise<string | null>;
    set(key: string, value: string): Promise<void>;
    remove(key: string): Promise<void>;
    commit(entries: Array<[string, string]>): Promise<void>;
}
declare class InMemoryDurableStore implements DurableStore {
    private readonly m;
    get(key: string): Promise<string | null>;
    set(key: string, value: string): Promise<void>;
    remove(key: string): Promise<void>;
    commit(entries: Array<[string, string]>): Promise<void>;
}
declare class LocalStorageDurableStore implements DurableStore {
    private readonly s;
    constructor(storage?: StorageLike);
    get(key: string): Promise<string | null>;
    remove(key: string): Promise<void>;
    set(key: string, value: string): Promise<void>;
    commit(entries: Array<[string, string]>): Promise<void>;
}
interface SessionStore {
    get(key: string): Promise<string | null>;
    set(key: string, value: string): Promise<void>;
    remove(key: string): Promise<void>;
}
declare class InMemorySessionStore implements SessionStore {
    private readonly m;
    get(key: string): Promise<string | null>;
    set(key: string, value: string): Promise<void>;
    remove(key: string): Promise<void>;
}
declare class WindowSessionStore implements SessionStore {
    private readonly s;
    constructor(storage?: StorageLike);
    get(key: string): Promise<string | null>;
    set(key: string, value: string): Promise<void>;
    remove(key: string): Promise<void>;
}
interface Mutex {
    withLock<T>(name: string, fn: () => Promise<T> | T): Promise<T>;
}
declare class MutexBusyError extends Error {
    readonly mutexBusy: true;
    constructor(name: string, scope: 'in-process' | 'cross-process' | 'cross-tab');
}
declare class InProcessMutex implements Mutex {
    private readonly tails;
    private readonly store?;
    private readonly ttlMs;
    private readonly token;
    private readonly now;
    private readonly settle;
    constructor(opts?: {
        store?: DurableStore;
        ttlMs?: number;
        token?: string;
        now?: () => number;
        settle?: () => Promise<void>;
    });
    withLock<T>(name: string, fn: () => Promise<T> | T): Promise<T>;
    private guarded;
}
interface WebLocksLike {
    request<T>(name: string, cb: () => Promise<T>): Promise<T>;
}
declare class BrowserMutex implements Mutex {
    private readonly token;
    private readonly ttlMs;
    private readonly ls?;
    private readonly locks?;
    constructor(opts?: {
        token?: string;
        ttlMs?: number;
        localStorage?: StorageLike;
        locks?: WebLocksLike | null;
    });
    withLock<T>(name: string, fn: () => Promise<T> | T): Promise<T>;
}

export { BrowserMutex, type DurableStore, InMemoryDurableStore, InMemorySessionStore, InProcessMutex, LocalStorageDurableStore, type Mutex, MutexBusyError, type SessionStore, type StorageLike, type WebLocksLike, WindowSessionStore };
