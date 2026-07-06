/**
 * Swap record persistence.
 *
 * Port of swapengine/persist.go. localStorage replaces the atomic file-per-swap
 * pattern (tmp→rename). localStorage.setItem is synchronous and either
 * completes atomically or throws — it does NOT partially write. However, a
 * process crash can interrupt JS execution before setItem is called, leaving
 * the record at a prior state. This is the same behaviour as Go's atomic
 * rename: a crash before the rename leaves the old file. The recovery path
 * (recover.ts) handles this by resuming from the last persisted state.
 *
 * loadSwapRecords skips any entry that fails JSON.parse or is missing required
 * fields — same as Go's "skip corrupt files silently" behaviour.
 *
 * ATOMICITY NOTE: unlike Go's rename(2), localStorage does not provide POSIX
 * durability guarantees. In practice, browsers journal localStorage writes, but
 * callers should not rely on durability across hard resets. For production use,
 * IndexedDB with explicit transactions would offer stronger guarantees.
 */

import { State, Role } from './state';

/** JSON-serialisable snapshot of engine state — mirrors Go's SwapRecord struct. */
export interface SwapRecord {
  swapID:              string;
  role:                Role;
  state:               State;
  hashLock:            string;   // 64 hex chars
  ourPrivKey:          string;   // 64 hex chars
  ourPubKey:           string;   // 66 hex chars
  counterPubKey:       string;   // 66 hex chars or ''
  ourCSVNSequence:     number;
  counterCSVNSequence: number;
  ourAmountSat:        number;
  counterAmountSat:    number;
  minConfirmations:    number;
  feeSatoshis:         number;
  ourFundTxid:         string;
  counterFundTxid:     string;
  secret:              string;   // 64 hex chars or ''
  htlcScriptHash:      string;   // 40 hex chars or ''
}

/** Storage abstraction — injectable for tests (MemorySwapStorage) vs production (LocalSwapStorage). */
export interface SwapStorage {
  save(swapID: string, record: SwapRecord): void;
  load(swapID: string): SwapRecord | null;
  loadAll(): SwapRecord[];
  delete(swapID: string): void;
}

/** Production implementation — uses localStorage. */
export class LocalSwapStorage implements SwapStorage {
  private readonly prefix = 'bch2swap:';

  save(swapID: string, record: SwapRecord): void {
    localStorage.setItem(this.prefix + swapID, JSON.stringify(record));
  }

  load(swapID: string): SwapRecord | null {
    const raw = localStorage.getItem(this.prefix + swapID);
    if (raw == null) return null;
    return parseRecord(raw);
  }

  loadAll(): SwapRecord[] {
    const records: SwapRecord[] = [];
    for (let i = 0; i < localStorage.length; i++) {
      const key = localStorage.key(i);
      if (!key?.startsWith(this.prefix)) continue;
      const raw = localStorage.getItem(key);
      if (!raw) continue;
      const rec = parseRecord(raw);
      if (rec) records.push(rec);
    }
    return records;
  }

  delete(swapID: string): void {
    localStorage.removeItem(this.prefix + swapID);
  }
}

/** In-memory implementation for tests — mirrors Go TempDir pattern. */
export class MemorySwapStorage implements SwapStorage {
  private store = new Map<string, SwapRecord>();

  save(swapID: string, record: SwapRecord): void {
    // Deep-copy so that subsequent mutations of the engine don't corrupt the stored record.
    this.store.set(swapID, JSON.parse(JSON.stringify(record)) as SwapRecord);
  }

  load(swapID: string): SwapRecord | null {
    const rec = this.store.get(swapID);
    if (!rec) return null;
    return JSON.parse(JSON.stringify(rec)) as SwapRecord;
  }

  loadAll(): SwapRecord[] {
    return Array.from(this.store.values())
      .map(r => JSON.parse(JSON.stringify(r)) as SwapRecord)
      .filter(isValidRecord);
  }

  delete(swapID: string): void {
    this.store.delete(swapID);
  }

  /** Expose underlying map size for test assertions. */
  size(): number {
    return this.store.size;
  }
}

/**
 * Returns all valid records from storage, silently skipping corrupt or
 * incomplete entries (mirrors Go's LoadSwapRecords corrupt-file skipping).
 */
export function loadSwapRecords(storage: SwapStorage): SwapRecord[] {
  return storage.loadAll();
}

/** Removes the persisted record for swapID. */
export function deleteSwapRecord(storage: SwapStorage, swapID: string): void {
  storage.delete(swapID);
}

// ── Internal helpers ──────────────────────────────────────────────────────────

function parseRecord(raw: string): SwapRecord | null {
  try {
    const rec = JSON.parse(raw) as Partial<SwapRecord>;
    if (!isValidRecord(rec)) return null;
    return rec as SwapRecord;
  } catch {
    return null;
  }
}

function isValidRecord(r: Partial<SwapRecord>): boolean {
  return (
    typeof r.swapID        === 'string' && r.swapID !== '' &&
    typeof r.ourPrivKey    === 'string' && r.ourPrivKey !== '' &&
    typeof r.ourPubKey     === 'string' && r.ourPubKey !== '' &&
    typeof r.hashLock      === 'string' && r.hashLock !== '' &&
    typeof r.role          === 'number' &&
    typeof r.state         === 'number'
  );
}
