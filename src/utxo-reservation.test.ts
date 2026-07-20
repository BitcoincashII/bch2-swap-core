import { describe, it, expect, beforeEach } from 'vitest';
import {
  UtxoReservationRegistry,
  LocalStorageReservationMirror,
  type ResUtxo,
} from './utxo-reservation';

// A Map-backed fake Storage supporting the length/key(i) iteration LocalStorageReservationMirror.readOtherReserved uses
// to scan peer keys, plus get/set/remove.
function makeFakeStorage() {
  const m = new Map<string, string>();
  return {
    get length() { return m.size; },
    key(i: number) { return [...m.keys()][i] ?? null; },
    getItem(k: string) { return m.has(k) ? (m.get(k) as string) : null; },
    setItem(k: string, v: string) { m.set(k, String(v)); },
    removeItem(k: string) { m.delete(k); },
    clear() { m.clear(); },
  };
}

const u = (txid: string, vout: number, value: number, height = 100): ResUtxo => ({ tx_hash: txid, tx_pos: vout, value, height });
const keys = (arr: ResUtxo[]) => arr.map(x => `${x.tx_hash}:${x.tx_pos}`).sort();
const A = 'a'.repeat(64), B = 'b'.repeat(64), C = 'c'.repeat(64);

describe('UtxoReservationRegistry — parallel-funding double-spend prevention', () => {
  let reg: UtxoReservationRegistry;
  beforeEach(() => { reg = new UtxoReservationRegistry(); });

  it('SINGLE-SWAP NO-OP: with nothing reserved, candidates == the chain UTXOs', () => {
    const chain = [u(A, 0, 1000), u(B, 1, 2000)];
    expect(keys(reg.candidateUtxos('swap1', chain))).toEqual(keys(chain));
  });

  it('DISJOINT SELECTION: inputs reserved by another swap are excluded (the core anti-double-spend)', () => {
    const chain = [u(A, 0, 1000), u(B, 0, 2000), u(C, 0, 3000)];
    reg.reserveInputs('swap1', [u(A, 0, 1000)]);          // swap1 is funding with input A
    const forSwap2 = reg.candidateUtxos('swap2', chain);
    expect(keys(forSwap2)).toEqual([`${B}:0`, `${C}:0`]); // swap2 cannot see A
    expect(forSwap2.some(x => x.tx_hash === A)).toBe(false);
  });

  it('a swap STILL sees its OWN reserved inputs (retry-safe candidacy)', () => {
    const chain = [u(A, 0, 1000)];
    reg.reserveInputs('swap1', [u(A, 0, 1000)]);
    expect(keys(reg.candidateUtxos('swap1', chain))).toEqual([`${A}:0`]); // own reservation is not excluded
  });

  it('CHANGE-CHAINING: a swap can spend another in-flight funding 0-conf change (invisible to scantxoutset)', () => {
    const chain: ResUtxo[] = []; // single-UTXO maker: the wallet UTXO is already spent by swap1, scan shows nothing
    reg.reserveInputs('swap1', [u(A, 0, 5000)]);
    reg.recordChange('swap1', u(B, 1, 4000, 0));           // swap1's funding change (0-conf, height 0)
    const forSwap2 = reg.candidateUtxos('swap2', chain);
    expect(keys(forSwap2)).toEqual([`${B}:1`]);            // swap2 funds from swap1's change with no confirmation wait
  });

  it("a swap's change already re-spent by another is NOT offered again", () => {
    reg.reserveInputs('swap1', [u(A, 0, 5000)]);
    reg.recordChange('swap1', u(B, 1, 4000, 0));
    reg.reserveInputs('swap2', [u(B, 1, 4000)]);           // swap2 spent swap1's change
    expect(keys(reg.candidateUtxos('swap3', []))).toEqual([]); // swap3 sees neither A nor B
  });

  it('DEDUPE: a change that later confirms (now in chain UTXOs) is not double-counted', () => {
    const change = u(B, 1, 4000, 0);
    reg.recordChange('swap1', change);
    const chain = [u(B, 1, 4000, 105)];                    // same outpoint, now confirmed at height 105
    const cand = reg.candidateUtxos('swap2', chain);
    expect(cand.filter(x => x.tx_hash === B && x.tx_pos === 1).length).toBe(1);
  });

  it('RELEASE frees a swap inputs + change (failure / unmount / retry)', () => {
    const chain = [u(A, 0, 1000)];
    reg.reserveInputs('swap1', [u(A, 0, 1000)]);
    reg.recordChange('swap1', u(B, 1, 900, 0));
    reg.releaseSwap('swap1');
    expect(keys(reg.candidateUtxos('swap2', chain))).toEqual([`${A}:0`]); // A available again, B change gone
  });

  it('FAIL-CLOSED MATRIX (a): two swaps reserving overlapping inputs — candidateUtxos excludes the other reserved input; releaseSwap frees only that swap', () => {
    const chain = [u(A, 0, 1000), u(B, 0, 2000)];
    reg.reserveInputs('swap1', [u(A, 0, 1000)]);
    reg.reserveInputs('swap2', [u(B, 0, 2000)]);
    // Each swap sees only its own + the unreserved rest; neither sees the other's input.
    expect(keys(reg.candidateUtxos('swap1', chain))).toEqual([`${A}:0`]);
    expect(keys(reg.candidateUtxos('swap2', chain))).toEqual([`${B}:0`]);
    // releaseSwap frees ONLY that swap's reservation — swap2's stays held.
    reg.releaseSwap('swap1');
    expect(keys(reg.candidateUtxos('swap1', chain))).toEqual([`${A}:0`]);       // A free again for swap1
    expect(keys(reg.candidateUtxos('swap3', chain))).toEqual([`${A}:0`]);       // A free to a 3rd swap, B still excluded
    expect(reg.candidateUtxos('swap3', chain).some(x => x.tx_hash === B)).toBe(false);
  });

  it('the mutex serializes select+reserve (no two swaps grab the same input under interleave)', async () => {
    const chain = [u(A, 0, 1000), u(B, 0, 1000)];
    const pick = (swapId: string) => reg.withUtxoLock(async () => {
      const cand = reg.candidateUtxos(swapId, chain);
      await Promise.resolve(); // force an await point between select and reserve
      const sel = [cand[0]];   // greedy: take the first candidate
      reg.reserveInputs(swapId, sel);
      return sel[0];
    });
    const [s1, s2] = await Promise.all([pick('swap1'), pick('swap2')]);
    expect(`${s1.tx_hash}:${s1.tx_pos}`).not.toBe(`${s2.tx_hash}:${s2.tx_pos}`); // disjoint despite concurrency
  });

  it('INSTANCE ISOLATION: a second registry does NOT see the first registry reservations (fix #3 — no process-global)', () => {
    const chain = [u(A, 0, 1000)];
    reg.reserveInputs('swap1', [u(A, 0, 1000)]);
    const other = new UtxoReservationRegistry();
    expect(keys(other.candidateUtxos('swapX', chain))).toEqual([`${A}:0`]); // independent instance, no shared singleton
  });
});

describe('UtxoReservationRegistry — cross-instance coordination via injected LocalStorageReservationMirror (R-RESPERSIST)', () => {
  const PEER = 'bch2swap:utxores:peerTAB'; // a DIFFERENT tab's persisted key (ours uses a random sessionStorage tabId)
  let ls: ReturnType<typeof makeFakeStorage>;
  let ss: ReturnType<typeof makeFakeStorage>;
  let reg: UtxoReservationRegistry;
  let mirror: LocalStorageReservationMirror;

  beforeEach(() => {
    ls = makeFakeStorage();
    ss = makeFakeStorage();
    mirror = new LocalStorageReservationMirror({ localStorage: ls, sessionStorage: ss });
    reg = new UtxoReservationRegistry(mirror);
  });

  const ownKey = (): string | null => { for (let i = 0; i < ls.length; i++) { const k = ls.key(i); if (k && k.startsWith('bch2swap:utxores:') && k !== PEER) return k; } return null; };

  it('EXCLUDES an input another tab reserves (persisted peer key)', () => {
    const now = Date.now();
    ls.setItem(PEER, JSON.stringify([[`${A}:0`, now]]));
    const chain = [u(A, 0, 1000), u(B, 0, 2000)];
    expect(keys(reg.candidateUtxos('swap1', chain, now))).toEqual([`${B}:0`]); // A excluded — a peer tab spends it
  });

  it('IGNORES + PRUNES a stale peer entry (older than the 60-min TTL)', () => {
    const now = Date.now();
    ls.setItem(PEER, JSON.stringify([[`${A}:0`, now - 61 * 60_000]]));
    const chain = [u(A, 0, 1000)];
    expect(keys(reg.candidateUtxos('swap1', chain, now))).toEqual([`${A}:0`]); // stale → not excluded
    expect(ls.getItem(PEER)).toBeNull();                                        // all-stale peer key pruned
  });

  it('WRITE-THROUGH: this tab persists its reservations so a peer would exclude them', () => {
    const now = Date.now();
    reg.reserveInputs('swap1', [u(A, 0, 1000)], now);
    const k = ownKey();
    expect(k).not.toBeNull();
    const rows = JSON.parse(ls.getItem(k as string) as string) as Array<[string, number]>;
    expect(rows.some(r => r[0] === `${A}:0`)).toBe(true);
  });

  it('RELEASE clears the persisted mirror', () => {
    const now = Date.now();
    reg.reserveInputs('swap1', [u(A, 0, 1000)], now);
    reg.releaseSwap('swap1');
    const k = ownKey();
    const rows = k ? (JSON.parse(ls.getItem(k) ?? '[]') as Array<[string, number]>) : [];
    expect(rows.some(r => r[0] === `${A}:0`)).toBe(false);
  });

  it('a peer reservation does NOT exclude a swap OWN reserved input (retry-safe; only OTHER tabs exclude)', () => {
    const now = Date.now();
    reg.reserveInputs('swap1', [u(A, 0, 1000)], now); // our own key holds A — must NOT be excluded for swap1 itself
    expect(keys(reg.candidateUtxos('swap1', [u(A, 0, 1000)], now))).toEqual([`${A}:0`]);
  });

  it('malformed / corrupt peer key is ignored (fail-soft) and pruned', () => {
    const now = Date.now();
    ls.setItem(PEER, '{not json');
    const chain = [u(A, 0, 1000)];
    expect(keys(reg.candidateUtxos('swap1', chain, now))).toEqual([`${A}:0`]); // corrupt peer contributes nothing
    expect(ls.getItem(PEER)).toBeNull();                                        // and is pruned
  });

  it('two registries sharing storage exclude each other reservations (cross-instance)', () => {
    const now = Date.now();
    const mirror2 = new LocalStorageReservationMirror({ localStorage: ls, sessionStorage: makeFakeStorage() });
    const reg2 = new UtxoReservationRegistry(mirror2);
    reg.reserveInputs('swap1', [u(A, 0, 1000)], now);      // registry 1 reserves A
    const chain = [u(A, 0, 1000), u(B, 0, 2000)];
    expect(keys(reg2.candidateUtxos('swap2', chain, now))).toEqual([`${B}:0`]); // registry 2 excludes A
  });
});
