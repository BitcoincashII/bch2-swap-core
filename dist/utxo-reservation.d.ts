interface ResUtxo {
    tx_hash: string;
    tx_pos: number;
    value: number;
    height: number;
}
interface ReservationMirror {
    readOtherReserved(now: number): Set<string>;
    persistReserved(rows: Array<[string, number]>): void;
}
declare class UtxoReservationRegistry {
    private readonly reservedBy;
    private readonly knownChange;
    private mutexTail;
    private readonly mirror?;
    constructor(mirror?: ReservationMirror);
    private prune;
    private persist;
    withUtxoLock<T>(fn: () => Promise<T> | T): Promise<T>;
    candidateUtxos(swapId: string, chainUtxos: ResUtxo[], now?: number): ResUtxo[];
    reserveInputs(swapId: string, inputs: Array<{
        tx_hash: string;
        tx_pos: number;
    }>, now?: number): void;
    recordChange(swapId: string, change: ResUtxo, now?: number): void;
    releaseSwap(swapId: string): void;
    reset(): void;
}
interface StorageLike {
    getItem(k: string): string | null;
    setItem(k: string, v: string): void;
    removeItem(k: string): void;
    readonly length: number;
    key(i: number): string | null;
}
declare class LocalStorageReservationMirror implements ReservationMirror {
    private readonly ls;
    private readonly persistKey;
    constructor(opts?: {
        localStorage?: StorageLike | null;
        sessionStorage?: StorageLike | null;
    });
    private static _makeTabId;
    persistReserved(rows: Array<[string, number]>): void;
    readOtherReserved(now: number): Set<string>;
}

export { LocalStorageReservationMirror, type ResUtxo, type ReservationMirror, UtxoReservationRegistry };
