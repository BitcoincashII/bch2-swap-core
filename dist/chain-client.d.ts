/**
 * ChainClient — the minimal READ surface the SDK's SPV verifier (./spv-verifier) calls on an UNTRUSTED
 * chain transport.
 *
 * The frontend app injects an `ElectrumProxyClient` (a WebSocket proxy to real Electrum servers); a Node
 * bot can inject any transport implementing these three read methods. The SPV verifier treats every
 * response as untrusted and PoW/Merkle-verifies it against the SDK's HARDCODED checkpoints + difficulty
 * params (see ./spv) — so this interface is a transport contract only and confers no trust (fix #6).
 *
 * Method names + signatures are copied verbatim from the app's ElectrumProxyClient
 * (bch2-swap/src/electrum/proxy-client.ts) so a real ElectrumProxyClient structurally satisfies
 * ChainClient with no adapter.
 */
interface ChainClient {
    /** R175-SPV: a batch of contiguous 80-byte headers (concatenated hex) for checkpoint→tip verification. */
    getBlockHeaders(start: number, count: number): Promise<{
        count: number;
        hex: string;
        max: number;
    }>;
    /** R175-SPV: Merkle inclusion proof {block_height, merkle (display hex), pos} for a funding tx at a height. */
    getMerkleProof(txid: string, height: number): Promise<{
        block_height: number;
        merkle: string[];
        pos: number;
    }>;
    /** Raw Electrum JSON-RPC — used by getChainTimeSec to read the tip header (blockchain.headers.subscribe). */
    request<T = unknown>(method: string, params: unknown[]): Promise<T>;
}

export type { ChainClient };
