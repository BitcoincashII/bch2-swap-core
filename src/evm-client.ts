/**
 * EVM / MetaMask interaction layer (ethers v6).
 *
 * All HTLC operations use sha256(secret) as the hashLock — matching the
 * OP_SHA256 used on the UTXO side.
 */

import {
  BrowserProvider,
  Contract,
  ethers,
  FallbackProvider,
  type FeeData,
  JsonRpcProvider,
  type Signer,
  type Provider,
} from 'ethers';
import { getEvmConfig, EVM_CHAINS, SUPPORTED_EVM_CHAINS } from './evm-config';
import type { EvmChainId } from './evm-config';

// ============================================================================
// Minimal inline HTLC ABI (matches TokenHTLC.sol)
// ============================================================================

// R278-TEST: exported so fault-injection tests build `new ethers.Interface(HTLC_ABI)` from the SAME ABI the
// SUT uses (encodeFunctionResult('getSwap', ...)) — prevents test/source ABI drift. Behaviour unchanged.
export const HTLC_ABI = [
  'function lock(address recipient, address token, uint256 amount, bytes32 hashLock, uint256 timeLock) payable returns (bytes32)',
  'function claim(bytes32 id, bytes32 secret)',
  'function refund(bytes32 id)',
  'function getSwap(bytes32 id) view returns (address initiator, address recipient, address token, uint256 amount, bytes32 hashLock, uint256 timeLock, bool claimed, bool refunded)',
  'event Locked(bytes32 indexed id, address indexed initiator, address recipient, address token, uint256 amount, bytes32 hashLock, uint256 timeLock)',
  'event Claimed(bytes32 indexed id, bytes32 secret)',
  'event Refunded(bytes32 indexed id)',
];

const ERC20_ABI = [
  'function balanceOf(address owner) view returns (uint256)',
  'function allowance(address owner, address spender) view returns (uint256)',
  'function approve(address spender, uint256 amount) returns (bool)',
];

// ============================================================================
// Types
// ============================================================================

export interface MetaMaskConnection {
  provider: BrowserProvider;
  signer: Signer;
  address: string;
  chainId: number;
}

export interface SwapData {
  initiator: string;
  recipient: string;
  token: string;
  amount: bigint;
  hashLock: string;
  timeLock: bigint;
  claimed: boolean;
  refunded: boolean;
}

// ============================================================================
// MetaMask connection
// ============================================================================

/** Connect to MetaMask and return provider, signer, address, and chainId. */
export async function connectMetaMask(): Promise<MetaMaskConnection> {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const win = window as any;
  if (!win.ethereum) {
    throw new Error('MetaMask not found. Please install the MetaMask browser extension.');
  }

  const provider = new BrowserProvider(win.ethereum);
  await provider.send('eth_requestAccounts', []);
  const signer = await provider.getSigner();
  const address = await signer.getAddress();
  // R98-EVM-001: getNetwork() is a pure RPC call; wrap with timeout so a stalled node doesn't
  // hang connectMetaMask indefinitely and block the entire swap UI with no recovery path.
  // R116-EVM-005: clear timer in .finally() to prevent ghost timer accumulation on rapid connect/disconnect.
  let _connectNetTimer: ReturnType<typeof setTimeout> | undefined;
  const network = await Promise.race([
    provider.getNetwork(),
    new Promise<never>((_, rej) => { _connectNetTimer = setTimeout(() => rej(new Error('getNetwork timed out')), 15_000); }),
  ]).finally(() => clearTimeout(_connectNetTimer));
  const chainId = Number(network.chainId);

  return { provider, signer, address, chainId };
}

/** Ask MetaMask to switch to the requested network by chainId. */
export async function switchToChain(chainId: number): Promise<void> {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const win = window as any;
  if (!win.ethereum) throw new Error('MetaMask not found.');
  const hexChainId = '0x' + chainId.toString(16);
  try {
    await win.ethereum.request({
      method: 'wallet_switchEthereumChain',
      params: [{ chainId: hexChainId }],
    });
  } catch (e: unknown) {
    const err = e as { code?: number };
    // Error code 4001 = user dismissed the network-switch UI
    if (err.code === 4001) {
      throw new Error('Network switch cancelled. Please switch to the required network in MetaMask and try again.');
    }
    // Error code 4902 = chain not added to MetaMask
    if (err.code === 4902) {
      throw new Error(
        `Network (chainId ${chainId}) is not configured in MetaMask. ` +
        `Please add it manually in MetaMask settings.`
      );
    }
    throw e;
  }
}

// ============================================================================
// Token helpers
// ============================================================================

/** Get ERC-20 token balance in raw units. */
export async function getTokenBalance(
  tokenAddr: string,
  walletAddr: string,
  provider: Provider,
): Promise<bigint> {
  const token = new Contract(tokenAddr, ERC20_ABI, provider);
  // R103-EVM-001: wrap with 15s timeout — a stalled provider hangs the wallet balance display indefinitely.
  return Promise.race([
    token.balanceOf(walletAddr) as Promise<bigint>,
    new Promise<never>((_, rej) => setTimeout(() => rej(new Error('[getTokenBalance] balanceOf timed out after 15s')), 15_000)),
  ]);
}

/** Approve HTLC to spend `amount` of the given ERC-20 token. */
export async function approveToken(
  tokenAddr: string,
  spenderAddr: string,
  amount: bigint,
  signer: Signer,
): Promise<void> {
  // R105-EVM-001: re-entry guard — reject concurrent approveToken calls for the same token/spender pair
  const approveKey = `${tokenAddr.toLowerCase()}:${spenderAddr.toLowerCase()}`;
  if (_approveInFlight.has(approveKey)) throw new Error('[approveToken] Approval already in flight for this token/spender pair');
  _approveInFlight.add(approveKey);
  try {
  const token = new Contract(tokenAddr, ERC20_ABI, signer);
  // R39-EVM-002: pre-flight staticCall to detect non-reverting false-return approve() (e.g. some USDT variants)
  // R100-EVM-001: wrap with timeout — stalled RPC holds approveToken call indefinitely before tx submission
  const wouldSucceed = await Promise.race([
    (token.approve as ethers.BaseContractMethod).staticCall(spenderAddr, amount),
    new Promise<never>((_, rej) => setTimeout(() => rej(new Error('approve staticCall timed out')), 15_000)),
  ]);
  if (!wouldSucceed) {
    throw new Error('Token approval would return false (non-standard ERC-20). Swap cannot proceed.');
  }
  // R100-EVM-001: wrap approve() tx submission — stalled RPC hangs indefinitely before returning a tx object
  // R114-EVM-005: explicit gasLimit=150_000 — prevents a compromised RPC from returning a deliberate
  // underestimate from eth_estimateGas that causes the on-chain approve() to OOG-revert; also covers
  // proxy-based tokens (USDT-style) whose approve() costs up to ~120,000 gas.
  const tx = await Promise.race([
    token.approve(spenderAddr, amount, { gasLimit: 150_000n }),
    new Promise<never>((_, rej) => setTimeout(() => rej(new Error('approve() submission timed out')), 30_000)),
  ]);
  // R74-EVM-001: 120s timeout — approval tx hung indefinitely before this, freezing the swap UI
  let approveWaitId: ReturnType<typeof setTimeout>;
  const approveTimeoutReject = new Promise<never>((_, rej) => { approveWaitId = setTimeout(() => rej(new Error('approveToken: tx.wait() timed out after 120s — tx may still confirm')), 120_000); });
  const receipt = await Promise.race([tx.wait(), approveTimeoutReject]).finally(() => clearTimeout(approveWaitId!));
  if (!receipt || receipt.status !== 1) throw new Error('Token approval transaction reverted');
  } finally {
    _approveInFlight.delete(approveKey); // R105-EVM-001: always release guard
  }
}

/**
 * Ensures the HTLC contract has sufficient ERC-20 allowance, approving if needed.
 *
 * Security: validates spenderAddr against the canonical HTLC address for this chainId
 * (R34-EVM-001) and rejects chains where the HTLC is not yet deployed (R35-EVM-002).
 * These internal checks are the authoritative enforcement point — do NOT remove them
 * even if callers also pre-validate. Defense in depth is intentional.
 */
export async function ensureAllowance(
  tokenAddr: string,
  ownerAddr: string,
  spenderAddr: string,
  amount: bigint,
  signer: Signer,
  provider: Provider,
  chainId: number,
): Promise<void> {
  // R41-EVM-003: assert ownerAddr matches signer.getAddress() — if MetaMask switches accounts,
  // the allowance check and approval would target different accounts, silently mis-approving.
  // R98-EVM-002: wrap with timeout — a stalled MetaMask response hangs ensureAllowance indefinitely.
  const signerAddr = (await Promise.race([
    signer.getAddress(),
    new Promise<never>((_, rej) => setTimeout(() => rej(new Error('getAddress timed out')), 15_000)),
  ])).toLowerCase();
  if (ownerAddr.toLowerCase() !== signerAddr) {
    throw new Error(
      `ensureAllowance: ownerAddr ${ownerAddr} does not match signer address ${signerAddr} — stale address after account switch?`
    );
  }
  // R34-EVM-001: validate spenderAddr against HTLC config to prevent accidental or malicious
  // approval of an address that is not the canonical HTLC contract for this chain.
  const htlcConfig = getEvmConfig(chainId as EvmChainId); // R112-CFG-003: boundary cast — ensureAllowance accepts number for MetaMask compat
  if (!htlcConfig) throw new Error(`No EVM config for chainId ${chainId}`);
  if (spenderAddr.toLowerCase() !== htlcConfig.htlcAddress.toLowerCase()) {
    throw new Error(`ensureAllowance: spenderAddr ${spenderAddr} does not match HTLC contract ${htlcConfig.htlcAddress} for chainId ${chainId}`);
  }
  // R35-EVM-002: reject chains where HTLC is not yet deployed (address is zero).
  // Without this, a caller with spenderAddr=ZERO_ADDRESS on an undeployed chain (e.g. Arb Sepolia)
  // passes the address-match check above and silently approves the zero address.
  const ZERO_ADDR = '0x0000000000000000000000000000000000000000';
  if (htlcConfig.htlcAddress.toLowerCase() === ZERO_ADDR) {
    throw new Error(`ensureAllowance: HTLC contract not deployed on chainId ${chainId} (address is zero)`);
  }
  const token = new Contract(tokenAddr, ERC20_ABI, provider);
  // R98-EVM-002: wrap with timeout — a stalled RPC node hangs allowance check indefinitely
  const allowance = (await Promise.race([
    token.allowance(ownerAddr, spenderAddr),
    new Promise<never>((_, rej) => setTimeout(() => rej(new Error('allowance check timed out')), 15_000)),
  ])) as bigint;
  if (allowance < amount) {
    // R27-EVM-007: removed the approve(0) → approve(N) two-step pattern.
    // The intermediate approve(0) creates a window where a front-running bot can observe the
    // zero allowance and race a transferFrom before the approve(N) confirms, potentially
    // draining whatever allowance the spender held. Standard ERC-20 tokens (including USDC/USDT
    // on Base) accept a direct approve(N) over a non-zero allowance, so the reset is unnecessary.
    await approveToken(tokenAddr, spenderAddr, amount, signer);
  }
}

// ============================================================================
// HTLC operations
// ============================================================================

/**
 * Takes a raw 32-byte secret preimage (NOT the secretHash/hashLock).
 * Calling this with an already-hashed value will double-hash and create
 * an unclaimable HTLC.
 */
export function hashPreimage(secret: Uint8Array): string {
  return ethers.sha256(secret);
}

// R105-EVM-001: per-(token, spender) re-entry guard for approveToken — prevents two concurrent
// approve calls for the same pair (e.g. double-click or rapid retry) from racing each other.
const _approveInFlight = new Set<string>();

// R70-EVM-002: per-hashLock re-entry guard — prevents concurrent calls from creating
// duplicate HTLCs for the same secret. Cleared on completion or throw.
const _activeLocks = new Set<string>();

// R282-EVMLOCK-FEE-001: ethers' default fee estimate on Base Sepolia can come out very low (~0.011 gwei).
// If the base fee ticks up before the tx mines, it strands PENDING, and a same-nonce retry at the same
// low fee is rejected REPLACEMENT_UNDERPRICED — blocking the account at that nonce (the exact failure
// users hit re-locking). Set fees with generous headroom (3x): negligible cost on an L2 testnet,
// comfortably above a rising base fee, AND >110% of a stranded low-fee tx so a same-nonce retry REPLACES
// it instead of being rejected. Falls back to ethers auto-estimation (returns {}) if the fee read fails,
// so a transient RPC hiccup never blocks the tx.
// R-POLY-GASSTATION-001: ethers v6 attaches a Polygon (chainId 137) fee plugin that fetches
// https://gasstation.polygon.technology/v2 inside getFeeData() — that endpoint is deprecated/flaky AND is
// blocked by our CSP (connect-src), so EVERY Polygon tx (native send, ERC-20 send, HTLC lock) throws before
// broadcast ("violates Content Security Policy"). Build providers through this factory so getFeeData reads
// eth_gasPrice from the RPC directly (CSP-allowed via polygon-rpc.com; works on all EVM chains), never the
// gas station. maxFeePerGas gets 2x headroom over the legacy price so it stays >= baseFee + priorityFee.
function patchFeeData(provider: JsonRpcProvider): JsonRpcProvider {
  provider.getFeeData = async () => {
    const gp = BigInt((await provider.send('eth_gasPrice', [])) as string);
    // R-GASFIX-002: refuse a 0 gasPrice — a maxFee=0 tx is underpriced and would never confirm; let the caller's
    // retry/error path handle a transient bad read.
    if (gp <= 0n) throw new Error('eth_gasPrice returned 0 — refusing to build an underpriced transaction');
    // R-GASFIX-002: proper EIP-1559 tip. The old code put the FULL gasPrice into maxPriorityFeePerGas, overpaying
    // the miner tip by ~a base fee on every send/lock. Query eth_maxPriorityFeePerGas (Polygon/Arbitrum support
    // it); clamp to (0, gp]; fall back to gp (prior behavior) if the RPC lacks the method.
    let tip = gp;
    try {
      const t = BigInt((await provider.send('eth_maxPriorityFeePerGas', [])) as string);
      if (t > 0n && t <= gp) tip = t;
    } catch { /* RPC lacks eth_maxPriorityFeePerGas — keep tip = gp (prior, safe, slightly over-pays) */ }
    return new ethers.FeeData(gp, gp * 2n, tip); // gasPrice, maxFeePerGas (2x headroom), maxPriorityFeePerGas
  };
  return provider;
}
export function makeEvmProvider(rpc: string): JsonRpcProvider {
  return patchFeeData(new JsonRpcProvider(rpc));
}

async function bumpedTxFees(
  signer: ethers.Signer,
): Promise<{ maxFeePerGas: bigint; maxPriorityFeePerGas: bigint } | Record<string, never>> {
  try {
    const fd = await Promise.race([
      signer.provider!.getFeeData(),
      new Promise<never>((_, rej) => setTimeout(() => rej(new Error('getFeeData timed out')), 15_000)),
    ]);
    const prioBase = fd.maxPriorityFeePerGas ?? 1_000_000n;       // 0.001 gwei fallback
    const feeBase = fd.maxFeePerGas ?? fd.gasPrice ?? 2_000_000n; // 0.002 gwei fallback
    const maxPriorityFeePerGas = prioBase * 3n;
    let maxFeePerGas = feeBase * 3n;
    if (maxFeePerGas < maxPriorityFeePerGas) maxFeePerGas = maxPriorityFeePerGas * 2n;
    return { maxFeePerGas, maxPriorityFeePerGas };
  } catch {
    return {};
  }
}

/**
 * Lock ERC-20 tokens in the HTLC.
 * Returns the swap ID (bytes32 as hex string).
 */
/**
 * R160-EVMLOCK-POSTBROADCAST-001: classify a broadcast-but-untracked lock tx (the durable
 * `bch2swap:lockpending:<id>` marker) so a reload can ADOPT an existing lock instead of re-locking it
 * (which would strand a second batch under a fresh per-nonce swapId). Outcomes:
 *  - { kind: 'locked', swapId } : mined OK, Locked event parsed → adopt this swapId.
 *  - { kind: 'safe' }           : mined+reverted OR not found anywhere (dropped) → no funds locked → re-lock is safe.
 *  - { kind: 'blocked' }        : still pending in mempool, OR mined-success with no Locked event (anomalous)
 *                                 → re-locking could duplicate → caller must wait + verify, NOT re-lock.
 */
export async function recoverLockFromTx(
  htlcAddr: string,
  txHash: string,
  provider: Provider,
  // R179: optional sender-scoped Locked-event scan. A MetaMask speed-up replaces the original (now-dropped) hash
  // with a new one that mined the real lock; if the marker still holds the dropped original, a both-null lookup
  // would return 'safe' and permit a re-lock (double-lock + strand). When `scan` is supplied, before returning
  // 'safe' we scan for a matching on-chain Locked from this sender and adopt it (fail-closed on any RPC error).
  // R-EVMLOCKID-RECOVERY-001: `token` + `expectTimeLock` bring the recovery-adopt corroboration to full 5-field parity
  // with the primary lock path (swap-controller lockEvm). swapId = keccak256(sender,nonce) excludes the token, so a
  // worthless-token decoy lock with the same public hashLock/recipient/amount has a DISTINCT on-chain swapId a lying
  // leaf can inject; binding token (+ the exact chain-clock timeLock only OUR lock has) rejects it.
  scan?: { sender: string; hashLock: string; recipient?: string; minAmount?: bigint; fromBlock?: number; token?: string; expectTimeLock?: bigint },
): Promise<{ kind: 'locked'; swapId: string; blockNumber?: number } | { kind: 'safe' | 'blocked' }> {
  // R224-RECOVER-QUORUM-001: the 'safe' verdict CLEARS the lockpending marker and authorizes a fresh IRREVERSIBLE
  // re-lock, so it must NOT trust a single quorum=1 FallbackProvider first-responder null. An honest-but-lagging /
  // pruned / rate-limited RPC answering not-found FIRST (no throw) would otherwise yield a false 'safe' -> a SECOND
  // on-chain lock under a fresh nonce/swapId (the contract does not revert), stranding the first batch. Require
  // EVERY leaf backend to INDEPENDENTLY + SUCCESSFULLY confirm not-found before returning 'safe'; any leaf that
  // finds the lock -> adopt ('locked'); any leaf that errors / is uncertain -> 'blocked' (fail-closed). This is
  // DISTINCT from the deferred R206/R175 quorum-1 class (a *lying* RPC on a *recoverable* read): here an *honest*
  // lagging node drives an *irreversible* double-lock, with no adversary.
  const leaves: Provider[] = (() => {
    const ls = (provider as unknown as { __leafProviders?: Provider[] }).__leafProviders;
    return Array.isArray(ls) && ls.length > 0 ? ls : [provider];
  })();

  // The original single-provider not-found logic, now run against ONE leaf. Returns 'safe' only on a definitive
  // not-found on THAT leaf (receipt + tx + sender-scan all succeeded and showed nothing); any error -> 'blocked'.
  const checkOneLeaf = async (p: Provider): Promise<{ kind: 'locked'; swapId: string; blockNumber?: number } | { kind: 'safe' | 'blocked' }> => {
    const htlc = new Contract(htlcAddr, HTLC_ABI, p);
    let receipt: ethers.TransactionReceipt | null;
    try { receipt = await p.getTransactionReceipt(txHash); }
    catch { return { kind: 'blocked' }; } // cannot determine → conservative: do not re-lock
    if (receipt) {
      if (receipt.status !== 1) return { kind: 'safe' }; // mined + reverted → moved no funds
      for (const log of receipt.logs) {
        // R239-RECOVER-RECEIPT-AUTH-001: AUTHENTICATE the Locked event before adopting its swapId — mirror the scan
        // path (335-338) + the R206 _deepIsOurs principle. The OLD code adopted the FIRST `Locked` event's swapId
        // with NO hashLock/recipient/amount check AND no address check (parseLog matches by topic0 alone, so a
        // `Locked` from ANOTHER contract would parse). getTransactionReceipt does NO Merkle verification of
        // receipt.logs, so a lying/MITM RPC leaf (the accepted-open R206/R175 trust class) could fabricate a `Locked`
        // log for OUR txHash carrying an attacker-chosen swapId → we adopt it, write bch2swap:funded=wrong-swapId,
        // STOP re-locking, and the resume watch filters on the WRONG indexed id → never observes our real lock being
        // claimed → owed leg lost (silent). Require: log FROM the HTLC contract AND hashLock(+recipient+amount)==ours.
        if (htlcAddr && String(log.address).toLowerCase() !== htlcAddr.toLowerCase()) continue;
        try {
          const parsed = htlc.interface.parseLog(log);
          if (parsed && parsed.name === 'Locked') {
            const a = parsed.args;
            const okHash = !scan?.hashLock || String(a.hashLock).toLowerCase() === scan.hashLock.toLowerCase();
            const okRcpt = !scan?.recipient || String(a.recipient).toLowerCase() === scan.recipient.toLowerCase();
            const okAmt = scan?.minAmount === undefined || (a.amount as bigint) >= scan.minAmount;
            if (okHash && okRcpt && okAmt) return { kind: 'locked', swapId: parsed.args[0] as string, blockNumber: receipt.blockNumber }; // R-EVMLOCKBLOCK-ADOPT-001: surface the lock block for the lossless [lockBlock, tip] Claimed-event scan
            // a Locked event whose hashLock != ours (a lying RPC, or an unrelated swap in the same tx) -> do NOT
            // adopt a foreign swapId; keep scanning the remaining logs.
          }
        } catch { /* skip non-matching log */ }
      }
      return { kind: 'blocked' }; // mined-success but no Locked event MATCHING OUR hashLock (anomalous) — do not re-lock
    }
    // No receipt: still pending in the mempool, or dropped/never-existed.
    let tx: ethers.TransactionResponse | null;
    try { tx = await p.getTransaction(txHash); }
    catch { return { kind: 'blocked' }; } // cannot determine → conservative: do not re-lock
    if (tx) return { kind: 'blocked' }; // still pending in mempool
    // R179-EVMLOCK-REPLACED-001: the original hash is definitively not on-chain on THIS leaf — BUT a MetaMask
    // speed-up may have mined the real lock under a DIFFERENT (replacement) hash the marker never captured. Scan
    // for a matching Locked event from this sender and adopt it. The Locked event carries hashLock+recipient+
    // amount directly, so no getSwap round-trip is needed.
    if (scan?.sender && scan.hashLock) {
      try {
        const tip = await p.getBlockNumber();
        // ~24h timelock window + margin. CHUNK the eth_getLogs query: public RPCs (e.g. sepolia.base.org) cap the
        // block range at 2000 — a single wide query THROWS, which would fail-closed to 'blocked' and brick the
        // swap on every reload (R179 re-verify reproduced this). Scan BACKWARD (recent-first) so the just-mined
        // replacement matches in the first chunk and we return early.
        // R-EVMLOCKBLOCK-POISON-001: clamp the scan floor to <= tip so a poisoned-high fromBlock (an evmLockBlock
        // adopted from a lying leaf) can never push `start` past the tip and skip this replacement-lock scan entirely
        // (an empty scan would falsely report not-found → 'safe' → risk a double-lock). start is only ever a lower bound.
        const start = Math.min(tip, Math.max(0, scan.fromBlock && scan.fromBlock > 0 ? scan.fromBlock : tip - 50_000));
        const CHUNK = 1_800; // strictly under the 2000-block cap
        for (let to = tip; to >= start; to -= CHUNK) {
          const from = Math.max(start, to - CHUNK + 1);
          const evs = await htlc.queryFilter(htlc.filters.Locked(null, scan.sender), from, to);
          for (const ev of evs) {
            const a = (ev as ethers.EventLog).args;
            if (!a) continue;
            // Locked(id, initiator(sender), recipient, token, amount, hashLock, timeLock)
            const okHash = String(a.hashLock).toLowerCase() === scan.hashLock.toLowerCase();
            const okRcpt = !scan.recipient || String(a.recipient).toLowerCase() === scan.recipient.toLowerCase();
            const okAmt = scan.minAmount === undefined || (a.amount as bigint) >= scan.minAmount;
            if (okHash && okRcpt && okAmt) return { kind: 'locked', swapId: String(a.id), blockNumber: (ev as ethers.EventLog).blockNumber }; // R-EVMLOCKBLOCK-ADOPT-001: surface the lock block
          }
          if (from <= start) break;
        }
      } catch { return { kind: 'blocked' }; } // RPC error during the scan → fail-closed (do not re-lock)
    }
    return { kind: 'safe' }; // this leaf: receipt + tx + scan all succeeded and found nothing
  };

  // Query EVERY leaf and combine CONSERVATIVELY: any leaf that found the lock wins (adopt it); else any
  // uncertain/errored leaf -> 'blocked' (fail-closed); 'safe' ONLY when EVERY leaf independently confirmed not-found.
  const results = await Promise.all(leaves.map(p => checkOneLeaf(p).catch(() => ({ kind: 'blocked' as const }))));
  // R-RECOVER-SWAPID-QUORUM-001: the swapId is the ONE Locked-event field checkOneLeaf cannot authenticate — the
  // on-chain id is keccak256(msg.sender, nonce), NOT derivable from our public hashLock/recipient/amount — yet it is
  // the value committed to fundedKey / myEvmSwapId and keyed on by the claim-watch + refund. checkOneLeaf reads a RAW
  // leaf (no Merkle proof of receipt.logs), so a single lying/MITM leaf can fabricate a Locked log carrying our PUBLIC
  // params but an ATTACKER-chosen swapId (exactly the attack R239's comment describes; R239 only bound the public
  // fields). Adopt a candidate swapId ONLY if QUORUM-corroborated by getSwap over the aggregating `provider`: a
  // fabricated id does not exist on-chain (initiator==0 / timeLock==0 → getSwap returns null), and one leaf cannot
  // make the quorum read agree. Iterate every candidate so a hostile leaf ordered first cannot mask the real lock.
  const lockedCandidates = results.filter((r): r is { kind: 'locked'; swapId: string; blockNumber?: number } => r.kind === 'locked');
  for (const cand of lockedCandidates) {
    let s: SwapData | null;
    try { s = await getSwap(htlcAddr, cand.swapId, provider); } catch { continue; } // quorum read failed → try next
    const okHash = !scan?.hashLock || (!!s && String(s.hashLock).toLowerCase() === scan.hashLock.toLowerCase());
    const okRcpt = !scan?.recipient || (!!s && String(s.recipient).toLowerCase() === scan.recipient.toLowerCase());
    const okAmt = scan?.minAmount === undefined || (!!s && s.amount >= scan.minAmount);
    // R-EVMLOCKID-RECOVERY-001: bind token (case-insensitive; getSwap normalizes to EIP-55 / ZeroAddress) and the exact
    // timeLock we set — full parity with the primary path — so a same-public-fields decoy on a different token / with a
    // different (attacker-chosen) timeLock cannot be adopted. Skipped only when a param is absent (token always known;
    // expectTimeLock absent for a pre-fix lock → degrades to token+3-field, never worse than before this fix).
    const okToken = scan?.token === undefined || (!!s && String(s.token).toLowerCase() === scan.token.toLowerCase());
    const okTL = scan?.expectTimeLock === undefined || (!!s && s.timeLock === scan.expectTimeLock);
    if (s && okHash && okRcpt && okAmt && okToken && okTL) return cand; // this id exists on-chain (quorum-corroborated) with our params
  }
  // an uncorroborated 'locked' (only a lying leaf claimed it), or any uncertain/errored leaf → fail closed (retry).
  if (lockedCandidates.length > 0 || results.some(r => r.kind === 'blocked')) return { kind: 'blocked' };
  return { kind: 'safe' }; // unanimous not-found across all leaves → no funds locked → re-lock is safe
}

// R239-RECOVER-RECEIPT-AUTH-001 (extended to the lock-broadcast path): AUTHENTICATE a `Locked` event before adopting
// its swapId. The lock-success + TRANSACTION_REPLACED branches of lockETH/lockTokens extract our swapId from a tx
// RECEIPT, but getTransactionReceipt does NO Merkle verification of receipt.logs (and parseLog matches by topic0
// alone, so a `Locked` from ANOTHER contract would parse). A lying/MITM RPC (the accepted-open R206/R175 trust class)
// could thus return a foreign swapId for OUR lock tx -> the caller adopts the wrong swapId -> watches the wrong swap
// -> never sees its real lock claimed -> owed leg lost (silent). Adopt ONLY the swapId of the FIRST Locked event that
// is emitted FROM htlcAddr AND carries OUR hashLock (the unique-per-swap binding). Returns null if none -> the caller
// throws/fails-closed (and a reload recovers via the now-authenticated recoverLockFromTx). One helper, no per-site drift.
function authenticatedLockedSwapId(htlc: Contract, htlcAddr: string, hashLock: string, logs: ReadonlyArray<ethers.Log>): string | null {
  for (const log of logs) {
    if (htlcAddr && String(log.address).toLowerCase() !== htlcAddr.toLowerCase()) continue;
    try {
      const parsed = htlc.interface.parseLog(log);
      if (parsed && parsed.name === 'Locked' && String(parsed.args.hashLock).toLowerCase() === hashLock.toLowerCase()) {
        return parsed.args[0] as string; // bytes32 id, bound to OUR hashLock
      }
    } catch { /* skip non-matching log */ }
  }
  return null;
}

export async function lockTokens(
  htlcAddr: string,
  recipient: string,
  tokenAddr: string,
  amount: bigint,
  hashLock: string,  // bytes32 hex string (sha256 of secret)
  timeLock: bigint,
  signer: Signer,
  expectedChainId: number, // R106-EVM-002: required — callers must pass the expected chainId for chain validation
  onBroadcast?: (txHash: string) => void, // R161: invoked the instant the lock tx is broadcast (before tx.wait) so the caller can durably record the tx hash for post-broadcast recovery even if a LATER (inner or outer) timeout fires
): Promise<string> {
  // R70-EVM-002: re-entry guard — reject concurrent lockTokens calls for the same hashLock+htlc pair
  // R109-EVM-001: key by hashLock+htlcAddr to avoid cross-function blocking when lockETH and
  // lockTokens share the same hashLock on different HTLC contracts.
  const lockKey = `${hashLock.toLowerCase()}:${htlcAddr.toLowerCase()}`;
  if (_activeLocks.has(lockKey)) throw new Error(`lockTokens: a lock for hashLock ${hashLock} on ${htlcAddr} is already in progress`);
  _activeLocks.add(lockKey);
  try {
  // R66-EVM-002: reject zero-amount lock — creates a structurally valid but value-less HTLC
  if (amount <= 0n) throw new Error('lockTokens: amount must be greater than 0');
  // R76-EC-001: reject zero or already-elapsed timeLock — counterparty could refund instantly in the same block
  if (timeLock === 0n) throw new Error('lockTokens: timeLock must not be zero');
  // R77-EVM-NEW-1: reject all-zero hashLock — an all-zero hashLock means the preimage is unknown or
  // unset, making the swap unclaimable by the intended recipient; the lock would be permanently stuck.
  if (!hashLock || hashLock.replace(/^0x/, '') === '0'.repeat(64)) throw new Error('lockTokens: hashLock must not be all zeros');
  // R66-EVM-003: reject zero-address recipient — no one holds the key; swap silently fails
  // R68-EVM-001: normalize via getAddress() before compare — rejects alternate representations (e.g. "0X000...000")
  if (ethers.getAddress(recipient) === ethers.ZeroAddress) throw new Error('lockTokens: recipient must not be the zero address');
  // R26-EVM-001: validate signer is on the expected chain before submitting any tx
  // R33-EVM-008: compare as BigInt to avoid precision loss for large chainIds
  if (expectedChainId !== undefined) {
    // R99-SE-004: wrap getNetwork() — stalled RPC holds _activeLocks + caller guards for ~120s
    // R116-EVM-005: clear timer in .finally() to prevent ghost timer leak on fast-resolve path
    let _ltNetTimer: ReturnType<typeof setTimeout> | undefined;
    const network = await Promise.race([
      signer.provider!.getNetwork(),
      new Promise<never>((_, rej) => { _ltNetTimer = setTimeout(() => rej(new Error('getNetwork timed out')), 15_000); }),
    ]).finally(() => clearTimeout(_ltNetTimer));
    if (network.chainId !== BigInt(expectedChainId)) {
      throw new Error(`Chain mismatch: wallet is on chainId ${network.chainId}, expected ${expectedChainId}. Switch networks in MetaMask.`);
    }
  }
  // R20-CRYPTO-002: verify contract is deployed before sending value — ETH sent to EOA is unrecoverable
  // R21-EVM-001: wrap getCode in try/catch to distinguish network errors from undeployed contract
  // R22-EVM-002: use a typed sentinel to avoid matching third-party RPC messages
  class _HtlcNotDeployedError extends Error { readonly isHtlcNotDeployed = true; }
  try {
    // R99-SE-005: wrap getCode() — stalled RPC holds evmFundingBroadcastedRef + evmKeyCopy for ~120s
    const code = await Promise.race([
      signer.provider!.getCode(htlcAddr),
      new Promise<never>((_, rej) => setTimeout(() => rej(new Error('getCode timed out')), 15_000)),
    ]);
    if (!code || code === '0x') throw new _HtlcNotDeployedError(`HTLC contract not deployed at ${htlcAddr} on this network`);
  } catch (codeErr: unknown) {
    if ((codeErr as _HtlcNotDeployedError).isHtlcNotDeployed) throw codeErr;
    const msg = codeErr instanceof Error ? codeErr.message : String(codeErr);
    throw new Error(`HTLC contract check failed (network/RPC error — check MetaMask): ${msg}`);
  }
  const htlc = new Contract(htlcAddr, HTLC_ABI, signer);
  // R34-EVM-002: wrap lock() in try/catch to best-effort revoke residual ERC-20 allowance
  // if the lock() call reverts after approve() already succeeded. Without this, the HTLC
  // contract retains a non-zero allowance that a malicious contract could exploit later.
  // R26-EVM-004: 200k can be insufficient for ERC-20 tokens with transfer hooks or cold addresses
  // R41-EVM-004: typed as TransactionReceipt | null instead of any for type safety
  let receipt: ethers.TransactionReceipt | null = null;
  // R160-EVMLOCK-POSTBROADCAST-001: see lockETH — tag AMBIGUOUS post-broadcast throws (timeout/RPC-drop/
  // replacement/missing-event) so handleEvmFund keeps its idempotency guard and refuses to re-lock (a naive
  // retry locks a second batch under a fresh per-nonce swapId → stranded). A definitive REVERT
  // (allowance/CALL_EXCEPTION/status!=1) is NOT tagged: it moved no funds, so retry is safe.
  let _broadcastTxHash: string | undefined;
  try {
    const lockTx = await htlc.lock(recipient, tokenAddr, amount, hashLock, timeLock, { gasLimit: 300_000n, ...(await bumpedTxFees(signer)) });
    _broadcastTxHash = lockTx.hash;
    try { onBroadcast?.(lockTx.hash); } catch { /* ignore — recovery marker is best-effort */ }
    // R73-EVM-001: 120s timeout on tx.wait() — without it a stalled RPC holds _activeLocks permanently
    let lockWaitId: ReturnType<typeof setTimeout>;
    const lockTimeoutReject = new Promise<never>((_, reject) => { lockWaitId = setTimeout(() => reject(new Error('lockTokens: tx.wait() timed out after 120s — tx may still confirm')), 120_000); });
    try {
      receipt = await Promise.race([lockTx.wait(), lockTimeoutReject]);
    } finally { clearTimeout(lockWaitId!); }
  } catch (lockErr) {
    // R179-EVMLOCK-REPLACED-001: MetaMask speed-up (ethers v6 TRANSACTION_REPLACED, reason repriced/replaced).
    // The REPLACEMENT (same nonce, new hash) mined the REAL lock and consumed the allowance — adopt it (return
    // the swapId from the replacement receipt, or tag with the REPLACEMENT hash) and SKIP the allowance-revoke
    // below (the lock already consumed it). Without this, the original (dropped) hash is tagged and post-reload
    // recoverLockFromTx returns a definitive-but-WRONG {kind:'safe'} -> re-lock -> DOUBLE-LOCK + strand of the
    // replacement's HTLC. (A "Cancel" is handled by the explicit cancel branch below the revoke — UNtagged
    // throw so the guard resets for a clean retry; no tokens were locked.)
    {
      const _re = lockErr as { code?: string; reason?: string; cancelled?: boolean; receipt?: ethers.TransactionReceipt | null; replacement?: { hash?: string } };
      if (_re.code === 'TRANSACTION_REPLACED' && _re.reason !== 'cancelled' && !_re.cancelled) {
        if (_re.replacement?.hash) { try { onBroadcast?.(_re.replacement.hash); } catch { /* best-effort */ } }
        if (_re.receipt && _re.receipt.status === 1) {
          const _sid = authenticatedLockedSwapId(htlc, htlcAddr, hashLock, _re.receipt.logs); // R239: hashLock+address-authenticated
          if (_sid) return _sid;
        }
        throw Object.assign(new Error('lockTokens: lock tx was sped up; the replacement is on-chain — reload to adopt the lock'),
          { broadcasted: true, txHash: _re.replacement?.hash ?? _broadcastTxHash });
      }
    }
    try {
      const tokenContract = new Contract(tokenAddr, ERC20_ABI, signer);
      // R101-EVM-001: wrap revoke submit — bare await stalls inside catch block, delaying _activeLocks release
      const revokeTx = await Promise.race([
        tokenContract.approve(htlcAddr, 0n),
        new Promise<never>((_, rej) => setTimeout(() => rej(new Error('revoke approve() timed out')), 30_000)),
      ]);
      // R74-EVM-002: 30s timeout — revoke is best-effort; a stalled wait() here holds _activeLocks
      // open until page reload since the outer finally runs AFTER this catch block completes.
      let revokeWaitId: ReturnType<typeof setTimeout>;
      await Promise.race([
        revokeTx.wait(),
        new Promise<never>((_, rej) => { revokeWaitId = setTimeout(() => rej(new Error('revoke timed out')), 30_000); }),
      ]).catch(() => { /* ignore — revoke failure is already non-fatal */ }).finally(() => clearTimeout(revokeWaitId!));
    } catch { /* ignore revoke failure — do not mask the original lockErr */ }
    // R184-LOCKTOKENS-CANCEL-001: a MetaMask "Cancel" (TRANSACTION_REPLACED reason='cancelled') replaced our
    // lock with a 0-value self-send -> NO tokens were locked -> safe to retry. Throw UNtagged (mirrors lockETH's
    // explicit cancel branch) so handleEvmFund RESETS the guard for a clean in-session retry. The old code let
    // cancel fall through to the broadcasted-tag below, which wedged the guard, forced a reload, and showed a
    // false 'second-HTLC strand' warning. The best-effort allowance-revoke above already ran.
    {
      const _reCancel = lockErr as { code?: string; reason?: string; cancelled?: boolean };
      if (_reCancel.code === 'TRANSACTION_REPLACED' && (_reCancel.reason === 'cancelled' || _reCancel.cancelled)) {
        throw new Error('lockTokens: lock transaction was cancelled in the wallet — no tokens were locked; retry the swap.');
      }
    }
    const rawMsg = lockErr instanceof Error ? lockErr.message : String(lockErr);
    const isAllowanceIssue = rawMsg.toLowerCase().includes('allowance') ||
                             rawMsg.toLowerCase().includes('insufficient') ||
                             rawMsg.includes('CALL_EXCEPTION');
    if (isAllowanceIssue) {
      throw new Error(
        `lockTokens: lock() reverted — likely an allowance race with a concurrent wallet operation. ` +
        `Wait for any pending transactions to confirm and retry the swap.`
      );
    }
    // Non-revert post-broadcast failure (timeout / RPC drop / replacement) — ambiguous: the lock may have
    // mined. Tag broadcasted so the caller keeps its guard and does NOT re-lock.
    if (lockErr instanceof Error && _broadcastTxHash) Object.assign(lockErr, { broadcasted: true, txHash: _broadcastTxHash });
    throw lockErr;
  }
  if (!receipt) throw Object.assign(new Error('Transaction was dropped or replaced before confirmation'), _broadcastTxHash ? { broadcasted: true, txHash: _broadcastTxHash } : {});
  if (receipt.status !== 1) throw new Error('Transaction reverted on-chain'); // definitive revert → no funds → retry safe (untagged)

  // Extract swap ID ONLY from an AUTHENTICATED Locked event (from htlcAddr, hashLock==ours) — R239.
  {
    const _sid = authenticatedLockedSwapId(htlc, htlcAddr, hashLock, receipt.logs);
    if (_sid) return _sid; // bytes32 id, bound to OUR hashLock
  }
  // status===1 but no AUTHENTICATED Locked event → funds likely locked → tag broadcasted.
  throw Object.assign(new Error('Locked event not found in transaction receipt'), _broadcastTxHash ? { broadcasted: true, txHash: _broadcastTxHash } : {});
  } finally { _activeLocks.delete(lockKey); } // R70-EVM-002: always release guard
}

/**
 * Lock native ETH in the HTLC.
 * Returns the swap ID (bytes32 as hex string).
 */
export async function lockETH(
  htlcAddr: string,
  recipient: string,
  amount: bigint,
  hashLock: string,  // bytes32 hex string
  timeLock: bigint,
  signer: Signer,
  expectedChainId: number, // R106-EVM-002: required — callers must pass the expected chainId for chain validation
  onBroadcast?: (txHash: string) => void, // R161: invoked the instant the lock tx is broadcast (before tx.wait) so the caller can durably record the tx hash for post-broadcast recovery even if a LATER (inner or outer) timeout fires
): Promise<string> {
  // R70-EVM-002: re-entry guard — reject concurrent lockETH calls for the same hashLock+htlc pair
  // R109-EVM-001: key by hashLock+htlcAddr to avoid cross-function blocking when lockETH and
  // lockTokens share the same hashLock on different HTLC contracts.
  const lockKey = `${hashLock.toLowerCase()}:${htlcAddr.toLowerCase()}`;
  if (_activeLocks.has(lockKey)) throw new Error(`lockETH: a lock for hashLock ${hashLock} on ${htlcAddr} is already in progress`);
  _activeLocks.add(lockKey);
  try {
  // R66-EVM-002: reject zero-amount lock — sends {value: 0n}, creates value-less HTLC
  if (amount <= 0n) throw new Error('lockETH: amount must be greater than 0');
  // R76-EC-001: reject zero timeLock — counterparty could refund before our claim confirms
  if (timeLock === 0n) throw new Error('lockETH: timeLock must not be zero');
  // R77-EVM-NEW-1: reject all-zero hashLock — same reasoning as lockTokens; swap unclaimable
  if (!hashLock || hashLock.replace(/^0x/, '') === '0'.repeat(64)) throw new Error('lockETH: hashLock must not be all zeros');
  // R66-EVM-003: reject zero-address recipient — no one holds the key; swap silently fails
  // R68-EVM-001: normalize via getAddress() before compare — rejects alternate representations
  if (ethers.getAddress(recipient) === ethers.ZeroAddress) throw new Error('lockETH: recipient must not be the zero address');
  // R26-EVM-001: validate signer is on the expected chain before locking ETH
  // R33-EVM-008: compare as BigInt to avoid precision loss for large chainIds
  if (expectedChainId !== undefined) {
    // R99-SE-004: wrap getNetwork() — stalled RPC holds _activeLocks + caller guards for ~120s
    // R116-EVM-005: clear timer in .finally() to prevent ghost timer leak on fast-resolve path
    let _leNetTimer2: ReturnType<typeof setTimeout> | undefined;
    const network = await Promise.race([
      signer.provider!.getNetwork(),
      new Promise<never>((_, rej) => { _leNetTimer2 = setTimeout(() => rej(new Error('getNetwork timed out')), 15_000); }),
    ]).finally(() => clearTimeout(_leNetTimer2));
    if (network.chainId !== BigInt(expectedChainId)) {
      throw new Error(`Chain mismatch: wallet is on chainId ${network.chainId}, expected ${expectedChainId}. Switch networks in MetaMask.`);
    }
  }
  // R20-CRYPTO-002: verify contract is deployed before sending ETH — ETH sent to EOA is unrecoverable
  // R21-EVM-001 / R22-EVM-002: use typed sentinel to avoid matching third-party RPC error messages
  class _HtlcNotDeployedError2 extends Error { readonly isHtlcNotDeployed = true; }
  try {
    // R99-SE-005: wrap getCode() — stalled RPC holds evmFundingBroadcastedRef + evmKeyCopy for ~120s
    const code = await Promise.race([
      signer.provider!.getCode(htlcAddr),
      new Promise<never>((_, rej) => setTimeout(() => rej(new Error('getCode timed out')), 15_000)),
    ]);
    if (!code || code === '0x') throw new _HtlcNotDeployedError2(`HTLC contract not deployed at ${htlcAddr} on this network`);
  } catch (codeErr: unknown) {
    if ((codeErr as _HtlcNotDeployedError2).isHtlcNotDeployed) throw codeErr;
    const msg = codeErr instanceof Error ? codeErr.message : String(codeErr);
    throw new Error(`HTLC contract check failed (network/RPC error — check MetaMask): ${msg}`);
  }
  const ZERO_ADDRESS = '0x0000000000000000000000000000000000000000';
  const htlc = new Contract(htlcAddr, HTLC_ABI, signer);
  // R26-EVM-004: 300k matches lockTokens — ETH lock can exceed 200k for complex code paths
  // R39-EVM-003: wrap lock()+wait() to emit a recovery hint if the receipt is lost
  let receipt: ethers.TransactionReceipt | null;
  // R160-EVMLOCK-POSTBROADCAST-001: once htlc.lock() RESOLVES, the tx is broadcast (in the mempool) and MAY
  // mine — so any throw AFTER this point (wait timeout, RPC drop, replacement, missing-event) is POST-broadcast
  // and a naive retry would lock a SECOND batch under a fresh per-nonce swapId (no revert → stranded). Tag such
  // ambiguous throws with broadcasted+txHash so handleEvmFund keeps its idempotency guard and refuses to
  // re-lock. (A definitive on-chain REVERT below is NOT tagged: it mined and moved no funds, so retry is safe.)
  let _broadcastTxHash: string | undefined;
  try {
    const tx = await htlc.lock(recipient, ZERO_ADDRESS, amount, hashLock, timeLock, { value: amount, gasLimit: 300_000n, ...(await bumpedTxFees(signer)) });
    _broadcastTxHash = tx.hash;
    try { onBroadcast?.(tx.hash); } catch { /* ignore — recovery marker is best-effort */ }
    // R73-EVM-001: 120s timeout — same as refundSwap; prevents _activeLocks from leaking on stalled RPC
    let ethWaitId: ReturnType<typeof setTimeout>;
    const ethTimeoutReject = new Promise<never>((_, reject) => { ethWaitId = setTimeout(() => reject(new Error('lockETH: tx.wait() timed out after 120s — tx may still confirm')), 120_000); });
    try {
      receipt = await Promise.race([tx.wait(), ethTimeoutReject]);
    } finally { clearTimeout(ethWaitId!); }
  } catch (lockErr: unknown) {
    // R179-EVMLOCK-REPLACED-001: handle MetaMask speed-up/cancel (ethers v6 TRANSACTION_REPLACED). A wallet
    // "Speed up" produces a same-nonce, higher-fee REPLACEMENT (new hash, identical calldata) that mines the
    // REAL lock; ethers attaches the replacement's receipt. Treat the replacement as AUTHORITATIVE — extract the
    // swapId from its receipt and RETURN it — instead of discarding it and tagging the ORIGINAL (now-dropped)
    // hash, which post-reload recoverLockFromTx would mis-classify as a definitive {kind:'safe'} (both lookups
    // legitimately find nothing) -> clear the marker -> re-lock -> DOUBLE-LOCK + strand of the replacement's HTLC.
    const _re = lockErr as { code?: string; reason?: string; cancelled?: boolean; receipt?: ethers.TransactionReceipt | null; replacement?: { hash?: string } };
    if (_re.code === 'TRANSACTION_REPLACED') {
      if (_re.reason === 'cancelled' || _re.cancelled) {
        // "Cancel" = a 0-value self-send replaced our lock -> NO ETH locked -> safe to retry. Throw UNtagged so
        // handleEvmFund resets the guard and allows a clean retry (not a strand).
        throw new Error('lockETH: lock transaction was cancelled in the wallet — no ETH was locked; retry the swap.');
      }
      // Repriced/replaced: re-point the durable recovery marker to the REPLACEMENT hash (so any later recovery
      // classifies the real on-chain tx), then return the swapId straight from the replacement receipt.
      if (_re.replacement?.hash) { try { onBroadcast?.(_re.replacement.hash); } catch { /* best-effort */ } }
      if (_re.receipt && _re.receipt.status === 1) {
        const _sid = authenticatedLockedSwapId(htlc, htlcAddr, hashLock, _re.receipt.logs); // R239: hashLock+address-authenticated
        if (_sid) return _sid;
      }
      // Replacement is on-chain but the Locked event was not parseable here -> tag broadcasted with the
      // REPLACEMENT hash (NOT the dropped original) so the reload recovery adopts the real tx.
      throw Object.assign(new Error('lockETH: lock tx was sped up; the replacement is on-chain — reload to adopt the lock'),
        { broadcasted: true, txHash: _re.replacement?.hash ?? _broadcastTxHash });
    }
    const msg = lockErr instanceof Error ? lockErr.message : String(lockErr);
    throw Object.assign(new Error(
      `lockETH: tx failed or receipt lost — if ETH was deducted, scan the HTLC contract ` +
      `${htlcAddr} for a Locked event from your address to recover the swap ID. ` +
      `Original error: ${msg}`
    ), _broadcastTxHash ? { broadcasted: true, txHash: _broadcastTxHash } : {});
  }
  // Dropped/replaced is ambiguous (a replacement may have mined the lock) → tag broadcasted (fail-safe).
  if (!receipt) throw Object.assign(new Error('Transaction was dropped or replaced before confirmation'), _broadcastTxHash ? { broadcasted: true, txHash: _broadcastTxHash } : {});
  // Definitive revert: mined, moved no funds → retry is safe, do NOT tag.
  if (receipt.status !== 1) throw new Error('Transaction reverted on-chain');

  // Extract swap ID ONLY from an AUTHENTICATED Locked event (from htlcAddr, hashLock==ours) — R239.
  {
    const _sid = authenticatedLockedSwapId(htlc, htlcAddr, hashLock, receipt.logs);
    if (_sid) return _sid; // bytes32 id, bound to OUR hashLock
  }
  // status===1 but no AUTHENTICATED Locked event: the tx mined successfully → funds likely locked → tag broadcasted.
  throw Object.assign(new Error('Locked event not found in transaction receipt'), _broadcastTxHash ? { broadcasted: true, txHash: _broadcastTxHash } : {});
  } finally { _activeLocks.delete(lockKey); } // R70-EVM-002: always release guard
}

// R60-EVM-002: per-swapId reentrancy guard — prevents two concurrent claimSwap calls from
// both passing the pre-flight check and submitting duplicate transactions (second reverts after
// spending gas; both hold a reference to the same secret buffer which the first zeros at line 393).
const _claimInFlight = new Set<string>();

/** Claim a funded HTLC by revealing the secret. */
export async function claimSwap(
  htlcAddr: string,
  swapId: string,
  secret: Uint8Array,
  signer: Signer,
  expectedChainId?: number,
): Promise<{ blockNumber: number }> {
  if (secret.length !== 32) {
    throw new Error(`Secret must be exactly 32 bytes; got ${secret.length}`);
  }
  // R60-EVM-002: guard against concurrent invocations for the same swap
  // R97-EVM-001: normalize both components so mixed-case callers (EIP-55 htlcAddr or uppercase
  // bytes32 swapId) cannot bypass the guard by passing a differently-cased argument.
  const claimKey = `${htlcAddr.toLowerCase()}:${swapId.toLowerCase()}`;
  if (_claimInFlight.has(claimKey)) {
    throw new Error(`claimSwap already in-flight for swap ${swapId} — duplicate call rejected`);
  }
  _claimInFlight.add(claimKey);
  // R201-CLAIM-SENTINEL-STALE-001: track whether we reached the secret-revealing broadcast. EVERY throw before
  // this flips true is PRE-BROADCAST (no secret revealed) and gets tagged `preBroadcast:true` by the outer catch
  // below, so the caller (handleEvmClaim) can clear the load-bearing bch2swap:claimbroadcast sentinel it set
  // pre-flight. We flip it true the instant we ENTER the broadcast block (before htlc.claim()), so an ambiguous
  // submission timeout is treated as POSSIBLY-broadcast (keep sentinel = fail-safe over-protect), never cleared.
  let broadcastReached = false;
  try {
  // R26-EVM-001: validate chain before revealing secret on-chain
  // R33-EVM-008: compare as BigInt to avoid precision loss for large chainIds
  if (expectedChainId !== undefined) {
    // R99-SE-004: wrap getNetwork() — stalled RPC holds _claimInFlight + secret live for ~120s
    // R116-EVM-005: clear timer in .finally() to prevent ghost timer leak on fast-resolve path
    let _claimNetTimer: ReturnType<typeof setTimeout> | undefined;
    const network = await Promise.race([
      signer.provider!.getNetwork(),
      new Promise<never>((_, rej) => { _claimNetTimer = setTimeout(() => rej(new Error('getNetwork timed out')), 15_000); }),
    ]).finally(() => clearTimeout(_claimNetTimer));
    if (network.chainId !== BigInt(expectedChainId)) {
      throw new Error(`Chain mismatch: wallet is on chainId ${network.chainId}, expected ${expectedChainId}. Switch networks in MetaMask.`);
    }
  }
  // R31-EVM-001: pre-flight getSwap check before broadcasting secret in calldata.
  // If claim() would revert (wrong swapId, already claimed/refunded, unfunded), the secret
  // becomes visible in mempool and front-running bots can race-claim with higher gas.
  // Verify the swap is claimable before revealing the secret on-chain.
  // R44-CORE-001: wrap pre-flight in Promise.race to prevent indefinite hang on RPC node stall.
  // R62-EVM-001: capture the timer ID so it can be cleared after the race settles (prevents leak).
  let preflightTimerId: ReturnType<typeof setTimeout> | undefined;
  const swapData = await Promise.race([
    getSwap(htlcAddr, swapId, signer.provider!),
    new Promise<never>((_, reject) => {
      preflightTimerId = setTimeout(() => reject(new Error('EVM pre-flight check timed out after 15s')), 15_000);
    }),
  ]).finally(() => clearTimeout(preflightTimerId));
  if (!swapData || swapData.amount === 0n) {
    throw new Error(`Swap ${swapId.slice(0, 18)}... not found or unfunded — aborting claim to protect secret`);
  }
  if (swapData.claimed) {
    throw new Error(`Swap ${swapId.slice(0, 18)}... already claimed — secret already on-chain`);
  }
  if (swapData.refunded) {
    throw new Error(`Swap ${swapId.slice(0, 18)}... already refunded — cannot claim`);
  }
  // R69-EVM-003: verify the HTLC was funded for this signer as recipient.
  // A compromised RPC returning a different swap's struct (e.g. swapId=0 with our hashLock)
  // would have a different recipient, preventing the secret from being broadcast against the
  // wrong HTLC and exposed in calldata.
  // R99-SE-007: wrap getAddress() — stalled node holds _claimInFlight + secret live for ~120s
  const signerAddress = (await Promise.race([
    signer.getAddress(),
    new Promise<never>((_, rej) => setTimeout(() => rej(new Error('getAddress timed out')), 15_000)),
  ])).toLowerCase();
  if (swapData.recipient.toLowerCase() !== signerAddress) {
    throw new Error(
      `Swap ${swapId.slice(0, 18)}... recipient mismatch: HTLC is for ${swapData.recipient} ` +
      `but signer is ${signerAddress}. Aborting to protect secret.`
    );
  }
  // R138b-XCHAIN-001: timeLock is an absolute UNIX TIMESTAMP (seconds) — the deployed TokenHTLC is
  // block.timestamp based. Sanity-guard the shape: a legitimate future timeLock is on the order of
  // ~1.7e9..1.9e9. Reject a block-number-shaped value (≪1e9) or an absurd far-future value: if a
  // compromised/buggy RPC returned such a value the (now >= timeLock) expiry check below could be
  // wrong, and claim() could broadcast the secret on an already-expired swap (revert → secret exposed
  // in calldata). NOTE: this guard was INVERTED from the old block-number invariant (which rejected
  // timestamp-shaped values) when the client converted to the unix-timestamp contract basis.
  if (swapData.timeLock === 0n) {
    throw new Error('[claimSwap] timeLock is zero — invalid swap data from contract. Aborting to protect secret.');
  }
  if (swapData.timeLock < 1_000_000_000n || swapData.timeLock > 100_000_000_000n) {
    throw new Error(
      `[claimSwap] timeLock ${swapData.timeLock} is not a plausible unix timestamp (expected ~1.7e9) — ` +
      `contract invariant violated. Aborting to protect secret.`
    );
  }
  // R63-EVM-001: check timelock expiry BEFORE broadcasting secret — if the lock has expired,
  // claim() will revert but the secret is still visible in calldata, letting a front-runner
  // call refund() and pocket the funds while the victim's tx is permanently reverted.
  // R64-EVM-001: restructured to only catch network errors — prior catch-all silently swallowed
  // null-provider TypeErrors, bypassing the guard and exposing the secret.
  // R138b-XCHAIN-001: compare the latest block's TIMESTAMP (not block number) against the timeLock.
  let nowSec: bigint | undefined;
  try {
    // R94-EVM-001: 15s timeout — a stalled RPC here permanently locks _claimInFlight[swapId].
    let _claimBlockTimerId: ReturnType<typeof setTimeout> | undefined;
    const latest = await Promise.race([
      signer.provider!.getBlock('latest'),
      new Promise<never>((_, rej) => {
        _claimBlockTimerId = setTimeout(() => rej(new Error('[claimSwap] getBlock timed out')), 15_000);
      }),
    ]).finally(() => clearTimeout(_claimBlockTimerId));
    if (latest && Number.isFinite(latest.timestamp)) nowSec = BigInt(latest.timestamp);
  } catch {
    // getBlock network error or timeout — leave nowSec undefined; the R278 fail-closed check below aborts.
  }
  // R278-CLAIM-EXPIRY-FAILCLOSED-001: if we could NOT read chain time, do NOT broadcast the claim. Previously
  // nowSec===undefined SKIPPED the expiry check and proceeded (fail-OPEN) — but a claim mined at/after timeLock
  // REVERTS and leaks the preimage in the calldata; for the party whose claim FIRST reveals the secret, that
  // hands the counterparty a free sweep of the other leg. An unverifiable chain time on an irreversible
  // secret-reveal must fail CLOSED (retryable: the caller re-arms and the contract still enforces the timelock
  // on-chain). refundSwap already fails closed on the same read (~L1004); this closes the claim-side asymmetry.
  if (nowSec === undefined) {
    throw new Error(
      `[claimSwap] could not read chain time to verify swap ${swapId.slice(0, 18)}... is before its timelock ` +
      `— refusing to broadcast (a claim at/after timeLock reverts and exposes the secret). Retry.`
    );
  }
  if (nowSec >= swapData.timeLock) {
    throw new Error(
      `Swap ${swapId.slice(0, 18)}... EVM timelock expired at unix ${swapData.timeLock} ` +
      `(now: ${nowSec}) — claim would revert and expose secret`
    );
  }
  // R66-EVM-001: verify sha256(secret) === hashLock before revealing on-chain.
  // If the caller passes a stale or wrong secret, claim() reverts and the wrong value
  // is broadcast in calldata — gas wasted and the confusing "front-run" path triggered.
  const computedHash = ethers.sha256(secret).toLowerCase();
  const expectedHash = swapData.hashLock.toLowerCase();
  if (computedHash !== expectedHash) {
    throw new Error(
      `Secret does not match hashLock for swap ${swapId.slice(0, 18)}… ` +
      `(computed ${computedHash.slice(0, 10)}…, expected ${expectedHash.slice(0, 10)}…). ` +
      `Do not broadcast — wrong secret would be exposed in calldata.`
    );
  }
  const htlc = new Contract(htlcAddr, HTLC_ABI, signer);
  const secretHex = ethers.hexlify(secret);
  // R42-CORE-002: do NOT zero secret here — htlc.claim() may throw before broadcasting
  // (e.g. MetaMask rejection), leaving the caller's Uint8Array permanently zeroed and
  // the secret unrecoverable for retry. Zero only after the tx is submitted to mempool.
  // R26-EVM-003: raised from 150k to 250k — cold-address ERC-20 transfers can exceed 150k;
  // secret exposed in calldata on revert allows front-runner to race-claim with higher gas. (R104-EVM-002)
  // R102-EVM-001: wrap claim() submission — without timeout a stalled MetaMask/RPC holds
  // _claimInFlight locked and the secret zeroed, preventing retry until page reload.
  // R112-EVM-002: txSubmitted flag lets the finally block zero the secret on the 30s timeout
  // path (when the Promise.race rejects, secret.fill(0) on the next line is never reached).
  let txSubmitted = false;
  try {
  broadcastReached = true; // R201: from here on, the secret-revealing claim() is being broadcast — keep the sentinel on any failure
  let submitTimerId: ReturnType<typeof setTimeout> | undefined;
  const tx = await Promise.race([
    htlc.claim(swapId, secretHex, { gasLimit: 250_000n, ...(await bumpedTxFees(signer)) }) as Promise<ethers.ContractTransactionResponse>,
    new Promise<never>((_, rej) => {
      submitTimerId = setTimeout(() => rej(new Error('[claimSwap] claim() submission timed out after 30s')), 30_000);
    }),
  ]).finally(() => clearTimeout(submitTimerId));
  txSubmitted = true;
  secret.fill(0); // Safe to zero now: tx is submitted to mempool, secret is public
  // R57-EVM-001: clear the timeout after the race resolves to prevent timer leak and late-firing reject
  let claimTimeoutId: ReturnType<typeof setTimeout> | undefined;
  let receipt: ethers.TransactionReceipt | null;
  try {
  receipt = await Promise.race([
    tx.wait(),
    new Promise<never>((_, reject) => {
      claimTimeoutId = setTimeout(
        () => {
          // R59-EVM-001: attach txHash as a structured field so callers can surface it without
          // string parsing (e.g., to display a block-explorer link even on timeout).
          const err = new Error(
            `Claim tx ${tx.hash} broadcast but receipt timed out after 120s. ` +
            `WARNING: the secret is now public in the mempool. ` +
            `Once the tx confirms, the secret will appear in the Claimed event — use it to claim the counterparty HTLC. ` +
            `Check block explorer for tx status.`
          ) as Error & { txHash: string };
          err.txHash = tx.hash;
          reject(err);
        },
        120_000,
      );
    }),
  ]).finally(() => clearTimeout(claimTimeoutId));
  } catch (waitErr) {
    // R194-EVMCLAIM-REPLACED-001: handle a MetaMask speed-up/cancel of the CLAIM (ethers v6 TRANSACTION_REPLACED),
    // mirroring the R179 lockETH/lockTokens handler — claimSwap/refundSwap were the un-mirrored siblings. A
    // speed-up replaces the claim tx; the REPLACEMENT mines the real claim (revealing the secret), and ethers
    // rejects tx.wait() with the replacement receipt. Adopt it (return its blockNumber) so handleEvmClaim starts
    // the R190 confirm monitor instead of showing a misleading 'claim failed' for a claim that actually landed.
    const _re = waitErr as { code?: string; reason?: string; cancelled?: boolean; receipt?: ethers.TransactionReceipt | null };
    if (_re.code === 'TRANSACTION_REPLACED') {
      if (_re.reason === 'cancelled' || _re.cancelled) {
        // Cancel: the claim never mined; the sessionStorage secret survives for a retry (the in-memory copy was
        // already zeroed at submit). NOTE the secret may be public in the dropped original's mempool calldata.
        throw new Error('claimSwap: claim was cancelled in the wallet — retry the claim (your secret is preserved).');
      }
      if (_re.receipt && _re.receipt.status === 1) {
        for (const log of _re.receipt.logs) {
          try { const p = htlc.interface.parseLog(log); if (p && p.name === 'Claimed' && (p.args[0] as string)?.toLowerCase() === swapId.toLowerCase()) return { blockNumber: _re.receipt.blockNumber }; } catch { /* skip non-matching log */ }
        }
      }
      throw new Error('claimSwap: claim tx was sped up; the replacement is on-chain — reload to confirm and finalize the claim.');
    }
    throw waitErr;
  }
  if (!receipt) throw new Error('Claim transaction dropped — secret not revealed on-chain');
  if (receipt.status !== 1) {
    // R33-EVM-001: post-revert getSwap check to distinguish front-run from generic failure
    // R95-EVM-001: add 15s timeout — bare getSwap stall holds _claimInFlight locked indefinitely
    try {
      let _postClaimGsTimer: ReturnType<typeof setTimeout> | undefined;
      const postClaimData = await Promise.race([
        getSwap(htlcAddr, swapId, signer.provider!),
        new Promise<never>((_, rej) => {
          _postClaimGsTimer = setTimeout(() => rej(new Error('[claimSwap] post-revert getSwap timed out')), 15_000);
        }),
      ]).finally(() => clearTimeout(_postClaimGsTimer));
      if (postClaimData?.claimed) {
        throw new Error('Claim reverted: HTLC was already claimed by another party — check block explorer. The secret may be recoverable from the claiming tx calldata.');
      }
    } catch (innerErr) {
      if (innerErr instanceof Error && innerErr.message.includes('claimed by another')) throw innerErr;
      // getSwap failed — secret is exposed in calldata; tell user to act immediately
      throw new Error(
        `Claim tx reverted and post-revert check failed. ` +
        `Secret may now be visible in mempool calldata for swap ${swapId.slice(0, 18)}… — ` +
        `check the block explorer and claim the counterparty HTLC immediately if still possible. ` +
        `Original error: ${innerErr instanceof Error ? innerErr.message : String(innerErr)}`
      );
    }
    throw new Error('Claim transaction reverted on-chain');
  }
  // R21-EVM-003 / R22-EVM-001: verify Claimed event; use existing htlc object (no need for htlc2)
  let claimEventFound = false;
  for (const log of receipt.logs) {
    try {
      const parsed = htlc.interface.parseLog(log);
      if (parsed && parsed.name === 'Claimed' && (parsed.args[0] as string)?.toLowerCase() === swapId.toLowerCase()) {
        claimEventFound = true;
        break;
      }
    } catch { /* skip non-matching logs */ }
  }
  if (!claimEventFound) {
    throw new Error('Claim tx confirmed but Claimed event not found in receipt — ABI mismatch or contract issue');
  }
  // R190-EVMCLAIM-REORG-FINALITY-001: return the claim receipt's block so the caller can DEFER deleting the
  // non-recoverable secret until the claim is past the chain's tip-reorg horizon (requiredConfirmations).
  return { blockNumber: receipt.blockNumber };
  } finally {
    if (!txSubmitted) {
      secret.fill(0); // R112-EVM-002: submission timed out — zero defensively (idempotent if already zeroed)
    }
  }
  } catch (claimErr) {
    // R201-CLAIM-SENTINEL-STALE-001: tag a PRE-BROADCAST failure (pre-flight check threw before htlc.claim())
    // so handleEvmClaim can clear the stale bch2swap:claimbroadcast sentinel it set before this call. We tag ONLY
    // when broadcastReached is false (positive proof no secret was revealed) — a post-broadcast/ambiguous failure
    // is left untagged so the caller KEEPS the sentinel (fail-safe over-protect of the secret/recovery material).
    if (!broadcastReached && claimErr instanceof Error && !(claimErr as { preBroadcast?: boolean }).preBroadcast) {
      try { (claimErr as { preBroadcast?: boolean }).preBroadcast = true; } catch { /* frozen error — ignore */ }
    }
    throw claimErr;
  } finally {
    _claimInFlight.delete(claimKey); // R60-EVM-002: release reentrancy guard on all exit paths
  }
}

/** Refund a timed-out HTLC. */
export async function refundSwap(
  htlcAddr: string,
  swapId: string,
  signer: Signer,
): Promise<void> {
  const provider = signer.provider;
  if (!provider) throw new Error('Signer has no provider attached');

  const htlc = new Contract(htlcAddr, HTLC_ABI, signer);

  // R-REFUND-SENTINEL-STALE-001 (fix #5): track whether we reached the refund broadcast. EVERY throw before this flips
  // true is PRE-BROADCAST (pre-flight getSwap/getAddress/getBlock read failed — no refund tx submitted, no funds moved)
  // and gets tagged `preBroadcast:true` by the outer catch below, so the caller (refundEvm) can clear the load-bearing
  // bch2swap:refundbroadcast sentinel it set pre-flight and a retry can re-arm. It flips true the instant we ENTER the
  // refund broadcast (before htlc.refund()), so an ambiguous submission/timeout is treated as POSSIBLY-broadcast (keep
  // the sentinel = fail-safe over-protect), never cleared. Mirrors claimSwap's broadcastReached/preBroadcast tagging.
  let broadcastReached = false;
  try {

  // Check timelock before broadcasting — saves gas on guaranteed revert
  // R65-EVM-001: add 15s timeout on getSwap — without it a stalled RPC hangs the entire
  // watchAndRefund poll loop indefinitely, preventing the refund from ever completing.
  let preflight15Id: ReturnType<typeof setTimeout> | undefined;
  const swapData = await Promise.race([
    getSwap(htlcAddr, swapId, provider),
    new Promise<never>((_, reject) => {
      preflight15Id = setTimeout(() => reject(new Error('[refundSwap] getSwap timed out after 15s')), 15_000);
    }),
  ]).finally(() => clearTimeout(preflight15Id)); // R66-EVM-004: use finally so timer clears on rejection too
  if (!swapData) throw new Error('Swap not found — may not be funded yet');
  // R39-EVM-001: verify caller is the HTLC initiator before submitting the refund tx
  // R99-SE-007: wrap getAddress() — stalled node holds caller's evmRefundBroadcastedRef for ~120s
  const signerAddress = (await Promise.race([
    signer.getAddress(),
    new Promise<never>((_, rej) => setTimeout(() => rej(new Error('getAddress timed out')), 15_000)),
  ])).toLowerCase();
  if (swapData.initiator.toLowerCase() !== signerAddress) {
    throw new Error(
      `refundSwap: caller ${signerAddress} is not the HTLC initiator (${swapData.initiator}). ` +
      `Only the initiator can trigger a refund.`
    );
  }
  if (swapData.claimed) throw new Error('Swap already claimed — initiator revealed the secret on-chain');
  if (swapData.refunded || swapData.amount === 0n) throw new Error('Swap already refunded');
  // R138b-XCHAIN-001: INVARIANT — TokenHTLC timeLock is an absolute UNIX TIMESTAMP (block.timestamp,
  // seconds). Sanity-guard the shape (was inverted from the old block-number invariant on conversion):
  // reject a block-number-shaped value (≪1e9) or an absurd far-future value, either of which would
  // make the (now <= timeLock) expiry check below unreliable and could allow a premature refund.
  // R78-A4-003: reject zero timeLock — a contract returning timeLock=0 would trivially pass any
  // "expired" check, allowing an immediate refund regardless of actual lock state.
  if (swapData.timeLock === 0n) {
    throw new Error('[refundSwap] timeLock is zero — invalid swap data from contract.');
  }
  if (swapData.timeLock < 1_000_000_000n || swapData.timeLock > 100_000_000_000n) {
    throw new Error(`[refundSwap] timeLock value ${swapData.timeLock} is not a plausible unix timestamp (expected ~1.7e9). Contract invariant violated.`);
  }
  // R93-EVM-003: add 15s timeout — all other blocking network calls in this file are wrapped in
  // Promise.race; a stalled RPC after the pre-flight getSwap hangs refundSwap indefinitely,
  // permanently blocking the watchAndRefund loop and stranding timed-out HTLC funds.
  // R138b-XCHAIN-001: compare the latest block's TIMESTAMP (not block number) against the timeLock.
  // The contract's refund guard is `block.timestamp <= s.timeLock => revert TimeLockNotExpired`.
  let _blockTimeoutId: ReturnType<typeof setTimeout> | undefined;
  const latestForRefund = await Promise.race([
    provider.getBlock('latest'),
    new Promise<never>((_, rej) => {
      _blockTimeoutId = setTimeout(() => rej(new Error('[refundSwap] getBlock timed out after 15s')), 15_000);
    }),
  ]).finally(() => clearTimeout(_blockTimeoutId));
  if (!latestForRefund || !Number.isFinite(latestForRefund.timestamp)) {
    throw new Error('[refundSwap] could not read latest block timestamp — cannot verify timelock expiry.');
  }
  const nowSec = BigInt(latestForRefund.timestamp);
  if (nowSec <= swapData.timeLock) {
    // R23-EVM-002: clamp bigint→Number conversion to avoid Infinity for malicious oversized timeLock
    const rawDelta = swapData.timeLock - nowSec;
    const secsLeft = rawDelta > BigInt(Number.MAX_SAFE_INTEGER) ? Number.MAX_SAFE_INTEGER : Number(rawDelta);
    throw new Error(`Timelock has not expired yet. ~${Math.ceil(secsLeft / 60).toLocaleString()} minutes remaining.`);
  }

  // R21-EVM-004: 80k was insufficient for ERC-20 refunds to cold addresses (~50k for SSTORE + overhead)
  // R102-EVM-002: wrap refund() submission — stalled MetaMask/RPC was left uncovered while all other
  // tx submission calls were wrapped; watchAndRefund retries on timeout.
  broadcastReached = true; // from here the refund() tx is being submitted — keep the sentinel on any failure (fail-safe)
  const tx = await Promise.race([
    htlc.refund(swapId, { gasLimit: 150_000n, ...(await bumpedTxFees(signer)) }) as Promise<ethers.ContractTransactionResponse>,
    new Promise<never>((_, rej) => setTimeout(() => rej(new Error('[refundSwap] refund() submission timed out after 30s')), 30_000)),
  ]);
  // R72-EVM-002: separate tx-wait errors from on-chain-revert errors so we can surface each distinctly.
  // The old pattern wrapped both in a single try/catch whose substring check would swallow our own
  // 'reverted' message and replace it with a generic one, making dropped-tx and on-chain-revert
  // indistinguishable.
  let receipt: ethers.TransactionReceipt | null;
  try {
    // R65-EVM-001: add 120s timeout on tx.wait() — without it a stalled RPC node hangs the entire
    // refund permanently; timeout allows watchAndRefund to retry or surface the error to the caller.
    let refundWaitId: ReturnType<typeof setTimeout> | undefined;
    receipt = await Promise.race([
      tx.wait(),
      new Promise<never>((_, reject) => {
        refundWaitId = setTimeout(() => reject(new Error('[refundSwap] tx.wait timed out after 120s — tx may still confirm')), 120_000);
      }),
    ]).finally(() => clearTimeout(refundWaitId)); // R66-EVM-004: use finally so timer clears on rejection too
  } catch (e: unknown) {
    const msg = e instanceof Error ? e.message : String(e);
    const _re = e as { code?: string; reason?: string; cancelled?: boolean; receipt?: ethers.TransactionReceipt | null };
    if (_re.code === 'TRANSACTION_REPLACED') {
      // R194-EVMCLAIM-REPLACED-001: MetaMask speed-up/cancel of the REFUND (mirrors R179 lockETH/lockTokens + the
      // claimSwap R194 handler — refundSwap was the other un-mirrored sibling). Cancel => no refund landed, retry.
      // Repriced/replaced => the replacement mined the real refund; adopt its receipt and FALL THROUGH to the
      // normal success checks below instead of surfacing a misleading 'refund failed' for a refund that landed.
      if (_re.reason === 'cancelled' || _re.cancelled) {
        throw new Error('refundSwap: refund was cancelled in the wallet — retry the refund.');
      }
      if (!_re.receipt) {
        throw new Error('refundSwap: refund tx was sped up; the replacement is on-chain — reload to confirm the refund.');
      }
      receipt = _re.receipt;
    } else if (msg.includes('CALL_EXCEPTION')) {
      // R184-REFUND-CLAIMED-001: a CALL_EXCEPTION revert means EITHER timelock-not-expired OR the swap was
      // CLAIMED in the expiry-boundary straddle (claim/refund are mutually exclusive on-chain). The old code
      // unconditionally threw the 'timelock may not have expired' message here — factually WRONG for the
      // claimed case, and the UI's secret-recovery pivot (which keyed off a claim-signal substring) never
      // fired. Authoritatively check claimed BEFORE defaulting; if claimed, throw the claim-signal message the
      // UI recovery predicate matches (mirrors the receipt.status!==1 path below).
      try {
        let _ceGsTimer: ReturnType<typeof setTimeout> | undefined;
        const postRevert = await Promise.race([
          getSwap(htlcAddr, swapId, provider),
          new Promise<never>((_, rej) => { _ceGsTimer = setTimeout(() => rej(new Error('[refundSwap] CALL_EXCEPTION getSwap timed out')), 15_000); }),
        ]).finally(() => clearTimeout(_ceGsTimer));
        if (postRevert?.claimed) {
          throw new Error('Swap was claimed before refund executed — secret is on-chain, check Claimed events');
        }
      } catch (checkErr: unknown) {
        const checkMsg = checkErr instanceof Error ? checkErr.message : String(checkErr);
        if (checkMsg.includes('Swap was claimed')) throw checkErr;
        // non-fatal check failure — fall through to the generic timelock message
      }
      throw new Error('Refund rejected by contract — timelock may not have expired yet');
    } else {
      throw e;
    }
  }
  if (receipt === null) {
    throw new Error('Refund transaction was dropped from mempool — may need to rebroadcast');
  }
  if (receipt.status !== 1) {
    // R70-EVM-001: check if swap was claimed during our refund attempt — if so, surface the right error
    // R95-EVM-001: add 15s timeout — bare getSwap stall hangs watchAndRefund loop indefinitely
    try {
      let _postRefundGsTimer: ReturnType<typeof setTimeout> | undefined;
      const postRevert = await Promise.race([
        getSwap(htlcAddr, swapId, provider),
        new Promise<never>((_, rej) => {
          _postRefundGsTimer = setTimeout(() => rej(new Error('[refundSwap] post-revert getSwap timed out')), 15_000);
        }),
      ]).finally(() => clearTimeout(_postRefundGsTimer));
      if (postRevert?.claimed) {
        throw new Error('Swap was claimed before refund executed — secret is on-chain, check Claimed events');
      }
    } catch (checkErr: unknown) {
      const checkMsg = checkErr instanceof Error ? checkErr.message : String(checkErr);
      if (checkMsg.includes('Swap was claimed')) throw checkErr;
      // non-fatal check failure — fall through to generic error
    }
    throw new Error('Refund rejected by contract — timelock may not have expired yet');
  }
  } catch (refundErr) {
    // R-REFUND-SENTINEL-STALE-001 (fix #5): tag a PRE-BROADCAST failure (pre-flight getSwap/getAddress/getBlock timeout
    // or chain-read error threw before htlc.refund() submitted) so refundEvm can clear the stale refundbroadcast
    // sentinel it set. Tag ONLY when broadcastReached is false (positive proof no refund tx was submitted) — a
    // post-broadcast / ambiguous failure is left untagged so the caller KEEPS the sentinel (fail-safe over-protect).
    if (!broadcastReached && refundErr instanceof Error && !(refundErr as { preBroadcast?: boolean }).preBroadcast) {
      try { (refundErr as { preBroadcast?: boolean }).preBroadcast = true; } catch { /* frozen error — ignore */ }
    }
    throw refundErr;
  }
}

/** Fetch the full swap struct from the HTLC contract.
 *  Returns null if the swap does not exist (zero initiator address).
 */
export async function getSwap(
  htlcAddr: string,
  swapId: string,
  provider: Provider,
  // R143-EVM-CONFDEPTH-001: optional historical block tag. Reading the swap struct as-of an EARLIER
  // block lets callers prove the lock has confirmation DEPTH (it existed N blocks back), not just that
  // it exists at the reorg-able `latest` tip. Omitted → `latest` (default behaviour, unchanged).
  blockTag?: number | string,
): Promise<SwapData | null> {
  const htlc = new Contract(htlcAddr, HTLC_ABI, provider);
  // R96-EVM-003: internal timeout so callers that omit their own Promise.race are still protected
  let _gsTimer: ReturnType<typeof setTimeout> | undefined;
  const result = await Promise.race([
    (blockTag !== undefined
      ? htlc.getSwap(swapId, { blockTag })
      : htlc.getSwap(swapId)) as Promise<unknown[]>,
    new Promise<never>((_, rej) => {
      _gsTimer = setTimeout(() => rej(new Error('[getSwap] contract call timed out after 15s')), 15_000);
    }),
  ]).finally(() => clearTimeout(_gsTimer));
  // FIX R14-EVM-002: Return null for non-existent swap instead of throwing.
  // Zero initiator means the swap has not been funded yet or doesn't exist.
  const initiator = result[0] as string;
  if (initiator === ethers.ZeroAddress) {
    return null;
  }
  // R73-EVM-005: timeLock=0n means the struct is zero-initialized (swap doesn't exist or is corrupted)
  // — treat as non-existent. A real HTLC always has a future block as its timeLock.
  if ((result[5] as bigint) === 0n) {
    return null;
  }
  // R40-EVM-005: normalize addresses via ethers.getAddress() to guarantee EIP-55 checksum,
  // so downstream callers using strict === against MetaMask-provided addresses always match.
  return {
    initiator: ethers.getAddress(initiator),
    recipient: ethers.getAddress(result[1] as string),
    token: (result[2] as string) === ethers.ZeroAddress
      ? ethers.ZeroAddress
      : ethers.getAddress(result[2] as string),
    amount:    result[3] as bigint,
    hashLock:  result[4] as string,
    timeLock:  result[5] as bigint,
    claimed:   result[6] as boolean,
    refunded:  result[7] as boolean,
  };
}

/**
 * R143-EVM-CONFDEPTH-001: returns true IFF the counterparty lock for `swapId` exists at a REORG-SAFE
 * point with all required invariants intact — used to gate a UTXO responder's irreversible fund-commit
 * against a counterparty EVM lock (the EVM analog of the UTXO requiredConfirmations + R125-SE-010 path).
 *
 * Finality reference: prefers the OP-stack `'safe'` block tag (L1-batch-posted head — past the sequencer's
 * unsafe-head tip-reorg horizon, strictly stronger than an arbitrary L2 block count). If the RPC does not
 * serve `'safe'`, falls back to a numeric `requiredConfirmations` depth (tip-(reqConf-1)).
 *
 * FAILS CLOSED: returns false on any read error, on a too-shallow tip in the numeric fallback, if the lock
 * is absent / already claimed / refunded at the safe point, or if hashLock / recipient / amount / token /
 * minTimeLock do not match the agreed invariants (defeats a same-nonce replacement that reuses the public
 * hashLock but changes the recipient, lowers the amount, swaps the token, or shortens the refund timelock —
 * swapId = keccak(initiator,nonce) is parameter-independent).
 */
// R280-I1: per-chainId memo of RPCs that DON'T serve the 'safe' block tag. Once we see a genuine
// "unsupported block tag / invalid params" error we record the chainId here and skip the (throwing)
// 'safe' probe on subsequent calls, going straight to the numeric-depth fallback. This is ONLY for the
// genuinely-unsupported case — a transient/hostile error is NOT cached and fails closed (see below).
// R-SAFETAG-TTL: memo maps chainId -> timestamp, valid for SAFE_TAG_MEMO_TTL_MS. The session-permanent Set
// meant a chain tagged once (a misclassified error, or a FallbackProvider leaf-set that later gains a node
// serving 'safe') was PERMANENTLY downgraded to the numeric-depth fallback for the whole session. The TTL lets
// it re-probe the stronger 'safe' tag periodically. Fund-safe either way (the numeric fallback is itself
// fail-closed on too-shallow depth), so this only ever RESTORES the stronger finality proof, never weakens it.
const SAFE_TAG_MEMO_TTL_MS = 60 * 60_000; // 1 h — re-probe 'safe' support at most once/hour per chain
const _safeTagUnsupportedChains = new Map<string, number>();

/**
 * R280-I1: classify a 'safe'-tag read error. Returns true ONLY for a node that structurally cannot serve
 * the tag (JSON-RPC -32602 invalid params / ethers INVALID_ARGUMENT, or a message naming an invalid/unknown
 * block tag). Everything else — a timeout, a network drop, a hostile leaf erroring out — returns false so
 * the caller FAILS CLOSED instead of silently downgrading finality to the numeric tip-depth fallback.
 */
function isUnsupportedBlockTagError(err: unknown): boolean {
  const e = err as {
    code?: unknown; shortMessage?: unknown; message?: unknown;
    error?: { code?: unknown; message?: unknown };
    info?: { error?: { code?: unknown; message?: unknown } };
  } | null | undefined;
  const code = e?.code ?? e?.error?.code ?? e?.info?.error?.code;
  if (code === -32602 || code === 'INVALID_ARGUMENT') return true;
  // R-SAFEBLK: ethers v6 nests the raw JSON-RPC message under .info.error.message / .error.message (with a generic
  // .message wrapper), so gather every location AND a stringify fallback before matching — the earlier single
  // e.message check missed nested messages entirely.
  let stringified = '';
  try { stringified = JSON.stringify(e); } catch { /* circular — ignore */ }
  const msg = [e?.message, e?.shortMessage, e?.error?.message, e?.info?.error?.message, stringified]
    .filter((s): s is string => typeof s === 'string').join(' | ').toLowerCase();
  if (!msg) return false;
  // A node that lacks the tag reports it as an invalid/unknown/unsupported block tag or invalid params.
  if (msg.includes('invalid block tag') || msg.includes('unknown block') || msg.includes('invalid params')) return true;
  // R-SAFEBLK: Polygon Bor (and some L2 RPCs) reply "safe block not found" / "finalized block not found" (code
  // -32000) — a STRUCTURAL inability to serve the safe/finalized tag, not a transient error. Without this, the
  // caller failed closed on every Polygon claim (the safe-depth gate never passed → the initiator never revealed
  // the secret → the swap stranded to mutual refund). Treat as unsupported so it uses the numeric-depth fallback,
  // which still enforces requiredConfirmations (128 on Polygon) through the SAME quorum provider — sound finality.
  if ((msg.includes('safe') || msg.includes('finalized')) && msg.includes('block') && msg.includes('not found')) return true;
  return msg.includes('block tag') &&
    (msg.includes('invalid') || msg.includes('unknown') || msg.includes('unsupported') ||
     msg.includes('not found') || msg.includes('does not') || msg.includes("doesn't"));
}

export async function isEvmLockAtSafeDepth(
  htlcAddr: string,
  swapId: string,
  provider: Provider,
  requiredConfirmations: number,
  // R280-H2: `minTimeLock` (absolute unix-seconds) and `token` widen the invariant set so this quorum=2
  // finality gate also binds the lock's REFUND TIMELOCK and token — closing the fund-side sibling of R278 #6.
  // Without a timeLock bound, a malicious initiator can lock the correct hashLock/recipient/amount/token but
  // with an almost-immediate expiry; the responder would fund its UTXO leg against an EVM lock that refunds
  // out from under it, inverting the cross-chain timelock ordering. Both are optional (back-compat: omitted →
  // not enforced here); when provided this FAILS CLOSED unless lock.timeLock >= minTimeLock and token matches.
  inv: { hashLock: string; recipient?: string; minAmount?: bigint; minTimeLock?: bigint; token?: string },
): Promise<boolean> {
  let lock: SwapData | null = null;
  let safeServed = false;
  // R280-I1: best-effort chainId for the unsupported-'safe'-tag memo. If network detection fails we simply
  // don't cache (chainKey stays ''), preserving correctness at the cost of re-probing.
  let chainKey = '';
  try { chainKey = String((await provider.getNetwork()).chainId); } catch { /* un-cacheable */ }
  // R-SAFETAG-TTL: honor the memo only within its TTL; an expired entry is dropped so we re-probe 'safe'.
  const _memoTs = chainKey ? _safeTagUnsupportedChains.get(chainKey) : undefined;
  if (_memoTs !== undefined && Date.now() - _memoTs < SAFE_TAG_MEMO_TTL_MS) {
    // R280-I1: this chain is known not to serve 'safe' (within TTL) — skip the throwing probe, use numeric depth below.
    safeServed = false;
  } else {
    if (_memoTs !== undefined && chainKey) _safeTagUnsupportedChains.delete(chainKey); // expired → re-probe
    try {
      lock = await getSwap(htlcAddr, swapId, provider, 'safe');
      safeServed = true;
    } catch (err) {
      // R280-I1: only a genuinely-unsupported block tag is safe to downgrade to the numeric-depth fallback.
      // A transient or hostile error (timeout, network drop, a leaf erroring on 'safe' to force a weaker
      // proof) must FAIL CLOSED — otherwise a hostile leaf could strip the 'safe' finality guarantee at will.
      if (isUnsupportedBlockTagError(err)) {
        if (chainKey) _safeTagUnsupportedChains.set(chainKey, Date.now());
        safeServed = false; // RPC does not serve the 'safe' tag — fall back to a numeric depth below
      } else {
        return false; // transient / hostile → do not downgrade finality
      }
    }
  }
  if (!safeServed) {
    try {
      const tip = await Promise.race([
        provider.getBlockNumber(),
        new Promise<never>((_, rej) => setTimeout(() => rej(new Error('getBlockNumber timeout')), 15_000)),
      ]);
      // Fail CLOSED on a too-shallow tip (e.g. a fresh chain): cannot prove depth → do not accept.
      if (!(requiredConfirmations > 1 && tip > requiredConfirmations)) return false;
      lock = await getSwap(htlcAddr, swapId, provider, tip - (requiredConfirmations - 1));
    } catch {
      return false;
    }
  }
  if (!lock) return false;                                   // not present at the safe/depth point
  if (lock.claimed || lock.refunded) return false;
  if (lock.hashLock.toLowerCase() !== inv.hashLock.toLowerCase()) return false;
  if (inv.recipient && lock.recipient.toLowerCase() !== inv.recipient.toLowerCase()) return false;
  if (inv.minAmount !== undefined && lock.amount < inv.minAmount) return false;
  // R280-H2: bind the token — reject a lock funded with a different (e.g. worthless scam) token even if
  // hashLock/recipient/amount match. Compared case-insensitively (getSwap normalizes to EIP-55).
  if (inv.token !== undefined && lock.token.toLowerCase() !== inv.token.toLowerCase()) return false;
  // R280-H2: bind the REFUND TIMELOCK at the reorg-safe point. Fail closed unless the lock outlasts the
  // caller's required maturity (responder own-leg lock + safety margin) — a lock that can refund before the
  // responder's own leg matures inverts the cross-chain ordering and lets the initiator reclaim both legs.
  if (inv.minTimeLock !== undefined && lock.timeLock < inv.minTimeLock) return false;
  return true;
}

/**
 * Poll for a Claimed event on the given swapId.
 * Returns the 32-byte secret once the initiator claims the HTLC.
 * @param expectedHashLock - bytes32 hex string (sha256 of secret); REQUIRED — omitting it
 *   allows a compromised RPC to inject a wrong secret from a fabricated Claimed event.
 * @returns The revealed preimage secret as a Uint8Array.
 * OWNERSHIP: The caller must call `secret.fill(0)` after using the returned value.
 * Failure to do so leaves the 32-byte preimage in heap memory until GC.
 *
 * TODO: All call sites in SwapExecute.tsx must pass expectedHashLock — verify before deployment.
 */
// R52-EVM-001: abortable sleep — resolves early when signal fires, avoiding hours-long zombie loops
// after the calling component unmounts and destroys the provider.
function abortableSleep(ms: number, signal?: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) { reject(new DOMException('aborted', 'AbortError')); return; }
    // R109-EVM-002: store the abort handler so we can remove it when the natural timer fires.
    // Without this, each sleep iteration accumulates a listener on the same AbortSignal;
    // over 8,640 watchForClaim iterations this leaks 8,640 listeners.
    const onAbort = () => { clearTimeout(id); reject(new DOMException('aborted', 'AbortError')); };
    const id = setTimeout(() => {
      signal?.removeEventListener('abort', onAbort);
      resolve();
    }, ms);
    signal?.addEventListener('abort', onAbort, { once: true });
  });
}

export async function watchForClaim(
  htlcAddr: string,
  swapId: string,
  provider: Provider,
  fromBlock = 0,
  expectedHashLock: string,
  signal?: AbortSignal,
): Promise<Uint8Array> {
  // R33-EVM-002: guard against callers omitting the required hashLock
  // R65-EVM-002: also reject all-zeros hashLock — it passes the falsy check but a zero-hash
  // expectedHashLock would accept a fabricated zero-secret Claimed event from a compromised RPC.
  if (!expectedHashLock || expectedHashLock.replace(/^0x/, '') === '0'.repeat(64)) {
    throw new Error('[watchForClaim] expectedHashLock is required and must not be all zeros — omitting or using zero allows a compromised RPC to inject a wrong secret');
  }
  const htlc = new Contract(htlcAddr, HTLC_ABI, provider);
  const POLL_MS = 10_000;
  const MAX_POLLS = 8640; // ~24 hours at 10s intervals

  if (fromBlock === 0) {
    // R20-CRYPTO-003 / R22-EVM-003: scanning from block 1 causes range-too-large errors on public RPC
    // providers. Use tip - 9000 as a safe floor. If getBlockNumber fails, defer to first poll iteration.
    try {
      // R100-EVM-002: wrap startup getBlockNumber — bare await blocked watchForClaim entry for ~120s
      const tip = await Promise.race([
        provider.getBlockNumber(),
        new Promise<never>((_, rej) => setTimeout(() => rej(new Error('startup getBlockNumber timed out')), 15_000)),
      ]);
      // R37-EVM-003: increased from 50_000 to 90_000 blocks to cover maxLockBlocks=86_400
      // on Base Sepolia (2s/block) plus a ~4% margin. 50_000 < 86_400 left a ~36,400-block
      // gap where the Claimed event could be permanently missed for resumed swaps near the
      // end of their lock period.
      fromBlock = Math.max(1, tip - 90_000); // covers maxLockBlocks=86400 on Base Sepolia
      console.warn(`[watchForClaim] fromBlock=0 — scanning from near tip (${fromBlock}). Pass evmLockBlock for lossless recovery.`);
    } catch {
      // Do not fall back to block 1 — defer; will be resolved inside the poll loop below.
      fromBlock = -1;
      console.warn('[watchForClaim] fromBlock=0 and could not fetch tip — will retry in poll loop.');
    }
  }

  // Preserve the origin block so sliding-window logic never advances past where the event was emitted.
  // R23-EVM-001: must be `let` so it can be anchored on first deferred resolution (was `const`, which
  // locked originBlock at -1 permanently when startup getBlockNumber() failed, defeating the guard).
  let originBlock = fromBlock;
  let warnedAboutSlide = false;

  for (let i = 0; i < MAX_POLLS; i++) {
    // R115-EVM-001: check abort at top of each iteration so a signal fired during eth_getLogs
    // (which can block up to 30s) is detected as soon as the current queryFilter resolves,
    // rather than waiting until the next abortableSleep call at the bottom of the loop.
    if (signal?.aborted) throw new DOMException('aborted', 'AbortError');
    // Resolve deferred fromBlock if startup getBlockNumber failed
    if (fromBlock < 0) {
      try {
        // R95-EVM-003: add 15s timeout — bare getBlockNumber stall blocks the entire poll iteration
        let _wfcDeferTimer: ReturnType<typeof setTimeout> | undefined;
        const tip = await Promise.race([
          provider.getBlockNumber(),
          new Promise<never>((_, rej) => {
            _wfcDeferTimer = setTimeout(() => rej(new Error('[watchForClaim] deferred getBlockNumber timed out')), 15_000);
          }),
        ]).finally(() => clearTimeout(_wfcDeferTimer));
        fromBlock = Math.max(1, tip - 90_000); // R72-EVM-001: match startup window so deferred path doesn't miss old claims
        if (originBlock < 0) originBlock = fromBlock; // R23-EVM-001: anchor guard on first resolution
      } catch (e) {
        // R52-EVM-001: re-throw AbortError so the loop exits cleanly on unmount
        if ((e as { name?: string }).name === 'AbortError') throw e; // R59-EVM-003: name check avoids instanceof DOMException polyfill fragility
        if (signal?.aborted) throw new DOMException('aborted', 'AbortError');
        await abortableSleep(POLL_MS, signal);
        continue;
      }
    }
    // Query from lock block so claims older than 1000 blocks are not missed
    const filter = htlc.filters.Claimed(swapId);
    // R38-EVM-002: guard against fromBlock > latestBlock when RPC returns a stale tip.
    // queryFilter(filter, fromBlock, 'latest') errors if fromBlock > actual latest block.
    // R42-CORE-001: wrap getBlockNumber() in try/catch — if it throws (RPC timeout, rate
    // limit), we must continue the loop rather than letting the throw kill the poll permanently.
    let latestForQuery: number;
    try {
        // R96-EVM-001: add 15s timeout — bare getBlockNumber stall freezes the entire poll loop
      let _wfcLatestTimer: ReturnType<typeof setTimeout> | undefined;
      latestForQuery = await Promise.race([
        provider.getBlockNumber(),
        new Promise<never>((_, rej) => {
          _wfcLatestTimer = setTimeout(() => rej(new Error('[watchForClaim] getBlockNumber timed out')), 15_000);
        }),
      ]).finally(() => clearTimeout(_wfcLatestTimer));
    } catch (e) {
      if ((e as { name?: string }).name === 'AbortError') throw e; // R59-EVM-003: name check avoids instanceof DOMException polyfill fragility
      if (signal?.aborted) throw new DOMException('aborted', 'AbortError');
      await abortableSleep(2_000, signal);
      continue;
    }
    // R48-CORE-003: guard against RPC returning 0 without throwing — would cause indefinite
    // poll spin with fromBlock always > 0 = latestForQuery, sleeping forever.
    if (latestForQuery <= 0) {
      await abortableSleep(2_000, signal);
      continue;
    }
    if (fromBlock > latestForQuery) {
      await abortableSleep(2_000, signal);
      continue;
    }
    // R60-EVM-001: cap query window to 9000 blocks so we never hit "range too large" from public
    // RPCs, and so the range-too-large error path can never slide fromBlock past originBlock
    // (which would permanently skip the Claimed event). The previous code used Math.max on the
    // slide, causing tip-9000 to dominate and skip all blocks between originBlock and tip-9001.
    const capBlock = Math.min(latestForQuery, fromBlock + 8_999);
    let events: Awaited<ReturnType<typeof htlc.queryFilter>>;
    try {
      // R96-EVM-002: add 30s timeout — bare queryFilter stall freezes the poll loop indefinitely
      let _wfcQfTimer: ReturnType<typeof setTimeout> | undefined;
      events = await Promise.race([
        htlc.queryFilter(filter, fromBlock, capBlock),
        new Promise<never>((_, rej) => {
          _wfcQfTimer = setTimeout(() => rej(new Error('[watchForClaim] queryFilter timed out')), 30_000);
        }),
      ]).finally(() => clearTimeout(_wfcQfTimer));
    } catch (qErr: unknown) {
      // R22-EVM-003: queryFilter can fail with "block range too large" if fromBlock is too old.
      // Advance minimally — do NOT jump to tip-9000 (that permanently skips the Claimed event).
      // R97-EVM-002: distinguish timeout from RPC error — on timeout the same 9000-block window
      // would be retried next poll, causing an infinite timeout loop. On timeout, slide by half
      // the current window (floor 1) so successive timeouts progressively shrink the range to 1.
      // On a range-too-large RPC error, slide by 1 as before (already shrinks the window via capBlock).
      const qMsg = qErr instanceof Error ? qErr.message : String(qErr);
      const isTimeout = qMsg.includes('queryFilter timed out');
      const currentWindowSize = capBlock - fromBlock + 1;
      const slide = isTimeout ? Math.max(1, Math.floor(currentWindowSize / 2)) : 1;
      console.warn(`[watchForClaim] queryFilter ${isTimeout ? 'timed out' : 'failed'} (${qMsg.slice(0, 80)}) — sliding fromBlock by ${slide}`);
      if (signal?.aborted) throw new DOMException('aborted', 'AbortError');
      fromBlock = Math.max(originBlock, fromBlock + slide);
      await abortableSleep(POLL_MS, signal);
      continue;
    }
    if (events.length > 0) {
      // R34-EVM-004: iterate all events and skip ones with invalid/mismatched secrets;
      // only throw if none of the events produce a valid matching secret. A single
      // malformed or reorg'd log must not abort the scan prematurely.
      let foundSecret: Uint8Array | null = null;
      let depthSkipped = false; // R75-EVM-002: track confirmation-depth skips for clearer error message
      for (const evt of events) {
        if (!('args' in evt) || !evt.args) continue;
        const secretHex = evt.args[1] as string;
        if (!secretHex || secretHex === '0x' + '0'.repeat(64)) continue;
        let secretBytes: Uint8Array;
        try { secretBytes = ethers.getBytes(secretHex); } catch { continue; }
        if (secretBytes.length !== 32) continue;
        if (expectedHashLock) {
          const computedHash = ethers.sha256(secretBytes).toLowerCase();
          const normalized = expectedHashLock.toLowerCase().startsWith('0x')
            ? expectedHashLock.toLowerCase() : '0x' + expectedHashLock.toLowerCase();
          if (computedHash !== normalized) continue;
        }
        // R74-EVM-003: require at least 1 confirmation before returning the secret — a Claimed event
        // in the same block as the latest query could disappear on a shallow chain reorg, allowing a
        // malicious counterparty to recover EVM funds while our BCH2 HTLC claim is in-flight.
        const evtBlock = ('blockNumber' in evt ? (evt as { blockNumber: number }).blockNumber : 0);
        // R79-HIGH-2: treat evtBlock===0 (missing or invalid blockNumber) as a depth-skip rather
        // than a pass-through. A malicious/buggy RPC returning an event with no blockNumber would
        // bypass the 1-confirmation reorg guard, allowing the secret to be returned from an event
        // that may not yet be on-chain. Skipping is safe — next poll will re-evaluate with real data.
        if (evtBlock === 0 || latestForQuery - evtBlock < 1) {
          depthSkipped = true; // R75-EVM-002 / R79-HIGH-2: valid event skipped for depth — not an RPC error
          continue;
        }
        // foundSecret is freshly allocated (not a view into provider internals) — caller must zero
        foundSecret = secretBytes;
        break;
      }
      // R75-EVM-002: distinguish depth-skip (transient, next poll will confirm) from genuine mismatch
      if (!foundSecret) {
        if (depthSkipped) {
          await abortableSleep(POLL_MS, signal); continue; // wait one more block for confirmation
        }
        // R105-EVM-003: changed from throw to warn+continue — a hash mismatch on a single poll
        // iteration may be an RPC anomaly (reorg'd log, stale cache). Permanently aborting the
        // 24h loop on the first mismatch would abandon a valid swap. Retry next block instead.
        // R108-EVM-001: advance fromBlock past the bad-event range so re-poll doesn't re-query same blocks
        fromBlock = Math.max(originBlock, capBlock + 1);
        console.warn('[watchForClaim] Claimed event found but hash mismatch — may be RPC anomaly, retrying next block');
        await abortableSleep(POLL_MS, signal); continue;
      }
      // Only reach here if foundSecret is non-null.
      // R69-EVM-002: check abort before returning secret — queryFilter may resolve synchronously
      // (e.g., from ethers.js cache or mock provider), bypassing the loop-top abort check.
      if (signal?.aborted) throw new DOMException('Aborted', 'AbortError');
      return foundSecret;
    }
    // Slide fromBlock forward from last queried point, but never go backward past originBlock.
    // R35-HTLC-004: Math.max(originBlock, fromBlock+1, tip-9000) returns the LARGEST value,
    // so tip-9000 dominates for old swaps and permanently skips the Claimed event window.
    // Instead, warn explicitly when the slide would skip blocks, then advance as intended.
    // R47-CORE-003: reuse latestForQuery — no second getBlockNumber() call here. A second call
    // against a FallbackProvider can return a different (higher) tip, causing blocks between
    // latestForQuery and latestBlock to be permanently skipped.
    try {
      const nextFrom = fromBlock + 1;
      const rpcMinBlock = latestForQuery - 9_000;
      if (nextFrom < rpcMinBlock && !warnedAboutSlide) {
        warnedAboutSlide = true;
        console.warn(
          `[watchForClaim] RPC node window is smaller than swap age. ` +
          `Re-scanning from originBlock=${originBlock} each poll. ` +
          `Use an archival RPC node to guarantee zero missed events.`
        );
      }
      // R45-CORE-001 / R60-EVM-001: advance past the full scanned range (up to capBlock), not
      // just +1. capBlock is Math.min(latestForQuery, fromBlock+8999) so this either advances
      // past the scanned window (catching up to tip in steps) or to latestForQuery+1 when caught up.
      fromBlock = Math.max(originBlock, capBlock + 1);
    } catch (e) {
      console.warn('[watchForClaim] slide-forward failed — fromBlock unchanged:', e);
    }
    await abortableSleep(POLL_MS, signal);
  }
  throw new Error('Timed out waiting for claim event on HTLC');
}

/**
 * Polls until the EVM HTLC timelock expires, then refunds the swap.
 * Call this on the responder side after funding if the initiator goes offline.
 * Returns the refund tx hash.
 *
 * When this throws Error('CLAIMED_WITH_SECRET'), the Error has a `.secret: Uint8Array` property.
 * The CALLER MUST call `err.secret.fill(0)` after using the secret to prevent heap exposure.
 *
 * @internal NOT CURRENTLY USED — wire up a caller with proper CLAIMED_WITH_SECRET + provider
 * cleanup before deploying this function in production.
 */
export async function watchAndRefund(
  htlcAddress: string,
  swapId: string,
  provider: JsonRpcProvider,
  signer: Signer,
  timeLockSec: number, // R138b-XCHAIN-001: absolute unix timestamp (seconds), not a block number
  onBlockUpdate?: (current: number, target: number) => void,
  expectedHashLock?: string | null,
  signal?: AbortSignal, // R61-EVM-004: optional abort signal to interrupt the 24-hour poll loop
): Promise<string> {
  // R35-EVM-001 / R138b-XCHAIN-001: reject an implausible timeLock early — a zero/negative or
  // block-number-shaped value would cause the first poll to find now >= timeLock (always true),
  // call refundSwap before the swap is funded, and silently return swapId on "Swap not found".
  if (!Number.isInteger(timeLockSec) || timeLockSec < 1_000_000_000 || timeLockSec > 100_000_000_000) {
    throw new Error(`watchAndRefund: invalid timeLockSec=${timeLockSec}; must be a plausible unix timestamp`);
  }
  const MAX_POLLS = 8640; // 24 hours at 10s intervals
  // R76-EC-002: ownership note — watchAndRefund does NOT own or destroy the provider.
  // The caller is responsible for calling destroyProvider(provider) after this function returns or throws.
  // This matches the exported API contract: callers construct the provider and must clean it up.
  for (let i = 0; i < MAX_POLLS; i++) {
    // R33-EVM-005: guard getBlockNumber against total RPC failure — an unguarded throw would
    // abort the poll loop permanently, leaving the HTLC unrefunded after timelock expiry.
    let nowSec: number;
    if (signal?.aborted) throw new DOMException('watchAndRefund aborted', 'AbortError');
    try {
      // R101-EVM-002 / R138b-XCHAIN-001: read the latest block TIMESTAMP (not number) — the unix-timestamp
      // contract enforces refund on block.timestamp. Wrap in timeout so a stall can't block the poll ~120s.
      const latest = await Promise.race([
        provider.getBlock('latest'),
        new Promise<never>((_, rej) => setTimeout(() => rej(new Error('watchAndRefund getBlock timed out')), 15_000)),
      ]);
      if (!latest || !Number.isFinite(latest.timestamp)) throw new Error('no block timestamp');
      nowSec = latest.timestamp;
    } catch {
      await abortableSleep(10_000, signal); // R61-EVM-004: abortable sleep
      continue;
    }
    onBlockUpdate?.(nowSec, timeLockSec);
    if (nowSec > timeLockSec) {
      // FIX R14-EVM-001: Handle already-refunded gracefully
      // R38-EVM-001: return swapId is INSIDE the try block (success path only); the
      // catch block either returns/throws for terminal cases, or falls through to the
      // sleep below for transient errors. There is NO unconditional return after the
      // try/catch — that caused transient errors to report false success immediately.
      try {
        await refundSwap(htlcAddress, swapId, signer);
        // Refund confirmed — return the swapId as the canonical identifier
        return swapId;
      } catch (e: unknown) {
        const msg = e instanceof Error ? e.message : String(e);
        if (msg.includes('already refunded') || msg.includes('Swap not found')) {
          // Already refunded or swap never existed — treat as success
          return swapId;
        }
        if (msg.includes('already claimed') || msg.includes('Swap already claimed')) {
          // R46-CORE-001: attempt to recover the secret from the Claimed event before giving up.
          // Only attempt recovery if expectedHashLock was provided — omitting it allows a
          // compromised RPC to inject a wrong secret via a fabricated Claimed event (watchForClaim guard).
          if (expectedHashLock) {
            let recoveredSecret: Uint8Array | null = null;
            try {
              // R95-EVM-002: add 15s timeout — bare getBlockNumber stall hangs watchAndRefund claimed-recovery path
              let _warGbnTimer: ReturnType<typeof setTimeout> | undefined;
              const tip = await Promise.race([
                provider.getBlockNumber(),
                new Promise<never>((_, rej) => {
                  _warGbnTimer = setTimeout(() => rej(new Error('[watchAndRefund] getBlockNumber timed out')), 15_000);
                }),
              ]).finally(() => clearTimeout(_warGbnTimer));
              recoveredSecret = await watchForClaim(
                htlcAddress,
                swapId,
                provider,
                Math.max(1, tip - 100_000),
                expectedHashLock,
                signal, // R64-EVM-002: propagate abort signal — without this, unmount cannot stop 24h zombie loop
              );
              // Surface the secret to the caller via a typed error so it can claim the BCH2 HTLC
              const claimedErr = new Error('CLAIMED_WITH_SECRET') as Error & { secret: Uint8Array };
              claimedErr.secret = recoveredSecret;
              recoveredSecret = null; // ownership transferred — do NOT zero (caller uses it), set to null to skip finally-zero
              throw claimedErr;
            } catch (inner) {
              if ((inner as Error).message === 'CLAIMED_WITH_SECRET') throw inner; // re-throw owned secret
              // watchForClaim failed — fall back to hint
              throw new Error(`Swap already claimed. Try extracting the secret from the Claimed event for swap ${swapId}.`);
            } finally {
              recoveredSecret?.fill(0); // only fires if throw happened before ownership transfer
            }
          }
          // No expectedHashLock provided — cannot safely verify recovered secret; surface hint only
          throw new Error('Swap already claimed by initiator — extract secret from Claimed event to recover funds');
        }
        // R37-EVM-001: transient RPC/congestion error — log and retry on next iteration
        // rather than permanently exiting the loop. Throwing here would leave the HTLC
        // unrefunded past expiry (fund loss) for any non-fatal network hiccup.
        // R40-EVM-006 / R41-EVM-001: detect non-retryable wallet lock / disconnect / rejection
        // and surface to caller immediately. MetaMask 4001 says "User denied" (capital U, "denied"
        // not "rejected"), so we check both strings. 4100 = "unauthorized" (wallet locked/no accounts).
        const lowerMsg = msg.toLowerCase();
        const errCode = (e as { code?: unknown }).code;
        const isNonRetryable =
          lowerMsg.includes('wallet') ||
          lowerMsg.includes('locked') ||
          lowerMsg.includes('disconnected') ||
          lowerMsg.includes('user rejected') ||
          lowerMsg.includes('user denied') ||
          lowerMsg.includes('unauthorized') ||
          lowerMsg.includes('provider') ||
          errCode === 4001 ||
          errCode === 4100 ||
          errCode === 'ACTION_REJECTED';
        if (isNonRetryable) {
          throw new Error(
            `watchAndRefund: wallet rejected or disconnected for swap ${swapId}. ` +
            `Unlock your wallet and call refundSwap('${htlcAddress}', '${swapId}') manually to recover funds. ` +
            `Error: ${msg}`
          );
        }
        console.warn(`[watchAndRefund] refundSwap transient error (will retry in 10s): ${msg}`);
        // fall through to sleep and loop — DO NOT return here
      }
      // DO NOT put return swapId here — fall through to the sleep below and continue looping
    }
    await abortableSleep(10_000, signal); // R61-EVM-004: abortable sleep so callers can exit cleanly
  }
  throw new Error(
    `watchAndRefund: gave up after ${MAX_POLLS} polls for swap ${swapId}. ` +
    `The HTLC is likely still refundable on-chain. Call refundSwap('${htlcAddress}', '${swapId}') ` +
    `manually with a funded signer to recover the funds.`
  );
}

// ============================================================================
// Read-only provider (for watching without MetaMask)
// ============================================================================

// R26-EVM-005: secondary public RPC endpoints for failover (primary comes from evm-config.ts rpcUrl)
const FALLBACK_RPCS: Record<number, string[]> = {
  // R-POLYRPC-DEAD (2026-07-13): dropped 'https://polygon-rpc.com' (HTTP 401 "tenant disabled").
  // R-POLYHIST (2026-07-13): Polygon leg needs THREE capabilities the public RPCs supply unevenly (BROWSER-tested,
  // i.e. with CORS): (a) 'latest' reads/broadcast, (b) HISTORICAL eth_call (finality gate reads the lock at
  // tip-requiredConfirmations because Polygon Bor can't serve the 'safe' tag), (c) getLogs (watchForClaim reads the
  // Claimed event to recover the secret). Findings:
  //   polygon-rpc.com: DEAD (401 tenant disabled).           publicnode: 403 on historical AND getLogs; POISONS a
  //   nodies: NO CORS header → browser blocks it.            FallbackProvider (its 403 isn't tolerated) → removed.
  //   drpc:  CORS+historical ok, 400 on getLogs.             tenderly: CORS + historical + getLogs ALL ok.
  // ethers' FallbackProvider uses the FIRST leaf for getLogs (a later 400/403 isn't retried), so tenderly must be
  // FIRST. [tenderly, drpc] gives: getLogs (quorum-1 watch) = tenderly-first ✅; historical (quorum-2 finality) =
  // both serve ✅; 'latest' = both ✅. Two leaves → quorum-2 has no spare (fail-closed if one is down), acceptable.
  // Verified end-to-end against mainnet (q1 getLogs recovered the live secret; q2 historical read succeeded).
  137:      ['https://polygon.gateway.tenderly.co', 'https://polygon.drpc.org'],
  // R-POLYHIST (Arbitrum parity, 2026-07-13): publicnode 403s getLogs beyond ~100 blocks AND ordering it FIRST
  // poisoned the getLogs FallbackProvider (same failure that broke Polygon) — dropped. Both arb1 + drpc serve
  // getLogs (9000-blk windows) + 'safe' tag + latest IN-BROWSER (CORS-verified); arb1 FIRST because ethers uses
  // the first leaf for getLogs. Arbitrum serves 'safe' (unlike Polygon Bor) so the finality gate needs no historical
  // fallback. Browser-verified end-to-end: q1 getLogs (arb1-first) + q2 'safe' both form.
  42161:    ['https://arb1.arbitrum.io/rpc', 'https://arbitrum.drpc.org'],
  84532:    ['https://sepolia.base.org', 'https://base-sepolia-rpc.publicnode.com'],
  421614:   ['https://sepolia-rollup.arbitrum.io/rpc', 'https://arbitrum-sepolia-rpc.publicnode.com'],
  11155111: ['https://rpc.sepolia.org', 'https://ethereum-sepolia-rpc.publicnode.com'],
};

/** Create a Provider for a given chainId using the configured RPC URL + fallbacks.
 * R206-EVM-QUORUM-001: opts.quorum lets FINALITY-gating call sites (the irreversible secret-reveal /
 * re-lock / claim-finalize reads) require N-of-leaves AGREEMENT instead of the ethers default quorum=1
 * (= first-responder, which a single hostile/lagging RPC can answer). Only applies when a FallbackProvider
 * is built (>=2 leaves); a single-URL chain has no FallbackProvider to gate, so quorum is clamped to the
 * leaf count (with a warning) rather than tripping ethers' "quorum exceed provider weight" assertion.
 * Non-finality reads MUST keep the default (call with no opts) for liveness. */
export function getPublicProvider(chainId: number, opts?: { quorum?: number }): Provider {
  // R39-CFG-001: explicit null-check so the error clearly identifies an unsupported chain
  // rather than falling through to the misleading "No public RPC configured" message.
  const cfg = getEvmConfig(chainId as EvmChainId); // R112-CFG-003: boundary cast — getPublicProvider accepts number for public API compat
  if (!cfg) {
    throw new Error(`getPublicProvider: chain ${chainId} is not a supported EVM chain`);
  }
  const primaryUrl = cfg.rpcUrl;
  const fallbacks = FALLBACK_RPCS[chainId] ?? [];
  const urls = primaryUrl
    ? (fallbacks.includes(primaryUrl) ? fallbacks : [primaryUrl, ...fallbacks])
    : fallbacks;
  if (urls.length === 0) throw new Error(`No public RPC configured for chainId ${chainId}`);
  // R105-EVM-004: warn if this chain has no deployed HTLC — contract calls will fail at runtime
  const htlcCfg = EVM_CHAINS[chainId as EvmChainId];
  if (!htlcCfg || htlcCfg.htlcAddress === '0x0000000000000000000000000000000000000000') {
    console.warn(`[getPublicProvider] chain ${chainId} has no deployed HTLC; contract calls will fail`);
  }
  if (urls.length === 1) {
    // R206-EVM-QUORUM-001: single trusted RPC — no FallbackProvider, so quorum>1 cannot be enforced.
    if (opts?.quorum != null && opts.quorum > 1) {
      // R206-EVM-QUORUM-002 (fail-closed): on a SUPPORTED (mainnet, real-funds) chain a finality gate MUST get its
      // requested multi-RPC quorum — silently returning a single-backend provider would re-open the single-lying-RPC
      // vector on an irreversible reveal/lock read. THROW so the caller's finality gate fails closed rather than
      // trusting one RPC. Non-supported (testnet) chains keep the soft warn. (Latent today: both supported chains
      // carry 3 distinct RPC leaves, so this branch is unreachable in the current config — it guards future misconfig.)
      if ((SUPPORTED_EVM_CHAINS as readonly number[]).includes(chainId)) {
        throw new Error(`getPublicProvider: chain ${chainId} has only 1 RPC but a finality gate requested quorum=${opts.quorum}; refusing to degrade to single-backend trust`);
      }
      console.warn(`[getPublicProvider] chain ${chainId} has only 1 RPC; requested quorum=${opts.quorum} cannot be enforced (single-backend trust).`);
    }
    return patchFeeData(new JsonRpcProvider(urls[0])); // R-POLY-GASSTATION-001: bypass ethers' Polygon gas station
  }
  const leaves = urls.map(url => patchFeeData(new JsonRpcProvider(url))); // R-POLY-GASSTATION-001
  // R206-EVM-QUORUM-001: clamp the requested quorum to the available leaf count so we never trip ethers'
  // assertArgument("quorum exceed provider weight") (provider-fallback.js). Each leaf has default weight 1.
  let fbOptions: { quorum?: number };
  if (opts?.quorum != null) {
    const q = Math.max(1, Math.min(opts.quorum, leaves.length));
    if (q < opts.quorum) {
      // R206-EVM-QUORUM-002 (fail-closed): a SUPPORTED (mainnet) chain that cannot supply the requested finality
      // quorum must fail closed, not silently clamp to first-responder trust. Testnet keeps the soft clamp+warn.
      if ((SUPPORTED_EVM_CHAINS as readonly number[]).includes(chainId)) {
        throw new Error(`getPublicProvider: chain ${chainId} has only ${leaves.length} RPCs but a finality gate requested quorum=${opts.quorum}; refusing to degrade`);
      }
      console.warn(`[getPublicProvider] chain ${chainId}: requested quorum=${opts.quorum} exceeds ${leaves.length} RPCs; clamped to ${q}.`);
    }
    fbOptions = { quorum: q };
  } else {
    // R-POLYHIST: NO explicit quorum == a LIVENESS read per the design contract above ("Non-finality reads MUST
    // keep the default … for liveness" = first-responder). But ethers' OWN default quorum is ceil(sum(weights)/2)
    // = 2 for a 3-leaf chain — UNMEETABLE for getLogs where only ONE public leaf serves it in-browser (this is the
    // Arbitrum secret-read fund-loss + the latent trap on any 3-leaf chain). Make the code match the contract:
    // default to quorum 1. Finality gates are unaffected — they ALWAYS pass explicit { quorum: 2 }.
    fbOptions = { quorum: 1 };
  }
  const fb = new FallbackProvider(
    leaves.map(provider => ({ provider, stallTimeout: 2_000 })),
    chainId,
    fbOptions,
  );
  // R-POLY-GASSTATION-002: the FallbackProvider's OWN getFeeData is AbstractProvider's, which for Polygon (137)
  // consults the deprecated/CSP-blocked gas-station network plugin — patchFeeData only overrode the LEAF providers,
  // not fb itself, so a signer connected to fb (the HTLC lock/claim/refund path, SwapExecute ~1025/1042) still threw
  // SERVER_ERROR before broadcast. Delegate fb.getFeeData to the already-patched leaves (eth_gasPrice), trying each.
  (fb as unknown as { getFeeData: () => Promise<FeeData> }).getFeeData = async () => {
    let lastErr: unknown;
    for (const leaf of leaves) {
      try {
        // Per-leaf 8s cap: ethers' internal populateTransaction re-calls getFeeData WITHOUT our outer 15s race,
        // so a reachable-but-hanging leaf must not stall the fee read up to the FetchRequest default (~300s).
        return await Promise.race([
          leaf.getFeeData(),
          new Promise<never>((_, rej) => setTimeout(() => rej(new Error('leaf getFeeData timeout')), 8_000)),
        ]);
      } catch (e) { lastErr = e; }
    }
    throw lastErr ?? new Error('getFeeData: all fallback backends failed');
  };
  // R224-RECOVER-QUORUM-001: expose the leaf providers so recoverLockFromTx can require UNANIMOUS not-found across
  // ALL backends before it clears the lockpending marker + authorizes an IRREVERSIBLE re-lock. A FallbackProvider
  // here is quorum=1 (ethers default ceil(2/2)=1), so every read resolves on the FIRST responder — an honest-but-
  // lagging/pruned RPC answering not-found first would otherwise drive a false 'safe' -> double-lock + strand.
  // (We attach our OWN reference rather than digging into ethers' private config — version-robust; same leaf
  // objects the FallbackProvider holds, so destroyProvider still cleans them up exactly once.)
  try { (fb as unknown as { __leafProviders?: JsonRpcProvider[] }).__leafProviders = leaves; } catch { /* ignore */ }
  return fb;
}

/**
 * R38-EVM-003: Safely destroy a provider, handling both JsonRpcProvider (which has .destroy())
 * and FallbackProvider (which does not — but wraps multiple JsonRpcProviders that each do).
 * Use this instead of inline `(provider as ethers.JsonRpcProvider).destroy?.()` calls, which
 * silently no-op on FallbackProvider and leave its sub-providers' connections open.
 */
export function destroyProvider(provider: Provider | null | undefined): void {
  if (!provider) return;
  // R51-EVM-001: mutually-exclusive branches prevent double-destroy if a future ethers version adds
  // destroy() to FallbackProvider (which would otherwise cause sub-providers to be destroyed twice).
  // FallbackProvider is identified by providerConfigs and is always handled by recursion.
  // Leaf providers (JsonRpcProvider, WebSocketProvider) are handled by direct destroy().
  if ('providerConfigs' in provider) {
    // FallbackProvider — destroy each sub-provider
    const fp = provider as { providerConfigs?: Array<{ provider: Provider }> };
    for (const cfg of fp.providerConfigs ?? []) {
      destroyProvider(cfg.provider);
    }
  } else if ('destroy' in provider && typeof (provider as { destroy?: () => void }).destroy === 'function') {
    // Leaf provider with destroy() — call directly
    try { (provider as { destroy: () => void }).destroy(); } catch { /* ignore */ }
  }
}
