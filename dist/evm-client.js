import { BrowserProvider, Contract, ethers, JsonRpcProvider, FallbackProvider } from 'ethers';

// src/evm-client.ts

// src/chain-config.ts
globalThis.process?.env?.BCH2_SWAP_NETWORK === "regtest";

// src/evm-config.ts
var NATIVE_ETH_ADDRESS = "0x0000000000000000000000000000000000000000";
var EVM_CHAINS = {
  // R114-CFG-002: Ethereum Sepolia (11155111) — in EvmChainId type but no contract deployed.
  // Included here so getEvmConfig(11155111) returns a config (not null → crash) and so
  // validateEvmConfigs() can check it. DO NOT add to SUPPORTED_EVM_CHAINS until deployed.
  11155111: {
    chainId: 11155111,
    name: "Ethereum Sepolia",
    shortName: "eth",
    nativeSymbol: "ETH",
    avgBlockTimeSec: 12,
    requiredConfirmations: 4,
    // R143: ~48s; Ethereum Sepolia (not deployed/used yet)
    htlcAddress: "0x0000000000000000000000000000000000000000",
    // TODO: deploy contract
    minLockSeconds: 300,
    maxLockSeconds: 86400,
    minLockBlocks: 300,
    maxLockBlocks: 86400,
    rpcUrl: "https://ethereum-sepolia-rpc.publicnode.com",
    tokens: {}
  },
  // R266-ARB-ENABLE: HTLC DEPLOYED on Arbitrum Sepolia + added to SUPPORTED_EVM_CHAINS. Lock params are identical
  // to the proven-safe Base Sepolia (300/86400, on-chain-verified), and Arbitrum supports the 'safe'/'finalized'
  // block tags so the R148/R206 reorg-safe finality reads work. USDT/USDC already deployed on Arbitrum Sepolia.
  421614: {
    chainId: 421614,
    name: "Arbitrum Sepolia",
    shortName: "arb",
    nativeSymbol: "ETH",
    avgBlockTimeSec: 1,
    requiredConfirmations: 30,
    // R143: ~30s at 1s/block (≈ Base Sepolia's 15×2s reorg-safe window)
    htlcAddress: "0x405A6dD5b51a00C5F789C9D215e4986ba1Dc9963",
    // R266: deployed TokenHTLCTestnet (MIN/MAX_LOCK_SECONDS 300/86400, verified on-chain)
    // WARNING: minLockBlocks here overrides chain-config.ts values (mainnet=43200/86400).
    // Swap engine reads from evm-config.ts for EVM-chain config. Keep these consistent with chain-config.ts
    // when deploying to mainnet.
    // R31-EVM-003: 300 blocks = ~5 min on Arb Sepolia (1s/block). Mainnet should use 2160+ (72 min at 1s/block).
    minLockSeconds: 300,
    maxLockSeconds: 86400,
    minLockBlocks: 300,
    maxLockBlocks: 86400,
    rpcUrl: "https://sepolia-rollup.arbitrum.io/rpc",
    tokens: {
      USDT: {
        symbol: "USDT",
        address: "0x1F6A3cEE99F04A306FE99E0E783be4C07DEd2525",
        decimals: 6,
        name: "Tether USD"
      },
      USDC: {
        symbol: "USDC",
        address: "0x77a07183922417C381262723fFe548dBF1afa838",
        decimals: 6,
        name: "USD Coin"
      },
      ETH: { symbol: "ETH", address: NATIVE_ETH_ADDRESS, decimals: 18, name: "Ether" }
      // R266: native ETH swappable (HTLC address(0) path)
    }
  },
  84532: {
    chainId: 84532,
    name: "Base Sepolia",
    shortName: "base",
    nativeSymbol: "ETH",
    avgBlockTimeSec: 2,
    requiredConfirmations: 15,
    // R143: ~30s, past Base Sepolia OP-stack tip-reorg horizon (2s blocks)
    // R138b-XCHAIN-001: canonical TokenHTLCTestnet (UNIX-TIMESTAMP based, MIN_LOCK_SECONDS=300,
    // MAX_LOCK_SECONDS=86400, verified on-chain). Reconciled with packages/swap-core
    // (TOKEN_HTLC_ADDRESS.baseSepoliaTestnet) + prover/e2e/config-base-sepolia.json (htlc_test_address).
    // PREVIOUS value 0xe0ED04861A00FC1f2656AEbde11590CDcBA767a2 was the ZK-DEX BCH2SwapEscrow
    // (no lock/claim/getSwap selectors) — every EVM lock reverted. See AUDIT_LOG R138 / R138b.
    htlcAddress: "0x9A7D64F9dF98112A16E56B1eD9F2Bb8D9986a4cF",
    // R138b-XCHAIN-001: authoritative lock bounds in SECONDS, matching the deployed contract's
    // MIN_LOCK_SECONDS/MAX_LOCK_SECONDS read on-chain. minLockBlocks/maxLockBlocks below are a
    // coarse block-window hint for event scanning only (Base Sepolia ~2s/block → 86400 blocks ≈ 48h).
    minLockSeconds: 300,
    maxLockSeconds: 86400,
    minLockBlocks: 300,
    maxLockBlocks: 86400,
    rpcUrl: "https://sepolia.base.org",
    tokens: {
      USDC: {
        symbol: "USDC",
        // R138b-XCHAIN-001: canonical MockUSDC shared with packages/swap-core + web-wallet
        // (prover/e2e/config-base-sepolia.json usdc_address). PREVIOUS 0x94F6567f… was a divergent
        // bch2-swap-only MockUSDC deployment, breaking interop with canonical-ecosystem counterparties.
        address: "0x5cAd6F5A4eC28Ec42e3953A728a5Eea35719BB0D",
        decimals: 6,
        name: "USD Coin"
      },
      // NOTE: no canonical testnet USDT exists in packages/swap-core. This MockUSDT is bch2-swap-internal
      // (offers are takeable only between bch2-swap users, not canonical-ecosystem wallets). Verified deployed.
      USDT: {
        symbol: "USDT",
        address: "0x0F697BB2f8eAdb75C868CfD58e6096Ab726B3E49",
        decimals: 6,
        name: "Tether USD"
      },
      ETH: { symbol: "ETH", address: NATIVE_ETH_ADDRESS, decimals: 18, name: "Ether" }
      // R266: native ETH swappable (HTLC address(0) path)
    }
  },
  // ── Polygon MAINNET (137) — TokenHTLCSwap deployed 0x405A6dD5b51a00C5F789C9D215e4986ba1Dc9963 (MIN 6h / MAX 48h,
  //    verified on-chain). Token addresses match the KDF/NonKYC PLG20 contracts. minLock/maxLockSeconds MUST equal
  //    the deployed contract's MIN_LOCK_SECONDS/MAX_LOCK_SECONDS. ───────────────────────────────────────────────
  137: {
    chainId: 137,
    name: "Polygon",
    shortName: "poly",
    nativeSymbol: "POL",
    avgBlockTimeSec: 2,
    requiredConfirmations: 128,
    // Polygon reorg safety — well beyond ~16-block milestone finality
    htlcAddress: "0x405A6dD5b51a00C5F789C9D215e4986ba1Dc9963",
    minLockSeconds: 21600,
    // 6h — MUST match contract MIN_LOCK_SECONDS
    maxLockSeconds: 172800,
    // 48h — MUST match contract MAX_LOCK_SECONDS
    minLockBlocks: 10800,
    // ~6h at 2s (event-scan hint only)
    maxLockBlocks: 86400,
    // ~48h at 2s (event-scan hint only)
    // R-POLYHIST: primary must be tenderly (NOT publicnode) — getPublicProvider prepends rpcUrl, and ethers'
    // FallbackProvider uses the FIRST leaf for getLogs; publicnode 403s on getLogs+historical and poisons the
    // read, so it's dropped from Polygon entirely. tenderly serves latest+historical+getLogs; drpc backs it.
    rpcUrl: "https://polygon.gateway.tenderly.co",
    tokens: {
      USDC: { symbol: "USDC", address: "0x3c499c542cEF5E3811e1192ce70d8cC03d5c3359", decimals: 6, name: "USD Coin" },
      // native Circle USDC (KDF/NonKYC USDC-PLG20)
      USDT: { symbol: "USDT", address: "0xc2132D05D31c914a87C6611C10748AEb04B58e8F", decimals: 6, name: "Tether USD" },
      // USDT-PLG20
      POL: { symbol: "POL", address: NATIVE_ETH_ADDRESS, decimals: 18, name: "Polygon" }
      // native gas token (HTLC address(0) path)
    }
  },
  // ── Arbitrum One MAINNET (42161) — TokenHTLCSwap 0x141F8f62F92c6486a7EfE8D0891A6800d7ED1186 (MIN 6h / MAX 48h,
  //    verified on-chain). Native Circle USDC + USDT + native ETH. ───────────────────────────────────────────────
  42161: {
    chainId: 42161,
    name: "Arbitrum",
    shortName: "arb",
    nativeSymbol: "ETH",
    avgBlockTimeSec: 1,
    requiredConfirmations: 30,
    // Arbitrum soft finality is fast (sequencer); reorgs are rare
    htlcAddress: "0x141F8f62F92c6486a7EfE8D0891A6800d7ED1186",
    minLockSeconds: 21600,
    // 6h — MUST match contract MIN_LOCK_SECONDS
    maxLockSeconds: 172800,
    // 48h — MUST match contract MAX_LOCK_SECONDS
    minLockBlocks: 21600,
    maxLockBlocks: 172800,
    // R-POLYHIST: primary must be arb1 (NOT publicnode) — getPublicProvider prepends rpcUrl and ethers uses the FIRST
    // leaf for getLogs; publicnode 403s getLogs beyond ~100 blocks and would poison the secret-read. See FALLBACK_RPCS.
    rpcUrl: "https://arb1.arbitrum.io/rpc",
    tokens: {
      USDC: { symbol: "USDC", address: "0xaf88d065e77c8cC2239327C5EDb3A432268e5831", decimals: 6, name: "USD Coin" },
      // native Circle USDC
      USDT: { symbol: "USDT", address: "0xFd086bC7CD5C481DCC9C85ebE478A1C0b69FCbb9", decimals: 6, name: "Tether USD" },
      // USDT (Arbitrum)
      ETH: { symbol: "ETH", address: NATIVE_ETH_ADDRESS, decimals: 18, name: "Ether" }
      // native gas token
    }
  }
};
var SUPPORTED_EVM_CHAINS = [137, 42161];
function getEvmConfig(chainId) {
  return EVM_CHAINS[chainId] ?? null;
}

// src/evm-client.ts
var HTLC_ABI = [
  "function lock(address recipient, address token, uint256 amount, bytes32 hashLock, uint256 timeLock) payable returns (bytes32)",
  "function claim(bytes32 id, bytes32 secret)",
  "function refund(bytes32 id)",
  "function getSwap(bytes32 id) view returns (address initiator, address recipient, address token, uint256 amount, bytes32 hashLock, uint256 timeLock, bool claimed, bool refunded)",
  "event Locked(bytes32 indexed id, address indexed initiator, address recipient, address token, uint256 amount, bytes32 hashLock, uint256 timeLock)",
  "event Claimed(bytes32 indexed id, bytes32 secret)",
  "event Refunded(bytes32 indexed id)"
];
var ERC20_ABI = [
  "function balanceOf(address owner) view returns (uint256)",
  "function allowance(address owner, address spender) view returns (uint256)",
  "function approve(address spender, uint256 amount) returns (bool)"
];
async function connectMetaMask() {
  const win = window;
  if (!win.ethereum) {
    throw new Error("MetaMask not found. Please install the MetaMask browser extension.");
  }
  const provider = new BrowserProvider(win.ethereum);
  await provider.send("eth_requestAccounts", []);
  const signer = await provider.getSigner();
  const address = await signer.getAddress();
  let _connectNetTimer;
  const network = await Promise.race([
    provider.getNetwork(),
    new Promise((_, rej) => {
      _connectNetTimer = setTimeout(() => rej(new Error("getNetwork timed out")), 15e3);
    })
  ]).finally(() => clearTimeout(_connectNetTimer));
  const chainId = Number(network.chainId);
  return { provider, signer, address, chainId };
}
async function switchToChain(chainId) {
  const win = window;
  if (!win.ethereum) throw new Error("MetaMask not found.");
  const hexChainId = "0x" + chainId.toString(16);
  try {
    await win.ethereum.request({
      method: "wallet_switchEthereumChain",
      params: [{ chainId: hexChainId }]
    });
  } catch (e) {
    const err = e;
    if (err.code === 4001) {
      throw new Error("Network switch cancelled. Please switch to the required network in MetaMask and try again.");
    }
    if (err.code === 4902) {
      throw new Error(
        `Network (chainId ${chainId}) is not configured in MetaMask. Please add it manually in MetaMask settings.`
      );
    }
    throw e;
  }
}
async function getTokenBalance(tokenAddr, walletAddr, provider) {
  const token = new Contract(tokenAddr, ERC20_ABI, provider);
  return Promise.race([
    token.balanceOf(walletAddr),
    new Promise((_, rej) => setTimeout(() => rej(new Error("[getTokenBalance] balanceOf timed out after 15s")), 15e3))
  ]);
}
async function approveToken(tokenAddr, spenderAddr, amount, signer) {
  const approveKey = `${tokenAddr.toLowerCase()}:${spenderAddr.toLowerCase()}`;
  if (_approveInFlight.has(approveKey)) throw new Error("[approveToken] Approval already in flight for this token/spender pair");
  _approveInFlight.add(approveKey);
  try {
    const token = new Contract(tokenAddr, ERC20_ABI, signer);
    const wouldSucceed = await Promise.race([
      token.approve.staticCall(spenderAddr, amount),
      new Promise((_, rej) => setTimeout(() => rej(new Error("approve staticCall timed out")), 15e3))
    ]);
    if (!wouldSucceed) {
      throw new Error("Token approval would return false (non-standard ERC-20). Swap cannot proceed.");
    }
    const tx = await Promise.race([
      token.approve(spenderAddr, amount, { gasLimit: 150000n }),
      new Promise((_, rej) => setTimeout(() => rej(new Error("approve() submission timed out")), 3e4))
    ]);
    let approveWaitId;
    const approveTimeoutReject = new Promise((_, rej) => {
      approveWaitId = setTimeout(() => rej(new Error("approveToken: tx.wait() timed out after 120s \u2014 tx may still confirm")), 12e4);
    });
    const receipt = await Promise.race([tx.wait(), approveTimeoutReject]).finally(() => clearTimeout(approveWaitId));
    if (!receipt || receipt.status !== 1) throw new Error("Token approval transaction reverted");
  } finally {
    _approveInFlight.delete(approveKey);
  }
}
async function ensureAllowance(tokenAddr, ownerAddr, spenderAddr, amount, signer, provider, chainId) {
  const signerAddr = (await Promise.race([
    signer.getAddress(),
    new Promise((_, rej) => setTimeout(() => rej(new Error("getAddress timed out")), 15e3))
  ])).toLowerCase();
  if (ownerAddr.toLowerCase() !== signerAddr) {
    throw new Error(
      `ensureAllowance: ownerAddr ${ownerAddr} does not match signer address ${signerAddr} \u2014 stale address after account switch?`
    );
  }
  const htlcConfig = getEvmConfig(chainId);
  if (!htlcConfig) throw new Error(`No EVM config for chainId ${chainId}`);
  if (spenderAddr.toLowerCase() !== htlcConfig.htlcAddress.toLowerCase()) {
    throw new Error(`ensureAllowance: spenderAddr ${spenderAddr} does not match HTLC contract ${htlcConfig.htlcAddress} for chainId ${chainId}`);
  }
  const ZERO_ADDR = "0x0000000000000000000000000000000000000000";
  if (htlcConfig.htlcAddress.toLowerCase() === ZERO_ADDR) {
    throw new Error(`ensureAllowance: HTLC contract not deployed on chainId ${chainId} (address is zero)`);
  }
  const token = new Contract(tokenAddr, ERC20_ABI, provider);
  const allowance = await Promise.race([
    token.allowance(ownerAddr, spenderAddr),
    new Promise((_, rej) => setTimeout(() => rej(new Error("allowance check timed out")), 15e3))
  ]);
  if (allowance < amount) {
    await approveToken(tokenAddr, spenderAddr, amount, signer);
  }
}
function hashPreimage(secret) {
  return ethers.sha256(secret);
}
var _approveInFlight = /* @__PURE__ */ new Set();
var _activeLocks = /* @__PURE__ */ new Set();
function patchFeeData(provider) {
  provider.getFeeData = async () => {
    const gp = BigInt(await provider.send("eth_gasPrice", []));
    if (gp <= 0n) throw new Error("eth_gasPrice returned 0 \u2014 refusing to build an underpriced transaction");
    let tip = gp;
    try {
      const t = BigInt(await provider.send("eth_maxPriorityFeePerGas", []));
      if (t > 0n && t <= gp) tip = t;
    } catch {
    }
    return new ethers.FeeData(gp, gp * 2n, tip);
  };
  return provider;
}
function makeEvmProvider(rpc) {
  return patchFeeData(new JsonRpcProvider(rpc));
}
async function bumpedTxFees(signer) {
  try {
    const fd = await Promise.race([
      signer.provider.getFeeData(),
      new Promise((_, rej) => setTimeout(() => rej(new Error("getFeeData timed out")), 15e3))
    ]);
    const prioBase = fd.maxPriorityFeePerGas ?? 1000000n;
    const feeBase = fd.maxFeePerGas ?? fd.gasPrice ?? 2000000n;
    const maxPriorityFeePerGas = prioBase * 3n;
    let maxFeePerGas = feeBase * 3n;
    if (maxFeePerGas < maxPriorityFeePerGas) maxFeePerGas = maxPriorityFeePerGas * 2n;
    return { maxFeePerGas, maxPriorityFeePerGas };
  } catch {
    return {};
  }
}
async function recoverLockFromTx(htlcAddr, txHash, provider, scan) {
  const leaves = (() => {
    const ls = provider.__leafProviders;
    return Array.isArray(ls) && ls.length > 0 ? ls : [provider];
  })();
  const checkOneLeaf = async (p) => {
    const htlc = new Contract(htlcAddr, HTLC_ABI, p);
    let receipt;
    try {
      receipt = await p.getTransactionReceipt(txHash);
    } catch {
      return { kind: "blocked" };
    }
    if (receipt) {
      if (receipt.status !== 1) return { kind: "safe" };
      for (const log of receipt.logs) {
        if (htlcAddr && String(log.address).toLowerCase() !== htlcAddr.toLowerCase()) continue;
        try {
          const parsed = htlc.interface.parseLog(log);
          if (parsed && parsed.name === "Locked") {
            const a = parsed.args;
            const okHash = !scan?.hashLock || String(a.hashLock).toLowerCase() === scan.hashLock.toLowerCase();
            const okRcpt = !scan?.recipient || String(a.recipient).toLowerCase() === scan.recipient.toLowerCase();
            const okAmt = scan?.minAmount === void 0 || a.amount >= scan.minAmount;
            if (okHash && okRcpt && okAmt) return { kind: "locked", swapId: parsed.args[0] };
          }
        } catch {
        }
      }
      return { kind: "blocked" };
    }
    let tx;
    try {
      tx = await p.getTransaction(txHash);
    } catch {
      return { kind: "blocked" };
    }
    if (tx) return { kind: "blocked" };
    if (scan?.sender && scan.hashLock) {
      try {
        const tip = await p.getBlockNumber();
        const start = Math.max(0, scan.fromBlock && scan.fromBlock > 0 ? scan.fromBlock : tip - 5e4);
        const CHUNK = 1800;
        for (let to = tip; to >= start; to -= CHUNK) {
          const from = Math.max(start, to - CHUNK + 1);
          const evs = await htlc.queryFilter(htlc.filters.Locked(null, scan.sender), from, to);
          for (const ev of evs) {
            const a = ev.args;
            if (!a) continue;
            const okHash = String(a.hashLock).toLowerCase() === scan.hashLock.toLowerCase();
            const okRcpt = !scan.recipient || String(a.recipient).toLowerCase() === scan.recipient.toLowerCase();
            const okAmt = scan.minAmount === void 0 || a.amount >= scan.minAmount;
            if (okHash && okRcpt && okAmt) return { kind: "locked", swapId: String(a.id) };
          }
          if (from <= start) break;
        }
      } catch {
        return { kind: "blocked" };
      }
    }
    return { kind: "safe" };
  };
  const results = await Promise.all(leaves.map((p) => checkOneLeaf(p).catch(() => ({ kind: "blocked" }))));
  const found = results.find((r) => r.kind === "locked");
  if (found) return found;
  if (results.some((r) => r.kind === "blocked")) return { kind: "blocked" };
  return { kind: "safe" };
}
function authenticatedLockedSwapId(htlc, htlcAddr, hashLock, logs) {
  for (const log of logs) {
    if (htlcAddr && String(log.address).toLowerCase() !== htlcAddr.toLowerCase()) continue;
    try {
      const parsed = htlc.interface.parseLog(log);
      if (parsed && parsed.name === "Locked" && String(parsed.args.hashLock).toLowerCase() === hashLock.toLowerCase()) {
        return parsed.args[0];
      }
    } catch {
    }
  }
  return null;
}
async function lockTokens(htlcAddr, recipient, tokenAddr, amount, hashLock, timeLock, signer, expectedChainId, onBroadcast) {
  const lockKey = `${hashLock.toLowerCase()}:${htlcAddr.toLowerCase()}`;
  if (_activeLocks.has(lockKey)) throw new Error(`lockTokens: a lock for hashLock ${hashLock} on ${htlcAddr} is already in progress`);
  _activeLocks.add(lockKey);
  try {
    if (amount <= 0n) throw new Error("lockTokens: amount must be greater than 0");
    if (timeLock === 0n) throw new Error("lockTokens: timeLock must not be zero");
    if (!hashLock || hashLock.replace(/^0x/, "") === "0".repeat(64)) throw new Error("lockTokens: hashLock must not be all zeros");
    if (ethers.getAddress(recipient) === ethers.ZeroAddress) throw new Error("lockTokens: recipient must not be the zero address");
    if (expectedChainId !== void 0) {
      let _ltNetTimer;
      const network = await Promise.race([
        signer.provider.getNetwork(),
        new Promise((_, rej) => {
          _ltNetTimer = setTimeout(() => rej(new Error("getNetwork timed out")), 15e3);
        })
      ]).finally(() => clearTimeout(_ltNetTimer));
      if (network.chainId !== BigInt(expectedChainId)) {
        throw new Error(`Chain mismatch: wallet is on chainId ${network.chainId}, expected ${expectedChainId}. Switch networks in MetaMask.`);
      }
    }
    class _HtlcNotDeployedError extends Error {
      constructor() {
        super(...arguments);
        this.isHtlcNotDeployed = true;
      }
    }
    try {
      const code = await Promise.race([
        signer.provider.getCode(htlcAddr),
        new Promise((_, rej) => setTimeout(() => rej(new Error("getCode timed out")), 15e3))
      ]);
      if (!code || code === "0x") throw new _HtlcNotDeployedError(`HTLC contract not deployed at ${htlcAddr} on this network`);
    } catch (codeErr) {
      if (codeErr.isHtlcNotDeployed) throw codeErr;
      const msg = codeErr instanceof Error ? codeErr.message : String(codeErr);
      throw new Error(`HTLC contract check failed (network/RPC error \u2014 check MetaMask): ${msg}`);
    }
    const htlc = new Contract(htlcAddr, HTLC_ABI, signer);
    let receipt = null;
    let _broadcastTxHash;
    try {
      const lockTx = await htlc.lock(recipient, tokenAddr, amount, hashLock, timeLock, { gasLimit: 300000n, ...await bumpedTxFees(signer) });
      _broadcastTxHash = lockTx.hash;
      try {
        onBroadcast?.(lockTx.hash);
      } catch {
      }
      let lockWaitId;
      const lockTimeoutReject = new Promise((_, reject) => {
        lockWaitId = setTimeout(() => reject(new Error("lockTokens: tx.wait() timed out after 120s \u2014 tx may still confirm")), 12e4);
      });
      try {
        receipt = await Promise.race([lockTx.wait(), lockTimeoutReject]);
      } finally {
        clearTimeout(lockWaitId);
      }
    } catch (lockErr) {
      {
        const _re = lockErr;
        if (_re.code === "TRANSACTION_REPLACED" && _re.reason !== "cancelled" && !_re.cancelled) {
          if (_re.replacement?.hash) {
            try {
              onBroadcast?.(_re.replacement.hash);
            } catch {
            }
          }
          if (_re.receipt && _re.receipt.status === 1) {
            const _sid = authenticatedLockedSwapId(htlc, htlcAddr, hashLock, _re.receipt.logs);
            if (_sid) return _sid;
          }
          throw Object.assign(
            new Error("lockTokens: lock tx was sped up; the replacement is on-chain \u2014 reload to adopt the lock"),
            { broadcasted: true, txHash: _re.replacement?.hash ?? _broadcastTxHash }
          );
        }
      }
      try {
        const tokenContract = new Contract(tokenAddr, ERC20_ABI, signer);
        const revokeTx = await Promise.race([
          tokenContract.approve(htlcAddr, 0n),
          new Promise((_, rej) => setTimeout(() => rej(new Error("revoke approve() timed out")), 3e4))
        ]);
        let revokeWaitId;
        await Promise.race([
          revokeTx.wait(),
          new Promise((_, rej) => {
            revokeWaitId = setTimeout(() => rej(new Error("revoke timed out")), 3e4);
          })
        ]).catch(() => {
        }).finally(() => clearTimeout(revokeWaitId));
      } catch {
      }
      {
        const _reCancel = lockErr;
        if (_reCancel.code === "TRANSACTION_REPLACED" && (_reCancel.reason === "cancelled" || _reCancel.cancelled)) {
          throw new Error("lockTokens: lock transaction was cancelled in the wallet \u2014 no tokens were locked; retry the swap.");
        }
      }
      const rawMsg = lockErr instanceof Error ? lockErr.message : String(lockErr);
      const isAllowanceIssue = rawMsg.toLowerCase().includes("allowance") || rawMsg.toLowerCase().includes("insufficient") || rawMsg.includes("CALL_EXCEPTION");
      if (isAllowanceIssue) {
        throw new Error(
          `lockTokens: lock() reverted \u2014 likely an allowance race with a concurrent wallet operation. Wait for any pending transactions to confirm and retry the swap.`
        );
      }
      if (lockErr instanceof Error && _broadcastTxHash) Object.assign(lockErr, { broadcasted: true, txHash: _broadcastTxHash });
      throw lockErr;
    }
    if (!receipt) throw Object.assign(new Error("Transaction was dropped or replaced before confirmation"), _broadcastTxHash ? { broadcasted: true, txHash: _broadcastTxHash } : {});
    if (receipt.status !== 1) throw new Error("Transaction reverted on-chain");
    {
      const _sid = authenticatedLockedSwapId(htlc, htlcAddr, hashLock, receipt.logs);
      if (_sid) return _sid;
    }
    throw Object.assign(new Error("Locked event not found in transaction receipt"), _broadcastTxHash ? { broadcasted: true, txHash: _broadcastTxHash } : {});
  } finally {
    _activeLocks.delete(lockKey);
  }
}
async function lockETH(htlcAddr, recipient, amount, hashLock, timeLock, signer, expectedChainId, onBroadcast) {
  const lockKey = `${hashLock.toLowerCase()}:${htlcAddr.toLowerCase()}`;
  if (_activeLocks.has(lockKey)) throw new Error(`lockETH: a lock for hashLock ${hashLock} on ${htlcAddr} is already in progress`);
  _activeLocks.add(lockKey);
  try {
    if (amount <= 0n) throw new Error("lockETH: amount must be greater than 0");
    if (timeLock === 0n) throw new Error("lockETH: timeLock must not be zero");
    if (!hashLock || hashLock.replace(/^0x/, "") === "0".repeat(64)) throw new Error("lockETH: hashLock must not be all zeros");
    if (ethers.getAddress(recipient) === ethers.ZeroAddress) throw new Error("lockETH: recipient must not be the zero address");
    if (expectedChainId !== void 0) {
      let _leNetTimer2;
      const network = await Promise.race([
        signer.provider.getNetwork(),
        new Promise((_, rej) => {
          _leNetTimer2 = setTimeout(() => rej(new Error("getNetwork timed out")), 15e3);
        })
      ]).finally(() => clearTimeout(_leNetTimer2));
      if (network.chainId !== BigInt(expectedChainId)) {
        throw new Error(`Chain mismatch: wallet is on chainId ${network.chainId}, expected ${expectedChainId}. Switch networks in MetaMask.`);
      }
    }
    class _HtlcNotDeployedError2 extends Error {
      constructor() {
        super(...arguments);
        this.isHtlcNotDeployed = true;
      }
    }
    try {
      const code = await Promise.race([
        signer.provider.getCode(htlcAddr),
        new Promise((_, rej) => setTimeout(() => rej(new Error("getCode timed out")), 15e3))
      ]);
      if (!code || code === "0x") throw new _HtlcNotDeployedError2(`HTLC contract not deployed at ${htlcAddr} on this network`);
    } catch (codeErr) {
      if (codeErr.isHtlcNotDeployed) throw codeErr;
      const msg = codeErr instanceof Error ? codeErr.message : String(codeErr);
      throw new Error(`HTLC contract check failed (network/RPC error \u2014 check MetaMask): ${msg}`);
    }
    const ZERO_ADDRESS = "0x0000000000000000000000000000000000000000";
    const htlc = new Contract(htlcAddr, HTLC_ABI, signer);
    let receipt;
    let _broadcastTxHash;
    try {
      const tx = await htlc.lock(recipient, ZERO_ADDRESS, amount, hashLock, timeLock, { value: amount, gasLimit: 300000n, ...await bumpedTxFees(signer) });
      _broadcastTxHash = tx.hash;
      try {
        onBroadcast?.(tx.hash);
      } catch {
      }
      let ethWaitId;
      const ethTimeoutReject = new Promise((_, reject) => {
        ethWaitId = setTimeout(() => reject(new Error("lockETH: tx.wait() timed out after 120s \u2014 tx may still confirm")), 12e4);
      });
      try {
        receipt = await Promise.race([tx.wait(), ethTimeoutReject]);
      } finally {
        clearTimeout(ethWaitId);
      }
    } catch (lockErr) {
      const _re = lockErr;
      if (_re.code === "TRANSACTION_REPLACED") {
        if (_re.reason === "cancelled" || _re.cancelled) {
          throw new Error("lockETH: lock transaction was cancelled in the wallet \u2014 no ETH was locked; retry the swap.");
        }
        if (_re.replacement?.hash) {
          try {
            onBroadcast?.(_re.replacement.hash);
          } catch {
          }
        }
        if (_re.receipt && _re.receipt.status === 1) {
          const _sid = authenticatedLockedSwapId(htlc, htlcAddr, hashLock, _re.receipt.logs);
          if (_sid) return _sid;
        }
        throw Object.assign(
          new Error("lockETH: lock tx was sped up; the replacement is on-chain \u2014 reload to adopt the lock"),
          { broadcasted: true, txHash: _re.replacement?.hash ?? _broadcastTxHash }
        );
      }
      const msg = lockErr instanceof Error ? lockErr.message : String(lockErr);
      throw Object.assign(new Error(
        `lockETH: tx failed or receipt lost \u2014 if ETH was deducted, scan the HTLC contract ${htlcAddr} for a Locked event from your address to recover the swap ID. Original error: ${msg}`
      ), _broadcastTxHash ? { broadcasted: true, txHash: _broadcastTxHash } : {});
    }
    if (!receipt) throw Object.assign(new Error("Transaction was dropped or replaced before confirmation"), _broadcastTxHash ? { broadcasted: true, txHash: _broadcastTxHash } : {});
    if (receipt.status !== 1) throw new Error("Transaction reverted on-chain");
    {
      const _sid = authenticatedLockedSwapId(htlc, htlcAddr, hashLock, receipt.logs);
      if (_sid) return _sid;
    }
    throw Object.assign(new Error("Locked event not found in transaction receipt"), _broadcastTxHash ? { broadcasted: true, txHash: _broadcastTxHash } : {});
  } finally {
    _activeLocks.delete(lockKey);
  }
}
var _claimInFlight = /* @__PURE__ */ new Set();
async function claimSwap(htlcAddr, swapId, secret, signer, expectedChainId) {
  if (secret.length !== 32) {
    throw new Error(`Secret must be exactly 32 bytes; got ${secret.length}`);
  }
  const claimKey = `${htlcAddr.toLowerCase()}:${swapId.toLowerCase()}`;
  if (_claimInFlight.has(claimKey)) {
    throw new Error(`claimSwap already in-flight for swap ${swapId} \u2014 duplicate call rejected`);
  }
  _claimInFlight.add(claimKey);
  let broadcastReached = false;
  try {
    if (expectedChainId !== void 0) {
      let _claimNetTimer;
      const network = await Promise.race([
        signer.provider.getNetwork(),
        new Promise((_, rej) => {
          _claimNetTimer = setTimeout(() => rej(new Error("getNetwork timed out")), 15e3);
        })
      ]).finally(() => clearTimeout(_claimNetTimer));
      if (network.chainId !== BigInt(expectedChainId)) {
        throw new Error(`Chain mismatch: wallet is on chainId ${network.chainId}, expected ${expectedChainId}. Switch networks in MetaMask.`);
      }
    }
    let preflightTimerId;
    const swapData = await Promise.race([
      getSwap(htlcAddr, swapId, signer.provider),
      new Promise((_, reject) => {
        preflightTimerId = setTimeout(() => reject(new Error("EVM pre-flight check timed out after 15s")), 15e3);
      })
    ]).finally(() => clearTimeout(preflightTimerId));
    if (!swapData || swapData.amount === 0n) {
      throw new Error(`Swap ${swapId.slice(0, 18)}... not found or unfunded \u2014 aborting claim to protect secret`);
    }
    if (swapData.claimed) {
      throw new Error(`Swap ${swapId.slice(0, 18)}... already claimed \u2014 secret already on-chain`);
    }
    if (swapData.refunded) {
      throw new Error(`Swap ${swapId.slice(0, 18)}... already refunded \u2014 cannot claim`);
    }
    const signerAddress = (await Promise.race([
      signer.getAddress(),
      new Promise((_, rej) => setTimeout(() => rej(new Error("getAddress timed out")), 15e3))
    ])).toLowerCase();
    if (swapData.recipient.toLowerCase() !== signerAddress) {
      throw new Error(
        `Swap ${swapId.slice(0, 18)}... recipient mismatch: HTLC is for ${swapData.recipient} but signer is ${signerAddress}. Aborting to protect secret.`
      );
    }
    if (swapData.timeLock === 0n) {
      throw new Error("[claimSwap] timeLock is zero \u2014 invalid swap data from contract. Aborting to protect secret.");
    }
    if (swapData.timeLock < 1000000000n || swapData.timeLock > 100000000000n) {
      throw new Error(
        `[claimSwap] timeLock ${swapData.timeLock} is not a plausible unix timestamp (expected ~1.7e9) \u2014 contract invariant violated. Aborting to protect secret.`
      );
    }
    let nowSec;
    try {
      let _claimBlockTimerId;
      const latest = await Promise.race([
        signer.provider.getBlock("latest"),
        new Promise((_, rej) => {
          _claimBlockTimerId = setTimeout(() => rej(new Error("[claimSwap] getBlock timed out")), 15e3);
        })
      ]).finally(() => clearTimeout(_claimBlockTimerId));
      if (latest && Number.isFinite(latest.timestamp)) nowSec = BigInt(latest.timestamp);
    } catch {
    }
    if (nowSec === void 0) {
      throw new Error(
        `[claimSwap] could not read chain time to verify swap ${swapId.slice(0, 18)}... is before its timelock \u2014 refusing to broadcast (a claim at/after timeLock reverts and exposes the secret). Retry.`
      );
    }
    if (nowSec >= swapData.timeLock) {
      throw new Error(
        `Swap ${swapId.slice(0, 18)}... EVM timelock expired at unix ${swapData.timeLock} (now: ${nowSec}) \u2014 claim would revert and expose secret`
      );
    }
    const computedHash = ethers.sha256(secret).toLowerCase();
    const expectedHash = swapData.hashLock.toLowerCase();
    if (computedHash !== expectedHash) {
      throw new Error(
        `Secret does not match hashLock for swap ${swapId.slice(0, 18)}\u2026 (computed ${computedHash.slice(0, 10)}\u2026, expected ${expectedHash.slice(0, 10)}\u2026). Do not broadcast \u2014 wrong secret would be exposed in calldata.`
      );
    }
    const htlc = new Contract(htlcAddr, HTLC_ABI, signer);
    const secretHex = ethers.hexlify(secret);
    let txSubmitted = false;
    try {
      broadcastReached = true;
      let submitTimerId;
      const tx = await Promise.race([
        htlc.claim(swapId, secretHex, { gasLimit: 250000n, ...await bumpedTxFees(signer) }),
        new Promise((_, rej) => {
          submitTimerId = setTimeout(() => rej(new Error("[claimSwap] claim() submission timed out after 30s")), 3e4);
        })
      ]).finally(() => clearTimeout(submitTimerId));
      txSubmitted = true;
      secret.fill(0);
      let claimTimeoutId;
      let receipt;
      try {
        receipt = await Promise.race([
          tx.wait(),
          new Promise((_, reject) => {
            claimTimeoutId = setTimeout(
              () => {
                const err = new Error(
                  `Claim tx ${tx.hash} broadcast but receipt timed out after 120s. WARNING: the secret is now public in the mempool. Once the tx confirms, the secret will appear in the Claimed event \u2014 use it to claim the counterparty HTLC. Check block explorer for tx status.`
                );
                err.txHash = tx.hash;
                reject(err);
              },
              12e4
            );
          })
        ]).finally(() => clearTimeout(claimTimeoutId));
      } catch (waitErr) {
        const _re = waitErr;
        if (_re.code === "TRANSACTION_REPLACED") {
          if (_re.reason === "cancelled" || _re.cancelled) {
            throw new Error("claimSwap: claim was cancelled in the wallet \u2014 retry the claim (your secret is preserved).");
          }
          if (_re.receipt && _re.receipt.status === 1) {
            for (const log of _re.receipt.logs) {
              try {
                const p = htlc.interface.parseLog(log);
                if (p && p.name === "Claimed" && p.args[0]?.toLowerCase() === swapId.toLowerCase()) return { blockNumber: _re.receipt.blockNumber };
              } catch {
              }
            }
          }
          throw new Error("claimSwap: claim tx was sped up; the replacement is on-chain \u2014 reload to confirm and finalize the claim.");
        }
        throw waitErr;
      }
      if (!receipt) throw new Error("Claim transaction dropped \u2014 secret not revealed on-chain");
      if (receipt.status !== 1) {
        try {
          let _postClaimGsTimer;
          const postClaimData = await Promise.race([
            getSwap(htlcAddr, swapId, signer.provider),
            new Promise((_, rej) => {
              _postClaimGsTimer = setTimeout(() => rej(new Error("[claimSwap] post-revert getSwap timed out")), 15e3);
            })
          ]).finally(() => clearTimeout(_postClaimGsTimer));
          if (postClaimData?.claimed) {
            throw new Error("Claim reverted: HTLC was already claimed by another party \u2014 check block explorer. The secret may be recoverable from the claiming tx calldata.");
          }
        } catch (innerErr) {
          if (innerErr instanceof Error && innerErr.message.includes("claimed by another")) throw innerErr;
          throw new Error(
            `Claim tx reverted and post-revert check failed. Secret may now be visible in mempool calldata for swap ${swapId.slice(0, 18)}\u2026 \u2014 check the block explorer and claim the counterparty HTLC immediately if still possible. Original error: ${innerErr instanceof Error ? innerErr.message : String(innerErr)}`
          );
        }
        throw new Error("Claim transaction reverted on-chain");
      }
      let claimEventFound = false;
      for (const log of receipt.logs) {
        try {
          const parsed = htlc.interface.parseLog(log);
          if (parsed && parsed.name === "Claimed" && parsed.args[0]?.toLowerCase() === swapId.toLowerCase()) {
            claimEventFound = true;
            break;
          }
        } catch {
        }
      }
      if (!claimEventFound) {
        throw new Error("Claim tx confirmed but Claimed event not found in receipt \u2014 ABI mismatch or contract issue");
      }
      return { blockNumber: receipt.blockNumber };
    } finally {
      if (!txSubmitted) {
        secret.fill(0);
      }
    }
  } catch (claimErr) {
    if (!broadcastReached && claimErr instanceof Error && !claimErr.preBroadcast) {
      try {
        claimErr.preBroadcast = true;
      } catch {
      }
    }
    throw claimErr;
  } finally {
    _claimInFlight.delete(claimKey);
  }
}
async function refundSwap(htlcAddr, swapId, signer) {
  const provider = signer.provider;
  if (!provider) throw new Error("Signer has no provider attached");
  const htlc = new Contract(htlcAddr, HTLC_ABI, signer);
  let preflight15Id;
  const swapData = await Promise.race([
    getSwap(htlcAddr, swapId, provider),
    new Promise((_, reject) => {
      preflight15Id = setTimeout(() => reject(new Error("[refundSwap] getSwap timed out after 15s")), 15e3);
    })
  ]).finally(() => clearTimeout(preflight15Id));
  if (!swapData) throw new Error("Swap not found \u2014 may not be funded yet");
  const signerAddress = (await Promise.race([
    signer.getAddress(),
    new Promise((_, rej) => setTimeout(() => rej(new Error("getAddress timed out")), 15e3))
  ])).toLowerCase();
  if (swapData.initiator.toLowerCase() !== signerAddress) {
    throw new Error(
      `refundSwap: caller ${signerAddress} is not the HTLC initiator (${swapData.initiator}). Only the initiator can trigger a refund.`
    );
  }
  if (swapData.claimed) throw new Error("Swap already claimed \u2014 initiator revealed the secret on-chain");
  if (swapData.refunded || swapData.amount === 0n) throw new Error("Swap already refunded");
  if (swapData.timeLock === 0n) {
    throw new Error("[refundSwap] timeLock is zero \u2014 invalid swap data from contract.");
  }
  if (swapData.timeLock < 1000000000n || swapData.timeLock > 100000000000n) {
    throw new Error(`[refundSwap] timeLock value ${swapData.timeLock} is not a plausible unix timestamp (expected ~1.7e9). Contract invariant violated.`);
  }
  let _blockTimeoutId;
  const latestForRefund = await Promise.race([
    provider.getBlock("latest"),
    new Promise((_, rej) => {
      _blockTimeoutId = setTimeout(() => rej(new Error("[refundSwap] getBlock timed out after 15s")), 15e3);
    })
  ]).finally(() => clearTimeout(_blockTimeoutId));
  if (!latestForRefund || !Number.isFinite(latestForRefund.timestamp)) {
    throw new Error("[refundSwap] could not read latest block timestamp \u2014 cannot verify timelock expiry.");
  }
  const nowSec = BigInt(latestForRefund.timestamp);
  if (nowSec <= swapData.timeLock) {
    const rawDelta = swapData.timeLock - nowSec;
    const secsLeft = rawDelta > BigInt(Number.MAX_SAFE_INTEGER) ? Number.MAX_SAFE_INTEGER : Number(rawDelta);
    throw new Error(`Timelock has not expired yet. ~${Math.ceil(secsLeft / 60).toLocaleString()} minutes remaining.`);
  }
  const tx = await Promise.race([
    htlc.refund(swapId, { gasLimit: 150000n, ...await bumpedTxFees(signer) }),
    new Promise((_, rej) => setTimeout(() => rej(new Error("[refundSwap] refund() submission timed out after 30s")), 3e4))
  ]);
  let receipt;
  try {
    let refundWaitId;
    receipt = await Promise.race([
      tx.wait(),
      new Promise((_, reject) => {
        refundWaitId = setTimeout(() => reject(new Error("[refundSwap] tx.wait timed out after 120s \u2014 tx may still confirm")), 12e4);
      })
    ]).finally(() => clearTimeout(refundWaitId));
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    const _re = e;
    if (_re.code === "TRANSACTION_REPLACED") {
      if (_re.reason === "cancelled" || _re.cancelled) {
        throw new Error("refundSwap: refund was cancelled in the wallet \u2014 retry the refund.");
      }
      if (!_re.receipt) {
        throw new Error("refundSwap: refund tx was sped up; the replacement is on-chain \u2014 reload to confirm the refund.");
      }
      receipt = _re.receipt;
    } else if (msg.includes("CALL_EXCEPTION")) {
      try {
        let _ceGsTimer;
        const postRevert = await Promise.race([
          getSwap(htlcAddr, swapId, provider),
          new Promise((_, rej) => {
            _ceGsTimer = setTimeout(() => rej(new Error("[refundSwap] CALL_EXCEPTION getSwap timed out")), 15e3);
          })
        ]).finally(() => clearTimeout(_ceGsTimer));
        if (postRevert?.claimed) {
          throw new Error("Swap was claimed before refund executed \u2014 secret is on-chain, check Claimed events");
        }
      } catch (checkErr) {
        const checkMsg = checkErr instanceof Error ? checkErr.message : String(checkErr);
        if (checkMsg.includes("Swap was claimed")) throw checkErr;
      }
      throw new Error("Refund rejected by contract \u2014 timelock may not have expired yet");
    } else {
      throw e;
    }
  }
  if (receipt === null) {
    throw new Error("Refund transaction was dropped from mempool \u2014 may need to rebroadcast");
  }
  if (receipt.status !== 1) {
    try {
      let _postRefundGsTimer;
      const postRevert = await Promise.race([
        getSwap(htlcAddr, swapId, provider),
        new Promise((_, rej) => {
          _postRefundGsTimer = setTimeout(() => rej(new Error("[refundSwap] post-revert getSwap timed out")), 15e3);
        })
      ]).finally(() => clearTimeout(_postRefundGsTimer));
      if (postRevert?.claimed) {
        throw new Error("Swap was claimed before refund executed \u2014 secret is on-chain, check Claimed events");
      }
    } catch (checkErr) {
      const checkMsg = checkErr instanceof Error ? checkErr.message : String(checkErr);
      if (checkMsg.includes("Swap was claimed")) throw checkErr;
    }
    throw new Error("Refund rejected by contract \u2014 timelock may not have expired yet");
  }
}
async function getSwap(htlcAddr, swapId, provider, blockTag) {
  const htlc = new Contract(htlcAddr, HTLC_ABI, provider);
  let _gsTimer;
  const result = await Promise.race([
    blockTag !== void 0 ? htlc.getSwap(swapId, { blockTag }) : htlc.getSwap(swapId),
    new Promise((_, rej) => {
      _gsTimer = setTimeout(() => rej(new Error("[getSwap] contract call timed out after 15s")), 15e3);
    })
  ]).finally(() => clearTimeout(_gsTimer));
  const initiator = result[0];
  if (initiator === ethers.ZeroAddress) {
    return null;
  }
  if (result[5] === 0n) {
    return null;
  }
  return {
    initiator: ethers.getAddress(initiator),
    recipient: ethers.getAddress(result[1]),
    token: result[2] === ethers.ZeroAddress ? ethers.ZeroAddress : ethers.getAddress(result[2]),
    amount: result[3],
    hashLock: result[4],
    timeLock: result[5],
    claimed: result[6],
    refunded: result[7]
  };
}
var SAFE_TAG_MEMO_TTL_MS = 60 * 6e4;
var _safeTagUnsupportedChains = /* @__PURE__ */ new Map();
function isUnsupportedBlockTagError(err) {
  const e = err;
  const code = e?.code ?? e?.error?.code ?? e?.info?.error?.code;
  if (code === -32602 || code === "INVALID_ARGUMENT") return true;
  let stringified = "";
  try {
    stringified = JSON.stringify(e);
  } catch {
  }
  const msg = [e?.message, e?.shortMessage, e?.error?.message, e?.info?.error?.message, stringified].filter((s) => typeof s === "string").join(" | ").toLowerCase();
  if (!msg) return false;
  if (msg.includes("invalid block tag") || msg.includes("unknown block") || msg.includes("invalid params")) return true;
  if ((msg.includes("safe") || msg.includes("finalized")) && msg.includes("block") && msg.includes("not found")) return true;
  return msg.includes("block tag") && (msg.includes("invalid") || msg.includes("unknown") || msg.includes("unsupported") || msg.includes("not found") || msg.includes("does not") || msg.includes("doesn't"));
}
async function isEvmLockAtSafeDepth(htlcAddr, swapId, provider, requiredConfirmations, inv) {
  let lock = null;
  let safeServed = false;
  let chainKey = "";
  try {
    chainKey = String((await provider.getNetwork()).chainId);
  } catch {
  }
  const _memoTs = chainKey ? _safeTagUnsupportedChains.get(chainKey) : void 0;
  if (_memoTs !== void 0 && Date.now() - _memoTs < SAFE_TAG_MEMO_TTL_MS) {
    safeServed = false;
  } else {
    if (_memoTs !== void 0 && chainKey) _safeTagUnsupportedChains.delete(chainKey);
    try {
      lock = await getSwap(htlcAddr, swapId, provider, "safe");
      safeServed = true;
    } catch (err) {
      if (isUnsupportedBlockTagError(err)) {
        if (chainKey) _safeTagUnsupportedChains.set(chainKey, Date.now());
        safeServed = false;
      } else {
        return false;
      }
    }
  }
  if (!safeServed) {
    try {
      const tip = await Promise.race([
        provider.getBlockNumber(),
        new Promise((_, rej) => setTimeout(() => rej(new Error("getBlockNumber timeout")), 15e3))
      ]);
      if (!(requiredConfirmations > 1 && tip > requiredConfirmations)) return false;
      lock = await getSwap(htlcAddr, swapId, provider, tip - (requiredConfirmations - 1));
    } catch {
      return false;
    }
  }
  if (!lock) return false;
  if (lock.claimed || lock.refunded) return false;
  if (lock.hashLock.toLowerCase() !== inv.hashLock.toLowerCase()) return false;
  if (inv.recipient && lock.recipient.toLowerCase() !== inv.recipient.toLowerCase()) return false;
  if (inv.minAmount !== void 0 && lock.amount < inv.minAmount) return false;
  if (inv.token !== void 0 && lock.token.toLowerCase() !== inv.token.toLowerCase()) return false;
  if (inv.minTimeLock !== void 0 && lock.timeLock < inv.minTimeLock) return false;
  return true;
}
function abortableSleep(ms, signal) {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) {
      reject(new DOMException("aborted", "AbortError"));
      return;
    }
    const onAbort = () => {
      clearTimeout(id);
      reject(new DOMException("aborted", "AbortError"));
    };
    const id = setTimeout(() => {
      signal?.removeEventListener("abort", onAbort);
      resolve();
    }, ms);
    signal?.addEventListener("abort", onAbort, { once: true });
  });
}
async function watchForClaim(htlcAddr, swapId, provider, fromBlock = 0, expectedHashLock, signal) {
  if (!expectedHashLock || expectedHashLock.replace(/^0x/, "") === "0".repeat(64)) {
    throw new Error("[watchForClaim] expectedHashLock is required and must not be all zeros \u2014 omitting or using zero allows a compromised RPC to inject a wrong secret");
  }
  const htlc = new Contract(htlcAddr, HTLC_ABI, provider);
  const POLL_MS = 1e4;
  const MAX_POLLS = 8640;
  if (fromBlock === 0) {
    try {
      const tip = await Promise.race([
        provider.getBlockNumber(),
        new Promise((_, rej) => setTimeout(() => rej(new Error("startup getBlockNumber timed out")), 15e3))
      ]);
      fromBlock = Math.max(1, tip - 9e4);
      console.warn(`[watchForClaim] fromBlock=0 \u2014 scanning from near tip (${fromBlock}). Pass evmLockBlock for lossless recovery.`);
    } catch {
      fromBlock = -1;
      console.warn("[watchForClaim] fromBlock=0 and could not fetch tip \u2014 will retry in poll loop.");
    }
  }
  let originBlock = fromBlock;
  let warnedAboutSlide = false;
  for (let i = 0; i < MAX_POLLS; i++) {
    if (signal?.aborted) throw new DOMException("aborted", "AbortError");
    if (fromBlock < 0) {
      try {
        let _wfcDeferTimer;
        const tip = await Promise.race([
          provider.getBlockNumber(),
          new Promise((_, rej) => {
            _wfcDeferTimer = setTimeout(() => rej(new Error("[watchForClaim] deferred getBlockNumber timed out")), 15e3);
          })
        ]).finally(() => clearTimeout(_wfcDeferTimer));
        fromBlock = Math.max(1, tip - 9e4);
        if (originBlock < 0) originBlock = fromBlock;
      } catch (e) {
        if (e.name === "AbortError") throw e;
        if (signal?.aborted) throw new DOMException("aborted", "AbortError");
        await abortableSleep(POLL_MS, signal);
        continue;
      }
    }
    const filter = htlc.filters.Claimed(swapId);
    let latestForQuery;
    try {
      let _wfcLatestTimer;
      latestForQuery = await Promise.race([
        provider.getBlockNumber(),
        new Promise((_, rej) => {
          _wfcLatestTimer = setTimeout(() => rej(new Error("[watchForClaim] getBlockNumber timed out")), 15e3);
        })
      ]).finally(() => clearTimeout(_wfcLatestTimer));
    } catch (e) {
      if (e.name === "AbortError") throw e;
      if (signal?.aborted) throw new DOMException("aborted", "AbortError");
      await abortableSleep(2e3, signal);
      continue;
    }
    if (latestForQuery <= 0) {
      await abortableSleep(2e3, signal);
      continue;
    }
    if (fromBlock > latestForQuery) {
      await abortableSleep(2e3, signal);
      continue;
    }
    const capBlock = Math.min(latestForQuery, fromBlock + 8999);
    let events;
    try {
      let _wfcQfTimer;
      events = await Promise.race([
        htlc.queryFilter(filter, fromBlock, capBlock),
        new Promise((_, rej) => {
          _wfcQfTimer = setTimeout(() => rej(new Error("[watchForClaim] queryFilter timed out")), 3e4);
        })
      ]).finally(() => clearTimeout(_wfcQfTimer));
    } catch (qErr) {
      const qMsg = qErr instanceof Error ? qErr.message : String(qErr);
      const isTimeout = qMsg.includes("queryFilter timed out");
      const currentWindowSize = capBlock - fromBlock + 1;
      const slide = isTimeout ? Math.max(1, Math.floor(currentWindowSize / 2)) : 1;
      console.warn(`[watchForClaim] queryFilter ${isTimeout ? "timed out" : "failed"} (${qMsg.slice(0, 80)}) \u2014 sliding fromBlock by ${slide}`);
      if (signal?.aborted) throw new DOMException("aborted", "AbortError");
      fromBlock = Math.max(originBlock, fromBlock + slide);
      await abortableSleep(POLL_MS, signal);
      continue;
    }
    if (events.length > 0) {
      let foundSecret = null;
      let depthSkipped = false;
      for (const evt of events) {
        if (!("args" in evt) || !evt.args) continue;
        const secretHex = evt.args[1];
        if (!secretHex || secretHex === "0x" + "0".repeat(64)) continue;
        let secretBytes;
        try {
          secretBytes = ethers.getBytes(secretHex);
        } catch {
          continue;
        }
        if (secretBytes.length !== 32) continue;
        if (expectedHashLock) {
          const computedHash = ethers.sha256(secretBytes).toLowerCase();
          const normalized = expectedHashLock.toLowerCase().startsWith("0x") ? expectedHashLock.toLowerCase() : "0x" + expectedHashLock.toLowerCase();
          if (computedHash !== normalized) continue;
        }
        const evtBlock = "blockNumber" in evt ? evt.blockNumber : 0;
        if (evtBlock === 0 || latestForQuery - evtBlock < 1) {
          depthSkipped = true;
          continue;
        }
        foundSecret = secretBytes;
        break;
      }
      if (!foundSecret) {
        if (depthSkipped) {
          await abortableSleep(POLL_MS, signal);
          continue;
        }
        fromBlock = Math.max(originBlock, capBlock + 1);
        console.warn("[watchForClaim] Claimed event found but hash mismatch \u2014 may be RPC anomaly, retrying next block");
        await abortableSleep(POLL_MS, signal);
        continue;
      }
      if (signal?.aborted) throw new DOMException("Aborted", "AbortError");
      return foundSecret;
    }
    try {
      const nextFrom = fromBlock + 1;
      const rpcMinBlock = latestForQuery - 9e3;
      if (nextFrom < rpcMinBlock && !warnedAboutSlide) {
        warnedAboutSlide = true;
        console.warn(
          `[watchForClaim] RPC node window is smaller than swap age. Re-scanning from originBlock=${originBlock} each poll. Use an archival RPC node to guarantee zero missed events.`
        );
      }
      fromBlock = Math.max(originBlock, capBlock + 1);
    } catch (e) {
      console.warn("[watchForClaim] slide-forward failed \u2014 fromBlock unchanged:", e);
    }
    await abortableSleep(POLL_MS, signal);
  }
  throw new Error("Timed out waiting for claim event on HTLC");
}
async function watchAndRefund(htlcAddress, swapId, provider, signer, timeLockSec, onBlockUpdate, expectedHashLock, signal) {
  if (!Number.isInteger(timeLockSec) || timeLockSec < 1e9 || timeLockSec > 1e11) {
    throw new Error(`watchAndRefund: invalid timeLockSec=${timeLockSec}; must be a plausible unix timestamp`);
  }
  const MAX_POLLS = 8640;
  for (let i = 0; i < MAX_POLLS; i++) {
    let nowSec;
    if (signal?.aborted) throw new DOMException("watchAndRefund aborted", "AbortError");
    try {
      const latest = await Promise.race([
        provider.getBlock("latest"),
        new Promise((_, rej) => setTimeout(() => rej(new Error("watchAndRefund getBlock timed out")), 15e3))
      ]);
      if (!latest || !Number.isFinite(latest.timestamp)) throw new Error("no block timestamp");
      nowSec = latest.timestamp;
    } catch {
      await abortableSleep(1e4, signal);
      continue;
    }
    onBlockUpdate?.(nowSec, timeLockSec);
    if (nowSec > timeLockSec) {
      try {
        await refundSwap(htlcAddress, swapId, signer);
        return swapId;
      } catch (e) {
        const msg = e instanceof Error ? e.message : String(e);
        if (msg.includes("already refunded") || msg.includes("Swap not found")) {
          return swapId;
        }
        if (msg.includes("already claimed") || msg.includes("Swap already claimed")) {
          if (expectedHashLock) {
            let recoveredSecret = null;
            try {
              let _warGbnTimer;
              const tip = await Promise.race([
                provider.getBlockNumber(),
                new Promise((_, rej) => {
                  _warGbnTimer = setTimeout(() => rej(new Error("[watchAndRefund] getBlockNumber timed out")), 15e3);
                })
              ]).finally(() => clearTimeout(_warGbnTimer));
              recoveredSecret = await watchForClaim(
                htlcAddress,
                swapId,
                provider,
                Math.max(1, tip - 1e5),
                expectedHashLock,
                signal
                // R64-EVM-002: propagate abort signal — without this, unmount cannot stop 24h zombie loop
              );
              const claimedErr = new Error("CLAIMED_WITH_SECRET");
              claimedErr.secret = recoveredSecret;
              recoveredSecret = null;
              throw claimedErr;
            } catch (inner) {
              if (inner.message === "CLAIMED_WITH_SECRET") throw inner;
              throw new Error(`Swap already claimed. Try extracting the secret from the Claimed event for swap ${swapId}.`);
            } finally {
              recoveredSecret?.fill(0);
            }
          }
          throw new Error("Swap already claimed by initiator \u2014 extract secret from Claimed event to recover funds");
        }
        const lowerMsg = msg.toLowerCase();
        const errCode = e.code;
        const isNonRetryable = lowerMsg.includes("wallet") || lowerMsg.includes("locked") || lowerMsg.includes("disconnected") || lowerMsg.includes("user rejected") || lowerMsg.includes("user denied") || lowerMsg.includes("unauthorized") || lowerMsg.includes("provider") || errCode === 4001 || errCode === 4100 || errCode === "ACTION_REJECTED";
        if (isNonRetryable) {
          throw new Error(
            `watchAndRefund: wallet rejected or disconnected for swap ${swapId}. Unlock your wallet and call refundSwap('${htlcAddress}', '${swapId}') manually to recover funds. Error: ${msg}`
          );
        }
        console.warn(`[watchAndRefund] refundSwap transient error (will retry in 10s): ${msg}`);
      }
    }
    await abortableSleep(1e4, signal);
  }
  throw new Error(
    `watchAndRefund: gave up after ${MAX_POLLS} polls for swap ${swapId}. The HTLC is likely still refundable on-chain. Call refundSwap('${htlcAddress}', '${swapId}') manually with a funded signer to recover the funds.`
  );
}
var FALLBACK_RPCS = {
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
  137: ["https://polygon.gateway.tenderly.co", "https://polygon.drpc.org"],
  // R-POLYHIST (Arbitrum parity, 2026-07-13): publicnode 403s getLogs beyond ~100 blocks AND ordering it FIRST
  // poisoned the getLogs FallbackProvider (same failure that broke Polygon) — dropped. Both arb1 + drpc serve
  // getLogs (9000-blk windows) + 'safe' tag + latest IN-BROWSER (CORS-verified); arb1 FIRST because ethers uses
  // the first leaf for getLogs. Arbitrum serves 'safe' (unlike Polygon Bor) so the finality gate needs no historical
  // fallback. Browser-verified end-to-end: q1 getLogs (arb1-first) + q2 'safe' both form.
  42161: ["https://arb1.arbitrum.io/rpc", "https://arbitrum.drpc.org"],
  84532: ["https://sepolia.base.org", "https://base-sepolia-rpc.publicnode.com"],
  421614: ["https://sepolia-rollup.arbitrum.io/rpc", "https://arbitrum-sepolia-rpc.publicnode.com"],
  11155111: ["https://rpc.sepolia.org", "https://ethereum-sepolia-rpc.publicnode.com"]
};
function getPublicProvider(chainId, opts) {
  const cfg = getEvmConfig(chainId);
  if (!cfg) {
    throw new Error(`getPublicProvider: chain ${chainId} is not a supported EVM chain`);
  }
  const primaryUrl = cfg.rpcUrl;
  const fallbacks = FALLBACK_RPCS[chainId] ?? [];
  const urls = primaryUrl ? fallbacks.includes(primaryUrl) ? fallbacks : [primaryUrl, ...fallbacks] : fallbacks;
  if (urls.length === 0) throw new Error(`No public RPC configured for chainId ${chainId}`);
  const htlcCfg = EVM_CHAINS[chainId];
  if (!htlcCfg || htlcCfg.htlcAddress === "0x0000000000000000000000000000000000000000") {
    console.warn(`[getPublicProvider] chain ${chainId} has no deployed HTLC; contract calls will fail`);
  }
  if (urls.length === 1) {
    if (opts?.quorum != null && opts.quorum > 1) {
      if (SUPPORTED_EVM_CHAINS.includes(chainId)) {
        throw new Error(`getPublicProvider: chain ${chainId} has only 1 RPC but a finality gate requested quorum=${opts.quorum}; refusing to degrade to single-backend trust`);
      }
      console.warn(`[getPublicProvider] chain ${chainId} has only 1 RPC; requested quorum=${opts.quorum} cannot be enforced (single-backend trust).`);
    }
    return patchFeeData(new JsonRpcProvider(urls[0]));
  }
  const leaves = urls.map((url) => patchFeeData(new JsonRpcProvider(url)));
  let fbOptions;
  if (opts?.quorum != null) {
    const q = Math.max(1, Math.min(opts.quorum, leaves.length));
    if (q < opts.quorum) {
      if (SUPPORTED_EVM_CHAINS.includes(chainId)) {
        throw new Error(`getPublicProvider: chain ${chainId} has only ${leaves.length} RPCs but a finality gate requested quorum=${opts.quorum}; refusing to degrade`);
      }
      console.warn(`[getPublicProvider] chain ${chainId}: requested quorum=${opts.quorum} exceeds ${leaves.length} RPCs; clamped to ${q}.`);
    }
    fbOptions = { quorum: q };
  } else {
    fbOptions = { quorum: 1 };
  }
  const fb = new FallbackProvider(
    leaves.map((provider) => ({ provider, stallTimeout: 2e3 })),
    chainId,
    fbOptions
  );
  fb.getFeeData = async () => {
    let lastErr;
    for (const leaf of leaves) {
      try {
        return await Promise.race([
          leaf.getFeeData(),
          new Promise((_, rej) => setTimeout(() => rej(new Error("leaf getFeeData timeout")), 8e3))
        ]);
      } catch (e) {
        lastErr = e;
      }
    }
    throw lastErr ?? new Error("getFeeData: all fallback backends failed");
  };
  try {
    fb.__leafProviders = leaves;
  } catch {
  }
  return fb;
}
function destroyProvider(provider) {
  if (!provider) return;
  if ("providerConfigs" in provider) {
    const fp = provider;
    for (const cfg of fp.providerConfigs ?? []) {
      destroyProvider(cfg.provider);
    }
  } else if ("destroy" in provider && typeof provider.destroy === "function") {
    try {
      provider.destroy();
    } catch {
    }
  }
}

export { HTLC_ABI, approveToken, claimSwap, connectMetaMask, destroyProvider, ensureAllowance, getPublicProvider, getSwap, getTokenBalance, hashPreimage, isEvmLockAtSafeDepth, lockETH, lockTokens, makeEvmProvider, recoverLockFromTx, refundSwap, switchToChain, watchAndRefund, watchForClaim };
