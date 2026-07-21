import { ethers } from 'ethers';

// src/evm-config.ts

// src/chain-config.ts
globalThis.process?.env?.BCH2_SWAP_NETWORK === "regtest";
var chainConfigs = {
  bch2: {
    avgBlockTimeSec: 600}};
var LOCKTIME_BLOCKS = {
  initiator: 216,
  // ~36 hours (R-TIMELOCK-K: raised from 144 so the ÷K responder fund gate still leaves a funding window)
  responder: 72
  // ~12 hours (R-TIMELOCK-K: kept at 12h — the initiator's claim window on this leg needs K*margin + confs)
};
var TIMELOCK_SAFETY_K = 2;
function minSecondsUntilRefund(blocksRemaining, chainBlockSec) {
  return blocksRemaining * chainBlockSec / TIMELOCK_SAFETY_K;
}
function maxSecondsUntilRefund(blocks, chainBlockSec) {
  return blocks * chainBlockSec * TIMELOCK_SAFETY_K;
}

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
function getEvmTokenSymbols(chainId) {
  return Object.keys(EVM_CHAINS[chainId]?.tokens ?? {});
}
var UTXO_REF_BLOCK_SEC = chainConfigs.bch2.avgBlockTimeSec;
var INITIATOR_LOCK_SEC = LOCKTIME_BLOCKS.initiator * UTXO_REF_BLOCK_SEC;
var RESPONDER_LOCK_SEC = LOCKTIME_BLOCKS.responder * UTXO_REF_BLOCK_SEC;
var EVM_CLAIM_MARGIN_SEC = 24 * UTXO_REF_BLOCK_SEC;
function evmLockBlocksForRole(cfg, role) {
  const sec = role === "initiator" ? INITIATOR_LOCK_SEC : RESPONDER_LOCK_SEC;
  const blocks = Math.ceil(sec / cfg.avgBlockTimeSec);
  return Math.min(Math.max(blocks, cfg.minLockBlocks), cfg.maxLockBlocks - 1);
}
function evmLockSecondsForRole(cfg, role) {
  const sec = role === "initiator" ? INITIATOR_LOCK_SEC : RESPONDER_LOCK_SEC;
  return Math.min(Math.max(sec, cfg.minLockSeconds), cfg.maxLockSeconds);
}
function isNativeToken(tokenAddress) {
  return tokenAddress === NATIVE_ETH_ADDRESS;
}
function assertCanonicalEvmToken(evmChainId, tokenAddress, tokenSymbol) {
  const cfg = EVM_CHAINS[evmChainId];
  if (!cfg) throw new Error(`EVM token check: chain ${evmChainId} is not configured \u2014 refusing`);
  const tokens = cfg.tokens ?? {};
  const addrLc = (tokenAddress ?? "").toLowerCase();
  if (addrLc === NATIVE_ETH_ADDRESS.toLowerCase()) {
    const nativeLocal = Object.values(tokens).find((t) => t.address.toLowerCase() === NATIVE_ETH_ADDRESS.toLowerCase());
    if (!nativeLocal) throw new Error(`EVM token check: chain ${evmChainId} has no configured native token \u2014 refusing`);
    return NATIVE_ETH_ADDRESS;
  }
  const claimed = typeof tokenSymbol === "string" ? tokenSymbol.toUpperCase().slice(0, 10) : "";
  if (!claimed) {
    throw new Error(`EVM token check: non-native token ${tokenAddress} on chain ${evmChainId} carries no symbol to bind \u2014 refusing`);
  }
  const canonical = tokens[claimed]?.address;
  if (!canonical || addrLc !== canonical.toLowerCase()) {
    throw new Error(
      `EVM token check: token ${tokenAddress} (claimed '${claimed}') is not the canonical ${claimed} on chain ${evmChainId} \u2014 refusing an unrecognized / non-allowlisted token`
    );
  }
  return canonical;
}
function validateEvmConfigs() {
  for (const [chainId, cfg] of Object.entries(EVM_CHAINS)) {
    if (!cfg) continue;
    if (cfg.htlcAddress === NATIVE_ETH_ADDRESS || cfg.htlcAddress === "") {
      if (SUPPORTED_EVM_CHAINS.includes(Number(chainId))) {
        throw new Error(`EVM chain ${chainId} is in SUPPORTED_EVM_CHAINS but has no HTLC contract address`);
      }
    }
    if (!Number.isInteger(cfg.requiredConfirmations) || cfg.requiredConfirmations < 1) {
      throw new Error(`EVM config chain ${chainId}: requiredConfirmations must be a positive integer (got ${cfg.requiredConfirmations})`);
    }
    for (const [symbol, tok] of Object.entries(cfg.tokens ?? {})) {
      if (!/^0x[0-9a-fA-F]{40}$/.test(tok.address)) {
        throw new Error(`EVM config chain ${chainId}: token ${symbol} address "${tok.address}" is not a valid EVM address`);
      }
      try {
        ethers.getAddress(tok.address);
      } catch {
        throw new Error(`EVM config chain ${chainId}: token ${symbol} address '${tok.address}' has invalid EIP-55 checksum`);
      }
      if (!Number.isInteger(tok.decimals) || tok.decimals < 0 || tok.decimals > 18) {
        throw new Error(`EVM config chain ${chainId}: token ${symbol} decimals=${tok.decimals} must be an integer in [0, 18]`);
      }
    }
    if (cfg.htlcAddress && cfg.htlcAddress !== NATIVE_ETH_ADDRESS) {
      if (!/^0x[0-9a-fA-F]{40}$/.test(cfg.htlcAddress)) {
        throw new Error(`EVM config error: chain ${chainId} htlcAddress '${cfg.htlcAddress}' is not a valid EVM address`);
      }
      try {
        ethers.getAddress(cfg.htlcAddress);
      } catch {
        throw new Error(`EVM config error: chain ${chainId} htlcAddress '${cfg.htlcAddress}' has invalid EIP-55 checksum`);
      }
    }
    if (SUPPORTED_EVM_CHAINS.includes(Number(chainId))) {
      if (typeof cfg.minLockBlocks !== "number" || cfg.minLockBlocks <= 0) {
        throw new Error(`EVM chain ${chainId} minLockBlocks must be a positive number, got ${cfg.minLockBlocks}`);
      }
      if (cfg.minLockBlocks < 150) {
        throw new Error(`EVM chain ${chainId} minLockBlocks=${cfg.minLockBlocks} is too short (minimum 150); increase to at least 300 for testnet or 2160 for mainnet`);
      }
      if (cfg.avgBlockTimeSec <= 0) {
        throw new Error(`EVM chain ${chainId} avgBlockTimeSec must be > 0`);
      }
      if (cfg.maxLockBlocks <= cfg.minLockBlocks) {
        throw new Error(`EVM chain ${chainId} maxLockBlocks (${cfg.maxLockBlocks}) must exceed minLockBlocks (${cfg.minLockBlocks})`);
      }
      if (!Number.isFinite(cfg.minLockSeconds) || cfg.minLockSeconds <= 0 || !Number.isFinite(cfg.maxLockSeconds) || cfg.maxLockSeconds <= cfg.minLockSeconds) {
        throw new Error(`EVM chain ${chainId} minLockSeconds/maxLockSeconds invalid (got ${cfg.minLockSeconds}/${cfg.maxLockSeconds})`);
      }
      const initEvmSec = evmLockSecondsForRole(cfg, "initiator");
      const respEvmSec = evmLockSecondsForRole(cfg, "responder");
      if (initEvmSec <= respEvmSec) {
        throw new Error(
          `EVM chain ${chainId}: normalized initiator lock (${initEvmSec}s) must exceed responder lock (${respEvmSec}s) after clamping \u2014 raise maxLockSeconds.`
        );
      }
      const utxoInitiatorSecMin = minSecondsUntilRefund(LOCKTIME_BLOCKS.initiator, chainConfigs.bch2.avgBlockTimeSec);
      const utxoResponderSecMax = maxSecondsUntilRefund(LOCKTIME_BLOCKS.responder, chainConfigs.bch2.avgBlockTimeSec);
      if (respEvmSec >= utxoInitiatorSecMin) {
        throw new Error(
          `EVM chain ${chainId}: responder EVM lock ${respEvmSec}s >= conservative UTXO initiator lock ${utxoInitiatorSecMin}s \u2014 swap safety invariant violated (EVM-responder topology).`
        );
      }
      if (initEvmSec <= utxoResponderSecMax + EVM_CLAIM_MARGIN_SEC) {
        throw new Error(
          `EVM chain ${chainId}: initiator EVM lock ${initEvmSec}s must exceed conservative UTXO responder lock ${utxoResponderSecMax}s + claim margin ${EVM_CLAIM_MARGIN_SEC}s \u2014 R124-XCHAIN-001 inversion guard.`
        );
      }
    }
  }
}

export { EVM_CHAINS, EVM_CLAIM_MARGIN_SEC, INITIATOR_LOCK_SEC, NATIVE_ETH_ADDRESS, RESPONDER_LOCK_SEC, SUPPORTED_EVM_CHAINS, assertCanonicalEvmToken, evmLockBlocksForRole, evmLockSecondsForRole, getEvmConfig, getEvmTokenSymbols, isNativeToken, validateEvmConfigs };
