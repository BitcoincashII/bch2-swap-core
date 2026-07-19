// src/chain-config.ts
var REGTEST = globalThis.process?.env?.BCH2_SWAP_NETWORK === "regtest";
var chainConfigs = {
  bch2: {
    name: "Bitcoin Cash II",
    ticker: "BCH2",
    addressPrefix: "bitcoincashii",
    p2shVersionByte: 5,
    sighashType: 65,
    // SIGHASH_ALL | SIGHASH_FORKID
    useBip143: true,
    electrumServers: [
      { host: "electrum.bch2.org", port: 50002, ssl: true },
      { host: "144.202.73.66", port: 50002, ssl: true }
    ],
    avgBlockTimeSec: 600,
    dustThreshold: 182,
    // 1000 sat/kvB relay rate: 1000/1000*(34+148)=182 sat for P2PKH
    feePerByte: 1,
    bip44CoinType: 20145,
    // BCH2-specific; differs from BCH (145) to prevent key reuse. BREAKING: existing wallets derived under 145 must re-derive.
    // R117-CHAIN-001: raised from 3 to 6 — BCH2 is a minority-hashrate chain; 51%-attack cost
    // on 3 BCH2 blocks is extremely low. 6 confs ≈ 1 hour at 10-min blocks. Re-assess at mainnet launch.
    requiredConfirmations: 6
  },
  bch: {
    name: "Bitcoin Cash",
    ticker: "BCH",
    addressPrefix: REGTEST ? "bchreg" : "bitcoincash",
    p2shVersionByte: 5,
    sighashType: 65,
    // SIGHASH_ALL | SIGHASH_FORKID
    useBip143: true,
    electrumServers: [
      { host: "bch0.kister.net", port: 50002, ssl: true },
      { host: "blackie.c3-soft.com", port: 50002, ssl: true }
    ],
    avgBlockTimeSec: 600,
    dustThreshold: 182,
    // 1000 sat/kvB relay rate: same as BCH2
    feePerByte: 1,
    bip44CoinType: 145,
    // R116-CHAIN-001: raised from 3 to 6 — BCH hashrate is orders of magnitude below BTC's,
    // making a 51% attack on 3 BCH blocks much cheaper than 2 BTC blocks. 6 confs ≈ 1 hour.
    requiredConfirmations: 6
  },
  btc: {
    name: "Bitcoin",
    ticker: "BTC",
    p2shVersionByte: REGTEST ? 196 : 5,
    p2pkhVersionByte: REGTEST ? 111 : 0,
    sighashType: 1,
    // SIGHASH_ALL
    useBip143: false,
    electrumServers: [
      { host: "electrum.blockstream.info", port: 50002, ssl: true },
      { host: "electrum.emzy.de", port: 50002, ssl: true }
    ],
    avgBlockTimeSec: 600,
    dustThreshold: 546,
    feePerByte: 10,
    bip44CoinType: 0,
    requiredConfirmations: 2
  },
  bc2: {
    name: "Bitcoin II",
    ticker: "BC2",
    p2shVersionByte: REGTEST ? 196 : 5,
    p2pkhVersionByte: REGTEST ? 111 : 0,
    sighashType: 1,
    // SIGHASH_ALL
    useBip143: false,
    electrumServers: [
      { host: "infra1.bitcoin-ii.org", port: 50009, ssl: true },
      { host: "50.6.6.41", port: 50009, ssl: true }
    ],
    avgBlockTimeSec: 600,
    dustThreshold: 546,
    feePerByte: 1,
    bip44CoinType: 1,
    // SLIP-0044 testnet reserved. WARNING: key reuse risk with any BTC/LTC testnet wallet using same mnemonic. TODO: register a custom coin type (e.g. 20002) before BC2 mainnet.
    requiredConfirmations: 3
  },
  // R21-HTLC-001: EVM responder minLockBlocks must be ~12h (not ~24h).
  // The UTXO initiator locks for LOCKTIME_BLOCKS.initiator (216 blocks, ~36h). The EVM responder must lock for
  // strictly less time so the initiator cannot simultaneously claim EVM and refund UTXO.
  // Rule: EVM minLockBlocks ≈ LOCKTIME_BLOCKS.responder * avgBlockTimeSec / evmAvgBlockTimeSec
  eth: {
    name: "Ethereum Sepolia",
    ticker: "ETH",
    isEvm: true,
    evmChainId: 11155111,
    avgBlockTimeSec: 12,
    // NOTE: minLockBlocks/maxLockBlocks for EVM chains in this file are DEAD CODE.
    // The swap engine reads lock parameters from evm-config.ts (EVM_CHAINS).
    // These values are intentionally different (production vs testnet scales).
    // Do NOT rely on chain-config.ts for EVM timing parameters. See R38-CFG-002.
    minLockBlocks: 3600,
    // ~12h at 12s/block (half of UTXO initiator locktime)
    maxLockBlocks: 86400
    // ~12 days at 12s/block
  },
  base: {
    name: "Base Sepolia",
    ticker: "BASE",
    isEvm: true,
    evmChainId: 84532,
    avgBlockTimeSec: 2,
    // NOTE: minLockBlocks/maxLockBlocks for EVM chains in this file are DEAD CODE.
    // The swap engine reads lock parameters from evm-config.ts (EVM_CHAINS).
    // These values are intentionally different (production vs testnet scales).
    // Do NOT rely on chain-config.ts for EVM timing parameters. See R38-CFG-002.
    minLockBlocks: 21600,
    // ~12h at 2s/block (half of UTXO initiator locktime)
    maxLockBlocks: 518400
    // ~12 days at 2s/block
  },
  arb: {
    name: "Arbitrum",
    ticker: "ARB",
    isEvm: true,
    evmChainId: 42161,
    avgBlockTimeSec: 1,
    // NOTE: minLockBlocks/maxLockBlocks for EVM chains in this file are DEAD CODE.
    // The swap engine reads lock parameters from evm-config.ts (EVM_CHAINS).
    // These values are intentionally different (production vs testnet scales).
    // Do NOT rely on chain-config.ts for EVM timing parameters. See R38-CFG-002.
    minLockBlocks: 43200,
    // ~12h at 1s/block (half of UTXO initiator locktime)
    maxLockBlocks: 1036800
    // ~12 days at 1s/block
  },
  poly: {
    name: "Polygon",
    ticker: "POL",
    isEvm: true,
    evmChainId: 137,
    avgBlockTimeSec: 2,
    // Dead code for EVM chains (lock params come from evm-config.ts EVM_CHAINS). See R38-CFG-002.
    minLockBlocks: 10800,
    // ~6h at 2s/block
    maxLockBlocks: 86400
    // ~48h at 2s/block
  }
};
var MAX_FEE_RATE_SAT_PER_BYTE = {
  bch2: 20,
  bch: 20,
  btc: 100,
  bc2: 20,
  eth: 0,
  base: 0,
  arb: 0,
  poly: 0
};
function maxFeeRate(chain) {
  return MAX_FEE_RATE_SAT_PER_BYTE[chain] || 1;
}
var FEE_URGENCY_MAX_MULT = 3;
var FEE_URGENCY_START_FACTOR = 4;
function getChainConfig(chain) {
  const cfg = chainConfigs[chain];
  if (!cfg) throw new Error(`getChainConfig: unknown chain '${chain}'`);
  return cfg;
}

// src/fee-rate.ts
var FEE_CACHE_TTL_MS = 45e3;
var _cache = /* @__PURE__ */ new Map();
function configFloor(chain) {
  const f = getChainConfig(chain).feePerByte;
  return typeof f === "number" && Number.isFinite(f) && f > 0 ? f : 1;
}
async function fetchFeeRate(chain, estimate, force = false) {
  const floor = configFloor(chain);
  const cap = maxFeeRate(chain);
  const cached = _cache.get(chain);
  if (!force && cached && Date.now() - cached.at < FEE_CACHE_TTL_MS) return cached.rate;
  let rate = floor;
  try {
    const live = await estimate();
    if (typeof live === "number" && Number.isFinite(live) && live > 0) {
      rate = Math.max(floor, Math.min(Math.ceil(live), cap));
    }
  } catch {
  }
  _cache.set(chain, { rate, at: Date.now() });
  return rate;
}
function _clearFeeRateCache() {
  _cache.clear();
}
function deadlineAwareFeeRate(chain, baseRate, remainingSec, marginSec) {
  const floor = configFloor(chain);
  const cap = maxFeeRate(chain);
  const base = Math.max(floor, Math.min(Number.isFinite(baseRate) ? baseRate : floor, cap));
  let mult = 1;
  if (Number.isFinite(remainingSec) && Number.isFinite(marginSec) && marginSec > 0) {
    if (remainingSec <= marginSec) {
      mult = FEE_URGENCY_MAX_MULT;
    } else {
      const startAt = marginSec * FEE_URGENCY_START_FACTOR;
      if (remainingSec < startAt) {
        const frac = (startAt - remainingSec) / (startAt - marginSec);
        mult = 1 + frac * (FEE_URGENCY_MAX_MULT - 1);
      }
    }
  }
  return Math.max(floor, Math.min(Math.ceil(base * mult), cap));
}

export { _clearFeeRateCache, deadlineAwareFeeRate, fetchFeeRate };
