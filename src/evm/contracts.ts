/**
 * TokenHTLC — deployed addresses and ABI for EVM ↔ BCH2 atomic swaps.
 *
 * TokenHTLC.sol: lock/claim/refund with sha256 hashLock, absolute unix timeLock.
 * This is Path A — no ZK proofs, no circuit. BCH2SwapEscrow is the shelved ZK path;
 * it is not referenced here.
 *
 * Source of truth: prover/e2e/config-base-sepolia.json + src/TokenHTLC.sol
 */

export const BASE_SEPOLIA_CHAIN_ID = 84532;
export const BASE_MAINNET_CHAIN_ID = 8453;
export const ARBITRUM_CHAIN_ID = 42161;

// Deployed TokenHTLC contract addresses.
// htlc_address = mainnet timelock params (MIN=35d, MAX=60d)
// htlc_test_address = TokenHTLCTestnet with MIN_LOCK_SECONDS=200 for fast integration testing
export const TOKEN_HTLC_ADDRESS = {
  baseSepolia:        '0x6873146b78f685f7e63d615281b1b68e5034617e' as const,
  baseSepoliaTestnet: '0x9a7d64f9df98112a16e56b1ed9f2bb8d9986a4cf' as const,
  arbitrum:           '0xaa363C30320D5c7Fd6f43ee38F449EB4fE8F1065' as const,
} as const;

// Minimal ABI — only the 4 functions the swap engine and wallet call.
// Derived directly from TokenHTLC.sol; no codegen.
export const TOKEN_HTLC_ABI = [
  // lock: initiator calls this to fund the EVM leg
  {
    name: 'lock',
    type: 'function',
    stateMutability: 'payable',
    inputs: [
      { name: 'recipient', type: 'address' },
      { name: 'token',     type: 'address' },
      { name: 'amount',    type: 'uint256' },
      { name: 'hashLock',  type: 'bytes32' },
      { name: 'timeLock',  type: 'uint256' },
    ],
    outputs: [{ name: 'id', type: 'bytes32' }],
  },
  // claim: recipient reveals preimage to collect funds
  {
    name: 'claim',
    type: 'function',
    stateMutability: 'nonpayable',
    inputs: [
      { name: 'id',     type: 'bytes32' },
      { name: 'secret', type: 'bytes32' },
    ],
    outputs: [],
  },
  // refund: initiator recovers funds after timeLock expires
  {
    name: 'refund',
    type: 'function',
    stateMutability: 'nonpayable',
    inputs: [{ name: 'id', type: 'bytes32' }],
    outputs: [],
  },
  // getSwap: read the full swap struct (for verification gate)
  {
    name: 'getSwap',
    type: 'function',
    stateMutability: 'view',
    inputs: [{ name: 'id', type: 'bytes32' }],
    outputs: [
      { name: 'initiator', type: 'address' },
      { name: 'recipient', type: 'address' },
      { name: 'token',     type: 'address' },
      { name: 'amount',    type: 'uint256' },
      { name: 'hashLock',  type: 'bytes32' },
      { name: 'timeLock',  type: 'uint256' },
      { name: 'claimed',   type: 'bool'    },
      { name: 'refunded',  type: 'bool'    },
    ],
  },
] as const;

// Events — for log parsing / subscription (step 3)
export const TOKEN_HTLC_EVENTS = [
  {
    name: 'Locked',
    type: 'event',
    inputs: [
      { name: 'id',        type: 'bytes32', indexed: true  },
      { name: 'initiator', type: 'address', indexed: true  },
      { name: 'recipient', type: 'address', indexed: false },
      { name: 'token',     type: 'address', indexed: false },
      { name: 'amount',    type: 'uint256', indexed: false },
      { name: 'hashLock',  type: 'bytes32', indexed: false },
      { name: 'timeLock',  type: 'uint256', indexed: false },
    ],
  },
  {
    name: 'Claimed',
    type: 'event',
    inputs: [
      { name: 'id',     type: 'bytes32', indexed: true  },
      { name: 'secret', type: 'bytes32', indexed: false },
    ],
  },
  {
    name: 'Refunded',
    type: 'event',
    inputs: [{ name: 'id', type: 'bytes32', indexed: true }],
  },
] as const;

export type SwapState = {
  initiator: `0x${string}`;
  recipient: `0x${string}`;
  token:     `0x${string}`;
  amount:    bigint;
  hashLock:  `0x${string}`;
  timeLock:  bigint;
  claimed:   boolean;
  refunded:  boolean;
};
