// src/evm/contracts.ts
var BASE_SEPOLIA_CHAIN_ID = 84532;
var BASE_MAINNET_CHAIN_ID = 8453;
var ARBITRUM_CHAIN_ID = 42161;
var TOKEN_HTLC_ADDRESS = {
  baseSepolia: "0x6873146b78f685f7e63d615281b1b68e5034617e",
  baseSepoliaTestnet: "0x9a7d64f9df98112a16e56b1ed9f2bb8d9986a4cf",
  arbitrum: "0xaa363C30320D5c7Fd6f43ee38F449EB4fE8F1065"
};
var TOKEN_HTLC_ABI = [
  // lock: initiator calls this to fund the EVM leg
  {
    name: "lock",
    type: "function",
    stateMutability: "payable",
    inputs: [
      { name: "recipient", type: "address" },
      { name: "token", type: "address" },
      { name: "amount", type: "uint256" },
      { name: "hashLock", type: "bytes32" },
      { name: "timeLock", type: "uint256" }
    ],
    outputs: [{ name: "id", type: "bytes32" }]
  },
  // claim: recipient reveals preimage to collect funds
  {
    name: "claim",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [
      { name: "id", type: "bytes32" },
      { name: "secret", type: "bytes32" }
    ],
    outputs: []
  },
  // refund: initiator recovers funds after timeLock expires
  {
    name: "refund",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [{ name: "id", type: "bytes32" }],
    outputs: []
  },
  // getSwap: read the full swap struct (for verification gate)
  {
    name: "getSwap",
    type: "function",
    stateMutability: "view",
    inputs: [{ name: "id", type: "bytes32" }],
    outputs: [
      { name: "initiator", type: "address" },
      { name: "recipient", type: "address" },
      { name: "token", type: "address" },
      { name: "amount", type: "uint256" },
      { name: "hashLock", type: "bytes32" },
      { name: "timeLock", type: "uint256" },
      { name: "claimed", type: "bool" },
      { name: "refunded", type: "bool" }
    ]
  }
];
var TOKEN_HTLC_EVENTS = [
  {
    name: "Locked",
    type: "event",
    inputs: [
      { name: "id", type: "bytes32", indexed: true },
      { name: "initiator", type: "address", indexed: true },
      { name: "recipient", type: "address", indexed: false },
      { name: "token", type: "address", indexed: false },
      { name: "amount", type: "uint256", indexed: false },
      { name: "hashLock", type: "bytes32", indexed: false },
      { name: "timeLock", type: "uint256", indexed: false }
    ]
  },
  {
    name: "Claimed",
    type: "event",
    inputs: [
      { name: "id", type: "bytes32", indexed: true },
      { name: "secret", type: "bytes32", indexed: false }
    ]
  },
  {
    name: "Refunded",
    type: "event",
    inputs: [{ name: "id", type: "bytes32", indexed: true }]
  }
];

export { ARBITRUM_CHAIN_ID, BASE_MAINNET_CHAIN_ID, BASE_SEPOLIA_CHAIN_ID, TOKEN_HTLC_ABI, TOKEN_HTLC_ADDRESS, TOKEN_HTLC_EVENTS };
