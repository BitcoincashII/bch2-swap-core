/**
 * TokenHTLC — deployed addresses and ABI for EVM ↔ BCH2 atomic swaps.
 *
 * TokenHTLC.sol: lock/claim/refund with sha256 hashLock, absolute unix timeLock.
 * This is Path A — no ZK proofs, no circuit. BCH2SwapEscrow is the shelved ZK path;
 * it is not referenced here.
 *
 * Source of truth: prover/e2e/config-base-sepolia.json + src/TokenHTLC.sol
 */
declare const BASE_SEPOLIA_CHAIN_ID = 84532;
declare const BASE_MAINNET_CHAIN_ID = 8453;
declare const ARBITRUM_CHAIN_ID = 42161;
declare const TOKEN_HTLC_ADDRESS: {
    readonly baseSepolia: "0x6873146b78f685f7e63d615281b1b68e5034617e";
    readonly baseSepoliaTestnet: "0x9a7d64f9df98112a16e56b1ed9f2bb8d9986a4cf";
    readonly arbitrum: "0xaa363C30320D5c7Fd6f43ee38F449EB4fE8F1065";
};
declare const TOKEN_HTLC_ABI: readonly [{
    readonly name: "lock";
    readonly type: "function";
    readonly stateMutability: "payable";
    readonly inputs: readonly [{
        readonly name: "recipient";
        readonly type: "address";
    }, {
        readonly name: "token";
        readonly type: "address";
    }, {
        readonly name: "amount";
        readonly type: "uint256";
    }, {
        readonly name: "hashLock";
        readonly type: "bytes32";
    }, {
        readonly name: "timeLock";
        readonly type: "uint256";
    }];
    readonly outputs: readonly [{
        readonly name: "id";
        readonly type: "bytes32";
    }];
}, {
    readonly name: "claim";
    readonly type: "function";
    readonly stateMutability: "nonpayable";
    readonly inputs: readonly [{
        readonly name: "id";
        readonly type: "bytes32";
    }, {
        readonly name: "secret";
        readonly type: "bytes32";
    }];
    readonly outputs: readonly [];
}, {
    readonly name: "refund";
    readonly type: "function";
    readonly stateMutability: "nonpayable";
    readonly inputs: readonly [{
        readonly name: "id";
        readonly type: "bytes32";
    }];
    readonly outputs: readonly [];
}, {
    readonly name: "getSwap";
    readonly type: "function";
    readonly stateMutability: "view";
    readonly inputs: readonly [{
        readonly name: "id";
        readonly type: "bytes32";
    }];
    readonly outputs: readonly [{
        readonly name: "initiator";
        readonly type: "address";
    }, {
        readonly name: "recipient";
        readonly type: "address";
    }, {
        readonly name: "token";
        readonly type: "address";
    }, {
        readonly name: "amount";
        readonly type: "uint256";
    }, {
        readonly name: "hashLock";
        readonly type: "bytes32";
    }, {
        readonly name: "timeLock";
        readonly type: "uint256";
    }, {
        readonly name: "claimed";
        readonly type: "bool";
    }, {
        readonly name: "refunded";
        readonly type: "bool";
    }];
}];
declare const TOKEN_HTLC_EVENTS: readonly [{
    readonly name: "Locked";
    readonly type: "event";
    readonly inputs: readonly [{
        readonly name: "id";
        readonly type: "bytes32";
        readonly indexed: true;
    }, {
        readonly name: "initiator";
        readonly type: "address";
        readonly indexed: true;
    }, {
        readonly name: "recipient";
        readonly type: "address";
        readonly indexed: false;
    }, {
        readonly name: "token";
        readonly type: "address";
        readonly indexed: false;
    }, {
        readonly name: "amount";
        readonly type: "uint256";
        readonly indexed: false;
    }, {
        readonly name: "hashLock";
        readonly type: "bytes32";
        readonly indexed: false;
    }, {
        readonly name: "timeLock";
        readonly type: "uint256";
        readonly indexed: false;
    }];
}, {
    readonly name: "Claimed";
    readonly type: "event";
    readonly inputs: readonly [{
        readonly name: "id";
        readonly type: "bytes32";
        readonly indexed: true;
    }, {
        readonly name: "secret";
        readonly type: "bytes32";
        readonly indexed: false;
    }];
}, {
    readonly name: "Refunded";
    readonly type: "event";
    readonly inputs: readonly [{
        readonly name: "id";
        readonly type: "bytes32";
        readonly indexed: true;
    }];
}];
type SwapState = {
    initiator: `0x${string}`;
    recipient: `0x${string}`;
    token: `0x${string}`;
    amount: bigint;
    hashLock: `0x${string}`;
    timeLock: bigint;
    claimed: boolean;
    refunded: boolean;
};

export { ARBITRUM_CHAIN_ID, BASE_MAINNET_CHAIN_ID, BASE_SEPOLIA_CHAIN_ID, type SwapState, TOKEN_HTLC_ABI, TOKEN_HTLC_ADDRESS, TOKEN_HTLC_EVENTS };
