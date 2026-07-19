type Chain = 'bch2' | 'bch' | 'btc' | 'bc2' | 'eth' | 'base' | 'arb' | 'poly';
type EvmChainId = 137 | 42161 | 11155111 | 84532 | 421614;
interface ChainConfig {
    name: string;
    ticker: string;
    isEvm?: boolean;
    evmChainId?: number;
    addressPrefix?: string;
    p2shVersionByte?: number;
    p2pkhVersionByte?: number;
    sighashType?: number;
    useBip143?: boolean;
    electrumServers?: ElectrumServer[];
    avgBlockTimeSec: number;
    minLockBlocks?: number;
    maxLockBlocks?: number;
    dustThreshold?: number;
    feePerByte?: number;
    bip44CoinType?: number;
    requiredConfirmations?: number;
}
interface ElectrumServer {
    host: string;
    port: number;
    ssl: boolean;
}
interface EvmSwapInfo {
    evmChainId: EvmChainId;
    tokenSymbol: string;
    tokenAddress: string;
    tokenDecimals: number;
    htlcAddress: string;
    swapId?: string;
}
interface SwapOffer {
    id: string;
    sendChain: Chain;
    receiveChain: Chain;
    sendAmount: string | number;
    receiveAmount: string | number;
    secretHash: string;
    secretNonce?: string;
    secretScheme?: string;
    makerIdPub?: string;
    makerSig?: string;
    authPub?: string;
    takerAuthPub?: string;
    initiatorSendAddress: string;
    initiatorReceiveAddress: string;
    status: SwapStatus;
    createdAt: number;
    expiresAt: number;
    evmInfo?: EvmSwapInfo;
    evmAddress?: string;
}
type SwapStatus = 'open' | 'accepting' | 'taken' | 'initiator_funded' | 'responder_funded' | 'claimed' | 'completed' | 'refunded' | 'expired' | 'cancelled';
interface HTLCParams {
    secretHash: Uint8Array;
    recipientPubkeyHash: Uint8Array;
    refundPubkeyHash: Uint8Array;
    locktime: number;
}
interface HTLCDetails {
    redeemScript: Uint8Array;
    p2shAddress: string;
    p2shScriptPubKey: Uint8Array;
    params: HTLCParams;
}
interface Utxo {
    tx_hash: string;
    tx_pos: number;
    value: number;
    height: number;
}
interface SwapState {
    offer: SwapOffer;
    role: 'initiator' | 'responder';
    secret?: Uint8Array;
    secretHash: Uint8Array;
    /** Destination address on theirChain for claiming counterparty's HTLC. Required for UTXO claim. */
    claimAddress: string;
    /** Refund address on myChain for HTLC refund. Required for UTXO refund. */
    refundAddress: string;
    myHTLC?: HTLCDetails;
    counterpartyHTLC?: HTLCDetails;
    myFundingTxid?: string;
    counterpartyFundingTxid?: string;
    counterpartyEvmSwapId?: string;
    myClaimTxid?: string;
    counterpartyClaimTxid?: string;
    evmLockBlock?: number;
    evmLockTxHash?: string;
    evmTimeLockBlock?: number;
    initiatorEvmLockBlock?: number;
    counterpartyEvmTimeLock?: number;
    responderToken?: string;
}

export type { Chain as C, EvmChainId as E, HTLCDetails as H, SwapState as S, Utxo as U, ChainConfig as a, HTLCParams as b };
