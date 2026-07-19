export type Chain = 'bch2' | 'bch' | 'btc' | 'bc2' | 'eth' | 'base' | 'arb' | 'poly';

export type EvmChainId = 137 | 42161 | 11155111 | 84532 | 421614;

export type SwapPair = `${Chain}/${Chain}`;

export interface ChainConfig {
  name: string;
  ticker: string;
  isEvm?: boolean;
  evmChainId?: number;
  // UTXO-only fields (optional so EVM entries can omit them)
  addressPrefix?: string; // CashAddr prefix (bch2, bch)
  p2shVersionByte?: number; // Base58 P2SH version (btc, bc2)
  p2pkhVersionByte?: number; // Base58 P2PKH (receive address) version (btc, bc2); default 0x00 mainnet, 0x6f regtest
  sighashType?: number; // 0x41 for BCH2/BCH, 0x01 for BTC/BC2
  useBip143?: boolean; // true for BCH2/BCH (FORKID), false for BTC/BC2
  electrumServers?: ElectrumServer[];
  avgBlockTimeSec: number;
  minLockBlocks?: number; // EVM: minimum timeLock duration enforced by HTLC contract
  maxLockBlocks?: number; // EVM: maximum timeLock duration
  dustThreshold?: number;
  feePerByte?: number;
  bip44CoinType?: number; // BIP44 coin type for derivation path
  requiredConfirmations?: number; // minimum confirmations before treating a UTXO as spendable
}

export interface ElectrumServer {
  host: string;
  port: number;
  ssl: boolean;
}

export interface EvmSwapInfo {
  evmChainId: EvmChainId;
  tokenSymbol: string;
  tokenAddress: string;
  tokenDecimals: number;
  htlcAddress: string;
  swapId?: string; // bytes32 hex — set after lock() tx confirms
}

export interface SwapOffer {
  id: string;
  sendChain: Chain;
  receiveChain: Chain;
  // R266-AMT-STR: canonical stored form is a decimal STRING of integer BASE UNITS (sats for UTXO,
  // wei for ETH, units×10^decimals for tokens). A bare `number` is the legacy on-the-wire/persisted
  // form (≤2^53) and MUST be normalized via baseUnitToBigInt()/toBaseUnitString() (src/core/amount-units)
  // before any arithmetic — never Number() an EVM amount (18-dec ETH overflows MAX_SAFE_INTEGER).
  sendAmount: string | number;
  receiveAmount: string | number;
  secretHash: string; // hex, SHA-256 of secret
  // PHASE-1 (stateless): public per-swap nonce for the SEED-DERIVED initiator secret (S = HMAC(K_ss, DOMAIN||nonce)).
  // Present only on scheme 'hmac-v1' offers; absent => legacy random secret. secretHash still authenticates it.
  secretNonce?: string; // 32-hex (16 bytes)
  secretScheme?: string; // e.g. 'hmac-v1'
  // PHASE-2 (stateless): seed-derived maker-identity authorship (both PUBLIC). makerIdPub = m/83'/1'/0' compressed
  // pubkey (66-hex); makerSig = ECDSA over sha256("BCH2SWAP/maker/v1"||secretHash) (128-hex). Used ONLY for
  // own-offer detection in Browse (isOwnOffer) — never for fund logic. Absent on legacy offers.
  makerIdPub?: string;
  makerSig?: string;
  // PHASE-4 (stateless auth): seed-derived API-auth pubkeys (m/83'/2'/0', 66-hex). authPub = initiator's (in the
  // proposal); takerAuthPub = responder's (in the taker data, present once taken). Each role confirms its own is
  // bound before preferring signature auth over the stored token; the box authenticates PATCH/DELETE against them.
  authPub?: string;
  takerAuthPub?: string;
  initiatorSendAddress: string; // initiator's address on sendChain (for refund)
  initiatorReceiveAddress: string; // initiator's address on receiveChain (for claim)
  status: SwapStatus;
  createdAt: number; // unix timestamp
  expiresAt: number; // unix timestamp
  // EVM extension fields (present when either side is an EVM chain)
  evmInfo?: EvmSwapInfo;
  evmAddress?: string; // the EVM address (0x…) that will send/receive tokens
}

export type SwapStatus =
  | 'open' // offer posted, waiting for taker
  | 'accepting' // taker is mid-accept flow (transient client-side state)
  | 'taken' // taker accepted, waiting for initiator HTLC
  | 'initiator_funded' // initiator HTLC on-chain
  | 'responder_funded' // responder HTLC on-chain
  | 'claimed' // initiator claimed responder's HTLC (secret revealed)
  | 'completed' // responder claimed initiator's HTLC
  | 'refunded' // timelock expired, funds returned
  | 'expired' // offer expired without acceptance
  | 'cancelled'; // offer cancelled by creator

export interface SwapAcceptance {
  offerId: string;
  responderSendAddress: string; // responder's address on receiveChain (for refund)
  responderReceiveAddress: string; // responder's address on sendChain (for claim)
}

export interface HTLCParams {
  secretHash: Uint8Array; // 32 bytes
  recipientPubkeyHash: Uint8Array; // 20 bytes
  refundPubkeyHash: Uint8Array; // 20 bytes
  locktime: number; // absolute block height
}

export interface HTLCDetails {
  redeemScript: Uint8Array;
  p2shAddress: string;
  p2shScriptPubKey: Uint8Array;
  params: HTLCParams;
}

export interface Utxo {
  tx_hash: string;
  tx_pos: number;
  value: number;
  height: number;
}

export interface SwapState {
  offer: SwapOffer;
  role: 'initiator' | 'responder';
  secret?: Uint8Array; // only initiator knows this initially
  secretHash: Uint8Array;
  /** Destination address on theirChain for claiming counterparty's HTLC. Required for UTXO claim. */
  claimAddress: string;  // required: destination for claim tx
  /** Refund address on myChain for HTLC refund. Required for UTXO refund. */
  refundAddress: string; // required: destination for refund tx
  myHTLC?: HTLCDetails;
  counterpartyHTLC?: HTLCDetails;
  myFundingTxid?: string;
  counterpartyFundingTxid?: string;
  counterpartyEvmSwapId?: string;
  myClaimTxid?: string;
  counterpartyClaimTxid?: string;
  evmLockBlock?: number;
  // R-EVMLOCKTX: the actual on-chain lock TX HASH (distinct from myFundingTxid, which for an EVM leg is the
  // contract swapId). Captured from lockTokens/lockETH onBroadcast (which re-fires with the replacement hash on
  // a speed-up), so the UI's "EVM Lock Tx" link points at the live tx instead of building a 404 from the swapId.
  evmLockTxHash?: string;
  evmTimeLockBlock?: number;
  initiatorEvmLockBlock?: number;
  counterpartyEvmTimeLock?: number; // R167: trusted EVM-leg expiry (absolute unix seconds) of the EVM
                                    // counterparty, used to bound the responder's own UTXO-leg TIMESTAMP CLTV
                                    // so a malicious proxy block height cannot invert the cross-chain ordering.
  responderToken?: string; // token for authenticated status updates (responder role only)
}
