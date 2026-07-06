/**
 * Address Encoding/Decoding for BCH2 (CashAddr) and BC2 (Legacy)
 */
declare function hash160(data: Uint8Array): Uint8Array;
declare function encodeCashAddr(prefix: string, type: number, hash: Uint8Array): string;
declare function decodeCashAddr(address: string): {
    prefix: string;
    type: number;
    hash: Uint8Array;
} | null;
declare function encodeBase58(data: Uint8Array): string;
declare function decodeBase58(str: string): Uint8Array | null;
declare function encodeLegacyAddress(pubkeyHash: Uint8Array): string;
declare function decodeLegacyAddress(address: string): Uint8Array | null;
declare function pubkeyToBCH2Address(pubkey: Uint8Array): string;
declare function pubkeyToBC2Address(pubkey: Uint8Array): string;
declare function decodeWIF(wif: string): {
    privateKey: Uint8Array;
    compressed: boolean;
} | null;
declare function encodeWIF(privateKey: Uint8Array, compressed?: boolean): string;
declare function encodeBech32(hrp: string, version: number, data: Uint8Array): string;
declare function decodeBech32(address: string): {
    hrp: string;
    version: number;
    program: Uint8Array;
} | null;
declare function pubkeyToBech32Address(pubkey: Uint8Array): string;
declare function pubkeyToBCHAddress(pubkey: Uint8Array): string;
declare function pubkeyToBTCAddress(pubkey: Uint8Array): string;
declare function isBech32Address(address: string): boolean;
declare function encodeBech32m(hrp: string, version: number, data: Uint8Array): string;
declare function decodeBech32m(address: string): {
    hrp: string;
    version: number;
    program: Uint8Array;
} | null;
declare function xonlyPubkeyToP2TRAddress(xonlyPubkey: Uint8Array): string;
declare function p2trScripthash(xonlyTweakedPubkey: Uint8Array): string;
declare function pubkeyToP2SHP2WPKHAddress(pubkey: Uint8Array): string;
declare function p2pkScripthash(publicKey: Uint8Array): string;
declare function p2pkhScripthash(pubkeyHash: Uint8Array): string;
declare function p2wpkhScripthash(pubkeyHash: Uint8Array): string;
declare function p2shP2wpkhScripthash(pubkeyHash: Uint8Array): string;
declare function bc1AddressToScripthash(address: string): string | null;

export { bc1AddressToScripthash, decodeBase58, decodeBech32, decodeBech32m, decodeCashAddr, decodeLegacyAddress, decodeWIF, encodeBase58, encodeBech32, encodeBech32m, encodeCashAddr, encodeLegacyAddress, encodeWIF, hash160, isBech32Address, p2pkScripthash, p2pkhScripthash, p2shP2wpkhScripthash, p2trScripthash, p2wpkhScripthash, pubkeyToBC2Address, pubkeyToBCH2Address, pubkeyToBCHAddress, pubkeyToBTCAddress, pubkeyToBech32Address, pubkeyToP2SHP2WPKHAddress, xonlyPubkeyToP2TRAddress };
