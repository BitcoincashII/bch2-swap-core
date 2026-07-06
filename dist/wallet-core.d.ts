/**
 * Core Wallet Operations
 * Mnemonic generation, key derivation, address generation
 */
interface WalletAddresses {
    bch2: string;
    bc2: string;
    bch?: string;
    btc?: string;
    bc1?: string;
    p2shSegwit?: string;
    evm?: string;
}
interface DerivedKey {
    privateKey: Uint8Array;
    publicKey: Uint8Array;
    address: string;
}
declare function generateMnemonic(): string;
declare function validateMnemonic(mnemonic: string): boolean;
declare function mnemonicToSeed(mnemonic: string, passphrase?: string): Uint8Array;
declare function deriveAddresses(mnemonic: string, passphrase?: string): WalletAddresses;
declare function deriveKeyForSigning(mnemonic: string, chain: 'bch2' | 'bch' | 'bc2' | 'btc' | 'bc1' | 'p2sh-segwit' | 'evm', index?: number, passphrase?: string): DerivedKey;
/**
 * Derive key for signing using an arbitrary BIP32 derivation path.
 * Used for airdrop claiming where we need to match specific paths found during scanning.
 */
declare function deriveKeyForSigningByPath(mnemonic: string, path: string, passphrase?: string): DerivedKey;
declare function deriveMultipleAddresses(mnemonic: string, chain: 'bch2' | 'bch' | 'bc2' | 'btc' | 'bc1' | 'p2sh-segwit', count?: number, passphrase?: string): string[];
declare function formatMnemonicWords(mnemonic: string): string[];
declare function sanitizeMnemonic(input: string): string;
interface WIFKeyData {
    privateKey: Uint8Array;
    publicKey: Uint8Array;
    bch2Address: string;
    bc2Address: string;
    bc1Address: string;
    p2shSegwitAddress: string;
    pubkeyHash: Uint8Array;
    compressed: boolean;
}
declare function deriveFromWIF(wif: string): WIFKeyData | null;
declare function validateWIF(wif: string): boolean;

export { type DerivedKey, type WIFKeyData, type WalletAddresses, deriveAddresses, deriveFromWIF, deriveKeyForSigning, deriveKeyForSigningByPath, deriveMultipleAddresses, formatMnemonicWords, generateMnemonic, mnemonicToSeed, sanitizeMnemonic, validateMnemonic, validateWIF };
