/**
 * Core Wallet Operations
 * Mnemonic generation, key derivation, address generation
 */

import * as bip39 from '@scure/bip39';
import { wordlist } from '@scure/bip39/wordlists/english';
import { HDKey } from '@scure/bip32';
import {
  pubkeyToBCH2Address,
  pubkeyToBC2Address,
  pubkeyToBCHAddress,
  pubkeyToBTCAddress,
  pubkeyToBech32Address,
  pubkeyToP2SHP2WPKHAddress,
  decodeWIF,
  p2pkhScripthash,
  p2wpkhScripthash,
  p2shP2wpkhScripthash,
  hash160,
} from './address-codec';
import * as secp256k1 from '@noble/secp256k1';
import { deriveEVMKey, evmAddressFromPubkey } from './evm-wallet';

export interface WalletAddresses {
  bch2: string;
  bc2: string;
  bch?: string;         // Bitcoin Cash CashAddr (coin type 145, same HD path as BCH2)
  btc?: string;         // Bitcoin native SegWit bc1q (BIP84)
  bc1?: string;         // Native SegWit for BCH2 airdrop recovery (BIP84)
  p2shSegwit?: string;  // Wrapped SegWit (BIP49)
  evm?: string;         // EVM address (EIP-55 checksummed, m/44'/60'/0'/0/0)
}

export interface DerivedKey {
  privateKey: Uint8Array;
  publicKey: Uint8Array;
  address: string;
}

// Derivation paths
const BCH2_PATH = "m/44'/20145'/0'/0/0";   // R322-AUDIT: BCH2-specific coin type 20145 (matches the DEX; NOT 145=BCH) — prevents key reuse and makes SDK-derived addresses match the DEX
const BCH_PATH  = "m/44'/145'/0'/0/0";    // BCH shares coin type 145 with BCH2; same key, different address prefix
const BC2_PATH  = "m/44'/0'/0'/0/0";      // BC2 uses coin type 0 (legacy P2PKH)
const BTC_PATH  = "m/84'/0'/0'/0/0";      // BTC BIP84 native SegWit (bc1q)
const BC1_PATH  = "m/84'/0'/0'/0/0";      // BCH2 airdrop recovery path (same as BTC BIP84)
const P2SH_SEGWIT_PATH = "m/49'/0'/0'/0/0"; // BIP49 Wrapped SegWit (3xxx)

export function generateMnemonic(): string {
  return bip39.generateMnemonic(wordlist, 128); // 12 words
}

export function validateMnemonic(mnemonic: string): boolean {
  return bip39.validateMnemonic(mnemonic, wordlist);
}

export function mnemonicToSeed(mnemonic: string, passphrase?: string): Uint8Array {
  return bip39.mnemonicToSeedSync(mnemonic, passphrase);
}

export function deriveAddresses(mnemonic: string, passphrase?: string): WalletAddresses {
  const seed = mnemonicToSeed(mnemonic, passphrase);
  let hdkey: HDKey;
  try {
    hdkey = HDKey.fromMasterSeed(seed);
  } finally {
    // Security: Zero seed after HD key creation (even if derivation throws)
    seed.fill(0);
  }

  // BCH2 address (CashAddr bitcoincashii:)
  const bch2Key = hdkey.derive(BCH2_PATH);
  if (!bch2Key.publicKey) throw new Error('Failed to derive BCH2 key');
  const bch2Address = pubkeyToBCH2Address(bch2Key.publicKey);

  // BCH address (CashAddr bitcoincash: — same HD key as BCH2, different prefix)
  const bchKey = hdkey.derive(BCH_PATH);
  if (!bchKey.publicKey) throw new Error('Failed to derive BCH key');
  const bchAddress = pubkeyToBCHAddress(bchKey.publicKey);

  // BC2 address (legacy P2PKH, coin type 0)
  const bc2Key = hdkey.derive(BC2_PATH);
  if (!bc2Key.publicKey) throw new Error('Failed to derive BC2 key');
  const bc2Address = pubkeyToBC2Address(bc2Key.publicKey);

  // BTC address (native SegWit bc1q, BIP84)
  const btcKey = hdkey.derive(BTC_PATH);
  if (!btcKey.publicKey) throw new Error('Failed to derive BTC key');
  const btcAddress = pubkeyToBTCAddress(btcKey.publicKey);

  // BC1 address (Native SegWit BIP84, BCH2 airdrop recovery — same path as BTC)
  const bc1Key = hdkey.derive(BC1_PATH);
  if (!bc1Key.publicKey) throw new Error('Failed to derive BC1 key');
  const bc1Address = pubkeyToBech32Address(bc1Key.publicKey);

  // P2SH-P2WPKH address (Wrapped SegWit BIP49)
  const p2shKey = hdkey.derive(P2SH_SEGWIT_PATH);
  if (!p2shKey.publicKey) throw new Error('Failed to derive P2SH key');
  const p2shSegwitAddress = pubkeyToP2SHP2WPKHAddress(p2shKey.publicKey);

  // EVM address (BIP44 m/44'/60'/0'/0/0 — standard Ethereum path)
  const evmKey = deriveEVMKey(mnemonic, 0, passphrase);
  const evmAddress = evmKey.address;

  return {
    bch2: bch2Address,
    bch: bchAddress,
    bc2: bc2Address,
    btc: btcAddress,
    bc1: bc1Address,
    p2shSegwit: p2shSegwitAddress,
    evm: evmAddress,
  };
}

export function deriveKeyForSigning(
  mnemonic: string,
  chain: 'bch2' | 'bch' | 'bc2' | 'btc' | 'bc1' | 'p2sh-segwit' | 'evm',
  index: number = 0,
  passphrase?: string
): DerivedKey {
  const seed = mnemonicToSeed(mnemonic, passphrase);
  let hdkey: HDKey;
  try {
    hdkey = HDKey.fromMasterSeed(seed);
  } finally {
    // Security: Zero seed after HD key creation (even if derivation throws)
    seed.fill(0);
  }

  let basePath: string;
  switch (chain) {
    case 'bch2':
      // R322-AUDIT: BCH2-specific coin type 20145 (matches the DEX chain-config; NOT 145) — a distinct key.
      basePath = "m/44'/20145'/0'";
      break;
    case 'bch':
      basePath = "m/44'/145'/0'";
      break;
    case 'bc2':
      basePath = "m/44'/0'/0'";
      break;
    case 'btc':
    case 'bc1':
      basePath = "m/84'/0'/0'";
      break;
    case 'p2sh-segwit':
      basePath = "m/49'/0'/0'";
      break;
    case 'evm':
      basePath = "m/44'/60'/0'";
      break;
  }
  const fullPath = `${basePath}/0/${index}`;

  const derived = hdkey.derive(fullPath);
  if (!derived.privateKey || !derived.publicKey) {
    throw new Error('Failed to derive key');
  }

  let address: string;
  switch (chain) {
    case 'bch2':
      address = pubkeyToBCH2Address(derived.publicKey);
      break;
    case 'bch':
      address = pubkeyToBCHAddress(derived.publicKey);
      break;
    case 'bc2':
      address = pubkeyToBC2Address(derived.publicKey);
      break;
    case 'btc':
      address = pubkeyToBTCAddress(derived.publicKey);
      break;
    case 'bc1':
      address = pubkeyToBech32Address(derived.publicKey);
      break;
    case 'p2sh-segwit':
      address = pubkeyToP2SHP2WPKHAddress(derived.publicKey);
      break;
    case 'evm':
      address = evmAddressFromPubkey(derived.publicKey);
      break;
  }

  return {
    privateKey: derived.privateKey,
    publicKey: derived.publicKey,
    address,
  };
}

/**
 * Derive key for signing using an arbitrary BIP32 derivation path.
 * Used for airdrop claiming where we need to match specific paths found during scanning.
 */
export function deriveKeyForSigningByPath(
  mnemonic: string,
  path: string,
  passphrase?: string
): DerivedKey {
  const seed = mnemonicToSeed(mnemonic, passphrase);
  let hdkey: HDKey;
  try {
    hdkey = HDKey.fromMasterSeed(seed);
  } finally {
    // Security: Zero seed after HD key creation (even if derivation throws)
    seed.fill(0);
  }

  const derived = hdkey.derive(path);
  if (!derived.privateKey || !derived.publicKey) {
    throw new Error('Failed to derive key for path: ' + path);
  }

  // Determine address format from path
  // BIP84 (m/84'/...) = bc1, BIP49 (m/49'/...) = p2sh-segwit, otherwise legacy BCH2
  let address: string;
  if (path.startsWith("m/84'")) {
    address = pubkeyToBech32Address(derived.publicKey);
  } else if (path.startsWith("m/49'")) {
    address = pubkeyToP2SHP2WPKHAddress(derived.publicKey);
  } else {
    // Default to BCH2 CashAddr for BIP44 and others
    address = pubkeyToBCH2Address(derived.publicKey);
  }

  return {
    privateKey: derived.privateKey,
    publicKey: derived.publicKey,
    address,
  };
}

export function deriveMultipleAddresses(
  mnemonic: string,
  chain: 'bch2' | 'bch' | 'bc2' | 'btc' | 'bc1' | 'p2sh-segwit',
  count: number = 20,
  passphrase?: string
): string[] {
  const seed = mnemonicToSeed(mnemonic, passphrase);
  let hdkey: HDKey;
  try {
    hdkey = HDKey.fromMasterSeed(seed);
  } finally {
    // Security: Zero seed after HD key creation (even if derivation throws)
    seed.fill(0);
  }

  let basePath: string;
  switch (chain) {
    case 'bch2':
      basePath = "m/44'/20145'/0'"; // R322-AUDIT: BCH2-specific coin type (matches the DEX)
      break;
    case 'bch':
      basePath = "m/44'/145'/0'";
      break;
    case 'bc2':
      basePath = "m/44'/0'/0'";
      break;
    case 'btc':
    case 'bc1':
      basePath = "m/84'/0'/0'";
      break;
    case 'p2sh-segwit':
      basePath = "m/49'/0'/0'";
      break;
  }

  const addresses: string[] = [];

  for (let i = 0; i < count; i++) {
    const derived = hdkey.derive(`${basePath}/0/${i}`);
    if (!derived.publicKey) continue;

    let address: string;
    switch (chain) {
      case 'bch2':
        address = pubkeyToBCH2Address(derived.publicKey);
        break;
      case 'bch':
        address = pubkeyToBCHAddress(derived.publicKey);
        break;
      case 'bc2':
        address = pubkeyToBC2Address(derived.publicKey);
        break;
      case 'btc':
        address = pubkeyToBTCAddress(derived.publicKey);
        break;
      case 'bc1':
        address = pubkeyToBech32Address(derived.publicKey);
        break;
      case 'p2sh-segwit':
        address = pubkeyToP2SHP2WPKHAddress(derived.publicKey);
        break;
    }

    addresses.push(address);
  }

  return addresses;
}

// Utility to format mnemonic for display
export function formatMnemonicWords(mnemonic: string): string[] {
  return mnemonic.trim().toLowerCase().split(/\s+/);
}

// Sanitize mnemonic input
export function sanitizeMnemonic(input: string): string {
  return input.toLowerCase().replace(/[^a-z\s]/g, '').trim().replace(/\s+/g, ' ');
}

// Derive addresses from a WIF private key (for airdrop claims)
export interface WIFKeyData {
  privateKey: Uint8Array;
  publicKey: Uint8Array;
  bch2Address: string;
  bc2Address: string;
  bc1Address: string;
  p2shSegwitAddress: string;
  pubkeyHash: Uint8Array;
  compressed: boolean;
}

export function deriveFromWIF(wif: string): WIFKeyData | null {
  const decoded = decodeWIF(wif);
  if (!decoded) return null;

  const { privateKey, compressed } = decoded;
  const publicKey = secp256k1.getPublicKey(privateKey, compressed);
  const pubkeyHash = hash160(publicKey);

  return {
    privateKey,
    publicKey,
    bch2Address: pubkeyToBCH2Address(publicKey),
    bc2Address: pubkeyToBC2Address(publicKey),
    bc1Address: pubkeyToBech32Address(publicKey),
    p2shSegwitAddress: pubkeyToP2SHP2WPKHAddress(publicKey),
    pubkeyHash,
    compressed,
  };
}

// Validate WIF format
export function validateWIF(wif: string): boolean {
  return decodeWIF(wif) !== null;
}
