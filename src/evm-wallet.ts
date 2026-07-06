/**
 * EVM key derivation + address encoding (BIP44 m/44'/60'/0'/0/index, EIP-55 checksum).
 * Kept separate so wallet-core stays chain-agnostic. Uses @scure/bip32 for HD derivation,
 * @noble/curves to decompress the pubkey, @noble/hashes keccak_256 for the address hash,
 * and viem's getAddress for the EIP-55 checksum.
 */
import { HDKey } from '@scure/bip32';
import { mnemonicToSeedSync } from '@scure/bip39';
import { secp256k1 } from '@noble/curves/secp256k1';
import { keccak_256 } from '@noble/hashes/sha3';
import { bytesToHex } from '@noble/hashes/utils';
import { getAddress } from 'viem';

export interface EvmDerivedKey {
  privateKey: Uint8Array;
  publicKey: Uint8Array;
  address: string;
}

/** EIP-55 checksummed 0x address from a secp256k1 public key (compressed 33-byte or uncompressed 65-byte). */
export function evmAddressFromPubkey(publicKey: Uint8Array): string {
  // Ethereum addresses derive from the UNCOMPRESSED key (0x04 || X || Y); drop the 0x04 prefix, keccak, take last 20.
  const uncompressed =
    publicKey.length === 65 ? publicKey : secp256k1.ProjectivePoint.fromHex(publicKey).toRawBytes(false);
  const hash = keccak_256(uncompressed.subarray(1));
  return getAddress(('0x' + bytesToHex(hash.subarray(hash.length - 20))) as `0x${string}`);
}

/** Derive the EVM signing key at m/44'/60'/0'/0/index. Seed is zeroed after derivation. */
export function deriveEVMKey(mnemonic: string, index = 0, passphrase?: string): EvmDerivedKey {
  const seed = mnemonicToSeedSync(mnemonic, passphrase);
  let hdkey: HDKey;
  try {
    hdkey = HDKey.fromMasterSeed(seed);
  } finally {
    seed.fill(0); // zero seed even if derivation throws
  }
  const node = hdkey.derive(`m/44'/60'/0'/0/${index}`);
  if (!node.privateKey || !node.publicKey) throw new Error('Failed to derive EVM key');
  return { privateKey: node.privateKey, publicKey: node.publicKey, address: evmAddressFromPubkey(node.publicKey) };
}
