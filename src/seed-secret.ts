// Seed-derived swap secret + maker identity (stateless-client rearchitecture, Phase 1).
//
// FROZEN — DECISION A (signed off 2026-07-08). Every value below is PERMANENT: once a real swap
// secret depends on it, changing the path, the domain string, the nonce length, or the primitive
// silently produces DIFFERENT secrets and would strand funds. The canonical test vectors in
// seed-secret.test.ts are asserted against two independent implementations (@scure/bip32 + ethers,
// @noble/hashes + node:crypto). Do not edit these constants.
import { HDKey } from '@scure/bip32';
import { mnemonicToSeedSync, validateMnemonic } from '@scure/bip39';
import { wordlist } from '@scure/bip39/wordlists/english';
import { hmac } from '@noble/hashes/hmac';
import { sha256 } from '@noble/hashes/sha256';
import * as secp256k1 from '@noble/secp256k1';

const _fromHex = (s: string): Uint8Array => Uint8Array.from((s.match(/../g) ?? []).map((h) => parseInt(h, 16)));
const _toHex = (u: Uint8Array): string => Array.from(u).map((b) => b.toString(16).padStart(2, '0')).join('');

const HARDENED = 0x80000000;
// Purpose 83 (= 0x53 = 'S' for Swap) — a dedicated, coin-type-INDEPENDENT branch, so nothing here is
// entangled with the BCH2 bip44 coin-type (kept at 20145; see project memory).
const SWAP_SECRET_PATH = [HARDENED + 83, HARDENED + 0, HARDENED + 0]; // m/83'/0'/0'  → K_ss (HTLC preimage key)
const MAKER_ID_PATH    = [HARDENED + 83, HARDENED + 1, HARDENED + 0]; // m/83'/1'/0'  → maker-identity pubkey
// (m/83'/2'/0' reserved for the Phase-4 API-auth key — deriveAuthKey ships with Phase 4.)
const SECRET_DOMAIN    = new TextEncoder().encode('BCH2SWAP/secret/v1'); // versioned; bump to /v2 to change anything
const MAKER_SIG_DOMAIN = new TextEncoder().encode('BCH2SWAP/maker/v1');  // domain-separates the own-offer authorship sig

/** Per-offer scheme tag stored on the box (`proposal.secretScheme`). An offer's OWN tag — never the live
 *  /health flag — decides how its secret is recovered, so flipping the flag can't strand a posted offer. */
export const SWAP_SECRET_SCHEME = 'hmac-v1';
export const SWAP_NONCE_BYTES = 16;
export const MAKER_SIG_SCHEME = 'ecdsa-v1'; // tag stored beside makerIdPub/makerSig on the offer

function wipeNode(n: HDKey | null): void {
  try { n?.wipePrivateData?.(); } catch { /* best-effort */ }
  try { if (n && 'chainCode' in n && n.chainCode instanceof Uint8Array) n.chainCode.fill(0); } catch { /* best-effort */ }
}

/**
 * Derive the 32-byte HTLC preimage `S = HMAC-SHA256(K_ss, DOMAIN || nonce)`, where
 * `K_ss` = seed → m/83'/0'/0' (all levels hardened, so a K_ss leak exposes neither the seed nor any
 * spending key). INITIATOR-side only — the responder learns S on-chain. Deterministic: the same
 * (mnemonic, nonce) always yields the same S, so it need never be stored and is recoverable on any
 * device. Returns null on an invalid mnemonic or wrong-length nonce. Wipes all intermediate material.
 */
export function deriveSwapSecret(mnemonic: string, nonce: Uint8Array): Uint8Array | null {
  const kss = deriveSwapKss(mnemonic);
  if (!kss) return null;
  try { return swapSecretFromKss(kss, nonce); }
  finally { kss.fill(0); }
}

/**
 * Derive K_ss = seed → m/83'/0'/0' (the 32-byte swap-secret key). Cache this at unlock beside the other
 * session keys so the preimage can be re-derived at fund/claim time (where the mnemonic has been wiped).
 * The CALLER owns the returned buffer and MUST zero it on lock. Wipes all intermediate material + the seed.
 */
export function deriveSwapKss(mnemonic: string): Uint8Array | null {
  const normalized = mnemonic.trim().toLowerCase();
  if (!validateMnemonic(normalized, wordlist)) return null;
  let seed: Uint8Array | undefined;
  let root: HDKey | null = null;
  let kss: Uint8Array | null = null;
  try {
    seed = mnemonicToSeedSync(normalized);
    root = HDKey.fromMasterSeed(seed);
    let l1: HDKey | null = null, l2: HDKey | null = null, l3: HDKey | null = null;
    try {
      l1 = root.deriveChild(SWAP_SECRET_PATH[0]);
      l2 = l1.deriveChild(SWAP_SECRET_PATH[1]);
      l3 = l2.deriveChild(SWAP_SECRET_PATH[2]);
      if (l3.privateKey) kss = new Uint8Array(l3.privateKey); // copy out BEFORE the finally wipes the node
    } finally {
      wipeNode(l1); wipeNode(l2); wipeNode(l3);
    }
    return kss;
  } catch {
    if (kss) kss.fill(0);
    return null;
  } finally {
    try { root?.wipePrivateData?.(); } catch { /* best-effort */ }
    if (seed) seed.fill(0);
  }
}

/** S = HMAC-SHA256(K_ss, DOMAIN || nonce) — the 32-byte HTLC preimage. Pure function of the cached key +
 *  the public nonce; does NOT wipe K_ss (the caller owns it). Returns null on a wrong-length nonce/key. */
export function swapSecretFromKss(kss: Uint8Array, nonce: Uint8Array): Uint8Array | null {
  if (!(kss instanceof Uint8Array) || kss.length !== 32) return null;
  if (!(nonce instanceof Uint8Array) || nonce.length !== SWAP_NONCE_BYTES) return null;
  const msg = new Uint8Array(SECRET_DOMAIN.length + nonce.length);
  msg.set(SECRET_DOMAIN, 0);
  msg.set(nonce, SECRET_DOMAIN.length);
  return hmac(sha256, kss, msg); // separate buffer from kss
}

/**
 * Derive the maker-identity public key (compressed, 33B hex) from m/83'/1'/0'. Public output only —
 * used to authenticate own-offer authorship (Phase 2). Cache this ONE public value at unlock; verifying
 * an offer's makerSig needs only this pubkey, never the seed. Returns null on an invalid mnemonic.
 */
export function deriveMakerIdPub(mnemonic: string): string | null {
  const normalized = mnemonic.trim().toLowerCase();
  if (!validateMnemonic(normalized, wordlist)) return null;
  let seed: Uint8Array | undefined;
  let root: HDKey | null = null;
  try {
    seed = mnemonicToSeedSync(normalized);
    root = HDKey.fromMasterSeed(seed);
    let l1: HDKey | null = null, l2: HDKey | null = null, l3: HDKey | null = null;
    let pub: Uint8Array | undefined;
    try {
      l1 = root.deriveChild(MAKER_ID_PATH[0]);
      l2 = l1.deriveChild(MAKER_ID_PATH[1]);
      l3 = l2.deriveChild(MAKER_ID_PATH[2]);
      if (l3.publicKey) pub = new Uint8Array(l3.publicKey);
    } finally {
      wipeNode(l1); wipeNode(l2); wipeNode(l3);
    }
    if (!pub) return null;
    return Array.from(pub).map((b) => b.toString(16).padStart(2, '0')).join('');
  } catch {
    return null;
  } finally {
    try { root?.wipePrivateData?.(); } catch { /* best-effort */ }
    if (seed) seed.fill(0);
  }
}

/** Derive the maker-identity PRIVATE key (m/83'/1'/0'). Internal — caller must zero the returned buffer. */
function deriveMakerIdPriv(mnemonic: string): Uint8Array | null {
  const normalized = mnemonic.trim().toLowerCase();
  if (!validateMnemonic(normalized, wordlist)) return null;
  let seed: Uint8Array | undefined;
  let root: HDKey | null = null;
  let priv: Uint8Array | null = null;
  try {
    seed = mnemonicToSeedSync(normalized);
    root = HDKey.fromMasterSeed(seed);
    let l1: HDKey | null = null, l2: HDKey | null = null, l3: HDKey | null = null;
    try {
      l1 = root.deriveChild(MAKER_ID_PATH[0]);
      l2 = l1.deriveChild(MAKER_ID_PATH[1]);
      l3 = l2.deriveChild(MAKER_ID_PATH[2]);
      if (l3.privateKey) priv = new Uint8Array(l3.privateKey);
    } finally {
      wipeNode(l1); wipeNode(l2); wipeNode(l3);
    }
    return priv;
  } catch {
    if (priv) priv.fill(0);
    return null;
  } finally {
    try { root?.wipePrivateData?.(); } catch { /* best-effort */ }
    if (seed) seed.fill(0);
  }
}

/** Message hash the maker-identity signature commits to: SHA256("BCH2SWAP/maker/v1" || secretHash_bytes).
 *  Binding to the per-offer secretHash makes the signature offer-specific — it can't be replayed onto another
 *  offer, and a hostile box can't fabricate one (it lacks the maker's identity key). */
function makerSigMsgHash(secretHashHex: string): Uint8Array | null {
  const h = secretHashHex.toLowerCase().replace(/^0x/, '');
  if (!/^[0-9a-f]{64}$/.test(h)) return null;
  const sh = _fromHex(h);
  const msg = new Uint8Array(MAKER_SIG_DOMAIN.length + sh.length);
  msg.set(MAKER_SIG_DOMAIN, 0);
  msg.set(sh, MAKER_SIG_DOMAIN.length);
  return sha256(msg);
}

/** Sign own-offer authorship: deterministic ECDSA over makerSigMsgHash(secretHash) with the m/83'/1'/0' key.
 *  Returns a 64-byte compact-hex signature, or null on bad input. Wipes the private key. PUBLIC output. */
export async function signMakerIdentity(mnemonic: string, secretHashHex: string): Promise<string | null> {
  const msgHash = makerSigMsgHash(secretHashHex);
  if (!msgHash) return null;
  const priv = deriveMakerIdPriv(mnemonic);
  if (!priv) return null;
  try {
    const sig = await secp256k1.signAsync(msgHash, priv, { lowS: true }); // RFC6979 deterministic, canonical low-S
    return _toHex(sig.toCompactRawBytes());
  } catch {
    return null;
  } finally {
    priv.fill(0);
  }
}

/** Verify own-offer authorship — PUBLIC-KEY ONLY (no seed), so it works with the wallet locked. Returns false on
 *  any malformed input or verification failure (never throws). A false here means "not provably mine" => show it. */
export function verifyMakerIdentity(makerIdPubHex: string, secretHashHex: string, sigHex: string): boolean {
  try {
    const pub = makerIdPubHex.toLowerCase().replace(/^0x/, '');
    const sig = sigHex.toLowerCase().replace(/^0x/, '');
    if (!/^0[23][0-9a-f]{64}$/.test(pub)) return false; // 33-byte compressed secp256k1 pubkey
    if (!/^[0-9a-f]{128}$/.test(sig)) return false;      // 64-byte compact ECDSA signature
    const msgHash = makerSigMsgHash(secretHashHex);
    if (!msgHash) return false;
    return secp256k1.verify(_fromHex(sig), msgHash, _fromHex(pub));
  } catch {
    return false;
  }
}

// ── Phase 4: seed-derived API request auth (m/83'/2'/0') ─────────────────────────────────────────
// Replaces the random per-swap admin/responder tokens as the authenticator for box status PATCH / DELETE, so the
// browser stores NO token — a fresh device re-derives the same key and signs. Box status is advisory (never a fund
// authority), so this is about retiring fragile local state, not fund-safety. The proxy verifies with node:crypto
// (SPKI-wrapped compressed pubkey + crypto.verify(..., ieee-p1363)); this signer emits the matching compact 64B sig.
const API_AUTH_PATH = [HARDENED + 83, HARDENED + 2, HARDENED + 0]; // m/83'/2'/0'
const API_AUTH_DOMAIN = 'BCH2SWAP/api/v1';
export const API_AUTH_SCHEME = 'ecdsa-v1';

/** The canonical signed preimage. Binds the sig to the endpoint (method+path), the order id, and a timestamp so a
 *  captured signature can't be replayed onto a different order or a different action, and expires (proxy enforces a
 *  ~120s window). MUST be byte-identical on client and proxy. (targetStatus is intentionally NOT bound — box status
 *  is not a fund authority, and binding it would require parsing the body before auth; the role→status allowlist
 *  still constrains what each party can set.) */
export function buildApiAuthPreimage(p: { method: string; path: string; id: string; timestamp: number }): string {
  return [API_AUTH_DOMAIN, p.method.toUpperCase(), p.path, p.id, String(p.timestamp)].join('\n');
}

function deriveApiAuthPriv(mnemonic: string): Uint8Array | null {
  const normalized = mnemonic.trim().toLowerCase();
  if (!validateMnemonic(normalized, wordlist)) return null;
  let seed: Uint8Array | undefined;
  let root: HDKey | null = null;
  let priv: Uint8Array | null = null;
  try {
    seed = mnemonicToSeedSync(normalized);
    root = HDKey.fromMasterSeed(seed);
    let l1: HDKey | null = null, l2: HDKey | null = null, l3: HDKey | null = null;
    try {
      l1 = root.deriveChild(API_AUTH_PATH[0]);
      l2 = l1.deriveChild(API_AUTH_PATH[1]);
      l3 = l2.deriveChild(API_AUTH_PATH[2]);
      if (l3.privateKey) priv = new Uint8Array(l3.privateKey);
    } finally {
      wipeNode(l1); wipeNode(l2); wipeNode(l3);
    }
    return priv;
  } catch {
    if (priv) priv.fill(0);
    return null;
  } finally {
    try { root?.wipePrivateData?.(); } catch { /* best-effort */ }
    if (seed) seed.fill(0);
  }
}

/** The maker's API-auth PUBLIC key (compressed, 33B hex) from m/83'/2'/0'. Attached to the offer / take (public),
 *  so the proxy knows which key must sign this order's status changes. Cached at unlock like the maker-id pubkey. */
export function deriveApiAuthPub(mnemonic: string): string | null {
  const normalized = mnemonic.trim().toLowerCase();
  if (!validateMnemonic(normalized, wordlist)) return null;
  let seed: Uint8Array | undefined;
  let root: HDKey | null = null;
  try {
    seed = mnemonicToSeedSync(normalized);
    root = HDKey.fromMasterSeed(seed);
    let l1: HDKey | null = null, l2: HDKey | null = null, l3: HDKey | null = null;
    let pub: Uint8Array | undefined;
    try {
      l1 = root.deriveChild(API_AUTH_PATH[0]);
      l2 = l1.deriveChild(API_AUTH_PATH[1]);
      l3 = l2.deriveChild(API_AUTH_PATH[2]);
      if (l3.publicKey) pub = new Uint8Array(l3.publicKey);
    } finally {
      wipeNode(l1); wipeNode(l2); wipeNode(l3);
    }
    if (!pub) return null;
    return Array.from(pub).map((b) => b.toString(16).padStart(2, '0')).join('');
  } catch {
    return null;
  } finally {
    try { root?.wipePrivateData?.(); } catch { /* best-effort */ }
    if (seed) seed.fill(0);
  }
}

/** Sign an API-request preimage with the m/83'/2'/0' key → 64-byte compact-hex ECDSA sig (RFC6979 low-S), matching
 *  the proxy's node:crypto ieee-p1363 verify. Returns null on an invalid mnemonic. Wipes the private key. */
export async function signApiRequest(mnemonic: string, preimage: string): Promise<string | null> {
  const priv = deriveApiAuthPriv(mnemonic);
  if (!priv) return null;
  try {
    const sig = await secp256k1.signAsync(sha256(new TextEncoder().encode(preimage)), priv, { lowS: true });
    return _toHex(sig.toCompactRawBytes());
  } catch {
    return null;
  } finally {
    priv.fill(0);
  }
}

/** A fresh, public, non-zero 16-byte swap nonce — CSPRNG only, generated fresh on every POST/retry. */
export function generateSwapNonce(): Uint8Array {
  const n = new Uint8Array(SWAP_NONCE_BYTES);
  do { crypto.getRandomValues(n); } while (n.every((b) => b === 0)); // never all-zero
  return n;
}
