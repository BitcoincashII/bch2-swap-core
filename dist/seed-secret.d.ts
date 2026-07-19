/** Per-offer scheme tag stored on the box (`proposal.secretScheme`). An offer's OWN tag — never the live
 *  /health flag — decides how its secret is recovered, so flipping the flag can't strand a posted offer. */
declare const SWAP_SECRET_SCHEME = "hmac-v1";
declare const SWAP_NONCE_BYTES = 16;
declare const MAKER_SIG_SCHEME = "ecdsa-v1";
/**
 * Derive the 32-byte HTLC preimage `S = HMAC-SHA256(K_ss, DOMAIN || nonce)`, where
 * `K_ss` = seed → m/83'/0'/0' (all levels hardened, so a K_ss leak exposes neither the seed nor any
 * spending key). INITIATOR-side only — the responder learns S on-chain. Deterministic: the same
 * (mnemonic, nonce) always yields the same S, so it need never be stored and is recoverable on any
 * device. Returns null on an invalid mnemonic or wrong-length nonce. Wipes all intermediate material.
 */
declare function deriveSwapSecret(mnemonic: string, nonce: Uint8Array): Uint8Array | null;
/**
 * Derive K_ss = seed → m/83'/0'/0' (the 32-byte swap-secret key). Cache this at unlock beside the other
 * session keys so the preimage can be re-derived at fund/claim time (where the mnemonic has been wiped).
 * The CALLER owns the returned buffer and MUST zero it on lock. Wipes all intermediate material + the seed.
 */
declare function deriveSwapKss(mnemonic: string): Uint8Array | null;
/** S = HMAC-SHA256(K_ss, DOMAIN || nonce) — the 32-byte HTLC preimage. Pure function of the cached key +
 *  the public nonce; does NOT wipe K_ss (the caller owns it). Returns null on a wrong-length nonce/key. */
declare function swapSecretFromKss(kss: Uint8Array, nonce: Uint8Array): Uint8Array | null;
/**
 * Derive the maker-identity public key (compressed, 33B hex) from m/83'/1'/0'. Public output only —
 * used to authenticate own-offer authorship (Phase 2). Cache this ONE public value at unlock; verifying
 * an offer's makerSig needs only this pubkey, never the seed. Returns null on an invalid mnemonic.
 */
declare function deriveMakerIdPub(mnemonic: string): string | null;
/** Sign own-offer authorship: deterministic ECDSA over makerSigMsgHash(secretHash) with the m/83'/1'/0' key.
 *  Returns a 64-byte compact-hex signature, or null on bad input. Wipes the private key. PUBLIC output. */
declare function signMakerIdentity(mnemonic: string, secretHashHex: string): Promise<string | null>;
/** Verify own-offer authorship — PUBLIC-KEY ONLY (no seed), so it works with the wallet locked. Returns false on
 *  any malformed input or verification failure (never throws). A false here means "not provably mine" => show it. */
declare function verifyMakerIdentity(makerIdPubHex: string, secretHashHex: string, sigHex: string): boolean;
declare const API_AUTH_SCHEME = "ecdsa-v1";
/** The canonical signed preimage. Binds the sig to the endpoint (method+path), the order id, and a timestamp so a
 *  captured signature can't be replayed onto a different order or a different action, and expires (proxy enforces a
 *  ~120s window). MUST be byte-identical on client and proxy. (targetStatus is intentionally NOT bound — box status
 *  is not a fund authority, and binding it would require parsing the body before auth; the role→status allowlist
 *  still constrains what each party can set.) */
declare function buildApiAuthPreimage(p: {
    method: string;
    path: string;
    id: string;
    timestamp: number;
}): string;
/** The maker's API-auth PUBLIC key (compressed, 33B hex) from m/83'/2'/0'. Attached to the offer / take (public),
 *  so the proxy knows which key must sign this order's status changes. Cached at unlock like the maker-id pubkey. */
declare function deriveApiAuthPub(mnemonic: string): string | null;
/** Sign an API-request preimage with the m/83'/2'/0' key → 64-byte compact-hex ECDSA sig (RFC6979 low-S), matching
 *  the proxy's node:crypto ieee-p1363 verify. Returns null on an invalid mnemonic. Wipes the private key. */
declare function signApiRequest(mnemonic: string, preimage: string): Promise<string | null>;
/** A fresh, public, non-zero 16-byte swap nonce — CSPRNG only, generated fresh on every POST/retry. */
declare function generateSwapNonce(): Uint8Array;

export { API_AUTH_SCHEME, MAKER_SIG_SCHEME, SWAP_NONCE_BYTES, SWAP_SECRET_SCHEME, buildApiAuthPreimage, deriveApiAuthPub, deriveMakerIdPub, deriveSwapKss, deriveSwapSecret, generateSwapNonce, signApiRequest, signMakerIdentity, swapSecretFromKss, verifyMakerIdentity };
