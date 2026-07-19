import { HDKey } from '@scure/bip32';
import { validateMnemonic, mnemonicToSeedSync } from '@scure/bip39';
import { wordlist } from '@scure/bip39/wordlists/english';
import { hmac } from '@noble/hashes/hmac';
import { sha256 } from '@noble/hashes/sha256';
import * as secp256k1 from '@noble/secp256k1';

// src/seed-secret.ts
var _fromHex = (s) => Uint8Array.from((s.match(/../g) ?? []).map((h) => parseInt(h, 16)));
var _toHex = (u) => Array.from(u).map((b) => b.toString(16).padStart(2, "0")).join("");
var HARDENED = 2147483648;
var SWAP_SECRET_PATH = [HARDENED + 83, HARDENED + 0, HARDENED + 0];
var MAKER_ID_PATH = [HARDENED + 83, HARDENED + 1, HARDENED + 0];
var SECRET_DOMAIN = new TextEncoder().encode("BCH2SWAP/secret/v1");
var MAKER_SIG_DOMAIN = new TextEncoder().encode("BCH2SWAP/maker/v1");
var SWAP_SECRET_SCHEME = "hmac-v1";
var SWAP_NONCE_BYTES = 16;
var MAKER_SIG_SCHEME = "ecdsa-v1";
function wipeNode(n) {
  try {
    n?.wipePrivateData?.();
  } catch {
  }
  try {
    if (n && "chainCode" in n && n.chainCode instanceof Uint8Array) n.chainCode.fill(0);
  } catch {
  }
}
function deriveSwapSecret(mnemonic, nonce) {
  const kss = deriveSwapKss(mnemonic);
  if (!kss) return null;
  try {
    return swapSecretFromKss(kss, nonce);
  } finally {
    kss.fill(0);
  }
}
function deriveSwapKss(mnemonic) {
  const normalized = mnemonic.trim().toLowerCase();
  if (!validateMnemonic(normalized, wordlist)) return null;
  let seed;
  let root = null;
  let kss = null;
  try {
    seed = mnemonicToSeedSync(normalized);
    root = HDKey.fromMasterSeed(seed);
    let l1 = null, l2 = null, l3 = null;
    try {
      l1 = root.deriveChild(SWAP_SECRET_PATH[0]);
      l2 = l1.deriveChild(SWAP_SECRET_PATH[1]);
      l3 = l2.deriveChild(SWAP_SECRET_PATH[2]);
      if (l3.privateKey) kss = new Uint8Array(l3.privateKey);
    } finally {
      wipeNode(l1);
      wipeNode(l2);
      wipeNode(l3);
    }
    return kss;
  } catch {
    if (kss) kss.fill(0);
    return null;
  } finally {
    try {
      root?.wipePrivateData?.();
    } catch {
    }
    if (seed) seed.fill(0);
  }
}
function swapSecretFromKss(kss, nonce) {
  if (!(kss instanceof Uint8Array) || kss.length !== 32) return null;
  if (!(nonce instanceof Uint8Array) || nonce.length !== SWAP_NONCE_BYTES) return null;
  const msg = new Uint8Array(SECRET_DOMAIN.length + nonce.length);
  msg.set(SECRET_DOMAIN, 0);
  msg.set(nonce, SECRET_DOMAIN.length);
  return hmac(sha256, kss, msg);
}
function deriveMakerIdPub(mnemonic) {
  const normalized = mnemonic.trim().toLowerCase();
  if (!validateMnemonic(normalized, wordlist)) return null;
  let seed;
  let root = null;
  try {
    seed = mnemonicToSeedSync(normalized);
    root = HDKey.fromMasterSeed(seed);
    let l1 = null, l2 = null, l3 = null;
    let pub;
    try {
      l1 = root.deriveChild(MAKER_ID_PATH[0]);
      l2 = l1.deriveChild(MAKER_ID_PATH[1]);
      l3 = l2.deriveChild(MAKER_ID_PATH[2]);
      if (l3.publicKey) pub = new Uint8Array(l3.publicKey);
    } finally {
      wipeNode(l1);
      wipeNode(l2);
      wipeNode(l3);
    }
    if (!pub) return null;
    return Array.from(pub).map((b) => b.toString(16).padStart(2, "0")).join("");
  } catch {
    return null;
  } finally {
    try {
      root?.wipePrivateData?.();
    } catch {
    }
    if (seed) seed.fill(0);
  }
}
function deriveMakerIdPriv(mnemonic) {
  const normalized = mnemonic.trim().toLowerCase();
  if (!validateMnemonic(normalized, wordlist)) return null;
  let seed;
  let root = null;
  let priv = null;
  try {
    seed = mnemonicToSeedSync(normalized);
    root = HDKey.fromMasterSeed(seed);
    let l1 = null, l2 = null, l3 = null;
    try {
      l1 = root.deriveChild(MAKER_ID_PATH[0]);
      l2 = l1.deriveChild(MAKER_ID_PATH[1]);
      l3 = l2.deriveChild(MAKER_ID_PATH[2]);
      if (l3.privateKey) priv = new Uint8Array(l3.privateKey);
    } finally {
      wipeNode(l1);
      wipeNode(l2);
      wipeNode(l3);
    }
    return priv;
  } catch {
    if (priv) priv.fill(0);
    return null;
  } finally {
    try {
      root?.wipePrivateData?.();
    } catch {
    }
    if (seed) seed.fill(0);
  }
}
function makerSigMsgHash(secretHashHex) {
  const h = secretHashHex.toLowerCase().replace(/^0x/, "");
  if (!/^[0-9a-f]{64}$/.test(h)) return null;
  const sh = _fromHex(h);
  const msg = new Uint8Array(MAKER_SIG_DOMAIN.length + sh.length);
  msg.set(MAKER_SIG_DOMAIN, 0);
  msg.set(sh, MAKER_SIG_DOMAIN.length);
  return sha256(msg);
}
async function signMakerIdentity(mnemonic, secretHashHex) {
  const msgHash = makerSigMsgHash(secretHashHex);
  if (!msgHash) return null;
  const priv = deriveMakerIdPriv(mnemonic);
  if (!priv) return null;
  try {
    const sig = await secp256k1.signAsync(msgHash, priv, { lowS: true });
    return _toHex(sig.toCompactRawBytes());
  } catch {
    return null;
  } finally {
    priv.fill(0);
  }
}
function verifyMakerIdentity(makerIdPubHex, secretHashHex, sigHex) {
  try {
    const pub = makerIdPubHex.toLowerCase().replace(/^0x/, "");
    const sig = sigHex.toLowerCase().replace(/^0x/, "");
    if (!/^0[23][0-9a-f]{64}$/.test(pub)) return false;
    if (!/^[0-9a-f]{128}$/.test(sig)) return false;
    const msgHash = makerSigMsgHash(secretHashHex);
    if (!msgHash) return false;
    return secp256k1.verify(_fromHex(sig), msgHash, _fromHex(pub));
  } catch {
    return false;
  }
}
var API_AUTH_PATH = [HARDENED + 83, HARDENED + 2, HARDENED + 0];
var API_AUTH_DOMAIN = "BCH2SWAP/api/v1";
var API_AUTH_SCHEME = "ecdsa-v1";
function buildApiAuthPreimage(p) {
  return [API_AUTH_DOMAIN, p.method.toUpperCase(), p.path, p.id, String(p.timestamp)].join("\n");
}
function deriveApiAuthPriv(mnemonic) {
  const normalized = mnemonic.trim().toLowerCase();
  if (!validateMnemonic(normalized, wordlist)) return null;
  let seed;
  let root = null;
  let priv = null;
  try {
    seed = mnemonicToSeedSync(normalized);
    root = HDKey.fromMasterSeed(seed);
    let l1 = null, l2 = null, l3 = null;
    try {
      l1 = root.deriveChild(API_AUTH_PATH[0]);
      l2 = l1.deriveChild(API_AUTH_PATH[1]);
      l3 = l2.deriveChild(API_AUTH_PATH[2]);
      if (l3.privateKey) priv = new Uint8Array(l3.privateKey);
    } finally {
      wipeNode(l1);
      wipeNode(l2);
      wipeNode(l3);
    }
    return priv;
  } catch {
    if (priv) priv.fill(0);
    return null;
  } finally {
    try {
      root?.wipePrivateData?.();
    } catch {
    }
    if (seed) seed.fill(0);
  }
}
function deriveApiAuthPub(mnemonic) {
  const normalized = mnemonic.trim().toLowerCase();
  if (!validateMnemonic(normalized, wordlist)) return null;
  let seed;
  let root = null;
  try {
    seed = mnemonicToSeedSync(normalized);
    root = HDKey.fromMasterSeed(seed);
    let l1 = null, l2 = null, l3 = null;
    let pub;
    try {
      l1 = root.deriveChild(API_AUTH_PATH[0]);
      l2 = l1.deriveChild(API_AUTH_PATH[1]);
      l3 = l2.deriveChild(API_AUTH_PATH[2]);
      if (l3.publicKey) pub = new Uint8Array(l3.publicKey);
    } finally {
      wipeNode(l1);
      wipeNode(l2);
      wipeNode(l3);
    }
    if (!pub) return null;
    return Array.from(pub).map((b) => b.toString(16).padStart(2, "0")).join("");
  } catch {
    return null;
  } finally {
    try {
      root?.wipePrivateData?.();
    } catch {
    }
    if (seed) seed.fill(0);
  }
}
async function signApiRequest(mnemonic, preimage) {
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
function generateSwapNonce() {
  const n = new Uint8Array(SWAP_NONCE_BYTES);
  do {
    crypto.getRandomValues(n);
  } while (n.every((b) => b === 0));
  return n;
}

export { API_AUTH_SCHEME, MAKER_SIG_SCHEME, SWAP_NONCE_BYTES, SWAP_SECRET_SCHEME, buildApiAuthPreimage, deriveApiAuthPub, deriveMakerIdPub, deriveSwapKss, deriveSwapSecret, generateSwapNonce, signApiRequest, signMakerIdentity, swapSecretFromKss, verifyMakerIdentity };
