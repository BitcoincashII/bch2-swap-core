import { sha256 } from '@noble/hashes/sha256';
import { ripemd160 } from '@noble/hashes/ripemd160';
import * as secp256k12 from '@noble/secp256k1';

// src/swap-engine/state.ts
var State = /* @__PURE__ */ ((State2) => {
  State2[State2["Created"] = 0] = "Created";
  State2[State2["Prepared"] = 1] = "Prepared";
  State2[State2["Funded"] = 2] = "Funded";
  State2[State2["CounterpartyFunded"] = 3] = "CounterpartyFunded";
  State2[State2["Verified"] = 4] = "Verified";
  State2[State2["Revealed"] = 5] = "Revealed";
  State2[State2["Complete"] = 6] = "Complete";
  State2[State2["TimedOut"] = 7] = "TimedOut";
  State2[State2["Refunding"] = 8] = "Refunding";
  State2[State2["Refunded"] = 9] = "Refunded";
  State2[State2["Failed"] = 10] = "Failed";
  return State2;
})(State || {});
var Role = /* @__PURE__ */ ((Role2) => {
  Role2[Role2["Initiator"] = 0] = "Initiator";
  Role2[Role2["Responder"] = 1] = "Responder";
  return Role2;
})(Role || {});
function stateToString(s) {
  return State[s] ?? `State(${s})`;
}
function roleToString(r) {
  return Role[r] ?? `Role(${r})`;
}
function isTerminal(s) {
  return s === 6 /* Complete */ || s === 9 /* Refunded */ || s === 10 /* Failed */;
}
var ErrVerificationRequired = class extends Error {
  constructor(msg) {
    super(msg ?? "swapengine: verification gate must pass before this action");
    this.name = "ErrVerificationRequired";
  }
};
var ErrWrongState = class extends Error {
  constructor(msg) {
    super(msg ?? "swapengine: action not valid in current state");
    this.name = "ErrWrongState";
  }
};
var ErrWrongRole = class extends Error {
  constructor(msg) {
    super(msg ?? "swapengine: action not valid for this role");
    this.name = "ErrWrongRole";
  }
};
var ErrNoSecret = class extends Error {
  constructor(msg) {
    super(msg ?? "swapengine: secret not available");
    this.name = "ErrNoSecret";
  }
};
var ErrHashMismatch = class extends Error {
  constructor(msg) {
    super(msg ?? "swapengine: SHA256(secret) does not match agreed hashLock");
    this.name = "ErrHashMismatch";
  }
};
var ErrOutputNotFound = class extends Error {
  constructor(msg) {
    super(msg ?? "swapengine: P2SH output not found");
    this.name = "ErrOutputNotFound";
  }
};
var ErrTimelockOrdering = class extends Error {
  constructor(msg) {
    super(msg ?? "swapengine: timelock ordering violated: initiator CSV must be < responder CSV");
    this.name = "ErrTimelockOrdering";
  }
};
var ErrInsufficientConfirmations = class extends Error {
  constructor(msg) {
    super(msg ?? "swapengine: counterparty HTLC has insufficient confirmations");
    this.name = "ErrInsufficientConfirmations";
  }
};
var ErrAmountTooLow = class extends Error {
  constructor(msg) {
    super(msg ?? "swapengine: counterparty HTLC amount is below agreed minimum");
    this.name = "ErrAmountTooLow";
  }
};
var validTransitions = {
  [0 /* Initiator */]: {
    [0 /* Created */]: [1 /* Prepared */, 10 /* Failed */],
    [1 /* Prepared */]: [3 /* CounterpartyFunded */, 10 /* Failed */],
    [3 /* CounterpartyFunded */]: [4 /* Verified */, 10 /* Failed */],
    [4 /* Verified */]: [2 /* Funded */, 10 /* Failed */],
    [2 /* Funded */]: [6 /* Complete */, 7 /* TimedOut */, 10 /* Failed */],
    [7 /* TimedOut */]: [8 /* Refunding */, 10 /* Failed */],
    [8 /* Refunding */]: [9 /* Refunded */, 10 /* Failed */]
  },
  [1 /* Responder */]: {
    [0 /* Created */]: [1 /* Prepared */, 10 /* Failed */],
    [1 /* Prepared */]: [2 /* Funded */, 10 /* Failed */],
    [2 /* Funded */]: [3 /* CounterpartyFunded */, 7 /* TimedOut */, 10 /* Failed */],
    [3 /* CounterpartyFunded */]: [4 /* Verified */, 10 /* Failed */],
    [4 /* Verified */]: [5 /* Revealed */, 10 /* Failed */],
    [5 /* Revealed */]: [6 /* Complete */, 10 /* Failed */],
    [7 /* TimedOut */]: [8 /* Refunding */, 10 /* Failed */],
    [8 /* Refunding */]: [9 /* Refunded */, 10 /* Failed */]
  }
};
function isValidTransition(role, from, to) {
  const allowed = validTransitions[role][from];
  return allowed !== void 0 && allowed.includes(to);
}
function validateParams(p, role, requireCounterPubKey = true) {
  if (requireCounterPubKey && p.counterPubKey.length === 0) {
    throw new Error("swapengine: counterPubKey is required");
  }
  if (role === 0 /* Initiator */) {
    if (p.ourCSVNSequence >= p.counterCSVNSequence) {
      throw new ErrTimelockOrdering(
        `swapengine: timelock ordering violated: initiator nSequence ${p.ourCSVNSequence} must be < responder nSequence ${p.counterCSVNSequence}`
      );
    }
  }
}
function validateTimelockOrdering(p, role) {
  validateParams(p, role, false);
}
function swapIDFromHashLock(hashLock) {
  const h = sha256(hashLock);
  return Array.from(h.slice(0, 16)).map((b) => b.toString(16).padStart(2, "0")).join("");
}

// src/swap-engine/chains.ts
function toHex(b) {
  return Array.from(b).map((v) => v.toString(16).padStart(2, "0")).join("");
}
var MockUTXOChain = class {
  constructor() {
    this.outputs = /* @__PURE__ */ new Map();
    this.scanError = null;
  }
  /** Add a P2SH output keyed by txid + script hash. */
  addOutput(txid, scriptHash, satoshis, confs) {
    this.outputs.set(`${txid}|${toHex(scriptHash)}`, { satoshis, confs });
  }
  /** Update the confirmation count on an existing output. */
  setConfirmations(txid, scriptHash, confs) {
    const key = `${txid}|${toHex(scriptHash)}`;
    const out = this.outputs.get(key);
    if (!out) throw new Error(`MockUTXOChain: no output for key ${key}`);
    this.outputs.set(key, { ...out, confs });
  }
  /** Force scanForHTLC to return an error (simulates a probe failure). */
  setScanError(err) {
    this.scanError = err;
  }
  async getP2SHOutput(txid, scriptHash) {
    const key = `${txid}|${toHex(scriptHash)}`;
    const out = this.outputs.get(key);
    if (!out) throw new ErrOutputNotFound(`txid=${txid} scriptHash=${toHex(scriptHash)}`);
    return { satoshis: out.satoshis, confs: out.confs };
  }
  async scanForHTLC(scriptHash, expectedSat) {
    if (this.scanError) throw this.scanError;
    const shHex = toHex(scriptHash);
    for (const [key, out] of this.outputs.entries()) {
      const [txid, sh] = key.split("|");
      if (sh === shHex && out.satoshis === expectedSat) return txid;
    }
    return "";
  }
};
function hash160(data) {
  return ripemd160(sha256(data));
}
function buildRedeemScript(buyerPubKey, sellerPubKey, csvNSequence, hashLock) {
  return concat([
    new Uint8Array([99]),
    // OP_IF
    new Uint8Array([168]),
    // OP_SHA256
    pushData(hashLock),
    // push 32-byte hashLock
    new Uint8Array([136]),
    // OP_EQUALVERIFY
    pushData(buyerPubKey),
    // push buyerPubKey (33 bytes)
    new Uint8Array([172]),
    // OP_CHECKSIG
    new Uint8Array([103]),
    // OP_ELSE
    encodeCSV(csvNSequence),
    // minimal CSV push
    new Uint8Array([178]),
    // OP_CSV
    new Uint8Array([117]),
    // OP_DROP
    pushData(sellerPubKey),
    // push sellerPubKey (33 bytes)
    new Uint8Array([172]),
    // OP_CHECKSIG
    new Uint8Array([104])
    // OP_ENDIF
  ]);
}
function pushData(data) {
  const n = data.length;
  if (n === 0) return new Uint8Array([0]);
  if (n <= 75) return concat([new Uint8Array([n]), data]);
  if (n <= 255) return concat([new Uint8Array([76, n]), data]);
  if (n <= 65535) return concat([new Uint8Array([77, n & 255, n >> 8 & 255]), data]);
  return concat([new Uint8Array([78, n & 255, n >> 8 & 255, n >> 16 & 255, n >> 24 & 255]), data]);
}
function encodeCSV(nSequence) {
  const n = nSequence >>> 0;
  if (n === 0) return new Uint8Array([0]);
  if (n <= 16) return new Uint8Array([80 + n]);
  return pushScriptInt(n);
}
function pushScriptInt(v) {
  if (v === 0) return new Uint8Array([0]);
  const bytes = [];
  let rem = v >>> 0;
  while (rem > 0) {
    bytes.push(rem & 255);
    rem = rem >>> 8;
  }
  if (bytes[bytes.length - 1] & 128) bytes.push(0);
  return pushData(new Uint8Array(bytes));
}
function concat(parts) {
  const total = parts.reduce((s, p) => s + p.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

// src/swap-engine/verify.ts
var VerificationGate = class {
  constructor(params, role, counterFundTxid, counterChain) {
    this.params = params;
    this.role = role;
    this.counterFundTxid = counterFundTxid;
    this.counterChain = counterChain;
  }
  /**
   * Runs all five checks in order:
   *   1. Timelock ordering
   *   2. Build expected P2SH hash from agreed params (H-derived, not counterparty-supplied)
   *   3. Query chain for the output — throws ErrOutputNotFound if absent or wrong structure
   *   4. Confirmation depth — throws ErrInsufficientConfirmations
   *   5. Amount — throws ErrAmountTooLow
   */
  async run() {
    validateTimelockOrdering(this.params, this.role);
    const redeemScript = buildRedeemScript(
      this.params.ourPubKey,
      this.params.counterPubKey,
      this.params.counterCSVNSequence,
      this.params.hashLock
    );
    const expectedHash = hash160(redeemScript);
    const { satoshis, confs } = await this.counterChain.getP2SHOutput(
      this.counterFundTxid,
      expectedHash
    );
    const minConfs = this.params.minConfirmations;
    if (confs < minConfs) {
      throw new ErrInsufficientConfirmations(
        `swapengine: counterparty HTLC has ${confs} confirmations, need ${minConfs}`
      );
    }
    if (satoshis < this.params.counterAmountSat) {
      throw new ErrAmountTooLow(
        `swapengine: counterparty HTLC has ${satoshis} sat, expected >= ${this.params.counterAmountSat}`
      );
    }
  }
};

// src/swap-engine/persist.ts
var LocalSwapStorage = class {
  constructor() {
    this.prefix = "bch2swap:";
  }
  save(swapID, record) {
    localStorage.setItem(this.prefix + swapID, JSON.stringify(record));
  }
  load(swapID) {
    const raw = localStorage.getItem(this.prefix + swapID);
    if (raw == null) return null;
    return parseRecord(raw);
  }
  loadAll() {
    const records = [];
    for (let i = 0; i < localStorage.length; i++) {
      const key = localStorage.key(i);
      if (!key?.startsWith(this.prefix)) continue;
      const raw = localStorage.getItem(key);
      if (!raw) continue;
      const rec = parseRecord(raw);
      if (rec) records.push(rec);
    }
    return records;
  }
  delete(swapID) {
    localStorage.removeItem(this.prefix + swapID);
  }
};
var MemorySwapStorage = class {
  constructor() {
    this.store = /* @__PURE__ */ new Map();
  }
  save(swapID, record) {
    this.store.set(swapID, JSON.parse(JSON.stringify(record)));
  }
  load(swapID) {
    const rec = this.store.get(swapID);
    if (!rec) return null;
    return JSON.parse(JSON.stringify(rec));
  }
  loadAll() {
    return Array.from(this.store.values()).map((r) => JSON.parse(JSON.stringify(r))).filter(isValidRecord);
  }
  delete(swapID) {
    this.store.delete(swapID);
  }
  /** Expose underlying map size for test assertions. */
  size() {
    return this.store.size;
  }
};
function loadSwapRecords(storage) {
  return storage.loadAll();
}
function deleteSwapRecord(storage, swapID) {
  storage.delete(swapID);
}
function parseRecord(raw) {
  try {
    const rec = JSON.parse(raw);
    if (!isValidRecord(rec)) return null;
    return rec;
  } catch {
    return null;
  }
}
function isValidRecord(r) {
  return typeof r.swapID === "string" && r.swapID !== "" && typeof r.ourPrivKey === "string" && r.ourPrivKey !== "" && typeof r.ourPubKey === "string" && r.ourPubKey !== "" && typeof r.hashLock === "string" && r.hashLock !== "" && typeof r.role === "number" && typeof r.state === "number";
}

// src/swap-engine/recover.ts
var RecoveryAction = /* @__PURE__ */ ((RecoveryAction2) => {
  RecoveryAction2[RecoveryAction2["None"] = 0] = "None";
  RecoveryAction2[RecoveryAction2["WaitForCounterparty"] = 1] = "WaitForCounterparty";
  RecoveryAction2[RecoveryAction2["VerifyAndFund"] = 2] = "VerifyAndFund";
  RecoveryAction2[RecoveryAction2["ClaimOrTimeout"] = 3] = "ClaimOrTimeout";
  RecoveryAction2[RecoveryAction2["Refund"] = 4] = "Refund";
  RecoveryAction2[RecoveryAction2["ConfirmRefund"] = 5] = "ConfirmRefund";
  return RecoveryAction2;
})(RecoveryAction || {});
function newFromRecord(rec, chain, storage, engineFactory) {
  return engineFactory(rec, chain, storage);
}
function determineRecoveryAction(role, state) {
  if (isTerminal(state)) return 0 /* None */;
  if (role === 0 /* Initiator */) {
    switch (state) {
      case 0 /* Created */:
      case 1 /* Prepared */:
        return 1 /* WaitForCounterparty */;
      case 3 /* CounterpartyFunded */:
        return 2 /* VerifyAndFund */;
      case 4 /* Verified */:
        return 2 /* VerifyAndFund */;
      case 2 /* Funded */:
        return 3 /* ClaimOrTimeout */;
      case 7 /* TimedOut */:
      case 8 /* Refunding */:
        return 4 /* Refund */;
      default:
        return 0 /* None */;
    }
  } else {
    switch (state) {
      case 0 /* Created */:
      case 1 /* Prepared */:
        return 1 /* WaitForCounterparty */;
      case 2 /* Funded */:
        return 1 /* WaitForCounterparty */;
      case 3 /* CounterpartyFunded */:
        return 2 /* VerifyAndFund */;
      case 4 /* Verified */:
        return 3 /* ClaimOrTimeout */;
      case 5 /* Revealed */:
        return 3 /* ClaimOrTimeout */;
      case 7 /* TimedOut */:
      case 8 /* Refunding */:
        return 4 /* Refund */;
      default:
        return 0 /* None */;
    }
  }
}
async function recoverAndResume(storage, chainFactory, resumeFn, engineFactory) {
  const records = storage.loadAll();
  const errors = [];
  for (const rec of records) {
    if (isTerminal(rec.state)) continue;
    const chain = chainFactory(rec.role, rec.swapID);
    if (!chain) continue;
    const engine = engineFactory(rec, chain, storage);
    const action = determineRecoveryAction(rec.role, rec.state);
    try {
      await resumeFn(engine, action);
    } catch (err) {
      errors.push(err instanceof Error ? err : new Error(String(err)));
    }
  }
  return errors;
}
function toHex2(b) {
  return Array.from(b).map((v) => v.toString(16).padStart(2, "0")).join("");
}
function fromHex(h) {
  if (h.length % 2 !== 0) throw new Error("fromHex: odd-length hex string");
  const buf = new Uint8Array(h.length / 2);
  for (let i = 0; i < buf.length; i++) {
    buf[i] = parseInt(h.slice(i * 2, i * 2 + 2), 16);
  }
  return buf;
}
function generateKeyPair() {
  while (true) {
    const privKey = new Uint8Array(32);
    crypto.getRandomValues(privKey);
    try {
      const pubKey = secp256k12.getPublicKey(privKey, true);
      return { privKey, pubKey };
    } catch {
    }
  }
}
var Engine = class _Engine {
  constructor(role, params, ourChain, storage) {
    this.role = role;
    this.params = { ...params };
    this.state = 0 /* Created */;
    this.swapID = "";
    this.ourPrivKey = new Uint8Array(0);
    this.secret = null;
    this.counterFundTxid = "";
    this.ourFundTxid = "";
    this.htlcScriptHash = new Uint8Array(20);
    this.verified = false;
    this.ourChain = ourChain ?? null;
    this.storage = storage ?? null;
  }
  // ── Getters ───────────────────────────────────────────────────────────────
  getState() {
    return this.state;
  }
  getRole() {
    return this.role;
  }
  getSwapID() {
    return this.swapID;
  }
  getOurFundTxid() {
    return this.ourFundTxid;
  }
  getHashLock() {
    return this.params.hashLock.slice();
  }
  getOurPubKey() {
    return this.params.ourPubKey.slice();
  }
  getHTLCScriptHash() {
    return this.htlcScriptHash.slice();
  }
  /**
   * Returns the private key. Throws ErrNoSecret if Prepare has not been called.
   * Caller receives a copy — the engine's copy is retained.
   */
  getPrivKey() {
    if (this.ourPrivKey.length === 0) throw new ErrNoSecret("swapengine: getPrivKey: prepare not called");
    return this.ourPrivKey.slice();
  }
  /**
   * Returns the revealed preimage. Throws ErrNoSecret if not yet known.
   */
  getSecret() {
    if (!this.secret) throw new ErrNoSecret("swapengine: secret not available");
    return this.secret.slice();
  }
  // ── Setters ───────────────────────────────────────────────────────────────
  setStorage(s) {
    this.storage = s;
  }
  setOurChain(c) {
    this.ourChain = c;
  }
  setCounterPubKey(pub) {
    this.params = { ...this.params, counterPubKey: pub };
  }
  // ── Core lifecycle ────────────────────────────────────────────────────────
  /**
   * Transitions Created → Prepared.
   * Generates an ephemeral secp256k1 key pair and (for initiator) a random
   * hashLock. Persists the new state.
   *
   * Returns a SwapProposal (initiator) or SwapResponse (responder) for the
   * peer. Caller is responsible for transmitting it.
   */
  async prepare() {
    this.transition(1 /* Prepared */);
    if (this.params.ourPubKey.length === 0) {
      const { privKey, pubKey } = generateKeyPair();
      this.ourPrivKey = privKey;
      this.params = { ...this.params, ourPubKey: pubKey };
    }
    if (this.role === 0 /* Initiator */) {
      const secret = new Uint8Array(32);
      crypto.getRandomValues(secret);
      this.secret = secret;
      const hashLock = sha256(secret);
      this.params = { ...this.params, hashLock };
      this.swapID = swapIDFromHashLock(hashLock);
      await this.persist();
      return {
        swapID: this.swapID,
        hashLock: toHex2(hashLock),
        initiatorPubKey: toHex2(this.params.ourPubKey),
        initiatorCSV: this.params.ourCSVNSequence,
        initiatorAmountSat: this.params.ourAmountSat,
        responderAmountSat: this.params.counterAmountSat,
        minConfirmations: this.params.minConfirmations,
        feeSatoshis: this.params.feeSatoshis
      };
    } else {
      this.swapID = swapIDFromHashLock(this.params.hashLock);
      await this.persist();
      return {
        swapID: this.swapID,
        responderPubKey: toHex2(this.params.ourPubKey),
        responderCSV: this.params.ourCSVNSequence
      };
    }
  }
  /**
   * Records that the counterparty has funded their HTLC.
   * Transitions Prepared → CounterpartyFunded (initiator) or
   *             Funded   → CounterpartyFunded (responder).
   */
  async notifyCounterpartyFunded(counterFundTxid) {
    if (this.role === 0 /* Initiator */ && this.state !== 1 /* Prepared */ || this.role === 1 /* Responder */ && this.state !== 2 /* Funded */) {
      throw new ErrWrongState(
        `swapengine: notifyCounterpartyFunded called in state ${State[this.state]}`
      );
    }
    this.counterFundTxid = counterFundTxid;
    this.transition(3 /* CounterpartyFunded */);
    await this.persist();
  }
  /**
   * Runs the verification gate against the counterparty's HTLC.
   * Transitions CounterpartyFunded → Verified.
   *
   * This is the unskippable gate before Fund().
   * Passing here is the only way to reach StateVerified.
   */
  async verify(counterChain) {
    if (this.state !== 3 /* CounterpartyFunded */) {
      throw new ErrWrongState(
        `swapengine: verify requires StateCounterpartyFunded, have ${State[this.state]}`
      );
    }
    if (this.counterFundTxid === "") {
      throw new ErrWrongState("swapengine: verify: counterFundTxid not set");
    }
    const gate = new VerificationGate(
      this.params,
      this.role,
      this.counterFundTxid,
      counterChain
    );
    await gate.run();
    this.verified = true;
    this.transition(4 /* Verified */);
    await this.persist();
  }
  /**
   * Funds our own HTLC.
   *
   * Initiator: requires StateVerified (gate is unskippable — no direct path from
   *            StateCounterpartyFunded or earlier).
   * Responder: requires StatePrepared.
   *
   * Double-fund probe (SEP-3): if ourChain is set, scanForHTLC is called first:
   *   - probe error   → return error; do NOT broadcast (safe = blocked)
   *   - HTLC found    → call recordFunded (idempotent); do NOT re-broadcast
   *   - HTLC absent   → call fundFn once, then transition to StateFunded
   *
   * scanForHTLC is passed ourAmountSat so the probe matches THIS swap's UTXO
   * and ignores any concurrent swap that shares the same P2SH script.
   *
   * @param htlcScriptHash 20-byte hash of our HTLC's redeemScript.
   * @param fundFn         Async callback that broadcasts the funding tx and
   *                       returns the txid.
   */
  async fund(htlcScriptHash, fundFn) {
    if (this.role === 0 /* Initiator */) {
      if (this.state !== 4 /* Verified */) {
        throw new ErrVerificationRequired(
          `swapengine: fund: initiator must pass verification gate first (state=${State[this.state]})`
        );
      }
    } else {
      if (this.state !== 1 /* Prepared */) {
        throw new ErrWrongState(
          `swapengine: fund: responder must be in StatePrepared (state=${State[this.state]})`
        );
      }
    }
    this.htlcScriptHash = htlcScriptHash;
    await this.persist();
    if (this.ourChain) {
      let existingTxid;
      try {
        existingTxid = await this.ourChain.scanForHTLC(htlcScriptHash, this.params.ourAmountSat);
      } catch (err) {
        return Promise.reject(err);
      }
      if (existingTxid !== "") {
        await this.recordFunded(existingTxid);
        return;
      }
    }
    const txid = await fundFn();
    await this.recordFunded(txid);
  }
  /**
   * Records a confirmed funding txid without re-broadcasting.
   * Idempotent: safe to call when the HTLC already exists on-chain.
   */
  async recordFunded(txid) {
    this.ourFundTxid = txid;
    this.transition(2 /* Funded */);
    await this.persist();
  }
  /**
   * Records the revealed preimage (responder learns it when initiator claims).
   * Validates SHA256(secret) == hashLock.
   * Responder transitions Verified → Revealed.
   */
  async setRevealedSecret(secret) {
    if (this.role !== 1 /* Responder */) {
      throw new ErrWrongRole("swapengine: setRevealedSecret is only valid for the responder role");
    }
    const h = sha256(secret);
    const hl = this.params.hashLock;
    if (h.length !== hl.length || !h.every((b, i) => b === hl[i])) {
      throw new ErrHashMismatch();
    }
    this.secret = secret;
    this.transition(5 /* Revealed */);
    await this.persist();
  }
  /** Marks the swap as Complete. */
  async claim() {
    this.transition(6 /* Complete */);
    await this.persist();
  }
  /** Initiator: claims the responder's HTLC using the preimage. */
  async claimAsInitiator() {
    if (this.role !== 0 /* Initiator */) {
      throw new ErrWrongRole("swapengine: claimAsInitiator is only valid for the initiator role");
    }
    if (!this.secret) throw new ErrNoSecret();
    await this.claim();
    return this.secret.slice();
  }
  /** Records that the counterparty's HTLC has timed out. */
  async timeout() {
    this.transition(7 /* TimedOut */);
    await this.persist();
  }
  /** Initiates the refund sequence. */
  async refund() {
    this.transition(8 /* Refunding */);
    await this.persist();
  }
  /** Confirms the refund transaction was mined. */
  async confirmRefund() {
    this.transition(9 /* Refunded */);
    await this.persist();
  }
  /**
   * Moves to StateFailed. No-op if already in a terminal state (mirrors Go
   * `Fail` which is a no-op on terminal states rather than returning an error).
   */
  async fail() {
    if (isTerminal(this.state)) return;
    this.transition(10 /* Failed */);
    await this.persist();
  }
  // ── Internal helpers ───────────────────────────────────────────────────────
  /**
   * Enforces the validTransitions table.
   * Throws ErrWrongState if the transition is not allowed.
   */
  transition(to) {
    if (!isValidTransition(this.role, this.state, to)) {
      throw new ErrWrongState(
        `swapengine: invalid transition ${State[this.state]} \u2192 ${State[to]} for role ${Role[this.role]}`
      );
    }
    this.state = to;
  }
  /**
   * Saves the current engine state to storage.
   * No-op when storage is null.
   */
  async persist() {
    if (!this.storage) return;
    const rec = {
      swapID: this.swapID,
      role: this.role,
      state: this.state,
      hashLock: toHex2(this.params.hashLock),
      ourPrivKey: toHex2(this.ourPrivKey),
      ourPubKey: toHex2(this.params.ourPubKey),
      counterPubKey: toHex2(this.params.counterPubKey),
      ourCSVNSequence: this.params.ourCSVNSequence,
      counterCSVNSequence: this.params.counterCSVNSequence,
      ourAmountSat: this.params.ourAmountSat,
      counterAmountSat: this.params.counterAmountSat,
      minConfirmations: this.params.minConfirmations,
      feeSatoshis: this.params.feeSatoshis,
      ourFundTxid: this.ourFundTxid,
      counterFundTxid: this.counterFundTxid,
      secret: this.secret ? toHex2(this.secret) : "",
      htlcScriptHash: toHex2(this.htlcScriptHash)
    };
    this.storage.save(this.swapID !== "" ? this.swapID : "_pending", rec);
  }
  // ── Record reconstruction (used by newFromRecord in recover.ts) ───────────
  static fromRecord(rec, chain, storage) {
    const hashLock = fromHex(rec.hashLock);
    const params = {
      hashLock,
      ourPubKey: fromHex(rec.ourPubKey),
      counterPubKey: rec.counterPubKey ? fromHex(rec.counterPubKey) : new Uint8Array(0),
      ourCSVNSequence: rec.ourCSVNSequence,
      counterCSVNSequence: rec.counterCSVNSequence,
      ourAmountSat: rec.ourAmountSat,
      counterAmountSat: rec.counterAmountSat,
      minConfirmations: rec.minConfirmations,
      feeSatoshis: rec.feeSatoshis
    };
    const e = new _Engine(rec.role, params, chain, storage);
    e.state = rec.state;
    e.swapID = rec.swapID;
    e.ourPrivKey = fromHex(rec.ourPrivKey);
    e.ourFundTxid = rec.ourFundTxid ?? "";
    e.counterFundTxid = rec.counterFundTxid ?? "";
    e.htlcScriptHash = rec.htlcScriptHash ? fromHex(rec.htlcScriptHash) : new Uint8Array(20);
    e.secret = rec.secret ? fromHex(rec.secret) : null;
    e.verified = rec.state >= 4 /* Verified */;
    return e;
  }
};

export { Engine, ErrAmountTooLow, ErrHashMismatch, ErrInsufficientConfirmations, ErrNoSecret, ErrOutputNotFound, ErrTimelockOrdering, ErrVerificationRequired, ErrWrongRole, ErrWrongState, LocalSwapStorage, MemorySwapStorage, MockUTXOChain, RecoveryAction, Role, State, VerificationGate, deleteSwapRecord, determineRecoveryAction, isTerminal, isValidTransition, loadSwapRecords, newFromRecord, recoverAndResume, roleToString, stateToString, swapIDFromHashLock, validTransitions, validateParams, validateTimelockOrdering };
