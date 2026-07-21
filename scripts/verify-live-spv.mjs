// LIVE real-data validation of the SDK's SPV/verification layer against BCH2 MAINNET.
//
// The unit tests exercise the SPV verifier over a SYNTHETIC easy-difficulty PoW chain. This script runs the SAME
// verifier (dist/spv-verifier.js) against the REAL BCH2 mainnet chain via a live ElectrumX server, proving:
//   1. the hardcoded checkpoint + ASERT params verify the REAL header chain (real difficulty, real ASERT retarget),
//   2. a REAL confirmed tx's Merkle proof + PoW-committed depth verify (provenTxid === txid binding),
//   3. the tip-freshness bound accepts a live tip.
// Read-only: it never broadcasts or touches funds.
import { makeElectrumChainClient, BCH2_ELECTRUM } from '../examples/electrum-node-client.mjs';
import { verifyConfirmations, spvVerifiedTipFresh, getChainTimeSec, spvSupported } from '../dist/spv-verifier.js';
import { BCH2_MAINNET_CHECKPOINT } from '../dist/spv.js';

const CHAIN = 'bch2';
const c = makeElectrumChainClient(BCH2_ELECTRUM);
let ok = true;
const pass = (m) => console.log(`  \x1b[32m✓\x1b[0m ${m}`);
const fail = (m) => { ok = false; console.log(`  \x1b[31m✗ ${m}\x1b[0m`); };

try {
  await c.serverVersion();
  console.log(`SPV supported for ${CHAIN}: ${spvSupported(CHAIN)} (checkpoint height ${BCH2_MAINNET_CHECKPOINT.height})`);

  const [tip] = await c.getBlockHeight();
  console.log(`live BCH2 tip height: ${tip}`);
  if (!(tip > BCH2_MAINNET_CHECKPOINT.height)) { fail(`tip ${tip} is not above the checkpoint`); }

  // Pick a REAL confirmed tx buried ~15 blocks: the coinbase (pos 0) of block (tip-15).
  const h = tip - 15;
  const idPos = await c.request('blockchain.transaction.id_from_pos', [h, 0, false]);
  const txid = typeof idPos === 'string' ? idPos : idPos.tx_hash;
  console.log(`real coinbase tx at height ${h}: ${txid}`);
  const rawTx = await c.getTx(txid);

  // (1)+(2): verifyConfirmations extends + PoW-verifies the REAL header chain from the checkpoint to `tip`
  // (real ASERT), fetches the REAL Merkle proof, checks provenTxid === txid, and returns the depth.
  const depth = await verifyConfirmations(c, CHAIN, txid, h, rawTx, tip);
  const expected = tip - h + 1;
  if (depth === expected) pass(`verifyConfirmations over the REAL ASERT header chain + Merkle proof: depth ${depth} (== tip-h+1)`);
  else fail(`verifyConfirmations returned ${depth}, expected ${expected}`);

  // (3): the tip-freshness bound accepts a live tip.
  const fresh = await spvVerifiedTipFresh(c, CHAIN, tip);
  if (fresh >= tip) pass(`spvVerifiedTipFresh accepted the live tip (${fresh})`);
  else fail(`spvVerifiedTipFresh returned ${fresh} < tip ${tip}`);

  // (bonus): chain time from the real header nTime (the anti-theft margin anchor).
  const chainSec = await getChainTimeSec(c);
  if (chainSec && Math.abs(Date.now() / 1000 - chainSec) < 24 * 3600) pass(`getChainTimeSec read the real header nTime (${new Date(chainSec * 1000).toISOString()})`);
  else fail(`getChainTimeSec returned ${chainSec}`);

  // Negative control: a made-up txid at that height must FAIL the provenTxid binding (fail-closed).
  try {
    await verifyConfirmations(c, CHAIN, '00'.repeat(32), h, rawTx, tip);
    fail('a fabricated txid did NOT fail closed');
  } catch { pass('a fabricated txid fails closed (provenTxid binding rejects it)'); }

} catch (e) {
  fail(`live check threw: ${e?.message ?? e}`);
} finally {
  c.close();
}

console.log(ok ? '\n\x1b[32mLIVE SPV VALIDATION PASSED — the SDK verifier works against real BCH2 mainnet data.\x1b[0m'
               : '\n\x1b[31mLIVE SPV VALIDATION FAILED.\x1b[0m');
process.exit(ok ? 0 : 1);
