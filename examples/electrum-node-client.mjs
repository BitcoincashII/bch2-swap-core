// A minimal Node.js ElectrumX transport that satisfies @bch2/swap-core's SwapChainClient — the untrusted chain
// read/broadcast surface the SwapController + SPV layer verify against. Line-delimited JSON-RPC over TLS.
//
// This is a reference transport for a Node bot: `chainClientFor: (chain) => makeElectrumChainClient(SERVERS[chain])`.
// It is UNTRUSTED by design — the SDK's SPV verifier proves depth/Merkle/PoW against it from a hardcoded checkpoint,
// so a lying server cannot fabricate confirmations.
import tls from 'node:tls';

export function makeElectrumChainClient({ host, port, timeoutMs = 20_000 }) {
  let sock = null;
  let buf = '';
  let nextId = 1;
  const pending = new Map();
  let connected = null;

  function connect() {
    if (connected) return connected;
    connected = new Promise((resolve, reject) => {
      sock = tls.connect({ host, port, rejectUnauthorized: false, servername: host }, () => resolve());
      sock.setEncoding('utf8');
      sock.on('data', (d) => {
        buf += d;
        let ix;
        while ((ix = buf.indexOf('\n')) >= 0) {
          const line = buf.slice(0, ix); buf = buf.slice(ix + 1);
          if (!line.trim()) continue;
          let msg; try { msg = JSON.parse(line); } catch { continue; }
          const p = pending.get(msg.id);
          if (!p) continue; // a subscription push — ignored here
          pending.delete(msg.id);
          if (msg.error) p.reject(new Error(`${msg.error?.message ?? JSON.stringify(msg.error)}`));
          else p.resolve(msg.result);
        }
      });
      sock.on('error', (e) => { for (const p of pending.values()) p.reject(e); pending.clear(); reject(e); });
      sock.on('close', () => { for (const p of pending.values()) p.reject(new Error('electrum socket closed')); pending.clear(); connected = null; });
    });
    return connected;
  }

  async function request(method, params = []) {
    await connect();
    const id = nextId++;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => { if (pending.has(id)) { pending.delete(id); reject(new Error(`electrum timeout: ${method}`)); } }, timeoutMs);
      pending.set(id, { resolve: (v) => { clearTimeout(timer); resolve(v); }, reject: (e) => { clearTimeout(timer); reject(e); } });
      sock.write(JSON.stringify({ id, method, params }) + '\n');
    });
  }

  return {
    // ── ElectrumX handshake (some servers require server.version before other calls) ──
    async serverVersion(client = 'bch2-swap-core', proto = '1.4.3') { return request('server.version', [client, proto]); },

    // ── SwapChainClient (the SDK's gate + fund/claim/refund read/write surface) ──
    request,
    getBlockHeaders: (start, count) => request('blockchain.block.headers', [start, count]),
    getMerkleProof: (txid, height) => request('blockchain.transaction.get_merkle', [txid, height]),
    getTx: (txid) => request('blockchain.transaction.get', [txid]),
    getUTXOs: (scripthash) => request('blockchain.scripthash.listunspent', [scripthash]),
    getHistory: (scripthash) => request('blockchain.scripthash.get_history', [scripthash]),
    broadcastTx: (rawTx) => request('blockchain.transaction.broadcast', [rawTx]),
    async getBlockHeight() { const h = await request('blockchain.headers.subscribe', []); return [h.height, () => {}]; },

    close() { try { sock?.end(); } catch { /* ignore */ } },
  };
}

export const BCH2_ELECTRUM = { host: 'electrum.bch2.org', port: 50002 };
