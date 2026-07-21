import { describe, it, expect } from 'vitest';
import {
  proposalToOffer, orderToOffer, offerToProposal, bookChainToOffer, offerChainToBook,
} from './adapter';
import type { SwapProposal, SwapOrder } from './types';
import type { SwapOffer } from '../swap-types';

// A FIXTURE of the REAL proxy shape (mirrors GET /api/orders → { success, data: SwapOrder[] }).
// Realistic invariants the proxy upholds and the adapter relies on:
//   - hashLock === secretHash
//   - refundAddress  === initiatorSendAddress
//   - receiveAddress === initiatorReceiveAddress
// so the 2-address execution SwapOffer captures the 4-address transport proposal losslessly.
const REAL_PROPOSAL: SwapProposal = {
  offerChain: 'POLY',
  wantChain: 'BCH2',
  sendAmount: '12.5',        // (fixture) base-unit decimal STRING per chain — sats for UTXO / wei for EVM; carried through verbatim
  receiveAmount: '0.031415',
  secretHash: 'a'.repeat(64),
  secretNonce: 'b'.repeat(32),
  secretScheme: 'hmac-v1',
  makerIdPub: '02' + 'c'.repeat(64),
  makerSig: 'd'.repeat(128),
  authPub: '03' + 'e'.repeat(64),
  refundAddress: '0xMakerRefundOnPoly',
  receiveAddress: 'bitcoincashii:qMakerReceiveOnBch2',
  initiatorSendAddress: '0xMakerRefundOnPoly',
  initiatorReceiveAddress: 'bitcoincashii:qMakerReceiveOnBch2',
  evmInfo: {
    evmChainId: 137,
    tokenSymbol: 'USDC',
    tokenAddress: '0xToken',
    tokenDecimals: 6,
    htlcAddress: '0xHtlc',
    swapId: '0x' + 'f'.repeat(64),
  },
  evmAddress: '0xMakerEvm',
  hashLock: 'a'.repeat(64),
};

const REAL_ORDER: SwapOrder = {
  id: 'ord_abc123',
  offerChain: 'POLY',
  wantChain: 'BCH2',
  status: 'taken',
  createdAt: 1_700_000_000_000,
  expiresAt: 1_700_000_003_600,
  takenAt: 1_700_000_001_000,
  responderLocktime: 216,
  evmSwapId: '0x' + '9'.repeat(64),
  initiatorTxid: '1'.repeat(64),
  responderTxid: '2'.repeat(64),
  responderSendAddress: 'bitcoincashii:qTakerRefundOnBch2',
  responderReceiveAddress: '0xTakerReceiveOnPoly',
  takerAuthPub: '02' + '7'.repeat(64),
  proposal: REAL_PROPOSAL,
};

describe('chain-code mapping (UPPER transport ⇄ lower execution)', () => {
  it('maps every transport code to its SwapOffer chain and back', () => {
    const pairs: Array<[string, string]> = [
      ['BCH2', 'bch2'], ['BCH', 'bch'], ['BTC', 'btc'], ['BC2', 'bc2'],
      ['ETH', 'eth'], ['BASE', 'base'], ['ARB', 'arb'], ['POLY', 'poly'],
    ];
    for (const [code, chain] of pairs) {
      expect(bookChainToOffer(code)).toBe(chain);
      expect(offerChainToBook(chain)).toBe(code);
    }
  });

  it('is case-insensitive on input', () => {
    expect(bookChainToOffer('poly')).toBe('poly');
    expect(bookChainToOffer('Poly')).toBe('poly');
    expect(offerChainToBook('BCH2')).toBe('BCH2');
  });

  it('fails closed on an unknown chain (never forwards a bad chain into fund logic)', () => {
    expect(() => bookChainToOffer('DOGE')).toThrow(/unknown order-book chain code/);
    expect(() => offerChainToBook('doge')).toThrow(/unknown SwapOffer chain/);
  });
});

describe('proposalToOffer', () => {
  const offer = proposalToOffer(REAL_PROPOSAL);

  it('lowercases the chain codes offerChain→sendChain / wantChain→receiveChain', () => {
    expect(offer.sendChain).toBe('poly');
    expect(offer.receiveChain).toBe('bch2');
  });

  it('carries amounts through as decimal strings (never converts to sats)', () => {
    expect(offer.sendAmount).toBe('12.5');
    expect(offer.receiveAmount).toBe('0.031415');
  });

  it('carries the secret commitment (hash / nonce / scheme)', () => {
    expect(offer.secretHash).toBe(REAL_PROPOSAL.secretHash);
    expect(offer.secretNonce).toBe(REAL_PROPOSAL.secretNonce);
    expect(offer.secretScheme).toBe('hmac-v1');
  });

  it('carries the seed-derived maker identity + API-auth pubkeys', () => {
    expect(offer.makerIdPub).toBe(REAL_PROPOSAL.makerIdPub);
    expect(offer.makerSig).toBe(REAL_PROPOSAL.makerSig);
    expect(offer.authPub).toBe(REAL_PROPOSAL.authPub);
  });

  it('maps the initiator addresses (refund on offerChain, receive on wantChain)', () => {
    expect(offer.initiatorSendAddress).toBe(REAL_PROPOSAL.initiatorSendAddress);
    expect(offer.initiatorReceiveAddress).toBe(REAL_PROPOSAL.initiatorReceiveAddress);
  });

  it('carries the EVM extension fields when a leg is EVM', () => {
    expect(offer.evmInfo).toEqual(REAL_PROPOSAL.evmInfo);
    expect(offer.evmAddress).toBe('0xMakerEvm');
  });

  it('falls back to refundAddress/receiveAddress when the explicit initiator fields are absent', () => {
    const legacy: SwapProposal = {
      ...REAL_PROPOSAL,
      initiatorSendAddress: '',
      initiatorReceiveAddress: '',
    };
    const o = proposalToOffer(legacy);
    expect(o.initiatorSendAddress).toBe(REAL_PROPOSAL.refundAddress);
    expect(o.initiatorReceiveAddress).toBe(REAL_PROPOSAL.receiveAddress);
  });

  it('applies overrides (e.g. order-level id / timestamps a bare proposal lacks)', () => {
    const o = proposalToOffer(REAL_PROPOSAL, { id: 'ord_x', createdAt: 42, expiresAt: 99, status: 'taken' });
    expect(o.id).toBe('ord_x');
    expect(o.createdAt).toBe(42);
    expect(o.expiresAt).toBe(99);
    expect(o.status).toBe('taken');
  });
});

describe('orderToOffer (full order → execution SwapOffer)', () => {
  const offer = orderToOffer(REAL_ORDER);

  it('carries the order-level fields the bare proposal lacks', () => {
    expect(offer.id).toBe('ord_abc123');
    expect(offer.status).toBe('taken');
    expect(offer.createdAt).toBe(REAL_ORDER.createdAt);
    expect(offer.expiresAt).toBe(REAL_ORDER.expiresAt);
    expect(offer.takerAuthPub).toBe(REAL_ORDER.takerAuthPub);
  });

  it('still lowercases chains + carries amounts/secret from the nested proposal', () => {
    expect(offer.sendChain).toBe('poly');
    expect(offer.receiveChain).toBe('bch2');
    expect(offer.sendAmount).toBe('12.5');
    expect(offer.secretHash).toBe(REAL_PROPOSAL.secretHash);
  });
});

describe('offerToProposal round-trip', () => {
  it('offerToProposal(proposalToOffer(P)) reproduces the transport proposal', () => {
    const roundTripped = offerToProposal(proposalToOffer(REAL_PROPOSAL));
    expect(roundTripped).toEqual(REAL_PROPOSAL);
  });

  it('round-trips a full order via orderToOffer too', () => {
    const roundTripped = offerToProposal(orderToOffer(REAL_ORDER));
    expect(roundTripped).toEqual(REAL_PROPOSAL);
  });

  it('coerces number amounts (legacy on-the-wire form) to decimal strings', () => {
    const numericOffer: SwapOffer = { ...proposalToOffer(REAL_PROPOSAL), sendAmount: 100000, receiveAmount: 250 };
    const p = offerToProposal(numericOffer);
    expect(p.sendAmount).toBe('100000');
    expect(p.receiveAmount).toBe('250');
    expect(typeof p.sendAmount).toBe('string');
  });

  it('derives hashLock and the mirrored refund/receive addresses from the offer', () => {
    const p = offerToProposal(proposalToOffer(REAL_PROPOSAL));
    expect(p.hashLock).toBe(p.secretHash);
    expect(p.refundAddress).toBe(p.initiatorSendAddress);
    expect(p.receiveAddress).toBe(p.initiatorReceiveAddress);
  });

  it('drops the EVM fields when the offer has none (UTXO↔UTXO)', () => {
    const utxoProposal: SwapProposal = {
      ...REAL_PROPOSAL,
      offerChain: 'BCH2', wantChain: 'BTC',
      refundAddress: 'bitcoincashii:qRefund', receiveAddress: '1BtcReceive',
      initiatorSendAddress: 'bitcoincashii:qRefund', initiatorReceiveAddress: '1BtcReceive',
    };
    delete (utxoProposal as { evmInfo?: unknown }).evmInfo;
    delete (utxoProposal as { evmAddress?: unknown }).evmAddress;
    const rt = offerToProposal(proposalToOffer(utxoProposal));
    expect(rt).toEqual(utxoProposal);
    expect('evmInfo' in rt).toBe(false);
    expect('evmAddress' in rt).toBe(false);
  });
});
