import { describe, expect, it } from 'vitest';
import { createSuite, sealEtM, sealMtE, utf8 } from '../src/compose';
import {
  createMtEPaddingOracle,
  etmRejectsTampering,
  recoverMtEPlaintext,
  tlsEvolutionNotes,
} from '../src/attacks';

describe('MtE padding oracle', () => {
  it.each([
    'pay=bob;amt=1337',
    'transfer=2500&to=alice',
    'hi',
  ])('recovers the plaintext of %j with no key', async (message) => {
    const suite = await createSuite();
    const packet = await sealMtE(suite, message);
    const oracle = createMtEPaddingOracle(suite);
    const result = await recoverMtEPlaintext(packet, oracle);
    const recovered = new TextDecoder().decode(result.recovered.slice(0, utf8(message).length));
    expect(recovered).toBe(message);
    expect(result.queries).toBeGreaterThan(0);
  });
});

describe('EtM closes the oracle', () => {
  it('rejects tampering at the MAC, before decryption', async () => {
    const suite = await createSuite();
    const packet = await sealEtM(suite, 'pay=bob;amt=1337');
    expect(await etmRejectsTampering(suite, packet)).toBe(true);
  });
});

describe('TLS timeline data', () => {
  it('progresses danger -> warn -> safe', () => {
    const notes = tlsEvolutionNotes();
    expect(notes.map((n) => n.safety)).toEqual(['danger', 'warn', 'safe']);
    for (const note of notes) {
      expect(note.version).toBeTruthy();
      expect(note.lesson).toBeTruthy();
    }
  });
});
