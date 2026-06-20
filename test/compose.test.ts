import { describe, expect, it } from 'vitest';
import {
  createSuite,
  openAead,
  openEAndM,
  openEtM,
  openMtE,
  sealAead,
  sealEAndM,
  sealEtM,
  sealMtE,
} from '../src/compose';

const MESSAGE = 'transfer=2500&to=alice';

describe('composition round-trips', () => {
  it('MtE seals and opens', async () => {
    const suite = await createSuite();
    const result = await openMtE(suite, await sealMtE(suite, MESSAGE));
    expect(result.ok).toBe(true);
    expect(result.plaintext).toBe(MESSAGE);
  });

  it('EtM seals and opens', async () => {
    const suite = await createSuite();
    const result = await openEtM(suite, await sealEtM(suite, MESSAGE));
    expect(result.ok).toBe(true);
    expect(result.plaintext).toBe(MESSAGE);
  });

  it('E&M seals and opens', async () => {
    const suite = await createSuite();
    const result = await openEAndM(suite, await sealEAndM(suite, MESSAGE));
    expect(result.ok).toBe(true);
    expect(result.plaintext).toBe(MESSAGE);
  });

  it('AEAD seals and opens', async () => {
    const suite = await createSuite();
    const result = await openAead(suite, await sealAead(suite, MESSAGE));
    expect(result.ok).toBe(true);
    expect(result.plaintext).toBe(MESSAGE);
  });
});

describe('tamper detection', () => {
  it('EtM rejects tampering before decrypting', async () => {
    const suite = await createSuite();
    const packet = await sealEtM(suite, MESSAGE);
    packet.ciphertext[0] ^= 0x01;
    const result = await openEtM(suite, packet);
    expect(result.ok).toBe(false);
    expect(result.reason).toBe('bad-mac-before-decrypt');
  });

  it('AEAD rejects tampering', async () => {
    const suite = await createSuite();
    const packet = await sealAead(suite, MESSAGE);
    packet.ciphertext[0] ^= 0x01;
    const result = await openAead(suite, packet);
    expect(result.ok).toBe(false);
  });

  it('E&M tag is deterministic over plaintext (the equality leak)', async () => {
    const suite = await createSuite();
    const a = await sealEAndM(suite, MESSAGE);
    const b = await sealEAndM(suite, MESSAGE);
    expect([...a.tag]).toEqual([...b.tag]); // identical plaintext -> identical tag
  });

  it('EtM tag differs across sends (random IV, no equality leak)', async () => {
    const suite = await createSuite();
    const a = await sealEtM(suite, MESSAGE);
    const b = await sealEtM(suite, MESSAGE);
    expect([...a.tag]).not.toEqual([...b.tag]);
  });
});
