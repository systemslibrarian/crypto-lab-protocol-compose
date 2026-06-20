import { describe, expect, it } from 'vitest';
import { CRIME_ALPHABET, compressedLength, crimeRecover, randomSecret } from '../src/crime';

describe('CRIME compression leak', () => {
  it('compresses redundant data smaller than random data', async () => {
    const redundant = await compressedLength('a'.repeat(200));
    const random = await compressedLength(randomSecret(200));
    expect(redundant).toBeLessThan(random);
  });

  it('recovers random secrets from compressed length alone', async () => {
    for (let trial = 0; trial < 5; trial += 1) {
      const secret = randomSecret(8);
      const result = await crimeRecover(secret, CRIME_ALPHABET);
      expect(result.recovered).toBe(secret);
      expect(result.queries).toBe(secret.length * CRIME_ALPHABET.length);
    }
  });

  it('reports each recovery step', async () => {
    const secret = randomSecret(4);
    const result = await crimeRecover(secret, CRIME_ALPHABET);
    expect(result.steps).toHaveLength(4);
    expect(result.steps[result.steps.length - 1].recovered).toBe(secret);
  });
});
