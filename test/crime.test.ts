import { describe, expect, it } from 'vitest';
import { CRIME_ALPHABET, compressedLength, crimeRecover, randomSecret, rejectionLimit } from '../src/crime';

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

describe('randomSecret draws without modulo bias', () => {
  // The bound is derived here from the alphabet, NOT read back from the module,
  // so a mutation to `rejectionLimit` cannot move the expectation with it.
  const size = CRIME_ALPHABET.length;
  const independentLimit = Math.floor(256 / size) * size;

  /** A source that hands out the given bytes in order, counting its calls. */
  function scripted(...bytes: number[]) {
    let draws = 0;
    return {
      get draws() {
        return draws;
      },
      source: (buffer: Uint8Array) => {
        // Throw rather than repeat the last byte. A sampler that rejects
        // forever would otherwise spin here, and a hang is a far worse
        // failure signal than an exhausted-source error.
        if (draws >= bytes.length) throw new Error(`scripted source exhausted after ${draws} draws`);
        buffer[0] = bytes[draws];
        draws += 1;
      },
    };
  }

  it('bounds at the largest multiple of the alphabet size that fits a byte', () => {
    expect(size).toBe(36);
    expect(independentLimit).toBe(252);
    // 256 is not a multiple of 36, which is the whole reason a bound is needed.
    expect(256 % size).toBe(4);
    expect(rejectionLimit(size)).toBe(independentLimit);
  });

  it('accepts the byte one below the bound, in a single draw', () => {
    const feed = scripted(independentLimit - 1);
    expect(randomSecret(1, CRIME_ALPHABET, feed.source)).toBe(
      CRIME_ALPHABET[(independentLimit - 1) % size],
    );
    expect(feed.draws).toBe(1);
  });

  it('rejects the byte AT the bound and draws again', () => {
    const feed = scripted(independentLimit, 0);
    expect(randomSecret(1, CRIME_ALPHABET, feed.source)).toBe(CRIME_ALPHABET[0]);
    expect(feed.draws).toBe(2);
  });

  it('rejects every byte in the biased tail, not just the first', () => {
    // 252, 253, 254, 255 are exactly the four that would skew the first four
    // symbols. Each must cost a redraw.
    const tail = [independentLimit, independentLimit + 1, independentLimit + 2, independentLimit + 3];
    const feed = scripted(...tail, 5);
    expect(randomSecret(1, CRIME_ALPHABET, feed.source)).toBe(CRIME_ALPHABET[5]);
    expect(feed.draws).toBe(tail.length + 1);
  });

  it('refuses an alphabet it cannot sample uniformly', () => {
    expect(() => randomSecret(1, '')).toThrow(/1 to 256 symbols/);
  });

  it('still produces a secret of the requested length from the real source', () => {
    expect(randomSecret(12)).toHaveLength(12);
    expect([...randomSecret(64)].every((ch) => CRIME_ALPHABET.includes(ch))).toBe(true);
  });
});
