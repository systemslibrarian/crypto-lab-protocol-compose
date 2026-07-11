import { describe, expect, it } from 'vitest';
import {
  constantTimeEqual,
  naiveEqual,
  randomTag,
  recoverViaTiming,
} from '../src/timing';

describe('tag comparison functions', () => {
  it('both report equality correctly', () => {
    const a = Uint8Array.from([1, 2, 3, 4]);
    const b = Uint8Array.from([1, 2, 3, 4]);
    const c = Uint8Array.from([1, 2, 9, 4]);
    expect(naiveEqual(a, b).equal).toBe(true);
    expect(naiveEqual(a, c).equal).toBe(false);
    expect(constantTimeEqual(a, b).equal).toBe(true);
    expect(constantTimeEqual(a, c).equal).toBe(false);
  });

  it('naive compare leaks the correct-prefix length through its comparison count', () => {
    const secret = Uint8Array.from([10, 20, 30, 40, 50]);
    // 0 correct leading bytes -> stops at byte 1.
    expect(naiveEqual(Uint8Array.from([0, 0, 0, 0, 0]), secret).comparisons).toBe(1);
    // 3 correct leading bytes -> stops at byte 4.
    expect(naiveEqual(Uint8Array.from([10, 20, 30, 0, 0]), secret).comparisons).toBe(4);
    // fully correct -> scans all 5.
    expect(naiveEqual(secret.slice(), secret).comparisons).toBe(5);
  });

  it('constant-time compare inspects every byte regardless of where inputs differ', () => {
    const secret = Uint8Array.from([10, 20, 30, 40, 50]);
    for (const guess of [
      [0, 0, 0, 0, 0],
      [10, 20, 30, 0, 0],
      [10, 20, 30, 40, 50],
    ]) {
      expect(constantTimeEqual(Uint8Array.from(guess), secret).comparisons).toBe(secret.length);
    }
  });
});

describe('timing recovery attack', () => {
  it('recovers a random tag from the naive-compare timing signal alone', async () => {
    for (let trial = 0; trial < 5; trial += 1) {
      const secret = randomTag(8);
      const result = await recoverViaTiming(secret, naiveEqual);
      expect(result.success).toBe(true);
      expect(Array.from(result.recovered)).toEqual(Array.from(secret));
      // 256 timed guesses per byte.
      expect(result.queries).toBe(secret.length * 256);
      // The counter is monotonic so the live display never goes backwards.
      const counts = result.steps.map((s) => s.queriesSoFar);
      expect(counts).toEqual([...counts].sort((x, y) => x - y));
    }
  });

  it('recovers nothing against a constant-time compare — the signal is flat', async () => {
    const secret = randomTag(8);
    const result = await recoverViaTiming(secret, constantTimeEqual);
    expect(result.success).toBe(false);
  });
});
