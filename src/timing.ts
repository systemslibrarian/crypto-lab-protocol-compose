// Timing side-channels (the Lucky Thirteen family). Even a *correct* composition
// order breaks if the tag comparison itself leaks. A byte-by-byte compare that
// returns as soon as it finds a mismatch runs in time proportional to the length
// of the correct prefix — so how long a rejection takes tells an attacker how
// many leading bytes of a forged tag are right. From that signal the whole tag
// falls out one byte at a time, with no key.
//
// We model "time" as the number of byte comparisons performed before the compare
// returns. That count is exactly what a variable-time compare's running time is
// proportional to, and unlike a wall-clock read it is deterministic — so the leak
// is testable rather than flaky.

export interface CompareTrace {
  equal: boolean;
  /** Bytes inspected before returning. Proportional to time; this is the leak. */
  comparisons: number;
}

export type CompareFn = (a: Uint8Array, b: Uint8Array) => CompareTrace;

/**
 * Vulnerable compare: bails at the first mismatching byte. The comparison count
 * (and thus the running time) leaks the length of the correct prefix. This is the
 * bug behind Lucky Thirteen and naive MAC/tag comparison timing attacks.
 */
export function naiveEqual(a: Uint8Array, b: Uint8Array): CompareTrace {
  if (a.length !== b.length) {
    return { equal: false, comparisons: 0 };
  }
  let comparisons = 0;
  for (let i = 0; i < a.length; i += 1) {
    comparisons += 1;
    if (a[i] !== b[i]) {
      return { equal: false, comparisons };
    }
  }
  return { equal: true, comparisons };
}

/**
 * Safe compare: always inspects every byte, accumulating any difference with OR.
 * The comparison count is constant no matter where — or whether — the inputs
 * differ, so there is no timing signal to measure.
 */
export function constantTimeEqual(a: Uint8Array, b: Uint8Array): CompareTrace {
  if (a.length !== b.length) {
    return { equal: false, comparisons: 0 };
  }
  let diff = 0;
  for (let i = 0; i < a.length; i += 1) {
    diff |= a[i] ^ b[i];
  }
  return { equal: diff === 0, comparisons: a.length };
}

export interface TimingStep {
  position: number;
  byte: number;
  /** Comparisons the winning guess produced — the timing that gave the byte away. */
  comparisons: number;
  queriesSoFar: number;
}

export interface TimingRecoveryResult {
  recovered: Uint8Array;
  steps: TimingStep[];
  queries: number;
  success: boolean;
}

/** Random tag to stand in for a real HMAC output the attacker is trying to forge. */
export function randomTag(length = 8): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(length));
}

/**
 * Recover `secret` using only the timing (comparison-count) signal from `compare`.
 *
 * For each position we already know the correct prefix, so we try all 256 values
 * for the next byte and keep the guess whose compare ran the *longest*: the wrong
 * bytes stop at this position, the correct byte lets the compare advance one step
 * further. Against `naiveEqual` this recovers the whole tag; against
 * `constantTimeEqual` every guess costs the same, the signal is flat, and recovery
 * fails — which is the whole point.
 */
export async function recoverViaTiming(
  secret: Uint8Array,
  compare: CompareFn = naiveEqual,
  onStep?: (step: TimingStep) => Promise<void> | void,
): Promise<TimingRecoveryResult> {
  const recovered = new Uint8Array(secret.length);
  const steps: TimingStep[] = [];
  let queries = 0;

  for (let pos = 0; pos < secret.length; pos += 1) {
    let bestByte = 0;
    let bestComparisons = -1;
    let bestEqual = false;

    const candidate = recovered.slice();
    for (let guess = 0; guess < 256; guess += 1) {
      candidate[pos] = guess;
      // Positions after `pos` stay zero: they only ever match the secret by
      // chance, so the correct byte still stands out as the longest-running guess.
      const trace = compare(candidate, secret);
      queries += 1;
      const better =
        trace.comparisons > bestComparisons ||
        (trace.comparisons === bestComparisons && trace.equal && !bestEqual);
      if (better) {
        bestComparisons = trace.comparisons;
        bestByte = guess;
        bestEqual = trace.equal;
      }
    }

    recovered[pos] = bestByte;
    const step: TimingStep = {
      position: pos,
      byte: bestByte,
      comparisons: bestComparisons,
      queriesSoFar: queries,
    };
    steps.push(step);
    if (onStep) {
      await onStep(step);
    }
  }

  const success = recovered.every((b, i) => b === secret[i]);
  return { recovered, steps, queries, success };
}
