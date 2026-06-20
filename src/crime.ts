// CRIME / BREACH: when you compress before encrypting, the ciphertext *length*
// leaks the plaintext. Encryption hides content, not size — so an attacker who
// can inject data next to a secret and watch the compressed size can recover the
// secret one character at a time, without ever decrypting anything.

const encoder = new TextEncoder();

export const CRIME_ALPHABET = 'abcdefghijklmnopqrstuvwxyz0123456789';

/** Length in bytes of `input` after raw DEFLATE compression (what CRIME measures). */
export async function compressedLength(input: string): Promise<number> {
  const stream = new Blob([encoder.encode(input)])
    .stream()
    .pipeThrough(new CompressionStream('deflate-raw'));
  const buffer = await new Response(stream).arrayBuffer();
  return buffer.byteLength;
}

/**
 * Model an attacker request that reflects their guess next to the secret, the
 * way a real CRIME/BREACH target reflects request data into a compressed,
 * encrypted response. The shared `session=` context aligns the back-reference.
 */
export function crimePayload(secret: string, guess: string): string {
  return `Cookie: session=${secret}\nX-Probe: session=${guess}`;
}

export interface CrimeStep {
  position: number;
  recovered: string;
  bestLength: number;
}

export interface CrimeResult {
  recovered: string;
  steps: CrimeStep[];
  queries: number;
}

/**
 * Recover `secret` using only compressed-length measurements. At each position
 * the correct next character compresses against the secret (shorter output);
 * the wrong characters do not. `onStep` lets callers animate the recovery.
 */
export async function crimeRecover(
  secret: string,
  alphabet: string = CRIME_ALPHABET,
  onStep?: (step: CrimeStep) => Promise<void> | void,
): Promise<CrimeResult> {
  let recovered = '';
  const steps: CrimeStep[] = [];
  let queries = 0;

  for (let pos = 0; pos < secret.length; pos += 1) {
    let bestChar = alphabet[0];
    let bestLength = Number.POSITIVE_INFINITY;

    for (const ch of alphabet) {
      const length = await compressedLength(crimePayload(secret, recovered + ch));
      queries += 1;
      if (length < bestLength) {
        bestLength = length;
        bestChar = ch;
      }
    }

    recovered += bestChar;
    const step: CrimeStep = { position: pos, recovered, bestLength };
    steps.push(step);
    if (onStep) {
      await onStep(step);
    }
  }

  return { recovered, steps, queries };
}

/** Generate a random secret drawn from the recovery alphabet. */
export function randomSecret(length = 8, alphabet: string = CRIME_ALPHABET): string {
  const values = crypto.getRandomValues(new Uint8Array(length));
  let out = '';
  for (let i = 0; i < length; i += 1) {
    out += alphabet[values[i] % alphabet.length];
  }
  return out;
}
