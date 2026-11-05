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
  /** Total length measurements spent by the moment this character was recovered. */
  queriesSoFar: number;
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
    const step: CrimeStep = { position: pos, recovered, bestLength, queriesSoFar: queries };
    steps.push(step);
    if (onStep) {
      await onStep(step);
    }
  }

  return { recovered, steps, queries };
}

/** Fill `buffer` with random bytes. Injectable so the rejection bound is testable. */
export type ByteSource = (buffer: Uint8Array<ArrayBuffer>) => void;

const cryptoSource: ByteSource = (buffer) => {
  crypto.getRandomValues(buffer);
};

/**
 * The largest multiple of `alphabetSize` that fits in one byte.
 *
 * `byte % alphabetSize` is only uniform when every residue has the same number
 * of byte values behind it, and 256 is not a multiple of 36: `256 % 36 === 4`,
 * so four of the alphabet's symbols would get eight byte values each and the
 * other thirty-two only seven — about 14% more likely. Drawing again on a byte
 * at or above this bound removes that skew exactly.
 */
export function rejectionLimit(alphabetSize: number): number {
  return 256 - (256 % alphabetSize);
}

/** Generate a random secret drawn from the recovery alphabet, without modulo bias. */
export function randomSecret(
  length = 8,
  alphabet: string = CRIME_ALPHABET,
  source: ByteSource = cryptoSource,
): string {
  if (alphabet.length === 0 || alphabet.length > 256) {
    throw new RangeError('randomSecret needs an alphabet of 1 to 256 symbols');
  }
  const limit = rejectionLimit(alphabet.length);
  const buffer = new Uint8Array(1) as Uint8Array<ArrayBuffer>;
  let out = '';
  while (out.length < length) {
    source(buffer);
    // The tail above `limit` is what would make the first residues likelier.
    if (buffer[0] >= limit) continue;
    out += alphabet[buffer[0] % alphabet.length];
  }
  return out;
}
