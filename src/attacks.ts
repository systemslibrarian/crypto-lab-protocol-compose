import {
  type CryptoSuite,
  type EtMPacket,
  type MtEPacket,
  fromUtf8,
  openEtM,
  openMtE,
} from './compose';

export interface OracleStep {
  blockIndex: number;
  byteIndex: number;
  guess: number;
  recoveredByte: number;
  recoveredTextPreview: string;
}

export interface PaddingOracleResult {
  recovered: Uint8Array;
  recoveredText: string;
  steps: OracleStep[];
  queries: number;
}

export interface TlsTimelinePoint {
  version: string;
  composition: string;
  failureOrWin: string;
  lesson: string;
}

type PaddingOracle = (iv: Uint8Array, ciphertext: Uint8Array) => Promise<boolean>;

function concatBytes(...parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((sum, part) => sum + part.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

function splitBlocks(bytes: Uint8Array, blockSize = 16): Uint8Array[] {
  const blocks: Uint8Array[] = [];
  for (let i = 0; i < bytes.length; i += blockSize) {
    blocks.push(bytes.slice(i, i + blockSize));
  }
  return blocks;
}

function safeDecode(bytes: Uint8Array): string {
  try {
    return fromUtf8(bytes);
  } catch {
    return '[non-utf8-bytes]';
  }
}

export function createMtEPaddingOracle(suite: CryptoSuite, packet: MtEPacket): PaddingOracle {
  return async (iv: Uint8Array, ciphertext: Uint8Array): Promise<boolean> => {
    const result = await openMtE(suite, { iv, ciphertext });
    return result.reason !== 'decrypt-failed-before-mac';
  };
}

export async function recoverMtEPlaintext(packet: MtEPacket, oracle: PaddingOracle): Promise<PaddingOracleResult> {
  const allBlocks = [packet.iv, ...splitBlocks(packet.ciphertext, 16)];
  const recovered = new Uint8Array(packet.ciphertext.length);
  const steps: OracleStep[] = [];
  let queries = 0;

  for (let blockIdx = 1; blockIdx < allBlocks.length; blockIdx += 1) {
    const previous = allBlocks[blockIdx - 1];
    const current = allBlocks[blockIdx];
    const intermediate = new Uint8Array(16);
    const plainBlock = new Uint8Array(16);

    for (let pos = 15; pos >= 0; pos -= 1) {
      const pad = 16 - pos;
      let found = false;

      for (let guess = 0; guess < 256; guess += 1) {
        const craftedPrev = previous.slice();

        for (let j = 15; j > pos; j -= 1) {
          craftedPrev[j] = intermediate[j] ^ pad;
        }

        craftedPrev[pos] = guess;

        const craftedIv = blockIdx === 1 ? craftedPrev : allBlocks[0];
        const craftedCipher = blockIdx === 1
          ? current
          : concatBytes(craftedPrev, current);

        queries += 1;
        const hit = await oracle(craftedIv, craftedCipher);
        if (!hit) {
          continue;
        }

        if (pos === 15) {
          const checkPrev = craftedPrev.slice();
          checkPrev[14] ^= 1;
          const checkIv = blockIdx === 1 ? checkPrev : allBlocks[0];
          const checkCipher = blockIdx === 1
            ? current
            : concatBytes(checkPrev, current);
          queries += 1;
          const confirmed = await oracle(checkIv, checkCipher);
          if (!confirmed) {
            continue;
          }
        }

        intermediate[pos] = guess ^ pad;
        plainBlock[pos] = intermediate[pos] ^ previous[pos];
        const globalOffset = (blockIdx - 1) * 16 + pos;
        recovered[globalOffset] = plainBlock[pos];
        steps.push({
          blockIndex: blockIdx - 1,
          byteIndex: pos,
          guess,
          recoveredByte: plainBlock[pos],
          recoveredTextPreview: safeDecode(recovered.slice(0, globalOffset + 1))
        });
        found = true;
        break;
      }

      if (!found) {
        plainBlock[pos] = 0x3f;
        const globalOffset = (blockIdx - 1) * 16 + pos;
        recovered[globalOffset] = plainBlock[pos];
      }
    }
  }

  return {
    recovered,
    recoveredText: safeDecode(recovered),
    steps,
    queries
  };
}

export async function etmRejectsTampering(suite: CryptoSuite, packet: EtMPacket): Promise<boolean> {
  const tampered = packet.ciphertext.slice();
  tampered[tampered.length - 1] ^= 1;
  const result = await openEtM(suite, {
    iv: packet.iv,
    ciphertext: tampered,
    tag: packet.tag
  });
  return result.reason === 'bad-mac-before-decrypt';
}

export function tlsEvolutionNotes(): TlsTimelinePoint[] {
  return [
    {
      version: 'TLS 1.0 / 1.1',
      composition: 'CBC with MAC-then-Encrypt record processing',
      failureOrWin: 'BEAST and CBC fragility under record-level composition',
      lesson: 'Encrypting MACed plaintext still left exploitable structure and side-channel surface.'
    },
    {
      version: 'TLS 1.2',
      composition: 'Still permits CBC MtE suites and therefore Lucky Thirteen class timing issues',
      failureOrWin: 'Residual risk from decryption-before-authentication code paths',
      lesson: 'Optional safer ciphers are not enough when dangerous composition remains negotiable.'
    },
    {
      version: 'TLS 1.3',
      composition: 'AEAD-only mandate (AES-GCM, ChaCha20-Poly1305, etc.)',
      failureOrWin: 'Removes CBC MtE record layer entirely',
      lesson: 'Protocol redesign constrained composition choices to eliminate known attack classes.'
    }
  ];
}

