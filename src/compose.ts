const encoder = new TextEncoder();
const decoder = new TextDecoder();

export type CompositionMode = 'mte' | 'etm' | 'eam' | 'aead';

export interface CryptoSuite {
  cbcKey: CryptoKey;
  hmacKey: CryptoKey;
  gcmKey: CryptoKey;
}

export interface MtEPacket {
  iv: Uint8Array;
  ciphertext: Uint8Array;
}

export interface EtMPacket {
  iv: Uint8Array;
  ciphertext: Uint8Array;
  tag: Uint8Array;
}

export interface EAndMPacket {
  iv: Uint8Array;
  ciphertext: Uint8Array;
  tag: Uint8Array;
}

export interface AeadPacket {
  iv: Uint8Array;
  ciphertext: Uint8Array;
  tag: Uint8Array;
}

export interface OpenResult {
  ok: boolean;
  plaintext: string;
  reason: string;
}

export interface CompositionResult {
  mte: MtEPacket;
  etm: EtMPacket;
  eam: EAndMPacket;
  aead: AeadPacket;
}

export async function createSuite(): Promise<CryptoSuite> {
  const cbcKey = await crypto.subtle.generateKey(
    { name: 'AES-CBC', length: 256 },
    true,
    ['encrypt', 'decrypt']
  );
  const hmacKey = await crypto.subtle.generateKey(
    { name: 'HMAC', hash: 'SHA-256', length: 256 },
    true,
    ['sign', 'verify']
  );
  const gcmKey = await crypto.subtle.generateKey(
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt']
  );
  return { cbcKey, hmacKey, gcmKey };
}

export function utf8(input: string): Uint8Array {
  return encoder.encode(input);
}

export function fromUtf8(input: Uint8Array): string {
  return decoder.decode(input);
}

export function toHex(data: Uint8Array): string {
  return Array.from(data, (b) => b.toString(16).padStart(2, '0')).join('');
}

export function concatBytes(...parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((sum, part) => sum + part.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

function toArrayBuffer(data: Uint8Array): ArrayBuffer {
  if (data.buffer instanceof ArrayBuffer) {
    return data.buffer.slice(data.byteOffset, data.byteOffset + data.byteLength);
  }
  return new Uint8Array(data).buffer;
}

async function hmacSign(key: CryptoKey, data: Uint8Array): Promise<Uint8Array> {
  const sig = await crypto.subtle.sign('HMAC', key, toArrayBuffer(data));
  return new Uint8Array(sig);
}

async function hmacVerify(key: CryptoKey, data: Uint8Array, tag: Uint8Array): Promise<boolean> {
  return crypto.subtle.verify('HMAC', key, toArrayBuffer(tag), toArrayBuffer(data));
}

export async function sealMtE(suite: CryptoSuite, plaintext: string): Promise<MtEPacket> {
  const data = utf8(plaintext);
  const tag = await hmacSign(suite.hmacKey, data);
  const payload = concatBytes(data, tag);
  const iv = crypto.getRandomValues(new Uint8Array(16));
  const ciphertext = new Uint8Array(
    await crypto.subtle.encrypt({ name: 'AES-CBC', iv: toArrayBuffer(iv) }, suite.cbcKey, toArrayBuffer(payload))
  );
  return { iv, ciphertext };
}

export async function openMtE(suite: CryptoSuite, packet: MtEPacket): Promise<OpenResult> {
  try {
    const payload = new Uint8Array(
      await crypto.subtle.decrypt(
        { name: 'AES-CBC', iv: toArrayBuffer(packet.iv) },
        suite.cbcKey,
        toArrayBuffer(packet.ciphertext)
      )
    );
    if (payload.length < 32) {
      return { ok: false, plaintext: '', reason: 'payload-too-short' };
    }
    const body = payload.slice(0, -32);
    const tag = payload.slice(-32);
    const ok = await hmacVerify(suite.hmacKey, body, tag);
    if (!ok) {
      return { ok: false, plaintext: fromUtf8(body), reason: 'bad-mac-after-decrypt' };
    }
    return { ok: true, plaintext: fromUtf8(body), reason: 'ok' };
  } catch {
    return { ok: false, plaintext: '', reason: 'decrypt-failed-before-mac' };
  }
}

export async function sealEtM(suite: CryptoSuite, plaintext: string): Promise<EtMPacket> {
  const data = utf8(plaintext);
  const iv = crypto.getRandomValues(new Uint8Array(16));
  const ciphertext = new Uint8Array(
    await crypto.subtle.encrypt({ name: 'AES-CBC', iv: toArrayBuffer(iv) }, suite.cbcKey, toArrayBuffer(data))
  );
  const tag = await hmacSign(suite.hmacKey, concatBytes(iv, ciphertext));
  return { iv, ciphertext, tag };
}

export async function openEtM(suite: CryptoSuite, packet: EtMPacket): Promise<OpenResult> {
  const macTarget = concatBytes(packet.iv, packet.ciphertext);
  const ok = await hmacVerify(suite.hmacKey, macTarget, packet.tag);
  if (!ok) {
    return { ok: false, plaintext: '', reason: 'bad-mac-before-decrypt' };
  }
  try {
    const plaintext = new Uint8Array(
      await crypto.subtle.decrypt(
        { name: 'AES-CBC', iv: toArrayBuffer(packet.iv) },
        suite.cbcKey,
        toArrayBuffer(packet.ciphertext)
      )
    );
    return { ok: true, plaintext: fromUtf8(plaintext), reason: 'ok' };
  } catch {
    return { ok: false, plaintext: '', reason: 'decrypt-failed-after-mac' };
  }
}

export async function sealEAndM(suite: CryptoSuite, plaintext: string): Promise<EAndMPacket> {
  const data = utf8(plaintext);
  const iv = crypto.getRandomValues(new Uint8Array(16));
  const ciphertext = new Uint8Array(
    await crypto.subtle.encrypt({ name: 'AES-CBC', iv: toArrayBuffer(iv) }, suite.cbcKey, toArrayBuffer(data))
  );
  const tag = await hmacSign(suite.hmacKey, data);
  return { iv, ciphertext, tag };
}

export async function openEAndM(suite: CryptoSuite, packet: EAndMPacket): Promise<OpenResult> {
  try {
    const plaintext = new Uint8Array(
      await crypto.subtle.decrypt(
        { name: 'AES-CBC', iv: toArrayBuffer(packet.iv) },
        suite.cbcKey,
        toArrayBuffer(packet.ciphertext)
      )
    );
    const ok = await hmacVerify(suite.hmacKey, plaintext, packet.tag);
    if (!ok) {
      return { ok: false, plaintext: fromUtf8(plaintext), reason: 'bad-mac-on-plaintext' };
    }
    return { ok: true, plaintext: fromUtf8(plaintext), reason: 'ok' };
  } catch {
    return { ok: false, plaintext: '', reason: 'decrypt-failed' };
  }
}

export async function sealAead(suite: CryptoSuite, plaintext: string): Promise<AeadPacket> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const data = utf8(plaintext);
  const enc = new Uint8Array(
    await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: toArrayBuffer(iv), tagLength: 128 },
      suite.gcmKey,
      toArrayBuffer(data)
    )
  );
  const ciphertext = enc.slice(0, -16);
  const tag = enc.slice(-16);
  return { iv, ciphertext, tag };
}

export async function openAead(suite: CryptoSuite, packet: AeadPacket): Promise<OpenResult> {
  try {
    const combined = concatBytes(packet.ciphertext, packet.tag);
    const plaintext = new Uint8Array(
      await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: toArrayBuffer(packet.iv), tagLength: 128 },
        suite.gcmKey,
        toArrayBuffer(combined)
      )
    );
    return { ok: true, plaintext: fromUtf8(plaintext), reason: 'ok' };
  } catch {
    return { ok: false, plaintext: '', reason: 'aead-auth-failed' };
  }
}

export async function composeAll(suite: CryptoSuite, message: string): Promise<CompositionResult> {
  const [mte, etm, eam, aead] = await Promise.all([
    sealMtE(suite, message),
    sealEtM(suite, message),
    sealEAndM(suite, message),
    sealAead(suite, message)
  ]);
  return { mte, etm, eam, aead };
}


