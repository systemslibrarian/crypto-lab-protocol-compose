/** Inspectable teaching protocols, not a production signcryption wire format.
 * ECIES pattern: Iron Letter (P-256 / HKDF / AES-GCM); Ed25519: SSH Handshake.
 * No key persistence and no signature fallback. */
export type Mode = 'bound' | 'ets' | 'ste';
export interface Party { name: string; encryption: CryptoKeyPair; signing: CryptoKeyPair }
export interface Envelope { ephemeral: string; iv: string; ciphertext: string }
export interface Packet { mode: Mode; sender: string; envelope: Envelope; outerSignature?: string }
export interface Check { ok: boolean | null; detail: string }
export interface Receipt {
  signature: Check; decryption: Check; identity: Check; accepted: boolean;
  receiver: string; claimedSender: string; verifiedSigner: string; message: string;
  signedRecipient: string; innerSender: string; signedHex: string; signatureHex: string; plaintextHex: string;
}
export const INFO = 'protocol-compose-exhibit7-ecies-v1';
export const utf = (s: string) => new TextEncoder().encode(s);
export const hex = (b: Uint8Array) => Array.from(b, x => x.toString(16).padStart(2, '0')).join('');
export function unhex(s: string): Uint8Array<ArrayBuffer> {
  if (!/^(?:[0-9a-f]{2})*$/i.test(s)) throw new Error('Malformed hex');
  return Uint8Array.from(s.match(/../g) ?? [], x => parseInt(x, 16));
}
const encode = (v: string[]) => utf(JSON.stringify(v));
const text = (b: Uint8Array) => new TextDecoder('utf-8', { fatal: true }).decode(b);
export async function makeParty(name: string): Promise<Party> {
  const [encryption, signing] = await Promise.all([
    crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']),
    crypto.subtle.generateKey('Ed25519', true, ['sign', 'verify']),
  ]);
  return { name, encryption, signing };
}
async function derive(privateKey: CryptoKey, publicKey: CryptoKey): Promise<CryptoKey> {
  const shared = await crypto.subtle.deriveBits({ name: 'ECDH', public: publicKey }, privateKey, 256);
  const ikm = await crypto.subtle.importKey('raw', shared, 'HKDF', false, ['deriveKey']);
  // [extension] point: HPKE's info/AAD binding is a modern version of this seam.
  return crypto.subtle.deriveKey({ name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(32), info: utf(INFO) }, ikm, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}
export async function eciesSeal(receiver: Party, plaintext: Uint8Array<ArrayBuffer>): Promise<Envelope> {
  const ephemeral = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
  const key = await derive(ephemeral.privateKey, receiver.encryption.publicKey);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  return { ephemeral: hex(new Uint8Array(await crypto.subtle.exportKey('raw', ephemeral.publicKey))), iv: hex(iv), ciphertext: hex(new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv, tagLength: 128 }, key, plaintext))) };
}
export async function eciesOpen(receiver: Party, envelope: Envelope): Promise<Uint8Array<ArrayBuffer>> {
  if (!/^04[0-9a-f]{128}$/i.test(envelope.ephemeral) || !/^[0-9a-f]{24}$/i.test(envelope.iv) || envelope.ciphertext.length < 32) throw new Error('Malformed ECIES envelope');
  const ephemeral = await crypto.subtle.importKey('raw', unhex(envelope.ephemeral), { name: 'ECDH', namedCurve: 'P-256' }, false, []);
  const key = await derive(receiver.encryption.privateKey, ephemeral);
  return new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: unhex(envelope.iv), tagLength: 128 }, key, unhex(envelope.ciphertext)));
}
export async function sign(party: Party, data: Uint8Array<ArrayBuffer>): Promise<string> {
  return hex(new Uint8Array(await crypto.subtle.sign('Ed25519', party.signing.privateKey, data)));
}
export async function verify(key: CryptoKey, data: Uint8Array<ArrayBuffer>, signature: string): Promise<boolean> {
  try { return await crypto.subtle.verify('Ed25519', key, unhex(signature), data); } catch { return false; }
}
export const envelopeBytes = (c: Envelope) => encode([c.ephemeral, c.iv, c.ciphertext]);
// [extension] point: compare signing the ciphertext AND the recipient.
export const boundSignedBytes = (message: string, recipient: string) => encode(['exhibit7-bound-v1', message, recipient]);
export async function send(mode: Mode, sender: Party, receiver: Party, message: string): Promise<Packet> {
  if (!message.trim()) throw new Error('Empty message: enter a message before sending.');
  if (utf(message).length > 4096) throw new Error('Message exceeds 4096 UTF-8 bytes.');
  if (mode === 'ets') {
    const envelope = await eciesSeal(receiver, utf(message));
    return { mode, sender: sender.name, envelope, outerSignature: await sign(sender, envelopeBytes(envelope)) };
  }
  const signature = await sign(sender, mode === 'ste' ? utf(message) : boundSignedBytes(message, receiver.name));
  return { mode, sender: sender.name, envelope: await eciesSeal(receiver, encode(mode === 'ste' ? [message, signature] : [sender.name, message, receiver.name, signature])) };
}
export async function receive(packet: Packet, receiver: Party, parties: Party[]): Promise<Receipt> {
  const skipped = (): Check => ({ ok: null, detail: 'Not checked' });
  const r: Receipt = { signature: skipped(), decryption: skipped(), identity: skipped(), accepted: false, receiver: receiver.name, claimedSender: packet.sender, verifiedSigner: '', message: '', signedRecipient: '', innerSender: '', signedHex: '', signatureHex: '', plaintextHex: '' };
  const checkSignature = async (name: string, data: Uint8Array<ArrayBuffer>, signature: string) => {
    const signer = parties.find(p => p.name === name);
    const ok = !!signer && await verify(signer.signing.publicKey, data, signature);
    r.signedHex = hex(data); r.signatureHex = signature; r.verifiedSigner = name;
    r.signature = { ok, detail: `${name}'s Ed25519 signature ${ok ? 'verifies' : 'does not verify'}` };
  };
  if (packet.mode === 'ets') await checkSignature(packet.sender, envelopeBytes(packet.envelope), packet.outerSignature ?? '');
  let plaintext: Uint8Array<ArrayBuffer>;
  try { plaintext = await eciesOpen(receiver, packet.envelope); r.decryption = { ok: true, detail: `AES-GCM decrypted and authenticated for ${receiver.name}` }; r.plaintextHex = hex(plaintext); }
  catch { r.decryption = { ok: false, detail: 'AES-GCM authentication/decryption failed' }; return r; }
  try {
    if (packet.mode === 'ets') r.message = text(plaintext);
    else {
      const payload: unknown = JSON.parse(text(plaintext));
      if (!Array.isArray(payload) || payload.length !== (packet.mode === 'ste' ? 2 : 4) || payload.some(x => typeof x !== 'string')) throw new Error('Malformed signed payload');
      if (packet.mode === 'ste') { r.message = payload[0]; await checkSignature(packet.sender, utf(r.message), payload[1]); }
      else {
        [r.innerSender, r.message, r.signedRecipient] = payload;
        const signed = boundSignedBytes(r.message, r.signedRecipient);
        await checkSignature(r.innerSender, signed, payload[3]);
        const senderMatches = r.innerSender === packet.sender;
        const recipientMatches = hex(boundSignedBytes(r.message, receiver.name)) === hex(signed);
        r.identity = { ok: senderMatches && recipientMatches, detail: !senderMatches ? `inner sender ${r.innerSender}, outer sender ${packet.sender}` : !recipientMatches ? `signed for ${r.signedRecipient}, received by ${receiver.name}` : `sender ${r.innerSender} and recipient ${receiver.name} bound` };
      }
    }
    if (packet.mode !== 'bound') r.identity = { ok: true, detail: 'Naive policy passes: no signed recipient exists (not identity evidence)' };
    r.accepted = r.signature.ok === true && r.decryption.ok === true && r.identity.ok === true;
  } catch { r.identity = { ok: false, detail: 'Malformed signed payload rejected' }; }
  return r;
}
/** Outsider sees only the packet and her own signing key, never Ravi's key. */
export async function stripAndResign(packet: Packet, ada: Party): Promise<Packet> {
  return { ...packet, envelope: { ...packet.envelope }, sender: ada.name, outerSignature: await sign(ada, envelopeBytes(packet.envelope)) };
}
/** A malicious intended receiver re-encrypts the exact decrypted payload. */
export async function forwardToThirdParty(packet: Packet, ravi: Party, rita: Party): Promise<Packet> {
  if (packet.mode === 'ets') throw new Error('Use the strip attack for encrypt-then-sign');
  return { ...packet, envelope: await eciesSeal(rita, await eciesOpen(ravi, packet.envelope)) };
}
export function flipCiphertext(packet: Packet): Packet {
  const bytes = unhex(packet.envelope.ciphertext); bytes[0] ^= 1;
  return { ...packet, envelope: { ...packet.envelope, ciphertext: hex(bytes) } };
}
export function addOrder(signature: string): string {
  const bytes = unhex(signature); if (bytes.length !== 64) throw new Error('Expected 64-byte Ed25519 signature');
  let s = 0n; for (let i = 63; i >= 32; i--) s = (s << 8n) + BigInt(bytes[i]);
  s += (1n << 252n) + 27742317777372353535851937790883648493n;
  for (let i = 32; i < 64; i++) { bytes[i] = Number(s & 255n); s >>= 8n; }
  return hex(bytes);
}
export async function malleateSignature(packet: Packet, receiver: Party): Promise<Packet> {
  if (packet.mode === 'ets') return { ...packet, outerSignature: addOrder(packet.outerSignature!) };
  const payload: string[] = JSON.parse(text(await eciesOpen(receiver, packet.envelope)));
  payload[payload.length - 1] = addOrder(payload[payload.length - 1]);
  return { ...packet, envelope: await eciesSeal(receiver, encode(payload)) };
}
export async function fingerprint(key: CryptoKey): Promise<string> {
  return hex(new Uint8Array(await crypto.subtle.digest('SHA-256', await crypto.subtle.exportKey('raw', key))));
}
/** Explicit local teaching disclosure. Never an input to the outsider attack. */
export async function publicTeachingTrace(packet: Packet, receiver: Party, parties: Party[]) {
  return { packet, receiver: receiver.name, receiverPrivateKey: await crypto.subtle.exportKey('jwk', receiver.encryption.privateKey), signingKeys: Object.fromEntries(await Promise.all(parties.map(async p => [p.name, hex(new Uint8Array(await crypto.subtle.exportKey('raw', p.signing.publicKey)))]))), info: INFO, salt: '00'.repeat(32) };
}
