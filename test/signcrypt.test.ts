import { beforeAll, expect, test } from 'vitest';
import vectors from './ed25519-rfc8032.json';
import { makeParty, send, receive, eciesOpen, eciesSeal, stripAndResign, forwardToThirdParty, flipCiphertext, malleateSignature, addOrder, verify, hex, unhex, utf, type Party, type Mode } from '../src/signcrypt';

// Published RFC 8032 §7.1 TEST 1, 2, 3, 1024 (the last message has 1023 bytes).
for (const v of vectors) test(`RFC 8032 TEST ${v.name}: exact signature and strict S`, async () => {
  const privateKey = await crypto.subtle.importKey('pkcs8', unhex('302e020100300506032b657004220420' + v.seed), 'Ed25519', false, ['sign']);
  const publicKey = await crypto.subtle.importKey('raw', unhex(v.publicKey), 'Ed25519', false, ['verify']);
  expect(hex(new Uint8Array(await crypto.subtle.sign('Ed25519', privateKey, unhex(v.message))))).toBe(v.signature);
  expect(await verify(publicKey, unhex(v.message), v.signature)).toBe(true);
  expect(await verify(publicKey, unhex(v.message), addOrder(v.signature))).toBe(false);
});

// RFC 5903 §8.1, P-256 initiator/responder. Iron Letter's fixture is locally
// generated, not a published ECDH KAT; this independently published pin replaces
// the brief's mistaken attribution, without changing the production ECIES path.
test('RFC 5903 P-256 shared x coordinate in both directions', async () => {
  const points = [
    ['c88f01f510d9ac3f70a292daa2316de544e9aab8afe84049c62a9c57862d1433', 'dad0b65394221cf9b051e1feca5787d098dfe637fc90b9ef945d0c3772581180', '5271a0461cdb8252d61f1c456fa3e59ab1f45b33accf5f58389e0577b8990bb3'],
    ['c6ef9c5d78ae012a011164acb397ce2088685d8f06bf9be0b283ab46476bee53', 'd12dfb5289c8d4f81208b70270398c342296970a0bccb74c736fc7554494bf63', '56fbf3ca366cc23e8157854c13c58d6aac23f046ada30f8353e74f33039872ab'],
  ];
  const b64 = (s: string) => Buffer.from(s, 'hex').toString('base64url');
  const keys = await Promise.all(points.map(async ([d,x,y]) => ({
    privateKey: await crypto.subtle.importKey('jwk', { kty: 'EC', crv: 'P-256', d: b64(d), x: b64(x), y: b64(y) }, { name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveBits']),
    publicKey: await crypto.subtle.importKey('raw', unhex('04' + x + y), { name: 'ECDH', namedCurve: 'P-256' }, false, []),
  })));
  for (let i = 0; i < 2; i++) expect(hex(new Uint8Array(await crypto.subtle.deriveBits({ name: 'ECDH', public: keys[1-i].publicKey }, keys[i].privateKey, 256)))).toBe('d6840f6b42f6edafd13116e0e12565202fef8e9ece7dce03812464d04b9442de');
});
let sara: Party, ravi: Party, ada: Party, rita: Party, parties: Party[];
beforeAll(async () => { [sara, ravi, ada] = await Promise.all(['Sara', 'Ravi', 'Ada'].map(makeParty)); rita = { ...ada, name: 'Rita' }; parties = [sara, ravi, ada, rita]; });
for (const mode of ['bound', 'ets', 'ste'] as Mode[]) {
  test(`${mode}: honest round trip and real GCM rejection`, async () => {
    const p = await send(mode, sara, ravi, 'I owe you $100. 🐈');
    const good = await receive(p, ravi, parties);
    expect(good.accepted).toBe(true); expect(good.message).toBe('I owe you $100. 🐈');
    const bad = await receive(flipCiphertext(p), ravi, parties);
    expect(bad.decryption.ok).toBe(false); expect(bad.accepted).toBe(false);
  });
  test(`${mode}: S plus L is rejected by WebCrypto itself`, async () => {
    const p = await malleateSignature(await send(mode, sara, ravi, 'test'), ravi);
    const r = await receive(p, ravi, parties); expect(r.decryption.ok).toBe(true); expect(r.signature.ok).toBe(false); expect(r.accepted).toBe(false);
  });
}
test('naive strip passes all checks and misattributes unchanged ciphertext', async () => {
  const p = await send('ets', sara, ravi, 'I owe you $100.'); const attack = await stripAndResign(p, ada);
  expect(attack.envelope).toEqual(p.envelope);
  const r = await receive(attack, ravi, parties); expect([r.signature.ok,r.decryption.ok,r.identity.ok,r.accepted]).toEqual([true,true,true,true]); expect(r.verifiedSigner).toBe('Ada'); expect(r.claimedSender).toBe('Ada');
});
test('naive forwarding preserves every signed byte but changes recipient', async () => {
  const p = await send('ste', sara, ravi, 'I owe you $100.'); const attack = await forwardToThirdParty(p, ravi, rita);
  expect(await eciesOpen(rita, attack.envelope)).toEqual(await eciesOpen(ravi, p.envelope));
  const r = await receive(attack, rita, parties); expect([r.signature.ok,r.decryption.ok,r.identity.ok,r.accepted]).toEqual([true,true,true,true]); expect(r.verifiedSigner).toBe('Sara'); expect(r.receiver).toBe('Rita'); expect(r.signedRecipient).toBe('');
});
test('bound strip rejects the actual inner and outer sender mismatch', async () => {
  const r = await receive(await stripAndResign(await send('bound', sara, ravi, 'test'), ada), ravi, parties);
  expect(r.signature.ok).toBe(true); expect(r.decryption.ok).toBe(true); expect(r.accepted).toBe(false); expect(r.identity.detail).toBe('inner sender Sara, outer sender Ada');
});
test('bound forwarding rejects the actual signed recipient mismatch', async () => {
  const r = await receive(await forwardToThirdParty(await send('bound', sara, ravi, 'test'), ravi, rita), rita, parties);
  expect(r.signature.ok).toBe(true); expect(r.decryption.ok).toBe(true); expect(r.accepted).toBe(false); expect(r.identity.detail).toBe('signed for Ravi, received by Rita');
});
test('changing the signed recipient to Rita destroys the signature', async () => {
  const p = await send('bound', sara, ravi, 'test'); const a = JSON.parse(new TextDecoder().decode(await eciesOpen(ravi,p.envelope))); a[2] = 'Rita';
  const r = await receive({ ...p, envelope: await eciesSeal(rita, utf(JSON.stringify(a))) }, rita, parties);
  expect(r.identity.ok).toBe(true); expect(r.signature.ok).toBe(false); expect(r.accepted).toBe(false);
});
test('ECIES uses fresh ephemeral keys and IVs; wrong keys and malformed bytes reject', async () => {
  const a = await eciesSeal(ravi, utf('same')), b = await eciesSeal(ravi, utf('same'));
  expect(a.ephemeral).not.toBe(b.ephemeral); expect(a.iv).not.toBe(b.iv); expect(a.ciphertext).not.toBe(b.ciphertext);
  await expect(eciesOpen(ada, a)).rejects.toThrow(); await expect(eciesOpen(ravi, { ...a, ephemeral: '00' })).rejects.toThrow();
});
test('empty and overlong UTF-8 messages refuse before producing a packet', async () => {
  await expect(send('bound', sara, ravi, '  ')).rejects.toThrow('Empty'); await expect(send('bound', sara, ravi, '🐈'.repeat(1100))).rejects.toThrow('4096');
});
