import { expect, type Page } from '@playwright/test';
import { createPublicKey, createPrivateKey, diffieHellman, hkdfSync, createDecipheriv, verify } from 'node:crypto';
export async function scReady(page: Page) { await expect(page.locator('#sc-send')).toBeEnabled(); }
export async function scMode(page: Page, mode: string) { await scReady(page); await page.locator(`input[name="sc-protocol"][value="${mode}"]`).check(); }
export async function scAction(page: Page, action: string) {
  await page.locator('#sc-' + action).click();
  await expect(page.locator('#sc-status')).toHaveText(/Checks complete|PLATFORM FINDING/);
  if (!await page.locator('#sc-bytes').getAttribute('open').then(v => v !== null)) await page.locator('#sc-bytes summary').click();
}
// These checks import no application code. Derive the ECDH/HKDF/AES key and
// Ed25519 signed transcript independently from the disclosure's exact bytes.
export async function independentReceipt(page: Page) {
  const trace = JSON.parse(await page.locator('#sc-trace').innerText());
  const p = trace.packet, c = p.envelope;
  const ephemeral = Buffer.from(c.ephemeral, 'hex');
  const epk = createPublicKey({ format: 'jwk', key: { kty: 'EC', crv: 'P-256', x: ephemeral.subarray(1,33).toString('base64url'), y: ephemeral.subarray(33).toString('base64url') } });
  const secret = diffieHellman({ privateKey: createPrivateKey({ format: 'jwk', key: trace.receiverPrivateKey }), publicKey: epk });
  const key = hkdfSync('sha256', secret, Buffer.alloc(32), Buffer.from('protocol-compose-exhibit7-ecies-v1'), 32);
  let decrypted = false, signature: boolean | null = null, identity: boolean | null = null, signer = p.sender, message = '', innerSender = '', recipient = '', plaintext = Buffer.alloc(0);
  const check = (name: string, data: Buffer, sig: string) => verify(null, data, createPublicKey({ format: 'der', type: 'spki', key: Buffer.concat([Buffer.from('302a300506032b6570032100','hex'),Buffer.from(trace.signingKeys[name],'hex')]) }),Buffer.from(sig,'hex'));
  if (p.mode === 'ets') signature = check(signer, Buffer.from(JSON.stringify([c.ephemeral,c.iv,c.ciphertext])),p.outerSignature);
  try {
    const ct = Buffer.from(c.ciphertext,'hex'), dec = createDecipheriv('aes-256-gcm',key,Buffer.from(c.iv,'hex')); dec.setAuthTag(ct.subarray(-16));
    plaintext = Buffer.concat([dec.update(ct.subarray(0,-16)),dec.final()]); decrypted = true;
    if (p.mode === 'ets') { message = plaintext.toString(); identity = true; }
    else {
      const a = JSON.parse(plaintext.toString());
      if (p.mode === 'ste') { message = a[0]; signature = check(signer,Buffer.from(message),a[1]); identity = true; }
      else { [innerSender,message,recipient] = a; signer = innerSender; signature = check(signer,Buffer.from(JSON.stringify(['exhibit7-bound-v1',message,recipient])),a[3]); identity = innerSender === p.sender && recipient === trace.receiver; }
    }
  } catch (error) { if (decrypted) throw error; }
  for (const [name,state] of [['signature',signature],['decryption',decrypted],['identity',identity]] as const) await expect(page.locator('#sc-'+name), `Node independently rederived ${name}`).toHaveAttribute('data-state',state===null?'skipped':state?'pass':'fail');
  return { trace, signature, decrypted, identity, signer, message, innerSender, recipient, plaintext };
}
