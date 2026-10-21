import { makeParty, send, receive, stripAndResign, forwardToThirdParty, flipCiphertext, malleateSignature, fingerprint, publicTeachingTrace, type Mode, type Party, type Packet, type Receipt } from './signcrypt';
export const NEGATIVE = 'A valid signature inside a correctly decrypted message does not establish who the sender meant it for.';
export function signcryptMarkup(): string { return `
<section class="panel" id="ex7" aria-labelledby="ex7-title">
  <h2 id="ex7-title">Exhibit 7 — The Public-Key Seam: Sign and Encrypt</h2>
  <p>Signing proves who wrote something; encrypting decides who can read it. Doing both sounds like it gives you both. Try two ways the order lets someone change who a message appears to be from, or to, without breaking either primitive — and the small fix that stops both.</p>
  <div id="sc-parties" role="group" aria-label="Parties and public-key fingerprints">Generating fresh session keys…</div>
  <fieldset id="sc-mode"><legend>Choose the protocol</legend>
    <label><input type="radio" name="sc-protocol" value="bound" checked> Fixed: bind sender and recipient</label>
    <label><input type="radio" name="sc-protocol" value="ets"> BROKEN: encrypt then sign</label>
    <label><input type="radio" name="sc-protocol" value="ste"> BROKEN: sign then encrypt</label>
  </fieldset>
  <label for="sc-message">Sara's message to Ravi</label><textarea id="sc-message" maxlength="4096">I owe you $100.</textarea>
  <p id="sc-explain">Fixed: sign the message and recipient; encrypt the sender, message and signature. The receiver checks both identities.</p>
  <div class="btn-row"><button id="sc-send" disabled>Send</button><button id="sc-strip" disabled>Attacker: strip and re-sign</button><button id="sc-forward" disabled>Ravi: forward to Rita</button><button id="sc-flip" disabled>Flip a ciphertext byte</button><button id="sc-malleate" disabled>Test signature S + L</button></div>
  <p id="sc-status" role="status" aria-live="polite">Waiting for WebCrypto ECDH and Ed25519…</p>
  <div id="sc-results" role="status" aria-live="polite"></div>
  <details id="sc-bytes"><summary>Inspect bytes and local teaching keys</summary>
    <p>This local teaching disclosure includes the receiver's private decryption key for independent checks. The outsider attack receives only the packet and Ada's own keys. These fresh session keys are never persisted. Do not enter real secrets.</p>
    <pre id="sc-trace" tabindex="0" role="region" aria-label="Cryptographic trace"></pre>
  </details>
  <p class="note">Katz–Lindell §13.8 requires CCA-secure encryption and strongly unforgeable signatures when identities are included. Ed25519's RFC 8032 verifier must reject S + L; the control above tests that essential rule. This one test is not a proof of the whole scheme. This is a teaching composition, not a production signcryption format.</p>
  <p class="note">Read more: <a href="https://static.usenix.org/publications/library/proceedings/usenix01/full_papers/davis/davis.pdf">Davis, Defective Sign &amp; Encrypt (2001)</a>; <a href="https://eprint.iacr.org/2002/046">An, Dodis &amp; Rabin (EUROCRYPT 2002)</a>; <a href="https://www.rfc-editor.org/rfc/rfc8032.html">RFC 8032</a>. Related: <a href="https://systemslibrarian.github.io/crypto-lab-iron-letter/">Iron Letter</a>, <a href="https://systemslibrarian.github.io/crypto-lab-hpke-envelope/">HPKE Envelope</a>, <a href="https://systemslibrarian.github.io/crypto-lab-vector-gate/">Vector Gate</a>.</p>
</section>`; }
export async function wireSigncrypt(badge: (kind: 'safe' | 'warn' | 'danger', text: string) => string): Promise<void> {
  const el = <T extends HTMLElement>(id: string) => document.getElementById(id) as T;
  const escape = (s: string) => s.replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]!));
  const message = el<HTMLTextAreaElement>('sc-message');
  const controls = ['send', 'strip', 'forward', 'flip', 'malleate'] as const;
  let ready = false, busy = false, revision = 0, mode: Mode = 'bound', previousMessage = message.value;
  let parties: Party[], sara: Party, ravi: Party, ada: Party, rita: Party;
  let original: Packet | undefined, current: Packet | undefined, receiver: Party;
  function buttons() { for (const id of controls) el<HTMLButtonElement>('sc-' + id).disabled = !ready || busy || (id !== 'send' && !original) || (id === 'strip' && mode === 'ste') || (id === 'forward' && mode === 'ets'); }
  function clear() { el('sc-results').replaceChildren(); el('sc-trace').textContent = ''; }
  function retire() { revision++; busy = false; original = current = undefined; clear(); el('sc-status').textContent = 'Previous verdict retired. Send the current message.'; buttons(); }
  message.addEventListener('input', () => { if (message.value !== previousMessage) { previousMessage = message.value; retire(); } });
  el('sc-mode').addEventListener('change', () => {
    const next = (document.querySelector('input[name="sc-protocol"]:checked') as HTMLInputElement).value as Mode;
    if (next === mode) return; mode = next; retire();
    el('sc-explain').textContent = mode === 'bound' ? 'Fixed: sign the message and recipient; encrypt the sender, message and signature. The receiver checks both identities.' : mode === 'ets' ? 'BROKEN: Ada replaces Sara’s outer signature with her own. The ciphertext stays unchanged; Ada cannot decrypt it.' : 'BROKEN: Ravi decrypts Sara’s signed message and re-encrypts those exact bytes to Rita. No signed field names the intended receiver.';
  });
  function render(r: Receipt) {
    let kind: 'safe' | 'warn' | 'danger', headline: string;
    if (!r.accepted) { kind = 'safe'; headline = 'REJECTED — ' + [r.signature, r.decryption, r.identity].filter(c => c.ok === false).map(c => c.detail).join('; '); }
    else if (r.claimedSender !== sara.name) { kind = 'danger'; headline = 'SIGNATURE VALID, DECRYPTED — AND MISATTRIBUTED'; }
    else if (r.receiver !== ravi.name) { kind = 'danger'; headline = 'SIGNATURE VALID, DECRYPTED — AND FORWARDED'; }
    else { kind = mode === 'bound' ? 'safe' : 'warn'; headline = mode === 'bound' ? 'ACCEPTED — sender and recipient bound' : 'HONEST MESSAGE ACCEPTED — identities not bound'; }
    const rows = (['signature', 'decryption', 'identity'] as const).map(k => `<li id="sc-${k}" data-state="${r[k].ok === null ? 'skipped' : r[k].ok ? 'pass' : 'fail'}"><strong>${k}: ${r[k].ok === null ? 'NOT CHECKED' : r[k].ok ? 'PASS' : 'FAIL'}</strong> — ${escape(r[k].detail)}</li>`).join('');
    el('sc-results').innerHTML = `<ul>${rows}</ul><div id="sc-conclusion">${badge(kind, headline)}</div><p id="sc-belief">${escape(r.receiver)} ${r.accepted ? 'believes' : 'rejects the claim'}: ${escape(r.claimedSender)} wrote this${mode !== 'ets' ? ' to ' + escape(r.receiver) : ''}. Signature checked under ${escape(r.verifiedSigner || 'no key')}.</p><p id="sc-plaintext">Message: ${escape(r.message)}</p>${r.accepted && r.claimedSender !== sara.name ? '<p id="sc-reply">Modelled auto-reply precondition: Ravi quotes the message back to the claimed sender Ada: “' + escape(r.message) + '”. Ada learns it through Ravi’s behaviour; she never decrypted the ciphertext.</p>' : ''}${r.accepted && r.receiver !== ravi.name ? '<p id="sc-negative">' + escape(NEGATIVE) + '</p>' : ''}`;
  }
  async function act(action: typeof controls[number]) {
    if (!ready || busy) return;
    const token = ++revision, chosenMode = mode, typed = message.value;
    busy = true; clear(); buttons(); el('sc-status').textContent = 'Running real WebCrypto checks…';
    try {
      let packet: Packet, target = receiver ?? ravi;
      if (action === 'send') { packet = await send(chosenMode, sara, ravi, typed); target = ravi; }
      else if (action === 'strip') { packet = await stripAndResign(original!, ada); target = ravi; }
      else if (action === 'forward') { packet = await forwardToThirdParty(original!, ravi, rita); target = rita; }
      else if (action === 'flip') packet = flipCiphertext(current!);
      else packet = await malleateSignature(current!, target);
      const receipt = await receive(packet, target, parties);
      const trace = await publicTeachingTrace(packet, target, parties);
      if (token !== revision) return;
      current = packet; receiver = target; if (action === 'send') original = packet;
      render(receipt); el('sc-trace').textContent = JSON.stringify(trace, null, 2);
      if (action === 'malleate' && receipt.signature.ok !== false) {
        ready = false; el('sc-conclusion').innerHTML = badge('danger', 'PLATFORM FINDING — exhibit stopped');
        el('sc-status').textContent = 'PLATFORM FINDING: WebCrypto accepted S + L. This exhibit is stopped; no fallback is used.';
      } else el('sc-status').textContent = 'Checks complete. Verdict derived from the displayed cryptographic checks.';
    } catch (error) { if (token === revision) { original = current = undefined; el('sc-status').textContent = error instanceof Error ? error.message : String(error); } }
    finally { if (token === revision) { busy = false; buttons(); } }
  }
  for (const id of controls) el('sc-' + id).addEventListener('click', () => { void act(id); });
  try {
    [sara, ravi, ada] = await Promise.all(['Sara', 'Ravi', 'Ada'].map(makeParty)); rita = { ...ada, name: 'Rita' }; parties = [sara, ravi, ada, rita]; receiver = ravi;
    el('sc-parties').innerHTML = (await Promise.all([sara, ravi, ada].map(async p => `<div class="card"><h3>${p === ada ? 'Ada / Rita' : p.name}</h3><p>ECDH fingerprint<br><code>${await fingerprint(p.encryption.publicKey)}</code></p><p>Ed25519 fingerprint<br><code>${await fingerprint(p.signing.publicKey)}</code></p></div>`))).join('');
    ready = true; el('sc-status').textContent = 'Fresh ECDH and Ed25519 keys ready. Send a message.'; buttons();
  } catch { el('sc-status').textContent = 'ECDH or Ed25519 unavailable in this browser. Exhibit refused; no fallback is used.'; buttons(); }
}
