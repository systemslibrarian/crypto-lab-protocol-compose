# crypto-lab-protocol-compose

## What It Is

crypto-lab-protocol-compose is a browser demo of protocol composition safety using AES-CBC, HMAC with SHA-256, and AES-256-GCM through the WebCrypto API. It compares MAC-then-Encrypt, Encrypt-then-MAC, Encrypt-and-MAC, and AEAD under one interactive interface. The project shows that composition order changes what an attacker can observe and exploit, even when each primitive is secure in isolation. The security model is symmetric-key authenticated messaging where attackers can tamper with transmitted ciphertexts and observe verifier behavior.

## When to Use It

- Use it when reviewing legacy AES-CBC + HMAC designs, because the demo shows exactly how MtE requires decryption before MAC validation.
- Use it for architecture decisions between EtM and AEAD, because the exhibits compare pre-decryption authentication versus decrypt-first workflows.
- Use it in secure coding training, because the padding oracle runner demonstrates real bytewise recovery against MtE ciphertext.
- Use it to evaluate protocol migration plans, because the TLS walkthrough maps CBC-era composition risk to TLS 1.3 AEAD-only design.
- Use it to catch common composition mistakes, because the checklist scores unsafe ordering choices such as MtE and E&M.
- Do NOT use it as a production messaging or transport security library — it is a teaching demo, not a hardened protocol stack.

## Live Demo

**[systemslibrarian.github.io/crypto-lab-protocol-compose](https://systemslibrarian.github.io/crypto-lab-protocol-compose/)**

The demo lets you encrypt a live message across composition modes and inspect resulting ciphertext/tag outputs. You can seal two messages side by side to surface the Encrypt-and-MAC equality leak, execute the padding oracle runner — whose live CBC mechanism diagram lights up the attacker-controlled byte and flips the matching plaintext byte green in step with the recovery — recover an HMAC tag from a naive comparison's timing (Lucky Thirteen) with a per-bar readout equating comparison count to elapsed time, watch the CRIME length-leak recover a session secret from its two reflected request lines, step through the TLS evolution walkthrough, and compute risk with the protocol safety checklist. Newcomer on-ramp: jargon terms (MAC, IV/nonce, AEAD, padding oracle) carry a one-line plain-language gloss on hover/focus, a "four orders as a spectrum" map frames each attack before you run it, and the AEAD exhibit is honest that AEAD only *moves* the footgun to nonce reuse. Each control is tied to real WebCrypto operations rather than simulated arithmetic, and the current configuration is encoded in the URL so a specific setup can be shared as a link.

## What Can Go Wrong

- MtE padding oracle exposure: decryption happens before MAC verification, so padding validity can become an oracle that leaks plaintext bytes.
- E&M plaintext-correlation leak: MACing plaintext separately exposes a reusable authenticator that can reveal message equality across sessions.
- TLS CBC timing side-channel (Lucky Thirteen): small processing differences during CBC record handling leak information about plaintext and padding validity.
- TLS 1.0 BEAST-era CBC composition weakness: CBC record chaining and composition details enabled practical chosen-plaintext attacks.
- Implementation pitfall in verification order: checking authenticity after decryption recreates oracle surfaces even if AES and HMAC are individually correct.
- AEAD nonce reuse: switching to AES-GCM removes the composition seam but adds one of its own — repeating a nonce under the same key collapses both confidentiality and integrity (see the linked nonce-guard demo).

## Real-World Usage

- TLS 1.0/1.1: relied on CBC-era constructions that motivated later composition hardening.
- TLS 1.2: still allowed CBC MtE suites, leaving room for Lucky Thirteen-style residual risk.
- TLS 1.3: removed CBC record protection and mandates AEAD, demonstrating safer composition by design.
- SSH (Encrypt-and-MAC variants): illustrates how separate plaintext MAC handling can leak correlations and composition metadata.
- BEAST and Lucky Thirteen case studies: concrete attacks that showed protocol composition, not primitive choice alone, determines security outcomes.

## How to Run Locally

```bash
git clone https://github.com/systemslibrarian/crypto-lab-protocol-compose
cd crypto-lab-protocol-compose
npm install
npm run dev
```

## Related Demos
- [crypto-lab-padding-oracle](https://systemslibrarian.github.io/crypto-lab-padding-oracle/) — the Vaudenay AES-CBC PKCS#7 padding oracle that MAC-then-Encrypt exposes.
- [crypto-lab-aes-modes](https://systemslibrarian.github.io/crypto-lab-aes-modes/) — AES-GCM and CBC modes, the building blocks composed here.
- [crypto-lab-nonce-guard](https://systemslibrarian.github.io/crypto-lab-nonce-guard/) — AES-GCM nonce-reuse pitfalls in the AEAD that replaces CBC composition.
- [crypto-lab-timing-oracle](https://systemslibrarian.github.io/crypto-lab-timing-oracle/) — the timing side-channels behind Lucky Thirteen and HMAC comparison leaks.
- [crypto-lab-mac-race](https://systemslibrarian.github.io/crypto-lab-mac-race/) — HMAC, CMAC, Poly1305, and GHASH, the authenticators these compositions rely on.

## Development

- `npm run dev` — local dev server.
- `npm run build` — type-check and produce the production bundle.
- `npm test` — Vitest suite covering the live crypto: composition round-trips, tamper rejection, byte-for-byte padding-oracle recovery, the E&M equality leak, CRIME compression recovery, timing-side-channel tag recovery (and its constant-time defense), and measured WCAG AA contrast for every color token in both themes.
- `npm run test:a11y` — real-browser accessibility audit (Playwright + axe-core, WCAG 2.0/2.1 A + AA) run against the production build in both light and dark themes. Run `npm run build` first.

---

*One of 120+ browser demos in the [Crypto Lab](https://crypto-lab.systemslibrarian.dev/) suite.*

*"So whether you eat or drink or whatever you do, do it all for the glory of God." — 1 Corinthians 10:31*
