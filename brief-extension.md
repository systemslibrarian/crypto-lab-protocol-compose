# Extension brief — `crypto-lab-protocol-compose`

**2026-10-20. Extension to a live lab; no new repository.** Written against
`crypto-lab-protocol-compose` at `f5c0b60c2614` and `audits/_MASTER-TEMPLATE.md`
(catalog `f48d9d2f2f06`). Template §5: "Extend, never restructure." Source of the gap:
Katz–Lindell, *Introduction to Modern Cryptography*, 3rd ed., §13.8 (Signcryption).

**Verdict: extension — a new "Exhibit 7 — The Public-Key Seam: Sign and Encrypt",
appended after Exhibit 6. No renumbering.**

## What the lab has now

Read at `f5c0b60c2614`:

- Symmetric compositions only, all WebCrypto, **no runtime dependencies**
  (`package.json` has devDependencies only): AES-CBC + HMAC-SHA-256 in MtE / EtM / E&M,
  and AES-256-GCM (`src/compose.ts:46–63`, `sealMtE`…`openAead`, `composeAll`).
- Exhibits in `src/main.ts`: intro (95), Exhibit 1 four orders (118), spectrum (177),
  Exhibit 2 padding oracle (195), Exhibit 3 timing (281), Exhibit 4 CRIME (342),
  Exhibit 5 TLS walkthrough (389), Exhibit 6 checklist (401). Badges are `safe` / `warn` /
  `danger` via `badge()`.
- **Sign-then-encrypt is one sentence**, in a note at the end of Exhibit 4
  (`src/main.ts:382–385`): *"…and sign-then-encrypt (a signed plaintext can be peeled off
  and forwarded by someone else)."* Encrypt-then-sign is not mentioned.
- `e2e/claims.spec.ts` covers Exhibits 1–6 by name in its header comment (lines 14–32) and
  tests; `e2e/gate.ts:254` asserts `section.panel` count **8**. There is **no §4.1d
  negative-claim test** (`grep -in negative e2e/claims.spec.ts` → nothing) and **no mutation
  script** (no `scripts/` directory) at this commit.
- README "Development" still says the a11y audit runs "in both light and dark themes" —
  stale since the fleet pinned dark; correct it in the same README pass.
- Neighbours read for reuse: `crypto-lab-iron-letter` at `0d6257cdad49` implements ECIES
  as ephemeral ECDH P-256 + HKDF-SHA-256 + AES-256-GCM in `src/crypto/ecies.ts` (`seal`,
  `open`); `crypto-lab-ssh-handshake` at `b7e334bc33fa` uses WebCrypto `Ed25519`
  (`src/engine.ts`). Copy the pattern, not the module — no cross-repo import.
- A grep of the sibling clones on 2026-10-20 for
  `signcrypt|surreptitious|sign.then.encrypt|encrypt.then.sign` matched only the
  sentence above (and one unrelated DNS paper title in `crypto-lab-covert-channel-studio`).
  Re-run it before building.

## What to add

Three parties, real keys: **Sara** (sender), **Ravi** (receiver), and a third party who
plays the attacker in two roles — **Ada** (an outsider on the wire) and **Rita** (a second
receiver). Each has an encryption key pair (ECDH P-256, ECIES as Iron Letter builds it) and
a signing key pair (Ed25519 via WebCrypto). Sara's message defaults to
"I owe you $100." — Katz–Lindell's own example.

1. **Encrypt-then-sign, and the strip.** Sara sends `⟨Sara, c, Sign_Sara(c)⟩` with
   `c = Enc_Ravi(m)`. Ada, who cannot decrypt `c`, removes Sara's signature and sends
   `⟨Ada, c, Sign_Ada(c)⟩`. Ravi's real checks: signature valid (under Ada's key),
   decryption succeeds, `m` intact. Ravi now believes **Ada** wrote `m`. A modelled
   auto-reply ("Ravi quotes the message back to whoever sent it") hands `m` to Ada —
   labelled as a modelled behaviour of Ravi, which is the precondition Katz–Lindell name.
2. **Sign-then-encrypt, and the forward.** Sara sends `⟨Sara, Enc_Ravi(m ‖ σ)⟩` with
   `σ = Sign_Sara(m)`. Ravi, now malicious, decrypts, re-encrypts the same `m ‖ σ` to Rita,
   and sends `⟨Sara, Enc_Rita(m ‖ σ)⟩`. Rita's real checks: decryption succeeds, Sara's
   signature verifies. Rita believes Sara wrote "I owe you $100." **to her**. This is Davis's
   *surreptitious forwarding*.
3. **Bind the identities (the fix).** Katz–Lindell's repair: sign `m ‖ recipient`, and
   encrypt `sender ‖ m ‖ σ`. Re-run both attacks: Ravi checks the decrypted sender field
   against the outer sender, so Ada's re-signed `c` fails ("inner sender Sara, outer sender
   Ada"); Rita checks that what was signed names her, so Ravi's forward fails ("signed for
   Ravi, received by Rita"). Each failure names its cause.

**The one headline mechanism:** every primitive check passes in steps 1 and 2 — the
signature, the decryption, the integrity — and the conclusion the receiver draws is still
wrong, because neither layer says **who the other layer was for**.

**Plain-language intro (no math):** Signing proves who wrote something; encrypting decides
who can read it. Doing both sounds like it gives you both. This exhibit shows two ways the
order of the two lets someone change *who* the message appears to be from, or *to*, without
breaking either one — and the small fix that stops both.

**One scoping sentence on the page:** Katz–Lindell state that with identities included,
both orders are secure when the encryption is CCA-secure and the signature scheme is
**strongly** unforgeable. The exhibit therefore uses Ed25519, whose RFC 8032 verification
rejects an out-of-range `S`, and a claims test checks that a malleated signature is rejected
(below) instead of asserting the property in prose.

## Why it belongs here and not in a new lab

This lab's thesis is "each piece is fine, the seam is not", and it already names
sign-then-encrypt as an instance. Exhibit 7 is the public-key version of Exhibit 1's
ordering question, with the same kind of verdicts.

## SECURITY / CORRECTNESS INVARIANTS

1. All five operations are real WebCrypto: ECDH P-256, HKDF-SHA-256, AES-256-GCM (ECIES),
   Ed25519 sign/verify. Nothing about acceptance is simulated; only Ravi's auto-reply in
   step 1 is modelled, and it is labelled.
2. Every key pair is generated per session in memory; none is persisted.
3. The fixed version is the default selection; the two naive versions are visibly marked
   broken when selected.
4. Each receiver verdict is derived from the receiver's actual checks, displayed one by one
   (signature / decryption / identity), never from a flag the attack sets.
5. If WebCrypto `Ed25519` or `ECDH` is unavailable, the exhibit refuses with a message — it
   does not fall back to another signature scheme silently.
6. Exhibits 1–6, their verdicts, the URL-hash state, and `src/compose.ts` are unchanged.

## ARCHITECTURE

- `src/signcrypt.ts` — `makeParty(name)`, `eciesSeal/eciesOpen` (pattern from
  `crypto-lab-iron-letter/src/crypto/ecies.ts`, with this lab's own HKDF info string),
  `sign/verify` (Ed25519), and the three protocols: `encThenSign`, `signThenEnc`,
  `boundIdentities` (each with `send` and `receive` returning per-check results), plus the
  two attacker functions `stripAndResign` and `forwardToThirdParty`.
- `test/signcrypt.test.ts` — Vitest, beside the existing `test/compose.test.ts`.
- `src/main.ts` — Exhibit 7 markup after Exhibit 6; wiring at the bottom with the other
  exhibits.
- `// [extension] point`s: (a) in `signcrypt.ts` for a "sign the ciphertext *and* the
  recipient" variant comparison; (b) a seam for HPKE's `info`/AAD binding as the modern
  shape of the same fix (link to `crypto-lab-hpke-envelope` in prose).

## UI

A three-column party strip (Sara · Ravi · Ada/Rita) with each party's public-key
fingerprints. A radio group for the protocol (fixed / encrypt-then-sign /
sign-then-encrypt), a message field, and buttons "Send", "Attacker: strip and re-sign",
"Ravi: forward to Rita". Each receiver shows a three-row check list (signature, decryption,
identity binding) and a conclusion line ("Ravi believes: Ada wrote this"). Results
`role="status" aria-live="polite"`. Stacks below 640px. Show bytes behind a disclosure, not
by default.

## VISUAL SEMANTICS

- Steps 1–2, naive protocols: every check row reads its true success state, and the
  **conclusion** reads `danger` — "SIGNATURE VALID, DECRYPTED — AND MISATTRIBUTED" /
  "— AND FORWARDED". Integrity colour tracks the conclusion, not the per-check returns.
- Step 3: the identity row fails with its cause, the conclusion reads `safe`
  ("REJECTED — signed for Ravi, received by Rita").
- Use the lab's existing `badge('safe' | 'warn' | 'danger', …)`; never colour alone.

## EDGE CASES

| Situation | Behaviour |
|---|---|
| Empty message | refuse to send; say why |
| Tampered ciphertext byte (offer a "flip a byte" control) | decryption fails (AES-GCM) — shown as the encryption layer working, distinct from the identity failures |
| Ed25519 signature with `S` replaced by `S + L` | verification fails; the page says strong unforgeability is why the fix holds. If the CI browser's WebCrypto **accepts** it, stop and report that as a platform finding — do not drop the test or switch libraries quietly (see `crypto-lab-vector-gate` for what that check is) |
| Attacker button pressed before "Send" | disabled until a message exists |
| Switching protocol or editing the message | retire every Exhibit 7 verdict and say it was retired |

## Tests

**KATs:** Ed25519 against RFC 8032 §7.1 test vectors including at least one multi-block
message (TEST 1024 or TEST SHA(abc)), via WebCrypto import of the RFC's raw keys; ECDH P-256
as Iron Letter checks it — `crypto-lab-iron-letter/src/__tests__/known-answer-vectors.test.ts`
references ECDH at `0d6257cdad49`; read which published vector it pins and reuse that one
rather than inventing one. AES-256-GCM already
runs here through WebCrypto; no new GCM vector is required.

**Vitest (`test/signcrypt.test.ts`):** each naive protocol accepts the attacked message with
every check passing and the wrong attribution; the bound protocol rejects both attacks and
reports the cause; a byte flip fails decryption; an `S + L` signature fails verification.

**`e2e/claims.spec.ts` additions** — independent re-derivation with `node:crypto`
(`verify(null, data, ed25519PublicKey, sig)` and Node ECDH/HKDF/AES-GCM), not the page's
module:
- for each displayed check, recompute it in Node from the bytes behind the disclosure and
  assert the row's state matches;
- the conclusion line names the party whose key verified the signature (step 1) and the
  recipient the ciphertext was sealed to (step 2), read from the bytes, not from labels;
- step 3's failure text names the mismatched identities actually present in the decrypted
  bytes;
- retirement on protocol switch and on message edit; the no-op guard (re-selecting the
  same protocol does not retire a fresh verdict).

**§4.1c** — Exhibit 7 renders verdicts, so record its mutations as concrete patches run from
a script, per §4.1c's verdict-marker rule; model the runner on
`crypto-lab-wep-crack/scripts/mutations.mjs` or `crypto-lab-lfsr-forge/scripts/mutation-check.mjs`
(both exist at their HEADs). At minimum:
1. Drop the recipient field from what is signed in `boundIdentities` → the step 3 forward
   test fails.
2. Drop the sender-field comparison on receipt → the step 3 strip test fails.
3. Make `receive` report "signature valid" without calling verify → the Node re-check fails.
4. Hard-wire the conclusion to `safe` → the step 1 conclusion test fails.

**§4.1d negative claim (this lab's first):**
> *"A valid signature inside a correctly decrypted message does not establish who the
> sender meant it for."*

Evidence fixture: sign-then-encrypt, Ravi forwards to Rita. Every check Rita performs reads
success (decryption, Sara's signature), the conclusion reads **"SIGNATURE VALID, DECRYPTED —
AND FORWARDED"**, and the sentence is on screen in that state. Assert all three; deleting the
sentence and breaking a check must each fail a named assertion.

**Structural gate:** `e2e/gate.ts:254` → 9 panels. Update the `claims.spec.ts` header
comment's exhibit list to include Exhibit 7.

## README and card follow-up

- "What It Is": add one sentence: Exhibit 7 extends the composition question to signatures
  and public-key encryption (ECDH P-256 ECIES + Ed25519, WebCrypto).
- "What Can Go Wrong": add "signature stripping (encrypt-then-sign)" and "surreptitious
  forwarding (sign-then-encrypt)", each with the identity-binding fix.
- "Development": correct "in both light and dark themes" to the dark-only page.
- Replace the Exhibit 4 note's sign-then-encrypt clause (`src/main.ts:384–385`) with
  "…and the public-key seam in Exhibit 7", so the one-line summary and the exhibit cannot
  disagree.
- Catalog handoff (do not edit `../crypto-lab`): chips may gain `Ed25519`, `ECDH`, `ECIES`
  (implemented). Related-demo links: Iron Letter, HPKE Envelope, Vector Gate.

## Do not touch

`src/compose.ts`, `src/attacks.ts`, `src/timing.ts`, `src/crime.ts` behaviour, Exhibits 1–6,
the URL-hash state keys, header, theme pin, footer.

## Sources

- Katz & Lindell, *Introduction to Modern Cryptography*, 3rd ed., CRC Press, 2021 (ISBN
  9780815354369): §13.8 — both attacks, the identity-binding fix, and the requirement of
  CCA-secure encryption plus strongly secure signatures; the "I owe you $100" example.
- D. Davis, "Defective Sign & Encrypt in S/MIME, PKCS#7, MOSS, PEM, PGP, and XML",
  2001 USENIX Annual Technical Conference, Boston (§1.1 surreptitious forwarding; §1.2
  signature replacement in encrypt-then-sign). Verified at
  https://www.usenix.org/conference/2001-usenix-annual-technical-conference/defective-sign-encrypt-smime-pkcs7-moss-pem-pgp
  and https://static.usenix.org/publications/library/proceedings/usenix01/full_papers/davis/davis.pdf
  (no page range printed in either).
- J. H. An, Y. Dodis, T. Rabin, "On the Security of Joint Signature and Encryption",
  EUROCRYPT 2002, LNCS 2332, pp. 83–107. Verified at
  https://www.iacr.org/archive/eurocrypt2002/bibtex-23320080.txt
- S. Josefsson, I. Liusvaara, RFC 8032, "Edwards-Curve Digital Signature Algorithm (EdDSA)",
  January 2017 — §5.1.7 step 1 rejects `S` outside `0 ≤ S < L`. Verified at
  https://www.rfc-editor.org/rfc/rfc8032.html
