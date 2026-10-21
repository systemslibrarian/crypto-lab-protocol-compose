# Protocol Compose — The Public-Key Seam

Starting main: `f5c0b60c2614045ed283805b6a4d4b17f654f8ed`.
Brief: `brief-extension.md`.
Live: https://systemslibrarian.github.io/crypto-lab-protocol-compose/

Exhibit 7 is appended after Exhibit 6, bringing the structural count to nine.
Its fresh session parties use real WebCrypto Ed25519 and ephemeral P-256 ECDH,
HKDF-SHA-256 and AES-256-GCM. The two naive protocols demonstrate signature
replacement and surreptitious forwarding while actual primitive checks pass.
The default identity-bound protocol rejects both attacks for the actual
decrypted identity mismatch. Only Ravi's auto-reply behaviour is modelled.
The ciphertext, signed transcript and explicitly disclosed local teaching keys
allow independent verification; the outsider's function receives no receiver key.

## Verification

- 61 unit tests passed, including 18 new tests. Four RFC 8032 Ed25519 vectors
  cover 0, 1, 2 and 1023 message bytes, exact signing, verification and S+L
  rejection. RFC 5903 §8.1 pins P-256 derivation in both directions.
- Correction to the brief: Iron Letter at `0d6257cdad49` uses a local ECDH
  fixture, not a published ECDH vector. RFC 5903 supplies the published pin.
  Iron Letter's ECIES and SSH Handshake's Ed25519 patterns were read; no
  cross-repo imports or runtime crypto dependencies were introduced.
- All 27 Chromium browser checks passed (24 claims, three accessibility
  walks), including all old exhibits, desktop, 380px and Exhibit 7 at 320px.
  The seven new claims independently reconstruct ECDH/HKDF/AES-GCM and verify
  Ed25519 with Node crypto; no app module supplies the expected result.
- Six concrete source mutations killed: omit recipient, omit sender check,
  falsely accept signatures, paint a compromise safe, delete the negative
  sentence, break the negative fixture's signature check. The replayable
  script and `mutation-evidence.json` record successful baselines and builds,
  changed bundle hashes, named assertion failures, served-JavaScript hashes,
  exact restoration and green owning tests. Zero retries.
- WebCrypto's S+L rule is tested directly in the browser before the app path.
  Any platform acceptance stops the exhibit without a library fallback.
  Unsupported key generation, GCM tampering, empty/oversize messages,
  revision retirement, no-op inputs and delayed completion are covered.
- Mobile, grayscale and deuteranopia screenshots were inspected. The longer
  page exposed the old timing explainer's intrinsic-width overflow; a scoped
  min-width fix contains it. No accessibility exemption or baseline added.

The source-grep of the available sibling clones matched only the existing
one-line public-key composition reference. That clause now points to Exhibit 7.
Original crypto modules, Exhibits 1–6 behaviour, hash keys, header, footer,
dark theme and deployment workflow are unchanged. Grouped dependencies,
auto-merge, PR gate and workflow dispatch remain present. The original workflow
gates deployment with the full unit/build/browser suite; mutations have their
own `npm run test:mutations` command.

The pinned browser download returned a non-ZIP response locally. Local checks
used Chromium 153.0.8010.0 with an ignored executable-path config; CI retains
its own pinned browser. No production config was weakened.

## Catalog handoff — no shared edits

Suggested sentence: “Strip or forward a genuinely signed, encrypted message,
then bind the sender and recipient to make the receiver reject the attack.”
Implemented chips: `Ed25519`, `ECDH`, `ECIES`.
Related links: Iron Letter, HPKE Envelope, Vector Gate.
Concept deepened: **29. Composition and parsing failures**.
Call sites: `src/signcrypt.ts`, `src/signcrypt-panel.ts`, Exhibit 7 insertion
and wiring in `src/main.ts`. Ciphertext-plus-recipient and HPKE AAD/info are
marked future seams, not implementation claims.

The fleet-wide sync check remains blocked by missing unrelated checkouts.
The shared catalog, counsel, census and checker are unchanged. Final main SHA
and live-byte proof are recorded after publication.

## Educational accuracy follow-up

Replaced the overstatement that signing proves human authorship. The exhibit
now explains verification against a public signing key and explicitly assumes
trusted bindings between keys and identities. The two broken modes are named
naïve compositions, and the scope note explains that neither ordering is
inherently broken. This matches the identity-binding failure described in
[Davis (2001)](https://static.usenix.org/publications/library/proceedings/usenix01/full_papers/davis/davis.pdf).
The cryptographic computations and attack demonstrations are unchanged.

Validation: all 61 unit tests, two publishing-request tests and all 27 browser
tests passed, including independent packet checks and accessibility.
