# crypto-lab-protocol-compose

[![crypto-lab portfolio](https://img.shields.io/badge/crypto--lab-portfolio-blue?style=flat-square)](https://systemslibrarian.github.io/crypto-lab/)

## What It Is

crypto-lab-protocol-compose is a browser demo of protocol composition safety using AES-CBC, HMAC with SHA-256, and AES-256-GCM through the WebCrypto API. It compares MAC-then-Encrypt, Encrypt-then-MAC, Encrypt-and-MAC, and AEAD under one interactive interface. The project shows that composition order changes what an attacker can observe and exploit, even when each primitive is secure in isolation. The security model is symmetric-key authenticated messaging where attackers can tamper with transmitted ciphertexts and observe verifier behavior.

## When to Use It

- Use it when reviewing legacy AES-CBC + HMAC designs, because the demo shows exactly how MtE requires decryption before MAC validation.
- Use it for architecture decisions between EtM and AEAD, because the exhibits compare pre-decryption authentication versus decrypt-first workflows.
- Use it in secure coding training, because the padding oracle runner demonstrates real bytewise recovery against MtE ciphertext.
- Use it to evaluate protocol migration plans, because the TLS walkthrough maps CBC-era composition risk to TLS 1.3 AEAD-only design.
- Use it to catch common composition mistakes, because the checklist scores unsafe ordering choices such as MtE and E&M.

## Live Demo

https://systemslibrarian.github.io/crypto-lab-protocol-compose/

The demo lets you encrypt a live message across composition modes and inspect resulting ciphertext/tag outputs. You can switch the composition mode selector, execute the padding oracle runner, step through the TLS evolution walkthrough, and compute risk with the protocol safety checklist. Each control is tied to real WebCrypto operations rather than simulated arithmetic.

## What Can Go Wrong

- MtE padding oracle exposure: decryption happens before MAC verification, so padding validity can become an oracle that leaks plaintext bytes.
- E&M plaintext-correlation leak: MACing plaintext separately exposes a reusable authenticator that can reveal message equality across sessions.
- TLS CBC timing side-channel (Lucky Thirteen): small processing differences during CBC record handling leak information about plaintext and padding validity.
- TLS 1.0 BEAST-era CBC composition weakness: CBC record chaining and composition details enabled practical chosen-plaintext attacks.
- Implementation pitfall in verification order: checking authenticity after decryption recreates oracle surfaces even if AES and HMAC are individually correct.

## Real-World Usage

- TLS 1.0/1.1: relied on CBC-era constructions that motivated later composition hardening.
- TLS 1.2: still allowed CBC MtE suites, leaving room for Lucky Thirteen-style residual risk.
- TLS 1.3: removed CBC record protection and mandates AEAD, demonstrating safer composition by design.
- SSH (Encrypt-and-MAC variants): illustrates how separate plaintext MAC handling can leak correlations and composition metadata.
- BEAST and Lucky Thirteen case studies: concrete attacks that showed protocol composition, not primitive choice alone, determines security outcomes.

> *"So whether you eat or drink or whatever you do, do it all for the glory of God." — 1 Corinthians 10:31*