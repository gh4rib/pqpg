# PQPG (Post-Quantum Privacy Guard)

By utilizing Cloudflare's `circl` library and EPFL's `kyber` abstract algebra engine, PQPG implements the latest FIPS 203, 204, and 205 post-quantum standards alongside composite hybrid cryptography. It guarantees absolute data confidentiality and metadata anonymity against both traditional and quantum adversaries.

PQPG operates as an **Asynchronous Secure Messenger (Sealed Sender Transport Layer)**, a **Personal Post-Quantum Vault**, and a **Trustless Distributed Vault (Feldman VSS)**, allowing users to wrap local files and networks inside an impenetrable quantum-resistant armor.

---

## Core Features & Security Guarantees

* **Hybrid Cryptography:** Natively supports composite algorithms like `X-Wing` (X25519 + ML-KEM-768) and `EdDilithium` to ensure security even if one cryptographic assumption fails.
* **Sealed Sender (Metadata Anonymity):** Utilizes a Dual-Ratchet Outer/Inner envelope architecture padded to a strict 1KB boundary. Adversaries can see a connection, but sender identity, algorithms, and timestamps remain mathematically obscured.
* **Traffic Analysis Defeat:** Defeats compression oracles (like CRIME/BREACH) and length-guessing attacks by compressing data streams (Zstd/Gzip) and appending cryptographically secure random noise to force all ciphertexts to standardized 4KB boundaries.
* **Trustless Distributed Vaults:** Implements Feldman’s Verifiable Secret Sharing (VSS) over the Ed25519 scalar field. Generates M-of-N Shamir shares bound to ECC commitments, mathematically proving share validity and preventing malicious dealers from destroying vaults.
* **ASIC-Resistant Key Protection:** Stretches user passphrases through Argon2id (RFC 9106 High-Security parameters: 256MB RAM, 3 iterations, 4 threads) to bankrupt GPU/ASIC brute-force attacks against local private keys.
* **Perfect Forward Secrecy (PFS):** Implements a continuous, one-way Symmetric Key Ratchet driven by Extendable-Output Functions (XOFs) with strict cryptographic domain separation.
* **Concurrent Chunked Streaming:** Processes massive binary archives (like `.iso` or massive `.kdbx` databases) inside continuous 64KB sequential streams with memory-efficient `io.Pipe` architecture, bypassing RAM bottlenecks.
* **Fiat-Shamir Hardening & Anti-Replay:** Mitigates context-manipulation by hashing the entire message envelope *before* generating the Post-Quantum signature, while caching unique transaction tokens locally to block duplicate packets.

---

## Supported Cryptographic Suite

| Category | Supported Algorithms |
| --- | --- |
| **KEM (Key Encapsulation)** | `ML-KEM-768`, `ML-KEM-1024`, `Kyber768`, `Kyber1024`, `FrodoKEM-640`, `X-Wing` (Hybrid) |
| **DSA (Digital Signatures)** | `ML-DSA-65`, `ML-DSA-87`, `Dilithium2/3/5`, `EdDilithium2/3` (Hybrid), `SLH-DSA` |
| **AEAD (Symmetric Ciphers)** | `AES-256-GCM`, `ChaCha20-Poly1305`, `Ascon-128`, `Ascon-128a` |
| **XOF / Hashing** | `SHAKE128`, `SHAKE256`, `SHA3-256/384/512`, `SHA-512`, `KangarooTwelve` |

---

## Architecture Layout

The codebase strictly adheres to SOLID principles, isolating cryptographic mathematics from network framing, anti-replay state validation, and identity management.

```text
pqc-messenger/
├── cmd/
│   └── messenger/
│       └── main.go                 # Interactive CLI orchestrator (Keys, Envelopes, & Vaults)
├── internal/
│   ├── crypto/
│   │   ├── interfaces.go           # Abstract SOLID contracts
│   │   ├── registry.go             # Suite validation and factory engine
│   │   ├── kem_adapters.go         # CIRCL KEM & Hybrid implementations
│   │   ├── dsa_adapters.go         # CIRCL Signature implementations
│   │   ├── sym_adapters.go         # Block & Lightweight ciphers (Ascon)
│   │   ├── hash_adapters.go        # Keccak, SHA-2, SHA-3, and XOF engines
│   │   └── ratchet.go              # PFS unidirectional KDF chain
│   ├── identity/
│   │   ├── keyring.go              # PKI management and disk I/O
│   │   └── protected.go            # Argon2id memory-hard AES/ChaCha/Ascon key wrapping
│   └── packet/
│       ├── detached.go             # High-speed streaming Cleartext Signatures
│       ├── replay.go               # Local signature-caching deduplication system
│       ├── shared.go               # Feldman VSS Threshold Vaults (Ed25519)
│       └── stream.go               # Compressed, Padded, Chunk-Streaming Sealed Sender Envelopes
├── go.mod
└── go.sum

```

---

## Installation & Build Guide

### Prerequisites

* **Go 1.25.10** or higher.
* Active internet connection to fetch Cloudflare `circl` and EPFL `kyber/v4`.

### Step-by-Step Build

1. **Clone the repository:**

```bash
git clone https://github.com/gh4rib/pqpg-cloudflare-circl.git
cd pqpg-cloudflare-circl

```

2. **Download dependencies:**

```bash
go mod tidy

```

3. **Compile the binary:**

```bash
go build -o pqpg ./cmd/messenger

```

---

## 📖 Usage Manual

Launch the interactive engine by running `./pqpg` in your terminal.

### 1. Establish an Identity (PKI Setup)

Select **Option 1** to generate a cryptographic profile. Choose from NIST FIPS Standards, Pre-Standard Lattice parameters, or Full Composite Hybrids. The engine secures your private key to disk using Argon2id and generates a public profile for distribution.

### 2. View Local Keyrings

Select **Option 2** to scan the current directory and print the cryptographic routing preferences (KEM, DSA, AEAD, and XOF) and fingerprints of all local profiles.

### 3. Encrypt & Sign a File (Send)

Select **Option 3** to seamlessly compress (Zstd/Gzip), pad, and stream-encrypt a payload using the Sealed Sender protocol. The output is a `outbox_msg.asc` ASCII-armored file ensuring total metadata anonymity against the recipient's public key.

### 4. Decrypt & Verify a File (Receive)

Select **Option 4** to authenticate an incoming `.asc` envelope. The engine verifies the signature, prevents replay attacks, unpads the uniform boundaries, decompresses the data, and restores the original file.

### 5 & 6. Personal Post-Quantum Vault (Lock/Unlock)

Select **Option 5** to wrap a local file (e.g., a KeePass database) inside a continuous stream-encrypted envelope bound to your own public key. Select **Option 6** to decrypt it.

### 7 & 8. M-of-N Shared Vault (Feldman VSS Threshold)

Select **Option 7** to distribute a vault across multiple stakeholders. The engine plots a secret polynomial over the Ed25519 scalar field, outputs `N` shares, and embeds ECC public commitments in the header. Select **Option 8** to provide `M` shares; the engine mathematically proves share authenticity before executing Lagrange interpolation to restore the file.

### 9 & 10. Cleartext Detached Signatures

Select **Option 9** to hash a massive file (e.g., an OS `.iso`) natively from the hard drive without encrypting it, generating a tiny, post-quantum detached signature file (`.pqc_sig`). Select **Option 10** to verify the payload mathematically.

---

## Acknowledgements & Upstream Projects

**Cloudflare CIRCL**
The core cryptographic mathematics of PQPG are powered by CIRCL (Cloudflare Interoperable, Reusable Cryptographic Library), an advanced open-source engine bringing state-of-the-art post-quantum primitives to Go.

**EPFL Advanced Cryptography Group (Kyber)**
Threshold cryptography and Feldman VSS operations rely on the `go.dedis.ch/kyber` abstract algebra suite, providing the vital Elliptic Curve scalar math required for Zero-Knowledge and verifiable group commitments.

---

## License & Third-Party Code

**CIRCL License**
This software relies on the Cloudflare CIRCL library which released under BSD-3 Clause License.
Faz-Hernandez, A. and Kwiatkowski, K. (2019). *Introducing CIRCL: An Advanced Cryptographic Library*. Cloudflare. Available at [https://github.com/cloudflare/circl](https://github.com/cloudflare/circl). v1.6.3 Accessed May, 2026.

> Copyright (c) 2019, Cloudflare Inc.
> All rights reserved.
> Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
> 1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
> 2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
> 3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.
> 
>
