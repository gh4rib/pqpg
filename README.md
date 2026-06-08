Here is the updated, comprehensive `README.md` for **PQPG**, fully updated to incorporate the **Zero-Knowledge Data Notary (Proof of Breach)** engine, along with its architecture paths and usage details.

---

# PQPG (Post-Quantum Privacy Guard)

By utilizing Cloudflare's `circl` library and EPFL's `kyber` abstract algebra engine, PQPG implements the latest FIPS 203, 204, and 205 post-quantum standards alongside composite hybrid cryptography. It guarantees absolute data confidentiality and metadata anonymity against both traditional and quantum adversaries.

PQPG operates as an **Asynchronous Secure Messenger (Sealed Sender Transport Layer)**, a **Personal Post-Quantum Vault**, a **Trustless Distributed Vault (Feldman VSS)**, a **Zero-Knowledge Time-Lock Engine**, and a **Zero-Knowledge Data Notary (Proof of Breach)**, allowing users to wrap local files and networks inside an impenetrable quantum-resistant armor.

---

## Core Features & Security Guarantees

* **Hybrid Cryptography & Crypto-Agility:** Natively supports composite algorithms like `X-Wing` (X25519 + ML-KEM-768) and `EdDilithium`. Every database and network protocol dynamically inherits the user's chosen Keccak (XOF) and AEAD suite, eliminating hardcoded downgrade vulnerabilities.
* **Stateful Post-Quantum Root Identities (LMS/XMSS):** Fully supports FIPS 205 Hash-Based Signatures for highly secure, failsafe software release engineering.
* **Hardware-Safe Anti-Rollback Canaries:** Defeats catastrophic state-reuse attacks in LMS/XMSS using POSIX-compliant, hardware-level atomic file swaps and AES-GCM protected canaries, ensuring state integrity even during sudden power-loss events.
* **Zero-Knowledge Data Notary (Proof of Breach):** Proves possession of massive datasets (e.g., leaked or compromised data) without revealing a single byte of the file itself. Employs a native **Groth16 zk-SNARK** over the **BN254** elliptic curve using a custom **MiMC Merkle Tree** pipeline.
* **Hardened Circuit Defenses:** Integrates strict domain separation for empty leaf padding (`PQPG-EMPTY-MERKLE-PAD`) to prevent length-extension collisions and mandates a minimum tree depth of 4. Protects verifiers against malicious "Rogue Setup" attacks by calculating and enforcing a **SHA3-256 fingerprint** verification step on the circuit's Verifying Key.
* **Zero-Knowledge Time-Lock Puzzles (VDF):** Encapsulates files inside an RSA-4096 Hidden Order Group. Uses a native Fiat-Shamir Zero-Knowledge Proof (Sigma Protocol) to mathematically guarantee puzzle validity, forcing sequential CPU delays (Dead Man's Switch) without exposing solvers to forged puzzles.
* **Cryptographic Memory Hygiene & Rainbow Table Immunity:** Secures local keyrings using dynamic Argon2id salt rotation to neutralize pre-computed Rainbow Tables. Guarantees that all highly sensitive private key byte-slices are explicitly shredded from RAM immediately after cryptographic operations conclude.
* **Sealed Sender & Receiver Anonymity:** Uses a Dual-Layer envelope padded to strict 1KB boundaries. Drops plaintext public keys and routes via **32-byte Keccak Key Hints**, meaning a network eavesdropper cannot mathematically identify the receiver.
* **Zero-Knowledge BoltDB (Blind Indexing):** Local databases (`sessions.db`) are encrypted using AES-256-GCM. All database keys (Contact IDs and Replay Tokens) are hashed using `HMAC-SHA3-256`, rendering the local contact graph and message history completely blind to forensic analysis.
* **Perfect Forward Secrecy (PFS):** Implements a Post-Quantum Double Ratchet. The state machine seamlessly handles out-of-order packets, dropping "dangling" keys after a strict 1000-message boundary to prevent RAM/State Exhaustion attacks.
* **Centralized Domain Separation:** Prevents cross-protocol signature collisions by anchoring all hash operations to a centralized registry of immutable Magic Strings and Domain Separation Tags.
* **Trustless Distributed Vaults:** Implements Feldman’s Verifiable Secret Sharing (VSS) over the Ed25519 scalar field. Generates M-of-N Shamir shares bound to ECC commitments, mathematically proving share validity and preventing malicious dealers from destroying vaults.

---

## The Post-Quantum Double Ratchet Engine

PQPG manages Perfect Forward Secrecy and Post-Compromise Security using a highly robust "Separation of Concerns" architecture. The engine is divided into three distinct layers to prevent database corruption during asynchronous transfers:

1. **The Brain (`double_ratchet.go`):** A strictly stateless, functional mathematical engine. It knows nothing about the network or databases; it simply ingests byte arrays, executes Keccak KDF sponge derivations, and outputs new cryptographic chain keys.
2. **The Memory (`session.go` / BoltDB):** The ACID-compliant, encrypted storage vault. It safely stores the `RatchetState`, tracks historical public keys to defeat the **Implicit Rejection (FO Transform) Trap**, and runs the HMAC-SHA3 Anti-Replay Cache.
3. **The Conductor (`stream.go`):** The orchestrator layer. It pulls state from BoltDB, asks the Brain to spin the Ratchets in RAM, and utilizes **Deferred Commits**. The database state is *only* updated and saved to the hard drive if the AEAD cryptographic signature perfectly authenticates the payload, rendering PQPG virtually immune to session corruption from malformed files.

*(Note: PQPG also includes a **Stateless Fallback** mechanism, providing a traditional PGP-style mathematical envelope that completely bypasses the Ratchet database for cold-storage and air-gapped backups).*

---

## Supported Cryptographic Suite

| Category | Supported Algorithms |
| --- | --- |
| **KEM (Key Encapsulation)** | `ML-KEM-768`, `ML-KEM-1024`, `Kyber768`, `Kyber1024`, `FrodoKEM-640`, `X-Wing` (Hybrid) |
| **DSA (Stateless Signatures)** | `ML-DSA-65`, `ML-DSA-87`, `Dilithium2/3/5`, `EdDilithium2/3` (Hybrid), `SLH-DSA` |
| **Stateful DSA (FIPS 205)** | `LMS_H5` -> `LMS_H25`, `XMSS`, `XMSSMT` |
| **AEAD (Symmetric Ciphers)** | `AES-256-GCM`, `ChaCha20-Poly1305`, `Ascon-128`, `Ascon-128a` |
| **XOF / Hashing** | `SHAKE128`, `SHAKE256`, `SHA3-256/384/512`, `SHA-512`, `KangarooTwelve` |
| **Zero-Knowledge Primitives** | `Groth16` (zk-SNARK), `BN254` Pairing-Friendly Curve, `MiMC` (Sponge-Hash) |

---

## Architecture Layout

The codebase strictly adheres to SOLID principles, isolating cryptographic mathematics from network framing, anti-replay state validation, and identity management.

```text
pqc-messenger/
├── cmd/
│   └── messenger/
│       ├── main.go
│       ├── notary-handlers.go    # CLI orchestration for ZK Data Notary (Prove/Verify)
│       └── *-handlers.go
├── internal/
│   ├── crypto/
│   │   ├── interfaces.go         # Abstract SOLID contracts (Stateful & Stateless)
│   │   ├── registry.go           # Suite validation and dynamic factory engine
│   │   ├── kem-adapters.go       # CIRCL KEM & Hybrid implementations
│   │   ├── dsa-adapters.go       # CIRCL Signature implementations
│   │   ├── sym-adapters.go       # Block & Lightweight ciphers (Ascon)
│   │   ├── hash-adapters.go      # Keccak, SHA-2, SHA-3, and XOF engines
│   │   ├── stateful.go           # Stateful Hash-Based Signature routing
│   │   ├── lms-adapter.go        # LMS primitive integration
│   │   ├── xmss-adapter.go       # XMSS primitive integration
│   │   └── double-ratchet.go     # Stateless KDF math for the PFS Ratchet
│   ├── identity/
│   │   ├── keyring.go            # PKI management and disk I/O
│   │   ├── protected.go          # Argon2id memory-hard AES/ChaCha/Ascon key wrapping
│   │   ├── rollback.go           # Hardware-safe atomic AES-GCM Canary state guard
│   │   └── session.go            # AES-GCM Encrypted BoltDB (Blind Indexes & Anti-Replay)
│   ├── vdf/
│   │   ├── engine.go             # Abstract interfaces for Verifiable Delay Functions
│   │   └── rsa_vdf.go            # Native RSA Subgroup math & Fiat-Shamir ZKP
│   ├── zkp/
│   │   ├── circuit.go            # Gnark R1CS Merkle Inclusion Proof Circuit
│   │   └── engine.go             # Groth16 Setup, Prove, and Verify mathematical interface
│   └── packet/
│       ├── constants.go          # Centralized Domain Separation Tags & Magic Strings
│       ├── detached.go           # High-speed streaming Cleartext Signatures
│       ├── detached-stateful.go  # FIPS 205 synchronous stateful file signing
│       ├── shared.go             # Feldman VSS Threshold Vaults (Ed25519)
│       ├── stateless.go          # Non-Ratchet Fallback for Cold Storage
│       ├── stream.go             # Double Ratchet Sealed Sender Envelopes (Chunked)
│       ├── timelock.go           # ZKP Time-Lock Puzzle Orchestration
│       └── vault.go              # Static Deterministic Encryption for Local At-Rest Data
├── go.mod
└── go.sum

```

---

## Installation & Build Guide

### Prerequisites

* **Go 1.25.10** or higher.
* Active internet connection to fetch Cloudflare `circl`, EPFL `kyber/v4`, and ConsenSys `gnark`.

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
CGO_ENABLED=1 go build -o pqpg ./cmd/messenger

```

---

## 📖 Usage Manual

Launch the interactive engine by running `./pqpg` in your terminal.

### 1. Establish an Identity (PKI Setup)

Select **Option 1** to generate a cryptographic profile. Choose from NIST FIPS Standards, Pre-Standard Lattice parameters, or Full Composite Hybrids. The engine secures your private key to disk using Argon2id and generates a public profile for distribution. (Supports dedicated LMS/XMSS Stateful Release profiles).

### 2. View Local Keyrings

Select **Option 2** to scan the current directory and print the cryptographic routing preferences (KEM, DSA, AEAD, and XOF) and fingerprints of all local profiles.

### 3 & 4. Asynchronous Messaging (Double Ratchet)

Select **Option 3** to seamlessly compress, pad, and stream-encrypt a payload using the Double Ratchet protocol. The output is a `outbox_[filename].asc` file ensuring Forward Secrecy. Select **Option 4** to authenticate an incoming `.asc` envelope. The engine verifies the AEAD headers, spins the state database, and restores the file.

### 5 & 6. Personal Post-Quantum Vault (Lock/Unlock)

Select **Option 5** to wrap a local file inside a continuous stream-encrypted envelope deterministically bound to your identity. Select **Option 6** to decrypt it.

### 7 & 8. M-of-N Shared Vault (Feldman VSS Threshold)

Select **Option 7** to distribute a vault across multiple stakeholders. The engine plots a secret polynomial over the Ed25519 scalar field, outputs `N` shares, and embeds ECC public commitments in the header. Select **Option 8** to provide `M` shares; the engine mathematically proves share authenticity before executing Lagrange interpolation to restore the file.

### 9 & 10. Cleartext Detached Signatures (Stateless & Stateful)

Select **Option 9** to hash a massive file natively from the hard drive without encrypting it, generating a tiny, domain-separated detached signature file (`.pqc_sig`). If utilizing an LMS or XMSS identity, the engine will synchronously lock the OS, advance the Anti-Rollback canary via atomic hardware writes, and append the FIPS 205 signature (`.lms_sig` or `.xmss_sig`). Select **Option 10** to stream-verify the payload.

### 11 & 12. Zero-Knowledge Time-Lock Puzzles (Dead Man's Switch)

Select **Option 11** to lock a payload inside an RSA-4096 Verifiable Delay Function (VDF). The engine generates a sequential CPU puzzle and a native Fiat-Shamir Zero-Knowledge Proof, outputting a `.timelock` artifact. Select **Option 12** to unlock a puzzle. The engine instantly verifies the ZKP to prevent forgery, then begins the un-parallelizable sequential CPU operations required to derive the AES decryption key.

### 13 & 14. Network Evasion (Steganography)

Select **Option 13** to mathematically weave a `.asc` or `.pq_vault` payload into the Least Significant Bits (LSB) of a PNG/BMP image or WAV/AIFF audio carrier to bypass DPI firewalls. Select **Option 14** to extract the payload natively.

### 15 & 16. Stateless Transfers (Simple Send Fallback)

Select **Option 15** to encrypt a file utilizing a single ephemeral KEM exchange without initializing the BoltDB state machine. Ideal for cold-storage backups. Select **Option 16** to extract a stateless payload.

### 17 & 18. Zero-Knowledge Data Notary (Proof of Breach)

Select **Option 17** to act as a Prover and generate a zk-SNARK proving possession of a targeted leak file or database. The engine processes the local file chunk-by-chunk inside a field-compliant MiMC Merkle tree, evaluates it against a targeted public root, and exports a standalone `.zkp` proof envelope containing the serialized cryptographic proofs and the verifying parameters. Select **Option 18** to act as an Auditor and verify a standalone proof. The verifier parses the proof envelope, extracts the circuit's verifying key, calculates its **SHA3-256 fingerprint** for human confirmation, and strictly checks the R1CS constraints to assert proof validity.

---

## Acknowledgements & Upstream Projects

**Cloudflare CIRCL**
The core cryptographic mathematics of PQPG are powered by CIRCL (Cloudflare Interoperable, Reusable Cryptographic Library), an advanced open-source engine bringing state-of-the-art post-quantum primitives to Go.

**EPFL Advanced Cryptography Group (Kyber)**
Threshold cryptography and Feldman VSS operations rely on the `go.dedis.ch/kyber` abstract algebra suite, providing the vital Elliptic Curve scalar math required for Zero-Knowledge and verifiable group commitments.

**ConsenSys gnark**
The zero-knowledge SNARK ecosystem, circuit compilation, and R1CS Groth16 proving/verifying mechanisms are powered entirely by the high-performance `gnark` framework.

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

---
