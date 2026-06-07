# PQPG (Post-Quantum Privacy Guard)

By utilizing Cloudflare's `circl` library and EPFL's `kyber` abstract algebra engine, PQPG implements the latest FIPS 203, 204, and 205 post-quantum standards alongside composite hybrid cryptography. It guarantees absolute data confidentiality and metadata anonymity against both traditional and quantum adversaries.

PQPG operates as an **Asynchronous Secure Messenger (Sealed Sender Transport Layer)**, a **Personal Post-Quantum Vault**, and a **Trustless Distributed Vault (Feldman VSS)**, allowing users to wrap local files and networks inside an impenetrable quantum-resistant armor.

---

## Core Features & Security Guarantees

* **Hybrid Cryptography & Crypto-Agility:** Natively supports composite algorithms like `X-Wing` (X25519 + ML-KEM-768) and `EdDilithium`. Every database and network protocol dynamically inherits the user's chosen Keccak (XOF) and AEAD suite, eliminating hardcoded downgrade vulnerabilities.
* **Sealed Sender & Receiver Anonymity:** Uses a Dual-Layer envelope padded to strict 1KB boundaries. To prevent network metadata leakage, PQPG drops plaintext public keys and relies on **32-byte Keccak Key Hints**, meaning a network eavesdropper cannot mathematically identify the receiver.
* **Zero-Knowledge BoltDB (Blind Indexing):** Local databases (`sessions.db`) are encrypted using AES-256-GCM. Furthermore, all database keys (Contact IDs and Replay Tokens) are hashed using `HMAC-SHA3-256`, rendering the local contact graph and message history completely blind to forensic analysis.
* **Perfect Forward Secrecy (PFS):** Implements a Post-Quantum Double Ratchet. The state machine seamlessly handles out-of-order packets, dropping "dangling" keys after a strict 1000-message boundary to prevent Ram/State Exhaustion attacks.
* **Simultaneous Initiation (Glare) Resolution:** Safely resolves the "Crossing Messages Paradox" using lexicographical tie-breaking without requiring a central server, ensuring sessions synchronize flawlessly even if both parties instantiate communication at the exact same millisecond.
* **AEAD Header Authentication:** Eliminates CPU Denial of Service attacks by binding the Outer Envelope JSON directly into the inner AES-GCM engine as Additional Authenticated Data (AAD). Tampered metadata triggers an instantaneous failure before any disk I/O occurs.
* **Strict Domain Separation:** Prevents Signature Context Confusion by prefixing all hashes (e.g., Detached Signatures, Ratchet KDFs, Blind Indexes) with unique, hardcoded domain separators.
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
│       └── main.go
|       └── *-handlers.go
├── internal/
│   ├── crypto/
│   │   ├── interfaces.go           # Abstract SOLID contracts
│   │   ├── registry.go             # Suite validation and dynamic factory engine
│   │   ├── kem-adapters.go         # CIRCL KEM & Hybrid implementations
│   │   ├── dsa-adapters.go         # CIRCL Signature implementations
│   │   ├── sym-adapters.go         # Block & Lightweight ciphers (Ascon)
│   │   ├── hash-adapters.go        # Keccak, SHA-2, SHA-3, and XOF engines
│   │   └── double-ratchet.go       # Stateless KDF math for the PFS Ratchet
│   ├── identity/
│   │   ├── keyring.go              # PKI management and disk I/O
│   │   ├── protected.go            # Argon2id memory-hard AES/ChaCha/Ascon key wrapping
│   │   └── session.go              # AES-GCM Encrypted BoltDB (Blind Indexes & Anti-Replay)
│   └── packet/
│       ├── detached.go             # High-speed streaming Cleartext Signatures
│       ├── shared.go               # Feldman VSS Threshold Vaults (Ed25519)
│       ├── stateless.go            # Non-Ratchet Fallback for Cold Storage / Air-Gapped Transfers
│       ├── stream.go               # Double Ratchet Sealed Sender Envelopes (Chunked Streaming)
│       └── vault.go                # Static Deterministic Encryption for Local At-Rest Data
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
CGO_ENABLED=1 go build -o pqpg ./cmd/messenger

```

---

## 📖 Usage Manual

Launch the interactive engine by running `./pqpg` in your terminal.

### 1. Establish an Identity (PKI Setup)

Select **Option 1** to generate a cryptographic profile. Choose from NIST FIPS Standards, Pre-Standard Lattice parameters, or Full Composite Hybrids. The engine secures your private key to disk using Argon2id and generates a public profile for distribution.

### 2. View Local Keyrings

Select **Option 2** to scan the current directory and print the cryptographic routing preferences (KEM, DSA, AEAD, and XOF) and fingerprints of all local profiles.

### 3 & 4. Asynchronous Messaging (Double Ratchet)

Select **Option 3** to seamlessly compress, pad, and stream-encrypt a payload using the Double Ratchet protocol. The output is a `outbox_[filename].asc` file ensuring Forward Secrecy. Select **Option 4** to authenticate an incoming `.asc` envelope. The engine verifies the AEAD headers, spins the state database, and restores the file.

### 5 & 6. Personal Post-Quantum Vault (Lock/Unlock)

Select **Option 5** to wrap a local file (e.g., a KeePass database) inside a continuous stream-encrypted envelope deterministically bound to your identity. Select **Option 6** to decrypt it.

### 7 & 8. M-of-N Shared Vault (Feldman VSS Threshold)

Select **Option 7** to distribute a vault across multiple stakeholders. The engine plots a secret polynomial over the Ed25519 scalar field, outputs `N` shares, and embeds ECC public commitments in the header. Select **Option 8** to provide `M` shares; the engine mathematically proves share authenticity before executing Lagrange interpolation to restore the file.

### 9 & 10. Cleartext Detached Signatures

Select **Option 9** to hash a massive file natively from the hard drive without encrypting it, generating a tiny, domain-separated detached signature file (`.pqc_sig`). Select **Option 10** to verify the payload.

### 11 & 12. Network Evasion (Steganography)

Select **Option 11** to mathematically weave a `.asc` or `.pq_vault` payload into the Least Significant Bits (LSB) of a PNG/BMP image or WAV/AIFF audio carrier to bypass DPI firewalls. Select **Option 12** to extract the payload natively.

### 13 & 14. Stateless Transfers (Simple Send Fallback)

Select **Option 13** to encrypt a file utilizing a single ephemeral KEM exchange without initializing the BoltDB state machine. Ideal for cold-storage backups. Select **Option 14** to extract a stateless payload.

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
