# PQPG (Post-Quantum Privacy Guard)

By utilizing Cloudflare's `circl` library, the **Open Quantum Safe (`liboqs`) C-FFI engine**, and EPFL's `kyber` abstract algebra engine, PQPG implements the latest FIPS 203, 204, and 205 post-quantum standards alongside composite hybrid cryptography. It guarantees absolute data confidentiality and metadata anonymity against both traditional and quantum adversaries.

PQPG operates as an **Asynchronous Secure Messenger (Sealed Sender Transport Layer)**, a **Personal Post-Quantum Vault**, a **Trustless Distributed Vault (Feldman VSS)**, a **Zero-Knowledge Time-Lock Engine**, and a **Zero-Knowledge Data Notary (Proof of Breach)**, allowing users to wrap local files, directories, and networks inside an impenetrable quantum-resistant armor.

---

## Core Features & Security Guarantees

* **Hybrid Cryptography & Crypto-Agility:** Natively supports composite algorithms like `X-Wing` (X25519 + ML-KEM-768) and `EdDilithium`. Every database and network protocol dynamically inherits the user's chosen Keccak (XOF) and AEAD suite, eliminating hardcoded downgrade vulnerabilities.
* **Stateful Post-Quantum Root Identities (LMS/XMSS):** Fully supports FIPS 205 Hash-Based Signatures for highly secure, failsafe software release engineering, powered natively by a statically linked Open Quantum Safe (`liboqs`) C library.
* **Intelligent Directory Archiving:** Seamlessly detects and bundles raw directories into highly compressed `.tar.gz` archives on the fly before routing them through the post-quantum encryption engine, preserving complex file tree structures natively without requiring third-party zip tools.
* **Hardware-Safe Anti-Rollback Canaries:** Defeats catastrophic state-reuse attacks in LMS/XMSS using POSIX-compliant, hardware-level atomic file swaps and AES-GCM protected canaries, ensuring state integrity even during sudden power-loss events.
* **Zero-Knowledge Data Notary (Proof of Breach):** Proves possession of massive datasets (e.g., leaked or compromised data) without revealing a single byte of the file itself. Employs a native **Groth16 zk-SNARK** over the **BN254** elliptic curve using a custom **MiMC Merkle Tree** pipeline.
* **Hardened Circuit Defenses:** Integrates strict domain separation for empty leaf padding (`PQPG-EMPTY-MERKLE-PAD`) to prevent length-extension collisions and mandates a minimum tree depth of 4. Protects verifiers against malicious "Rogue Setup" attacks by calculating and enforcing a **SHA3-256 fingerprint** verification step on the circuit's Verifying Key.
* **Zero-Knowledge Time-Lock Puzzles (VDF):** Encapsulates files inside an RSA-4096 Hidden Order Group. Uses a native Fiat-Shamir Zero-Knowledge Proof (Sigma Protocol) to mathematically guarantee puzzle validity, forcing sequential CPU delays (Dead Man's Switch) without exposing solvers to forged puzzles.
* **Cryptographic Memory Hygiene & Rainbow Table Immunity:** Secures local keyrings using dynamic Argon2id salt rotation to neutralize pre-computed Rainbow Tables. Guarantees that all highly sensitive private key byte-slices are explicitly shredded from RAM immediately after cryptographic operations conclude.
* **Sealed Sender & Receiver Anonymity:** Uses a Dual-Layer envelope padded to strict 1KB boundaries. Drops plaintext public keys and routes via **32-byte Keccak Key Hints**, meaning a network eavesdropper cannot mathematically identify the receiver.
* **Zero-Knowledge BoltDB (Blind Indexing):** Local databases (`sessions.db`) are encrypted using AES-256-GCM. All database keys (Contact IDs and Replay Tokens) are hashed using `HMAC-SHA3-256`, rendering the local contact graph and message history completely blind to forensic analysis.
* **Perfect Forward Secrecy (PFS):** Implements a Post-Quantum Double Ratchet. The state machine seamlessly handles out-of-order packets, dropping "dangling" keys after a strict 1000-message boundary to prevent RAM/State Exhaustion attacks.
* **Trustless Distributed Vaults:** Implements Feldman’s Verifiable Secret Sharing (VSS) over the Ed25519 scalar field. Generates M-of-N Shamir shares bound to ECC commitments, mathematically proving share validity and preventing malicious dealers from destroying vaults.

---

## The Post-Quantum Double Ratchet Engine

PQPG manages Perfect Forward Secrecy and Post-Compromise Security using a highly robust "Separation of Concerns" architecture. The engine is divided into three distinct layers to prevent database corruption during asynchronous transfers:

1. **The Brain (`double_ratchet.go`):** A strictly stateless, functional mathematical engine. It knows nothing about the network or databases; it simply ingests byte arrays, executes Keccak KDF sponge derivations, and outputs new cryptographic chain keys.
2. **The Memory (`session.go` / BoltDB):** The ACID-compliant, encrypted storage vault. It safely stores the `RatchetState`, tracks historical public keys to defeat the **Implicit Rejection (FO Transform) Trap**, and runs the HMAC-SHA3 Anti-Replay Cache.
3. **The Conductor (`stream.go`):** The orchestrator layer. It pulls state from BoltDB, asks the Brain to spin the Ratchets in RAM, and utilizes **Deferred Commits**. The database state is *only* updated and saved to the hard drive if the AEAD cryptographic signature perfectly authenticates the payload, rendering PQPG virtually immune to session corruption from malformed files.

---

## Supported Cryptographic Suite

| Category | Supported Algorithms |
| --- | --- |
| **KEM (Key Encapsulation)** | `ML-KEM-768`, `ML-KEM-1024`, `Kyber768`, `Kyber1024`, `FrodoKEM-640`, `X-Wing` (Hybrid) |
| **DSA (Stateless Signatures)** | `ML-DSA-65`, `ML-DSA-87`, `Dilithium2/3/5`, `EdDilithium2/3` (Hybrid), `SLH-DSA` |
| **Stateful DSA (FIPS 205)** | `LMS_H5` -> `LMS_H25`, `XMSS`, `XMSSMT` (Via natively linked `liboqs`) |
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
│       ├── main.go               # Top-level Subsystem Routing (Core vs OQS)
│       ├── archive.go            # On-the-fly Directory Tarball & Compression Engine
│       ├── notary-handlers.go    # CLI orchestration for ZK Data Notary (Prove/Verify)
│       └── *-handlers.go
├── internal/
│   ├── crypto/
│   │   ├── registry.go           # Suite validation and dynamic factory engine
│   │   ├── stateful.go           # Stateful Hash-Based Signature routing
│   │   └── double-ratchet.go     # Stateless KDF math for the PFS Ratchet
│   ├── oqs/                      # Hardcoded Open Quantum Safe C-FFI Wrappers
│   │   ├── oqs.go                # Static linkage hooks (-lcrypto stripped for portability)
│   │   └── cfuncs.go
│   ├── identity/
│   │   ├── keyring.go            # PKI management and disk I/O
│   │   ├── rollback.go           # Hardware-safe atomic AES-GCM Canary state guard
│   │   └── session.go            # AES-GCM Encrypted BoltDB (Blind Indexes & Anti-Replay)
│   ├── vdf/
│   │   └── rsa_vdf.go            # Native RSA Subgroup math & Fiat-Shamir ZKP
│   ├── zkp/
│   │   ├── circuit.go            # Gnark R1CS Merkle Inclusion Proof Circuit
│   │   └── engine.go             # Groth16 Setup, Prove, and Verify mathematical interface
│   └── packet/
│       ├── stream.go             # Double Ratchet Sealed Sender Envelopes (Chunked)
│       └── timelock.go           # ZKP Time-Lock Puzzle Orchestration
├── go.mod
└── go.sum

```

---

## Installation & Build Guide

### Prerequisites

* **Go 1.25.10** or higher.
* **CMake**, **Ninja**, and a **C Compiler** (`gcc`/`clang`) for building the static OQS subsystem.
* Active internet connection to fetch Cloudflare `circl`, EPFL `kyber/v4`, and ConsenSys `gnark`.

### Phase 1: Build the Static `liboqs` C-Engine

To utilize FIPS 205 Stateful Signatures without trapping users in shared-library (`.so`) dependency hell, PQPG explicitly requires compiling `liboqs` as a static archive (`.a`) with OpenSSL disabled. This guarantees maximum cross-platform binary portability.

```bash
# Clone the upstream Open Quantum Safe repository
git clone -b main https://github.com/open-quantum-safe/liboqs.git
cd liboqs

# Prepare the build directory
mkdir build && cd build

# Configure CMake for a Static Archive WITHOUT OpenSSL
cmake -G Ninja \
  -DCMAKE_INSTALL_PREFIX=$(pwd)/../oqs_static_env \
  -DBUILD_SHARED_LIBS=OFF \
  -DOQS_USE_OPENSSL=OFF \
  -DOQS_ENABLE_SIG_STFL_LMS=ON \
  -DOQS_ENABLE_SIG_STFL_XMSS=ON \
  -DOQS_HAZARDOUS_EXPERIMENTAL_ENABLE_SIG_STFL_KEY_SIG_GEN=ON \
  ..

# Compile and output the static archive to the isolated environment folder
ninja
ninja install
cd ../..

```

### Phase 2: Build the PQPG Executable

Once the `oqs_static_env` is successfully built, go to the ``internal/oqs`` and change the ``cgo LDFLAGS`` and ``cgo CFLAGS`` to the corresponding path.

```bash
# Clone the PQPG repository alongside the liboqs folder
git clone https://github.com/gh4rib/pqpg-cloudflare-circl.git
cd pqpg-cloudflare-circl

# Download Go dependencies
go mod tidy

# Compile the binary with CGO explicitly enabled to bridge the C-FFI
export CGO_ENABLED=1
go build -o pqpg ./cmd/messenger

```

---

## 📖 Usage Manual

Launch the interactive engine by running `./pqpg` in your terminal. You will be prompted to select either the **Core Crypto Engine** or the **OQS Extension Engine** (Restricted to supported native platforms).

### 1. Establish an Identity (PKI Setup)

Select **Option 1** to generate a cryptographic profile. Choose from NIST FIPS Standards, Pre-Standard Lattice parameters, or Full Composite Hybrids. The engine secures your private key to disk using Argon2id and generates a public profile for distribution.

### 2 & 3. Asynchronous Messaging (Double Ratchet)

Select **Option 2** to securely send a payload using the Double Ratchet protocol. **(Note: You can target either a single file OR an entire directory. Directories are automatically bundled into maximum-compression `.tar.gz` archives on the fly before encryption).** Select **Option 3** to authenticate and extract an incoming `.asc` envelope.

### 4 & 5. Personal Post-Quantum Vault (Lock/Unlock)

Select **Option 4** to wrap a local file or directory inside a continuous stream-encrypted envelope deterministically bound to your identity. Select **Option 5** to decrypt it.

### 6 & 7. M-of-N Shared Vault (Feldman VSS Threshold)

Select **Option 6** to distribute a vault across multiple stakeholders. The engine plots a secret polynomial over the Ed25519 scalar field and outputs `N` shares. Select **Option 7** to provide `M` shares; the engine mathematically proves share authenticity before executing Lagrange interpolation to restore the data.

### 8 & 9. Cleartext Detached Signatures (Stateless & Stateful)

Select **Option 8** to hash a massive file natively from the hard drive, generating a tiny detached signature file (`.pqc_sig`). If utilizing an LMS or XMSS identity via the OQS subsystem, the engine synchronously locks the OS, advances the Anti-Rollback canary, and appends the FIPS 205 signature (`.lms_sig`). Select **Option 9** to stream-verify the payload.

### 10 & 11. Zero-Knowledge Time-Lock Puzzles (Dead Man's Switch)

Select **Option 10** to lock a file or directory inside an RSA-4096 Verifiable Delay Function (VDF). The engine generates a sequential CPU puzzle and a native Fiat-Shamir Zero-Knowledge Proof, outputting a `.timelock` artifact. Select **Option 11** to unlock a puzzle, forcing un-parallelizable sequential CPU operations to derive the AES decryption key.

### 12 & 13. Zero-Knowledge Data Notary (Proof of Breach)

Select **Option 12** to act as a Prover and generate a zk-SNARK proving possession of a targeted leak file or database. The engine processes the local file chunk-by-chunk inside a field-compliant MiMC Merkle tree and exports a standalone `.zkp` proof envelope. Select **Option 13** to act as an Auditor and verify a standalone proof. The verifier calculates the Verifying Key's **SHA3-256 fingerprint** for human confirmation before checking the R1CS constraints.

---

## Acknowledgements & Upstream Projects

**Cloudflare CIRCL**
The core cryptographic mathematics of PQPG are powered by CIRCL (Cloudflare Interoperable, Reusable Cryptographic Library), an advanced open-source engine bringing state-of-the-art post-quantum primitives to Go.

**Open Quantum Safe (liboqs)**
Stateful Hash-Based Signatures (LMS/XMSS) are provided by statically linking `liboqs`, the premier C library for prototyping quantum-resistant cryptography.

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
