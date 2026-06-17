# PQPG (Post-Quantum Privacy Guard)

By utilizing Cloudflare's `circl` library, the **Open Quantum Safe (`liboqs`) C-FFI engine**, Katzenpost's **`hpqc` (Hybrid Post-Quantum Cryptography) engine**, and EPFL's `kyber` abstract algebra engine, PQPG implements the latest FIPS 203, 204, and 205 post-quantum standards alongside an exhaustive, mathematically absolute composite hybrid architecture. It guarantees absolute data confidentiality and metadata anonymity against both traditional and quantum adversaries.

PQPG operates as an **Secured/Signed with Perfect Forward Secrecy(PFS) Privacy Guard (Double Ratchet)**, a **One-Shot Stateless Privacy Guard No (PFS)**, a **Personal Post-Quantum Vault**, a **Trustless Distributed Vault (Feldman VSS)**, a **Zero-Knowledge Time-Lock Engine**, a **Zero-Knowledge Data Notary (Proof of Breach)**, and an **Interoperable OpenPGP Node**, allowing users to wrap local files, directories, and networks inside an impenetrable quantum-resistant armor.

---

## Core Features & Security Guarantees

* **The 120-Suite Universal Hybrid Engines:** Enforces a strict, 100% Hybrid-Only rule across distinct cryptographic profiles. By seamlessly bridging Cloudflare's lattice logic (`circl`), Katzenpost's code-based logic (`hpqc`), and the hardware-accelerated `liboqs` C-FFI pipeline with classical ECC (X25519/X448/Ed25519/Ed448), PQPG guarantees that even if a devastating quantum cryptanalytic breakthrough occurs, your payloads cannot fall below classical baseline security.
* **Operational OQS Integration (MPC & Multivariate):** Natively binds experimental `liboqs` algorithms—such as MPC-in-the-head (MQOM, CROSS) and Multivariate Quadratics (MAYO, OV, SNOVA)—into pure Go architectures via strict CGO memory isolation and `SHA3-512` dynamic combiners.
* **Cross-Library Paranoia Composites:** Dynamically combines entirely different mathematical hardness assumptions from entirely different software libraries. Seamlessly pair a native CGO McEliece-8192 KEM (Code-Based) alongside a Cloudflare Dilithium5 DSA (Lattice-Based) and lock it using a Skein-1024 Wide-Block Cipher.
* **Stateless Encrypted Payloads:** Enables secure, one-shot messaging outside of an active Double Ratchet session. Utilizes direct KEM encapsulation passing through a 64-byte `SHA3-512` Cryptographic Combiner to dynamically derive maximum-entropy keys for massive symmetric ciphers.
* **Detached Signatures (Stateless & Stateful):** Hash massive payloads natively from the hard drive to generate tiny, mathematically isolated `.pqc_sig` files (using advanced lattice, code-based, or multivariate combinations) or ultra-secure `.lms_sig` files for failsafe release engineering.
* **Unified Wide-Block Architecture (Pure Skein):** Integrates the massive Threefish tweakable block cipher (up to 1024-bit block sizes) with the Skein hash function. This creates an ultra-conservative, unified cryptographic core immune to Grover's algorithm and future classical cryptanalysis, utilizing native Encrypt-then-MAC (EtM) processing for enormous payloads.
* **Misuse-Resistant & Extended-Nonce AEADs:** The Ratchet, Stateless, and Vault architectures natively integrate CAESAR-winning **Deoxys-II**, RFC 8452 **AES-GCM-SIV**, and extended 24-byte nonce stream ciphers (**XChaCha20**, **XAES-GCM**). This mathematically eliminates the risk of nonce-reuse attacks, state-desynchronization leakage, and birthday-bound collisions on massive payloads.
* **Isolated OpenPGP v6 Compatibility Engine:** Natively implements `draft-ietf-openpgp-pqc` utilizing strict composite algorithms (e.g., Kyber768 + X25519, ML-DSA-65 + Ed25519). Features a completely air-gapped architectural compartment to ensure standard Web of Trust interoperability without polluting the bespoke Double Ratchet ecosystem.
* **Stateful Post-Quantum Root Identities (LMS/XMSS):** Fully supports FIPS 205 Hash-Based Signatures for highly secure, failsafe software release engineering, powered natively by a statically linked Open Quantum Safe (`liboqs`) C library.
* **Zero-Knowledge Data Notary (Proof of Breach):** Proves possession of massive datasets (e.g., leaked or compromised data) without revealing a single byte of the file itself. Employs a native **Groth16 zk-SNARK** over the **BN254** elliptic curve using a custom **MiMC Merkle Tree** pipeline.
* **Zero-Knowledge Time-Lock Puzzles (VDF):** Encapsulates files inside an RSA-4096 Hidden Order Group. Uses a native Fiat-Shamir Zero-Knowledge Proof (Sigma Protocol) to mathematically guarantee puzzle validity, forcing sequential CPU delays (Dead Man's Switch) without exposing solvers to forged puzzles.
* **Trustless Distributed Vaults:** Implements Feldman’s Verifiable Secret Sharing (VSS) over the Ed25519 scalar field. Generates M-of-N Shamir shares bound to ECC commitments, mathematically proving share validity and preventing malicious dealers from destroying vaults.
* **Cryptographic Memory Hygiene & Rainbow Table Immunity:** Secures local keyrings using dynamic Argon2id salt rotation to neutralize pre-computed Rainbow Tables. Guarantees that all highly sensitive private key byte-slices (and C-FFI allocated buffers) are explicitly shredded from RAM immediately after cryptographic operations conclude.
* **Perfect Forward Secrecy (PFS):** Implements a Post-Quantum Double Ratchet. The state machine seamlessly handles out-of-order packets, dropping "dangling" keys after a strict 1000-message boundary to prevent RAM/State Exhaustion attacks.

---

## The Post-Quantum Double Ratchet Engine

PQPG manages Perfect Forward Secrecy and Post-Compromise Security using a highly robust "Separation of Concerns" architecture. The engine is divided into three distinct layers to prevent database corruption during asynchronous transfers:

1. **The Brain (`double_ratchet.go`):** A strictly stateless, functional mathematical engine. It knows nothing about the network or databases; it simply ingests byte arrays, executes Keccak KDF sponge derivations (now securely outputting 512-bit pure entropy for massive symmetric ciphers), and outputs new cryptographic chain keys.
2. **The Memory (`session.go` / BoltDB):** The ACID-compliant, encrypted storage vault. It safely stores the `RatchetState`, tracks historical public keys to defeat the **Implicit Rejection (FO Transform) Trap**, and runs the HMAC-SHA3 Anti-Replay Cache.
3. **The Conductor (`stream.go`):** The orchestrator layer. It pulls state from BoltDB, asks the Brain to spin the Ratchets in RAM, and utilizes **Deferred Commits**. The database state is *only* updated and saved to the hard drive if the AEAD cryptographic signature perfectly authenticates the payload, rendering PQPG virtually immune to session corruption from malformed files.

---

## Supported Cryptographic Suite

| Category | Supported Algorithms |
| --- | --- |
| **KEM (Key Encapsulation)** | `ML-KEM-768/1024`, `Kyber768/1024`, `FrodoKEM-640`, `HQC-128/192/256`, `mceliece348864` -> `mceliece8192128f`, `sntrup761`, `BIKE`, `CROSS`, `SNOVA` |
| **DSA (Stateless Signatures)** | `ML-DSA-65/87`, `Dilithium2/3/5`, `SLH-DSA` (Pure & Pre-hashed), `Falcon-padded-512/1024`, `MAYO`, `OV`, `MQOM2` |
| **Stateful DSA (FIPS 205)** | `LMS_H5` -> `LMS_H25`, `XMSS`, `XMSSMT` (Via natively linked `liboqs`) |
| **Dynamic Combiner Hybrids** | Engine dynamically pairs any lattice, code-based, hash-based, or multivariate algorithm with `X25519`, `X448`, `Ed25519`, or `Ed448` via SHA3-512 blenders |
| **AEAD (Symmetric Ciphers)** | `AES-256-GCM`, `ChaCha20-Poly1305`, `XAES-256-GCM`, `XChaCha20-Poly1305`, `AES-256-GCM-SIV`, `Deoxys-II-256-128`, `Ascon-128/128a/80pq`, `Threefish-256/512/1024-EtM`, `Camellia-256-EtM`, `Serpent-256-EtM` |
| **XOF / Hashing** | `SHAKE128/256`, `SHA3-256/384/512`, `SHA-512`, `KangarooTwelve`, `Skein-256/512/1024`, `BLAKE3-512` |
| **Zero-Knowledge Primitives** | `Groth16` (zk-SNARK), `BN254` Pairing-Friendly Curve, `MiMC` (Sponge-Hash) |

---

## Architecture Layout

The codebase strictly adheres to SOLID principles, utilizing Adapter Patterns and dynamic Factory Registries to isolate cryptographic mathematics from network framing, anti-replay state validation, and identity management.

```text
pqc-messenger/
├── cmd/
│   └── messenger/
│       ├── main.go               # Top-level Subsystem Routing (Core, OQS, OpenPGP)
│       ├── archive.go            # On-the-fly Directory Tarball & Compression Engine
│       ├── notary-handlers.go    # CLI orchestration for ZK Data Notary (Prove/Verify)
│       ├── openpgp-handlers.go   # CLI orchestration for the isolated OpenPGP v6 compartment
│       ├── identity-handlers.go  # Orchestrates the Core HPQC Hybrid UI Selection
│       ├── oqs-handlers.go       # Orchestrates the liboqs 120-suite Hybrid UI Selection
│       └── *-handlers.go
├── internal/
│   ├── crypto/
│   │   ├── registry.go           # Dynamic Namespace Router (Hpqc-, Oqs-, Hybrid-)
│   │   ├── hybrid-kem.go         # PQPG SHA3-512 KEM Cryptographic Combiner
│   │   ├── hybrid-dsa.go         # PQPG Independent Proof DSA Combiner
│   │   ├── hpqc-adapter.go       # Abstract Interface Adapter for Katzenpost HPQC
│   │   ├── oqs-adapter.go        # Safe C-FFI Interface Adapter & Memory Manager for liboqs
│   │   └── double-ratchet.go     # Stateless KDF math for the PFS Ratchet
│   ├── hpqc/                     # Native Katzenpost engine (Code-based/NTRU Lattices)
│   ├── hpq/                      # Scorched-Earth localized HPQ dependency
│   ├── xx-network-crypto/        # Scorched-Earth localized upstream dependency
│   ├── xx-network-primitives/    # Scorched-Earth localized upstream dependency
│   ├── elixxir-crypto/           # Scorched-Earth localized upstream dependency
│   ├── deoxysii/                 # CAESAR-Winning Misuse-Resistant AEAD (MRAE)
│   ├── aesgcmsiv-noasm/          # RFC 8452 AES-GCM-SIV (Pure Go / Cross-Platform)
│   ├── aesgcmsiv-asm/            # AES-SIV-CMAC (Deterministic Hardware Accelerated)
│   ├── threefish/                # Tweakable Wide-Block Cipher Engine (256/512/1024)
│   ├── skein/                    # UBI Chaining Mode Hashing & XOF Engine
│   ├── blake3/                   # Native BLAKE3 Implementation
│   ├── oqs/                      # Hardcoded Open Quantum Safe C-FFI Wrappers
│   ├── openpgp_pqc/              # draft-ietf-openpgp-pqc wrappers for ProtonMail/gopenpgp v3
│   ├── identity/
│   │   ├── keyring.go            # PKI management and disk I/O
│   │   ├── rollback.go           # Hardware-safe atomic AES-GCM Canary state guard
│   │   └── session.go            # AES-GCM Encrypted BoltDB (Blind Indexes & Anti-Replay)
│   ├── vdf/
│   │   └── rsa_vdf.go            # Native RSA Subgroup math & Fiat-Shamir ZKP
│   ├── zkp/
│   │   └── engine.go             # Groth16 Setup, Prove, and Verify mathematical interface
│   └── packet/
│       ├── stream.go             # Double Ratchet Sealed Sender Envelopes (Chunked)
│       └── stateless.go          # One-Shot Payloads & Massive Entropy KEM Extraction
├── go.mod
└── go.sum

```

---

## Installation & Build Guide

### Prerequisites

* **Go 1.25.10** or higher.
* **CMake**, **Ninja**, and a **C Compiler** (`gcc`/`clang`) for building the static OQS subsystem.
* Active internet connection to fetch Cloudflare `circl`, EPFL `kyber/v4`, ConsenSys `gnark`, and ProtonMail `gopenpgp`.
* *(Note: `hpqc` and its upstream dependencies are hard-forked and strictly localized in the `internal/` directory to permanently protect against upstream GitLab/GitHub repository deletions and dependency poisoning).*

### Phase 1: Build the Static `liboqs` C-Engine

To utilize FIPS 205 Stateful Signatures and experimental OQS KEMs without trapping users in shared-library (`.so`) dependency hell, PQPG explicitly requires compiling `liboqs` as a static archive (`.a`) with OpenSSL disabled. This guarantees maximum cross-platform binary portability.

```bash
cd pqpg
# Clone the upstream Open Quantum Safe repository
git clone -b main https://github.com/open-quantum-safe/liboqs.git
cd liboqs

# Prepare the build directory
mkdir build && cd build

# Configure CMake for a Static Archive WITHOUT OpenSSL (AMD64)
cmake -G Ninja \
  -DCMAKE_INSTALL_PREFIX=$(pwd)/../oqs_static_env \
  -DBUILD_SHARED_LIBS=OFF \
  -DOQS_USE_OPENSSL=OFF \
  -DOQS_ENABLE_SIG_STFL_LMS=ON \
  -DOQS_ENABLE_SIG_STFL_XMSS=ON \
  -DOQS_HAZARDOUS_EXPERIMENTAL_ENABLE_SIG_STFL_KEY_SIG_GEN=ON \
  ..
  
# Configure CMake for a Static Archive WITHOUT OpenSSL (ARM64)
cmake -G Ninja \
  -DCMAKE_INSTALL_PREFIX=$(pwd)/../oqs_static_env \
  -DBUILD_SHARED_LIBS=OFF \
  -DOQS_USE_OPENSSL=OFF \
  -DOQS_ENABLE_SIG_STFL_LMS=ON \
  -DOQS_ENABLE_SIG_STFL_XMSS=ON \
  -DOQS_HAZARDOUS_EXPERIMENTAL_ENABLE_SIG_STFL_KEY_SIG_GEN=ON \
  -DCMAKE_TOOLCHAIN_FILE=../.CMake/toolchain_arm64.cmake \
  ..

# Compile and output the static archive to the isolated environment folder
ninja
ninja install
cd ../..

```

### Phase 2: Build the PQPG Executable

Once the `oqs_static_env` is successfully built, go to the `internal/oqs` and change the `cgo LDFLAGS` and `cgo CFLAGS` to the corresponding `liboqs.a` library path inside `cfuncs.go` and `oqs.go`.

```bash

# ARM64
CGO_ENABLED=1 \
CC=aarch64-linux-gnu-gcc \
GOOS=linux \
GOARCH=arm64 \
go build -mod=vendor -compiler=gc -o pqpg-linux-arm64 ./cmd/messenger

#AMD64
CGO_ENABLED=1 \
GOOS=linux \
GOARCH=amd64 \
go build -mod=vendor  -compiler=gc  -o pqpg-linux-amd64 ./cmd/messenger

```

---

## 📖 Usage Manual

Launch the interactive engine by running `./pqpg` in your terminal. You will be prompted to select one of three routing modules:

* **Option 1: Core Crypto Engine:** The native, pure-Go/Assembly ecosystem containing the advanced Zero-Knowledge interfaces (Multi-platform).
* **Option 2: OQS Extension Engine:** The hardware-accelerated `liboqs` C-FFI pipeline exclusively driving messaging, vaults, and detached signatures (Restricted to Linux/AMD64).
* **Option 3: OpenPGP PQC Engine:** The interoperable `draft-ietf-openpgp-pqc` v6 compatibility node.

### Application Workflows

Depending on whether you boot into the **Core Engine** or the **OQS Extension Engine**, PQPG routes you through the unified network layers.

#### 1. Establish an Identity (PKI Setup)

Generate a cryptographic profile. The **Core Engine** offers a 120-suite selection built on CIRCL and HPQC logic, while the **OQS Engine** unlocks an exclusive 120-suite hardware-accelerated profiler featuring experimental algorithms like MAYO, OV, SNOVA, MQOM2, and CROSS.

#### 2. Asynchronous Messaging (Double Ratchet)

Securely send a payload using the Perfect Forward Secrecy protocol. You can target either a single file or an entire directory (which is automatically bundled into a maximum-compression `.tar.gz` archive on the fly before encryption).

#### 3. Stateless Messaging (One-Shot Payloads)

Encrypt data for a recipient *outside* of an active Ratchet session. Using the `stateless.go` architecture, the engine executes direct KEM encapsulation and derives the payload key via a strict 64-byte `SHA3-512` KDF, ensuring maximum entropy for wide-block ciphers.

#### 4. Personal Post-Quantum Vault

Wrap a local file or directory inside a continuous stream-encrypted envelope deterministically bound to your own identity for secure cold storage.

#### 5. Detached Signatures (Stateless)

Hash a massive file natively from the hard drive to generate a tiny, mathematically isolated `.pqc_sig` file using advanced lattice, code-based, or multivariate quadratic signature combinations.

#### 6. Release Engineering (FIPS 205 Stateful Signatures)

Generate an ultra-secure `.lms_sig` or `.xmss_sig` file specifically designed for software release engineering. The engine synchronously locks the OS, executes the hash-tree traversal, advances the hardware-safe Anti-Rollback AES-GCM canary, and outputs the signature.

### Advanced Capabilities (Exclusive to Core Engine)

The following computational features rely on the `gnark` and `kyber` abstract algebra engines and are accessible strictly through the **Option 1: Core Crypto Engine** menu.

#### 7. M-of-N Shared Vault (Feldman VSS Threshold)

Distribute a vault across multiple stakeholders. The engine plots a secret polynomial over the Ed25519 scalar field and outputs `N` shares. Upon restoration, the engine mathematically proves share authenticity before executing Lagrange interpolation to restore the data.

#### 8. Zero-Knowledge Time-Lock Puzzles (Dead Man's Switch)

Lock a file or directory inside an RSA-4096 Verifiable Delay Function (VDF). The engine generates a sequential CPU puzzle and a native Fiat-Shamir Zero-Knowledge Proof, outputting a `.timelock` artifact. Unlocking a puzzle forces un-parallelizable sequential CPU operations to derive the AES decryption key.

#### 9. Zero-Knowledge Data Notary (Proof of Breach)

Act as a Prover and generate a zk-SNARK proving possession of a targeted leak file or database. The engine processes the local file chunk-by-chunk inside a field-compliant MiMC Merkle tree and exports a standalone `.zkp` proof envelope. Auditors can verify the proof by checking the R1CS constraints against a SHA3-256 Verifying Key fingerprint.

---

## Acknowledgements & Upstream Projects

**Cloudflare CIRCL**
The core lattice and ECC mathematics of PQPG are powered by CIRCL (Cloudflare Interoperable, Reusable Cryptographic Library), an advanced open-source engine bringing state-of-the-art post-quantum primitives to Go.

**Katzenpost HPQC**
This library contains highly optimized, native CGO/Assembly Golang implementations of leading quantum-resistant Code-based primitives (McEliece, HQC) and NTRU lattices (SNTRUP). Available at: `https://github.com/katzenpost/hpqc`

**Open Quantum Safe (liboqs)**
The C-FFI pipeline providing hardware-accelerated Stateful Hash-Based Signatures (LMS/XMSS) and experimental MPC-in-the-head/Multivariate algorithms by statically linking `liboqs`, the premier C library for prototyping quantum-resistant cryptography.

**EPFL Advanced Cryptography Group (Kyber)**
Threshold cryptography and Feldman VSS operations rely on the `go.dedis.ch/kyber` abstract algebra suite, providing the vital Elliptic Curve scalar math required for Zero-Knowledge and verifiable group commitments.

**ConsenSys gnark**
The zero-knowledge SNARK ecosystem, circuit compilation, and R1CS Groth16 proving/verifying mechanisms are powered entirely by the high-performance `gnark` framework.

**Oasis Protocol & Deoxys-II**
The CAESAR competition-winning Deoxys-II algorithm is powered by the highly audited implementations developed for the Oasis network core, bringing Misuse-Resistant Authenticated Encryption (MRAE) to PQPG.

**MinIO (secure-io) & Fernandezvara**
AES-SIV-CMAC and RFC 8452 AES-GCM-SIV implementations utilize the high-performance logic provided by the MinIO cryptography team and the `fernandezvara` BoringSSL Go ports.

**Skein & Threefish**
The wide-block cryptographic primitives are based on the Skein hash function family designed by Bruce Schneier, Niels Ferguson, Stefan Lucks, Doug Whiting, Mihir Bellare, Tadayoshi Kohno, Jon Callas, and Jesse Walker. Implemented via Go adaptations.

**ProtonMail (gopenpgp & go-crypto)**
The OpenPGP compatibility compartment is powered by ProtonMail's highly audited `gopenpgp` (v3) library and their fork of the Go crypto library, providing strict compliance with the `draft-ietf-openpgp-pqc` specifications.

**Multiple packages from [github.com/aead](https://github.com/aead) developed by Andreas Auernhammer**
The Serpent block cipher, Ascon, and related high-performance symmetric packages.

**go-xmssmt (by bwesterb)**
Go implementation of the stateful hash-based signature-scheme XMSS(MT) described in RFC 8391 (XMSS: Extended Hash-Based Signatures) and NIST SP 800-208.

**lms-go (by Trail of Bits)**
Go implementation of Leighton-Micali stateful Hash-Based Signatures (RFC 8554).

**Elixxir & xx network**
Primitives and cryptography libraries (`git.xx.network`) providing upstream dependency support for HPQC sub-modules.

---

## License & Third-Party Code

**CIRCL License**
This software relies on the Cloudflare CIRCL library which is released under the BSD-3 Clause License.
Faz-Hernandez, A. and Kwiatkowski, K. (2019). *Introducing CIRCL: An Advanced Cryptographic Library*. Cloudflare. Available at [https://github.com/cloudflare/circl](https://github.com/cloudflare/circl). v1.6.3 Accessed May, 2026.

> Copyright (c) 2019, Cloudflare Inc.
> All rights reserved.
> Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
> 1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
> 2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
> 3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.
> 
>
