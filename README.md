# PQPG (Post-Quantum Privacy Guard)

By utilizing Cloudflare's `circl` library, the **Open Quantum Safe (`liboqs`) C-FFI engine**, Katzenpost's **`hpqc` (Hybrid Post-Quantum Cryptography) engine**, and EPFL's `kyber` abstract algebra engine, PQPG implements the latest FIPS 203, 204, and 205 post-quantum standards alongside an exhaustive, mathematically absolute composite hybrid architecture. It guarantees absolute data confidentiality and metadata anonymity against both traditional and quantum adversaries.

PQPG operates as an **Asynchronous Secure Messenger (Sealed Sender Transport Layer)**, a **Personal Post-Quantum Vault**, a **Trustless Distributed Vault (Feldman VSS)**, a **Zero-Knowledge Time-Lock Engine**, a **Zero-Knowledge Data Notary (Proof of Breach)**, and an **Interoperable OpenPGP Node**, allowing users to wrap local files, directories, and networks inside an impenetrable quantum-resistant armor.

---

## Core Features & Security Guarantees

* **The 120-Suite Universal Hybrid Engine:** Enforces a strict, 100% Hybrid-Only rule across 120 distinct cryptographic profiles. By seamlessly bridging Cloudflare's lattice logic (`circl`) with Katzenpost's code-based/NTRU logic (`hpqc`) and classical ECC (X25519/X448/Ed25519/Ed448), PQPG guarantees that even if a devastating quantum cryptanalytic breakthrough shatters every post-quantum algorithm tomorrow, your payloads cannot fall below classical baseline security.
* **Cross-Library Paranoia Composites:** Dynamically combines entirely different mathematical hardness assumptions from entirely different software libraries. Seamlessly pair a native CGO McEliece-8192 KEM (Code-Based) alongside a Cloudflare Dilithium5 DSA (Lattice-Based) and lock it using a Skein-1024 Wide-Block Cipher.
* **Unified Wide-Block Architecture (Pure Skein):** Integrates the massive Threefish tweakable block cipher (up to 1024-bit block sizes) with the Skein hash function. This creates an ultra-conservative, unified cryptographic core immune to Grover's algorithm and future classical cryptanalysis, utilizing native Encrypt-then-MAC (EtM) processing for enormous payloads.
* **Misuse-Resistant & Extended-Nonce AEADs:** The Double Ratchet and Vault architectures natively integrate CAESAR-winning **Deoxys-II**, RFC 8452 **AES-GCM-SIV**, and extended 24-byte nonce stream ciphers (**XChaCha20**, **XAES-GCM**). This mathematically eliminates the risk of nonce-reuse attacks, state-desynchronization leakage, and birthday-bound collisions on massive payloads.
* **Isolated OpenPGP v6 Compatibility Engine:** Natively implements `draft-ietf-openpgp-pqc` utilizing strict composite algorithms (e.g., Kyber768 + X25519, ML-DSA-65 + Ed25519). Features a completely air-gapped architectural compartment to ensure standard Web of Trust interoperability without polluting the bespoke Double Ratchet ecosystem.
* **Stateful Post-Quantum Root Identities (LMS/XMSS):** Fully supports FIPS 205 Hash-Based Signatures for highly secure, failsafe software release engineering, powered natively by a statically linked Open Quantum Safe (`liboqs`) C library.
* **Intelligent Directory Archiving:** Seamlessly detects and bundles raw directories into highly compressed `.tar.gz` archives on the fly before routing them through the post-quantum encryption engine, preserving complex file tree structures natively without requiring third-party zip tools.
* **Hardware-Safe Anti-Rollback Canaries:** Defeats catastrophic state-reuse attacks in LMS/XMSS using POSIX-compliant, hardware-level atomic file swaps and AES-GCM protected canaries, ensuring state integrity even during sudden power-loss events.
* **Zero-Knowledge Data Notary (Proof of Breach):** Proves possession of massive datasets (e.g., leaked or compromised data) without revealing a single byte of the file itself. Employs a native **Groth16 zk-SNARK** over the **BN254** elliptic curve using a custom **MiMC Merkle Tree** pipeline.
* **Hardened Circuit Defenses:** Integrates strict domain separation for empty leaf padding (`PQPG-EMPTY-MERKLE-PAD`) to prevent length-extension collisions and mandates a minimum tree depth of 4. Protects verifiers against malicious "Rogue Setup" attacks by calculating and enforcing a **SHA3-256 fingerprint** verification step on the circuit's Verifying Key.
* **Zero-Knowledge Time-Lock Puzzles (VDF):** Encapsulates files inside an RSA-4096 Hidden Order Group. Uses a native Fiat-Shamir Zero-Knowledge Proof (Sigma Protocol) to mathematically guarantee puzzle validity, forcing sequential CPU delays (Dead Man's Switch) without exposing solvers to forged puzzles.
* **Cryptographic Memory Hygiene & Rainbow Table Immunity:** Secures local keyrings using dynamic Argon2id salt rotation to neutralize pre-computed Rainbow Tables. Guarantees that all highly sensitive private key byte-slices are explicitly shredded from RAM immediately after cryptographic operations conclude.
* **Sealed Sender & Receiver Anonymity:** Uses a Dual-Layer envelope padded to strict 1KB boundaries. Drops plaintext public keys and routes via **32-byte Keccak Key Hints**, meaning a network eavesdropper cannot mathematically identify the receiver.
* **Perfect Forward Secrecy (PFS):** Implements a Post-Quantum Double Ratchet. The state machine seamlessly handles out-of-order packets, dropping "dangling" keys after a strict 1000-message boundary to prevent RAM/State Exhaustion attacks.
* **Trustless Distributed Vaults:** Implements Feldman’s Verifiable Secret Sharing (VSS) over the Ed25519 scalar field. Generates M-of-N Shamir shares bound to ECC commitments, mathematically proving share validity and preventing malicious dealers from destroying vaults.

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
| **KEM (Key Encapsulation)** | `ML-KEM-768/1024`, `Kyber768/1024`, `FrodoKEM-640`, `HQC-128/192/256`, `mceliece348864` -> `mceliece8192128f`, `sntrup4591761` |
| **DSA (Stateless Signatures)** | `ML-DSA-65/87`, `Dilithium2/3/5`, `SLH-DSA`, `Falcon-padded-512`, `Falcon-padded-1024` |
| **Stateful DSA (FIPS 205)** | `LMS_H5` -> `LMS_H25`, `XMSS`, `XMSSMT` (Via natively linked `liboqs`) |
| **Dynamic Combiner Hybrids** | Engine dynamically pairs any lattice, code-based, or hash-based algorithm with `X25519`, `X448`, `Ed25519`, or `Ed448` via SHA3-512 blenders |
| **AEAD (Symmetric Ciphers)** | `AES-256-GCM`, `ChaCha20-Poly1305`, `XAES-256-GCM`, `XChaCha20-Poly1305`, `AES-256-GCM-SIV`, `AES-256-SIV-CMAC`, `Deoxys-II-256-128`, `Ascon-128/128a`, `Threefish-256/512/1024-EtM` |
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
│       ├── identity-handlers.go  # Orchestrates the 120-suite Hybrid UI Selection
│       └── *-handlers.go
├── internal/
│   ├── crypto/
│   │   ├── registry.go           # Dynamic Namespace Router (Hpqc- vs Hybrid-)
│   │   ├── hybrid-kem.go         # PQPG SHA3-512 KEM Cryptographic Combiner
│   │   ├── hybrid-dsa.go         # PQPG Independent Proof DSA Combiner
│   │   ├── hpqc-adapter.go       # Abstract Interface Adapter for Katzenpost HPQC
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
│       └── stateless.go          # Massive Entropy KEM Extraction for Threefish-1024
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

To utilize FIPS 205 Stateful Signatures without trapping users in shared-library (`.so`) dependency hell, PQPG explicitly requires compiling `liboqs` as a static archive (`.a`) with OpenSSL disabled. This guarantees maximum cross-platform binary portability.

```bash
cd pqpg
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

Once the `oqs_static_env` is successfully built, go to the `internal/oqs` and change the `cgo LDFLAGS` and `cgo CFLAGS` to the corresponding `liboqs.a` library path inside `cfuncs.go` and `oqs.go`.

---

## 📖 Usage Manual

Launch the interactive engine by running `./pqpg` in your terminal. You will be prompted to select one of three engines:

* **Option 1: Core Crypto Engine:** The native PQPG Double Ratchet ecosystem (Multi-platform).
* **Option 2: OQS Extension Engine:** Strict Hash-Based Signatures (Restricted to supported Linux/AMD64 environments).
* **Option 3: OpenPGP PQC Engine:** The interoperable `draft-ietf-openpgp-pqc` compatibility node.

### Core Crypto Engine (Option 1)

#### Establish an Identity (PKI Setup)

Select **Option 1** to generate a cryptographic profile. You will be presented with a 120-suite selection menu encompassing NIST FIPS Standards, Native HPQC Code-Based/NTRU combinations, Stateful Release-Engineer profiles, and Extreme Paranoia Cross-Library Composites.

#### Asynchronous Messaging (Double Ratchet)

Select **Option 2** to securely send a payload using the Double Ratchet protocol. **(Note: You can target either a single file OR an entire directory. Directories are automatically bundled into maximum-compression `.tar.gz` archives on the fly before encryption).** Select **Option 3** to authenticate and extract an incoming `.asc` envelope.

#### Personal Post-Quantum Vault (Lock/Unlock)

Select **Option 4** to wrap a local file or directory inside a continuous stream-encrypted envelope deterministically bound to your identity. Select **Option 5** to decrypt it.

#### M-of-N Shared Vault (Feldman VSS Threshold)

Select **Option 6** to distribute a vault across multiple stakeholders. The engine plots a secret polynomial over the Ed25519 scalar field and outputs `N` shares. Select **Option 7** to provide `M` shares; the engine mathematically proves share authenticity before executing Lagrange interpolation to restore the data.

#### Cleartext Detached Signatures (Stateless & Stateful)

Select **Option 8** to hash a massive file natively from the hard drive, generating a tiny detached signature file (`.pqc_sig`). If utilizing an LMS or XMSS identity via the OQS subsystem, the engine synchronously locks the OS, advances the Anti-Rollback canary, and appends the FIPS 205 signature (`.lms_sig`). Select **Option 9** to stream-verify the payload.

#### Zero-Knowledge Time-Lock Puzzles (Dead Man's Switch)

Select **Option 10** to lock a file or directory inside an RSA-4096 Verifiable Delay Function (VDF). The engine generates a sequential CPU puzzle and a native Fiat-Shamir Zero-Knowledge Proof, outputting a `.timelock` artifact. Select **Option 11** to unlock a puzzle, forcing un-parallelizable sequential CPU operations to derive the AES decryption key.

#### Zero-Knowledge Data Notary (Proof of Breach)

Select **Option 12** to act as a Prover and generate a zk-SNARK proving possession of a targeted leak file or database. The engine processes the local file chunk-by-chunk inside a field-compliant MiMC Merkle tree and exports a standalone `.zkp` proof envelope. Select **Option 13** to act as an Auditor and verify a standalone proof. The verifier calculates the Verifying Key's **SHA3-256 fingerprint** for human confirmation before checking the R1CS constraints.

---

## Acknowledgements & Upstream Projects

**Cloudflare CIRCL**
The core lattice and ECC mathematics of PQPG are powered by CIRCL (Cloudflare Interoperable, Reusable Cryptographic Library), an advanced open-source engine bringing state-of-the-art post-quantum primitives to Go.

**Katzenpost HPQC**
This library contains highly optimized, native CGO/Assembly Golang implementations of leading quantum-resistant Code-based primitives (McEliece, HQC) and NTRU lattices (SNTRUP). Available at: `https://github.com/katzenpost/hpqc`

**Oasis Protocol & Deoxys-II**
The CAESAR competition-winning Deoxys-II algorithm is powered by the highly audited implementations developed for the Oasis network core, bringing Misuse-Resistant Authenticated Encryption (MRAE) to PQPG.

**MinIO (secure-io) & Fernandezvara**
AES-SIV-CMAC and RFC 8452 AES-GCM-SIV implementations utilize the high-performance logic provided by the MinIO cryptography team and the `fernandezvara` BoringSSL Go ports.

**Open Quantum Safe (liboqs)**
Stateful Hash-Based Signatures (LMS/XMSS) are provided by statically linking `liboqs`, the premier C library for prototyping quantum-resistant cryptography.

**EPFL Advanced Cryptography Group (Kyber)**
Threshold cryptography and Feldman VSS operations rely on the `go.dedis.ch/kyber` abstract algebra suite, providing the vital Elliptic Curve scalar math required for Zero-Knowledge and verifiable group commitments.

**ConsenSys gnark**
The zero-knowledge SNARK ecosystem, circuit compilation, and R1CS Groth16 proving/verifying mechanisms are powered entirely by the high-performance `gnark` framework.

**Skein & Threefish**
The wide-block cryptographic primitives are based on the Skein hash function family designed by Bruce Schneier, Niels Ferguson, Stefan Lucks, Doug Whiting, Mihir Bellare, Tadayoshi Kohno, Jon Callas, and Jesse Walker. Implemented via Go adaptations.

**ProtonMail (gopenpgp & go-crypto)**
The OpenPGP compatibility compartment is powered by ProtonMail's highly audited `gopenpgp` (v3) library and their fork of the Go crypto library, providing strict compliance with the `draft-ietf-openpgp-pqc` specifications.

**Multiple packages from [github.com/aead](https://github.com/aead) developed by Andreas Auernhammer**
The Serpent block cipher and related high-performance symmetric packages.

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
