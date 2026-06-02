# PQPG (Post-Quantum Privacy Guard) using Cloudflare Circl Library

By utilizing Cloudflare's `circl` library, PQPG implements the latest FIPS 203, 204, and 205 post-quantum standards alongside composite hybrid cryptography (combining classical elliptic curves with post-quantum lattices) to guarantee absolute data confidentiality against both traditional and quantum adversaries.

PQPG operates as both an **Asynchronous Secure Messenger (Encrypt-then-Sign Transport Layer)** and a **Personal Post-Quantum Vault**, allowing users to wrap local files (such as KeePass `.kdbx` databases) inside an impenetrable quantum-resistant armor layer.

---

## Core Features & Security Guarantees

* **Hybrid Cryptography:** Natively supports composite algorithms like **X-Wing** ($X25519$ + ML-KEM-768) and **EdDilithium** (Ed25519/Ed448 + Dilithium) to ensure security even if one cryptographic assumption fails.
* **Double-Layer Vault Defense:** Wraps standard symmetric-encrypted password vaults (e.g., KeePass AES-256/Argon2id cores) inside a layer of ML-KEM encapsulation and ML-DSA signatures, mitigating Grover's algorithm harvesting risks and securing local databases for long-term untrusted cloud synchronization.
* **Perfect Forward Secrecy (PFS):** Implements a continuous, one-way Symmetric Key Ratchet driven by Extendable-Output Functions (XOFs) with strict cryptographic domain separation (`PQPG-v1-KDF-Chain-`). Every packet derives a unique ephemeral key, ensuring compromised future states cannot decrypt past messages.
* **Fiat-Shamir Hardening:** Completely mitigates context-manipulation attacks by hashing the entire message envelope, timestamp, and routing suite (`PQPG-v1-FiatShamir-`) *before* generating the Post-Quantum digital signature.
* **Asynchronous Replay Mitigation:** Specifically designed for store-and-forward (email-style) architectures. Binds a Unix timestamp into the encrypted state and utilizes the unique cryptographic signature as a one-time transaction token, blocking duplicated packets via local state-deduplication checks.
* **Crypto-Agility:** Adheres strictly to SOLID principles. The underlying KEM, DSA, AEAD, and XOF implementations are fully decoupled via interfaces, allowing instant swapping of primitives.
* **ASCII Armor Encoding:** Wraps raw JSON and binary ciphertexts into clean, easily transmittable Base64 ASCII blocks, preventing data corruption across standard text channels.

---

## Supported Cryptographic Suite

| Category | Supported Algorithms |
| --- | --- |
| **KEM (Key Encapsulation)** | `ML-KEM-768`, `ML-KEM-1024`, `Kyber768`, `Kyber1024`, `FrodoKEM-640`, `X-Wing` (Hybrid) |
| **DSA (Digital Signatures)** | `ML-DSA-65`, `ML-DSA-87`, `Dilithium2/3/5`, `EdDilithium2/3` (Hybrid), `SLH-DSA` (All SHA2/SHAKE variants) |
| **AEAD (Symmetric Ciphers)** | `AES-256-GCM`, `ChaCha20-Poly1305`, `Ascon-128`, `Ascon-128a` |
| **XOF / Hashing** | `SHAKE128`, `SHAKE256`, `SHA3-256/384/512`, `KangarooTwelve` |

---

## Architecture Layout

The codebase is structured to isolate cryptographic mathematics from network framing, anti-replay state validation, and identity management.

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
│   │   ├── hash_adapters.go        # Keccak, SHA-3, and XOF engines
│   │   └── ratchet.go              # PFS unidirectional KDF chain (Domain Separated)
│   ├── identity/
│   │   └── keyring.go              # PKI management and disk I/O
│   └── packet/
│       ├── armor.go                # Base64 ASCII encoding
│       ├── envelope.go             # Encrypt-then-Sign protocol logic with Timestamping
│       └── replay.go               # Local signature-caching deduplication system
├── go.mod
└── go.sum

```

---

## Installation & Build Guide

### Prerequisites

* **Go 1.25.10** or higher.
* An active internet connection to fetch the Cloudflare CIRCL library.

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

Before sending files or locking vaults, you must generate a cryptographic profile.

* Select **Option 1**.
* Provide a name (e.g., `alice`).
* Choose a security profile (e.g., Option 4: `Full Hybrid Maximum` utilizing X-Wing, EdDilithium3, Ascon-128a, and KangarooTwelve).
* The engine will generate two folders: `./keys_alice/private` (which you protect) and `./keys_alice/public` (which you share with the world).

### 2. View Local Keyrings

Select **Option 2** to scan the current directory and print the cryptographic routing preferences (KEM, DSA, AEAD, and XOF choices) of all local public and private profiles.

### 3. Encrypt & Sign a File for Transport (Send)

To securely transmit a file to an external associate asynchronously:

* Select **Option 3**.
* **Inputs:** 1. The path to your private folder (e.g., `./keys_alice/private`).
2. The path to the recipient's public folder (e.g., `./keys_bob/public`).
3. The path to the target file (e.g., `payload.txt`).
* **Output:** An encrypted, cryptographically signed, ASCII-armored file named `outbox_msg.asc`.

### 4. Decrypt & Verify a File (Receive)

To open an encrypted envelope sent to you by a verified associate:

* Select **Option 4**.
* **Inputs:**
1. The path to your private folder (e.g., `./keys_bob/private`).
2. The path to the sender's public folder (e.g., `./keys_alice/public`).
3. The path to the ASCII armored file (e.g., `outbox_msg.asc`).


* **Output:** A verified, timestamped file (e.g., `decrypted_msg_20260531_150405.txt`).

### 5. Lock Personal Post-Quantum Vault (Local Storage)

To seal an offline file (such as a KeePass `passwords.kdbx` file) for long-term secure local backup or cloud synchronization:

* Select the **Lock Vault** action.
* **Inputs:**
1. The path to your private folder (e.g., `./keys_alice/private`).
2. Passphrase to unlock your local identity key.
3. The path to the file you want to lock (e.g., `passwords.kdbx`).


* **Output:** Generates a signed, encrypted, and armored file named `<filename>.pq_vault`. The original plaintext file can safely be purged from disk.

### 6. Unlock Personal Post-Quantum Vault (Local Storage)

To decrypt and verify your local storage file:

* Select the **Unlock Vault** action.
* **Inputs:**
1. The path to your private folder (e.g., `./keys_alice/private`).
2. Passphrase to unlock your local identity key.
3. The path to the locked vault file (e.g., `passwords.kdbx.pq_vault`).


* **Output:** Re-verifies signature context integrity against replay strings, decrypts the contents via post-quantum decapsulation, and restores the base file (e.g., `passwords.kdbx`).

---

## 🚀 Feature Trajectory & Roadmap

Future architectural sprints will focus on the following components:

### Phase 1: Core Performance & Operational Safety (No ZKPs)

* **Chunked Streaming Encryption (AEAD):** Refactoring pipeline architecture to process massive binary archives inside continuous 64KB sequential streams using `io.Reader` and `io.Writer` interfaces instead of reading complete files directly to memory.
* **Key Expiration & Expiry Metadata:** Introducing a deterministic validation deadline field (`ValidUntil`) embedded straight inside signed public user profiles to natively handle old key obsolescence.
* **BIP39 Entropy Backups:** Generating standard 24-word deterministic mnemonic strings during seed construction to recover identity keys over a plain text paper record sheet.

### Phase 2: User Experience and Management Layouts

* **Terminal User Interfaces (TUI):** Integrating advanced command layouts (e.g., via `charmbracelet/bubbletea`) to enable responsive pick menus and inline transfer monitoring.
* **Public Key Discovery Servers:** A minimal discovery directory service matching structural metadata configurations to specific target email identities.

### Phase 3: Zero-Knowledge Verification Layers (Transient Security)

*Note: ZKP primitives utilize classical discrete log equality constraints over standard elliptic curves. They are scoped strictly to short-term authorization routines to protect identity tokens, never long-term storage serialization.*

* **Blind Cloud Synchronization Verification (OPRF via RFC-9497 DLEQ):** Authenticating vault synchronization state against third-party remote file hosting platforms securely without passing direct static passwords or plaintext credential tokens.
* **Trustless Shared Vault Splits (Verifiable Secret Sharing via Schnorr ZKP):** Generating polynomial threshold shares for group vault recovery matrices while validating each chunk's mathematical accuracy via explicit zero-knowledge proofs.

---

## Acknowledgements & Upstream Projects

**Cloudflare CIRCL** The core cryptographic mathematics of PQPG are powered by **CIRCL (Cloudflare Interoperable, Reusable Cryptographic Library)**. CIRCL is an advanced open-source cryptographic engine written in pure Go, designed to bring state-of-the-art, experimental, and post-quantum cryptographic primitives to modern applications. It provides the highly optimized, memory-safe implementations of the NIST FIPS 203, 204, and 205 standards (ML-KEM, ML-DSA, SLH-DSA), as well as the composite hybrid architecture (X-Wing, EdDilithium) utilized in this engine.

We extend our profound gratitude to Cloudflare, the internal security engineering teams, and the global open-source contributors who maintain the CIRCL repository. Additionally, we acknowledge the academic researchers and cryptographers who dedicated years to designing and proving the underlying lattice-based and symmetric algorithms that make post-quantum security a reality.

---

## License & Third-Party Code

**CIRCL License** This software relies on the Cloudflare CIRCL library which released under BSD-3 Clause License.

Faz-Hernandez, A. and Kwiatkowski, K. (2019). Introducing CIRCL: An Advanced Cryptographic Library. Cloudflare. Available at [https://github.com/cloudflare/circl](https://github.com/cloudflare/circl). v1.6.3 Accessed May, 2026.

> Copyright (c) 2019, Cloudflare Inc.
> All rights reserved.
> Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
> 1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
> 2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
> 3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.
> 
> 
> *THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.*
