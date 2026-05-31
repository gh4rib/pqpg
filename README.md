# PQPG (Post-Quantum Privacy Guard) using Cloudflare Circl Library

By utilizing Cloudflare's `circl` library, PQPG implements the latest FIPS 203, 204, and 205 post-quantum standards alongside composite hybrid cryptography (combining classical elliptic curves with post-quantum lattices) to guarantee absolute data confidentiality against both traditional and quantum adversaries.

---

## Core Features & Security Guarantees

- **Hybrid Cryptography:** Natively supports composite algorithms like **X-Wing** (X25519 + ML-KEM-768) and **EdDilithium** (Ed25519/Ed448 + Dilithium) to ensure security even if one cryptographic assumption fails.
- **Perfect Forward Secrecy (PFS):** Implements a continuous, one-way Symmetric Key Ratchet driven by Extendable-Output Functions (XOFs). Every packet derives a unique ephemeral key, ensuring compromised future states cannot decrypt past messages.
- **Fiat-Shamir Hardening:** Completely mitigates context-manipulation attacks by hashing the entire message envelope and routing suite *before* generating the Post-Quantum digital signature.
- **Crypto-Agility:** Adheres strictly to SOLID principles. The underlying KEM, DSA, AEAD, and XOF implementations are fully decoupled via interfaces, allowing instant swapping of primitives.
- **ASCII Armor Encoding:** Wraps raw JSON and binary ciphertexts into clean, easily transmittable Base64 ASCII blocks, preventing data corruption across standard text channels.

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

The codebase is structured to isolate cryptographic mathematics from network framing and identity management.

```text
pqc-messenger/
├── cmd/
│   └── messenger/
│       └── main.go                 # Interactive CLI orchestrator
├── internal/
│   ├── crypto/
│   │   ├── interfaces.go           # Abstract SOLID contracts
│   │   ├── registry.go             # Suite validation and factory engine
│   │   ├── kem_adapters.go         # CIRCL KEM & Hybrid implementations
│   │   ├── dsa_adapters.go         # CIRCL Signature implementations
│   │   ├── sym_adapters.go         # Block & Lightweight ciphers (Ascon)
│   │   ├── hash_adapters.go        # Keccak, SHA-3, and XOF engines
│   │   └── ratchet.go              # PFS unidirectional KDF chain
│   ├── identity/
│   │   └── keyring.go              # PKI management and disk I/O
│   └── packet/
│       ├── armor.go                # Base64 ASCII encoding
│       └── envelope.go             # Encrypt-then-Sign protocol logic
├── go.mod
└── go.sum

```

---

## Installation & Build Guide

### Prerequisites

- **Go 1.25.10** or higher.
- An active internet connection to fetch the Cloudflare CIRCL library.

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

Before sending or receiving files, you must generate a cryptographic profile.

* Select **Option 1**.
* Provide a name (e.g., `alice`).
* Choose a security profile. (e.g., Option 4: `Full Hybrid Maximum` utilizing X-Wing, EdDilithium3, Ascon-128a, and KangarooTwelve).
* The engine will generate two folders: `./keys_alice/private` (which you protect) and `./keys_alice/public` (which you share with the world).

### 2. View Local Keyrings

Select **Option 2** to scan the current directory and print the cryptographic routing preferences (KEM, DSA, AEAD, and XOF choices) of all local public and private profiles.

### 3. Encrypt & Sign a File (Send)

To securely transmit a file to an associate:

* Select **Option 3**.
* **Inputs:** 1. The path to your private folder (e.g., `./keys_alice/private`).
2. The path to the recipient's public folder (e.g., `./keys_bob/public`).
3. The path to the target file (e.g., `payload.txt`).
* **Output:** An encrypted, cryptographically signed, ASCII-armored file named `outbox_msg.asc`.

### 4. Decrypt & Verify a File (Receive)

To open an encrypted envelope sent to you:

* Select **Option 4**.
* **Inputs:**
1. The path to your private folder (e.g., `./keys_bob/private`).
2. The path to the sender's public folder (e.g., `./keys_alice/public`).
3. The path to the ASCII armored file (e.g., `outbox_msg.asc`).


* **Output:** The engine mathematically verifies the signature and MAC tag. If successful, it writes the original data to a timestamped file (e.g., `decrypted_msg_20260531_150405.txt`).
