package main

import (
	"bufio"
	"fmt"
)

// showEncyclopedia runs the interactive CLI encyclopedia for the PQPG project.
func showEncyclopedia(reader *bufio.Reader) {
	for {
		fmt.Println("\n=========================================================================================")
		fmt.Println("                   PQPG CRYPTOGRAPHIC ENCYCLOPEDIA & ARCHIVE                             ")
		fmt.Println("=========================================================================================")
		fmt.Println(" Select a cryptographic domain to explore:")
		fmt.Println("  1) Key Encapsulation Mechanisms (KEMs - Lattices & Codes)")
		fmt.Println("  2) Digital Signature Algorithms (DSAs - FIPS & Experimental)")
		fmt.Println("  3) Stateful Hash-Based Signatures (Root PKI & Release Engineering)")
		fmt.Println("  4) Authenticated Encryption (AEADs, CAESAR Winners, Wide-Blocks)")
		fmt.Println("  5) Cryptographic Hashes & Extendable-Output Functions (XOFs)")
		fmt.Println("\n  99) Return to Main Menu")
		fmt.Println("=========================================================================================")
		fmt.Print("Choice [1-5]: ")

		choice := readInput(reader)

		switch choice {
		case "1":
			printKEMs(reader)
		case "2":
			printDSAs(reader)
		case "3":
			printStatefulDSAs(reader)
		case "4":
			printAEADs(reader)
		case "5":
			printHashes(reader)
		case "99":
			return
		default:
			fmt.Println("[-] Invalid selection.")
		}
	}
}

func printKEMs(reader *bufio.Reader) {
	fmt.Println("\n=========================================================================================")
	fmt.Println("                 KEY ENCAPSULATION MECHANISMS (KEMs - Asymmetric)                        ")
	fmt.Println("=========================================================================================")
	fmt.Println(`
[ LATTICE-BASED CRYPTOGRAPHY ]
* ML-KEM (Kyber):
  - Standard: NIST FIPS 203 (Published August 13, 2024).
  - Origin: The CRYSTALS (Cryptographic Suite for Algebraic Lattices) Team.
  - Mathematics: Module Learning With Errors (MLWE). It operates over polynomial rings, 
    introducing mathematical "noise" that is easily corrected by the private key holder but 
    computationally impossible for an attacker (even a quantum one) to reverse.
  - Profile: The primary general-purpose standard for global internet traffic, balancing 
    fast execution times with highly manageable public key sizes (~1 KB).

* FrodoKEM / eFrodo:
  - Standard: ISO/IEC 18033-2. Recommended by Germany (BSI) and France (ANSSI).
  - Origin: NIST PQC Round 3 Alternate Candidate.
  - Mathematics: Unstructured Learning With Errors (LWE).
  - Profile: Unlike Kyber, Frodo avoids the "algebraic structure" of ideal lattices. 
    It is considered extremely conservative and immune to specialized ring-based algebraic 
    attacks. The trade-off is massive key and ciphertext sizes (approx. 10–20 KB).

* SNTRUP (NTRU Prime):
  - Standard: De facto standard in OpenSSH 9.0+ (via sntrup761x25519).
  - Origin: Daniel J. Bernstein (djb), Chitchanok Chuengsatiansup, Tanja Lange.
  - Mathematics: NTRU lattices over prime degree rings.
  - Profile: Explicitly engineered to destroy the algebraic "noise" and decryption failures 
    inherent to earlier lattice designs. It intentionally avoids cyclotomic rings, making 
    it a highly trusted "structural failsafe" against lattice cryptanalysis.

[ CODE-BASED (ERROR-CORRECTING CODES) ]
* Classic McEliece:
  - Standard: NIST PQC Round 4 Finalist (Pending standardization for high-security systems).
  - Origin: Invented by Robert McEliece in 1978.
  - Mathematics: Binary Goppa Codes using hidden parity-check matrices.
  - Profile: The apex of cryptographic paranoia. It has survived 45+ years of intense 
    mathematical scrutiny. Keys are absolutely massive (1.3 MB for Level 5), but the 
    resulting ciphertexts are incredibly tiny (under 250 bytes).

* HQC (Hamming Quasi-Cyclic):
  - Standard: NIST PQC Round 4 Finalist.
  - Origin: French INRIA team.
  - Mathematics: Relies on the hardness of the Syndrome Decoding problem over Quasi-Cyclic codes.
  - Profile: A modern code-based alternative that shrinks McEliece's megabyte-sized public 
    keys down to manageable kilobytes, while retaining a rigorous security reduction.

* BIKE (Bit Flipping Key Encapsulation):
  - Standard: NIST PQC Round 4 Finalist.
  - Mathematics: Quasi-Cyclic Moderate Density Parity-Check (QC-MDPC) codes.
  - Profile: Intel-backed algorithm optimized for hardware acceleration and ephemeral 
    key exchanges, offering an excellent alternative to lattice-based math.

[ CLASSICAL ELLIPTIC CURVES ]
* X25519 & X448:
  - Standard: RFC 7748.
  - Origin: Daniel J. Bernstein (X25519) and Mike Hamburg (X448).
  - Profile: The pinnacle of classical ECC. Used in PQPG exclusively as the "classical 
    failsafe" half of all Dynamic Hybrid configurations.
`)
	pause(reader)
}

func printDSAs(reader *bufio.Reader) {
	fmt.Println("\n=========================================================================================")
	fmt.Println("                 DIGITAL SIGNATURE ALGORITHMS (DSAs - Stateless)                         ")
	fmt.Println("=========================================================================================")
	fmt.Println(`
[ LATTICE-BASED ]
* ML-DSA (Dilithium):
  - Standard: NIST FIPS 204 (Published August 13, 2024).
  - Origin: The CRYSTALS Team.
  - Mathematics: Fiat-Shamir with Aborts paradigm over Module Lattices.
  - Profile: The primary global post-quantum signature standard. It utilizes uniform 
    sampling rather than complex Gaussian sampling, making it fast and easy to implement 
    securely across varied architectures.

* FN-DSA (Falcon / Falcon-Padded):
  - Standard: FIPS 206 (Initial Public Draft phase 2025/2026).
  - Origin: Thomas Prest, Pierre-Alain Fouque, et al.
  - Mathematics: Hash-then-Sign over NTT-friendly rings using Fast Fourier Transforms 
    and Gaussian sampling over NTRU lattices.
  - Profile: Unmatched performance. It produces unbelievably tiny signatures and verifies 
    in microseconds. However, its reliance on constant-time 64-bit floating-point math 
    makes it notoriously difficult to implement securely without side-channel leaks.

[ STATELESS HASH-BASED ]
* SLH-DSA (SPHINCS+):
  - Standard: NIST FIPS 205 (Published August 13, 2024).
  - Mathematics: Merkle trees, WOTS+ (Winternitz), and FORS (Forest of Random Subsets).
  - Profile: The ultimate conservative fallback. Its security relies entirely on the 
    hardness of the underlying hash function (SHA2 or SHAKE). Signatures are huge 
    (up to 49 KB) and slow to generate, but mathematically bulletproof.

[ MULTIVARIATE QUADRATIC (NIST Round 3 Candidates - May 2026) ]
* UOV / OV (Unbalanced Oil and Vinegar):
  - Status: Advanced to Round 3 (NIST IR 8610).
  - Mathematics: Solves multivariate quadratic equations over finite fields.
  - Profile: Generates signatures of less than 100 bytes, but requires public keys 
    in the hundreds of kilobytes.

* MAYO:
  - Status: Advanced to Round 3 (NIST IR 8610).
  - Profile: An ingenious UOV variant that dramatically shrinks the public key size 
    by utilizing a smaller quadratic map ("mini-UOV") to construct the signature.

* SNOVA:
  - Status: Advanced to Round 3 (NIST IR 8610).
  - Profile: Shrinks UOV keys even further by operating over non-commutative rings 
    (matrices), trading mathematical simplicity for extreme compression.

[ MPC-IN-THE-HEAD & CODE-BASED (NIST Round 3 Candidates) ]
* MQOM (Multi-Party Computation in the Head):
  - Profile: Evaluates a multivariate quadratic function using an imaginary Multi-Party 
    Computation protocol, relying on Zero-Knowledge proofs to generate the signature.

* CROSS:
  - Profile: A code-based signature scheme relying on the Restricted Syndrome Decoding 
    Problem (RSDP). Offers excellent structural diversity away from lattices.
`)
	pause(reader)
}

func printStatefulDSAs(reader *bufio.Reader) {
	fmt.Println("\n=========================================================================================")
	fmt.Println("          STATEFUL HASH-BASED SIGNATURES (Release Engineering & Root PKI)                ")
	fmt.Println("=========================================================================================")
	fmt.Println(`
Stateful signatures are mathematically pristine and invulnerable to quantum computers. 
However, the signer MUST maintain a strict, persistent internal counter. If the signer 
ever signs two different messages with the exact same state (counter reuse), the 
private key is immediately, permanently compromised. 

PQPG handles this via the OQS C-FFI pipeline using Hardware-Safe Atomic AES-GCM Canaries.

* LMS (Leighton-Micali Signature):
  - Standard: NIST SP 800-208 / IETF RFC 8554.
  - Origin: Invented by David Leighton and Silvio Micali in 1995.
  - Profile: Utilizes a Merkle tree of Winternitz One-Time Signatures (WOTS). 
    It is the preferred standard for signing highly critical artifacts (like OS updates, 
    firmware, or immutable logs) where the total number of required signatures over the 
    key's lifetime is known in advance.

* XMSS & XMSS^MT (eXtended Merkle Signature Scheme):
  - Standard: NIST SP 800-208 / IETF RFC 8391.
  - Origin: Andreas Hülsing, et al.
  - Profile: Similar to LMS but applies randomized hashing (using XOR bitmasks before 
    hash compressions). The Multi-Tree (MT) variant layers trees on top of one another, 
    allowing for a virtually inexhaustible number of signatures (up to 2^60). 
    It is the gold standard for Post-Quantum Root Certificate Authorities.
`)
	pause(reader)
}

func printAEADs(reader *bufio.Reader) {
	fmt.Println("\n=========================================================================================")
	fmt.Println("              AUTHENTICATED ENCRYPTION (AEADs & Symmetric Ciphers)                       ")
	fmt.Println("=========================================================================================")
	fmt.Println(`
[ NIST STANDARDS ]
* AES-256-GCM / XAES-256-GCM:
  - Standard: FIPS 197. (XAES utilizes 24-byte extended nonces).
  - Profile: Hardware-accelerated (AES-NI). Extremely fast, but fragile if nonces are 
    ever accidentally reused.

* Ascon (128, 128a, 80pq):
  - Standard: NIST Lightweight Cryptography (LWC) Winner (2023) / CAESAR Winner.
  - Origin: TU Graz, Infineon, Lamponi.
  - Profile: Sponge-based AEAD designed specifically for constrained environments. 
    The 80pq variant expands the key to 160 bits specifically to resist Grover's 
    quantum search algorithms.

[ MISUSE-RESISTANT AUTHENTICATED ENCRYPTION (MRAE) ]
* Deoxys-II:
  - Standard: CAESAR Competition Winner (Defense in Depth category).
  - Origin: J. Jean, I. Nikolić, T. Peyrin.
  - Profile: A tweakable block cipher. If you accidentally reuse a nonce, an attacker 
    only learns if you sent the exact same message twice, completely protecting the 
    master key and remaining ciphertexts from extraction.

* AES-256-GCM-SIV:
  - Standard: IETF RFC 8452.
  - Profile: Replaces standard GCM with Synthetic Initialization Vectors (SIV). 
    It derives the nonce dynamically from the plaintext itself, making it completely 
    immune to random number generator (RNG) failures.

[ EXTENDED NONCE STREAM CIPHERS ]
* ChaCha20-Poly1305 / XChaCha20-Poly1305:
  - Standard: IETF RFC 8439.
  - Origin: Daniel J. Bernstein.
  - Profile: Software-optimized ARX (Add-Rotate-Xor) stream cipher. XChaCha expands 
    the nonce to 192 bits, pushing the probability of a random collision (Birthday Attack) 
    past the mathematical limits of the universe.

[ ULTRA-CONSERVATIVE BLOCK CIPHERS (Via PQPG EtM) ]
* Camellia:
  - Standard: ISO/IEC 18033-3, CRYPTREC (Japan), NESSIE (Europe).
  - Origin: Mitsubishi Electric and NTT (2000).
  - Profile: A Japanese Feistel network holding the exact same security margin as AES. 
    Deployed heavily in EU/Asian banking systems.

* Serpent:
  - Standard: AES Competition Finalist (Ranked 2nd to Rijndael).
  - Origin: Ross Anderson, Eli Biham, Lars Knudsen.
  - Profile: Designed for absolute maximum paranoia. While AES-256 uses 14 rounds, 
    Serpent uses 32 rounds of Substitution-Permutation networks.

* Threefish (256/512/1024):
  - Origin: Bruce Schneier, Niels Ferguson, et al.
  - Profile: The massive tweakable ARX block cipher powering the Skein hash function. 
    Capable of encrypting 1024 bits of data per single block. It completely obliterates 
    any classical cryptanalysis and requires 512 bits of pure KEM entropy to fuel.
`)
	pause(reader)
}

func printHashes(reader *bufio.Reader) {
	fmt.Println("\n=========================================================================================")
	fmt.Println("             CRYPTOGRAPHIC HASHES & EXTENDABLE-OUTPUT FUNCTIONS (XOFs)                   ")
	fmt.Println("=========================================================================================")
	fmt.Println(`
[ NIST STANDARDS ]
* SHA-2 (256/384/512):
  - Standard: FIPS 180-4.
  - Profile: The classic NSA-designed Merkle-Damgård construction. Highly accelerated 
    on modern silicon but vulnerable to length-extension attacks.

* SHA-3 / SHAKE (128/256):
  - Standard: FIPS 202.
  - Origin: The Keccak Team (Bertoni, Daemen, Peeters, Van Assche).
  - Profile: A completely different mathematical structure (Sponge Construction) that 
    is immune to length-extension. SHAKE functions are XOFs (Extendable-Output), meaning 
    they can securely generate an infinite, pseudo-random stream of bytes from a small seed. 
    Used heavily in PQPG as the primary Key Derivation Function (KDF).

[ HIGH-PERFORMANCE MODERN HASHES ]
* BLAKE3:
  - Origin: O'Connor, Aumasson, Neves, Wilcox-O'Hearn.
  - Profile: The evolutionary successor to the SHA-3 finalist BLAKE. It uses a highly 
    optimized Merkle tree internally, making it massively parallelizable. It is currently 
    the fastest cryptographic hash function in the world.

* KangarooTwelve:
  - Origin: The Keccak Team.
  - Profile: A heavily optimized, parallelizable version of Keccak (SHA-3) that operates 
    with 12 rounds instead of 24. Extremely fast while retaining a massive security margin.

[ WIDE-BLOCK HASHES ]
* Skein (256/512/1024):
  - Standard: SHA-3 Competition Finalist.
  - Origin: Bruce Schneier, Niels Ferguson, et al.
  - Profile: Built on the Threefish block cipher using the Unique Block Iteration (UBI) 
    chaining mode. Allows for enormous internal states (up to 1024 bits), making it 
    practically impervious to internal collision algorithms.
`)
	pause(reader)
}

func pause(reader *bufio.Reader) {
	fmt.Print("\n[Press ENTER to return to the Encyclopedia Menu...]")
	reader.ReadString('\n')
}
