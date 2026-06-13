package main

import (
	"bufio"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/gh4rib/pqpg/internal/identity"
	"github.com/gh4rib/pqpg/internal/oqs"
	"github.com/gh4rib/pqpg/internal/phantom"
)

func handleOQSDiagnostics() {
	fmt.Println("\n=======================================================")
	fmt.Println("             liboqs C-FFI ENGINE DIAGNOSTICS           ")
	fmt.Println("=======================================================")

	// 1. Verify C-FFI Bridge & Version
	// This reaches directly into the statically linked C archive.
	// If it returns a string without crashing, your static build is perfect.
	version := oqs.LiboqsVersion()
	fmt.Printf("[+] C-FFI Bridge Active. liboqs Version: %s\n", version)

	// 2. Fetch Signature Algorithms
	sigs := oqs.EnabledSigs()
	fmt.Printf("\n[*] Enabled Signature Algorithms (%d Total):\n", len(sigs))
	for _, sig := range sigs {
		// Visually highlight the stateful algorithms we specifically compiled via CMake
		if strings.HasPrefix(sig, "LMS") || strings.HasPrefix(sig, "XMSS") {
			fmt.Printf("    - %s  [STATEFUL - READY]\n", sig)
		} else {
			fmt.Printf("    - %s\n", sig)
		}
	}

	// 3. Fetch KEM Algorithms
	kems := oqs.EnabledKEMs()
	fmt.Printf("\n[*] Enabled Key Encapsulation Mechanisms (%d Total):\n", len(kems))
	for _, kem := range kems {
		fmt.Printf("    - %s\n", kem)
	}

	fmt.Println("\n=======================================================")
	fmt.Println("[+] Diagnostics Complete. Ready for Post-Quantum Operations.")
}

func handleOQSIdentityGeneration(reader *bufio.Reader) {

	fmt.Print("\nEnter Real Name (e.g., Alice Vance): ")
	name := readInput(reader)
	if name == "" {
		return
	}

	fmt.Print("Enter E-mail Address (e.g., alice@example.com): ")
	email := readInput(reader)
	if email == "" || !strings.Contains(email, "@") {
		return
	}

	fmt.Print("Enter Comment/Description (Optional): ")
	comment := readInput(reader)

	fmt.Print("Enter an Identity Protection Passphrase: ")
	pass1 := readInput(reader)
	if len(pass1) < 4 {
		fmt.Println("[-] Passphrase too short for absolute safety. Aborting.")
		return
	}
	fmt.Print("Confirm Identity Protection Passphrase: ")
	pass2 := readInput(reader)
	if pass1 != pass2 {
		fmt.Println("[-] Passphrases do not match. Aborting.")
		return
	}

	fmt.Println("\n=========================================================================================")
	fmt.Println("       [⚡ OQS ENGINE] SELECT A PROFILE")
	fmt.Println("=========================================================================================")

	fmt.Println("\n --- 1. NIST STANDARDS & SPHINCS+ PURE (LATTICE / HASH) ---")
	fmt.Println("   1) ML-KEM / ML-DSA L3   [Hybrid-Oqs-ML-KEM-768+X25519       | Hybrid-Oqs-ML-DSA-65+Ed25519          | AES-256-GCM       | SHAKE256]")
	fmt.Println("   2) ML-KEM / ML-DSA L5   [Hybrid-Oqs-ML-KEM-1024+X448        | Hybrid-Oqs-ML-DSA-87+Ed448            | XAES-256-GCM      | SHA3-512]")
	fmt.Println("   3) ML-KEM / SLH-DSA SHA2[Hybrid-Oqs-ML-KEM-1024+X448        | Hybrid-Oqs-SLH_DSA_PURE_SHA2_256F+Ed448| ChaCha20-Poly1305 | BLAKE3-512]")
	fmt.Println("   4) Kyber / SLH-DSA SHAKE[Hybrid-Oqs-Kyber1024+X448          | Hybrid-Oqs-SLH_DSA_PURE_SHAKE_256S+Ed448| AES-256-GCM-SIV  | KangarooTwelve]")
	fmt.Println("   5) Kyber / Falcon Pad   [Hybrid-Oqs-Kyber768+X25519         | Hybrid-Oqs-Falcon-padded-1024+Ed25519 | Deoxys-II-256-128 | SHA3-384]")

	fmt.Println("\n --- 2. MULTIVARIATE QUADRATIC & MPC-IN-THE-HEAD (MAYO, OV, MQOM) ---")
	fmt.Println("   6) ML-KEM / MAYO-1 Fast [Hybrid-Oqs-ML-KEM-768+X25519       | Hybrid-Oqs-MAYO-1+Ed25519             | Camellia-256-EtM  | Skein-256]")
	fmt.Println("   7) ML-KEM / MAYO-5 Max  [Hybrid-Oqs-ML-KEM-1024+X448        | Hybrid-Oqs-MAYO-5+Ed448               | Serpent-256-EtM   | SHA3-512]")
	fmt.Println("   8) ML-KEM / SNOVA 60_10 [Hybrid-Oqs-ML-KEM-1024+X448        | Hybrid-Oqs-SNOVA_60_10_4+Ed448        | Threefish-256-EtM | BLAKE3-512]")
	fmt.Println("   9) Kyber / OV-V (OilVine)[Hybrid-Oqs-Kyber1024+X448         | Hybrid-Oqs-OV-V-pkc-skc+Ed448         | XChaCha20-Poly1305| KangarooTwelve]")
	fmt.Println("  10) Kyber / MQOM2 Cat5   [Hybrid-Oqs-Kyber1024+X448          | Hybrid-Oqs-mqom2_cat5_gf16_fast_r5+Ed448| AES-256-GCM    | SHA3-512]")
	fmt.Println("  11) Frodo / CROSS RSDPG  [Hybrid-Oqs-FrodoKEM-1344-SHAKE+X448| Hybrid-Oqs-cross-rsdpg-256-fast+Ed448 | XAES-256-GCM      | Skein-1024]")

	fmt.Println("\n --- 3. ADVANCED CODE-BASED (BIKE & CLASSIC MCELIECE) ---")
	fmt.Println("  12) BIKE L1 / ML-DSA L1  [Hybrid-Oqs-BIKE-L1+X25519          | Hybrid-Oqs-ML-DSA-44+Ed25519          | AES-256-GCM       | SHAKE128]")
	fmt.Println("  13) BIKE L5 / ML-DSA L5  [Hybrid-Oqs-BIKE-L5+X448            | Hybrid-Oqs-ML-DSA-87+Ed448            | Deoxys-II-256-128 | SHA3-512]")
	fmt.Println("  14) BIKE L5 / MAYO-5     [Hybrid-Oqs-BIKE-L5+X448            | Hybrid-Oqs-MAYO-5+Ed448               | ChaCha20-Poly1305 | BLAKE3-512]")
	fmt.Println("  15) McEliece / Falcon Pad[Hybrid-Oqs-Classic-McEliece-8192128f+X448 | Hybrid-Oqs-Falcon-padded-1024+Ed448| XAES-256-GCM | KangarooTwelve]")
	fmt.Println("  16) McEliece / SNOVA     [Hybrid-Oqs-Classic-McEliece-6688128+X448  | Hybrid-Oqs-SNOVA_56_25_2+Ed448 | AES-256-GCM-SIV   | SHA3-512]")
	fmt.Println("  17) McEliece / CROSS     [Hybrid-Oqs-Classic-McEliece-8192128+X448  | Hybrid-Oqs-cross-rsdp-256-fast+Ed448| Camellia-256-EtM| Skein-512]")

	fmt.Println("\n --- 4. ALTERNATIVE LATTICES (NTRU & FRODO EXTENDED) ---")
	fmt.Println("  18) NTRU HPS / ML-DSA    [Hybrid-Oqs-NTRU-HPS-4096-1229+X448 | Hybrid-Oqs-ML-DSA-87+Ed448            | Serpent-256-EtM   | SHA3-512]")
	fmt.Println("  19) NTRU HRSS / MAYO     [Hybrid-Oqs-NTRU-HRSS-1373+X448     | Hybrid-Oqs-MAYO-5+Ed448               | XChaCha20-Poly1305| BLAKE3-512]")
	fmt.Println("  20) SNTRUP / OV-V        [Hybrid-Oqs-sntrup761+X25519        | Hybrid-Oqs-OV-V-pkc+Ed25519           | AES-256-GCM       | KangarooTwelve]")
	fmt.Println("  21) eFrodo / MQOM2       [Hybrid-Oqs-eFrodoKEM-1344-SHAKE+X448| Hybrid-Oqs-mqom2_cat5_gf16_short_r5+Ed448| XAES-256-GCM | SHA3-512]")
	fmt.Println("  22) Frodo AES / CROSS    [Hybrid-Oqs-FrodoKEM-1344-AES+X448  | Hybrid-Oqs-cross-rsdpg-256-small+Ed448| Deoxys-II-256-128 | Skein-1024]")

	fmt.Println("\n --- 5. EXTREME PRE-HASHED SPHINCS+ (HARDENED RELEASE ENGINEERING) ---")
	fmt.Println("  23) ML-KEM / SLH Pre-SHA2[Hybrid-Oqs-ML-KEM-1024+X448        | Hybrid-Oqs-SLH_DSA_SHA2_256_PREHASH_SHA2_256F+Ed448| AES-256-GCM | SHA3-512]")
	fmt.Println("  24) BIKE / SLH Pre-SHAKE [Hybrid-Oqs-BIKE-L5+X448            | Hybrid-Oqs-SLH_DSA_SHAKE_256_PREHASH_SHAKE_256S+Ed448| XAES-256-GCM | BLAKE3-512]")
	fmt.Println("  25) McEliece / SLH SHA3  [Hybrid-Oqs-Classic-McEliece-8192128+X448| Hybrid-Oqs-SLH_DSA_SHA3_512_PREHASH_SHA2_256F+Ed448| ChaCha20 | Skein-1024]")
	fmt.Println("  26) NTRU / SLH 512-256   [Hybrid-Oqs-NTRU-HPS-4096-1229+X448 | Hybrid-Oqs-SLH_DSA_SHA2_512_256_PREHASH_SHAKE_256F+Ed448| Deoxys| SHA3-512]")

	fmt.Println("\n --- 6. THE WIDE-BLOCK FORTRESS ARCHITECTURES (THREEFISH 512/1024) ---")
	fmt.Println("  27) BIKE / MAYO Threefish[Hybrid-Oqs-BIKE-L5+X448            | Hybrid-Oqs-MAYO-5+Ed448               | Threefish-1024-EtM| SHA3-512]")
	fmt.Println("  28) McEliece / CROSS TF  [Hybrid-Oqs-Classic-McEliece-8192128+X448| Hybrid-Oqs-cross-rsdpg-256-fast+Ed448| Threefish-1024-EtM| Skein-1024]")
	fmt.Println("  29) eFrodo / SNOVA TF    [Hybrid-Oqs-eFrodoKEM-1344-SHAKE+X448| Hybrid-Oqs-SNOVA_60_10_4+Ed448        | Threefish-1024-EtM| BLAKE3-512]")
	fmt.Println("  30) ML-KEM / OV-V TF     [Hybrid-Oqs-ML-KEM-1024+X448        | Hybrid-Oqs-OV-V-pkc-skc+Ed448         | Threefish-512-EtM | KangarooTwelve]")

	fmt.Println("\n --- 7. EXHAUSTIVE CROSS-FAMILY SCATTER (MULTIVARIATE, MPC, & PRE-HASHED) ---")
	fmt.Println("  31) BIKE / SNOVA 24    [Hybrid-Oqs-BIKE-L1+X25519                   | Hybrid-Oqs-SNOVA_24_5_4+Ed25519                | Ascon-128a         | SHAKE256]")
	fmt.Println("  32) BIKE / SNOVA 37    [Hybrid-Oqs-BIKE-L3+X25519                   | Hybrid-Oqs-SNOVA_37_17_2+Ed25519               | Ascon-128          | SHA3-384]")
	fmt.Println("  33) BIKE / SNOVA 49    [Hybrid-Oqs-BIKE-L5+X448                     | Hybrid-Oqs-SNOVA_49_11_3+Ed448                 | Ascon-80pq         | SHA3-512]")
	fmt.Println("  34) McEliece / RSDP 128[Hybrid-Oqs-Classic-McEliece-348864+X25519  | Hybrid-Oqs-cross-rsdp-128-fast+Ed25519         | Serpent-256-EtM    | BLAKE3-512]")
	fmt.Println("  35) McEliece / RSDP 192[Hybrid-Oqs-Classic-McEliece-460896+X448    | Hybrid-Oqs-cross-rsdp-192-small+Ed448          | Camellia-256-EtM   | KangarooTwelve]")
	fmt.Println("  36) McEliece / RSDP 256[Hybrid-Oqs-Classic-McEliece-6688128+X448   | Hybrid-Oqs-cross-rsdp-256-balanced+Ed448       | Deoxys-II-256-128  | Skein-512]")
	fmt.Println("  37) McEliece / RSDPG256[Hybrid-Oqs-Classic-McEliece-8192128+X448   | Hybrid-Oqs-cross-rsdpg-256-fast+Ed448          | Threefish-1024-EtM | Skein-1024]")
	fmt.Println("  38) Kyber512 / OV-Is   [Hybrid-Oqs-Kyber512+X25519                  | Hybrid-Oqs-OV-Is+Ed25519                       | AES-256-GCM        | SHA3-256]")
	fmt.Println("  39) Kyber768 / OV-III  [Hybrid-Oqs-Kyber768+X448                    | Hybrid-Oqs-OV-III-pkc+Ed448                    | XAES-256-GCM       | SHA3-512]")
	fmt.Println("  40) Kyber1024 / OV-V   [Hybrid-Oqs-Kyber1024+X448                   | Hybrid-Oqs-OV-V-pkc-skc+Ed448                  | XChaCha20-Poly1305 | BLAKE3-512]")

	fmt.Println("  41) MLKEM512 / MQOM 1  [Hybrid-Oqs-ML-KEM-512+X25519                | Hybrid-Oqs-mqom2_cat1_gf16_fast_r3+Ed25519     | AES-256-GCM-SIV    | KangarooTwelve]")
	fmt.Println("  42) MLKEM768 / MQOM 3  [Hybrid-Oqs-ML-KEM-768+X448                  | Hybrid-Oqs-mqom2_cat3_gf16_short_r5+Ed448      | ChaCha20-Poly1305  | SHA3-512]")
	fmt.Println("  43) MLKEM1024 / MQOM 5 [Hybrid-Oqs-ML-KEM-1024+X448                 | Hybrid-Oqs-mqom2_cat5_gf16_fast_r5+Ed448       | Threefish-512-EtM  | Skein-1024]")
	fmt.Println("  44) NTRU2048 / MAYO-1  [Hybrid-Oqs-NTRU-HPS-2048-509+X25519         | Hybrid-Oqs-MAYO-1+Ed25519                      | Serpent-256-EtM    | SHAKE256]")
	fmt.Println("  45) NTRU2048 / MAYO-2  [Hybrid-Oqs-NTRU-HPS-2048-677+X448           | Hybrid-Oqs-MAYO-2+Ed448                        | Camellia-256-EtM   | SHA3-384]")
	fmt.Println("  46) NTRU4096 / MAYO-3  [Hybrid-Oqs-NTRU-HPS-4096-821+X448           | Hybrid-Oqs-MAYO-3+Ed448                        | Deoxys-II-256-128  | BLAKE3-512]")
	fmt.Println("  47) NTRU4096 / MAYO-5  [Hybrid-Oqs-NTRU-HPS-4096-1229+X448          | Hybrid-Oqs-MAYO-5+Ed448                        | Threefish-1024-EtM | Skein-512]")
	fmt.Println("  48) NTRU701 / Falcon512[Hybrid-Oqs-NTRU-HRSS-701+X25519             | Hybrid-Oqs-Falcon-padded-512+Ed25519           | XAES-256-GCM       | KangarooTwelve]")
	fmt.Println("  49) NTRU1373 / Falc1024[Hybrid-Oqs-NTRU-HRSS-1373+X448              | Hybrid-Oqs-Falcon-padded-1024+Ed448            | XChaCha20-Poly1305 | SHA3-512]")
	fmt.Println("  50) SNTRUP / SLH SHA2  [Hybrid-Oqs-sntrup761+X448                   | Hybrid-Oqs-SLH_DSA_PURE_SHA2_192S+Ed448        | AES-256-GCM        | BLAKE3-512]")

	fmt.Println("  51) Frodo640 / SLH F   [Hybrid-Oqs-FrodoKEM-640-AES+X25519          | Hybrid-Oqs-SLH_DSA_PURE_SHAKE_128F+Ed25519     | Ascon-128          | SHAKE256]")
	fmt.Println("  52) Frodo640 / SLH S   [Hybrid-Oqs-FrodoKEM-640-SHAKE+X448          | Hybrid-Oqs-SLH_DSA_PURE_SHAKE_128S+Ed448       | Ascon-80pq         | SHA3-384]")
	fmt.Println("  53) Frodo976 / SLH F   [Hybrid-Oqs-FrodoKEM-976-AES+X448            | Hybrid-Oqs-SLH_DSA_PURE_SHA2_192F+Ed448        | AES-256-GCM-SIV    | SHA3-512]")
	fmt.Println("  54) Frodo976 / SLH S   [Hybrid-Oqs-FrodoKEM-976-SHAKE+X448          | Hybrid-Oqs-SLH_DSA_PURE_SHAKE_192S+Ed448       | Deoxys-II-256-128  | KangarooTwelve]")
	fmt.Println("  55) Frodo1344 / SLH F  [Hybrid-Oqs-FrodoKEM-1344-AES+X448           | Hybrid-Oqs-SLH_DSA_PURE_SHA2_256F+Ed448        | Camellia-256-EtM   | Skein-512]")
	fmt.Println("  56) Frodo1344 / SLH S  [Hybrid-Oqs-FrodoKEM-1344-SHAKE+X448         | Hybrid-Oqs-SLH_DSA_PURE_SHAKE_256S+Ed448       | Serpent-256-EtM    | BLAKE3-512]")
	fmt.Println("  57) eFrodo640 / SLH Pre[Hybrid-Oqs-eFrodoKEM-640-AES+X25519         | Hybrid-Oqs-SLH_DSA_SHA2_224_PREHASH_SHA2_128S+Ed25519| XAES-256-GCM| SHA3-256]")
	fmt.Println("  58) eFrodo640 / SLH Pre[Hybrid-Oqs-eFrodoKEM-640-SHAKE+X448         | Hybrid-Oqs-SLH_DSA_SHA2_256_PREHASH_SHAKE_128F+Ed448| XChaCha20-P1305| SHA3-512]")
	fmt.Println("  59) eFrodo976 / SLH Pre[Hybrid-Oqs-eFrodoKEM-976-AES+X448           | Hybrid-Oqs-SLH_DSA_SHA2_384_PREHASH_SHA2_192S+Ed448| Threefish-512-EtM| Skein-1024]")
	fmt.Println("  60) eFrodo976 / SLH Pre[Hybrid-Oqs-eFrodoKEM-976-SHAKE+X448         | Hybrid-Oqs-SLH_DSA_SHA2_512_PREHASH_SHAKE_192F+Ed448| Threefish-1024-EtM| BLAKE3-512]")

	fmt.Println("  61) eFrodo1344 / SLH   [Hybrid-Oqs-eFrodoKEM-1344-AES+X448          | Hybrid-Oqs-SLH_DSA_SHA3_256_PREHASH_SHA2_256S+Ed448| AES-256-GCM    | KangarooTwelve]")
	fmt.Println("  62) eFrodo1344 / SLH   [Hybrid-Oqs-eFrodoKEM-1344-SHAKE+X448        | Hybrid-Oqs-SLH_DSA_SHAKE_256_PREHASH_SHAKE_256F+Ed448| ChaCha20-P1305 | SHA3-512]")
	fmt.Println("  63) BIKE L5 / SLH Pre  [Hybrid-Oqs-BIKE-L5+X448                     | Hybrid-Oqs-SLH_DSA_SHA2_512_256_PREHASH_SHA2_256S+Ed448| Deoxys-II| Skein-512]")
	fmt.Println("  64) McEliece / SLH Pre [Hybrid-Oqs-Classic-McEliece-8192128f+X448   | Hybrid-Oqs-SLH_DSA_SHA3_512_PREHASH_SHAKE_256S+Ed448| Serpent-256 | BLAKE3-512]")
	fmt.Println("  65) MLKEM1024 / MAYO-5 [Hybrid-Oqs-ML-KEM-1024+X448                 | Hybrid-Oqs-MAYO-5+Ed448                        | XAES-256-GCM       | SHA3-512]")
	fmt.Println("  66) MLKEM1024 / OV-V   [Hybrid-Oqs-ML-KEM-1024+X448                 | Hybrid-Oqs-OV-V-pkc-skc+Ed448                  | XChaCha20-Poly1305 | KangarooTwelve]")
	fmt.Println("  67) MLKEM1024 / RSDPG  [Hybrid-Oqs-ML-KEM-1024+X448                 | Hybrid-Oqs-cross-rsdpg-256-fast+Ed448          | Camellia-256-EtM   | Skein-1024]")
	fmt.Println("  68) MLKEM1024 / SNOVA  [Hybrid-Oqs-ML-KEM-1024+X448                 | Hybrid-Oqs-SNOVA_60_10_4+Ed448                 | AES-256-GCM-SIV    | BLAKE3-512]")
	fmt.Println("  69) MLKEM1024 / MQOM 5 [Hybrid-Oqs-ML-KEM-1024+X448                 | Hybrid-Oqs-mqom2_cat5_gf16_fast_r5+Ed448       | Threefish-1024-EtM | SHA3-512]")
	fmt.Println("  70) Kyber1024 / MAYO-5 [Hybrid-Oqs-Kyber1024+X448                   | Hybrid-Oqs-MAYO-5+Ed448                        | Ascon-80pq         | SHA3-512]")

	fmt.Println("  71) Kyber1024 / RSDPG  [Hybrid-Oqs-Kyber1024+X448                   | Hybrid-Oqs-cross-rsdpg-256-small+Ed448         | XAES-256-GCM       | Skein-512]")
	fmt.Println("  72) Kyber1024 / SNOVA  [Hybrid-Oqs-Kyber1024+X448                   | Hybrid-Oqs-SNOVA_49_11_3+Ed448                 | Deoxys-II-256-128  | BLAKE3-512]")
	fmt.Println("  73) Kyber1024 / MQOM 5 [Hybrid-Oqs-Kyber1024+X448                   | Hybrid-Oqs-mqom2_cat5_gf16_short_r5+Ed448      | Serpent-256-EtM    | KangarooTwelve]")
	fmt.Println("  74) Frodo1344 / MAYO-5 [Hybrid-Oqs-FrodoKEM-1344-SHAKE+X448         | Hybrid-Oqs-MAYO-5+Ed448                        | AES-256-GCM        | SHA3-512]")
	fmt.Println("  75) Frodo1344 / OV-V   [Hybrid-Oqs-FrodoKEM-1344-SHAKE+X448         | Hybrid-Oqs-OV-V-pkc-skc+Ed448                  | ChaCha20-Poly1305  | BLAKE3-512]")
	fmt.Println("  76) Frodo1344 / RSDP   [Hybrid-Oqs-FrodoKEM-1344-SHAKE+X448         | Hybrid-Oqs-cross-rsdp-256-balanced+Ed448       | Camellia-256-EtM   | Skein-1024]")
	fmt.Println("  77) Frodo1344 / SNOVA  [Hybrid-Oqs-FrodoKEM-1344-SHAKE+X448         | Hybrid-Oqs-SNOVA_60_10_4+Ed448                 | XChaCha20-Poly1305 | SHA3-512]")
	fmt.Println("  78) Frodo1344 / MQOM 5 [Hybrid-Oqs-FrodoKEM-1344-SHAKE+X448         | Hybrid-Oqs-mqom2_cat5_gf16_fast_r5+Ed448       | Threefish-512-EtM  | KangarooTwelve]")
	fmt.Println("  79) BIKE L5 / OV-V     [Hybrid-Oqs-BIKE-L5+X448                     | Hybrid-Oqs-OV-V-pkc-skc+Ed448                  | AES-256-GCM-SIV    | BLAKE3-512]")
	fmt.Println("  80) BIKE L5 / RSDP 256 [Hybrid-Oqs-BIKE-L5+X448                     | Hybrid-Oqs-cross-rsdp-256-fast+Ed448           | Deoxys-II-256-128  | SHA3-512]")

	fmt.Println("  81) BIKE L5 / SNOVA 56 [Hybrid-Oqs-BIKE-L5+X448                     | Hybrid-Oqs-SNOVA_56_25_2+Ed448                 | Serpent-256-EtM    | Skein-512]")
	fmt.Println("  82) BIKE L5 / MQOM 5   [Hybrid-Oqs-BIKE-L5+X448                     | Hybrid-Oqs-mqom2_cat5_gf16_short_r3+Ed448      | XAES-256-GCM       | KangarooTwelve]")
	fmt.Println("  83) McElieceFast/ MAYO5[Hybrid-Oqs-Classic-McEliece-8192128f+X448   | Hybrid-Oqs-MAYO-5+Ed448                        | Camellia-256-EtM   | BLAKE3-512]")
	fmt.Println("  84) McElieceFast/ OV-V [Hybrid-Oqs-Classic-McEliece-8192128f+X448   | Hybrid-Oqs-OV-V-pkc-skc+Ed448                  | Threefish-1024-EtM | SHA3-512]")
	fmt.Println("  85) McElieceFast/ RSDPG[Hybrid-Oqs-Classic-McEliece-8192128f+X448   | Hybrid-Oqs-cross-rsdpg-256-balanced+Ed448      | AES-256-GCM        | Skein-1024]")
	fmt.Println("  86) McElieceFast/ SNOVA[Hybrid-Oqs-Classic-McEliece-8192128f+X448   | Hybrid-Oqs-SNOVA_60_10_4+Ed448                 | XChaCha20-Poly1305 | SHA3-512]")
	fmt.Println("  87) McElieceFast/ MQOM5[Hybrid-Oqs-Classic-McEliece-8192128f+X448   | Hybrid-Oqs-mqom2_cat5_gf16_fast_r5+Ed448       | Deoxys-II-256-128  | BLAKE3-512]")
	fmt.Println("  88) NTRU4096 / MAYO-5  [Hybrid-Oqs-NTRU-HPS-4096-1229+X448          | Hybrid-Oqs-MAYO-5+Ed448                        | AES-256-GCM-SIV    | KangarooTwelve]")
	fmt.Println("  89) NTRU4096 / OV-V    [Hybrid-Oqs-NTRU-HPS-4096-1229+X448          | Hybrid-Oqs-OV-V-pkc-skc+Ed448                  | Serpent-256-EtM    | SHA3-512]")
	fmt.Println("  90) NTRU4096 / RSDPG   [Hybrid-Oqs-NTRU-HPS-4096-1229+X448          | Hybrid-Oqs-cross-rsdpg-256-small+Ed448         | Threefish-1024-EtM | BLAKE3-512]")

	fmt.Println("  91) NTRU4096 / SNOVA 49[Hybrid-Oqs-NTRU-HPS-4096-1229+X448          | Hybrid-Oqs-SNOVA_49_11_3+Ed448                 | XAES-256-GCM       | Skein-512]")
	fmt.Println("  92) NTRU4096 / MQOM 5  [Hybrid-Oqs-NTRU-HPS-4096-1229+X448          | Hybrid-Oqs-mqom2_cat5_gf16_short_r5+Ed448      | Camellia-256-EtM   | SHA3-512]")
	fmt.Println("  93) eFrodo1344/ MAYO-5 [Hybrid-Oqs-eFrodoKEM-1344-SHAKE+X448        | Hybrid-Oqs-MAYO-5+Ed448                        | ChaCha20-Poly1305  | KangarooTwelve]")
	fmt.Println("  94) eFrodo1344/ OV-V   [Hybrid-Oqs-eFrodoKEM-1344-SHAKE+X448        | Hybrid-Oqs-OV-V-pkc-skc+Ed448                  | Deoxys-II-256-128  | BLAKE3-512]")
	fmt.Println("  95) eFrodo1344/ RSDP   [Hybrid-Oqs-eFrodoKEM-1344-SHAKE+X448        | Hybrid-Oqs-cross-rsdp-256-fast+Ed448           | Threefish-1024-EtM | SHA3-512]")
	fmt.Println("  96) eFrodo1344/ SNOVA  [Hybrid-Oqs-eFrodoKEM-1344-SHAKE+X448        | Hybrid-Oqs-SNOVA_60_10_4+Ed448                 | AES-256-GCM        | Skein-1024]")
	fmt.Println("  97) eFrodo1344/ MQOM   [Hybrid-Oqs-eFrodoKEM-1344-SHAKE+X448        | Hybrid-Oqs-mqom2_cat5_gf16_fast_r5+Ed448       | XChaCha20-Poly1305 | SHA3-512]")
	fmt.Println("  98) SNTRUP / MAYO-5    [Hybrid-Oqs-sntrup761+X448                   | Hybrid-Oqs-MAYO-5+Ed448                        | AES-256-GCM-SIV    | BLAKE3-512]")
	fmt.Println("  99) SNTRUP / OV-V      [Hybrid-Oqs-sntrup761+X448                   | Hybrid-Oqs-OV-V-pkc-skc+Ed448                  | Camellia-256-EtM   | KangarooTwelve]")
	fmt.Println(" 100) SNTRUP / RSDPG 256 [Hybrid-Oqs-sntrup761+X448                   | Hybrid-Oqs-cross-rsdpg-256-fast+Ed448          | XAES-256-GCM       | SHA3-512]")

	fmt.Println(" 101) SNTRUP / SNOVA 56  [Hybrid-Oqs-sntrup761+X448                   | Hybrid-Oqs-SNOVA_56_25_2+Ed448                 | Serpent-256-EtM    | Skein-512]")
	fmt.Println(" 102) SNTRUP / MQOM 5    [Hybrid-Oqs-sntrup761+X448                   | Hybrid-Oqs-mqom2_cat5_gf16_short_r5+Ed448      | Threefish-1024-EtM | BLAKE3-512]")
	fmt.Println(" 103) MLKEM1024 / MAYO-3 [Hybrid-Oqs-ML-KEM-1024+X448                 | Hybrid-Oqs-MAYO-3+Ed448                        | Deoxys-II-256-128  | SHA3-512]")
	fmt.Println(" 104) BIKE L5 / RSDP 192 [Hybrid-Oqs-BIKE-L5+X448                     | Hybrid-Oqs-cross-rsdp-192-balanced+Ed448       | AES-256-GCM        | KangarooTwelve]")
	fmt.Println(" 105) McElieceFast/ SNOVA[Hybrid-Oqs-Classic-McEliece-8192128f+X448   | Hybrid-Oqs-SNOVA_24_5_5+Ed448                  | XChaCha20-Poly1305 | BLAKE3-512]")
	fmt.Println(" 106) NTRU4096 / MQOM 3  [Hybrid-Oqs-NTRU-HPS-4096-1229+X448          | Hybrid-Oqs-mqom2_cat3_gf16_fast_r5+Ed448       | Camellia-256-EtM   | Skein-1024]")
	fmt.Println(" 107) Frodo1344 / OV-Ip  [Hybrid-Oqs-FrodoKEM-1344-SHAKE+X448         | Hybrid-Oqs-OV-Ip-pkc-skc+Ed448                 | Threefish-512-EtM  | SHA3-512]")
	fmt.Println(" 108) eFrodo1344/ RSDP   [Hybrid-Oqs-eFrodoKEM-1344-SHAKE+X448        | Hybrid-Oqs-cross-rsdp-256-small+Ed448          | XAES-256-GCM       | BLAKE3-512]")
	fmt.Println(" 109) Kyber1024 / SNOVA37[Hybrid-Oqs-Kyber1024+X448                   | Hybrid-Oqs-SNOVA_37_8_4+Ed448                  | Serpent-256-EtM    | KangarooTwelve]")
	fmt.Println(" 110) SNTRUP / MAYO-2    [Hybrid-Oqs-sntrup761+X448                   | Hybrid-Oqs-MAYO-2+Ed448                        | AES-256-GCM-SIV    | Skein-512]")

	fmt.Println(" 111) MLKEM768 / RSDPG   [Hybrid-Oqs-ML-KEM-768+X25519                | Hybrid-Oqs-cross-rsdpg-128-fast+Ed25519        | Deoxys-II-256-128  | SHA3-512]")
	fmt.Println(" 112) BIKE L3 / SNOVA 24 [Hybrid-Oqs-BIKE-L3+X25519                   | Hybrid-Oqs-SNOVA_24_5_4_SHAKE_esk+Ed25519      | AES-256-GCM        | BLAKE3-512]")
	fmt.Println(" 113) McEliece3488/ OV-Is[Hybrid-Oqs-Classic-McEliece-348864f+X25519  | Hybrid-Oqs-OV-Is-pkc-skc+Ed25519               | XChaCha20-Poly1305 | KangarooTwelve]")
	fmt.Println(" 114) NTRU2048 / MQOM 1  [Hybrid-Oqs-NTRU-HPS-2048-677+X25519         | Hybrid-Oqs-mqom2_cat1_gf16_fast_r5+Ed25519     | Camellia-256-EtM   | SHA3-512]")
	fmt.Println(" 115) Frodo640 / MAYO-1  [Hybrid-Oqs-FrodoKEM-640-SHAKE+X25519        | Hybrid-Oqs-MAYO-1+Ed25519                      | Threefish-512-EtM  | Skein-1024]")
	fmt.Println(" 116) eFrodo640 / RSDP   [Hybrid-Oqs-eFrodoKEM-640-SHAKE+X25519       | Hybrid-Oqs-cross-rsdp-128-small+Ed25519        | XAES-256-GCM       | BLAKE3-512]")
	fmt.Println(" 117) Kyber512 / SNOVA 29[Hybrid-Oqs-Kyber512+X25519                  | Hybrid-Oqs-SNOVA_29_6_5+Ed25519                | Serpent-256-EtM    | SHA3-256]")
	fmt.Println(" 118) SNTRUP / OV-Ip     [Hybrid-Oqs-sntrup761+X25519                 | Hybrid-Oqs-OV-Ip-pkc+Ed25519                   | Deoxys-II-256-128  | KangarooTwelve]")
	fmt.Println(" 119) MLKEM1024 / RSDP256[Hybrid-Oqs-ML-KEM-1024+X448                 | Hybrid-Oqs-cross-rsdp-256-fast+Ed448           | Threefish-1024-EtM | Skein-512]")
	fmt.Println(" 120) McEliece8192/ MAYO [Hybrid-Oqs-Classic-McEliece-8192128+X448    | Hybrid-Oqs-MAYO-5+Ed448                        | AES-256-GCM-SIV    | SHA3-512]")
	fmt.Println("=========================================================================================")
	fmt.Print("Choice [1-120]: ")

	profChoice := readInput(reader)

	var kem, dsa, aead, xof string
	switch profChoice {
	// --- 1. NIST STANDARDS & SPHINCS+ PURE (LATTICE / HASH) ---
	case "1":
		kem, dsa, aead, xof = "Hybrid-Oqs-ML-KEM-768+X25519", "Hybrid-Oqs-ML-DSA-65+Ed25519", "AES-256-GCM", "SHAKE256"
	case "2":
		kem, dsa, aead, xof = "Hybrid-Oqs-ML-KEM-1024+X448", "Hybrid-Oqs-ML-DSA-87+Ed448", "XAES-256-GCM", "SHA3-512"
	case "3":
		kem, dsa, aead, xof = "Hybrid-Oqs-ML-KEM-1024+X448", "Hybrid-Oqs-SLH_DSA_PURE_SHA2_256F+Ed448", "ChaCha20-Poly1305", "BLAKE3-512"
	case "4":
		kem, dsa, aead, xof = "Hybrid-Oqs-Kyber1024+X448", "Hybrid-Oqs-SLH_DSA_PURE_SHAKE_256S+Ed448", "AES-256-GCM-SIV", "KangarooTwelve"
	case "5":
		kem, dsa, aead, xof = "Hybrid-Oqs-Kyber768+X25519", "Hybrid-Oqs-Falcon-padded-1024+Ed25519", "Deoxys-II-256-128", "SHA3-384"

	// --- 2. MULTIVARIATE QUADRATIC & MPC-IN-THE-HEAD (MAYO, OV, MQOM) ---
	case "6":
		kem, dsa, aead, xof = "Hybrid-Oqs-ML-KEM-768+X25519", "Hybrid-Oqs-MAYO-1+Ed25519", "Camellia-256-EtM", "Skein-256"
	case "7":
		kem, dsa, aead, xof = "Hybrid-Oqs-ML-KEM-1024+X448", "Hybrid-Oqs-MAYO-5+Ed448", "Serpent-256-EtM", "SHA3-512"
	case "8":
		kem, dsa, aead, xof = "Hybrid-Oqs-ML-KEM-1024+X448", "Hybrid-Oqs-SNOVA_60_10_4+Ed448", "Threefish-256-EtM", "BLAKE3-512"
	case "9":
		kem, dsa, aead, xof = "Hybrid-Oqs-Kyber1024+X448", "Hybrid-Oqs-OV-V-pkc-skc+Ed448", "XChaCha20-Poly1305", "KangarooTwelve"
	case "10":
		kem, dsa, aead, xof = "Hybrid-Oqs-Kyber1024+X448", "Hybrid-Oqs-mqom2_cat5_gf16_fast_r5+Ed448", "AES-256-GCM", "SHA3-512"
	case "11":
		kem, dsa, aead, xof = "Hybrid-Oqs-FrodoKEM-1344-SHAKE+X448", "Hybrid-Oqs-cross-rsdpg-256-fast+Ed448", "XAES-256-GCM", "Skein-1024"

	// --- 3. ADVANCED CODE-BASED (BIKE & CLASSIC MCELIECE) ---
	case "12":
		kem, dsa, aead, xof = "Hybrid-Oqs-BIKE-L1+X25519", "Hybrid-Oqs-ML-DSA-44+Ed25519", "AES-256-GCM", "SHAKE128"
	case "13":
		kem, dsa, aead, xof = "Hybrid-Oqs-BIKE-L5+X448", "Hybrid-Oqs-ML-DSA-87+Ed448", "Deoxys-II-256-128", "SHA3-512"
	case "14":
		kem, dsa, aead, xof = "Hybrid-Oqs-BIKE-L5+X448", "Hybrid-Oqs-MAYO-5+Ed448", "ChaCha20-Poly1305", "BLAKE3-512"
	case "15":
		kem, dsa, aead, xof = "Hybrid-Oqs-Classic-McEliece-8192128f+X448", "Hybrid-Oqs-Falcon-padded-1024+Ed448", "XAES-256-GCM", "KangarooTwelve"
	case "16":
		kem, dsa, aead, xof = "Hybrid-Oqs-Classic-McEliece-6688128+X448", "Hybrid-Oqs-SNOVA_56_25_2+Ed448", "AES-256-GCM-SIV", "SHA3-512"
	case "17":
		kem, dsa, aead, xof = "Hybrid-Oqs-Classic-McEliece-8192128+X448", "Hybrid-Oqs-cross-rsdp-256-fast+Ed448", "Camellia-256-EtM", "Skein-512"

	// --- 4. ALTERNATIVE LATTICES (NTRU & FRODO EXTENDED) ---
	case "18":
		kem, dsa, aead, xof = "Hybrid-Oqs-NTRU-HPS-4096-1229+X448", "Hybrid-Oqs-ML-DSA-87+Ed448", "Serpent-256-EtM", "SHA3-512"
	case "19":
		kem, dsa, aead, xof = "Hybrid-Oqs-NTRU-HRSS-1373+X448", "Hybrid-Oqs-MAYO-5+Ed448", "XChaCha20-Poly1305", "BLAKE3-512"
	case "20":
		kem, dsa, aead, xof = "Hybrid-Oqs-sntrup761+X25519", "Hybrid-Oqs-OV-V-pkc+Ed25519", "AES-256-GCM", "KangarooTwelve"
	case "21":
		kem, dsa, aead, xof = "Hybrid-Oqs-eFrodoKEM-1344-SHAKE+X448", "Hybrid-Oqs-mqom2_cat5_gf16_short_r5+Ed448", "XAES-256-GCM", "SHA3-512"
	case "22":
		kem, dsa, aead, xof = "Hybrid-Oqs-FrodoKEM-1344-AES+X448", "Hybrid-Oqs-cross-rsdpg-256-small+Ed448", "Deoxys-II-256-128", "Skein-1024"

	// --- 5. EXTREME PRE-HASHED SPHINCS+ (HARDENED RELEASE ENGINEERING) ---
	case "23":
		kem, dsa, aead, xof = "Hybrid-Oqs-ML-KEM-1024+X448", "Hybrid-Oqs-SLH_DSA_SHA2_256_PREHASH_SHA2_256F+Ed448", "AES-256-GCM", "SHA3-512"
	case "24":
		kem, dsa, aead, xof = "Hybrid-Oqs-BIKE-L5+X448", "Hybrid-Oqs-SLH_DSA_SHAKE_256_PREHASH_SHAKE_256S+Ed448", "XAES-256-GCM", "BLAKE3-512"
	case "25":
		kem, dsa, aead, xof = "Hybrid-Oqs-Classic-McEliece-8192128+X448", "Hybrid-Oqs-SLH_DSA_SHA3_512_PREHASH_SHA2_256F+Ed448", "ChaCha20-Poly1305", "Skein-1024"
	case "26":
		kem, dsa, aead, xof = "Hybrid-Oqs-NTRU-HPS-4096-1229+X448", "Hybrid-Oqs-SLH_DSA_SHA2_512_256_PREHASH_SHAKE_256F+Ed448", "Deoxys-II-256-128", "SHA3-512"

	// --- 6. THE WIDE-BLOCK FORTRESS ARCHITECTURES (THREEFISH 512/1024) ---
	case "27":
		kem, dsa, aead, xof = "Hybrid-Oqs-BIKE-L5+X448", "Hybrid-Oqs-MAYO-5+Ed448", "Threefish-1024-EtM", "SHA3-512"
	case "28":
		kem, dsa, aead, xof = "Hybrid-Oqs-Classic-McEliece-8192128+X448", "Hybrid-Oqs-cross-rsdpg-256-fast+Ed448", "Threefish-1024-EtM", "Skein-1024"
	case "29":
		kem, dsa, aead, xof = "Hybrid-Oqs-eFrodoKEM-1344-SHAKE+X448", "Hybrid-Oqs-SNOVA_60_10_4+Ed448", "Threefish-1024-EtM", "BLAKE3-512"
	case "30":
		kem, dsa, aead, xof = "Hybrid-Oqs-ML-KEM-1024+X448", "Hybrid-Oqs-OV-V-pkc-skc+Ed448", "Threefish-512-EtM", "KangarooTwelve"

	// --- 7. EXHAUSTIVE CROSS-FAMILY SCATTER (SUITES 31 - 120) ---
	case "31":
		kem, dsa, aead, xof = "Hybrid-Oqs-BIKE-L1+X25519", "Hybrid-Oqs-SNOVA_24_5_4+Ed25519", "Ascon-128a", "SHAKE256"
	case "32":
		kem, dsa, aead, xof = "Hybrid-Oqs-BIKE-L3+X25519", "Hybrid-Oqs-SNOVA_37_17_2+Ed25519", "Ascon-128", "SHA3-384"
	case "33":
		kem, dsa, aead, xof = "Hybrid-Oqs-BIKE-L5+X448", "Hybrid-Oqs-SNOVA_49_11_3+Ed448", "Ascon-80pq", "SHA3-512"
	case "34":
		kem, dsa, aead, xof = "Hybrid-Oqs-Classic-McEliece-348864+X25519", "Hybrid-Oqs-cross-rsdp-128-fast+Ed25519", "Serpent-256-EtM", "BLAKE3-512"
	case "35":
		kem, dsa, aead, xof = "Hybrid-Oqs-Classic-McEliece-460896+X448", "Hybrid-Oqs-cross-rsdp-192-small+Ed448", "Camellia-256-EtM", "KangarooTwelve"
	case "36":
		kem, dsa, aead, xof = "Hybrid-Oqs-Classic-McEliece-6688128+X448", "Hybrid-Oqs-cross-rsdp-256-balanced+Ed448", "Deoxys-II-256-128", "Skein-512"
	case "37":
		kem, dsa, aead, xof = "Hybrid-Oqs-Classic-McEliece-8192128+X448", "Hybrid-Oqs-cross-rsdpg-256-fast+Ed448", "Threefish-1024-EtM", "Skein-1024"
	case "38":
		kem, dsa, aead, xof = "Hybrid-Oqs-Kyber512+X25519", "Hybrid-Oqs-OV-Is+Ed25519", "AES-256-GCM", "SHA3-256"
	case "39":
		kem, dsa, aead, xof = "Hybrid-Oqs-Kyber768+X448", "Hybrid-Oqs-OV-III-pkc+Ed448", "XAES-256-GCM", "SHA3-512"
	case "40":
		kem, dsa, aead, xof = "Hybrid-Oqs-Kyber1024+X448", "Hybrid-Oqs-OV-V-pkc-skc+Ed448", "XChaCha20-Poly1305", "BLAKE3-512"
	case "41":
		kem, dsa, aead, xof = "Hybrid-Oqs-ML-KEM-512+X25519", "Hybrid-Oqs-mqom2_cat1_gf16_fast_r3+Ed25519", "AES-256-GCM-SIV", "KangarooTwelve"
	case "42":
		kem, dsa, aead, xof = "Hybrid-Oqs-ML-KEM-768+X448", "Hybrid-Oqs-mqom2_cat3_gf16_short_r5+Ed448", "ChaCha20-Poly1305", "SHA3-512"
	case "43":
		kem, dsa, aead, xof = "Hybrid-Oqs-ML-KEM-1024+X448", "Hybrid-Oqs-mqom2_cat5_gf16_fast_r5+Ed448", "Threefish-512-EtM", "Skein-1024"
	case "44":
		kem, dsa, aead, xof = "Hybrid-Oqs-NTRU-HPS-2048-509+X25519", "Hybrid-Oqs-MAYO-1+Ed25519", "Serpent-256-EtM", "SHAKE256"
	case "45":
		kem, dsa, aead, xof = "Hybrid-Oqs-NTRU-HPS-2048-677+X448", "Hybrid-Oqs-MAYO-2+Ed448", "Camellia-256-EtM", "SHA3-384"
	case "46":
		kem, dsa, aead, xof = "Hybrid-Oqs-NTRU-HPS-4096-821+X448", "Hybrid-Oqs-MAYO-3+Ed448", "Deoxys-II-256-128", "BLAKE3-512"
	case "47":
		kem, dsa, aead, xof = "Hybrid-Oqs-NTRU-HPS-4096-1229+X448", "Hybrid-Oqs-MAYO-5+Ed448", "Threefish-1024-EtM", "Skein-512"
	case "48":
		kem, dsa, aead, xof = "Hybrid-Oqs-NTRU-HRSS-701+X25519", "Hybrid-Oqs-Falcon-padded-512+Ed25519", "XAES-256-GCM", "KangarooTwelve"
	case "49":
		kem, dsa, aead, xof = "Hybrid-Oqs-NTRU-HRSS-1373+X448", "Hybrid-Oqs-Falcon-padded-1024+Ed448", "XChaCha20-Poly1305", "SHA3-512"
	case "50":
		kem, dsa, aead, xof = "Hybrid-Oqs-sntrup761+X448", "Hybrid-Oqs-SLH_DSA_PURE_SHA2_192S+Ed448", "AES-256-GCM", "BLAKE3-512"

	case "51":
		kem, dsa, aead, xof = "Hybrid-Oqs-FrodoKEM-640-AES+X25519", "Hybrid-Oqs-SLH_DSA_PURE_SHAKE_128F+Ed25519", "Ascon-128", "SHAKE256"
	case "52":
		kem, dsa, aead, xof = "Hybrid-Oqs-FrodoKEM-640-SHAKE+X448", "Hybrid-Oqs-SLH_DSA_PURE_SHAKE_128S+Ed448", "Ascon-80pq", "SHA3-384"
	case "53":
		kem, dsa, aead, xof = "Hybrid-Oqs-FrodoKEM-976-AES+X448", "Hybrid-Oqs-SLH_DSA_PURE_SHA2_192F+Ed448", "AES-256-GCM-SIV", "SHA3-512"
	case "54":
		kem, dsa, aead, xof = "Hybrid-Oqs-FrodoKEM-976-SHAKE+X448", "Hybrid-Oqs-SLH_DSA_PURE_SHAKE_192S+Ed448", "Deoxys-II-256-128", "KangarooTwelve"
	case "55":
		kem, dsa, aead, xof = "Hybrid-Oqs-FrodoKEM-1344-AES+X448", "Hybrid-Oqs-SLH_DSA_PURE_SHA2_256F+Ed448", "Camellia-256-EtM", "Skein-512"
	case "56":
		kem, dsa, aead, xof = "Hybrid-Oqs-FrodoKEM-1344-SHAKE+X448", "Hybrid-Oqs-SLH_DSA_PURE_SHAKE_256S+Ed448", "Serpent-256-EtM", "BLAKE3-512"
	case "57":
		kem, dsa, aead, xof = "Hybrid-Oqs-eFrodoKEM-640-AES+X25519", "Hybrid-Oqs-SLH_DSA_SHA2_224_PREHASH_SHA2_128S+Ed25519", "XAES-256-GCM", "SHA3-256"
	case "58":
		kem, dsa, aead, xof = "Hybrid-Oqs-eFrodoKEM-640-SHAKE+X448", "Hybrid-Oqs-SLH_DSA_SHA2_256_PREHASH_SHAKE_128F+Ed448", "XChaCha20-Poly1305", "SHA3-512"
	case "59":
		kem, dsa, aead, xof = "Hybrid-Oqs-eFrodoKEM-976-AES+X448", "Hybrid-Oqs-SLH_DSA_SHA2_384_PREHASH_SHA2_192S+Ed448", "Threefish-512-EtM", "Skein-1024"
	case "60":
		kem, dsa, aead, xof = "Hybrid-Oqs-eFrodoKEM-976-SHAKE+X448", "Hybrid-Oqs-SLH_DSA_SHA2_512_PREHASH_SHAKE_192F+Ed448", "Threefish-1024-EtM", "BLAKE3-512"

	case "61":
		kem, dsa, aead, xof = "Hybrid-Oqs-eFrodoKEM-1344-AES+X448", "Hybrid-Oqs-SLH_DSA_SHA3_256_PREHASH_SHA2_256S+Ed448", "AES-256-GCM", "KangarooTwelve"
	case "62":
		kem, dsa, aead, xof = "Hybrid-Oqs-eFrodoKEM-1344-SHAKE+X448", "Hybrid-Oqs-SLH_DSA_SHAKE_256_PREHASH_SHAKE_256F+Ed448", "ChaCha20-Poly1305", "SHA3-512"
	case "63":
		kem, dsa, aead, xof = "Hybrid-Oqs-BIKE-L5+X448", "Hybrid-Oqs-SLH_DSA_SHA2_512_256_PREHASH_SHA2_256S+Ed448", "Deoxys-II-256-128", "Skein-512"
	case "64":
		kem, dsa, aead, xof = "Hybrid-Oqs-Classic-McEliece-8192128f+X448", "Hybrid-Oqs-SLH_DSA_SHA3_512_PREHASH_SHAKE_256S+Ed448", "Serpent-256-EtM", "BLAKE3-512"
	case "65":
		kem, dsa, aead, xof = "Hybrid-Oqs-ML-KEM-1024+X448", "Hybrid-Oqs-MAYO-5+Ed448", "XAES-256-GCM", "SHA3-512"
	case "66":
		kem, dsa, aead, xof = "Hybrid-Oqs-ML-KEM-1024+X448", "Hybrid-Oqs-OV-V-pkc-skc+Ed448", "XChaCha20-Poly1305", "KangarooTwelve"
	case "67":
		kem, dsa, aead, xof = "Hybrid-Oqs-ML-KEM-1024+X448", "Hybrid-Oqs-cross-rsdpg-256-fast+Ed448", "Camellia-256-EtM", "Skein-1024"
	case "68":
		kem, dsa, aead, xof = "Hybrid-Oqs-ML-KEM-1024+X448", "Hybrid-Oqs-SNOVA_60_10_4+Ed448", "AES-256-GCM-SIV", "BLAKE3-512"
	case "69":
		kem, dsa, aead, xof = "Hybrid-Oqs-ML-KEM-1024+X448", "Hybrid-Oqs-mqom2_cat5_gf16_fast_r5+Ed448", "Threefish-1024-EtM", "SHA3-512"
	case "70":
		kem, dsa, aead, xof = "Hybrid-Oqs-Kyber1024+X448", "Hybrid-Oqs-MAYO-5+Ed448", "Ascon-80pq", "SHA3-512"

	case "71":
		kem, dsa, aead, xof = "Hybrid-Oqs-Kyber1024+X448", "Hybrid-Oqs-cross-rsdpg-256-small+Ed448", "XAES-256-GCM", "Skein-512"
	case "72":
		kem, dsa, aead, xof = "Hybrid-Oqs-Kyber1024+X448", "Hybrid-Oqs-SNOVA_49_11_3+Ed448", "Deoxys-II-256-128", "BLAKE3-512"
	case "73":
		kem, dsa, aead, xof = "Hybrid-Oqs-Kyber1024+X448", "Hybrid-Oqs-mqom2_cat5_gf16_short_r5+Ed448", "Serpent-256-EtM", "KangarooTwelve"
	case "74":
		kem, dsa, aead, xof = "Hybrid-Oqs-FrodoKEM-1344-SHAKE+X448", "Hybrid-Oqs-MAYO-5+Ed448", "AES-256-GCM", "SHA3-512"
	case "75":
		kem, dsa, aead, xof = "Hybrid-Oqs-FrodoKEM-1344-SHAKE+X448", "Hybrid-Oqs-OV-V-pkc-skc+Ed448", "ChaCha20-Poly1305", "BLAKE3-512"
	case "76":
		kem, dsa, aead, xof = "Hybrid-Oqs-FrodoKEM-1344-SHAKE+X448", "Hybrid-Oqs-cross-rsdp-256-balanced+Ed448", "Camellia-256-EtM", "Skein-1024"
	case "77":
		kem, dsa, aead, xof = "Hybrid-Oqs-FrodoKEM-1344-SHAKE+X448", "Hybrid-Oqs-SNOVA_60_10_4+Ed448", "XChaCha20-Poly1305", "SHA3-512"
	case "78":
		kem, dsa, aead, xof = "Hybrid-Oqs-FrodoKEM-1344-SHAKE+X448", "Hybrid-Oqs-mqom2_cat5_gf16_fast_r5+Ed448", "Threefish-512-EtM", "KangarooTwelve"
	case "79":
		kem, dsa, aead, xof = "Hybrid-Oqs-BIKE-L5+X448", "Hybrid-Oqs-OV-V-pkc-skc+Ed448", "AES-256-GCM-SIV", "BLAKE3-512"
	case "80":
		kem, dsa, aead, xof = "Hybrid-Oqs-BIKE-L5+X448", "Hybrid-Oqs-cross-rsdp-256-fast+Ed448", "Deoxys-II-256-128", "SHA3-512"

	case "81":
		kem, dsa, aead, xof = "Hybrid-Oqs-BIKE-L5+X448", "Hybrid-Oqs-SNOVA_56_25_2+Ed448", "Serpent-256-EtM", "Skein-512"
	case "82":
		kem, dsa, aead, xof = "Hybrid-Oqs-BIKE-L5+X448", "Hybrid-Oqs-mqom2_cat5_gf16_short_r3+Ed448", "XAES-256-GCM", "KangarooTwelve"
	case "83":
		kem, dsa, aead, xof = "Hybrid-Oqs-Classic-McEliece-8192128f+X448", "Hybrid-Oqs-MAYO-5+Ed448", "Camellia-256-EtM", "BLAKE3-512"
	case "84":
		kem, dsa, aead, xof = "Hybrid-Oqs-Classic-McEliece-8192128f+X448", "Hybrid-Oqs-OV-V-pkc-skc+Ed448", "Threefish-1024-EtM", "SHA3-512"
	case "85":
		kem, dsa, aead, xof = "Hybrid-Oqs-Classic-McEliece-8192128f+X448", "Hybrid-Oqs-cross-rsdpg-256-balanced+Ed448", "AES-256-GCM", "Skein-1024"
	case "86":
		kem, dsa, aead, xof = "Hybrid-Oqs-Classic-McEliece-8192128f+X448", "Hybrid-Oqs-SNOVA_60_10_4+Ed448", "XChaCha20-Poly1305", "SHA3-512"
	case "87":
		kem, dsa, aead, xof = "Hybrid-Oqs-Classic-McEliece-8192128f+X448", "Hybrid-Oqs-mqom2_cat5_gf16_fast_r5+Ed448", "Deoxys-II-256-128", "BLAKE3-512"
	case "88":
		kem, dsa, aead, xof = "Hybrid-Oqs-NTRU-HPS-4096-1229+X448", "Hybrid-Oqs-MAYO-5+Ed448", "AES-256-GCM-SIV", "KangarooTwelve"
	case "89":
		kem, dsa, aead, xof = "Hybrid-Oqs-NTRU-HPS-4096-1229+X448", "Hybrid-Oqs-OV-V-pkc-skc+Ed448", "Serpent-256-EtM", "SHA3-512"
	case "90":
		kem, dsa, aead, xof = "Hybrid-Oqs-NTRU-HPS-4096-1229+X448", "Hybrid-Oqs-cross-rsdpg-256-small+Ed448", "Threefish-1024-EtM", "BLAKE3-512"

	case "91":
		kem, dsa, aead, xof = "Hybrid-Oqs-NTRU-HPS-4096-1229+X448", "Hybrid-Oqs-SNOVA_49_11_3+Ed448", "XAES-256-GCM", "Skein-512"
	case "92":
		kem, dsa, aead, xof = "Hybrid-Oqs-NTRU-HPS-4096-1229+X448", "Hybrid-Oqs-mqom2_cat5_gf16_short_r5+Ed448", "Camellia-256-EtM", "SHA3-512"
	case "93":
		kem, dsa, aead, xof = "Hybrid-Oqs-eFrodoKEM-1344-SHAKE+X448", "Hybrid-Oqs-MAYO-5+Ed448", "ChaCha20-Poly1305", "KangarooTwelve"
	case "94":
		kem, dsa, aead, xof = "Hybrid-Oqs-eFrodoKEM-1344-SHAKE+X448", "Hybrid-Oqs-OV-V-pkc-skc+Ed448", "Deoxys-II-256-128", "BLAKE3-512"
	case "95":
		kem, dsa, aead, xof = "Hybrid-Oqs-eFrodoKEM-1344-SHAKE+X448", "Hybrid-Oqs-cross-rsdp-256-fast+Ed448", "Threefish-1024-EtM", "SHA3-512"
	case "96":
		kem, dsa, aead, xof = "Hybrid-Oqs-eFrodoKEM-1344-SHAKE+X448", "Hybrid-Oqs-SNOVA_60_10_4+Ed448", "AES-256-GCM", "Skein-1024"
	case "97":
		kem, dsa, aead, xof = "Hybrid-Oqs-eFrodoKEM-1344-SHAKE+X448", "Hybrid-Oqs-mqom2_cat5_gf16_fast_r5+Ed448", "XChaCha20-Poly1305", "SHA3-512"
	case "98":
		kem, dsa, aead, xof = "Hybrid-Oqs-sntrup761+X448", "Hybrid-Oqs-MAYO-5+Ed448", "AES-256-GCM-SIV", "BLAKE3-512"
	case "99":
		kem, dsa, aead, xof = "Hybrid-Oqs-sntrup761+X448", "Hybrid-Oqs-OV-V-pkc-skc+Ed448", "Camellia-256-EtM", "KangarooTwelve"
	case "100":
		kem, dsa, aead, xof = "Hybrid-Oqs-sntrup761+X448", "Hybrid-Oqs-cross-rsdpg-256-fast+Ed448", "XAES-256-GCM", "SHA3-512"

	case "101":
		kem, dsa, aead, xof = "Hybrid-Oqs-sntrup761+X448", "Hybrid-Oqs-SNOVA_56_25_2+Ed448", "Serpent-256-EtM", "Skein-512"
	case "102":
		kem, dsa, aead, xof = "Hybrid-Oqs-sntrup761+X448", "Hybrid-Oqs-mqom2_cat5_gf16_short_r5+Ed448", "Threefish-1024-EtM", "BLAKE3-512"
	case "103":
		kem, dsa, aead, xof = "Hybrid-Oqs-ML-KEM-1024+X448", "Hybrid-Oqs-MAYO-3+Ed448", "Deoxys-II-256-128", "SHA3-512"
	case "104":
		kem, dsa, aead, xof = "Hybrid-Oqs-BIKE-L5+X448", "Hybrid-Oqs-cross-rsdp-192-balanced+Ed448", "AES-256-GCM", "KangarooTwelve"
	case "105":
		kem, dsa, aead, xof = "Hybrid-Oqs-Classic-McEliece-8192128f+X448", "Hybrid-Oqs-SNOVA_24_5_5+Ed448", "XChaCha20-Poly1305", "BLAKE3-512"
	case "106":
		kem, dsa, aead, xof = "Hybrid-Oqs-NTRU-HPS-4096-1229+X448", "Hybrid-Oqs-mqom2_cat3_gf16_fast_r5+Ed448", "Camellia-256-EtM", "Skein-1024"
	case "107":
		kem, dsa, aead, xof = "Hybrid-Oqs-FrodoKEM-1344-SHAKE+X448", "Hybrid-Oqs-OV-Ip-pkc-skc+Ed448", "Threefish-512-EtM", "SHA3-512"
	case "108":
		kem, dsa, aead, xof = "Hybrid-Oqs-eFrodoKEM-1344-SHAKE+X448", "Hybrid-Oqs-cross-rsdp-256-small+Ed448", "XAES-256-GCM", "BLAKE3-512"
	case "109":
		kem, dsa, aead, xof = "Hybrid-Oqs-Kyber1024+X448", "Hybrid-Oqs-SNOVA_37_8_4+Ed448", "Serpent-256-EtM", "KangarooTwelve"
	case "110":
		kem, dsa, aead, xof = "Hybrid-Oqs-sntrup761+X448", "Hybrid-Oqs-MAYO-2+Ed448", "AES-256-GCM-SIV", "Skein-512"

	case "111":
		kem, dsa, aead, xof = "Hybrid-Oqs-ML-KEM-768+X25519", "Hybrid-Oqs-cross-rsdpg-128-fast+Ed25519", "Deoxys-II-256-128", "SHA3-512"
	case "112":
		kem, dsa, aead, xof = "Hybrid-Oqs-BIKE-L3+X25519", "Hybrid-Oqs-SNOVA_24_5_4_SHAKE_esk+Ed25519", "AES-256-GCM", "BLAKE3-512"
	case "113":
		kem, dsa, aead, xof = "Hybrid-Oqs-Classic-McEliece-348864f+X25519", "Hybrid-Oqs-OV-Is-pkc-skc+Ed25519", "XChaCha20-Poly1305", "KangarooTwelve"
	case "114":
		kem, dsa, aead, xof = "Hybrid-Oqs-NTRU-HPS-2048-677+X25519", "Hybrid-Oqs-mqom2_cat1_gf16_fast_r5+Ed25519", "Camellia-256-EtM", "SHA3-512"
	case "115":
		kem, dsa, aead, xof = "Hybrid-Oqs-FrodoKEM-640-SHAKE+X25519", "Hybrid-Oqs-MAYO-1+Ed25519", "Threefish-512-EtM", "Skein-1024"
	case "116":
		kem, dsa, aead, xof = "Hybrid-Oqs-eFrodoKEM-640-SHAKE+X25519", "Hybrid-Oqs-cross-rsdp-128-small+Ed25519", "XAES-256-GCM", "BLAKE3-512"
	case "117":
		kem, dsa, aead, xof = "Hybrid-Oqs-Kyber512+X25519", "Hybrid-Oqs-SNOVA_29_6_5+Ed25519", "Serpent-256-EtM", "SHA3-256"
	case "118":
		kem, dsa, aead, xof = "Hybrid-Oqs-sntrup761+X25519", "Hybrid-Oqs-OV-Ip-pkc+Ed25519", "Deoxys-II-256-128", "KangarooTwelve"
	case "119":
		kem, dsa, aead, xof = "Hybrid-Oqs-ML-KEM-1024+X448", "Hybrid-Oqs-cross-rsdp-256-fast+Ed448", "Threefish-1024-EtM", "Skein-512"
	case "120":
		kem, dsa, aead, xof = "Hybrid-Oqs-Classic-McEliece-8192128+X448", "Hybrid-Oqs-MAYO-5+Ed448", "AES-256-GCM-SIV", "SHA3-512"

	default:
		fmt.Println("[-] Invalid choice. Aborting.")
		return
	}

	// Output logic for your keyring generator...
	fmt.Printf("[*] KEM Selected:  %s\n", kem)
	fmt.Printf("[*] DSA Selected:  %s\n", dsa)
	fmt.Printf("[*] AEAD Selected: %s\n", aead)
	fmt.Printf("[*] Hash Selected: %s\n", xof)

	// THE PARANOIA IDENTITY PITCH ---
	if strings.HasPrefix(dsa, "LMS") || strings.HasPrefix(dsa, "XMSS") {
		fmt.Println("\n=====================================================================")
		fmt.Println("             [🛡️] THE PARANOIA IDENTITY PROFILE INITIATED            ")
		fmt.Println("=====================================================================")
		fmt.Println(" You are generating a cryptographic profile entirely immune to Lattice-")
		fmt.Println(" reduction breakthroughs. Your identity relies solely on the proven ")
		fmt.Println(" mathematical limits of cryptographic hash functions.")
		fmt.Println("\n [!] ARCHITECTURAL LIMITATIONS CAUTION:")
		fmt.Println("  - Your OUTBOX is strictly locked to prevent state-exhaustion.")
		fmt.Println("  - You cannot send standard Ratchet messages (Option 3).")
		fmt.Println("  - Your INBOX remains open for stateless incoming messages (Option 14).")
		fmt.Println("  - You are fully equipped to issue 50+ Year Release Signatures.")
		fmt.Println("=====================================================================")

		fmt.Print("Do you understand these limitations and wish to proceed? (y/n): ")
		proceed := strings.ToLower(strings.TrimSpace(readInput(reader)))
		if proceed != "y" && proceed != "yes" {
			fmt.Println("[-] Identity generation aborted.")
			return
		}
	}

	// =========================================================================
	// THE PHANTOM PIPELINE INITIATION (Key Generation)
	// =========================================================================
	fmt.Println("\n[*] Negotiating ephemeral tmpfs mount with OS Kernel...")
	workspace, err := phantom.NewWorkspace()
	if err != nil {
		fmt.Printf("[-] Phantom Architecture initialization failed: %v\n", err)
		return
	}
	defer workspace.Destroy()

	fmt.Println("[*] Executing mathematical key generation arrays strictly in volatile RAM...")

	// Pass the RAM-disk MountPoint as the directory for identity generation
	err = identity.GenerateIdentity(name, email, comment, kem, dsa, aead, xof, workspace.MountPoint, pass1)
	if err != nil {
		fmt.Printf("[-] Failed to generate identity: %v\n", err)
		return
	}

	// Calculate the directory name created by GenerateIdentity
	safeName := strings.ReplaceAll(name, " ", "_")
	identityDirName := fmt.Sprintf("keys_%s", safeName)

	srcDir := filepath.Join(workspace.MountPoint, identityDirName)
	dstDir := filepath.Join(".", identityDirName)

	fmt.Println("[*] Key generation complete. Extracting sealed vault to persistent SSD...")

	// Safely copy the encrypted vault out of RAM and onto the physical disk
	err = copyDirToSSD(srcDir, dstDir)
	if err != nil {
		fmt.Printf("[-] Failed to save encrypted identity to SSD: %v\n", err)
		return
	}

	pubDir := filepath.Join(dstDir, "public")
	prof, err := identity.LoadProfile(pubDir)
	if err == nil {
		fmt.Println("\n[+] Identity Successfully Created and Symmetrically Encrypted!")
		fmt.Printf("    User ID:     %s\n", prof.UserID())
		fmt.Printf("    Fingerprint: %s\n", prof.Fingerprint)
		fmt.Printf("    -> Encrypted key block: ./keys_%s/private/private_key.asc (PROTECTED)\n", safeName)
		fmt.Println("[+] Phantom Workspace shredded and unmounted successfully.")
	}
}
