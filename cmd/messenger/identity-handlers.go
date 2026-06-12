package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/gh4rib/pqpg/internal/identity"
	"github.com/gh4rib/pqpg/internal/phantom"
)

func handleGenerateIdentity(reader *bufio.Reader) {
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
	fmt.Println("                      SELECT A SECURITY PROFILE CONFIGURATION")
	fmt.Println("=========================================================================================")
	fmt.Println(" --- X-Wing == Hybrid-ML-KEM-768+X25519")
	fmt.Println(" --- NIST FIPS STANDARDS ---")
	fmt.Println("  1) NIST Level 3 Standard [Hybrid-ML-KEM-768+X448   | Hybrid-ML-DSA-65+Ed448          | AES-256-GCM  | SHAKE256]")
	fmt.Println("  2) NIST Level 5 Maximum  [Hybrid-ML-KEM-1024+X25519| Hybrid-ML-DSA-87+Ed25519        | AES-256-GCM  | SHA3-512]")
	fmt.Println("  3) FIPS L5 Alternative   [Hybrid-ML-KEM-1024+X448  | Hybrid-ML-DSA-87+Ed448          | ChaCha20-Poly1305 | KangarooTwelve]")
	fmt.Println("  4) FIPS Hash-Failsafe    [Hybrid-ML-KEM-1024+X448  | Hybrid-SLH-DSA-SHA2-256s+Ed448  | AES-256-GCM  | BLAKE3-512")
	fmt.Println("\n --- CONSERVATIVE / PRE-STANDARD ---")
	fmt.Println("  5) Conservative L5       [Hybrid-Kyber1024+X448    | Hybrid-Dilithium5+Ed448         | AES-256-GCM  | BLAKE3-512]")
	fmt.Println("  6) High-Margin Lattice   [Hybrid-FrodoKEM-640+X448 | Hybrid-ML-DSA-87+Ed25519        | AES-256-GCM  | SHAKE256]")
	fmt.Println("  7) Ultimate Paranoia     [Hybrid-FrodoKEM-640+X25519 | Hybrid-SLH-DSA-SHAKE-256s+Ed448 | ChaCha20-Poly1305 | SHA3-512]")
	fmt.Println("\n --- HYBRID (CLASSICAL + POST-QUANTUM) ---")
	fmt.Println("  8) Hybrid Standard       [Hybrid-ML-KEM-768+X25519 | Hybrid-ML-DSA-87+Ed448          | AES-256-GCM  | SHA3-512]")
	fmt.Println("  9) Hybrid Failsafe       [Hybrid-ML-KEM-768+X25519 | Hybrid-SLH-DSA-SHA2-256s+Ed448  | ChaCha20-Poly1305 | KangarooTwelve]")
	fmt.Println(" 10) Full Composite Max    [Hybrid-ML-KEM-768+X448   | Hybrid-Dilithium5+Ed25519       | AES-256-GCM  | SHA3-512]")
	fmt.Println("\n --- FALCON-1024 (FAST FOURIER LATTICE) ---")
	fmt.Println(" 11) ML-KEM + Falcon       [Hybrid-ML-KEM-1024+X448  | Hybrid-Falcon-1024+Ed448        | AES-256-GCM  | SHA3-512]")
	fmt.Println(" 12) Frodo + Falcon        [Hybrid-FrodoKEM-640+X448 | Hybrid-Falcon-1024+Ed25519      | ChaCha20-Poly1305 | SHAKE256]")
	fmt.Println(" 13) Hybrid X-Wing + Falcon[Hybrid-ML-KEM-768+X25519 | Hybrid-Falcon-1024+Ed448        | AES-256-GCM  | BLAKE3-512]")
	fmt.Println("\n --- STATEFUL HASH-BASED (RELEASE ENGINEER) ---")
	fmt.Println(" 14) Absolute Max SHA2     [Hybrid-ML-KEM-1024+X448  | XMSSMT-SHA2_60/12_512     | AES-256-GCM  | KangarooTwelve]")
	fmt.Println(" 15) Absolute Max SHAKE    [Hybrid-ML-KEM-1024+X448  | XMSSMT-SHAKE256_60/12_512 | ChaCha20-Poly1305 | BLAKE3-512]")
	fmt.Println(" 16) Conservative Lattice  [Hybrid-FrodoKEM-640+X448 | XMSSMT-SHA2_40/8_512      | AES-256-GCM  | SHAKE256]")
	fmt.Println(" 17) Pure Sponge L-Free    [Hybrid-FrodoKEM-640+X448 | XMSSMT-SHAKE256_40/8_512  | ChaCha20-Poly1305 | SHAKE256]")
	fmt.Println(" 18) Hybrid Max SHA2       [Hybrid-ML-KEM-768+X25519 | XMSSMT-SHA2_60/6_256      | AES-256-GCM  | SHA3-512]")
	fmt.Println(" 19) Hybrid Max SHAKE      [Hybrid-ML-KEM-768+X448   | XMSSMT-SHAKE256_60/6_256  | ChaCha20-Poly1305 | BLAKE3-512]")
	fmt.Println(" 20) Single-Tree SHA2      [Hybrid-ML-KEM-1024+X448  | XMSS-SHA2_20_512          | AES-256-GCM  | SHA3-512]")
	fmt.Println(" 21) Single-Tree SHAKE     [Hybrid-ML-KEM-768+X25519 | XMSS-SHAKE256_20_512      | ChaCha20-Poly1305 | KangarooTwelve]")
	fmt.Println("\n --- LEIGHTON-MICALI (LMS) MAXIMUM SECRECY ---")
	fmt.Println(" 22) Max LMS Compact       [Hybrid-ML-KEM-1024+X448  | LMS_H25_W8                | AES-256-GCM  | KangarooTwelve]")
	fmt.Println(" 23) Max LMS Balanced      [Hybrid-ML-KEM-1024+X448  | LMS_H25_W4                | ChaCha20-Poly1305 | SHA3-512]")
	fmt.Println(" 24) Frodo LMS Compact     [Hybrid-FrodoKEM-640+X448 | LMS_H25_W8                | AES-256-GCM  | SHAKE256]")
	fmt.Println(" 25) Frodo LMS Balanced    [Hybrid-FrodoKEM-640+X448 | LMS_H20_W4                | ChaCha20-Poly1305 | SHAKE256]")
	fmt.Println(" 26) X-Wing LMS Compact    [Hybrid-ML-KEM-768+X448   | LMS_H25_W8                | AES-256-GCM  | SHA3-512]")
	fmt.Println(" 27) X-Wing LMS Balanced   [Hybrid-ML-KEM-768+X448   | LMS_H20_W4                | ChaCha20-Poly1305 | SHA3-512]")
	fmt.Println(" 28) Fast LMS Compact      [Hybrid-ML-KEM-1024+X25519| LMS_H20_W8                | AES-256-GCM  | BLAKE3-512]")
	fmt.Println(" 29) Fast LMS Balanced     [Hybrid-ML-KEM-768+X448   | LMS_H20_W4                | ChaCha20-Poly1305 | SHA3-512]")
	fmt.Println(" 30) Max LMS Compact       [Hybrid-ML-KEM-1024+X448  | LMS_H15_W8                | AES-256-GCM  | SHA3-512]")
	fmt.Println(" 31) Max LMS Balanced      [Hybrid-ML-KEM-1024+X448  | LMS_H15_W4                | ChaCha20-Poly1305 | SHA3-512]")
	fmt.Println(" 32) Frodo LMS Compact     [Hybrid-FrodoKEM-640+X25519 | LMS_H10_W8              | AES-256-GCM  | SHAKE256]")
	fmt.Println(" 33) Frodo LMS Balanced    [Hybrid-FrodoKEM-640+X448 | LMS_H15_W4                | ChaCha20-Poly1305 | SHAKE256]")
	fmt.Println(" 34) X-Wing LMS Compact    [Hybrid-ML-KEM-768+X25519 | LMS_H10_W8                | AES-256-GCM  | BLAKE3-512]")
	fmt.Println(" 35) X-Wing LMS Balanced   [Hybrid-ML-KEM-768+X25519 | LMS_H15_W4                | ChaCha20-Poly1305 | KangarooTwelve]")
	fmt.Println(" 36) Fast LMS Compact      [Hybrid-ML-KEM-1024+X448  | LMS_H10_W8                | AES-256-GCM  | SHA3-512]")
	fmt.Println(" 37) Fast LMS Balanced     [Hybrid-ML-KEM-768+X25519 | LMS_H10_W4                | ChaCha20-Poly1305 | SHA3-512]")
	fmt.Println("\n --- EXTENDED NONCE (24-BYTE COLLISION RESISTANT) ---")
	fmt.Println(" 38) XAES NIST Level 5     [Hybrid-ML-KEM-1024+X448  | Hybrid-ML-DSA-87+Ed25519        | XAES-256-GCM | SHA3-512]")
	fmt.Println(" 39) XAES Conservative     [Hybrid-FrodoKEM-640+X448 | Hybrid-ML-DSA-87+Ed448          | XAES-256-GCM | SHAKE256]")
	fmt.Println(" 40) XAES Hybrid Max       [Hybrid-ML-KEM-768+X25519 | Hybrid-Dilithium5+Ed25519       | XAES-256-GCM | BLAKE3-512]")
	fmt.Println(" 41) XChaCha NIST Level 5  [Hybrid-ML-KEM-1024+X448  | Hybrid-ML-DSA-87+Ed25519        | XChaCha-Poly1305  | SHA3-512]")
	fmt.Println(" 42) XChaCha Conservative  [Hybrid-FrodoKEM-640+X448 | Hybrid-SLH-DSA-SHAKE-256s+Ed448 | XChaCha-Poly1305  | SHAKE256]")
	fmt.Println(" 43) XChaCha Hybrid Max    [Hybrid-ML-KEM-768+X25519 | Hybrid-Dilithium5+Ed448         | XChaCha-Poly1305  | BLAKE3-512]")
	fmt.Println("\n --- MISUSE-RESISTANT / DETERMINISTIC AEAD ---")
	fmt.Println(" 44) GCM-SIV NIST Level 5  [Hybrid-ML-KEM-1024+X448  | Hybrid-ML-DSA-87+Ed448          | AES-256-GCM-SIV  | KangarooTwelve]")
	fmt.Println(" 45) GCM-SIV Conservative  [Hybrid-FrodoKEM-640+X448 | Hybrid-SLH-DSA-SHAKE-256s+Ed25519 | AES-256-GCM-SIV  | SHAKE256]")
	fmt.Println(" 46) GCM-SIV Hybrid Max    [Hybrid-ML-KEM-768+X25519 | Hybrid-Dilithium5+Ed25519       | AES-256-GCM-SIV  | BLAKE3-512]")
	fmt.Println(" 47) SIV-CMAC NIST Level 5 [Hybrid-ML-KEM-1024+X448  | Hybrid-ML-DSA-87+Ed448          | AES-256-SIV-CMAC | SHA3-512]")
	fmt.Println(" 48) SIV-CMAC Conservative [Hybrid-FrodoKEM-640+X448 | Hybrid-SLH-DSA-SHAKE-256s+Ed448 | AES-256-SIV-CMAC | SHAKE256]")
	fmt.Println(" 49) SIV-CMAC Hybrid Max   [Hybrid-ML-KEM-768+X25519 | Hybrid-Dilithi+Ed25519um3+Ed25519 | AES-256-SIV-CMAC | SHA3-512]")
	fmt.Println(" 50) Deoxys-II NIST L5     [Hybrid-ML-KEM-1024+X448  | Hybrid-ML-DSA-87+Ed448          | Deoxys-II-256-128 | KangarooTwelve]")
	fmt.Println(" 51) Deoxys-II Conserv.    [Hybrid-FrodoKEM-640+X448 | Hybrid-SLH-DSA-SHAKE-256s+Ed25519 | Deoxys-II-256-128 | SHAKE256]")
	fmt.Println(" 52) Deoxys-II Hybrid Max  [Hybrid-ML-KEM-768+X25519 | Hybrid-Dilithium5+Ed448         | Deoxys-II-256-128 | BLAKE3-512]")
	fmt.Println(" 53) Deoxys-II Stateful    [Hybrid-ML-KEM-768+X448   | XMSSMT-SHA2_60/12  | Deoxys-II-256-128 | SHA3-512]")
	fmt.Println("\n --- SOVEREIGN / ISO STANDARDS (FEISTEL NETWORK) ---")
	fmt.Println(" 54) Camellia NIST L5      [Hybrid-ML-KEM-1024+X25519| Hybrid-ML-DSA-87+Ed448          | Camellia-EtM | BLAKE3-512]")
	fmt.Println(" 55) Camellia Conserv.     [Hybrid-FrodoKEM-640+X448 | Hybrid-SLH-DSA-SHAKE-256s+Ed25519 | Camellia-EtM | SHAKE256]")
	fmt.Println(" 56) Camellia Hybrid Max   [Hybrid-ML-KEM-768+X25519 | Hybrid-Dilithium3+Ed448         | Camellia-EtM | SHA3-512]")
	fmt.Println("\n --- ULTRA-CONSERVATIVE FORTRESS (MAXIMUM STRUCTURAL SECURITY) ---")
	fmt.Println(" 57) Serpent NIST L5       [Hybrid-ML-KEM-1024+X448  | Hybrid-ML-DSA-87+Ed448          | Serpent-EtM  | BLAKE3-512]")
	fmt.Println(" 58) Serpent Conserv.      [Hybrid-FrodoKEM-640+X448 | Hybrid-SLH-DSA-SHAKE-256s+Ed448 | Serpent-EtM  | SHAKE256]")
	fmt.Println(" 59) Serpent Hybrid Max    [Hybrid-ML-KEM-768+X25519 | Hybrid-Dilithium5+Ed25519       | Serpent-EtM  | SHA3-512]")
	fmt.Println("\n --- MASSIVE WIDE-BLOCK CIPHERS (SKEIN/THREEFISH) ---")
	fmt.Println(" 60) Threefish-256 L5      [Hybrid-ML-KEM-1024+X25519| Hybrid-ML-DSA-87+Ed25519        | Threefish-256-EtM | SHA3-512]")
	fmt.Println(" 61) Threefish-512 Conserv.[Hybrid-FrodoKEM-640+X448 | Hybrid-SLH-DSA-SHAKE-256s+Ed448 | Threefish-512-EtM | SHAKE256]")
	fmt.Println(" 62) Threefish-1024 Max    [Hybrid-ML-KEM-768+X25519 | Hybrid-Dilithium5+Ed25519       | Threefish-1024-EtM  | KangarooTwelve]")
	fmt.Println("\n --- NIST LIGHTWEIGHT CRYPTOGRAPHY WINNER (LWC) ---")
	fmt.Println(" 63) Ascon-128a Fast       [Hybrid-ML-KEM-768+X25519 | Hybrid-ML-DSA-65+Ed25519        | Ascon-128a    | BLAKE3-512]")
	fmt.Println(" 64) Ascon-128 Standard    [Hybrid-ML-KEM-1024+X448  | Hybrid-ML-DSA-87+Ed448          | Ascon-128     | SHAKE256]")
	fmt.Println(" 65) Ascon-80pq Grover     [Hybrid-ML-KEM-768+X25519 | Hybrid-Dilithium3+Ed25519       | Ascon-80pq    | SHA3-512]")
	fmt.Println(" 66) Pure Sponge/Keccak    [Hybrid-ML-KEM-1024+X448  | Hybrid-SLH-DSA-SHAKE-256f+Ed448 | Ascon-80pq    | KangarooTwelve]")
	fmt.Println(" 67) Paranoia Composite    [Hybrid-FrodoKEM-640+X448 | Hybrid-Dilithium5+Ed448         | Ascon-80pq    | KangarooTwelve]")
	fmt.Println("\n --- PURE SKEIN ARCHITECTURE (UNIFIED BLOCK & HASH ENGINE) ---")
	fmt.Println(" 68) Pure Skein-256 L5     [Hybrid-ML-KEM-1024+X448  | Hybrid-ML-DSA-87+Ed25519        | Threefish-256-EtM  | Skein-256]")
	fmt.Println(" 69) Pure Skein-512 Cons.  [Hybrid-FrodoKEM-640+X448 | Hybrid-SLH-DSA-SHAKE-256s+Ed448 | Threefish-512-EtM  | Skein-512]")
	fmt.Println(" 70) Pure Skein-1024 Max   [Hybrid-ML-KEM-768+X25519 | Hybrid-Dilithium5+Ed25519       | Threefish-1024-EtM | Skein-1024]")
	fmt.Println("=========================================================================================")
	fmt.Print("Choice [1-70]: ")

	profChoice := readInput(reader)

	var kem, dsa, aead, xof string
	switch profChoice {
	case "1":
		kem, dsa, aead, xof = "Hybrid-ML-KEM-768+X448", "Hybrid-ML-DSA-65+Ed448", "AES-256-GCM", "SHAKE256"
	case "2":
		kem, dsa, aead, xof = "Hybrid-ML-KEM-1024+X25519", "Hybrid-ML-DSA-87+Ed25519", "AES-256-GCM", "SHA3-512"
	case "3":
		kem, dsa, aead, xof = "Hybrid-ML-KEM-1024+X448", "Hybrid-ML-DSA-87+Ed448", "ChaCha20-Poly1305", "KangarooTwelve"
	case "4":
		kem, dsa, aead, xof = "Hybrid-ML-KEM-1024+X448", "Hybrid-SLH-DSA-SHA2-256s+Ed448", "AES-256-GCM", "BLAKE3-512"
	case "5":
		kem, dsa, aead, xof = "Hybrid-Kyber1024+X448", "Hybrid-Dilithium5+Ed448", "AES-256-GCM", "BLAKE3-512"
	case "6":
		kem, dsa, aead, xof = "Hybrid-FrodoKEM-640-SHAKE+X448", "Hybrid-ML-DSA-87+Ed25519", "AES-256-GCM", "SHAKE256"
	case "7":
		kem, dsa, aead, xof = "Hybrid-FrodoKEM-640-SHAKE+X25519", "Hybrid-SLH-DSA-SHAKE-256s+Ed448", "ChaCha20-Poly1305", "SHA3-512"
	case "8":
		kem, dsa, aead, xof = "Hybrid-ML-KEM-768+X25519", "Hybrid-ML-DSA-87+Ed448", "AES-256-GCM", "SHA3-512"
	case "9":
		kem, dsa, aead, xof = "Hybrid-ML-KEM-768+X25519", "Hybrid-SLH-DSA-SHA2-256s+Ed448", "ChaCha20-Poly1305", "KangarooTwelve"
	case "10":
		kem, dsa, aead, xof = "Hybrid-ML-KEM-768+X448", "Hybrid-Dilithium5+Ed25519", "AES-256-GCM", "SHA3-512"
	case "11":
		kem, dsa, aead, xof = "Hybrid-ML-KEM-1024+X448", "Hybrid-Falcon-1024+Ed448", "AES-256-GCM", "SHA3-512"
	case "12":
		kem, dsa, aead, xof = "Hybrid-FrodoKEM-640-SHAKE+X448", "Hybrid-Falcon-1024+Ed25519", "ChaCha20-Poly1305", "SHAKE256"
	case "13":
		kem, dsa, aead, xof = "Hybrid-ML-KEM-768+X25519", "Hybrid-Falcon-1024+Ed448", "AES-256-GCM", "BLAKE3-512"
	case "14":
		kem, dsa, aead, xof = "Hybrid-ML-KEM-1024+X448", "XMSSMT-SHA2_60/12_512", "AES-256-GCM", "KangarooTwelve"
	case "15":
		kem, dsa, aead, xof = "Hybrid-ML-KEM-1024+X448", "XMSSMT-SHAKE256_60/12_512", "ChaCha20-Poly1305", "BLAKE3-512"
	case "16":
		kem, dsa, aead, xof = "Hybrid-FrodoKEM-640-SHAKE+X448", "XMSSMT-SHA2_40/8_512", "AES-256-GCM", "SHAKE256"
	case "17":
		kem, dsa, aead, xof = "Hybrid-FrodoKEM-640-SHAKE+X448", "XMSSMT-SHAKE256_40/8_512", "ChaCha20-Poly1305", "SHAKE256"
	case "18":
		kem, dsa, aead, xof = "Hybrid-ML-KEM-768+X25519", "XMSSMT-SHA2_60/6_256", "AES-256-GCM", "SHA3-512"
	case "19":
		kem, dsa, aead, xof = "Hybrid-ML-KEM-768+X448", "XMSSMT-SHAKE256_60/6_256", "ChaCha20-Poly1305", "BLAKE3-512"
	case "20":
		kem, dsa, aead, xof = "Hybrid-ML-KEM-1024+X448", "XMSS-SHA2_20_512", "AES-256-GCM", "SHA3-512"
	case "21":
		kem, dsa, aead, xof = "Hybrid-ML-KEM-768+X25519", "XMSS-SHAKE256_20_512", "ChaCha20-Poly1305", "KangarooTwelve"
	case "22":
		kem, dsa, aead, xof = "Hybrid-ML-KEM-1024+X448", "LMS_H25_W8", "AES-256-GCM", "KangarooTwelve"
	case "23":
		kem, dsa, aead, xof = "Hybrid-ML-KEM-1024+X448", "LMS_H25_W4", "ChaCha20-Poly1305", "SHA3-512"
	case "24":
		kem, dsa, aead, xof = "Hybrid-FrodoKEM-640-SHAKE+X448", "LMS_H25_W8", "AES-256-GCM", "SHAKE256"
	case "25":
		kem, dsa, aead, xof = "Hybrid-FrodoKEM-640-SHAKE+X448", "LMS_H20_W4", "ChaCha20-Poly1305", "SHAKE256"
	case "26":
		kem, dsa, aead, xof = "Hybrid-ML-KEM-768+X448", "LMS_H25_W8", "AES-256-GCM", "SHA3-512"
	case "27":
		kem, dsa, aead, xof = "Hybrid-ML-KEM-768+X448", "LMS_H20_W4", "ChaCha20-Poly1305", "SHA3-512"
	case "28":
		kem, dsa, aead, xof = "Hybrid-ML-KEM-1024+X25519", "LMS_H20_W8", "AES-256-GCM", "BLAKE3-512"
	case "29":
		kem, dsa, aead, xof = "Hybrid-ML-KEM-768+X448", "LMS_H20_W4", "ChaCha20-Poly1305", "SHA3-512"
	case "30":
		kem, dsa, aead, xof = "Hybrid-ML-KEM-1024+X448", "LMS_H15_W8", "AES-256-GCM", "SHA3-512"
	case "31":
		kem, dsa, aead, xof = "Hybrid-ML-KEM-1024+X448", "LMS_H15_W4", "ChaCha20-Poly1305", "SHA3-512"
	case "32":
		kem, dsa, aead, xof = "Hybrid-FrodoKEM-640-SHAKE+X25519", "LMS_H10_W8", "AES-256-GCM", "SHAKE256"
	case "33":
		kem, dsa, aead, xof = "Hybrid-FrodoKEM-640-SHAKE+X448", "LMS_H15_W4", "ChaCha20-Poly1305", "SHAKE256"
	case "34":
		kem, dsa, aead, xof = "Hybrid-ML-KEM-768+X25519", "LMS_H10_W8", "AES-256-GCM", "BLAKE3-512"
	case "35":
		kem, dsa, aead, xof = "Hybrid-ML-KEM-768+X25519", "LMS_H15_W4", "ChaCha20-Poly1305", "KangarooTwelve"
	case "36":
		kem, dsa, aead, xof = "Hybrid-ML-KEM-1024+X448", "LMS_H10_W8", "AES-256-GCM", "SHA3-512"
	case "37":
		kem, dsa, aead, xof = "Hybrid-ML-KEM-768+X25519", "LMS_H10_W4", "ChaCha20-Poly1305", "SHA3-512"
	case "38":
		kem, dsa, aead, xof = "Hybrid-ML-KEM-1024+X448", "Hybrid-ML-DSA-87+Ed25519", "XAES-256-GCM", "SHA3-512"
	case "39":
		kem, dsa, aead, xof = "Hybrid-FrodoKEM-640-SHAKE+X448", "Hybrid-ML-DSA-87+Ed448", "XAES-256-GCM", "SHAKE256"
	case "40":
		kem, dsa, aead, xof = "Hybrid-ML-KEM-768+X25519", "Hybrid-Dilithium5+Ed25519", "XAES-256-GCM", "BLAKE3-512"
	case "41":
		kem, dsa, aead, xof = "Hybrid-ML-KEM-1024+X448", "Hybrid-ML-DSA-87+Ed25519", "XChaCha20-Poly1305", "SHA3-512"
	case "42":
		kem, dsa, aead, xof = "Hybrid-FrodoKEM-640-SHAKE+X448", "Hybrid-SLH-DSA-SHAKE-256s+Ed448", "XChaCha20-Poly1305", "SHAKE256"
	case "43":
		kem, dsa, aead, xof = "Hybrid-ML-KEM-768+X25519", "Hybrid-Dilithium5+Ed448", "XChaCha20-Poly1305", "BLAKE3-512"
	case "44":
		kem, dsa, aead, xof = "Hybrid-ML-KEM-1024+X448", "Hybrid-ML-DSA-87+Ed448", "AES-256-GCM-SIV", "KangarooTwelve"
	case "45":
		kem, dsa, aead, xof = "Hybrid-FrodoKEM-640-SHAKE+X448", "Hybrid-SLH-DSA-SHAKE-256s+Ed25519", "AES-256-GCM-SIV", "SHAKE256"
	case "46":
		kem, dsa, aead, xof = "Hybrid-ML-KEM-768+X25519", "Hybrid-Dilithium5+Ed25519", "AES-256-GCM-SIV", "BLAKE3-512"
	case "47":
		kem, dsa, aead, xof = "Hybrid-ML-KEM-1024+X448", "Hybrid-ML-DSA-87+Ed448", "AES-256-SIV-CMAC", "SHA3-512"
	case "48":
		kem, dsa, aead, xof = "Hybrid-FrodoKEM-640-SHAKE+X448", "Hybrid-SLH-DSA-SHAKE-256s+Ed448", "AES-256-SIV-CMAC", "SHAKE256"
	case "49":
		kem, dsa, aead, xof = "Hybrid-ML-KEM-768+X25519", "Hybrid-Dilithium3+Ed25519", "AES-256-SIV-CMAC", "SHA3-512"
	case "50":
		kem, dsa, aead, xof = "Hybrid-ML-KEM-1024+X448", "Hybrid-ML-DSA-87+Ed448", "Deoxys-II-256-128", "KangarooTwelve"
	case "51":
		kem, dsa, aead, xof = "Hybrid-FrodoKEM-640-SHAKE+X448", "Hybrid-SLH-DSA-SHAKE-256s+Ed25519", "Deoxys-II-256-128", "SHAKE256"
	case "52":
		kem, dsa, aead, xof = "Hybrid-ML-KEM-768+X25519", "Hybrid-Dilithium5+Ed448", "Deoxys-II-256-128", "BLAKE3-512"
	case "53":
		kem, dsa, aead, xof = "Hybrid-ML-KEM-768+X448", "XMSSMT-SHA2_60/12_512", "Deoxys-II-256-128", "SHA3-512"
	case "54":
		kem, dsa, aead, xof = "Hybrid-ML-KEM-1024+X25519", "Hybrid-ML-DSA-87+Ed448", "Camellia-256-EtM", "BLAKE3-512"
	case "55":
		kem, dsa, aead, xof = "Hybrid-FrodoKEM-640-SHAKE+X448", "Hybrid-SLH-DSA-SHAKE-256s+Ed25519", "Camellia-256-EtM", "SHAKE256"
	case "56":
		kem, dsa, aead, xof = "Hybrid-ML-KEM-768+X25519", "Hybrid-Dilithium3+Ed448", "Camellia-256-EtM", "SHA3-512"
	case "57":
		kem, dsa, aead, xof = "Hybrid-ML-KEM-1024+X448", "Hybrid-ML-DSA-87+Ed448", "Serpent-256-EtM", "BLAKE3-512"
	case "58":
		kem, dsa, aead, xof = "Hybrid-FrodoKEM-640-SHAKE+X448", "Hybrid-SLH-DSA-SHAKE-256s+Ed448", "Serpent-256-EtM", "SHAKE256"
	case "59":
		kem, dsa, aead, xof = "Hybrid-ML-KEM-768+X25519", "Hybrid-Dilithium5+Ed25519", "Serpent-256-EtM", "SHA3-512"
	case "60":
		kem, dsa, aead, xof = "Hybrid-ML-KEM-1024+X25519", "Hybrid-ML-DSA-87+Ed25519", "Threefish-256-EtM", "SHA3-512"
	case "61":
		kem, dsa, aead, xof = "Hybrid-FrodoKEM-640-SHAKE+X448", "Hybrid-SLH-DSA-SHAKE-256s+Ed448", "Threefish-512-EtM", "SHAKE256"
	case "62":
		kem, dsa, aead, xof = "Hybrid-ML-KEM-768+X25519", "Hybrid-Dilithium5+Ed25519", "Threefish-1024-EtM", "KangarooTwelve"
	case "63":
		kem, dsa, aead, xof = "Hybrid-ML-KEM-768+X25519", "Hybrid-ML-DSA-65+Ed25519", "Ascon-128a", "BLAKE3-512"
	case "64":
		kem, dsa, aead, xof = "Hybrid-ML-KEM-1024+X448", "Hybrid-ML-DSA-87+Ed448", "Ascon-128", "SHAKE256"
	case "65":
		kem, dsa, aead, xof = "Hybrid-ML-KEM-768+X25519", "Hybrid-Dilithium3+Ed25519", "Ascon-80pq", "SHA3-512"
	case "66":
		kem, dsa, aead, xof = "Hybrid-ML-KEM-1024+X448", "Hybrid-SLH-DSA-SHAKE-256f+Ed448", "Ascon-80pq", "KangarooTwelve"
	case "67":
		kem, dsa, aead, xof = "Hybrid-FrodoKEM-640-SHAKE+X448", "Hybrid-Dilithium5+Ed448", "Ascon-80pq", "KangarooTwelve"
	case "68":
		kem, dsa, aead, xof = "Hybrid-ML-KEM-1024+X448", "Hybrid-ML-DSA-87+Ed25519", "Threefish-256-EtM", "Skein-256"
	case "69":
		kem, dsa, aead, xof = "Hybrid-FrodoKEM-640-SHAKE+X448", "Hybrid-SLH-DSA-SHAKE-256s+Ed448", "Threefish-512-EtM", "Skein-512"
	case "70":
		kem, dsa, aead, xof = "Hybrid-ML-KEM-768+X25519", "Hybrid-Dilithium5+Ed25519", "Threefish-1024-EtM", "Skein-1024"
	default:
		fmt.Println("[-] Invalid choice. Aborting.")
		return
	}

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

func handleViewKeyrings() {
	fmt.Println("\n[*] Scanning current directory for local keyrings...")

	files, err := os.ReadDir(".")
	if err != nil {
		fmt.Printf("[-] Failed to read directory: %v\n", err)
		return
	}

	found := false
	for _, f := range files {
		if f.IsDir() && strings.HasPrefix(f.Name(), "keys_") {
			// Profile reads are exclusively public metadata. No Phantom isolation required.
			pubDir := filepath.Join(f.Name(), "public")
			prof, err := identity.LoadProfile(pubDir)
			if err == nil {
				found = true
				fmt.Println(strings.Repeat("-", 75))
				fmt.Printf("User ID:     %s\n", prof.UserID())
				fmt.Printf("Fingerprint: %s\n", prof.Fingerprint)
				fmt.Printf("Algorithms:  KEM: %s | DSA: %s\n", prof.KEMSuite, prof.DSASuite)
				fmt.Printf("             AEAD: %s | XOF: %s\n", prof.AEADSuite, prof.XOFSuite)
				fmt.Printf("Local Path:  ./%s\n", f.Name())
			}
		}
	}

	if found {
		fmt.Println(strings.Repeat("-", 75))
	} else {
		fmt.Println("[-] No local keyrings found in the current directory.")
	}
}

// copyDirToSSD performs a recursive, cross-device safe copy from the tmpfs RAM disk to the SSD.
func copyDirToSSD(src string, dst string) error {
	return filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		relPath, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		destPath := filepath.Join(dst, relPath)

		if info.IsDir() {
			return os.MkdirAll(destPath, info.Mode())
		}

		sourceFile, err := os.Open(path)
		if err != nil {
			return err
		}
		defer sourceFile.Close()

		destFile, err := os.OpenFile(destPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, info.Mode())
		if err != nil {
			return err
		}
		defer destFile.Close()

		_, err = io.Copy(destFile, sourceFile)
		return err
	})
}
