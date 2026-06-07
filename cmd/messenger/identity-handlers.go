package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/gh4rib/pqpg/internal/identity"
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
	fmt.Println(" --- NIST FIPS STANDARDS ---")
	fmt.Println("  1) NIST Level 3 Standard [ML-KEM-768   | ML-DSA-65          | AES-GCM  | SHAKE256]")
	fmt.Println("  2) NIST Level 5 Maximum  [ML-KEM-1024  | ML-DSA-87          | AES-GCM  | SHA3-512]")
	fmt.Println("  3) FIPS L5 Alternative   [ML-KEM-1024  | ML-DSA-87          | ChaCha20 | SHAKE256]")
	fmt.Println("  4) FIPS Hash-Failsafe    [ML-KEM-1024  | SLH-DSA-SHA2-256s  | AES-GCM  | SHA3-512]")
	fmt.Println("\n --- CONSERVATIVE / PRE-STANDARD ---")
	fmt.Println("  5) Conservative L5       [Kyber1024    | Dilithium5         | AES-GCM  | SHA3-512]")
	fmt.Println("  6) High-Margin Lattice   [FrodoKEM-640 | ML-DSA-87          | AES-GCM  | SHAKE256]")
	fmt.Println("  7) Pure Sponge/Keccak    [ML-KEM-1024  | SLH-DSA-SHAKE-256f | Ascon    | KangarooTwelve]")
	fmt.Println("  8) Ultimate Paranoia     [FrodoKEM-640 | SLH-DSA-SHAKE-256s | ChaCha20 | SHA3-512]")
	fmt.Println("\n --- HYBRID (CLASSICAL + POST-QUANTUM) ---")
	fmt.Println("  9) Hybrid Standard       [X-Wing       | ML-DSA-87          | AES-GCM  | SHA3-512]")
	fmt.Println(" 10) Hybrid Failsafe       [X-Wing       | SLH-DSA-SHA2-256s  | ChaCha20 | KangarooTwelve]")
	fmt.Println(" 11) Full Composite Max    [X-Wing       | EdDilithium3       | AES-GCM  | SHA3-512]")
	fmt.Println(" 12) Paranoia Composite    [X-Wing       | EdDilithium3       | Ascon    | KangarooTwelve]")
	fmt.Println("=========================================================================================")
	fmt.Print("Choice [1-12]: ")

	profChoice := readInput(reader)

	var kem, dsa, aead, xof string
	switch profChoice {
	case "1":
		kem, dsa, aead, xof = "ML-KEM-768", "ML-DSA-65", "AES-256-GCM", "SHAKE256"
	case "2":
		kem, dsa, aead, xof = "ML-KEM-1024", "ML-DSA-87", "AES-256-GCM", "SHA3-512"
	case "3":
		kem, dsa, aead, xof = "ML-KEM-1024", "ML-DSA-87", "ChaCha20-Poly1305", "SHAKE256"
	case "4":
		kem, dsa, aead, xof = "ML-KEM-1024", "SLH-DSA-SHA2-256s", "AES-256-GCM", "SHA3-512"
	case "5":
		kem, dsa, aead, xof = "Kyber1024", "Dilithium5", "AES-256-GCM", "SHA3-512"
	case "6":
		kem, dsa, aead, xof = "FrodoKEM-640-SHAKE", "ML-DSA-87", "AES-256-GCM", "SHAKE256"
	case "7":
		kem, dsa, aead, xof = "ML-KEM-1024", "SLH-DSA-SHAKE-256f", "Ascon-128a", "KangarooTwelve"
	case "8":
		kem, dsa, aead, xof = "FrodoKEM-640-SHAKE", "SLH-DSA-SHAKE-256s", "ChaCha20-Poly1305", "SHA3-512"
	case "9":
		kem, dsa, aead, xof = "X-Wing", "ML-DSA-87", "AES-256-GCM", "SHA3-512"
	case "10":
		kem, dsa, aead, xof = "X-Wing", "SLH-DSA-SHA2-256s", "ChaCha20-Poly1305", "KangarooTwelve"
	case "11":
		kem, dsa, aead, xof = "X-Wing", "EdDilithium3", "AES-256-GCM", "SHA3-512"
	case "12":
		kem, dsa, aead, xof = "X-Wing", "EdDilithium3", "Ascon-128a", "KangarooTwelve"
	default:
		fmt.Println("[-] Invalid choice. Aborting.")
		return
	}

	fmt.Println("[*] Executing mathematical key generation arrays...")
	err := identity.GenerateIdentity(name, email, comment, kem, dsa, aead, xof, ".", pass1)
	if err != nil {
		fmt.Printf("[-] Failed to generate identity: %v\n", err)
		return
	}

	safeName := strings.ReplaceAll(name, " ", "_")
	pubDir := filepath.Join(".", fmt.Sprintf("keys_%s", safeName), "public")
	prof, err := identity.LoadProfile(pubDir)
	if err == nil {
		fmt.Println("\n[+] Identity Successfully Created and Symmetrically Encrypted!")
		fmt.Printf("    User ID:     %s\n", prof.UserID())
		fmt.Printf("    Fingerprint: %s\n", prof.Fingerprint)
		fmt.Printf("    -> Encrypted key block: ./keys_%s/private/private_key.asc (PROTECTED)\n", safeName)
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
