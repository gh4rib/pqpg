package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gh4rib/pqpg-cloudflare-circl/internal/identity"
	"github.com/gh4rib/pqpg-cloudflare-circl/internal/packet"
)

func main() {
	reader := bufio.NewReader(os.Stdin)

	for {
		fmt.Println("=====================================================================")
		fmt.Println("             PQPG: POST-QUANTUM PRIVACY GUARD ENGINE                 ")
		fmt.Println("=====================================================================")
		fmt.Println(" 1) Generate New Identity (PKI Setup)")
		fmt.Println(" 2) View Local Keyrings")
		fmt.Println(" 3) Encrypt & Sign a File (Send)")
		fmt.Println(" 4) Decrypt & Verify a File (Receive)")
		fmt.Println(" 5) Lock File into Personal Vault")   // NEW
		fmt.Println(" 6) Unlock Personal Vault")           // NEW
		fmt.Println(" 7) Sign Massive File (Cleartext Detached)")     // NEW
		fmt.Println(" 8) Verify Massive File (Cleartext Detached)")   // NEW
		fmt.Println(" 9) Exit")
		fmt.Println("=====================================================================")
		fmt.Print("Select an option [1-9]: ")

		option := readInput(reader)

		switch option {
		case "1":
			handleGenerateIdentity(reader)
		case "2":
			handleViewKeyrings()
		case "3":
			handleSend(reader)
		case "4":
			handleReceive(reader)
		case "5":
			handleVaultLock(reader)
		case "6":
			handleVaultUnlock(reader)
		case "7":
			handleDetachedSign(reader)
		case "8":
			handleDetachedVerify(reader)
		case "9":
			fmt.Println("[*] Exiting PQPG. Stay secure.")
			return
		default:
			fmt.Println("[-] Invalid option. Please select 1-5.")
		}
	}
}

// ---------------------------------------------------------------------
// Feature Handlers
// ---------------------------------------------------------------------

func handleDetachedSign(reader *bufio.Reader) {
	fmt.Print("\nEnter path to YOUR private folder (e.g., ./keys_alice/private): ")
	privPath := readInput(reader)

	fmt.Print("Enter Passphrase to unlock your private key: ")
	passphrase := readInput(reader)

	senderKr, err := identity.LoadKeyring(privPath, passphrase)
	if err != nil {
		fmt.Printf("[-] Access Denied: %v\n", err)
		return
	}

	fmt.Print("Enter path to the massive file to sign (e.g., ubuntu.iso): ")
	filePath := readInput(reader)

	inFile, err := os.Open(filePath)
	if err != nil {
		fmt.Printf("[-] Failed to open target file: %v\n", err)
		return
	}
	defer inFile.Close()

	fmt.Println("\nSelect Cryptographic Hashing Algorithm:")
	fmt.Println(" 1) SHA-512       (Strongest SHA-2)")
	fmt.Println(" 2) SHA3-512      (Strongest SHA-3)")
	fmt.Println(" 3) SHAKE256      (Strongest Keccak XOF)")
	fmt.Println(" 4) KangarooTwelve (High-Speed Parallel Keccak)")
	fmt.Print("Choice [1-4]: ")
	hashChoice := readInput(reader)

	var hashAlgo string
	switch hashChoice {
	case "1": hashAlgo = "SHA-512"
	case "2": hashAlgo = "SHA3-512"
	case "3": hashAlgo = "SHAKE256"
	case "4": hashAlgo = "KangarooTwelve"
	default:
		fmt.Println("[-] Invalid selection. Aborting.")
		return
	}

	fmt.Println("[*] Streaming file into hashing engine...")
	armoredSig, err := packet.SignCleartextStream(inFile, senderKr, hashAlgo)
	if err != nil {
		fmt.Printf("[-] Signing failed: %v\n", err)
		return
	}

	outboxName := filePath + ".pqc_sig"
	err = os.WriteFile(outboxName, []byte(armoredSig), 0644)
	if err != nil {
		fmt.Printf("[-] Failed to write signature file: %v\n", err)
		return
	}

	fmt.Printf("\n[+] SUCCESS! Detached signature saved to '%s'\n", outboxName)
}

func handleDetachedVerify(reader *bufio.Reader) {
	fmt.Print("\nEnter path to SENDER'S public folder (e.g., ./keys_bob/public): ")
	pubPath := readInput(reader)

	senderProf, err := identity.LoadProfile(pubPath)
	if err != nil {
		fmt.Printf("[-] Failed to load sender public keys: %v\n", err)
		return
	}

	fmt.Print("Enter path to the massive raw file (e.g., ubuntu.iso): ")
	filePath := readInput(reader)

	inFile, err := os.Open(filePath)
	if err != nil {
		fmt.Printf("[-] Failed to open raw file: %v\n", err)
		return
	}
	defer inFile.Close()

	fmt.Print("Enter path to the detached signature file (e.g., ubuntu.iso.pqc_sig): ")
	sigPath := readInput(reader)

	sigBytes, err := os.ReadFile(sigPath)
	if err != nil {
		fmt.Printf("[-] Failed to read signature file: %v\n", err)
		return
	}

	fmt.Println("[*] Streaming raw file into verification engine...")
	err = packet.VerifyCleartextStream(inFile, string(sigBytes), senderProf)
	if err != nil {
		fmt.Printf("\n[-] %v\n", err)
		return
	}

	fmt.Printf("\n[+] VERIFICATION SUCCESSFUL. Mathematical identity proven.\n")
	fmt.Printf("[+] The file '%s' is authentic and completely unaltered.\n", filePath)
}

func handleGenerateIdentity(reader *bufio.Reader) {
	fmt.Print("\nEnter Real Name (e.g., Alice Vance): ")
	name := readInput(reader)
	if name == "" { return }

	fmt.Print("Enter E-mail Address (e.g., alice@example.com): ")
	email := readInput(reader)
	if email == "" || !strings.Contains(email, "@") { return }

	fmt.Print("Enter Comment/Description (Optional): ")
	comment := readInput(reader)

	// --- PASSPHRASE ENTRY SECURED ---
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
	// --- NIST FIPS STANDARDS ---
	case "1":
		kem, dsa, aead, xof = "ML-KEM-768", "ML-DSA-65", "AES-256-GCM", "SHAKE256"
	case "2":
		kem, dsa, aead, xof = "ML-KEM-1024", "ML-DSA-87", "AES-256-GCM", "SHA3-512"
	case "3":
		kem, dsa, aead, xof = "ML-KEM-1024", "ML-DSA-87", "ChaCha20-Poly1305", "SHAKE256"
	case "4":
		kem, dsa, aead, xof = "ML-KEM-1024", "SLH-DSA-SHA2-256s", "AES-256-GCM", "SHA3-512"

	// --- CONSERVATIVE / PRE-STANDARD ---
	case "5":
		kem, dsa, aead, xof = "Kyber1024", "Dilithium5", "AES-256-GCM", "SHA3-512"
	case "6":
		kem, dsa, aead, xof = "FrodoKEM-640-SHAKE", "ML-DSA-87", "AES-256-GCM", "SHAKE256"
	case "7":
		kem, dsa, aead, xof = "ML-KEM-1024", "SLH-DSA-SHAKE-256f", "Ascon-128a", "KangarooTwelve"
	case "8":
		kem, dsa, aead, xof = "FrodoKEM-640-SHAKE", "SLH-DSA-SHAKE-256s", "ChaCha20-Poly1305", "SHA3-512"

	// --- HYBRID (CLASSICAL + POST-QUANTUM) ---
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

func handleSend(reader *bufio.Reader) {
	fmt.Print("\nEnter path to YOUR private folder (e.g., ./keys_alice/private): ")
	privPath := readInput(reader)

	fmt.Print("Enter Passphrase to unlock your private key: ")
	passphrase := readInput(reader)

	senderKr, err := identity.LoadKeyring(privPath, passphrase)
	if err != nil {
		fmt.Printf("[-] Access Denied: %v\n", err)
		return
	}

	fmt.Print("Enter path to RECIPIENT'S public folder (e.g., ./keys_bob/public): ")
	pubPath := readInput(reader)

	fmt.Print("Enter path to the file you want to send: ")
	filePath := readInput(reader)

	inFile, err := os.Open(filePath)
	if err != nil {
		fmt.Printf("[-] Failed to open target file for streaming: %v\n", err)
		return
	}
	defer inFile.Close()

	receiverProf, err := identity.LoadProfile(pubPath)
	if err != nil {
		fmt.Printf("[-] Failed to load recipient public keys: %v\n", err)
		return
	}

	outboxName := "outbox_msg.asc"
	outFile, err := os.Create(outboxName)
	if err != nil {
		fmt.Printf("[-] Failed to create outbox stream: %v\n", err)
		return
	}
	defer outFile.Close()

	fmt.Println("[*] Sealing Post-Quantum Streaming Envelope...")
	err = packet.StreamSeal(inFile, outFile, senderKr, receiverProf)
	if err != nil {
		fmt.Printf("[-] Encryption interrupted: %v\n", err)
		return
	}

	fmt.Printf("\n[+] SUCCESS! File encrypted in chunks, signed, and saved to '%s'\n", outboxName)
}

func handleReceive(reader *bufio.Reader) {
	fmt.Print("\nEnter path to YOUR private folder (e.g., ./keys_bob/private): ")
	privPath := readInput(reader)

	fmt.Print("Enter Passphrase to unlock your private key: ")
	passphrase := readInput(reader)

	receiverKr, err := identity.LoadKeyring(privPath, passphrase)
	if err != nil {
		fmt.Printf("[-] Access Denied: %v\n", err)
		return
	}

	fmt.Print("Enter path to SENDER'S public folder (e.g., ./keys_alice/public): ")
	pubPath := readInput(reader)

	fmt.Print("Enter path to the armored packet file (e.g., outbox_msg.asc): ")
	ascPath := readInput(reader)

	senderProf, err := identity.LoadProfile(pubPath)
	if err != nil {
		fmt.Printf("[-] Failed to load sender public keys: %v\n", err)
		return
	}

	inFile, err := os.Open(ascPath)
	if err != nil {
		fmt.Printf("[-] Failed to open incoming stream: %v\n", err)
		return
	}
	defer inFile.Close()

	outFilename := fmt.Sprintf("decrypted_msg_%s.txt", time.Now().Format("20060102_150405"))
	outFile, err := os.Create(outFilename)
	if err != nil {
		fmt.Printf("[-] Failed to allocate output file: %v\n", err)
		return
	}
	
	fmt.Println("[*] Streaming decryption engine engaged...")
	err = packet.StreamOpen(inFile, outFile, receiverKr, senderProf)
	outFile.Close() // Close immediately to allow deletion on failure
	
	if err != nil {
		os.Remove(outFilename) // Purge the corrupt file instantly to protect the user
		fmt.Printf("[-] CRITICAL: Verification or Decryption failed. File Purged. Reason: %v\n", err)
		return
	}

	fmt.Printf("[+] VERIFICATION SUCCESSFUL. Mathematical identity proven.\n")
	fmt.Printf("[+] Decrypted file saved to: %s\n", outFilename)
}

func handleVaultLock(reader *bufio.Reader) {
	fmt.Print("\nEnter path to YOUR private folder (e.g., ./keys_alice/private): ")
	privPath := readInput(reader)

	fmt.Print("Enter Passphrase to unlock your private key: ")
	passphrase := readInput(reader)

	myKr, err := identity.LoadKeyring(privPath, passphrase)
	if err != nil {
		fmt.Printf("[-] Access Denied: %v\n", err)
		return
	}

	fmt.Print("Enter path to the file you want to lock (e.g., massive_database.kdbx): ")
	filePath := readInput(reader)

	inFile, err := os.Open(filePath)
	if err != nil {
		fmt.Printf("[-] Failed to open database stream: %v\n", err)
		return
	}
	defer inFile.Close()

	outboxName := filePath + ".pq_vault"
	outFile, err := os.Create(outboxName)
	if err != nil {
		fmt.Printf("[-] Failed to allocate vault file: %v\n", err)
		return
	}
	defer outFile.Close()

	fmt.Println("[*] Sealing Database into Personal Post-Quantum Vault via Chunking...")

	err = packet.StreamSeal(inFile, outFile, myKr, &myKr.Profile)
	if err != nil {
		fmt.Printf("[-] Vault encryption failed: %v\n", err)
		return
	}

	fmt.Printf("\n[+] VAULT LOCKED! Stream encrypted, signed, and saved to '%s'\n", outboxName)
}

func handleVaultUnlock(reader *bufio.Reader) {
	fmt.Print("\nEnter path to YOUR private folder (e.g., ./keys_alice/private): ")
	privPath := readInput(reader)

	fmt.Print("Enter Passphrase to unlock your private key: ")
	passphrase := readInput(reader)

	myKr, err := identity.LoadKeyring(privPath, passphrase)
	if err != nil {
		fmt.Printf("[-] Access Denied: %v\n", err)
		return
	}

	fmt.Print("Enter path to the locked vault file (e.g., massive_database.kdbx.pq_vault): ")
	ascPath := readInput(reader)

	inFile, err := os.Open(ascPath)
	if err != nil {
		fmt.Printf("[-] Failed to open Vault stream: %v\n", err)
		return
	}
	defer inFile.Close()

	outFilename := strings.TrimSuffix(ascPath, ".pq_vault")
	outFile, err := os.Create(outFilename)
	if err != nil {
		fmt.Printf("[-] Failed to allocate restored file: %v\n", err)
		return
	}

	fmt.Println("[*] Streaming decryption engine engaged. Unlocking vault...")
	err = packet.StreamOpen(inFile, outFile, myKr, &myKr.Profile)
	outFile.Close()

	if err != nil {
		os.Remove(outFilename)
		fmt.Printf("[-] CRITICAL: Vault Authentication failed. File Purged. Reason: %v\n", err)
		return
	}

	fmt.Printf("[+] VAULT OPENED. Mathematical identity proven.\n")
	fmt.Printf("[+] Decrypted database restored to: %s\n", outFilename)
}

func readInput(reader *bufio.Reader) string {
	input, _ := reader.ReadString('\n')
	return strings.TrimSpace(input)
}