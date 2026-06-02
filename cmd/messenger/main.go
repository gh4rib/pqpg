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
		fmt.Println(" 7) Exit")
		fmt.Println("=====================================================================")
		fmt.Print("Select an option [1-7]: ")

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

	fmt.Print("Enter path to the file you want to send (e.g., secret.txt): ")
	filePath := readInput(reader)

	msgBytes, err := os.ReadFile(filePath)
	if err != nil {
		fmt.Printf("[-] Failed to read message file: %v\n", err)
		return
	}

	receiverProf, err := identity.LoadProfile(pubPath)
	if err != nil {
		fmt.Printf("[-] Failed to load recipient public keys: %v\n", err)
		return
	}

	fmt.Println("[*] Sealing Post-Quantum envelope...")
	env, err := packet.Seal(msgBytes, senderKr, receiverProf)
	if err != nil {
		fmt.Printf("[-] Encryption failed: %v\n", err)
		return
	}

	armored, err := packet.EncodeArmor(env)
	if err != nil {
		fmt.Printf("[-] ASCII Armoring failed: %v\n", err)
		return
	}

	outboxName := "outbox_msg.asc"
	err = os.WriteFile(outboxName, []byte(armored), 0644)
	if err != nil {
		fmt.Printf("[-] Failed to save packet: %v\n", err)
		return
	}

	fmt.Printf("\n[+] SUCCESS! File encrypted, signed, and saved to '%s'\n", outboxName)
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

	ascBytes, err := os.ReadFile(ascPath)
	if err != nil {
		fmt.Printf("[-] Failed to read packet file: %v\n", err)
		return
	}

	env, err := packet.DecodeArmor(string(ascBytes))
	if err != nil {
		fmt.Printf("[-] Failed to decode ASCII Armor: %v\n", err)
		return
	}

	if err := packet.CheckAndCacheMessage(env); err != nil {
		fmt.Printf("[-] %v\n", err)
		return
	}

	fmt.Printf("\n[*] Opening Envelope...\n    Sender Claim: %s\n    Timestamp: %v\n    KEM: %s\n",
		env.SenderName, time.Unix(env.Timestamp, 0).Format(time.RFC1123), env.KEMSuite)

	recovered, err := packet.Open(env, receiverKr, senderProf)
	if err != nil {
		fmt.Printf("[-] Verification or Decryption failed: %v\n", err)
		return
	}

	timestamp := time.Now().Format("20060102_150405")
	outFilename := fmt.Sprintf("decrypted_msg_%s.txt", timestamp)

	err = os.WriteFile(outFilename, recovered, 0644)
	if err != nil {
		fmt.Printf("[-] Failed to save decrypted file: %v\n", err)
		return
	}

	fmt.Printf("[+] VERIFICATION SUCCESSFUL. Mathematical identity proven.\n")
	fmt.Printf("[+] Decrypted file saved to: %s\n", outFilename)
}

// ---------------------------------------------------------------------
// Utility
// ---------------------------------------------------------------------

func readInput(reader *bufio.Reader) string {
	input, _ := reader.ReadString('\n')
	return strings.TrimSpace(input)
}

// ---------------------------------------------------------------------
// Vault Handlers (Self-Encryption)
// ---------------------------------------------------------------------

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

	fmt.Print("Enter path to the file you want to lock (e.g., passwords.kdbx): ")
	filePath := readInput(reader)

	msgBytes, err := os.ReadFile(filePath)
	if err != nil {
		fmt.Printf("[-] Failed to read database file: %v\n", err)
		return
	}

	fmt.Println("[*] Sealing Database into Personal Post-Quantum Vault...")

	env, err := packet.Seal(msgBytes, myKr, &myKr.Profile)
	if err != nil {
		fmt.Printf("[-] Vault encryption failed: %v\n", err)
		return
	}

	armored, err := packet.EncodeArmor(env)
	if err != nil {
		fmt.Printf("[-] Vault ASCII Armoring failed: %v\n", err)
		return
	}

	outboxName := filePath + ".pq_vault"
	err = os.WriteFile(outboxName, []byte(armored), 0644)
	if err != nil {
		fmt.Printf("[-] Failed to save Vault packet: %v\n", err)
		return
	}

	fmt.Printf("\n[+] VAULT LOCKED! Encrypted, signed, and saved to '%s'\n", outboxName)
	fmt.Println("    (Recommendation: You can safely delete the original plaintext file now).")
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

	fmt.Print("Enter path to the locked vault file (e.g., passwords.kdbx.pq_vault): ")
	ascPath := readInput(reader)

	ascBytes, err := os.ReadFile(ascPath)
	if err != nil {
		fmt.Printf("[-] Failed to read Vault file: %v\n", err)
		return
	}

	env, err := packet.DecodeArmor(string(ascBytes))
	if err != nil {
		fmt.Printf("[-] Failed to decode Vault Armor: %v\n", err)
		return
	}

	if err := packet.CheckAndCacheMessage(env); err != nil {
		fmt.Printf("[-] %v\n", err)
		return
	}

	fmt.Printf("\n[*] Unlocking Vault...\n    Owner: %s\n    Locked On: %v\n",
		env.SenderName, time.Unix(env.Timestamp, 0).Format(time.RFC1123))

	recovered, err := packet.Open(env, myKr, &myKr.Profile)
	if err != nil {
		fmt.Printf("[-] Vault Verification or Decryption failed: %v\n", err)
		return
	}

	outFilename := strings.TrimSuffix(ascPath, ".pq_vault")

	err = os.WriteFile(outFilename, recovered, 0644)
	if err != nil {
		fmt.Printf("[-] Failed to save decrypted file: %v\n", err)
		return
	}

	fmt.Printf("[+] VAULT OPENED. Mathematical identity proven.\n")
	fmt.Printf("[+] Decrypted database restored to: %s\n", outFilename)
}