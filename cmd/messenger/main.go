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
		fmt.Println("\n=====================================================================")
		fmt.Println("             PQPG: POST-QUANTUM PRIVACY GUARD ENGINE                 ")
		fmt.Println("=====================================================================")
		fmt.Println(" 1) Generate New Identity (PKI Setup)")
		fmt.Println(" 2) View Local Keyrings")
		fmt.Println(" 3) Encrypt & Sign a File (Send)")
		fmt.Println(" 4) Decrypt & Verify a File (Receive)")
		fmt.Println(" 5) Exit")
		fmt.Println("=====================================================================")
		fmt.Print("Select an option [1-5]: ")

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
	if name == "" {
		fmt.Println("[-] Name cannot be empty. Aborting.")
		return
	}

	fmt.Print("Enter E-mail Address (e.g., alice@example.com): ")
	email := readInput(reader)
	if email == "" || !strings.Contains(email, "@") {
		fmt.Println("[-] Invalid or missing email address. Aborting.")
		return
	}

	fmt.Print("Enter Comment/Description (Optional, e.g., Work Key): ")
	comment := readInput(reader)

	fmt.Println("\nSelect a Security Profile Configuration:")
	fmt.Println(" 1) NIST Level 3 (ML-KEM-768 + ML-DSA-65 + AES-256-GCM + SHAKE256)")
	fmt.Println(" 2) NIST Level 5 (ML-KEM-1024 + ML-DSA-87 + AES-256-GCM + SHA3-512)")
	fmt.Println(" 3) Hash-Based Maximum (X-Wing + SLH-DSA-SHA2-256s + Ascon-128a + KangarooTwelve)")
	fmt.Println(" 4) Full Hybrid Maximum (X-Wing + EdDilithium3 + Ascon-128a + KangarooTwelve)")
	fmt.Print("Choice [1-4]: ")

	profChoice := readInput(reader)

	var kem, dsa, aead, xof string
	switch profChoice {
	case "1":
		kem, dsa, aead, xof = "ML-KEM-768", "ML-DSA-65", "AES-256-GCM", "SHAKE256"
	case "2":
		kem, dsa, aead, xof = "ML-KEM-1024", "ML-DSA-87", "AES-256-GCM", "SHA3-512"
	case "3":
		kem, dsa, aead, xof = "X-Wing", "SLH-DSA-SHA2-256s", "Ascon-128a", "KangarooTwelve"
	case "4":
		kem, dsa, aead, xof = "X-Wing", "EdDilithium3", "Ascon-128a", "KangarooTwelve"
	default:
		fmt.Println("[-] Invalid choice. Aborting.")
		return
	}

	fmt.Println("[*] Generating keys. This may take a moment for large parameter sets...")
	err := identity.GenerateIdentity(name, email, comment, kem, dsa, aead, xof, ".")
	if err != nil {
		fmt.Printf("[-] Failed to generate identity: %v\n", err)
		return
	}

	// Mirror the filesystem sanitization to construct the correct path
	safeName := strings.ReplaceAll(name, " ", "_")

	// Load the newly generated profile to display the computed fingerprint
	pubDir := filepath.Join(".", fmt.Sprintf("keys_%s", safeName), "public")
	prof, err := identity.LoadProfile(pubDir)
	if err == nil {
		fmt.Println("\n[+] Identity Successfully Created!")
		fmt.Printf("    User ID:     %s\n", prof.UserID())
		fmt.Printf("    Fingerprint: %s\n", prof.Fingerprint)
		fmt.Printf("    -> Private keys: ./keys_%s/private (KEEP SECRET)\n", safeName)
		fmt.Printf("    -> Public keys:  ./keys_%s/public  (SHARE THIS)\n", safeName)
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

	fmt.Print("Enter path to RECIPIENT'S public folder (e.g., ./keys_bob/public): ")
	pubPath := readInput(reader)

	fmt.Print("Enter path to the file you want to send (e.g., secret.txt): ")
	filePath := readInput(reader)

	msgBytes, err := os.ReadFile(filePath)
	if err != nil {
		fmt.Printf("[-] Failed to read message file: %v\n", err)
		return
	}

	senderKr, err := identity.LoadKeyring(privPath)
	if err != nil {
		fmt.Printf("[-] Failed to load private keys: %v\n", err)
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

	fmt.Print("Enter path to SENDER'S public folder (e.g., ./keys_alice/public): ")
	pubPath := readInput(reader)

	fmt.Print("Enter path to the armored packet file (e.g., outbox_msg.asc): ")
	ascPath := readInput(reader)

	receiverKr, err := identity.LoadKeyring(privPath)
	if err != nil {
		fmt.Printf("[-] Failed to load private keys: %v\n", err)
		return
	}

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

	// ---- ANTI-REPLAY DEFENSE ----
	if err := packet.CheckAndCacheMessage(env); err != nil {
		fmt.Printf("[-] %v\n", err)
		return
	}
	// ----------------------------------

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
