package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/gh4rib/pqpg-cloudflare-circl/internal/crypto"
	"github.com/gh4rib/pqpg-cloudflare-circl/internal/identity"
	"github.com/gh4rib/pqpg-cloudflare-circl/internal/packet"
)

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

	// Initialize DB early so we can use the Address Book
	registry := crypto.NewRegistry()
	xof, err := registry.GetXOF(senderKr.Profile.XOFSuite)
	if err != nil {
		fmt.Printf("[-] Failed to load Keccak suite: %v\n", err)
		return
	}
	xof.Write([]byte("PQPG-BoltDB-MasterKey"))
	xof.Write(senderKr.KEMPrivKey)
	sessionKey := xof.Derive(nil, 32)

	sessionStore, err := identity.OpenSessionStore(privPath, sessionKey)
	if err != nil {
		fmt.Printf("[-] Failed to initialize offline Double Ratchet database: %v\n", err)
		return
	}
	defer sessionStore.Close()

	fmt.Println("\n[*] Select the RECIPIENT:")
	receiverProf, err := selectContact(reader, sessionStore, "RECIPIENT")
	if err != nil {
		fmt.Printf("[-] Failed to load recipient profile: %v\n", err)
		return
	}

	fmt.Print("\nEnter path to the file you want to send: ")
	filePath := readInput(reader)

	inFile, err := os.Open(filePath)
	if err != nil {
		fmt.Printf("[-] Failed to open target file for streaming: %v\n", err)
		return
	}
	defer inFile.Close()

	fmt.Println("\nSelect Data Compression Profile:")
	fmt.Println(" 1) None (Best for already compressed files like .mp4, .zip, .kdbx)")
	fmt.Println(" 2) Zstandard (Extremely Fast, High Compression)")
	fmt.Println(" 3) GZIP (Legacy Standard)")
	fmt.Print("Choice [1-3]: ")
	compChoice := readInput(reader)

	var compression string
	switch compChoice {
	case "2":
		compression = "Zstd"
	case "3":
		compression = "Gzip"
	default:
		compression = "None"
	}

	baseFilename := filepath.Base(filePath)
	outboxName := fmt.Sprintf("outbox_%s.asc", baseFilename)
	outFile, err := os.Create(outboxName)
	if err != nil {
		fmt.Printf("[-] Failed to create outbox stream: %v\n", err)
		return
	}
	defer outFile.Close()

	fmt.Println("[*] Sealing Post-Quantum Streaming Envelope & Advancing Ratchets...")
	err = packet.StreamSeal(inFile, outFile, sessionStore, senderKr, receiverProf, compression)
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

	// Initialize DB early so we can use the Address Book
	registry := crypto.NewRegistry()
	xof, err := registry.GetXOF(receiverKr.Profile.XOFSuite)
	if err != nil {
		fmt.Printf("[-] Failed to load Keccak suite: %v\n", err)
		return
	}
	xof.Write([]byte("PQPG-BoltDB-MasterKey"))
	xof.Write(receiverKr.KEMPrivKey)
	sessionKey := xof.Derive(nil, 32)

	sessionStore, err := identity.OpenSessionStore(privPath, sessionKey)
	if err != nil {
		fmt.Printf("[-] Failed to initialize offline Double Ratchet database: %v\n", err)
		return
	}
	defer sessionStore.Close()

	fmt.Println("\n[*] Select the SENDER:")
	senderProf, err := selectContact(reader, sessionStore, "SENDER")
	if err != nil {
		fmt.Printf("[-] Failed to load sender profile: %v\n", err)
		return
	}

	fmt.Print("\nEnter path to the armored packet file (e.g., outbox_msg.asc): ")
	ascPath := readInput(reader)

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

	fmt.Println("[*] Engaging Double Ratchet Engine and processing payload...")
	err = packet.StreamOpen(inFile, outFile, sessionStore, receiverKr, senderProf)
	outFile.Close()

	if err != nil {
		os.Remove(outFilename)
		fmt.Printf("[-] CRITICAL: Verification or Decryption failed. File Purged. Reason: %v\n", err)
		return
	}

	fmt.Printf("[+] VERIFICATION SUCCESSFUL. Mathematical identity proven.\n")
	fmt.Printf("[+] Decrypted file saved to: %s\n", outFilename)
}

func handleImportContact(reader *bufio.Reader) {
	fmt.Print("\nEnter path to YOUR private folder (e.g., ./keys_alice/private): ")
	privPath := readInput(reader)

	fmt.Print("Enter Passphrase to unlock your private database: ")
	passphrase := readInput(reader)

	myKr, err := identity.LoadKeyring(privPath, passphrase)
	if err != nil {
		fmt.Printf("[-] Access Denied: %v\n", err)
		return
	}

	fmt.Print("Enter path to the CONTACT'S public folder to import (e.g., ./keys_bob/public): ")
	pubPath := readInput(reader)

	contactProf, err := identity.LoadProfile(pubPath)
	if err != nil {
		fmt.Printf("[-] Failed to load contact profile: %v\n", err)
		return
	}

	registry := crypto.NewRegistry()
	xof, _ := registry.GetXOF(myKr.Profile.XOFSuite)
	xof.Write([]byte("PQPG-BoltDB-MasterKey"))
	xof.Write(myKr.KEMPrivKey)
	sessionKey := xof.Derive(nil, 32)

	sessionStore, err := identity.OpenSessionStore(privPath, sessionKey)
	if err != nil {
		fmt.Printf("[-] Failed to open database: %v\n", err)
		return
	}
	defer sessionStore.Close()

	err = sessionStore.ImportContact(contactProf)
	if err != nil {
		fmt.Printf("[-] Failed to save contact to Address Book: %v\n", err)
		return
	}

	fmt.Printf("\n[+] SUCCESS! %s has been securely added to your Address Book.\n", contactProf.Name)
}

func handleResetSession(reader *bufio.Reader) {
	fmt.Print("\nEnter path to YOUR private folder (e.g., ./keys_alice/private): ")
	privPath := readInput(reader)

	fmt.Print("Enter Passphrase to unlock your private database: ")
	passphrase := readInput(reader)

	myKr, err := identity.LoadKeyring(privPath, passphrase)
	if err != nil {
		fmt.Printf("[-] Access Denied: %v\n", err)
		return
	}

	registry := crypto.NewRegistry()
	xof, _ := registry.GetXOF(myKr.Profile.XOFSuite)
	xof.Write([]byte("PQPG-BoltDB-MasterKey"))
	xof.Write(myKr.KEMPrivKey)
	sessionKey := xof.Derive(nil, 32)

	sessionStore, err := identity.OpenSessionStore(privPath, sessionKey)
	if err != nil {
		fmt.Printf("[-] Failed to open database: %v\n", err)
		return
	}
	defer sessionStore.Close()

	fmt.Println("\n[*] Select the contact whose session you want to RESET:")
	targetProf, err := selectContact(reader, sessionStore, "CONTACT")
	if err != nil || targetProf == nil {
		fmt.Printf("[-] Session reset aborted: %v\n", err)
		return
	}

	if err := sessionStore.ResetSession(targetProf.Fingerprint); err != nil {
		fmt.Printf("[-] Failed to reset session: %v\n", err)
		return
	}

	fmt.Printf("\n[+] SESSION RESET SUCCESSFUL.\n")
	fmt.Printf("[+] All cryptographic state with '%s' has been wiped.\n", targetProf.Name)
	fmt.Printf("[+] Your next message to them will initiate a fresh Bootstrap phase.\n")
}
