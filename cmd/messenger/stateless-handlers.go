package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/gh4rib/pqpg/internal/crypto"
	"github.com/gh4rib/pqpg/internal/identity"
	"github.com/gh4rib/pqpg/internal/packet"
)

func handleStatelessSend(reader *bufio.Reader) {
	fmt.Print("\nEnter path to YOUR private folder (e.g., ./keys_alice/private): ")
	privPath := readInput(reader)

	fmt.Print("Enter Passphrase to unlock your private key: ")
	passphrase := readInput(reader)

	senderKr, err := identity.LoadKeyring(privPath, passphrase)
	if err != nil {
		fmt.Printf("[-] Access Denied: %v\n", err)
		return
	}

	// Initialize DB strictly to access the Address Book
	registry := crypto.NewRegistry()
	xof, err := registry.GetXOF(senderKr.Profile.XOFSuite)
	if err != nil {
		return
	}
	xof.Write([]byte("PQPG-BoltDB-MasterKey"))
	xof.Write(senderKr.KEMPrivKey)
	sessionKey := xof.Derive(nil, 32)

	sessionStore, err := identity.OpenSessionStore(privPath, sessionKey)
	if err != nil {
		return
	}
	defer sessionStore.Close()

	fmt.Println("\n[*] Select the RECIPIENT:")
	receiverProf, err := selectContact(reader, sessionStore, "RECIPIENT")
	if err != nil {
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
	outboxName := fmt.Sprintf("stateless_%s.asc", baseFilename)
	outFile, err := os.Create(outboxName)
	if err != nil {
		fmt.Printf("[-] Failed to create stateless stream: %v\n", err)
		return
	}
	defer outFile.Close()

	fmt.Println("[*] Sealing Post-Quantum Stateless Envelope...")
	err = packet.StatelessSeal(inFile, outFile, senderKr, receiverProf, compression)
	if err != nil {
		fmt.Printf("[-] Encryption interrupted: %v\n", err)
		return
	}

	fmt.Printf("\n[+] SUCCESS! File encrypted statelessly and saved to '%s'\n", outboxName)
}

func handleStatelessReceive(reader *bufio.Reader) {
	fmt.Print("\nEnter path to YOUR private folder (e.g., ./keys_bob/private): ")
	privPath := readInput(reader)

	fmt.Print("Enter Passphrase to unlock your private key: ")
	passphrase := readInput(reader)

	receiverKr, err := identity.LoadKeyring(privPath, passphrase)
	if err != nil {
		fmt.Printf("[-] Access Denied: %v\n", err)
		return
	}

	// Initialize DB strictly to access Address Book & Anti-Replay Cache
	registry := crypto.NewRegistry()
	xof, err := registry.GetXOF(receiverKr.Profile.XOFSuite)
	if err != nil {
		return
	}
	xof.Write([]byte("PQPG-BoltDB-MasterKey"))
	xof.Write(receiverKr.KEMPrivKey)
	sessionKey := xof.Derive(nil, 32)

	sessionStore, err := identity.OpenSessionStore(privPath, sessionKey)
	if err != nil {
		return
	}
	defer sessionStore.Close()

	fmt.Println("\n[*] Select the SENDER:")
	senderProf, err := selectContact(reader, sessionStore, "SENDER")
	if err != nil {
		return
	}

	fmt.Print("\nEnter path to the stateless armored packet file (e.g., stateless_msg.asc): ")
	ascPath := readInput(reader)

	inFile, err := os.Open(ascPath)
	if err != nil {
		fmt.Printf("[-] Failed to open incoming stream: %v\n", err)
		return
	}
	defer inFile.Close()

	outFilename := fmt.Sprintf("decrypted_stateless_%s.txt", time.Now().Format("20060102_150405"))
	outFile, err := os.Create(outFilename)
	if err != nil {
		fmt.Printf("[-] Failed to allocate output file: %v\n", err)
		return
	}

	fmt.Println("[*] Engaging Stateless Decryption Engine with Anti-Replay Memory...")
	err = packet.StatelessOpen(inFile, outFile, sessionStore, receiverKr, senderProf)
	outFile.Close()

	if err != nil {
		os.Remove(outFilename)
		fmt.Printf("[-] CRITICAL: Verification or Decryption failed. File Purged. Reason: %v\n", err)
		return
	}

	fmt.Printf("[+] STATELESS VERIFICATION SUCCESSFUL. Mathematical identity proven.\n")
	fmt.Printf("[+] Decrypted file saved to: %s\n", outFilename)
}
