package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/gh4rib/pqpg/internal/identity"
	"github.com/gh4rib/pqpg/internal/packet"
)

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

	outboxName := filePath + ".pq_vault"
	outFile, err := os.Create(outboxName)
	if err != nil {
		fmt.Printf("[-] Failed to allocate vault file: %v\n", err)
		return
	}
	defer outFile.Close()

	fmt.Println("[*] Sealing Database into Personal Post-Quantum Vault via Chunking...")

	err = packet.VaultSeal(inFile, outFile, myKr, compression)
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

	err = packet.VaultOpen(inFile, outFile, myKr)
	outFile.Close()

	if err != nil {
		os.Remove(outFilename)
		fmt.Printf("[-] CRITICAL: Vault Authentication failed. File Purged. Reason: %v\n", err)
		return
	}

	fmt.Printf("[+] VAULT OPENED. Mathematical identity proven.\n")
	fmt.Printf("[+] Decrypted database restored to: %s\n", outFilename)
}
