package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/gh4rib/pqpg/internal/identity"
	"github.com/gh4rib/pqpg/internal/packet"
	"github.com/gh4rib/pqpg/internal/phantom"
)

func handleVaultLock(reader *bufio.Reader) {
	fmt.Print("\nEnter path to YOUR private folder (e.g., ./keys_alice/private): ")
	privPath := readInput(reader)

	fmt.Print("Enter Passphrase to unlock your private key: ")
	passphrase := readInput(reader)

	// =========================================================================
	// THE PHANTOM PIPELINE INITIATION
	// =========================================================================
	fmt.Println("\n[*] Negotiating ephemeral tmpfs mount with OS Kernel...")
	workspace, err := phantom.NewWorkspace()
	if err != nil {
		fmt.Printf("[-] Phantom Architecture initialization failed: %v\n", err)
		return
	}
	defer workspace.Destroy() // Guarantees RAM shredding on exit/panic

	fmt.Println("[*] Unpacking cryptographic identity directly into volatile memory...")
	err = phantom.UnlockVaultToRAM(privPath, workspace.MountPoint)
	if err != nil {
		fmt.Printf("[-] Failed to bridge vault to RAM: %v\n", err)
		return
	}

	// LOAD KEYS STRICTLY FROM RAM
	myKr, err := identity.LoadKeyring(workspace.MountPoint, passphrase)
	if err != nil {
		fmt.Printf("[-] Access Denied: %v\n", err)
		return
	}
	// =========================================================================

	//fmt.Print("Enter path to the file you want to lock (e.g., massive_database.kdbx): ")
	//filePath := readInput(reader)

	filePath, err := resolveInputPath(reader, "\nEnter path to the file or directory you want to lock: ")
	if err != nil {
		fmt.Printf("[-] %v\n", err)
		return
	}

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

	// Note: No LockRAMToVault is needed because vault operations do not mutate identity state.

	fmt.Printf("\n[+] VAULT LOCKED! Stream encrypted, signed, and saved to '%s'\n", outboxName)
	fmt.Println("[+] Phantom Workspace shredded and unmounted successfully.")
}

func handleVaultUnlock(reader *bufio.Reader) {
	fmt.Print("\nEnter path to YOUR private folder (e.g., ./keys_alice/private): ")
	privPath := readInput(reader)

	fmt.Print("Enter Passphrase to unlock your private key: ")
	passphrase := readInput(reader)

	// =========================================================================
	// THE PHANTOM PIPELINE INITIATION
	// =========================================================================
	fmt.Println("\n[*] Negotiating ephemeral tmpfs mount with OS Kernel...")
	workspace, err := phantom.NewWorkspace()
	if err != nil {
		fmt.Printf("[-] Phantom Architecture initialization failed: %v\n", err)
		return
	}
	defer workspace.Destroy()

	fmt.Println("[*] Unpacking cryptographic identity directly into volatile memory...")
	err = phantom.UnlockVaultToRAM(privPath, workspace.MountPoint)
	if err != nil {
		fmt.Printf("[-] Failed to bridge vault to RAM: %v\n", err)
		return
	}

	// LOAD KEYS STRICTLY FROM RAM
	myKr, err := identity.LoadKeyring(workspace.MountPoint, passphrase)
	if err != nil {
		fmt.Printf("[-] Access Denied: %v\n", err)
		return
	}
	// =========================================================================

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

	fmt.Printf("\n[+] VAULT OPENED. Mathematical identity proven.\n")
	fmt.Printf("[+] Decrypted database restored to: %s\n", outFilename)
	fmt.Println("[+] Phantom Workspace shredded and unmounted successfully.")
}
