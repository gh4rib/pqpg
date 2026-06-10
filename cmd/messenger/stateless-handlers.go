package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gh4rib/pqpg/internal/crypto"
	"github.com/gh4rib/pqpg/internal/identity"
	"github.com/gh4rib/pqpg/internal/packet"
	"github.com/gh4rib/pqpg/internal/phantom"
)

func handleStatelessSend(reader *bufio.Reader) {
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

	// LOAD KEYS FROM RAM
	senderKr, err := identity.LoadKeyring(workspace.MountPoint, passphrase)
	if err != nil {
		fmt.Printf("[-] Access Denied: %v\n", err)
		return
	}
	// =========================================================================

	// --- THE STATEFUL SAFETY BLOCK ---
	if senderKr.Profile.DSASuite == "LMS-SHA256" || senderKr.Profile.DSASuite == "XMSSMT-SHA2" {
		fmt.Println("\n[-] CRITICAL ARCHITECTURE HALT: Stateful Keys Cannot Be Streamed.")
		fmt.Println("    Your identity uses a strict Hash-Based Signature Scheme (LMS/XMSS).")
		fmt.Println("    To prevent state-reuse and identity corruption, these keys are restricted")
		fmt.Println("    exclusively to synchronous Detached Signatures (Option 17).")
		fmt.Println("    Please generate a stateless identity (e.g., ML-DSA or Falcon) for network messaging.")
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

	// LOAD DATABASE FROM RAM
	sessionStore, err := identity.OpenSessionStore(workspace.MountPoint, sessionKey)
	if err != nil {
		return
	}

	fmt.Println("\n[*] Select the RECIPIENT:")
	receiverProf, err := selectContact(reader, sessionStore, "RECIPIENT")
	if err != nil {
		sessionStore.Close()
		return
	}

	// Address Book query is complete, we can close the RAM database lock early
	sessionStore.Close()

	//fmt.Print("\nEnter path to the file you want to send: ")
	//filePath := readInput(reader)
	filePath, err := resolveInputPath(reader, "\nEnter path to the file or directory you want to send: ")
	if err != nil {
		fmt.Printf("[-] %v\n", err)
		return
	}

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

	// Note: No LockRAMToVault needed because sending statelessly does not mutate the sender's DB state.

	fmt.Printf("\n[+] SUCCESS! File encrypted statelessly and saved to '%s'\n", outboxName)
	fmt.Println("[+] Phantom Workspace shredded and unmounted successfully.")
}

func handleStatelessReceive(reader *bufio.Reader) {
	fmt.Print("\nEnter path to YOUR private folder (e.g., ./keys_bob/private): ")
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

	// LOAD KEYS FROM RAM
	receiverKr, err := identity.LoadKeyring(workspace.MountPoint, passphrase)
	if err != nil {
		fmt.Printf("[-] Access Denied: %v\n", err)
		return
	}
	// =========================================================================

	// Initialize DB strictly to access Address Book & Anti-Replay Cache
	registry := crypto.NewRegistry()
	xof, err := registry.GetXOF(receiverKr.Profile.XOFSuite)
	if err != nil {
		return
	}
	xof.Write([]byte("PQPG-BoltDB-MasterKey"))
	xof.Write(receiverKr.KEMPrivKey)
	sessionKey := xof.Derive(nil, 32)

	// LOAD DATABASE FROM RAM
	sessionStore, err := identity.OpenSessionStore(workspace.MountPoint, sessionKey)
	if err != nil {
		return
	}

	fmt.Println("\n[*] Select the SENDER:")
	senderProf, err := selectContact(reader, sessionStore, "SENDER")
	if err != nil {
		sessionStore.Close()
		return
	}

	fmt.Print("\nEnter path to the stateless armored packet file (e.g., stateless_msg.asc): ")
	ascPath := readInput(reader)

	inFile, err := os.Open(ascPath)
	if err != nil {
		fmt.Printf("[-] Failed to open incoming stream: %v\n", err)
		sessionStore.Close()
		return
	}
	defer inFile.Close()

	// Intelligent Filename Extraction
	baseName := filepath.Base(ascPath)
	cleanName := strings.TrimSuffix(baseName, ".asc")
	cleanName = strings.TrimPrefix(cleanName, "stateless_")
	if cleanName == "" {
		cleanName = fmt.Sprintf("payload_%s.bin", time.Now().Format("150405"))
	}
	outFilename := fmt.Sprintf("inbox_stateless_%s", cleanName)

	outFile, err := os.Create(outFilename)
	if err != nil {
		fmt.Printf("[-] Failed to allocate output file: %v\n", err)
		sessionStore.Close()
		return
	}

	fmt.Println("[*] Engaging Stateless Decryption Engine with Anti-Replay Memory...")
	err = packet.StatelessOpen(inFile, outFile, sessionStore, receiverKr, senderProf)
	outFile.Close()

	// Explicitly release the BoltDB file lock in the RAM disk
	sessionStore.Close()

	if err != nil {
		// ATOMIC ROLLBACK
		os.Remove(outFilename)
		fmt.Printf("[-] CRITICAL: Verification or Decryption failed. File Purged. Reason: %v\n", err)
		fmt.Println("[-] Phantom RAM-disk discarded. Persistent state rollback successful.")
		return
	}

	// =========================================================================
	// STATE SYNCHRONIZATION (Saves the updated Anti-Replay Cache to SSD)
	// =========================================================================
	fmt.Println("[*] Verification Complete. Synchronizing Anti-Replay Cache to persistent storage...")
	err = phantom.LockRAMToVault(workspace.MountPoint, privPath)
	if err != nil {
		fmt.Printf("[-] Warning: Failed to sync database back to SSD: %v\n", err)
		return
	}

	fmt.Printf("\n[+] STATELESS VERIFICATION SUCCESSFUL. Mathematical identity proven.\n")
	fmt.Printf("[+] Decrypted file natively restored to: %s\n", outFilename)
	fmt.Println("[+] Phantom Workspace shredded and unmounted successfully.")
}
