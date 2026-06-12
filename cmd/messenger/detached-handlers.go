package main

import (
	"bufio"
	"fmt"
	"os"

	"github.com/gh4rib/pqpg/internal/identity"
	"github.com/gh4rib/pqpg/internal/packet"
	"github.com/gh4rib/pqpg/internal/phantom"
)

func handleDetachedSign(reader *bufio.Reader) {
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

	fmt.Print("Enter path to the massive file to sign (e.g., ubuntu.iso): ")
	filePath := readInput(reader)

	inFile, err := os.Open(filePath)
	if err != nil {
		fmt.Printf("[-] Failed to open target file: %v\n", err)
		return
	}
	defer inFile.Close()

	fmt.Println("\nSelect Cryptographic Hashing Algorithm:")
	fmt.Println(" 1) SHA-512        (Strongest SHA-2)")
	fmt.Println(" 2) SHA3-512       (Strongest SHA-3)")
	fmt.Println(" 3) SHAKE256       (Strongest Keccak XOF)")
	fmt.Println(" 4) KangarooTwelve (High-Speed Parallel Keccak)")
	fmt.Println(" 5) BLAKE3         (Strongest BLAKE3)")
	fmt.Print("Choice [1-4]: ")
	hashChoice := readInput(reader)

	var hashAlgo string
	switch hashChoice {
	case "1":
		hashAlgo = "SHA-512"
	case "2":
		hashAlgo = "SHA3-512"
	case "3":
		hashAlgo = "SHAKE256"
	case "4":
		hashAlgo = "KangarooTwelve"
	case "5":
		hashAlgo = "BLAKE3-512"
	default:
		fmt.Println("[-] Invalid selection. Aborting.")
		return
	}

	fmt.Println("[*] Streaming file into hashing engine...")

	// The Data Plane (inFile) streams natively from the SSD.
	// Only the Control Plane (senderKr) operates inside the RAM-disk.
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

	// NOTE: We do not need phantom.LockRAMToVault here because stateless
	// ML-DSA/Falcon signing does not mutate the sessions.db state database!

	fmt.Printf("\n[+] SUCCESS! Detached signature saved to '%s'\n", outboxName)
	fmt.Println("[+] Phantom Workspace shredded and unmounted successfully.")
}

func handleDetachedVerify(reader *bufio.Reader) {
	fmt.Print("\nEnter path to SENDER'S public folder (e.g., ./keys_bob/public): ")
	pubPath := readInput(reader)

	// Verification only requires Public Keys, so it bypasses the Phantom Workspace
	// and executes natively on the SSD.
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
