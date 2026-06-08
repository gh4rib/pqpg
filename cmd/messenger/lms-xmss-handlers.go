package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/gh4rib/pqpg/internal/crypto"
	"github.com/gh4rib/pqpg/internal/identity"
	"github.com/gh4rib/pqpg/internal/packet"
)

func handleStatefulDetachedSign(reader *bufio.Reader) {
	fmt.Print("\nEnter path to YOUR private folder (e.g., ./keys_alice/private): ")
	privPath := readInput(reader)

	fmt.Print("Enter Passphrase to unlock your private key: ")
	passphrase := readInput(reader)

	senderKr, err := identity.LoadKeyring(privPath, passphrase)
	if err != nil {
		fmt.Printf("[-] Access Denied: %v\n", err)
		return
	}

	// =====================================================================
	// FEATURE 4: CRYPTOGRAPHIC MEMORY HYGIENE
	// Guarantee that sensitive private key material is shredded from RAM
	// the exact moment this function finishes or errors out.
	// =====================================================================
	defer func() {
		if senderKr != nil {
			// Zero out the DSA private key (LMS/XMSS)
			for i := range senderKr.DSAPrivKey {
				senderKr.DSAPrivKey[i] = 0
			}
			// Zero out the KEM private key (Kyber/Frodo)
			for i := range senderKr.KEMPrivKey {
				senderKr.KEMPrivKey[i] = 0
			}
		}
	}()
	// =====================================================================

	// --- DYNAMIC STATEFUL DETECTION ---
	var ext string
	var algoName string
	if strings.HasPrefix(senderKr.Profile.DSASuite, "LMS") {
		ext = ".lms_sig"
		algoName = "LMS"
	} else if strings.HasPrefix(senderKr.Profile.DSASuite, "XMSS") {
		ext = ".xmss_sig"
		algoName = "XMSS"
	} else {
		fmt.Println("[-] CRITICAL: Your identity does not use a Stateful Hash-Based Signature scheme.")
		fmt.Println("    Please use standard Detached Signing (Option 9) for Lattice/Stateless keys.")
		return
	}

	// =====================================================================
	// FEATURE 3: HARDWARE-STYLE ANTI-ROLLBACK PROTECTION
	// =====================================================================
	registry := crypto.NewRegistry()
	statefulDSA, _ := registry.GetStatefulDSA(senderKr.Profile.DSASuite)

	// 1. Read the counter currently sitting in the AES-GCM vault
	currentCounter, err := statefulDSA.ExtractCounter(senderKr.DSAPrivKey)
	if err != nil {
		fmt.Printf("[-] Failed to read internal state counter: %v\n", err)
		return
	}

	// 2. Check the Canary file to ensure it hasn't gone backwards
	err = identity.VerifyAndCommitCounter(senderKr.Profile.Fingerprint, currentCounter, passphrase, privPath)
	if err != nil {
		fmt.Printf("\n[☠️] %v\n", err)
		return
	}
	// =====================================================================

	fmt.Print("Enter path to the release artifact to sign (e.g., ubuntu.iso): ")
	filePath := readInput(reader)

	inFile, err := os.Open(filePath)
	if err != nil {
		fmt.Printf("[-] Failed to open target file: %v\n", err)
		return
	}
	defer inFile.Close()

	hashAlgo := senderKr.Profile.XOFSuite

	fmt.Printf("\n[*] Identity Profile enforces %s for payload hashing.\n", hashAlgo)
	fmt.Printf("[*] Streaming file into %s engine...\n", hashAlgo)
	fmt.Printf("[!] WARNING: Performing Synchronous %s Key Overwrite...\n", algoName)

	armoredSig, err := packet.SignStatefulCleartextStream(inFile, senderKr, hashAlgo, passphrase, privPath)
	if err != nil {
		fmt.Printf("[-] Stateful Signing failed: %v\n", err)
		return
	}

	// =====================================================================
	// COMMIT NEW STATE TO CANARY
	// =====================================================================
	newCounter, _ := statefulDSA.ExtractCounter(senderKr.DSAPrivKey)
	_ = identity.VerifyAndCommitCounter(senderKr.Profile.Fingerprint, newCounter, passphrase, privPath)
	// =====================================================================

	outboxName := filePath + ext
	_ = os.WriteFile(outboxName, []byte(armoredSig), 0644)

	fmt.Printf("\n[+] SUCCESS! Artifact signed using %s.\n", algoName)
	fmt.Printf("[+] Internal counter successfully committed to disk and Anti-Rollback Guard.\n")
	fmt.Printf("[+] Signature saved to: %s\n", outboxName)
}

func handleStatefulDetachedVerify(reader *bufio.Reader) {
	fmt.Print("\nEnter path to SENDER'S public folder (e.g., ./keys_bob/public): ")
	pubPath := readInput(reader)

	senderProf, err := identity.LoadProfile(pubPath)
	if err != nil {
		fmt.Printf("[-] Failed to load sender public keys: %v\n", err)
		return
	}

	// --- DYNAMIC STATEFUL DETECTION ---
	var algoName string
	if strings.HasPrefix(senderProf.DSASuite, "LMS") {
		algoName = "LMS"
	} else if strings.HasPrefix(senderProf.DSASuite, "XMSS") {
		algoName = "XMSS"
	} else {
		fmt.Println("[-] The sender's identity is not a Stateful Release Engineer profile.")
		fmt.Println("    Please use standard Detached Verification (Option 10).")
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

	fmt.Printf("Enter path to the stateful detached signature file (e.g., ubuntu.iso.%s_sig): ", strings.ToLower(algoName))
	sigPath := readInput(reader)

	sigBytes, err := os.ReadFile(sigPath)
	if err != nil {
		fmt.Printf("[-] Failed to read signature file: %v\n", err)
		return
	}

	// --- UX SYMMETRY: Extract and display the enforced Hash Suite ---
	hashAlgo := senderProf.XOFSuite

	fmt.Printf("\n[*] Identity Profile enforces %s for payload hashing.\n", hashAlgo)
	fmt.Printf("[*] Streaming raw file into %s verification engine...\n", algoName)

	err = packet.VerifyStatefulCleartextStream(inFile, string(sigBytes), senderProf)
	if err != nil {
		fmt.Printf("\n[-] %v\n", err)
		return
	}

	fmt.Printf("\n[+] %s VERIFICATION SUCCESSFUL. Mathematical identity proven.\n", algoName)
	fmt.Printf("[+] The artifact '%s' is authentic and completely unaltered.\n", filePath)
}
