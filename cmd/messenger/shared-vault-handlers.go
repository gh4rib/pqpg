package main

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/gh4rib/pqpg-cloudflare-circl/internal/packet"
)

func handleSharedVaultLock(reader *bufio.Reader) {
	fmt.Print("\nEnter path to the file you want to split-lock (e.g., corporate_passwords.kdbx): ")
	filePath := readInput(reader)

	inFile, err := os.Open(filePath)
	if err != nil {
		fmt.Printf("[-] Failed to open database stream: %v\n", err)
		return
	}
	defer inFile.Close()

	fmt.Print("Enter TOTAL number of shares to generate (N) [Max 255]: ")
	nStr := readInput(reader)
	parts, _ := strconv.Atoi(nStr)

	fmt.Print("Enter THRESHOLD required to unlock (M) [Must be <= N]: ")
	mStr := readInput(reader)
	threshold, _ := strconv.Atoi(mStr)

	if threshold > parts || threshold < 2 {
		fmt.Println("[-] Invalid parameters. Threshold must be >= 2 and <= Total Shares.")
		return
	}

	fmt.Println("\nSelect Cryptographic Cipher for Vault:")
	fmt.Println(" 1) AES-256-GCM       (Hardware Accelerated Standard)")
	fmt.Println(" 2) ChaCha20-Poly1305 (Fast Software Stream Cipher)")
	fmt.Println(" 3) Ascon-128a        (Lightweight IoT Standard)")
	fmt.Print("Choice [1-3]: ")
	cipherChoice := readInput(reader)

	var aeadSuite string
	switch cipherChoice {
	case "2":
		aeadSuite = "ChaCha20-Poly1305"
	case "3":
		aeadSuite = "Ascon-128a"
	default:
		aeadSuite = "AES-256-GCM"
	}

	fmt.Println("\nSelect Cryptographic Hashing Algorithm:")
	fmt.Println(" 1) SHAKE256       (Standard Keccak XOF)")
	fmt.Println(" 2) SHA3-512       (Maximum FIPS Margin)")
	fmt.Println(" 3) KangarooTwelve (High-Speed Parallel Keccak)")
	fmt.Print("Choice [1-3]: ")
	hashChoice := readInput(reader)

	var xofSuite string
	switch hashChoice {
	case "2":
		xofSuite = "SHA3-512"
	case "3":
		xofSuite = "KangarooTwelve"
	default:
		xofSuite = "SHAKE256"
	}

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

	outboxName := filePath + ".pq_shared"
	outFile, err := os.Create(outboxName)
	if err != nil {
		fmt.Printf("[-] Failed to allocate vault file: %v\n", err)
		return
	}
	defer outFile.Close()

	fmt.Println("[*] Generating Master Key and plotting Feldman VSS Polynomial on Ed25519...")
	shares, err := packet.SharedVaultLock(inFile, outFile, aeadSuite, xofSuite, compression, parts, threshold)
	if err != nil {
		fmt.Printf("[-] Shared Vault encryption failed: %v\n", err)
		return
	}

	fmt.Printf("\n[+] SHARED VAULT LOCKED! Encrypted file saved to '%s'\n", outboxName)
	fmt.Println(strings.Repeat("=", 89))
	fmt.Printf("   DISTRIBUTE THESE %d SHARES SECURELY. %d ARE REQUIRED TO UNLOCK.\n", parts, threshold)
	fmt.Println(strings.Repeat("=", 89))
	for i, share := range shares {
		fmt.Printf(" Share %d: %s\n", i+1, share)
	}
	fmt.Println(strings.Repeat("=", 89))
}

func handleSharedVaultUnlock(reader *bufio.Reader) {
	fmt.Print("\nEnter path to the locked shared vault (e.g., corporate_passwords.kdbx.pq_shared): ")
	ascPath := readInput(reader)

	inFile, err := os.Open(ascPath)
	if err != nil {
		fmt.Printf("[-] Failed to open Vault stream: %v\n", err)
		return
	}
	defer inFile.Close()

	fmt.Print("How many VSS shares are you providing? (Enter the threshold number): ")
	mStr := readInput(reader)
	count, _ := strconv.Atoi(mStr)

	if count < 2 {
		fmt.Println("[-] At least 2 shares are required to reconstruct a polynomial.")
		return
	}

	var providedShares []string
	for i := 0; i < count; i++ {
		fmt.Printf(" Paste Share %d: ", i+1)
		share := readInput(reader)
		providedShares = append(providedShares, strings.TrimSpace(share))
	}

	outFilename := strings.TrimSuffix(ascPath, ".pq_shared")
	outFile, err := os.Create(outFilename)
	if err != nil {
		fmt.Printf("[-] Failed to allocate restored file: %v\n", err)
		return
	}

	fmt.Println("[*] Verifying shares against Public Commitments & Reconstructing Master Key...")
	err = packet.SharedVaultUnlock(inFile, outFile, providedShares)
	outFile.Close()

	if err != nil {
		os.Remove(outFilename)
		fmt.Printf("\n[-] CRITICAL: Vault Unlock failed. File Purged. Reason: %v\n", err)
		return
	}

	fmt.Printf("\n[+] VAULT OPENED. Mathematical authenticity verified and Key flawlessly reconstructed.\n")
	fmt.Printf("[+] Decrypted database restored to: %s\n", outFilename)
}
