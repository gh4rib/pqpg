package main

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/gh4rib/pqpg/internal/packet"
)

func handleTimeLockSeal(reader *bufio.Reader) {
	fmt.Println("\n======================================================================")
	fmt.Println("             PQPG TIME-LOCK SEAL (DEAD MAN'S SWITCH)                  ")
	fmt.Println("======================================================================")
	fmt.Println("[!] WARNING: This locks your file inside an RSA-4096 Verifiable Delay")
	fmt.Println("    Function (VDF). There is NO BACKDOOR and NO MASTER KEY.")
	fmt.Println()
	fmt.Println("[*] HOW IT WORKS (THE CPU BOTTLENECK):")
	fmt.Println("    - The lock relies on strictly sequential mathematical squaring.")
	fmt.Println("    - It CANNOT be sped up by multi-core processors or GPU clusters.")
	fmt.Println("    - Unlock time depends entirely on single-thread CPU clock speed.")
	fmt.Println()
	fmt.Println("[*] CALIBRATION GUIDE (MODERN HARDWARE):")
	fmt.Println("    - A fast CPU does ~50,000 to 80,000 operations per second.")
	fmt.Println("    - For a ~1 MINUTE delay: Use ~4,000,000 operations.")
	fmt.Println("    - For a ~1 HOUR delay:   Use ~250,000,000 operations.")
	fmt.Println("    - For a ~1 DAY delay:    Use ~6,000,000,000 operations.")
	fmt.Println()
	fmt.Println("    PRO TIP: Always run a small test (e.g., 500000) to benchmark your")
	fmt.Println("    specific hardware before sealing critical long-term files!")
	fmt.Println("======================================================================")

	fmt.Print("\nEnter path to the file to lock (e.g., leak.zip): ")
	filePath := readInput(reader)

	inFile, err := os.Open(filePath)
	if err != nil {
		fmt.Printf("[-] Failed to open target file: %v\n", err)
		return
	}
	defer inFile.Close()

	fmt.Print("\nEnter the number of sequential squaring operations.\n")
	fmt.Print("(Calibration: ~1,000,000 ops takes a few seconds on modern CPUs)\n")
	fmt.Print("Operations (e.g., 5000000): ")
	opsStr := readInput(reader)

	operations, err := strconv.ParseUint(opsStr, 10, 64)
	if err != nil || operations < 1 {
		fmt.Println("[-] Invalid operations count. Must be a positive integer.")
		return
	}

	outPath := filePath + ".timelock"
	outFile, err := os.Create(outPath)
	if err != nil {
		fmt.Printf("[-] Failed to create output file: %v\n", err)
		return
	}
	defer outFile.Close()

	fmt.Printf("\n[*] Generating RSA Subgroup Modulus and Zero-Knowledge Proof...\n")

	// We default to AES-256-GCM for the underlying stream cipher
	err = packet.SealTimeLockStream(inFile, outFile, operations, "AES-256-GCM")
	if err != nil {
		fmt.Printf("[-] Time-Lock Sealing failed: %v\n", err)
		return
	}

	fmt.Printf("\n[+] SUCCESS! Dead Man's Switch activated.\n")
	fmt.Printf("[+] Puzzle and ZKP mathematically bound to AES Key.\n")
	fmt.Printf("[+] Time-Locked file saved to: %s\n", outPath)
}

func handleTimeLockOpen(reader *bufio.Reader) {
	fmt.Println("\n=======================================================")
	fmt.Println("              SOLVE TIME-LOCK PUZZLE                   ")
	fmt.Println("=======================================================")

	fmt.Print("Enter path to the Time-Locked file (e.g., leak.zip.timelock): ")
	filePath := readInput(reader)

	inFile, err := os.Open(filePath)
	if err != nil {
		fmt.Printf("[-] Failed to open locked file: %v\n", err)
		return
	}
	defer inFile.Close()

	// 1. Manually parse the ASCII Armor Headers to extract the Meta payload
	fileReader := bufio.NewReader(inFile)
	header, _ := fileReader.ReadString('\n')
	if strings.TrimSpace(header) != "-----BEGIN PQPG TIMELOCK PUZZLE-----" {
		fmt.Println("[-] Invalid file: Missing PQPG Time-Lock header.")
		return
	}

	metaBase64, _ := fileReader.ReadString('\n')

	payloadHeader, _ := fileReader.ReadString('\n')
	if strings.TrimSpace(payloadHeader) != "-----BEGIN TIMELOCK PAYLOAD-----" {
		fmt.Println("[-] Invalid file: Missing Time-Lock payload boundary.")
		return
	}

	// 2. Prepare the output file
	outPath := strings.TrimSuffix(filePath, ".timelock")
	outFile, err := os.Create(outPath)
	if err != nil {
		fmt.Printf("[-] Failed to create output file: %v\n", err)
		return
	}
	defer outFile.Close()

	fmt.Printf("\n[*] Reading puzzle parameters...\n")

	// 3. Pass the remaining stream to the engine
	// Note: OpenTimeLockStream will handle ZKP verification, the solving loop,
	// and the AES decryption stream.
	err = packet.OpenTimeLockStream(fileReader, outFile, metaBase64)
	if err != nil {
		// Clean up the empty output file if solving failed or was interrupted
		os.Remove(outPath)
		fmt.Printf("\n[-] Solving Failed: %v\n", err)
		return
	}

	fmt.Printf("\n[+] DECRYPTION COMPLETE. Dead Man's Switch unlocked.\n")
	fmt.Printf("[+] File saved to: %s\n", outPath)
}
