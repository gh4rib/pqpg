package main

import (
	"fmt"
	"strings"

	"github.com/gh4rib/pqpg/internal/oqs"
)

func handleOQSDiagnostics() {
	fmt.Println("\n=======================================================")
	fmt.Println("             liboqs C-FFI ENGINE DIAGNOSTICS           ")
	fmt.Println("=======================================================")

	// 1. Verify C-FFI Bridge & Version
	// This reaches directly into the statically linked C archive.
	// If it returns a string without crashing, your static build is perfect.
	version := oqs.LiboqsVersion()
	fmt.Printf("[+] C-FFI Bridge Active. liboqs Version: %s\n", version)

	// 2. Fetch Signature Algorithms
	sigs := oqs.EnabledSigs()
	fmt.Printf("\n[*] Enabled Signature Algorithms (%d Total):\n", len(sigs))
	for _, sig := range sigs {
		// Visually highlight the stateful algorithms we specifically compiled via CMake
		if strings.HasPrefix(sig, "LMS") || strings.HasPrefix(sig, "XMSS") {
			fmt.Printf("    - %s  [STATEFUL - READY]\n", sig)
		} else {
			fmt.Printf("    - %s\n", sig)
		}
	}

	// 3. Fetch KEM Algorithms
	kems := oqs.EnabledKEMs()
	fmt.Printf("\n[*] Enabled Key Encapsulation Mechanisms (%d Total):\n", len(kems))
	for _, kem := range kems {
		fmt.Printf("    - %s\n", kem)
	}

	fmt.Println("\n=======================================================")
	fmt.Println("[+] Diagnostics Complete. Ready for Post-Quantum Operations.")
}
