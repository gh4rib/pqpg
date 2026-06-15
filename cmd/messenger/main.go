package main

import (
	"bufio"
	"fmt"
	"os"
	"runtime"
)

func main() {
	reader := bufio.NewReader(os.Stdin)

	for {
		fmt.Println("=====================================================================")
		fmt.Println("             PQPG: POST-QUANTUM PRIVACY GUARD ENGINE                 ")
		fmt.Println("       !! WARNING: The engines operations are NOT COMPATIBLE  !!      ")
		fmt.Println("=====================================================================")
		fmt.Println(" 1) CIRCL/HPQC Crypto Engine           [Multi-Platform]")
		fmt.Println(" 2) Open-Quantum Safe Crypto Engine    [Linux Only]")
		fmt.Println(" 3) Proton OpenPGP Crypto Engine       [Multi-Platform / Interoperable]")
		fmt.Println(" 4) Cryptographic Encyclopedia (Algorithm Standards & Origins)")
		fmt.Println("\n 99) Exit")
		fmt.Println("=====================================================================")
		fmt.Print("Select an engine: ")

		choice := readInput(reader)

		switch choice {
		case "1":
			showCoreMenu(reader)
		case "2":
			// PLATFORM GATE: Enforce Linux-only access for the static CGO engine
			if runtime.GOOS != "linux" && runtime.GOARCH != "amd64" {
				fmt.Printf("\n[-] ACCESS DENIED: The OQS extension requires a statically linked\n")
				fmt.Printf("    liboqs.a compile target. Your current OS (%s) is not supported.\n\n", runtime.GOOS)
				break
			}
			showOQSMenu(reader)
		case "3":
			// >>> THE NEW ISOLATED OPENPGP <<<
			showOpenPGPMenu(reader)
		case "4":
			showEncyclopedia(reader)
		case "99":
			fmt.Println("[*] Exiting PQPG. Stay secure.")
			return
		default:
			fmt.Println("[-] Invalid selection. Please choose a valid engine.")
		}
	}
}
