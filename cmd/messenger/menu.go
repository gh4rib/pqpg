package main

import (
	"bufio"
	"fmt"

	openpgp_pqc "github.com/gh4rib/pqpg/internal/openpgp-pqc"
)

func showCoreMenu(reader *bufio.Reader) {
	for {
		fmt.Println("===========================================================================")
		fmt.Println("             PQPG: POST-QUANTUM PRIVACY GUARD ENGINE (Native)              ")
		fmt.Println("===========================================================================")
		fmt.Println(" --- IDENTITY & KEY MANAGEMENT ---")
		fmt.Println("  1) Generate New Identity (Standard PKI Setup)")
		fmt.Println("  2) View Local Keyrings")
		fmt.Println("\n --- NETWORK TRANSFERS (SEALED SENDER) ---")
		fmt.Println("  3) Encrypt & Sign a File (Send)")
		fmt.Println("  4) Decrypt & Verify a File (Receive)")
		fmt.Println("\n --- LOCAL VAULT STORAGE ---")
		fmt.Println("  5) Lock File into Personal Vault")
		fmt.Println("  6) Unlock Personal Vault")
		fmt.Println("\n --- DISTRIBUTED THRESHOLD STORAGE ---")
		fmt.Println("  7) Lock M-of-N Shared Vault (Feldman VSS)")
		fmt.Println("  8) Unlock M-of-N Shared Vault")
		fmt.Println("\n --- CLEAR-TEXT SIGNATURES ---")
		fmt.Println(" 9) Sign Massive File (Detached)")
		fmt.Println(" 10) Verify Massive File (Detached)")
		fmt.Println("\n --- NETWORK EVASION (STEGANOGRAPHY) ---")
		fmt.Println(" 11) Inject Envelope into Image or Audio Carrier")
		fmt.Println(" 12) Extract Envelope from Image or Audio Carrier")
		fmt.Println("\n --- STATELESS TRANSFERS (SIMPLE SEND FALLBACK) ---")
		fmt.Println(" 13) Encrypt & Sign a File (Stateless Send)")
		fmt.Println(" 14) Decrypt & Verify a File (Stateless Receive)")
		fmt.Println("\n --- CONTACTS & SESSIONS ---")
		fmt.Println(" 15) Import Contact to Address Book")
		fmt.Println(" 16) Reset Secure Session (Panic Button)")
		fmt.Println("\n --- STATEFUL SIGNATURES (RELEASE ENGINEER) ---")
		fmt.Println(" 17) Sign Release Artifact (Stateful LMS/XMSS)")
		fmt.Println(" 18) Verify Release Artifact (Stateful LMS/XMSS)")
		fmt.Println("\n --- Verifiable Delay Function (RSA - Not PQ Safe!) ---")
		fmt.Println(" 19) Seal a File in a Time-Lock Puzzle (Dead Man's Switch)")
		fmt.Println(" 20) Verify & Solve a Time-Lock Puzzle")
		fmt.Println("\n --- Zero-Knowledge Proof of Breach (Data Notary) ---")
		fmt.Println(" 21) Generate a Zero-Knowledge Proof of Data (Data Notary)")
		fmt.Println(" 22) Verify a Zero-Knowledge Proof of Data")
		fmt.Println("\n --- SYSTEM ---")
		fmt.Println(" 99) Exit")
		fmt.Println("===========================================================================")
		fmt.Print("Select an option: ")

		option := readInput(reader)

		switch option {
		case "1":
			handleGenerateIdentity(reader)
		case "2":
			handleViewKeyrings()
		case "3":
			handleSend(reader)
		case "4":
			handleReceive(reader)
		case "5":
			handleVaultLock(reader)
		case "6":
			handleVaultUnlock(reader)
		case "7":
			handleSharedVaultLock(reader)
		case "8":
			handleSharedVaultUnlock(reader)
		case "9":
			handleDetachedSign(reader)
		case "10":
			handleDetachedVerify(reader)
		case "11":
			handleStegoInject(reader)
		case "12":
			handleStegoExtract(reader)
		case "13":
			handleStatelessSend(reader)
		case "14":
			handleStatelessReceive(reader)
		case "15":
			handleImportContact(reader)
		case "16":
			handleResetSession(reader)
		case "17":
			handleStatefulDetachedSign(reader)
		case "18":
			handleStatefulDetachedVerify(reader)
		case "19":
			handleTimeLockSeal(reader)
		case "20":
			handleTimeLockOpen(reader)
		case "21":
			handleDataNotaryProve(reader)
		case "22":
			handleDataNotaryVerify(reader)
		case "99":
			fmt.Println("[*] Returning to the engine chooser menu.")
			return
		default:
			fmt.Println("[-] Invalid option. Please select a valid number from the menu.")
		}
	}
}

func showOQSMenu(reader *bufio.Reader) {
	for {
		fmt.Println("==================================================================================================")
		fmt.Println("             PQPG: POST-QUANTUM PRIVACY GUARD ENGINE (liboqs main branch - 0.15.0)                ")
		fmt.Println("==================================================================================================")
		fmt.Println(" --- SYSTEM DIAGNOSIS ---")
		fmt.Println(" 1) Diagnostics: Verify liboqs C-FFI Engine & Algorithms")
		fmt.Println("\n --- SYSTEM ---")
		fmt.Println(" 99) Exit")
		fmt.Println("==================================================================================================")
		fmt.Print("Select an option: ")

		option := readInput(reader)

		switch option {
		case "1":
			handleOQSDiagnostics()
		case "99":
			fmt.Println("[*] Returning to the engine chooser menu.")
			return
		default:
			fmt.Println("[-] Invalid option. Please select a valid number from the menu.")
		}
	}
}

func showOpenPGPMenu(reader *bufio.Reader) {
	engine := openpgp_pqc.NewEngine()

	for {
		fmt.Println("\n===========================================================================")
		fmt.Println("         OPENPGP COMPATIBILITY ENGINE (draft-ietf-openpgp-pqc)             ")
		fmt.Println("===========================================================================")
		fmt.Println(" --- IDENTITY MANAGEMENT ---")
		fmt.Println("  1) Generate OpenPGP Key (Standard: Kyber768+x25519 + ML-DSA-56+ed25519)")
		fmt.Println("  2) Generate OpenPGP Key (High Security: Kyber1024+x448 + ML-DSA-87+ed448)")
		fmt.Println("\n --- ASYNCHRONOUS MESSAGING ---")
		fmt.Println("  3) Encrypt & Sign File")
		fmt.Println("  4) Decrypt & Verify File")
		fmt.Println("\n --- SPECIALIZED SIGNATURES ---")
		fmt.Println("  5) Create Cleartext Signed Message")
		fmt.Println("  6) Verify Cleartext Signed Message")
		fmt.Println("  7) Create Detached Signature (.sig)")
		fmt.Println("  8) Verify Detached Signature")
		fmt.Println("\n 99) Return to Main Engine Selection")
		fmt.Println("===========================================================================")
		fmt.Print("Select an option: ")

		choice := readInput(reader)

		switch choice {
		case "1":
			handlePGPGenerateKey(reader, engine, false)
		case "2":
			handlePGPGenerateKey(reader, engine, true)
		case "3":
			handlePGPEncryptSign(reader, engine)
		case "4":
			handlePGPDecryptVerify(reader, engine)
		case "5":
			handlePGPCleartextSign(reader, engine)
		case "6":
			handlePGPCleartextVerify(reader, engine)
		case "7":
			handlePGPDetachedSign(reader, engine)
		case "8":
			handlePGPDetachedVerify(reader, engine)
		case "99":
			return
		default:
			fmt.Println("[-] Invalid selection.")
		}
	}
}
