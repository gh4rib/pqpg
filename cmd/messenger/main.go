package main

import (
	"bufio"
	"fmt"
	"os"
)

func main() {
	reader := bufio.NewReader(os.Stdin)

	for {
		fmt.Println("=====================================================================")
		fmt.Println("             PQPG: POST-QUANTUM PRIVACY GUARD ENGINE                 ")
		fmt.Println("=====================================================================")
		fmt.Println(" --- IDENTITY & KEY MANAGEMENT ---")
		fmt.Println("  1) Generate New Identity (PKI Setup)")
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
		fmt.Println("  9) Sign Massive File (Detached)")
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
		fmt.Println("\n --- SYSTEM ---")
		fmt.Println(" 99) Exit")
		fmt.Println("=====================================================================")
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
		case "99":
			fmt.Println("[*] Exiting PQPG. Stay secure.")
			return
		default:
			fmt.Println("[-] Invalid option. Please select a valid number from the menu.")
		}
	}
}
