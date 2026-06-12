package main

import (
	"bufio"
	"fmt"
	_ "io"
	"os"
	"path/filepath"
	"strings"

	"github.com/gh4rib/pqpg/internal/openpgp-pqc"
)

func handlePGPGenerateKey(reader *bufio.Reader, engine *openpgp_pqc.OpenPGPEngine, highSecurity bool) {
	fmt.Print("\nEnter Your Name: ")
	name := readInput(reader)
	fmt.Print("Enter Your Email: ")
	email := readInput(reader)
	fmt.Print("Enter a Passphrase to protect your Private Key: ")
	pass := readInput(reader)

	fmt.Println("\n[*] Generating Composite Post-Quantum OpenPGP Key block...")
	pub, priv, err := engine.GenerateKey(name, email, pass, highSecurity)
	if err != nil {
		fmt.Printf("[-] Key generation failed: %v\n", err)
		return
	}

	// Sanitize the name for the filesystem (replace spaces with underscores)
	safeName := strings.ReplaceAll(strings.TrimSpace(name), " ", "_")
	dirName := fmt.Sprintf("%s_openpgp_keys", safeName)

	err = os.MkdirAll(dirName, 0700)
	if err != nil {
		fmt.Printf("[-] Failed to create directory: %v\n", err)
		return
	}

	pubPath := filepath.Join(dirName, "public_key.asc")
	privPath := filepath.Join(dirName, "private_key.asc")

	os.WriteFile(pubPath, []byte(pub), 0644)
	os.WriteFile(privPath, []byte(priv), 0600)

	fmt.Printf("[+] Success! Keys saved to:\n  - %s\n  - %s\n", pubPath, privPath)
}

func handlePGPEncryptSign(reader *bufio.Reader, engine *openpgp_pqc.OpenPGPEngine) {
	fmt.Print("\nEnter path to Recipient's Public Key (.asc): ")
	pubPath := readInput(reader)
	recipientPub, _ := os.ReadFile(pubPath)

	fmt.Print("Enter path to YOUR Private Key (.asc): ")
	privPath := readInput(reader)
	myPriv, _ := os.ReadFile(privPath)

	fmt.Print("Enter Passphrase for your Private Key: ")
	myPass := readInput(reader)

	fmt.Print("Enter path to the File to Encrypt: ")
	filePath := readInput(reader)

	inFile, err := os.Open(filePath)
	if err != nil {
		fmt.Printf("[-] Cannot open file: %v\n", err)
		return
	}
	defer inFile.Close()

	outPath := filePath + ".pgp"
	outFile, err := os.Create(outPath)
	if err != nil {
		fmt.Printf("[-] Cannot create output file: %v\n", err)
		return
	}
	defer outFile.Close()

	fmt.Println("[*] Encrypting and Signing Stream...")
	err = engine.EncryptAndSignStream(inFile, outFile, string(recipientPub), string(myPriv), myPass)
	if err != nil {
		fmt.Printf("[-] Failed: %v\n", err)
		return
	}
	fmt.Printf("[+] Success! Encrypted file saved to: %s\n", outPath)
}

func handlePGPDecryptVerify(reader *bufio.Reader, engine *openpgp_pqc.OpenPGPEngine) {
	fmt.Print("\nEnter path to YOUR Private Key (.asc): ")
	privPath := readInput(reader)
	myPriv, _ := os.ReadFile(privPath)

	fmt.Print("Enter Passphrase for your Private Key: ")
	myPass := readInput(reader)

	fmt.Print("Enter path to Sender's Public Key (.asc): ")
	pubPath := readInput(reader)
	senderPub, _ := os.ReadFile(pubPath)

	fmt.Print("Enter path to the Encrypted File (.pgp): ")
	filePath := readInput(reader)

	inFile, err := os.Open(filePath)
	if err != nil {
		fmt.Printf("[-] Cannot open file: %v\n", err)
		return
	}
	defer inFile.Close()

	outPath := "decrypted_" + filepath.Base(filePath)
	outPath = strings.TrimSuffix(outPath, ".pgp")
	outFile, err := os.Create(outPath)
	if err != nil {
		fmt.Printf("[-] Cannot create output file: %v\n", err)
		return
	}
	defer outFile.Close()

	fmt.Println("[*] Decrypting and Verifying Signature...")
	err = engine.DecryptAndVerifyStream(inFile, outFile, string(myPriv), myPass, string(senderPub))
	if err != nil {
		os.Remove(outPath) // Rollback
		fmt.Printf("[-] Failed: %v\n", err)
		return
	}
	fmt.Printf("[+] Success! Verified and saved to: %s\n", outPath)
}

func handlePGPCleartextSign(reader *bufio.Reader, engine *openpgp_pqc.OpenPGPEngine) {
	fmt.Print("\nEnter path to YOUR Private Key (.asc): ")
	privPath := readInput(reader)
	myPriv, _ := os.ReadFile(privPath)

	fmt.Print("Enter Passphrase for your Private Key: ")
	myPass := readInput(reader)

	fmt.Print("Enter message to sign: ")
	msg := readInput(reader)

	fmt.Println("[*] Generating Cleartext Signature...")
	armored, err := engine.SignCleartext([]byte(msg), string(myPriv), myPass)
	if err != nil {
		fmt.Printf("[-] Failed: %v\n", err)
		return
	}
	fmt.Printf("\n%s\n", armored)
}

func handlePGPCleartextVerify(reader *bufio.Reader, engine *openpgp_pqc.OpenPGPEngine) {
	fmt.Print("\nEnter path to Sender's Public Key (.asc): ")
	pubPath := readInput(reader)
	senderPub, _ := os.ReadFile(pubPath)

	fmt.Println("Paste the Cleartext Signed Message (End with an empty line or CTRL+D):")
	var msg string
	for {
		line := readInput(reader)
		if line == "" {
			break
		}
		msg += line + "\n"
	}

	fmt.Println("[*] Verifying Cleartext Signature...")
	err := engine.VerifyCleartext(msg, string(senderPub))
	if err != nil {
		fmt.Printf("[-] Failed: %v\n", err)
		return
	}
	fmt.Println("[+] Signature is mathematically VALID.")
}

func handlePGPDetachedSign(reader *bufio.Reader, engine *openpgp_pqc.OpenPGPEngine) {
	fmt.Print("\nEnter path to YOUR Private Key (.asc): ")
	privPath := readInput(reader)
	myPriv, _ := os.ReadFile(privPath)

	fmt.Print("Enter Passphrase for your Private Key: ")
	myPass := readInput(reader)

	fmt.Print("Enter path to the File to Sign: ")
	filePath := readInput(reader)
	msg, _ := os.ReadFile(filePath)

	fmt.Println("[*] Generating Detached Signature...")
	sig, err := engine.SignDetached(msg, string(myPriv), myPass)
	if err != nil {
		fmt.Printf("[-] Failed: %v\n", err)
		return
	}

	outPath := filePath + ".sig"
	os.WriteFile(outPath, sig, 0644)
	fmt.Printf("[+] Success! Detached signature saved to: %s\n", outPath)
}

func handlePGPDetachedVerify(reader *bufio.Reader, engine *openpgp_pqc.OpenPGPEngine) {
	fmt.Print("\nEnter path to Sender's Public Key (.asc): ")
	pubPath := readInput(reader)
	senderPub, _ := os.ReadFile(pubPath)

	fmt.Print("Enter path to the original File: ")
	filePath := readInput(reader)
	msg, _ := os.ReadFile(filePath)

	fmt.Print("Enter path to the Detached Signature (.sig): ")
	sigPath := readInput(reader)
	sig, _ := os.ReadFile(sigPath)

	fmt.Println("[*] Verifying Detached Signature...")
	err := engine.VerifyDetached(msg, sig, string(senderPub))
	if err != nil {
		fmt.Printf("[-] Failed: %v\n", err)
		return
	}
	fmt.Println("[+] Signature is mathematically VALID.")
}
