package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/gh4rib/pqpg/internal/packet"
)

func handleStegoInject(reader *bufio.Reader) {
	fmt.Print("\nEnter path to the Encrypted Payload (e.g., outbox_msg.asc or .pq_vault): ")
	payloadPath := readInput(reader)

	payloadFile, err := os.Open(payloadPath)
	if err != nil {
		fmt.Printf("[-] Failed to open payload: %v\n", err)
		return
	}
	defer payloadFile.Close()

	fmt.Print("Enter path to Carrier File (Images: .png, .jpg | Audio: .wav, .aiff): ")
	carrierPath := readInput(reader)

	ext := strings.ToLower(filepath.Ext(carrierPath))
	isAudio := ext == ".wav" || ext == ".aiff" || ext == ".aif"

	var outExt, formatStr string

	if isAudio {
		fmt.Println("\nSelect Lossless Output Format for Audio:")
		fmt.Println(" 1) WAV  (Universal PCM standard)")
		fmt.Println(" 2) AIFF (Apple uncompressed standard)")
		fmt.Print("Choice [1-2]: ")
		formatChoice := readInput(reader)

		if formatChoice == "2" {
			outExt, formatStr = "_stego.aiff", "aiff"
		} else {
			outExt, formatStr = "_stego.wav", "wav"
		}

		outFilename := strings.TrimSuffix(filepath.Base(carrierPath), ext) + outExt
		fmt.Println("[*] Executing Deep Packet Evasion via Acoustic LSB Injection...")

		err = packet.EmbedInAudio(payloadFile, carrierPath, outFilename, formatStr)
		if err != nil {
			fmt.Printf("[-] Acoustic Steganography failed: %v\n", err)
			return
		}

		fmt.Printf("\n[+] SUCCESS! Payload mathematically woven into audio frequencies.\n")
		fmt.Printf("[+] Safely transmit '%s' across monitored networks.\n", outFilename)
		return
	}

	fmt.Println("\nSelect Lossless Output Format for Image:")
	fmt.Println(" 1) PNG (Standard web footprint, compressed size, slower generation)")
	fmt.Println(" 2) BMP (Standard forensic footprint, massive size, instant generation)")
	fmt.Print("Choice [1-2]: ")
	formatChoice := readInput(reader)

	if formatChoice == "2" {
		outExt, formatStr = "_stego.bmp", "bmp"
	} else {
		outExt, formatStr = "_stego.png", "png"
	}

	outFilename := strings.TrimSuffix(filepath.Base(carrierPath), ext) + outExt
	fmt.Println("[*] Executing Deep Packet Evasion via Visual LSB Injection...")
	err = packet.EmbedInImage(payloadFile, carrierPath, outFilename, formatStr)
	if err != nil {
		fmt.Printf("[-] Visual Steganography failed: %v\n", err)
		return
	}

	fmt.Printf("\n[+] SUCCESS! Payload mathematically woven into image pixels.\n")
	fmt.Printf("[+] Safely transmit '%s' across monitored networks.\n", outFilename)
}

func handleStegoExtract(reader *bufio.Reader) {
	fmt.Print("\nEnter path to the Steganographic Carrier (e.g., target_stego.png or track_stego.wav): ")
	carrierPath := readInput(reader)

	outFilename := "extracted_payload.asc"
	outFile, err := os.Create(outFilename)
	if err != nil {
		fmt.Printf("[-] Failed to allocate extraction file: %v\n", err)
		return
	}
	defer outFile.Close()

	ext := strings.ToLower(filepath.Ext(carrierPath))
	isAudio := ext == ".wav" || ext == ".aiff" || ext == ".aif"

	if isAudio {
		fmt.Println("[*] Scanning Acoustic LSB architecture for hidden data streams...")
		err = packet.ExtractFromAudio(carrierPath, outFile)
	} else {
		fmt.Println("[*] Scanning Visual LSB architecture for hidden data streams...")
		err = packet.ExtractFromImage(carrierPath, outFile)
	}

	if err != nil {
		os.Remove(outFilename)
		fmt.Printf("[-] CRITICAL: Extraction failed. Reason: %v\n", err)
		return
	}

	fmt.Printf("\n[+] PAYLOAD EXTRACTED! Hidden data cleanly separated from carrier.\n")
	fmt.Printf("[+] Payload saved to: %s. You may now decrypt it.\n", outFilename)
}
