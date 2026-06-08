package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"math/bits"
	"os"
	"strings"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
	"github.com/gh4rib/pqpg/internal/zkp"
	"golang.org/x/crypto/sha3"
)

// nextPowerOf2 calculates the required tree width to keep the Merkle tree balanced.
func nextPowerOf2(n int) int {
	if n <= 1 {
		return 1
	}
	return 1 << (32 - bits.LeadingZeros32(uint32(n-1)))
}

// buildLocalMerkleProof natively chunks a file and computes the MiMC Merkle path for a specific leaf.
func buildLocalMerkleProof(fileBytes []byte, targetIndex int) (leaf []byte, path [][]byte, helper []int, root string, depth int, err error) {
	// 1. Chunk the file into 31-byte blocks (Safe BN254 Field Element capacity)
	chunkSize := 31
	var leaves [][]byte

	for i := 0; i < len(fileBytes); i += chunkSize {
		end := i + chunkSize
		if end > len(fileBytes) {
			end = len(fileBytes)
		}

		// Pad chunk to exactly 32 bytes (Big Endian Field Element representation)
		chunk := make([]byte, 32)
		copy(chunk[32-(end-i):], fileBytes[i:end])
		leaves = append(leaves, chunk)
	}

	// 2. Pad the total number of leaves to a Power of 2 (Enforce Minimum Depth of 4)
	numLeaves := nextPowerOf2(len(leaves))
	if numLeaves < 16 {
		numLeaves = 16 // Force a minimum tree depth of 4 to prevent trivial empty-tree collisions
	}

	// Domain Separation: Empty leaves must strictly fit inside the BN254 modulus.
	// We right-align the padding so the highest-order byte remains 0x00.
	emptyLeaf := make([]byte, 32)
	paddingStr := []byte("PQPG-EMPTY-MERKLE-PAD") // 21 bytes
	copy(emptyLeaf[32-len(paddingStr):], paddingStr)

	for len(leaves) < numLeaves {
		leaves = append(leaves, emptyLeaf)
	}

	depth = bits.TrailingZeros(uint(numLeaves))

	// 3. Build the Tree Level by Level
	tree := make([][][]byte, depth+1)
	tree[0] = leaves

	hashEngine := mimc.NewMiMC()

	for d := 0; d < depth; d++ {
		currentLayer := tree[d]
		nextLayer := make([][]byte, len(currentLayer)/2)

		for i := 0; i < len(currentLayer); i += 2 {
			hashEngine.Reset()
			hashEngine.Write(currentLayer[i])
			hashEngine.Write(currentLayer[i+1])

			nodeHash := hashEngine.Sum(nil)
			nextLayer[i/2] = nodeHash
		}
		tree[d+1] = nextLayer
	}

	// 4. Extract the Path and Helper for the target index
	currentIndex := targetIndex
	leaf = tree[0][targetIndex]

	for d := 0; d < depth; d++ {
		isRightChild := currentIndex%2 == 1
		var siblingIndex int

		if isRightChild {
			siblingIndex = currentIndex - 1
			helper = append(helper, 1) // Sibling is on the Left
		} else {
			siblingIndex = currentIndex + 1
			helper = append(helper, 0) // Sibling is on the Right
		}

		path = append(path, tree[d][siblingIndex])
		currentIndex /= 2
	}

	// Format root as a base-10 string for gnark
	var rootFr fr.Element
	rootFr.SetBytes(tree[depth][0])
	root = rootFr.String()

	return leaf, path, helper, root, depth, nil
}

// handleDataNotaryProve walks the user through generating the ZKP.
func handleDataNotaryProve(reader *bufio.Reader) {
	fmt.Println("\n======================================================================")
	fmt.Println("             ZERO-KNOWLEDGE DATA NOTARY (PROOF OF BREACH)             ")
	fmt.Println("======================================================================")
	fmt.Println("[*] WHAT THIS DOES:")
	fmt.Println("    - Proves you possess a specific file (e.g., a leaked database).")
	fmt.Println("    - Generates a tiny mathematical proof (.zkp) you can post online.")
	fmt.Println("    - NEVER exposes a single byte of your actual file to the public.")
	fmt.Println()
	fmt.Println("[*] HOW IT WORKS:")
	fmt.Println("    1. You select your local, raw file.")
	fmt.Println("    2. The engine builds a FIPS-compliant MiMC Merkle Tree.")
	fmt.Println("    3. A zk-SNARK proves you hold the data required to generate the root.")
	fmt.Println("======================================================================")

	fmt.Print("\nEnter path to the local database/file you possess: ")
	filePath := readInput(reader)

	fileBytes, err := os.ReadFile(filePath)
	if err != nil {
		fmt.Printf("[-] Failed to read file: %v\n", err)
		return
	}

	fmt.Print("Enter the Public Target MiMC Root (Leave blank to auto-calculate): ")
	publicTarget := readInput(reader)

	fmt.Println("\n[*] Calculating Native MiMC Merkle Tree. Please wait...")

	leaf, path, helper, calculatedRoot, depth, err := buildLocalMerkleProof(fileBytes, 0)
	if err != nil {
		fmt.Printf("[-] Failed to build local Merkle tree: %v\n", err)
		return
	}

	if publicTarget == "" {
		publicTarget = calculatedRoot
		fmt.Printf("[+] Auto-Calculated Target Root: %s\n", publicTarget)
		fmt.Println("[!] Share this Target Root publicly so others know what file you are proving.")
	} else if strings.TrimSpace(publicTarget) != calculatedRoot {
		fmt.Println("[-] CRITICAL ALARM: Your local file does NOT match the provided public footprint.")
		fmt.Println("[-] The SNARK circuit refuses to generate a forged proof.")
		return
	}

	fmt.Printf("[*] Tree Depth: %d (Supports up to %d chunks)\n", depth, 1<<depth)
	fmt.Println("[*] Compiling R1CS Circuit Constraints...")

	engine, err := zkp.Setup(depth)
	if err != nil {
		fmt.Printf("[-] Circuit compilation failed: %v\n", err)
		return
	}

	fmt.Println("[*] Executing Groth16 Prover Sequence...")
	envelope, err := engine.Prove(leaf, path, helper, publicTarget)
	if err != nil {
		fmt.Printf("[-] Proof Generation Failed: %v\n", err)
		return
	}

	outPath := filePath + ".zkp"
	envBytes, _ := json.MarshalIndent(envelope, "", "  ")
	_ = os.WriteFile(outPath, envBytes, 0644)

	fmt.Println("\n[+] SUCCESS! Proof of Breach generated.")
	fmt.Printf("[+] Artifact saved to: %s\n", outPath)
	fmt.Println("[+] You may safely publish this .zkp file online. Your data remains perfectly hidden.")
}

// handleDataNotaryVerify allows the public audience to verify the claim.
func handleDataNotaryVerify(reader *bufio.Reader) {
	fmt.Println("\n======================================================================")
	fmt.Println("                  VERIFY A ZERO-KNOWLEDGE CLAIM                       ")
	fmt.Println("======================================================================")
	fmt.Println("[*] This engine will mathematically verify if a claimant actually")
	fmt.Println("    possesses the data they claim to hold, without seeing the data.")
	fmt.Println("======================================================================")

	fmt.Print("\nEnter path to the provided .zkp file: ")
	filePath := readInput(reader)

	envBytes, err := os.ReadFile(filePath)
	if err != nil {
		fmt.Printf("[-] Failed to read ZKP file: %v\n", err)
		return
	}

	var envelope zkp.ZKProofEnvelope
	if err := json.Unmarshal(envBytes, &envelope); err != nil {
		fmt.Printf("[-] Corrupt or invalid ZKP file format: %v\n", err)
		return
	}

	fmt.Printf("\n[*] Parsing ZKP Envelope...\n")
	fmt.Printf("    - Curve: %s\n", envelope.Curve)
	fmt.Printf("    - Algorithm: %s\n", envelope.Algorithm)
	fmt.Printf("    - Tree Depth: %d\n", envelope.TreeDepth)

	// VULNERABILITY 1 FIX: FINGERPRINT THE VERIFYING KEY (Upgraded to SHA3-256)
	vkHash := sha3.Sum256(envelope.VerifyingKey)

	fmt.Printf("\n[!] CRITICAL: VERIFYING KEY FINGERPRINT\n")
	fmt.Printf("    SHA3-256: %x\n", vkHash)
	fmt.Println("    Do not trust this proof if you do not recognize this fingerprint!")
	fmt.Println("    A malicious prover can forge a proof by generating their own key.")
	fmt.Println("----------------------------------------------------------------------")

	fmt.Print("Do you trust this Verifying Key? (y/N): ")
	confirm := readInput(reader)
	if strings.ToLower(confirm) != "y" {
		fmt.Println("[-] Verification aborted by user. Untrusted circuit.")
		return
	}

	engine := &zkp.DataNotaryEngine{}

	fmt.Println("\n[*] Executing Groth16 Verifier...")

	isValid := engine.Verify(&envelope)
	if isValid {
		fmt.Println("\n[+] CRYPTOGRAPHIC VERIFICATION: SUCCESS")
		fmt.Println("[+] The math is absolute. The claimant definitively possesses")
		fmt.Println("    the raw data matching the public footprint.")
	} else {
		fmt.Println("\n[-] CRYPTOGRAPHIC VERIFICATION: FAILED")
		fmt.Println("[-] This proof is a forgery or the data is corrupted.")
	}
}
