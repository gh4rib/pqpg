package zkp

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/mimc"
)

// MerkleInclusionCircuit proves that a secret data block exists inside a massive dataset
// without revealing the data block or its position.
type MerkleInclusionCircuit struct {
	// The depth of the tree (e.g., 20 levels can represent ~1 million chunks)
	Depth int

	// Secret Witnesses (The user knows these, but they are NOT in the final .zkp file)
	SecretLeaf frontend.Variable   // The raw chunk of the breached file
	Path       []frontend.Variable // The sibling hashes required to reach the root
	Helper     []frontend.Variable // Binary selectors (0 or 1) indicating left/right positioning

	// Public Witness (The footprint the world knows)
	TargetRoot frontend.Variable `gnark:",public"`
}

// Define wires the constraint system for the gnark compiler.
func (c *MerkleInclusionCircuit) Define(api frontend.API) error {
	// 1. Initialize the SNARK-friendly MiMC Hash function
	h, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}

	// 2. Start from the secret leaf
	currentHash := c.SecretLeaf

	// 3. Traverse up the tree to the root
	for i := 0; i < len(c.Path); i++ {
		h.Reset()

		// THE CONDITIONAL SWAP (SNARK equivalent of If/Else)
		// If Helper == 1: the sibling is on the Left  (Path || Current)
		// If Helper == 0: the sibling is on the Right (Current || Path)
		leftNode := api.Select(c.Helper[i], c.Path[i], currentHash)
		rightNode := api.Select(c.Helper[i], currentHash, c.Path[i])

		// Hash the two nodes together
		h.Write(leftNode, rightNode)
		
		// Move up one level
		currentHash = h.Sum()
	}

	// 4. The Absolute Constraint: 
	// The final computed root MUST equal the public TargetRoot.
	api.AssertIsEqual(currentHash, c.TargetRoot)

	return nil
}