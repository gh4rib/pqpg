package zkp

import (
	"bytes"
	"fmt"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

// ZKProofEnvelope is the portable artifact users will post online.
type ZKProofEnvelope struct {
	Curve         string `json:"curve"`
	Algorithm     string `json:"algorithm"`
	TreeDepth     int    `json:"tree_depth"`
	Proof         []byte `json:"proof"`
	PublicWitness []byte `json:"public_witness"`
	VerifyingKey  []byte `json:"verifying_key"`
}

// DataNotaryEngine holds the compiled constraints and Groth16 keys.
type DataNotaryEngine struct {
	Depth int
	CCS   constraint.ConstraintSystem
	PK    groth16.ProvingKey
	VK    groth16.VerifyingKey
}

// Setup compiles the Merkle circuit for a specific tree depth.
func Setup(depth int) (*DataNotaryEngine, error) {
	// Initialize empty arrays based on tree depth
	circuit := &MerkleInclusionCircuit{
		Depth:  depth,
		Path:   make([]frontend.Variable, depth),
		Helper: make([]frontend.Variable, depth),
	}

	// Compile the R1CS for BN254
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, circuit)
	if err != nil {
		return nil, fmt.Errorf("failed to compile Merkle circuit: %w", err)
	}

	// Run the Trusted Setup
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		return nil, fmt.Errorf("trusted setup failed: %w", err)
	}

	return &DataNotaryEngine{Depth: depth, CCS: ccs, PK: pk, VK: vk}, nil
}

// Prove generates the Groth16 proof using the secret Merkle path.
func (engine *DataNotaryEngine) Prove(leaf []byte, path [][]byte, helper []int, targetRoot string) (*ZKProofEnvelope, error) {
	if len(path) != engine.Depth || len(helper) != engine.Depth {
		return nil, fmt.Errorf("invalid path length: expected %d, got %d", engine.Depth, len(path))
	}

	// 1. Assign Witnesses
	assignment := &MerkleInclusionCircuit{
		SecretLeaf: leaf,
		Path:       make([]frontend.Variable, engine.Depth),
		Helper:     make([]frontend.Variable, engine.Depth),
		TargetRoot: targetRoot,
	}

	for i := 0; i < engine.Depth; i++ {
		assignment.Path[i] = path[i]
		assignment.Helper[i] = helper[i]
	}

	// 2. Build Prover Witness
	fullWitness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		return nil, err
	}

	// 3. Build Verifier Witness
	publicWitness, err := fullWitness.Public()
	if err != nil {
		return nil, err
	}

	// 4. Generate Groth16 Proof
	proof, err := groth16.Prove(engine.CCS, engine.PK, fullWitness)
	if err != nil {
		return nil, fmt.Errorf("proof generation failed (invalid Merkle path): %w", err)
	}

	// 5. Serialize Proof to bytes
	var proofBuf bytes.Buffer
	proof.WriteTo(&proofBuf)

	// 6. Serialize Public Witness to bytes
	var pubBuf bytes.Buffer
	publicWitness.WriteTo(&pubBuf)

	// 7. Serialize Verifying Key to bytes
	var vkBuf bytes.Buffer
	engine.VK.WriteTo(&vkBuf)

	return &ZKProofEnvelope{
		Curve:         "BN254",
		Algorithm:     "Groth16-Merkle-MiMC",
		TreeDepth:     engine.Depth,
		Proof:         proofBuf.Bytes(),
		PublicWitness: pubBuf.Bytes(),
		VerifyingKey:  vkBuf.Bytes(),
	}, nil
}

// Verify instantly checks the ZKP against the public footprint.
func (engine *DataNotaryEngine) Verify(envelope *ZKProofEnvelope) bool {
	// 1. Unpack the Proof
	proof := groth16.NewProof(ecc.BN254)
	if _, err := proof.ReadFrom(bytes.NewReader(envelope.Proof)); err != nil {
		return false
	}

	// 2. Unpack the Public Witness
	publicWitness, err := witness.New(ecc.BN254.ScalarField())
	if err != nil {
		return false
	}
	if _, err := publicWitness.ReadFrom(bytes.NewReader(envelope.PublicWitness)); err != nil {
		return false
	}

	// 3. Unpack the Verifying Key dynamically from the envelope
	vk := groth16.NewVerifyingKey(ecc.BN254)
	if _, err := vk.ReadFrom(bytes.NewReader(envelope.VerifyingKey)); err != nil {
		return false
	}

	// 4. Execute the verification math
	err = groth16.Verify(proof, vk, publicWitness)
	return err == nil
}
