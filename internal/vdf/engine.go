package vdf

import "errors"

// Puzzle represents the mathematical state of a Delay Function.
// It contains the public parameters and the serialized Zero-Knowledge Proof.
type Puzzle struct {
	ModulusN  []byte `json:"modulus_n"` // The Hidden Order Group (N)
	Generator []byte `json:"generator"` // Base (g)
	TargetH   []byte `json:"target_h"`  // Solved State (h)
	TimeT     uint64 `json:"time_t"`    // Sequential Operations
	ZkProof   []byte `json:"zk_proof"`  // Serialized ZKP (e.g., qndleq or gnark)
}

// Engine defines the strict contract for any Time-Lock puzzle implementation.
type Engine interface {
	// Generate creates the puzzle and an instant Zero-Knowledge proof of its validity.
	Generate(operations uint64) (*Puzzle, error)

	// Verify instantly checks the ZKP to guarantee the puzzle is mathematically solvable.
	Verify(p *Puzzle) bool

	// Solve performs the sequential brute-force math to unlock the target state.
	Solve(p *Puzzle) ([]byte, error)
}

var ErrInvalidZKP = errors.New("CRITICAL ALARM: Zero-Knowledge Proof failed. The Time-Lock puzzle is mathematically invalid or forged")