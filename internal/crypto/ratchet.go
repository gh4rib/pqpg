package crypto

import (
	"errors"
)

// SymmetricRatchet implements a forward-secret Key Derivation Function (KDF) chain.
type SymmetricRatchet struct {
	chainKey []byte
	xof      XOF
}

// NewRatchet initializes the KDF chain with a shared master secret and an XOF engine.
func NewRatchet(masterSecret []byte, xofEngine XOF) (*SymmetricRatchet, error) {
	if len(masterSecret) == 0 {
		return nil, errors.New("master secret cannot be empty")
	}
	if xofEngine == nil {
		return nil, errors.New("XOF engine cannot be nil")
	}

	initialChainKey := make([]byte, len(masterSecret))
	copy(initialChainKey, masterSecret)

	return &SymmetricRatchet{
		chainKey: initialChainKey,
		xof:      xofEngine,
	}, nil
}

// Advance spins the ratchet forward using Domain Separated XOF derivation.
func (r *SymmetricRatchet) Advance(messageKeySize int) ([]byte, error) {
	if len(r.chainKey) == 0 {
		return nil, errors.New("ratchet is exhausted or uninitialized")
	}

	// 1. STRICT DOMAIN SEPARATION: Prefix the input to isolate the KDF context
	domainLabel := []byte("PQPG-v1-KDF-Chain-")
	kdfInput := append(domainLabel, r.chainKey...)

	// 2. Derive the expanded key block
	deriveSize := len(r.chainKey) + messageKeySize
	kdfOutput := r.xof.Derive(kdfInput, deriveSize)

	// Security: Aggressively zero-out the old chain key and intermediate input buffer
	for i := range r.chainKey {
		r.chainKey[i] = 0
	}
	for i := range kdfInput {
		kdfInput[i] = 0
	}

	// Split the output
	newChainKey := kdfOutput[:len(r.chainKey)]
	messageKey := kdfOutput[len(r.chainKey):]

	r.chainKey = newChainKey

	return messageKey, nil
}

func (r *SymmetricRatchet) Destroy() {
	if r.chainKey != nil {
		for i := range r.chainKey {
			r.chainKey[i] = 0
		}
		r.chainKey = nil
	}
}