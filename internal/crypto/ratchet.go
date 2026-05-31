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
// The masterSecret typically comes from the successful decapsulation of the Hybrid KEM.
func NewRatchet(masterSecret []byte, xofEngine XOF) (*SymmetricRatchet, error) {
	if len(masterSecret) == 0 {
		return nil, errors.New("master secret cannot be empty")
	}
	if xofEngine == nil {
		return nil, errors.New("XOF engine cannot be nil")
	}

	// Safely copy the master secret to isolate it from external slice mutations.
	initialChainKey := make([]byte, len(masterSecret))
	copy(initialChainKey, masterSecret)

	return &SymmetricRatchet{
		chainKey: initialChainKey,
		xof:      xofEngine,
	}, nil
}

// Advance spins the ratchet forward. It returns the Message Key for the current packet
// and irreversibly replaces the internal Chain Key to guarantee Perfect Forward Secrecy (PFS).
func (r *SymmetricRatchet) Advance(messageKeySize int) ([]byte, error) {
	if len(r.chainKey) == 0 {
		return nil, errors.New("ratchet is exhausted or uninitialized")
	}

	// We derive a block large enough for both the new Chain Key and the Message Key.
	deriveSize := len(r.chainKey) + messageKeySize
	kdfOutput := r.xof.Derive(r.chainKey, deriveSize)

	// Security: Aggressively zero-out the old chain key from memory immediately.
	for i := range r.chainKey {
		r.chainKey[i] = 0
	}

	// Split the output: First part is the new Chain Key, second part is the Message Key.
	newChainKey := kdfOutput[:len(r.chainKey)]
	messageKey := kdfOutput[len(r.chainKey):]

	r.chainKey = newChainKey

	return messageKey, nil
}

// Destroy explicitly zeroes the ratchet state in memory when the session concludes
// to prevent cold-boot attacks and memory scraping.
func (r *SymmetricRatchet) Destroy() {
	if r.chainKey != nil {
		for i := range r.chainKey {
			r.chainKey[i] = 0
		}
		r.chainKey = nil
	}
}