package crypto

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
)

const (
	DomainRootRatchet  = "PQPG-DoubleRatchet-Root-v1"
	DomainChainRatchet = "PQPG-DoubleRatchet-Chain-v1"
)

// ratchetKDF dynamically uses the negotiated XOF to extract exactly 64 bytes (512 bits) of key material.
func ratchetKDF(xofSuite, domain string, key, data []byte) (out1, out2 []byte) {
	registry := NewRegistry()
	xof, err := registry.GetXOF(xofSuite)
	if err != nil {
		// Failsafe fallback if an invalid suite somehow bypasses initialization
		xof, _ = registry.GetXOF("SHAKE256")
	}

	xof.Write([]byte(domain))
	xof.Write(key)
	if data != nil {
		xof.Write(data)
	}

	// Squeeze 512 bits of entropy dynamically
	derived := xof.Derive(nil, 64)

	// Return two isolated 256-bit keys
	return derived[:32], derived[32:]
}

// AdvanceRootRatchet mixes the current Root Key with a fresh Post-Quantum KEM Shared Secret.
func AdvanceRootRatchet(xofSuite string, rootKey, pqSharedSecret []byte) (newRootKey, newChainKey []byte) {
	return ratchetKDF(xofSuite, DomainRootRatchet, rootKey, pqSharedSecret)
}

// AdvanceSymmetricRatchet spins the Chain Key forward.
func AdvanceSymmetricRatchet(xofSuite string, chainKey []byte) (newChainKey, messageKey []byte) {
	return ratchetKDF(xofSuite, DomainChainRatchet, chainKey, nil)
}

// -------------------------------------------------------------------------
// Ephemeral KEM Handlers for the Ratchet Ping-Pong
// -------------------------------------------------------------------------

// GenerateEphemeralKEM creates a fresh throwaway keypair to attach to a new message.
func GenerateEphemeralKEM(kemSuite string) (publicKey []byte, privateKey []byte, err error) {
	registry := NewRegistry()
	sch, err := registry.GetKEM(kemSuite)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid KEM suite for double ratchet: %w", err)
	}

	pubBytes, privBytes, err := sch.GenerateKeyPair()
	if err != nil {
		return nil, nil, err
	}

	return pubBytes, privBytes, nil
}

// EncapsulateEphemeral encapsulates a shared secret against the recipient's LAST KNOWN public key.
func EncapsulateEphemeral(kemSuite string, recipientPubBytes []byte) (ciphertext []byte, sharedSecret []byte, err error) {
	registry := NewRegistry()
	sch, err := registry.GetKEM(kemSuite)
	if err != nil {
		return nil, nil, err
	}

	ct, ss, err := sch.Encapsulate(recipientPubBytes)
	if err != nil {
		return nil, nil, err
	}

	return ct, ss, nil
}

// DecapsulateEphemeral decapsulates the incoming shared secret using YOUR current ephemeral private key.
func DecapsulateEphemeral(kemSuite string, ciphertext []byte, myPrivBytes []byte) (sharedSecret []byte, err error) {
	registry := NewRegistry()
	sch, err := registry.GetKEM(kemSuite)
	if err != nil {
		return nil, err
	}

	ss, err := sch.Decapsulate(ciphertext, myPrivBytes)
	if err != nil {
		return nil, errors.New("KEM decapsulation failed: possible tampering or corrupt state")
	}

	return ss, nil
}

// InitializeDoubleRatchet sets up the very first connection state using an initial shared secret.
func InitializeDoubleRatchet(xofSuite string, initialSecret []byte) (rootKey, initialSendChain, initialReceiveChain []byte) {
	root, sendChain := AdvanceRootRatchet(xofSuite, make([]byte, 32), initialSecret)
	
	receiveChain := make([]byte, 32)
	io.ReadFull(rand.Reader, receiveChain)

	return root, sendChain, receiveChain
}