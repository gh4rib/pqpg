package packet

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/gh4rib/pqpg-cloudflare-circl/internal/crypto"
	"github.com/gh4rib/pqpg-cloudflare-circl/internal/identity"
)

// Envelope is the JSON wire-format sent across the network.
type Envelope struct {
	SenderName string `json:"sender_name"`
	KEMSuite   string `json:"kem_suite"`
	DSASuite   string `json:"dsa_suite"`
	AEADSuite  string `json:"aead_suite"`
	XOFSuite   string `json:"xof_suite"`
	KEMEncap   []byte `json:"kem_encap"`
	Ciphertext []byte `json:"ciphertext"`
	Nonce      []byte `json:"nonce"`
	Signature  []byte `json:"signature"`
}

// Seal packages a plaintext file into a Post-Quantum Secure Envelope.
func Seal(plaintext []byte, sender *identity.Keyring, receiver *identity.Profile) (*Envelope, error) {
	registry := crypto.NewRegistry()

	// 1. Initialize Recipient's Encapsulation Engine
	kem, err := registry.GetKEM(receiver.KEMSuite)
	if err != nil {
		return nil, err
	}
	ctKEM, sharedSecret, err := kem.Encapsulate(receiver.KEMPubKey)
	if err != nil {
		return nil, fmt.Errorf("kem encapsulation failed: %w", err)
	}

	// 2. Convert XOF string to Engine, then initialize PFS Ratchet
	ratchetXOF, err := registry.GetXOF(receiver.XOFSuite)
	if err != nil {
		return nil, err
	}
	
	ratchet, err := crypto.NewRatchet(sharedSecret, ratchetXOF)
	if err != nil {
		return nil, err
	}
	defer ratchet.Destroy() // Burn KDF state when done

	aead, _ := registry.GetAEAD(receiver.AEADSuite)
	msgKey, err := ratchet.Advance(aead.KeySize())
	if err != nil {
		return nil, err
	}

	// 3. Encrypt the Payload
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	ciphertext, err := aead.Seal(msgKey, nonce, plaintext, nil)
	if err != nil {
		return nil, fmt.Errorf("aead encryption failed: %w", err)
	}

	// 4. Construct the Envelope (without signature yet)
	env := &Envelope{
		SenderName: sender.Profile.Name,
		KEMSuite:   receiver.KEMSuite,
		DSASuite:   sender.Profile.DSASuite,
		AEADSuite:  receiver.AEADSuite,
		XOFSuite:   receiver.XOFSuite,
		KEMEncap:   ctKEM,
		Ciphertext: ciphertext,
		Nonce:      nonce,
	}

	// 5. Fiat-Shamir Binding: Hash the exact envelope state, then sign the digest
	envBytes, _ := json.Marshal(env)
	fiatShamirXOF, _ := registry.GetXOF(env.XOFSuite)
	digest := fiatShamirXOF.Derive(envBytes, 64)

	dsa, _ := registry.GetDSA(sender.Profile.DSASuite)
	sig, err := dsa.Sign(sender.DSAPrivKey, digest)
	if err != nil {
		return nil, fmt.Errorf("dsa signing failed: %w", err)
	}
	env.Signature = sig

	return env, nil
}

// Open verifies the Post-Quantum Signature and decrypts the Envelope.
func Open(env *Envelope, receiver *identity.Keyring, sender *identity.Profile) ([]byte, error) {
	registry := crypto.NewRegistry()

	// 1. Fiat-Shamir Binding: Reconstruct the exact hash digest
	sigSnapshot := env.Signature
	env.Signature = nil // Temporarily remove signature to reconstruct the signed bytes
	envBytes, _ := json.Marshal(env)
	env.Signature = sigSnapshot // Restore

	fiatShamirXOF, err := registry.GetXOF(env.XOFSuite)
	if err != nil {
		return nil, err
	}
	digest := fiatShamirXOF.Derive(envBytes, 64)

	// 2. Verify Identity via DSA
	dsa, err := registry.GetDSA(env.DSASuite)
	if err != nil {
		return nil, err
	}
	if !dsa.Verify(sender.DSAPubKey, digest, env.Signature) {
		return nil, errors.New("CRITICAL: invalid signature or envelope altered in transit")
	}

	// 3. Decapsulate the Hybrid/PQ KEM
	kem, err := registry.GetKEM(env.KEMSuite)
	if err != nil {
		return nil, err
	}
	sharedSecret, err := kem.Decapsulate(env.KEMEncap, receiver.KEMPrivKey)
	if err != nil {
		return nil, fmt.Errorf("kem decapsulation failed: %w", err)
	}

	// 4. Convert XOF string to Engine, then initialize Ratchet to recover Message Key
	ratchetXOF, err := registry.GetXOF(env.XOFSuite)
	if err != nil {
		return nil, err
	}
	
	ratchet, err := crypto.NewRatchet(sharedSecret, ratchetXOF)
	if err != nil {
		return nil, err
	}
	defer ratchet.Destroy()

	aead, _ := registry.GetAEAD(env.AEADSuite)
	msgKey, err := ratchet.Advance(aead.KeySize())
	if err != nil {
		return nil, err
	}

	// 5. Decrypt and Authenticate Payload
	plaintext, err := aead.Open(msgKey, env.Nonce, env.Ciphertext, nil)
	if err != nil {
		return nil, errors.New("CRITICAL: MAC authentication failed; ciphertext corrupt")
	}

	return plaintext, nil
}