package packet

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/gh4rib/pqpg-cloudflare-circl/internal/crypto"
	"github.com/gh4rib/pqpg-cloudflare-circl/internal/identity"
)

// Envelope includes the new Timestamp for anti-replay uniqueness
type Envelope struct {
	SenderName string `json:"sender_name"`
	Timestamp  int64  `json:"timestamp"` // Unix timestamp injected at creation
	KEMSuite   string `json:"kem_suite"`
	DSASuite   string `json:"dsa_suite"`
	AEADSuite  string `json:"aead_suite"`
	XOFSuite   string `json:"xof_suite"`
	KEMEncap   []byte `json:"kem_encap"`
	Ciphertext []byte `json:"ciphertext"`
	Nonce      []byte `json:"nonce"`
	Signature  []byte `json:"signature"`
}

func Seal(plaintext []byte, sender *identity.Keyring, receiver *identity.Profile) (*Envelope, error) {
	registry := crypto.NewRegistry()

	kem, err := registry.GetKEM(receiver.KEMSuite)
	if err != nil { return nil, err }
	ctKEM, sharedSecret, err := kem.Encapsulate(receiver.KEMPubKey)
	if err != nil { return nil, fmt.Errorf("kem encapsulation failed: %w", err) }

	ratchetXOF, err := registry.GetXOF(receiver.XOFSuite)
	if err != nil { return nil, err }
	ratchet, err := crypto.NewRatchet(sharedSecret, ratchetXOF)
	if err != nil { return nil, err }
	defer ratchet.Destroy()

	aead, _ := registry.GetAEAD(receiver.AEADSuite)
	msgKey, err := ratchet.Advance(aead.KeySize())
	if err != nil { return nil, err }

	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil { return nil, err }
	ciphertext, err := aead.Seal(msgKey, nonce, plaintext, nil)
	if err != nil { return nil, fmt.Errorf("aead encryption failed: %w", err) }

	// Construct Envelope with LIVE Timestamp
	env := &Envelope{
		SenderName: sender.Profile.Name,
		Timestamp:  time.Now().Unix(),
		KEMSuite:   receiver.KEMSuite,
		DSASuite:   sender.Profile.DSASuite,
		AEADSuite:  receiver.AEADSuite,
		XOFSuite:   receiver.XOFSuite,
		KEMEncap:   ctKEM,
		Ciphertext: ciphertext,
		Nonce:      nonce,
	}

	// STRICT DOMAIN SEPARATION for Fiat-Shamir Binding
	envBytes, _ := json.Marshal(env)
	fiatShamirInput := append([]byte("PQPG-v1-FiatShamir-"), envBytes...)
	
	fiatShamirXOF, _ := registry.GetXOF(env.XOFSuite)
	digest := fiatShamirXOF.Derive(fiatShamirInput, 64)

	dsa, _ := registry.GetDSA(sender.Profile.DSASuite)
	sig, err := dsa.Sign(sender.DSAPrivKey, digest)
	if err != nil { return nil, fmt.Errorf("dsa signing failed: %w", err) }
	env.Signature = sig

	return env, nil
}

func Open(env *Envelope, receiver *identity.Keyring, sender *identity.Profile) ([]byte, error) {
	registry := crypto.NewRegistry()

	// Reconstruct the exact Domain Separated hash digest
	sigSnapshot := env.Signature
	env.Signature = nil 
	envBytes, _ := json.Marshal(env)
	env.Signature = sigSnapshot 

	fiatShamirInput := append([]byte("PQPG-v1-FiatShamir-"), envBytes...)

	fiatShamirXOF, err := registry.GetXOF(env.XOFSuite)
	if err != nil { return nil, err }
	digest := fiatShamirXOF.Derive(fiatShamirInput, 64)

	dsa, err := registry.GetDSA(env.DSASuite)
	if err != nil { return nil, err }
	if !dsa.Verify(sender.DSAPubKey, digest, env.Signature) {
		return nil, errors.New("CRITICAL: invalid signature or envelope altered in transit")
	}

	kem, err := registry.GetKEM(env.KEMSuite)
	if err != nil { return nil, err }
	sharedSecret, err := kem.Decapsulate(env.KEMEncap, receiver.KEMPrivKey)
	if err != nil { return nil, fmt.Errorf("kem decapsulation failed: %w", err) }

	ratchetXOF, err := registry.GetXOF(env.XOFSuite)
	if err != nil { return nil, err }
	ratchet, err := crypto.NewRatchet(sharedSecret, ratchetXOF)
	if err != nil { return nil, err }
	defer ratchet.Destroy()

	aead, _ := registry.GetAEAD(env.AEADSuite)
	msgKey, err := ratchet.Advance(aead.KeySize())
	if err != nil { return nil, err }

	plaintext, err := aead.Open(msgKey, env.Nonce, env.Ciphertext, nil)
	if err != nil { return nil, errors.New("CRITICAL: MAC authentication failed; ciphertext corrupt") }

	return plaintext, nil
}