package crypto

import (
	"errors"
	"fmt"

	// Import BOTH the core engine (for constants/types) and your wrapper (for math)
	"github.com/algorand/falcon"
	myfalcon "github.com/gh4rib/pqpg/internal/falcon"
)

// falconAdapter bridges your custom wrapper to the PQPG abstract DSA interface.
type falconAdapter struct{}

// Name Identity Method
func (f *falconAdapter) Name() string {
	return "Falcon-1024"
}

// PublicKeySize Sizing Methods (Pulled dynamically from the Algorand CGo constants)
func (f *falconAdapter) PublicKeySize() int {
	return falcon.PublicKeySize
}

func (f *falconAdapter) PrivateKeySize() int {
	return falcon.PrivateKeySize
}

func (f *falconAdapter) SignatureSize() int {
	return falcon.SignatureMaxSize // Falcon signatures are variable; we return the max bounds
}

// GenerateKeyPair Mathematical Methods
func (f *falconAdapter) GenerateKeyPair() ([]byte, []byte, error) {
	// Call your wrapper function natively (it auto-generates the 48-byte seed)
	kp, err := myfalcon.GenerateKeyPair(nil)
	if err != nil {
		return nil, nil, err
	}

	// FIX: Safely copy the fixed-size CGo arrays to dynamic Go byte slices
	pub := make([]byte, len(kp.PublicKey))
	copy(pub, kp.PublicKey[:])

	priv := make([]byte, len(kp.PrivateKey))
	copy(priv, kp.PrivateKey[:])

	return pub, priv, nil
}

func (f *falconAdapter) Sign(privKey []byte, message []byte) ([]byte, error) {
	if len(privKey) == 0 {
		return nil, errors.New("falcon private key is empty")
	}

	// Reconstruct the strict Algorand array type from the incoming byte slice
	var sk falcon.PrivateKey
	if len(privKey) != len(sk) {
		return nil, fmt.Errorf("invalid falcon private key length: expected %d, got %d", len(sk), len(privKey))
	}
	copy(sk[:], privKey)

	// Build your wrapper's KeyPair struct
	kp := myfalcon.KeyPair{
		PrivateKey: sk,
	}

	sig, err := kp.Sign(message)
	if err != nil {
		return nil, err
	}

	// CompressedSignature is a byte slice under the hood, so this cast works natively
	return []byte(sig), nil
}

func (f *falconAdapter) Verify(pubKey []byte, message []byte, signature []byte) bool {
	if len(pubKey) == 0 || len(signature) == 0 {
		return false
	}

	// Reconstruct the strict Algorand array type for the public key
	var pk falcon.PublicKey
	if len(pubKey) != len(pk) {
		return false
	}
	copy(pk[:], pubKey)

	// Call your wrapper function, casting the byte slice to the required CompressedSignature type
	err := myfalcon.Verify(message, falcon.CompressedSignature(signature), pk)
	return err == nil
}
