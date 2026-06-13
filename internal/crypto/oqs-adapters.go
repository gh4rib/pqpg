package crypto

import (
	"fmt"

	"github.com/gh4rib/pqpg/internal/oqs"
)

// =========================================================================
// LIBOQS KEM ADAPTER
// =========================================================================

type oqsKEMAdapter struct {
	algName string
	details oqs.KeyEncapsulationDetails
}

func (a *oqsKEMAdapter) Name() string        { return a.algName }
func (a *oqsKEMAdapter) PublicKeySize() int  { return a.details.LengthPublicKey }
func (a *oqsKEMAdapter) PrivateKeySize() int { return a.details.LengthSecretKey }
func (a *oqsKEMAdapter) CiphertextSize() int { return a.details.LengthCiphertext }
func (a *oqsKEMAdapter) SharedKeySize() int  { return a.details.LengthSharedSecret }

func (a *oqsKEMAdapter) GenerateKeyPair() ([]byte, []byte, error) {
	kem := &oqs.KeyEncapsulation{}
	if err := kem.Init(a.algName, nil); err != nil {
		return nil, nil, err
	}
	defer kem.Clean() // CRITICAL: Safely scrubs C-memory when the function exits

	pubKey, err := kem.GenerateKeyPair()
	if err != nil {
		return nil, nil, err
	}

	// CRITICAL MEMORY FIX:
	// kem.Clean() explicitly calls C.OQS_MEM_cleanse on the secretKey slice.
	// If we return the raw slice, it will be zeroed out the microsecond this function returns.
	// We MUST copy the bytes into a new, purely Go-managed slice before Clean() executes.
	rawPrivKey := kem.ExportSecretKey()
	safePrivKey := make([]byte, len(rawPrivKey))
	copy(safePrivKey, rawPrivKey)

	return pubKey, safePrivKey, nil
}

func (a *oqsKEMAdapter) Encapsulate(pubKeyBytes []byte) ([]byte, []byte, error) {
	kem := &oqs.KeyEncapsulation{}
	if err := kem.Init(a.algName, nil); err != nil {
		return nil, nil, err
	}
	defer kem.Clean()

	ct, ss, err := kem.EncapSecret(pubKeyBytes)
	if err != nil {
		return nil, nil, err
	}
	return ct, ss, nil
}

func (a *oqsKEMAdapter) Decapsulate(ctBytes, privKeyBytes []byte) ([]byte, error) {
	kem := &oqs.KeyEncapsulation{}
	if err := kem.Init(a.algName, privKeyBytes); err != nil {
		return nil, err
	}
	defer kem.Clean()

	ss, err := kem.DecapSecret(ctBytes)
	if err != nil {
		return nil, err
	}
	return ss, nil
}

func GetOQSKEM(name string) (KEM, error) {
	// We temporarily spin up an instance just to fetch the hardware metadata (key sizes)
	kem := &oqs.KeyEncapsulation{}
	if err := kem.Init(name, nil); err != nil {
		return nil, fmt.Errorf("liboqs KEM primitive not found or unsupported: %s", name)
	}
	details := kem.Details()
	kem.Clean() // Immediately destroy the temporary instance

	return &oqsKEMAdapter{algName: name, details: details}, nil
}

// =========================================================================
// LIBOQS DSA ADAPTER
// =========================================================================

type oqsDSAAdapter struct {
	algName string
	details oqs.SignatureDetails
}

func (a *oqsDSAAdapter) Name() string        { return a.algName }
func (a *oqsDSAAdapter) PublicKeySize() int  { return a.details.LengthPublicKey }
func (a *oqsDSAAdapter) PrivateKeySize() int { return a.details.LengthSecretKey }
func (a *oqsDSAAdapter) SignatureSize() int  { return a.details.MaxLengthSignature }

func (a *oqsDSAAdapter) GenerateKeyPair() ([]byte, []byte, error) {
	sig := &oqs.Signature{}
	if err := sig.Init(a.algName, nil); err != nil {
		return nil, nil, err
	}
	defer sig.Clean()

	pubKey, err := sig.GenerateKeyPair()
	if err != nil {
		return nil, nil, err
	}

	// CRITICAL MEMORY FIX: Securely escape the C.OQS_MEM_cleanse destruction radius
	rawPrivKey := sig.ExportSecretKey()
	safePrivKey := make([]byte, len(rawPrivKey))
	copy(safePrivKey, rawPrivKey)

	return pubKey, safePrivKey, nil
}

func (a *oqsDSAAdapter) Sign(privKeyBytes, message []byte) ([]byte, error) {
	sig := &oqs.Signature{}
	if err := sig.Init(a.algName, privKeyBytes); err != nil {
		return nil, err
	}
	defer sig.Clean()

	signature, err := sig.Sign(message)
	if err != nil {
		return nil, err
	}
	return signature, nil
}

func (a *oqsDSAAdapter) Verify(pubKeyBytes, message, signature []byte) bool {
	sig := &oqs.Signature{}
	if err := sig.Init(a.algName, nil); err != nil {
		return false
	}
	defer sig.Clean()

	isValid, err := sig.Verify(message, signature, pubKeyBytes)
	return isValid && err == nil
}

func GetOQSDSA(name string) (DSA, error) {
	sig := &oqs.Signature{}
	if err := sig.Init(name, nil); err != nil {
		return nil, fmt.Errorf("liboqs DSA primitive not found or unsupported: %s", name)
	}
	details := sig.Details()
	sig.Clean()

	return &oqsDSAAdapter{algName: name, details: details}, nil
}
