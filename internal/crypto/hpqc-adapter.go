package crypto

import (
	"fmt"

	"github.com/gh4rib/pqpg/internal/hpqc/kem"
	kemschemes "github.com/gh4rib/pqpg/internal/hpqc/kem/schemes"
	"github.com/gh4rib/pqpg/internal/hpqc/sign"
	signschemes "github.com/gh4rib/pqpg/internal/hpqc/sign/schemes"
)

// =========================================================================
// HPQC KEM ADAPTER
// =========================================================================

type hpqcKEMAdapter struct {
	scheme kem.Scheme
}

func (a *hpqcKEMAdapter) Name() string        { return a.scheme.Name() }
func (a *hpqcKEMAdapter) PublicKeySize() int  { return a.scheme.PublicKeySize() }
func (a *hpqcKEMAdapter) PrivateKeySize() int { return a.scheme.PrivateKeySize() }
func (a *hpqcKEMAdapter) CiphertextSize() int { return a.scheme.CiphertextSize() }
func (a *hpqcKEMAdapter) SharedKeySize() int  { return a.scheme.SharedKeySize() }

func (a *hpqcKEMAdapter) GenerateKeyPair() ([]byte, []byte, error) {
	pub, priv, err := a.scheme.GenerateKeyPair()
	if err != nil {
		return nil, nil, err
	}
	pubBytes, err := pub.MarshalBinary()
	if err != nil {
		return nil, nil, err
	}
	privBytes, err := priv.MarshalBinary()
	if err != nil {
		return nil, nil, err
	}
	return pubBytes, privBytes, nil
}

func (a *hpqcKEMAdapter) Encapsulate(pubKeyBytes []byte) ([]byte, []byte, error) {
	pub, err := a.scheme.UnmarshalBinaryPublicKey(pubKeyBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid HPQC KEM public key: %w", err)
	}
	ct, ss, err := a.scheme.Encapsulate(pub)
	if err != nil {
		return nil, nil, err
	}
	return ct, ss, nil
}

func (a *hpqcKEMAdapter) Decapsulate(ctBytes, privKeyBytes []byte) ([]byte, error) {
	priv, err := a.scheme.UnmarshalBinaryPrivateKey(privKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("invalid HPQC KEM private key: %w", err)
	}
	ss, err := a.scheme.Decapsulate(priv, ctBytes)
	if err != nil {
		return nil, err
	}
	return ss, nil
}

func GetHPQCKEM(name string) (KEM, error) {
	scheme := kemschemes.ByName(name)
	if scheme == nil {
		return nil, fmt.Errorf("HPQC KEM primitive not found: %s", name)
	}
	return &hpqcKEMAdapter{scheme: scheme}, nil
}

// =========================================================================
// HPQC DSA ADAPTER
// =========================================================================

type hpqcDSAAdapter struct {
	scheme sign.Scheme
}

func (a *hpqcDSAAdapter) Name() string        { return a.scheme.Name() }
func (a *hpqcDSAAdapter) PublicKeySize() int  { return a.scheme.PublicKeySize() }
func (a *hpqcDSAAdapter) PrivateKeySize() int { return a.scheme.PrivateKeySize() }
func (a *hpqcDSAAdapter) SignatureSize() int  { return a.scheme.SignatureSize() }

func (a *hpqcDSAAdapter) GenerateKeyPair() ([]byte, []byte, error) {
	pub, priv, err := a.scheme.GenerateKey()
	if err != nil {
		return nil, nil, err
	}
	pubBytes, err := pub.MarshalBinary()
	if err != nil {
		return nil, nil, err
	}
	privBytes, err := priv.MarshalBinary()
	if err != nil {
		return nil, nil, err
	}
	return pubBytes, privBytes, nil
}

func (a *hpqcDSAAdapter) Sign(privKeyBytes, message []byte) ([]byte, error) {
	priv, err := a.scheme.UnmarshalBinaryPrivateKey(privKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("invalid HPQC DSA private key: %w", err)
	}
	sig := a.scheme.Sign(priv, message, nil)
	return sig, nil
}

func (a *hpqcDSAAdapter) Verify(pubKeyBytes, message, signature []byte) bool {
	pub, err := a.scheme.UnmarshalBinaryPublicKey(pubKeyBytes)
	if err != nil {
		return false
	}
	return a.scheme.Verify(pub, message, signature, nil)
}

func GetHPQCDSA(name string) (DSA, error) {
	scheme := signschemes.ByName(name)
	if scheme == nil {
		return nil, fmt.Errorf("HPQC DSA primitive not found: %s", name)
	}
	return &hpqcDSAAdapter{scheme: scheme}, nil
}
