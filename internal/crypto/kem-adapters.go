package crypto

import (
	"fmt"

	"github.com/cloudflare/circl/kem"
	"github.com/cloudflare/circl/kem/frodo/frodo640shake"
	"github.com/cloudflare/circl/kem/kyber/kyber1024"
	"github.com/cloudflare/circl/kem/kyber/kyber768"
	"github.com/cloudflare/circl/kem/mlkem/mlkem1024"
	"github.com/cloudflare/circl/kem/mlkem/mlkem768"
	"github.com/cloudflare/circl/kem/xwing"
)

type genericKEMAdapter struct {
	name   string
	scheme kem.Scheme
}

func (a *genericKEMAdapter) Name() string           { return a.name }
func (a *genericKEMAdapter) PublicKeySize() int     { return a.scheme.PublicKeySize() }
func (a *genericKEMAdapter) PrivateKeySize() int    { return a.scheme.PrivateKeySize() }
func (a *genericKEMAdapter) CiphertextSize() int    { return a.scheme.CiphertextSize() }
// FIXED: Matched to CIRCL's SharedKeySize method
func (a *genericKEMAdapter) SharedKeySize() int     { return a.scheme.SharedKeySize() }

func (a *genericKEMAdapter) GenerateKeyPair() ([]byte, []byte, error) {
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

func (a *genericKEMAdapter) Encapsulate(pubKeyBytes []byte) ([]byte, []byte, error) {
	pub, err := a.scheme.UnmarshalBinaryPublicKey(pubKeyBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid KEM public key: %w", err)
	}
	ct, ss, err := a.scheme.Encapsulate(pub)
	if err != nil {
		return nil, nil, err
	}
	return ct, ss, nil
}

func (a *genericKEMAdapter) Decapsulate(ctBytes, privKeyBytes []byte) ([]byte, error) {
	priv, err := a.scheme.UnmarshalBinaryPrivateKey(privKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("invalid KEM private key: %w", err)
	}
	ss, err := a.scheme.Decapsulate(priv, ctBytes)
	if err != nil {
		return nil, err
	}
	return ss, nil
}

func GetKEM(name string) (KEM, error) {
	switch name {
	case "ML-KEM-768":
		return &genericKEMAdapter{name: name, scheme: mlkem768.Scheme()}, nil
	case "ML-KEM-1024":
		return &genericKEMAdapter{name: name, scheme: mlkem1024.Scheme()}, nil
	case "Kyber768":
		return &genericKEMAdapter{name: name, scheme: kyber768.Scheme()}, nil
	case "Kyber1024":
		return &genericKEMAdapter{name: name, scheme: kyber1024.Scheme()}, nil
	case "FrodoKEM-640-SHAKE":
		return &genericKEMAdapter{name: name, scheme: frodo640shake.Scheme()}, nil
	case "Hybrid-X25519-MLKEM768", "X-Wing":
		return &genericKEMAdapter{name: "X-Wing", scheme: xwing.Scheme()}, nil
	default:
		return nil, fmt.Errorf("unsupported KEM variant: %s", name)
	}
}