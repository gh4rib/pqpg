package crypto

import (
	"fmt"

	"github.com/cloudflare/circl/sign"
	"github.com/cloudflare/circl/sign/dilithium/mode2"
	"github.com/cloudflare/circl/sign/dilithium/mode3"
	"github.com/cloudflare/circl/sign/dilithium/mode5"
	"github.com/cloudflare/circl/sign/eddilithium2"
	"github.com/cloudflare/circl/sign/eddilithium3"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
	"github.com/cloudflare/circl/sign/slhdsa"
)

type genericDSAAdapter struct {
	name   string
	scheme sign.Scheme
}

func (a *genericDSAAdapter) Name() string        { return a.name }
func (a *genericDSAAdapter) PublicKeySize() int  { return a.scheme.PublicKeySize() }
func (a *genericDSAAdapter) PrivateKeySize() int { return a.scheme.PrivateKeySize() }
func (a *genericDSAAdapter) SignatureSize() int  { return a.scheme.SignatureSize() }

func (a *genericDSAAdapter) GenerateKeyPair() ([]byte, []byte, error) {
	// FIX 1: CIRCL's sign.Scheme uses GenerateKey() instead of GenerateKeyPair()
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

func (a *genericDSAAdapter) Sign(privKeyBytes, message []byte) ([]byte, error) {
	priv, err := a.scheme.UnmarshalBinaryPrivateKey(privKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("invalid signature private key: %w", err)
	}
	
	// FIX 2: CIRCL's Sign method only returns []byte. We wrap it with a nil error.
	sig := a.scheme.Sign(priv, message, nil)
	return sig, nil
}

func (a *genericDSAAdapter) Verify(pubKeyBytes, message, signature []byte) bool {
	pub, err := a.scheme.UnmarshalBinaryPublicKey(pubKeyBytes)
	if err != nil {
		return false
	}
	
	// FIX 3: Corrected the argument order. 
	// Signature is the 3rd argument, Options (nil) is the 4th.
	return a.scheme.Verify(pub, message, signature, nil)
}

func GetDSA(name string) (DSA, error) {
	switch name {
	// NIST FIPS 204 Standard
	case "ML-DSA-65":
		return &genericDSAAdapter{name: name, scheme: mldsa65.Scheme()}, nil
	case "ML-DSA-87":
		return &genericDSAAdapter{name: name, scheme: mldsa87.Scheme()}, nil

	// Pre-standardization Dilithium
	case "Dilithium2":
		return &genericDSAAdapter{name: name, scheme: mode2.Scheme()}, nil
	case "Dilithium3":
		return &genericDSAAdapter{name: name, scheme: mode3.Scheme()}, nil
	case "Dilithium5":
		return &genericDSAAdapter{name: name, scheme: mode5.Scheme()}, nil

	// Composite Hybrid Signatures (Classical Curve + Post-Quantum Lattice)
	case "EdDilithium2":
		return &genericDSAAdapter{name: name, scheme: eddilithium2.Scheme()}, nil
	case "EdDilithium3":
		return &genericDSAAdapter{name: name, scheme: eddilithium3.Scheme()}, nil

	// FIX 4: Call .Scheme() on the SLH-DSA ID constants
	
	// Category 1
	case "SLH-DSA-SHA2-128s":
		return &genericDSAAdapter{name: name, scheme: slhdsa.SHA2_128s.Scheme()}, nil
	case "SLH-DSA-SHA2-128f":
		return &genericDSAAdapter{name: name, scheme: slhdsa.SHA2_128f.Scheme()}, nil
	case "SLH-DSA-SHAKE-128s":
		return &genericDSAAdapter{name: name, scheme: slhdsa.SHAKE_128s.Scheme()}, nil
	case "SLH-DSA-SHAKE-128f":
		return &genericDSAAdapter{name: name, scheme: slhdsa.SHAKE_128f.Scheme()}, nil

	// Category 3
	case "SLH-DSA-SHA2-192s":
		return &genericDSAAdapter{name: name, scheme: slhdsa.SHA2_192s.Scheme()}, nil
	case "SLH-DSA-SHA2-192f":
		return &genericDSAAdapter{name: name, scheme: slhdsa.SHA2_192f.Scheme()}, nil
	case "SLH-DSA-SHAKE-192s":
		return &genericDSAAdapter{name: name, scheme: slhdsa.SHAKE_192s.Scheme()}, nil
	case "SLH-DSA-SHAKE-192f":
		return &genericDSAAdapter{name: name, scheme: slhdsa.SHAKE_192f.Scheme()}, nil

	// Category 5
	case "SLH-DSA-SHA2-256s":
		return &genericDSAAdapter{name: name, scheme: slhdsa.SHA2_256s.Scheme()}, nil
	case "SLH-DSA-SHA2-256f":
		return &genericDSAAdapter{name: name, scheme: slhdsa.SHA2_256f.Scheme()}, nil
	case "SLH-DSA-SHAKE-256s":
		return &genericDSAAdapter{name: name, scheme: slhdsa.SHAKE_256s.Scheme()}, nil
	case "SLH-DSA-SHAKE-256f":
		return &genericDSAAdapter{name: name, scheme: slhdsa.SHAKE_256f.Scheme()}, nil

	default:
		return nil, fmt.Errorf("unsupported DSA variant: %s", name)
	}
}