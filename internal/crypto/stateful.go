package crypto

import (
	"fmt"
	"strings"
)

// StatefulDSA defines the contract for stateful Hash-Based Signature Schemes.
type StatefulDSA interface {
	Name() string
	GenerateKeyPair() (pub, priv []byte, err error)

	// Added 'privDir string' as the 3rd argument to match the adapters
	Sign(privKey, message []byte, privDir string) (signature, newPrivKey []byte, err error)

	Verify(pubKey, message, signature []byte) bool

	// Allows the engine to read the internal state counter for Anti-Rollback checks
	ExtractCounter(privKey []byte) (uint64, error)
}

// GetStatefulDSA routes to algorithms requiring synchronous counter updates.
func (r *Registry) GetStatefulDSA(name string) (StatefulDSA, error) {
	// Dynamically intercept ANY valid LMS string
	if strings.HasPrefix(name, "LMS_") {
		return &lmsAdapter{algName: name}, nil
	}

	// Dynamically intercept ANY valid XMSS/XMSSMT string
	if strings.HasPrefix(name, "XMSS") {
		return &xmssAdapter{algName: name}, nil
	}

	return nil, fmt.Errorf("stateful signature primitive not found: %s", name)
}
