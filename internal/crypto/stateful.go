package crypto

import (
	"fmt"
	"strings"
)

// StatefulDSA defines the contract for stateful Hash-Based Signature Schemes.
type StatefulDSA interface {
	Name() string
	GenerateKeyPair() (pub, priv []byte, err error)
	Sign(privKey, message []byte) (signature, newPrivKey []byte, err error)
	Verify(pubKey, message, signature []byte) bool
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
