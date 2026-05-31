package crypto

import "fmt"

type Registry struct{}

func NewRegistry() *Registry {
	return &Registry{}
}

func (r *Registry) GetXOF(name string) (XOF, error) {
	switch name {
	case "SHAKE128":
		return &shakeAdapter{variant: "SHAKE128"}, nil
	case "SHAKE256":
		return &shakeAdapter{variant: "SHAKE256"}, nil
	case "SHA3-256":
		return &sha3StandardAdapter{variant: "SHA3-256"}, nil
	case "SHA3-384":
		return &sha3StandardAdapter{variant: "SHA3-384"}, nil
	case "SHA3-512":
		return &sha3StandardAdapter{variant: "SHA3-512"}, nil
	case "KangarooTwelve":
		return &k12Adapter{}, nil
	default:
		return nil, fmt.Errorf("hash/XOF primitive not found: %s", name)
	}
}

func (r *Registry) GetKEM(name string) (KEM, error) {
	return GetKEM(name)
}

func (r *Registry) GetDSA(name string) (DSA, error) {
	return GetDSA(name)
}

func (r *Registry) GetAEAD(name string) (AEAD, error) {
	return GetAEAD(name)
}

// ValidateSuite ensures the chosen cryptographic combinations strictly adhere to valid primitives.
func (r *Registry) ValidateSuite(kemSuite, dsaSuite, symSuite, hashSuite string) bool {
	if _, err := r.GetXOF(hashSuite); err != nil {
		return false
	}
	if _, err := r.GetKEM(kemSuite); err != nil {
		return false
	}
	if _, err := r.GetDSA(dsaSuite); err != nil {
		return false
	}
	if _, err := r.GetAEAD(symSuite); err != nil {
		return false
	}
	return true
}