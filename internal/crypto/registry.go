package crypto

import (
	"fmt"
	"strings"
)

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
	case "SHA-512":
		return &sha2Adapter{}, nil
	case "KangarooTwelve":
		return &k12Adapter{}, nil
	case "Skein-256":
		return &skeinAdapter{variant: "Skein-256"}, nil
	case "Skein-512":
		return &skeinAdapter{variant: "Skein-512"}, nil
	case "Skein-1024":
		return &skeinAdapter{variant: "Skein-1024"}, nil
	case "BLAKE3-512":
		return &blake3Adapter{}, nil
	default:
		return nil, fmt.Errorf("hash/XOF primitive not found: %s", name)
	}
}

func (r *Registry) GetKEM(name string) (KEM, error) {
	// 1. DYNAMIC COMBINER NAMESPACE
	// Examples: "Hybrid-ML-KEM-1024+X448" or "Hybrid-Hpqc-mceliece8192128+X448"
	if strings.HasPrefix(name, "Hybrid-") {
		base := strings.TrimPrefix(name, "Hybrid-")
		parts := strings.Split(base, "+")

		if len(parts) == 2 {
			pqName := parts[0]
			curve := parts[1]

			// Recurse to resolve the PQ half (which might be Hpqc- or CIRCL)
			pqKEM, err := r.GetKEM(pqName)
			if err != nil {
				return nil, err
			}
			return &hybridKEMAdapter{pqKEM: pqKEM, eccCurve: curve}, nil
		}
	}

	// 2. HPQC EXPLICIT NAMESPACE
	// Examples: "Hpqc-HQC-256-X448" or "Hpqc-mceliece8192128"
	if strings.HasPrefix(name, "Hpqc-") {
		hpqcName := strings.TrimPrefix(name, "Hpqc-")
		return GetHPQCKEM(hpqcName)
	}

	// 3. CIRCL DEFAULT NAMESPACE
	return GetKEM(name)
}

func (r *Registry) GetDSA(name string) (DSA, error) {
	// 1. DYNAMIC COMBINER NAMESPACE
	if strings.HasPrefix(name, "Hybrid-") {
		base := strings.TrimPrefix(name, "Hybrid-")
		parts := strings.Split(base, "+")

		if len(parts) == 2 {
			pqName := parts[0]
			curve := parts[1]

			pqDSA, err := r.GetDSA(pqName)
			if err != nil {
				return nil, err
			}
			return &hybridDSAAdapter{pqDSA: pqDSA, eccCurve: curve}, nil
		}
	}

	// 2. HPQC EXPLICIT NAMESPACE
	// Examples: "Hpqc-Falcon-padded-1024-Ed25519"
	if strings.HasPrefix(name, "Hpqc-") {
		hpqcName := strings.TrimPrefix(name, "Hpqc-")
		return GetHPQCDSA(hpqcName)
	}

	// 3. PURE CGO FALCON INTERCEPT
	if name == "Falcon-1024" {
		return &falconAdapter{}, nil
	}

	// 4. CIRCL DEFAULT NAMESPACE
	return GetDSA(name)
}

func (r *Registry) GetAEAD(name string) (AEAD, error) {
	return GetAEAD(name)
}

func (r *Registry) ValidateSuite(kemSuite, dsaSuite, symSuite, hashSuite string) bool {
	if _, err := r.GetXOF(hashSuite); err != nil {
		return false
	}
	if _, err := r.GetKEM(kemSuite); err != nil {
		return false
	}
	if _, err := r.GetAEAD(symSuite); err != nil {
		return false
	}

	_, errDSA := r.GetDSA(dsaSuite)
	_, errStateful := r.GetStatefulDSA(dsaSuite)

	if errDSA != nil && errStateful != nil {
		return false
	}
	return true
}
