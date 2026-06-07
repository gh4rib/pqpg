package crypto

import (
	"fmt"
	"strings"

	"github.com/gh4rib/pqpg/internal/lms/common"
	"github.com/gh4rib/pqpg/internal/lms/lms"
)

type lmsAdapter struct {
	algName string // e.g., "LMS_H25_W8"
}

func (a *lmsAdapter) Name() string { return a.algName }

// parseParams decodes the dynamic string into the strict trailofbits constants.
func (a *lmsAdapter) parseParams() (common.LmsAlgorithmType, common.LmsOtsAlgorithmType, error) {
	parts := strings.Split(a.algName, "_")
	if len(parts) != 3 {
		// FIX: Returning nil, nil for the interfaces
		return nil, nil, fmt.Errorf("invalid LMS dynamic string: %s", a.algName)
	}

	var lmsType common.LmsTypecode
	switch parts[1] {
	case "H5":
		lmsType = common.LMS_SHA256_M32_H5
	case "H10":
		lmsType = common.LMS_SHA256_M32_H10
	case "H15":
		lmsType = common.LMS_SHA256_M32_H15
	case "H20":
		lmsType = common.LMS_SHA256_M32_H20
	case "H25":
		lmsType = common.LMS_SHA256_M32_H25
	default:
		// FIX: Returning nil, nil for the interfaces
		return nil, nil, fmt.Errorf("unsupported LMS tree height: %s", parts[1])
	}

	var otsType common.LmotsTypecode
	switch parts[2] {
	case "W1":
		otsType = common.LMOTS_SHA256_N32_W1
	case "W2":
		otsType = common.LMOTS_SHA256_N32_W2
	case "W4":
		otsType = common.LMOTS_SHA256_N32_W4
	case "W8":
		otsType = common.LMOTS_SHA256_N32_W8
	default:
		// FIX: Returning nil, nil for the interfaces
		return nil, nil, fmt.Errorf("unsupported LM-OTS Winternitz width: %s", parts[2])
	}

	return lmsType, otsType, nil
}

func (a *lmsAdapter) GenerateKeyPair() ([]byte, []byte, error) {
	lmsType, otsType, err := a.parseParams()
	if err != nil {
		return nil, nil, err
	}

	seckey, err := lms.NewPrivateKey(lmsType, otsType)
	if err != nil {
		return nil, nil, err
	}

	pubkey := seckey.Public()
	pubBytes := pubkey.ToBytes()
	privBytes := seckey.ToBytes()

	return pubBytes, privBytes, nil
}

func (a *lmsAdapter) Sign(privKey []byte, message []byte) ([]byte, []byte, error) {
	seckey, err := lms.LmsPrivateKeyFromBytes(privKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse LMS private key: %w", err)
	}

	sig, err := seckey.Sign(message, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("LMS signing failed (key exhausted?): %w", err)
	}

	sigBytes, err := sig.ToBytes()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to serialize LMS signature: %w", err)
	}

	newPrivKeyBytes := seckey.ToBytes()
	return sigBytes, newPrivKeyBytes, nil
}

func (a *lmsAdapter) Verify(pubKey []byte, message []byte, signature []byte) bool {
	pubkey, err := lms.LmsPublicKeyFromBytes(pubKey)
	if err != nil {
		return false
	}

	sig, err := lms.LmsSignatureFromBytes(signature)
	if err != nil {
		return false
	}

	return pubkey.Verify(message, sig)
}
