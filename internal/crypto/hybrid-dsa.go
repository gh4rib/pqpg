package crypto

import (
	"crypto/rand"
	"errors"

	"github.com/cloudflare/circl/sign/ed25519"
	"github.com/cloudflare/circl/sign/ed448"
)

type hybridDSAAdapter struct {
	pqDSA    DSA
	eccCurve string // "Ed25519" or "Ed448"
}

func (h *hybridDSAAdapter) getECCLengths() (pubLen, privLen, sigLen int) {
	if h.eccCurve == "Ed25519" {
		return ed25519.PublicKeySize, ed25519.PrivateKeySize, ed25519.SignatureSize
	}
	return ed448.PublicKeySize, ed448.PrivateKeySize, ed448.SignatureSize
}

func (h *hybridDSAAdapter) GenerateKeyPair() ([]byte, []byte, error) {
	pqPub, pqPriv, err := h.pqDSA.GenerateKeyPair()
	if err != nil {
		return nil, nil, err
	}

	var eccPub, eccPriv []byte
	if h.eccCurve == "Ed25519" {
		eccPub, eccPriv, err = ed25519.GenerateKey(rand.Reader)
	} else {
		eccPub, eccPriv, err = ed448.GenerateKey(rand.Reader)
	}
	if err != nil {
		return nil, nil, err
	}

	// Combiner Layout: [ECC Key] || [PQ Key]
	pub := append(eccPub, pqPub...)
	priv := append(eccPriv, pqPriv...)
	return pub, priv, nil
}

func (h *hybridDSAAdapter) Sign(privKey, message []byte) ([]byte, error) {
	_, eccPrivLen, _ := h.getECCLengths()
	if len(privKey) < eccPrivLen {
		return nil, errors.New("invalid hybrid private key length")
	}

	eccPriv := privKey[:eccPrivLen]
	pqPriv := privKey[eccPrivLen:]

	var eccSig []byte
	if h.eccCurve == "Ed25519" {
		eccSig = ed25519.Sign(eccPriv, message)
	} else {
		// FIX: Ed448 strictly requires a context string per RFC 8032
		eccSig = ed448.Sign(eccPriv, message, "")
	}

	pqSig, err := h.pqDSA.Sign(pqPriv, message)
	if err != nil {
		return nil, err
	}

	return append(eccSig, pqSig...), nil
}

func (h *hybridDSAAdapter) Verify(pubKey, message, signature []byte) bool {
	eccPubLen, _, eccSigLen := h.getECCLengths()

	if len(pubKey) < eccPubLen || len(signature) < eccSigLen {
		return false
	}

	eccPub := pubKey[:eccPubLen]
	pqPub := pubKey[eccPubLen:]
	eccSig := signature[:eccSigLen]
	pqSig := signature[eccSigLen:]

	var classicalValid bool
	if h.eccCurve == "Ed25519" {
		classicalValid = ed25519.Verify(eccPub, message, eccSig)
	} else {
		// FIX: Pass the empty context string to match the Sign method
		classicalValid = ed448.Verify(eccPub, message, eccSig, "")
	}

	if !classicalValid {
		return false
	}

	return h.pqDSA.Verify(pqPub, message, pqSig)
}

func (h *hybridDSAAdapter) Name() string {
	return "Hybrid-" + h.pqDSA.Name() + "+" + h.eccCurve
}

func (h *hybridDSAAdapter) PublicKeySize() int {
	eccPubLen, _, _ := h.getECCLengths()
	return eccPubLen + h.pqDSA.PublicKeySize()
}

func (h *hybridDSAAdapter) PrivateKeySize() int {
	_, eccPrivLen, _ := h.getECCLengths()
	return eccPrivLen + h.pqDSA.PrivateKeySize()
}

func (h *hybridDSAAdapter) SignatureSize() int {
	_, _, eccSigLen := h.getECCLengths()
	return eccSigLen + h.pqDSA.SignatureSize()
}
