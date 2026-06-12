package crypto

import (
	"crypto/rand"
	"errors"

	"github.com/cloudflare/circl/dh/x25519"
	"github.com/cloudflare/circl/dh/x448"
	"golang.org/x/crypto/sha3"
)

type hybridKEMAdapter struct {
	pqKEM    KEM
	eccCurve string // "X25519" or "X448"
}

func (h *hybridKEMAdapter) getECCLengths() (pubLen, privLen, ctLen int) {
	if h.eccCurve == "X25519" {
		return 32, 32, 32
	}
	return 56, 56, 56
}

func (h *hybridKEMAdapter) GenerateKeyPair() ([]byte, []byte, error) {
	pqPub, pqPriv, err := h.pqKEM.GenerateKeyPair()
	if err != nil {
		return nil, nil, err
	}

	var eccPub, eccPriv []byte
	if h.eccCurve == "X25519" {
		var secret, public x25519.Key
		_, _ = rand.Read(secret[:])
		x25519.KeyGen(&public, &secret)
		eccPub, eccPriv = public[:], secret[:]
	} else {
		var secret, public x448.Key
		_, _ = rand.Read(secret[:])
		x448.KeyGen(&public, &secret)
		eccPub, eccPriv = public[:], secret[:]
	}

	return append(eccPub, pqPub...), append(eccPriv, pqPriv...), nil
}

func (h *hybridKEMAdapter) Encapsulate(pubKey []byte) ([]byte, []byte, error) {
	eccPubLen, _, _ := h.getECCLengths()
	if len(pubKey) < eccPubLen {
		return nil, nil, errors.New("invalid hybrid public key length")
	}

	peerEccPub := pubKey[:eccPubLen]
	peerPqPub := pubKey[eccPubLen:]

	// 1. Encapsulate Post-Quantum
	pqCT, pqSS, err := h.pqKEM.Encapsulate(peerPqPub)
	if err != nil {
		return nil, nil, err
	}

	// 2. Diffie-Hellman Ephemeral Exchange
	var eccCT, eccSS []byte
	if h.eccCurve == "X25519" {
		var ephemPriv, ephemPub, peerPub, shared x25519.Key
		_, _ = rand.Read(ephemPriv[:])
		x25519.KeyGen(&ephemPub, &ephemPriv)
		copy(peerPub[:], peerEccPub)
		x25519.Shared(&shared, &ephemPriv, &peerPub)
		eccCT, eccSS = ephemPub[:], shared[:]
	} else {
		var ephemPriv, ephemPub, peerPub, shared x448.Key
		_, _ = rand.Read(ephemPriv[:])
		x448.KeyGen(&ephemPub, &ephemPriv)
		copy(peerPub[:], peerEccPub)
		x448.Shared(&shared, &ephemPriv, &peerPub)
		eccCT, eccSS = ephemPub[:], shared[:]
	}

	finalCT := append(eccCT, pqCT...)

	// 3. Cryptographic Combiner: SHA3-512( ECC_SS || PQ_SS || CT )
	combiner := sha3.New512()
	combiner.Write(eccSS)
	combiner.Write(pqSS)
	combiner.Write(finalCT)
	finalSS := combiner.Sum(nil)

	return finalCT, finalSS, nil
}

func (h *hybridKEMAdapter) Decapsulate(ciphertext, privKey []byte) ([]byte, error) {
	_, eccPrivLen, eccCTLen := h.getECCLengths()

	if len(ciphertext) < eccCTLen || len(privKey) < eccPrivLen {
		return nil, errors.New("invalid hybrid ciphertext or private key length")
	}

	eccCT := ciphertext[:eccCTLen]
	pqCT := ciphertext[eccCTLen:]
	myEccPriv := privKey[:eccPrivLen]
	myPqPriv := privKey[eccPrivLen:]

	// 1. Decapsulate Post-Quantum
	pqSS, err := h.pqKEM.Decapsulate(pqCT, myPqPriv)
	if err != nil {
		return nil, err
	}

	// 2. Diffie-Hellman Resolution
	var eccSS []byte
	if h.eccCurve == "X25519" {
		var myPriv, peerPub, shared x25519.Key
		copy(myPriv[:], myEccPriv)
		copy(peerPub[:], eccCT)
		x25519.Shared(&shared, &myPriv, &peerPub)
		eccSS = shared[:]
	} else {
		var myPriv, peerPub, shared x448.Key
		copy(myPriv[:], myEccPriv)
		copy(peerPub[:], eccCT)
		x448.Shared(&shared, &myPriv, &peerPub)
		eccSS = shared[:]
	}

	// 3. Cryptographic Combiner
	combiner := sha3.New512()
	combiner.Write(eccSS)
	combiner.Write(pqSS)
	combiner.Write(ciphertext)
	finalSS := combiner.Sum(nil)

	return finalSS, nil
}

func (h *hybridKEMAdapter) Name() string {
	return "Hybrid-" + h.pqKEM.Name() + "+" + h.eccCurve
}

func (h *hybridKEMAdapter) PublicKeySize() int {
	eccPubLen, _, _ := h.getECCLengths()
	return eccPubLen + h.pqKEM.PublicKeySize()
}

func (h *hybridKEMAdapter) PrivateKeySize() int {
	_, eccPrivLen, _ := h.getECCLengths()
	return eccPrivLen + h.pqKEM.PrivateKeySize()
}

func (h *hybridKEMAdapter) CiphertextSize() int {
	_, _, eccCTLen := h.getECCLengths()
	return eccCTLen + h.pqKEM.CiphertextSize()
}

func (h *hybridKEMAdapter) SharedKeySize() int {
	// Our SHA3-512 combiner always outputs a 32-byte shared secret
	return 64
}
