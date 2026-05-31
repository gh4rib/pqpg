package crypto

import (
	"io"

	"github.com/cloudflare/circl/xof/k12"
	"golang.org/x/crypto/sha3"
)

type shakeAdapter struct {
	variant string // "SHAKE128" or "SHAKE256"
}

func (s *shakeAdapter) Name() string { return s.variant }

func (s *shakeAdapter) Derive(input []byte, outputSize int) []byte {
	// Reverted to legacy camelCase naming as requested by the x/crypto compiler
	var hasher sha3.ShakeHash
	if s.variant == "SHAKE128" {
		hasher = sha3.NewShake128()
	} else {
		hasher = sha3.NewShake256()
	}
	hasher.Write(input)
	out := make([]byte, outputSize)
	_, _ = hasher.Read(out)
	return out
}

func (s *shakeAdapter) NewWriter() io.Writer {
	if s.variant == "SHAKE128" {
		return sha3.NewShake128()
	}
	return sha3.NewShake256()
}

type sha3StandardAdapter struct {
	variant string // "SHA3-256", "SHA3-384", "SHA3-512"
}

func (s *sha3StandardAdapter) Name() string { return s.variant }

func (s *sha3StandardAdapter) Derive(input []byte, outputSize int) []byte {
	var h []byte
	switch s.variant {
	case "SHA3-384":
		state := sha3.New384()
		state.Write(input)
		h = state.Sum(nil)
	case "SHA3-512":
		state := sha3.New512()
		state.Write(input)
		h = state.Sum(nil)
	default:
		state := sha3.New256()
		state.Write(input)
		h = state.Sum(nil)
	}

	out := make([]byte, outputSize)
	copy(out, h)
	return out
}

func (s *sha3StandardAdapter) NewWriter() io.Writer {
	switch s.variant {
	case "SHA3-384":
		return sha3.New384()
	case "SHA3-512":
		return sha3.New512()
	default:
		return sha3.New256()
	}
}

type k12Adapter struct{}

func (k *k12Adapter) Name() string { return "KangarooTwelve" }

func (k *k12Adapter) Derive(input []byte, outputSize int) []byte {
	h := k12.NewDraft10([]byte{})
	h.Write(input)
	out := make([]byte, outputSize)
	_, _ = h.Read(out)
	return out
}

func (k *k12Adapter) NewWriter() io.Writer {
	h := k12.NewDraft10([]byte{})
	return &h
}