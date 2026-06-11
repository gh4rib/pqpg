package crypto

import (
	"hash"
	"io"

	"crypto/sha512"

	"github.com/cloudflare/circl/xof/k12"
	"golang.org/x/crypto/sha3"
)

// ---------------------------------------------------------
// Standard SHA-2 Adapter (Fixed Hash)
// ---------------------------------------------------------
type sha2Adapter struct {
	hasher hash.Hash
}

func (s *sha2Adapter) Name() string { return "SHA-512" }

func (s *sha2Adapter) init() {
	if s.hasher == nil {
		s.hasher = sha512.New()
	}
}

func (s *sha2Adapter) Write(p []byte) (n int, err error) {
	s.init()
	return s.hasher.Write(p)
}

func (s *sha2Adapter) Derive(input []byte, outputSize int) []byte {
	s.init()
	if len(input) > 0 {
		s.hasher.Write(input)
	}

	h := s.hasher.Sum(nil)
	out := make([]byte, outputSize)

	if outputSize <= len(h) {
		copy(out, h)
	} else {
		// CRITICAL FIX: Securely stretch entropy to prevent zero-padding on massive keys
		shake := sha3.NewShake256()
		shake.Write(h)
		shake.Read(out)
	}

	s.hasher = nil
	return out
}

func (s *sha2Adapter) NewWriter() io.Writer {
	s.init()
	return s.hasher
}

// ---------------------------------------------------------
// SHAKE Adapter (XOF)
// ---------------------------------------------------------
type shakeAdapter struct {
	variant string
	hasher  sha3.ShakeHash
}

func (s *shakeAdapter) Name() string { return s.variant }

func (s *shakeAdapter) init() {
	if s.hasher == nil {
		if s.variant == "SHAKE128" {
			s.hasher = sha3.NewShake128()
		} else {
			s.hasher = sha3.NewShake256()
		}
	}
}

func (s *shakeAdapter) Write(p []byte) (n int, err error) {
	s.init()
	return s.hasher.Write(p)
}

func (s *shakeAdapter) Derive(input []byte, outputSize int) []byte {
	s.init()
	if len(input) > 0 {
		s.hasher.Write(input)
	}
	out := make([]byte, outputSize)
	_, _ = s.hasher.Read(out)

	s.hasher = nil // Reset state to ensure Ratchet KDF remains isolated
	return out
}

func (s *shakeAdapter) NewWriter() io.Writer {
	s.init()
	return s.hasher
}

// ---------------------------------------------------------
// Standard SHA-3 Adapter (Fixed Hash)
// ---------------------------------------------------------
type sha3StandardAdapter struct {
	variant string
	hasher  hash.Hash
}

func (s *sha3StandardAdapter) Name() string { return s.variant }

func (s *sha3StandardAdapter) init() {
	if s.hasher == nil {
		switch s.variant {
		case "SHA3-384":
			s.hasher = sha3.New384()
		case "SHA3-512":
			s.hasher = sha3.New512()
		default:
			s.hasher = sha3.New256()
		}
	}
}

func (s *sha3StandardAdapter) Write(p []byte) (n int, err error) {
	s.init()
	return s.hasher.Write(p)
}

func (s *sha3StandardAdapter) Derive(input []byte, outputSize int) []byte {
	s.init()
	if len(input) > 0 {
		s.hasher.Write(input)
	}

	h := s.hasher.Sum(nil)
	out := make([]byte, outputSize)

	if outputSize <= len(h) {
		copy(out, h)
	} else {
		// CRITICAL FIX: Securely stretch entropy to prevent zero-padding on massive keys
		shake := sha3.NewShake256()
		shake.Write(h)
		shake.Read(out)
	}

	s.hasher = nil // Reset state
	return out
}

func (s *sha3StandardAdapter) NewWriter() io.Writer {
	s.init()
	return s.hasher
}

// ---------------------------------------------------------
// KangarooTwelve Adapter (XOF)
// ---------------------------------------------------------
type k12Adapter struct {
	hasher interface {
		io.Writer
		io.Reader
	}
}

func (k *k12Adapter) Name() string { return "KangarooTwelve" }

func (k *k12Adapter) init() {
	if k.hasher == nil {
		h := k12.NewDraft10([]byte{})
		k.hasher = &h
	}
}

func (k *k12Adapter) Write(p []byte) (n int, err error) {
	k.init()
	return k.hasher.Write(p)
}

func (k *k12Adapter) Derive(input []byte, outputSize int) []byte {
	k.init()
	if len(input) > 0 {
		k.hasher.Write(input)
	}

	out := make([]byte, outputSize)
	_, _ = k.hasher.Read(out)

	k.hasher = nil // Reset state
	return out
}

func (k *k12Adapter) NewWriter() io.Writer {
	k.init()
	return k.hasher
}
