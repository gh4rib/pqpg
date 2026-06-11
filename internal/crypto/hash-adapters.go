package crypto

import (
	"crypto/sha512"
	"hash"
	"io"

	"github.com/cloudflare/circl/xof/k12"
	"golang.org/x/crypto/sha3"

	// SKEIN NATIVE IMPORTS (Separated by Block Size)
	"github.com/gh4rib/pqpg/internal/skein"
	"github.com/gh4rib/pqpg/internal/skein/skein1024"
	"github.com/gh4rib/pqpg/internal/skein/skein256"
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

// ---------------------------------------------------------
// Skein Adapter (UBI Chaining / Threefish Core)
// ---------------------------------------------------------
type skeinAdapter struct {
	variant string
	hasher  hash.Hash
}

func (s *skeinAdapter) Name() string { return s.variant }

func (s *skeinAdapter) init() {
	if s.hasher == nil {
		switch s.variant {
		case "Skein-256":
			// Uses the native New constructor: 32 bytes = 256 bits
			s.hasher = skein256.New(32, nil)
		case "Skein-1024":
			// Uses the native New constructor: 128 bytes = 1024 bits
			s.hasher = skein1024.New(128, nil)
		default:
			// Skein-512 is the default recommended standard
			s.hasher = skein.New512(nil)
		}
	}
}

func (s *skeinAdapter) Write(p []byte) (n int, err error) {
	s.init()
	return s.hasher.Write(p)
}

func (s *skeinAdapter) Derive(input []byte, outputSize int) []byte {
	s.init()
	if len(input) > 0 {
		s.hasher.Write(input)
	}

	h := s.hasher.Sum(nil)
	out := make([]byte, outputSize)

	if outputSize <= len(h) {
		copy(out, h)
	} else {
		// Securely stretch entropy for massive keys (e.g. Threefish-1024 keys)
		shake := sha3.NewShake256()
		shake.Write(h)
		shake.Read(out)
	}

	s.hasher = nil // Reset state
	return out
}

func (s *skeinAdapter) NewWriter() io.Writer {
	s.init()
	return s.hasher
}
