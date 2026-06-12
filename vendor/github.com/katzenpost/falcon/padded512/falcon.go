// SPDX-FileCopyrightText: (c) 2026 David Stainton
// SPDX-License-Identifier: MIT

// Package padded512 wraps the PQClean Falcon-padded-512 reference C
// implementation. Signatures are emitted in the padded encoding and
// always have length SignatureSize (666); public keys and private keys
// are likewise fixed-length.
//
// The vendored C is the PQCLEAN_FALCONPADDED512_CLEAN variant, MIT
// licensed by the Falcon Project; see LICENSE alongside the C sources
// in this directory.
package padded512

// #cgo CFLAGS: -O3 -fomit-frame-pointer -include namespace.h
// #include "api.h"
import "C"

import (
	"errors"
	"unsafe"
)

// AlgName is the PQClean algorithm identifier.
const AlgName = "Falcon-padded-512"

const (
	// PublicKeySize is the fixed Falcon-padded-512 public key length in bytes.
	PublicKeySize = C.PQCLEAN_FALCONPADDED512_CLEAN_CRYPTO_PUBLICKEYBYTES

	// PrivateKeySize is the fixed Falcon-padded-512 private key length in bytes.
	PrivateKeySize = C.PQCLEAN_FALCONPADDED512_CLEAN_CRYPTO_SECRETKEYBYTES

	// SignatureSize is the fixed Falcon-padded-512 signature length in bytes.
	SignatureSize = C.PQCLEAN_FALCONPADDED512_CLEAN_CRYPTO_BYTES
)

var (
	ErrKeygen = errors.New("falcon-padded-512: key generation failed")
	ErrSign   = errors.New("falcon-padded-512: signing failed")
	ErrSize   = errors.New("falcon-padded-512: input has wrong size")
)

// PublicKey is a Falcon-padded-512 public key.
type PublicKey [PublicKeySize]byte

// PrivateKey is a Falcon-padded-512 private key.
type PrivateKey [PrivateKeySize]byte

// GenerateKey returns a fresh Falcon-padded-512 keypair. Randomness is
// drawn from PQClean's internal SHAKE256 PRNG, which seeds itself from
// the operating system entropy source.
func GenerateKey() (PublicKey, PrivateKey, error) {
	var pk PublicKey
	var sk PrivateKey
	r := C.PQCLEAN_FALCONPADDED512_CLEAN_crypto_sign_keypair(
		(*C.uint8_t)(unsafe.Pointer(&pk[0])),
		(*C.uint8_t)(unsafe.Pointer(&sk[0])),
	)
	if r != 0 {
		return PublicKey{}, PrivateKey{}, ErrKeygen
	}
	return pk, sk, nil
}

// Sign signs message with sk and returns the fixed-length padded
// signature.
func Sign(sk *PrivateKey, message []byte) ([]byte, error) {
	sig := make([]byte, SignatureSize)
	var sigLen C.size_t
	var mPtr *C.uint8_t
	if len(message) > 0 {
		mPtr = (*C.uint8_t)(unsafe.Pointer(&message[0]))
	}
	r := C.PQCLEAN_FALCONPADDED512_CLEAN_crypto_sign_signature(
		(*C.uint8_t)(unsafe.Pointer(&sig[0])), &sigLen,
		mPtr, C.size_t(len(message)),
		(*C.uint8_t)(unsafe.Pointer(&sk[0])),
	)
	if r != 0 {
		return nil, ErrSign
	}
	if int(sigLen) != SignatureSize {
		return nil, errors.New("falcon-padded-512: unexpected signature length from PQClean")
	}
	return sig, nil
}

// Verify reports whether sig is a valid Falcon-padded-512 signature
// over message under pk.
func Verify(pk *PublicKey, message, sig []byte) bool {
	if len(sig) != SignatureSize {
		return false
	}
	var mPtr *C.uint8_t
	if len(message) > 0 {
		mPtr = (*C.uint8_t)(unsafe.Pointer(&message[0]))
	}
	r := C.PQCLEAN_FALCONPADDED512_CLEAN_crypto_sign_verify(
		(*C.uint8_t)(unsafe.Pointer(&sig[0])), C.size_t(len(sig)),
		mPtr, C.size_t(len(message)),
		(*C.uint8_t)(unsafe.Pointer(&pk[0])),
	)
	return r == 0
}
