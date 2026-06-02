package crypto

import "io"

// KEM defines the contract for Key Encapsulation Mechanisms (both standard and hybrid).
type KEM interface {
	Name() string
	PublicKeySize() int
	PrivateKeySize() int
	CiphertextSize() int
	SharedKeySize() int // FIXED: Renamed to match CIRCL's API

	GenerateKeyPair() (pub, priv []byte, err error)
	Encapsulate(pubKey []byte) (ciphertext, sharedSecret []byte, err error)
	Decapsulate(ciphertext, privKey []byte) (sharedSecret []byte, err error)
}

// DSA defines the contract for Digital Signature Schemes.
type DSA interface {
	Name() string
	PublicKeySize() int
	PrivateKeySize() int
	SignatureSize() int

	GenerateKeyPair() (pub, priv []byte, err error)
	Sign(privKey, message []byte) (signature []byte, err error)
	Verify(pubKey, message, signature []byte) bool
}

// AEAD defines the unified block and lightweight authenticated encryption contract.
type AEAD interface {
	Name() string
	KeySize() int
	NonceSize() int

	Seal(key, nonce, plaintext, additionalData []byte) ([]byte, error)
	Open(key, nonce, ciphertext, additionalData []byte) ([]byte, error)
}

type XOF interface {
	Name() string
	Write(p []byte) (n int, err error)           // ADD THIS: Allows continuous chunk streaming
	Derive(input []byte, outputSize int) []byte  
	NewWriter() io.Writer
}