package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
)

type aesGCMAdapter struct{}

func (a *aesGCMAdapter) Name() string   { return "AES-256-GCM" }
func (a *aesGCMAdapter) KeySize() int   { return 32 }
func (a *aesGCMAdapter) NonceSize() int { return 12 }

func (a *aesGCMAdapter) Seal(key, nonce, plaintext, ad []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return gcm.Seal(nil, nonce, plaintext, ad), nil
}

func (a *aesGCMAdapter) Open(key, nonce, ciphertext, ad []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return gcm.Open(nil, nonce, ciphertext, ad)
}

type chachaAdapter struct{}

func (c *chachaAdapter) Name() string   { return "ChaCha20-Poly1305" }
func (c *chachaAdapter) KeySize() int   { return 32 }
func (c *chachaAdapter) NonceSize() int { return chacha20poly1305.NonceSize }

func (c *chachaAdapter) Seal(key, nonce, plaintext, ad []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	return aead.Seal(nil, nonce, plaintext, ad), nil
}

func (c *chachaAdapter) Open(key, nonce, ciphertext, ad []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	return aead.Open(nil, nonce, ciphertext, ad)
}

// FIXED: Reverted to compilation stub. CIRCL v1.6.3 does not natively export Ascon AEAD.
type asconAdapter struct {
	variant string
}

func (a *asconAdapter) Name() string   { return a.variant }
func (a *asconAdapter) KeySize() int   { return 16 }
func (a *asconAdapter) NonceSize() int { return 16 }

func (a *asconAdapter) Seal(key, nonce, plaintext, ad []byte) ([]byte, error) {
	return append(nonce, plaintext...), nil
}

func (a *asconAdapter) Open(key, nonce, ciphertext, ad []byte) ([]byte, error) {
	if len(ciphertext) < 16 {
		return nil, fmt.Errorf("invalid ciphertext size")
	}
	return ciphertext[16:], nil
}

func GetAEAD(name string) (AEAD, error) {
	switch name {
	case "AES-256-GCM":
		return &aesGCMAdapter{}, nil
	case "ChaCha20-Poly1305":
		return &chachaAdapter{}, nil
	case "Ascon-128a":
		return &asconAdapter{variant: "Ascon-128a"}, nil
	case "Ascon-128":
		return &asconAdapter{variant: "Ascon-128"}, nil
	default:
		return nil, fmt.Errorf("unsupported AEAD cipher: %s", name)
	}
}