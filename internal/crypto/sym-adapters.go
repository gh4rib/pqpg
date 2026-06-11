package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"

	// Your internal MISUSE-RESISTANT packages
	sivAsm "github.com/gh4rib/pqpg/internal/aesgcmsiv-asm"
	sivNoAsm "github.com/gh4rib/pqpg/internal/aesgcmsiv-noasm"

	// CAESAR Winner
	"github.com/gh4rib/pqpg/internal/deoxysii"
)

// --- STANDARD AES-GCM (12-Byte Nonce) ---
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

// --- EXTENDED XAES-GCM (24-Byte Nonce) ---
type xaesGCMAdapter struct{}

func (a *xaesGCMAdapter) Name() string   { return "XAES-256-GCM" }
func (a *xaesGCMAdapter) KeySize() int   { return XAESKeySize }
func (a *xaesGCMAdapter) NonceSize() int { return XAESNonceSize }

func (a *xaesGCMAdapter) Seal(key, nonce, plaintext, ad []byte) ([]byte, error) {
	aead, err := NewXAES256GCM(key)
	if err != nil {
		return nil, err
	}
	return aead.Seal(nil, nonce, plaintext, ad), nil
}

func (a *xaesGCMAdapter) Open(key, nonce, ciphertext, ad []byte) ([]byte, error) {
	aead, err := NewXAES256GCM(key)
	if err != nil {
		return nil, err
	}
	return aead.Open(nil, nonce, ciphertext, ad)
}

// --- MISUSE-RESISTANT AES-GCM-SIV (RFC 8452 - NO ASM) ---
type aesGCMSIVAdapter struct{}

func (a *aesGCMSIVAdapter) Name() string   { return "AES-256-GCM-SIV" }
func (a *aesGCMSIVAdapter) KeySize() int   { return 32 }
func (a *aesGCMSIVAdapter) NonceSize() int { return 12 } // SIV natively takes a 12-byte nonce

func (a *aesGCMSIVAdapter) Seal(key, nonce, plaintext, ad []byte) ([]byte, error) {
	aead, err := sivNoAsm.New(key)
	if err != nil {
		return nil, err
	}
	return aead.Seal(nil, nonce, plaintext, ad), nil
}

func (a *aesGCMSIVAdapter) Open(key, nonce, ciphertext, ad []byte) ([]byte, error) {
	aead, err := sivNoAsm.New(key)
	if err != nil {
		return nil, err
	}
	return aead.Open(nil, nonce, ciphertext, ad)
}

// --- DETERMINISTIC AES-SIV-CMAC (ASM ACCELERATED) ---
type aesSIVCMACAdapter struct{}

func (a *aesSIVCMACAdapter) Name() string { return "AES-256-SIV-CMAC" }

// Requires 64 bytes total (32 for MAC, 32 for CTR) to maintain AES-256 security bounds
func (a *aesSIVCMACAdapter) KeySize() int   { return 64 }
func (a *aesSIVCMACAdapter) NonceSize() int { return 16 } // Allows random or deterministic initialization

func (a *aesSIVCMACAdapter) Seal(key, nonce, plaintext, ad []byte) ([]byte, error) {
	aessiv, err := sivAsm.NewCMAC(key)
	if err != nil {
		return nil, err
	}
	return aessiv.Seal(nil, nonce, plaintext, ad), nil
}

func (a *aesSIVCMACAdapter) Open(key, nonce, ciphertext, ad []byte) ([]byte, error) {
	aessiv, err := sivAsm.NewCMAC(key)
	if err != nil {
		return nil, err
	}
	return aessiv.Open(nil, nonce, ciphertext, ad)
}

// --- CAESAR WINNER: DEOXYS-II (MISUSE-RESISTANT) ---
type deoxysIIAdapter struct{}

func (a *deoxysIIAdapter) Name() string   { return "Deoxys-II-256-128" }
func (a *deoxysIIAdapter) KeySize() int   { return 32 } // deoxysii.KeySize
func (a *deoxysIIAdapter) NonceSize() int { return 15 } // deoxysii.NonceSize

func (a *deoxysIIAdapter) Seal(key, nonce, plaintext, ad []byte) ([]byte, error) {
	aead, err := deoxysii.New(key)
	if err != nil {
		return nil, err
	}
	return aead.Seal(nil, nonce, plaintext, ad), nil
}

func (a *deoxysIIAdapter) Open(key, nonce, ciphertext, ad []byte) ([]byte, error) {
	aead, err := deoxysii.New(key)
	if err != nil {
		return nil, err
	}
	return aead.Open(nil, nonce, ciphertext, ad)
}

// --- STANDARD CHACHA20-POLY1305 (12-Byte Nonce) ---
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

// --- EXTENDED XCHACHA20-POLY1305 (24-Byte Nonce) ---
type xChachaAdapter struct{}

func (c *xChachaAdapter) Name() string   { return "XChaCha20-Poly1305" }
func (c *xChachaAdapter) KeySize() int   { return 32 }
func (c *xChachaAdapter) NonceSize() int { return chacha20poly1305.NonceSizeX }

func (c *xChachaAdapter) Seal(key, nonce, plaintext, ad []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	return aead.Seal(nil, nonce, plaintext, ad), nil
}

func (c *xChachaAdapter) Open(key, nonce, ciphertext, ad []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	return aead.Open(nil, nonce, ciphertext, ad)
}

// --- ASCON (Lightweight Stub) ---
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

// --- FACTORY ENGINE ---
func GetAEAD(name string) (AEAD, error) {
	switch name {
	case "AES-256-GCM":
		return &aesGCMAdapter{}, nil
	case "XAES-256-GCM":
		return &xaesGCMAdapter{}, nil
	case "AES-256-GCM-SIV":
		return &aesGCMSIVAdapter{}, nil
	case "AES-256-SIV-CMAC":
		return &aesSIVCMACAdapter{}, nil
	case "Deoxys-II-256-128":
		return &deoxysIIAdapter{}, nil
	case "ChaCha20-Poly1305":
		return &chachaAdapter{}, nil
	case "XChaCha20-Poly1305":
		return &xChachaAdapter{}, nil
	case "Ascon-128a":
		return &asconAdapter{variant: "Ascon-128a"}, nil
	case "Ascon-128":
		return &asconAdapter{variant: "Ascon-128"}, nil
	default:
		return nil, fmt.Errorf("unsupported AEAD cipher: %s", name)
	}
}
