package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/subtle"
	"encoding/binary"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/sha3"

	// Misuse-Resistant Packages
	sivAsm "github.com/gh4rib/pqpg/internal/aesgcmsiv-asm"
	sivNoAsm "github.com/gh4rib/pqpg/internal/aesgcmsiv-noasm"
	"github.com/gh4rib/pqpg/internal/deoxysii"

	// Custom EtM Targets
	"github.com/gh4rib/pqpg/internal/camellia"
	"github.com/gh4rib/pqpg/internal/serpent"

	// The Skein Wide-Block Engine
	"github.com/gh4rib/pqpg/internal/threefish"

	// NIST LWC Winner
	"github.com/cloudflare/circl/cipher/ascon"
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
func (a *aesGCMSIVAdapter) NonceSize() int { return 12 }

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

func (a *aesSIVCMACAdapter) Name() string   { return "AES-256-SIV-CMAC" }
func (a *aesSIVCMACAdapter) KeySize() int   { return 64 }
func (a *aesSIVCMACAdapter) NonceSize() int { return 16 }

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
func (a *deoxysIIAdapter) KeySize() int   { return 32 }
func (a *deoxysIIAdapter) NonceSize() int { return 15 }

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

// --- ULTRA-SECURE ENCRYPT-THEN-MAC (EtM) WRAPPER ---
type etmCTRAdapter struct {
	name      string
	newCipher func([]byte) (cipher.Block, error)
}

func (a *etmCTRAdapter) Name() string   { return a.name }
func (a *etmCTRAdapter) KeySize() int   { return 64 } // 32 for Encryption (CTR), 32 for MAC
func (a *etmCTRAdapter) NonceSize() int { return 16 } // Block size for Camellia/Serpent is 16 bytes

func (a *etmCTRAdapter) Seal(key, nonce, plaintext, ad []byte) ([]byte, error) {
	if len(key) != 64 {
		return nil, fmt.Errorf("etm: invalid key size, expected 64 bytes")
	}
	if len(nonce) != 16 {
		return nil, fmt.Errorf("etm: invalid nonce size, expected 16 bytes")
	}
	encKey := key[:32]
	macKey := key[32:]

	block, err := a.newCipher(encKey)
	if err != nil {
		return nil, err
	}

	ciphertext := make([]byte, len(plaintext))
	stream := cipher.NewCTR(block, nonce)
	stream.XORKeyStream(ciphertext, plaintext)

	mac := hmac.New(sha3.New512, macKey)
	lenBuf := make([]byte, 8)
	binary.LittleEndian.PutUint64(lenBuf, uint64(len(ad)*8))
	mac.Write(lenBuf)
	mac.Write(ad)
	mac.Write(nonce)
	mac.Write(ciphertext)
	tag := mac.Sum(nil)

	return append(ciphertext, tag...), nil
}

func (a *etmCTRAdapter) Open(key, nonce, ciphertext, ad []byte) ([]byte, error) {
	if len(key) != 64 {
		return nil, fmt.Errorf("etm: invalid key size, expected 64 bytes")
	}
	if len(nonce) != 16 {
		return nil, fmt.Errorf("etm: invalid nonce size, expected 16 bytes")
	}
	encKey := key[:32]
	macKey := key[32:]

	if len(ciphertext) < 64 {
		return nil, fmt.Errorf("etm: ciphertext too short")
	}

	actualCiphertext := ciphertext[:len(ciphertext)-64]
	expectedTag := ciphertext[len(ciphertext)-64:]

	mac := hmac.New(sha3.New512, macKey)
	lenBuf := make([]byte, 8)
	binary.LittleEndian.PutUint64(lenBuf, uint64(len(ad)*8))
	mac.Write(lenBuf)
	mac.Write(ad)
	mac.Write(nonce)
	mac.Write(actualCiphertext)
	actualTag := mac.Sum(nil)

	if subtle.ConstantTimeCompare(expectedTag, actualTag) != 1 {
		return nil, fmt.Errorf("etm: message authentication failed")
	}

	block, err := a.newCipher(encKey)
	if err != nil {
		return nil, err
	}

	plaintext := make([]byte, len(actualCiphertext))
	stream := cipher.NewCTR(block, nonce)
	stream.XORKeyStream(plaintext, actualCiphertext)

	return plaintext, nil
}

// --- THREEFISH WIDE-BLOCK EtM WRAPPER ---
type threefishEtMAdapter struct {
	name      string
	tfKeySize int
	tfBlock   int
	newCipher func(key, tweak []byte) (cipher.Block, error)
}

func (a *threefishEtMAdapter) Name() string   { return a.name }
func (a *threefishEtMAdapter) KeySize() int   { return a.tfKeySize + 32 } // Core Key + 32-byte MAC Key
func (a *threefishEtMAdapter) NonceSize() int { return a.tfBlock }        // CTR mode demands Nonce == Block Size

func (a *threefishEtMAdapter) Seal(key, nonce, plaintext, ad []byte) ([]byte, error) {
	if len(key) != a.KeySize() {
		return nil, fmt.Errorf("threefish: invalid key size")
	}
	if len(nonce) != a.NonceSize() {
		return nil, fmt.Errorf("threefish: invalid nonce size")
	}

	encKey := key[:a.tfKeySize]
	macKey := key[a.tfKeySize:]

	// Use a static domain separator for the tweak
	tweak := []byte("PQPG-Threefish--")

	block, err := a.newCipher(encKey, tweak)
	if err != nil {
		return nil, err
	}

	ciphertext := make([]byte, len(plaintext))
	stream := cipher.NewCTR(block, nonce)
	stream.XORKeyStream(ciphertext, plaintext)

	mac := hmac.New(sha3.New512, macKey)
	lenBuf := make([]byte, 8)
	binary.LittleEndian.PutUint64(lenBuf, uint64(len(ad)*8))
	mac.Write(lenBuf)
	mac.Write(ad)
	mac.Write(nonce)
	mac.Write(ciphertext)
	tag := mac.Sum(nil)

	return append(ciphertext, tag...), nil
}

func (a *threefishEtMAdapter) Open(key, nonce, ciphertext, ad []byte) ([]byte, error) {
	if len(key) != a.KeySize() {
		return nil, fmt.Errorf("threefish: invalid key size")
	}
	if len(nonce) != a.NonceSize() {
		return nil, fmt.Errorf("threefish: invalid nonce size")
	}
	if len(ciphertext) < 64 {
		return nil, fmt.Errorf("threefish: ciphertext too short")
	}

	encKey := key[:a.tfKeySize]
	macKey := key[a.tfKeySize:]

	actualCiphertext := ciphertext[:len(ciphertext)-64]
	expectedTag := ciphertext[len(ciphertext)-64:]

	mac := hmac.New(sha3.New512, macKey)
	lenBuf := make([]byte, 8)
	binary.LittleEndian.PutUint64(lenBuf, uint64(len(ad)*8))
	mac.Write(lenBuf)
	mac.Write(ad)
	mac.Write(nonce)
	mac.Write(actualCiphertext)
	actualTag := mac.Sum(nil)

	if subtle.ConstantTimeCompare(expectedTag, actualTag) != 1 {
		return nil, fmt.Errorf("threefish: message authentication failed")
	}

	tweak := []byte("PQPG-Threefish--")
	block, err := a.newCipher(encKey, tweak)
	if err != nil {
		return nil, err
	}

	plaintext := make([]byte, len(actualCiphertext))
	stream := cipher.NewCTR(block, nonce)
	stream.XORKeyStream(plaintext, actualCiphertext)

	return plaintext, nil
}

// --- ASCON (FULLY IMPLEMENTED AEAD VIA CIRCL) ---
type asconAdapter struct {
	variant string
}

func (a *asconAdapter) Name() string { return a.variant }

func (a *asconAdapter) KeySize() int {
	// Ascon-80pq uses a 160-bit (20-byte) key for Grover's quantum resistance
	if a.variant == "Ascon-80pq" {
		return 20
	}
	// Ascon-128 and Ascon-128a use standard 128-bit (16-byte) keys
	return 16
}

func (a *asconAdapter) NonceSize() int { return 16 }

func (a *asconAdapter) Seal(key, nonce, plaintext, ad []byte) ([]byte, error) {
	if len(key) != a.KeySize() {
		return nil, fmt.Errorf("ascon: invalid key size, expected %d bytes", a.KeySize())
	}
	if len(nonce) != 16 {
		return nil, fmt.Errorf("ascon: invalid nonce size, expected 16 bytes")
	}

	var aead cipher.AEAD
	var err error

	switch a.variant {
	case "Ascon-128a":
		aead, err = ascon.New(key, ascon.Ascon128a)
	case "Ascon-80pq":
		aead, err = ascon.New(key, ascon.Ascon80pq)
	default:
		aead, err = ascon.New(key, ascon.Ascon128)
	}

	if err != nil {
		return nil, err
	}

	return aead.Seal(nil, nonce, plaintext, ad), nil
}

func (a *asconAdapter) Open(key, nonce, ciphertext, ad []byte) ([]byte, error) {
	if len(key) != a.KeySize() {
		return nil, fmt.Errorf("ascon: invalid key size, expected %d bytes", a.KeySize())
	}
	if len(nonce) != 16 {
		return nil, fmt.Errorf("ascon: invalid nonce size, expected 16 bytes")
	}

	var aead cipher.AEAD
	var err error

	switch a.variant {
	case "Ascon-128a":
		aead, err = ascon.New(key, ascon.Ascon128a)
	case "Ascon-80pq":
		aead, err = ascon.New(key, ascon.Ascon80pq)
	default:
		aead, err = ascon.New(key, ascon.Ascon128)
	}

	if err != nil {
		return nil, err
	}

	return aead.Open(nil, nonce, ciphertext, ad)
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
	case "Camellia-256-EtM":
		return &etmCTRAdapter{
			name:      "Camellia-256-EtM",
			newCipher: camellia.NewCipher,
		}, nil
	case "Serpent-256-EtM":
		return &etmCTRAdapter{
			name:      "Serpent-256-EtM",
			newCipher: serpent.NewCipher,
		}, nil
	case "Threefish-256-EtM":
		return &threefishEtMAdapter{
			name:      "Threefish-256-EtM",
			tfKeySize: 32,
			tfBlock:   32,
			newCipher: threefish.New256,
		}, nil
	case "Threefish-512-EtM":
		return &threefishEtMAdapter{
			name:      "Threefish-512-EtM",
			tfKeySize: 64,
			tfBlock:   64,
			newCipher: threefish.New512,
		}, nil
	case "Threefish-1024-EtM":
		return &threefishEtMAdapter{
			name:      "Threefish-1024-EtM",
			tfKeySize: 128,
			tfBlock:   128,
			newCipher: threefish.New1024,
		}, nil
	case "Ascon-128a":
		return &asconAdapter{variant: "Ascon-128a"}, nil
	case "Ascon-128":
		return &asconAdapter{variant: "Ascon-128"}, nil
	case "Ascon-80pq": // <<< NEW ASCON-80pq INTEGRATION
		return &asconAdapter{variant: "Ascon-80pq"}, nil
	default:
		return nil, fmt.Errorf("unsupported AEAD cipher: %s", name)
	}
}
