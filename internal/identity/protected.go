package identity

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/gh4rib/pqpg/internal/crypto"
	"golang.org/x/crypto/argon2"
)



// PlaintextKeyBundle represents the unencrypted cluster of private assets
type PlaintextKeyBundle struct {
	KEMPriv []byte `json:"kem_priv"`
	DSAPriv []byte `json:"dsa_priv"`
}

// EncryptedKeyContainer matches the structured binary layout stored on disk
type EncryptedKeyContainer struct {
	AEADSuite  string `json:"aead_suite"`
	Salt       []byte `json:"salt"`
	Nonce      []byte `json:"nonce"`
	Ciphertext []byte `json:"ciphertext"`
}

// derivePassphraseKey dynamically stretches a password based on the required cipher key length.
func derivePassphraseKey(password string, salt []byte, keyLen uint32) []byte {
	// RFC 9106 High-Security / OWASP Aggressive Parameters
	var time uint32 = 3            
	var memory uint32 = 256 * 1024 
	var threads uint8 = 4          

	return argon2.IDKey([]byte(password), salt, time, memory, threads, keyLen)
}

// EncryptAndArmorKeys packs subkeys, encrypts them dynamically, and applies ASCII framing
func EncryptAndArmorKeys(kemPriv, dsaPriv []byte, password, aeadSuite string) (string, error) {
	registry := crypto.NewRegistry()
	aead, err := registry.GetAEAD(aeadSuite)
	if err != nil {
		return "", fmt.Errorf("invalid cipher suite for key protection: %w", err)
	}

	salt := make([]byte, 16)
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}

	bundle := PlaintextKeyBundle{KEMPriv: kemPriv, DSAPriv: dsaPriv}
	plaintext, err := json.Marshal(bundle)
	if err != nil {
		return "", err
	}

	// Dynamically size the key based on the cipher (32 bytes for AES/ChaCha, 16 for Ascon)
	derivedKey := derivePassphraseKey(password, salt, uint32(aead.KeySize()))

	ciphertext, err := aead.Seal(derivedKey, nonce, plaintext, nil)
	if err != nil {
		return "", fmt.Errorf("encryption failed: %w", err)
	}

	container := EncryptedKeyContainer{
		AEADSuite:  aeadSuite,
		Salt:       salt,
		Nonce:      nonce,
		Ciphertext: ciphertext,
	}
	containerBytes, err := json.Marshal(container)
	if err != nil {
		return "", err
	}

	encodedBody := base64.StdEncoding.EncodeToString(containerBytes)

	var armoredBuilder strings.Builder
	armoredBuilder.WriteString(ArmorHeader + "\n")

	for i := 0; i < len(encodedBody); i += 64 {
		end := i + 64
		if end > len(encodedBody) {
			end = len(encodedBody)
		}
		armoredBuilder.WriteString(encodedBody[i:end] + "\n")
	}
	armoredBuilder.WriteString(ArmorFooter)

	return armoredBuilder.String(), nil
}

// DecryptArmoredKeys ingests an armored text block and restores raw private key states
func DecryptArmoredKeys(armoredText, password string) ([]byte, []byte, error) {
	cleaned := strings.ReplaceAll(armoredText, ArmorHeader, "")
	cleaned = strings.ReplaceAll(cleaned, ArmorFooter, "")
	cleaned = strings.ReplaceAll(cleaned, "\n", "")
	cleaned = strings.ReplaceAll(cleaned, "\r", "")
	cleaned = strings.TrimSpace(cleaned)

	containerBytes, err := base64.StdEncoding.DecodeString(cleaned)
	if err != nil {
		return nil, nil, fmt.Errorf("malformed armor encryption padding: %v", err)
	}

	var container EncryptedKeyContainer
	if err := json.Unmarshal(containerBytes, &container); err != nil {
		return nil, nil, err
	}

	// Backwards compatibility for older private keys that didn't tag the suite
	if container.AEADSuite == "" {
		container.AEADSuite = "AES-256-GCM"
	}

	registry := crypto.NewRegistry()
	aead, err := registry.GetAEAD(container.AEADSuite)
	if err != nil {
		return nil, nil, fmt.Errorf("unsupported cipher suite found in protected key: %w", err)
	}

	derivedKey := derivePassphraseKey(password, container.Salt, uint32(aead.KeySize()))

	plaintext, err := aead.Open(derivedKey, container.Nonce, container.Ciphertext, nil)
	if err != nil {
		return nil, nil, errors.New("authentication failed: invalid key decryption passphrase or corrupt file")
	}

	var bundle PlaintextKeyBundle
	if err := json.Unmarshal(plaintext, &bundle); err != nil {
		return nil, nil, err
	}

	return bundle.KEMPriv, bundle.DSAPriv, nil
}