package identity

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

const (
	KdfIterations = 100000 // High iteration count to prevent brute-force attacks
	ArmorHeader   = "-----BEGIN PQPG PROTECTED PRIVATE KEY-----"
	ArmorFooter   = "-----END PQPG PROTECTED PRIVATE KEY-----"
)

// PlaintextKeyBundle represents the unencrypted cluster of private assets
type PlaintextKeyBundle struct {
	KEMPriv []byte `json:"kem_priv"`
	DSAPriv []byte `json:"dsa_priv"`
}

// EncryptedKeyContainer matches the structured binary layout stored on disk
type EncryptedKeyContainer struct {
	Salt       []byte `json:"salt"`
	Nonce      []byte `json:"nonce"`
	Ciphertext []byte `json:"ciphertext"`
}

// derivePassphraseKey stretches a user password into a post-quantum secure 32-byte AES key
func derivePassphraseKey(password string, salt []byte) []byte {
	pwdBytes := []byte(password)
	mac := hmac.New(sha512.New, pwdBytes)
	mac.Write(salt)
	currentHash := mac.Sum(nil)

	// Perform computationally intense key stretching loop
	for i := 1; i < KdfIterations; i++ {
		mac.Reset()
		mac.Write(currentHash)
		currentHash = mac.Sum(nil)
	}
	// Return the first 32 bytes for an unbreakable AES-256 key configuration
	return currentHash[:32]
}

// EncryptAndArmorKeys packs subkeys, encrypts them via AES-GCM, and applies ASCII framing
func EncryptAndArmorKeys(kemPriv, dsaPriv []byte, password string) (string, error) {
	salt := make([]byte, 16)
	nonce := make([]byte, 12)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}

	// 1. Serialize keys into a single plaintext payload
	bundle := PlaintextKeyBundle{KEMPriv: kemPriv, DSAPriv: dsaPriv}
	plaintext, err := json.Marshal(bundle)
	if err != nil {
		return "", err
	}

	// 2. Derive the encryption key
	aesKey := derivePassphraseKey(password, salt)

	// 3. Symmetric Block Encryption
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return "", err
	}
	aesGcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	ciphertext := aesGcm.Seal(nil, nonce, plaintext, nil)

	// 4. Structural Packing & Base64 Armoring
	container := EncryptedKeyContainer{
		Salt:       salt,
		Nonce:      nonce,
		Ciphertext: ciphertext,
	}
	containerBytes, err := json.Marshal(container)
	if err != nil {
		return "", err
	}

	encodedBody := base64.StdEncoding.EncodeToString(containerBytes)

	// Format with traditional cryptographic armor framing
	var armoredBuilder strings.Builder
	armoredBuilder.WriteString(ArmorHeader + "\n")

	// Wrap lines at 64 characters for transport readability
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
	// Clean up armor structures
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

	// Re-derive key using matching salt parameters
	aesKey := derivePassphraseKey(password, container.Salt)

	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, nil, err
	}
	aesGcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}

	plaintext, err := aesGcm.Open(nil, container.Nonce, container.Ciphertext, nil)
	if err != nil {
		return nil, nil, errors.New("authentication failed: invalid key decryption passphrase")
	}

	var bundle PlaintextKeyBundle
	if err := json.Unmarshal(plaintext, &bundle); err != nil {
		return nil, nil, err
	}

	return bundle.KEMPriv, bundle.DSAPriv, nil
}