package identity

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"golang.org/x/crypto/argon2"
)

var rollbackMutex sync.Mutex

// VerifyAndCommitCounter checks if the key's internal counter has gone backwards.
// It encrypts the state using AES-GCM and wraps it in an ASCII-armored PEM block
// stored directly inside the user's private folder.
func VerifyAndCommitCounter(fingerprint string, currentCounter uint64, passphrase string, privDir string) error {
	rollbackMutex.Lock()
	defer rollbackMutex.Unlock()

	// Target the canary file inside the user's private directory
	canaryPath := filepath.Join(privDir, "pqpg_system_canary.asc")
	data := make(map[string]uint64)

	// Derive a stable local encryption key from the user's passphrase
	salt := []byte("PQPG-Local-Rollback-Canary-Salt")
	canaryKey := argon2.IDKey([]byte(passphrase), salt, 1, 64*1024, 4, 32)
	block, _ := aes.NewCipher(canaryKey)
	aesgcm, _ := cipher.NewGCM(block)

	// 1. DECRYPT EXISTING CANARY (If it exists)
	if armoredBytes, err := os.ReadFile(canaryPath); err == nil {
		// Decode the ASCII armor
		pemBlock, _ := pem.Decode(armoredBytes)
		if pemBlock != nil && pemBlock.Type == "PQPG ANTI-ROLLBACK CANARY" {
			encryptedBytes := pemBlock.Bytes
			if len(encryptedBytes) > aesgcm.NonceSize() {
				nonce := encryptedBytes[:aesgcm.NonceSize()]
				ciphertext := encryptedBytes[aesgcm.NonceSize():]

				// Open the AES-GCM vault
				if plaintext, err := aesgcm.Open(nil, nonce, ciphertext, nil); err == nil {
					json.Unmarshal(plaintext, &data)
				} else {
					return fmt.Errorf("CRITICAL: Rollback Canary file corrupted or tampered with")
				}
			}
		}
	}

	// 2. VERIFY ROLLBACK STATE
	savedCounter, exists := data[fingerprint]
	if exists {
		if currentCounter < savedCounter {
			return fmt.Errorf("CRITICAL SECURITY VIOLATION: STATE ROLLBACK DETECTED!\n"+
				"======================================================================\n"+
				"  Expected Counter: >= %d\n"+
				"  Keyring Counter:  %d\n"+
				"======================================================================\n"+
				"Your keystore was restored from an old backup or cloud sync. To prevent\n"+
				"catastrophic mathematical state-reuse, this identity has been LOCKED.", savedCounter, currentCounter)
		}
	}

	// 3. COMMIT & ENCRYPT
	data[fingerprint] = currentCounter
	outBytes, _ := json.Marshal(data)

	nonce := make([]byte, aesgcm.NonceSize())
	rand.Read(nonce)
	ciphertext := aesgcm.Seal(nonce, nonce, outBytes, nil)

	// 4. ASCII ARMOR THE CIPHERTEXT
	pemBlock := &pem.Block{
		Type:  "PQPG ANTI-ROLLBACK CANARY",
		Bytes: ciphertext,
	}
	armoredData := pem.EncodeToMemory(pemBlock)

	if err := os.WriteFile(canaryPath, armoredData, 0600); err != nil {
		return fmt.Errorf("failed to update local anti-rollback guard file: %w", err)
	}

	return nil
}
