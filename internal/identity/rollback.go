package identity

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"golang.org/x/crypto/argon2"
)

var rollbackMutex sync.Mutex

// acquireOSLock creates an OS-level file lock to prevent multi-process race conditions.
func acquireOSLock(lockPath string) (*os.File, error) {
	lockFile, err := os.OpenFile(lockPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return nil, fmt.Errorf("identity is currently locked by another process (if PQPG crashed, manually delete %s)", lockPath)
	}
	return lockFile, nil
}

// VerifyAndCommitCounter checks if the key's internal counter has gone backwards.
// It uses dynamic Argon2id salting and AES-GCM to ensure the Canary file cannot be tampered with.
func VerifyAndCommitCounter(fingerprint string, currentCounter uint64, passphrase string, privDir string) error {
	rollbackMutex.Lock()
	defer rollbackMutex.Unlock()

	// --- 1. OS-LEVEL CONCURRENCY LOCK ---
	lockPath := filepath.Join(privDir, "pqpg_system.lock")
	lockFile, err := acquireOSLock(lockPath)
	if err != nil {
		return err
	}
	defer func() {
		lockFile.Close()
		os.Remove(lockPath)
	}()
	// ------------------------------------

	canaryPath := filepath.Join(privDir, "pqpg_system_canary.asc")
	data := make(map[string]uint64)

	// 2. DECRYPT EXISTING CANARY (If it exists)
	if armoredBytes, err := os.ReadFile(canaryPath); err == nil {
		pemBlock, _ := pem.Decode(armoredBytes)
		if pemBlock != nil && pemBlock.Type == "PQPG ANTI-ROLLBACK CANARY" {

			// Extract dynamic salt from PEM headers
			var currentSalt []byte
			if hexSalt, ok := pemBlock.Headers["Argon2-Salt"]; ok {
				decodedSalt, err := hex.DecodeString(hexSalt)
				if err != nil {
					return fmt.Errorf("CRITICAL: Canary salt header is corrupted")
				}
				currentSalt = decodedSalt
			} else {
				// Backward compatibility for Canary files created before the dynamic salt patch
				currentSalt = []byte("PQPG-Local-Rollback-Canary-Salt")
			}

			// Derive decryption key using the extracted salt
			canaryKey := argon2.IDKey([]byte(passphrase), currentSalt, 1, 64*1024, 4, 32)
			block, _ := aes.NewCipher(canaryKey)
			aesgcm, _ := cipher.NewGCM(block)

			encryptedBytes := pemBlock.Bytes
			if len(encryptedBytes) > aesgcm.NonceSize() {
				nonce := encryptedBytes[:aesgcm.NonceSize()]
				ciphertext := encryptedBytes[aesgcm.NonceSize():]

				if plaintext, err := aesgcm.Open(nil, nonce, ciphertext, nil); err == nil {
					json.Unmarshal(plaintext, &data)
				} else {
					return fmt.Errorf("CRITICAL: Rollback Canary file corrupted or tampered with")
				}
			}
		}
	}

	// 3. VERIFY ROLLBACK STATE
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

	// 4. COMMIT & ENCRYPT (WITH SALT ROTATION)
	data[fingerprint] = currentCounter
	outBytes, _ := json.Marshal(data)

	// Generate a brand new random salt for this write
	newSalt := make([]byte, 16)
	rand.Read(newSalt)

	newCanaryKey := argon2.IDKey([]byte(passphrase), newSalt, 1, 64*1024, 4, 32)
	newBlock, _ := aes.NewCipher(newCanaryKey)
	newAesgcm, _ := cipher.NewGCM(newBlock)

	nonce := make([]byte, newAesgcm.NonceSize())
	rand.Read(nonce)
	ciphertext := newAesgcm.Seal(nonce, nonce, outBytes, nil)

	// 5. ASCII ARMOR THE CIPHERTEXT (Injecting the dynamic salt into the header)
	pemBlock := &pem.Block{
		Type: "PQPG ANTI-ROLLBACK CANARY",
		Headers: map[string]string{
			"Argon2-Salt": hex.EncodeToString(newSalt), // Save salt in plaintext
		},
		Bytes: ciphertext,
	}
	armoredData := pem.EncodeToMemory(pemBlock)

	// 6. HARDWARE-SAFE ATOMIC WRITE (Mitigates Power-Loss Corruption)
	tmpPath := canaryPath + ".tmp"
	f, err := os.OpenFile(tmpPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("failed to create temporary canary file: %w", err)
	}

	if _, err := f.Write(armoredData); err != nil {
		f.Close()
		os.Remove(tmpPath)
		return fmt.Errorf("failed to write to temporary canary file: %w", err)
	}

	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmpPath)
		return fmt.Errorf("failed to flush hardware cache for canary file: %w", err)
	}

	if err := f.Close(); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("failed to close temporary canary file: %w", err)
	}

	if err := os.Rename(tmpPath, canaryPath); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("atomic swap of canary file failed: %w", err)
	}

	return nil
}
