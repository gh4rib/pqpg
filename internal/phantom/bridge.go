package phantom

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// UnlockVaultToRAM securely copies the encrypted vault files from the SSD into the tmpfs RAM-disk.
func UnlockVaultToRAM(privPath string, tmpfsPath string) error {
	// 1. Copy the encrypted private key block
	keyPath := filepath.Join(privPath, "private_key.asc")
	if _, err := os.Stat(keyPath); err == nil {
		if err := secureCopy(keyPath, filepath.Join(tmpfsPath, "private_key.asc")); err != nil {
			return fmt.Errorf("failed to load private key to RAM: %v", err)
		}
	} else {
		return fmt.Errorf("private key not found at %s", keyPath)
	}

	// 2. Copy the Double Ratchet database (if it exists yet)
	dbPath := filepath.Join(privPath, "sessions.db")
	if _, err := os.Stat(dbPath); err == nil {
		if err := secureCopy(dbPath, filepath.Join(tmpfsPath, "sessions.db")); err != nil {
			return fmt.Errorf("failed to load sessions database to RAM: %v", err)
		}
	}

	// 3. Copy the Anti-Rollback Canary (Crucial for Stateful LMS/XMSS signatures)
	canaryPath := filepath.Join(privPath, "pqpg_system_canary.asc")
	if _, err := os.Stat(canaryPath); err == nil {
		if err := secureCopy(canaryPath, filepath.Join(tmpfsPath, "pqpg_system_canary.asc")); err != nil {
			return fmt.Errorf("failed to load canary to RAM: %v", err)
		}
	}

	// 4. CRITICAL FIX: Find and copy the public profile.json
	// The identity engine needs this to know which algorithms to use for decryption.
	profilePath := filepath.Join(privPath, "profile.json")
	if _, err := os.Stat(profilePath); os.IsNotExist(err) {
		// If it's not in the private folder, check the standard ../public/ folder on the SSD
		profilePath = filepath.Join(filepath.Dir(privPath), "public", "profile.json")
	}

	if _, err := os.Stat(profilePath); err == nil {
		// The engine expects profile.json directly in the workspace root
		if err := secureCopy(profilePath, filepath.Join(tmpfsPath, "profile.json")); err != nil {
			return fmt.Errorf("failed to copy profile.json to RAM: %v", err)
		}

		// NOTE: Some internal functions might still try to climb out via "../public/profile.json".
		// To guarantee we never hit an OS-level "no such file" panic, we recreate the public folder
		// INSIDE the RAM disk and put a copy there too. Total Phantom Isolation.
		ramPublicDir := filepath.Join(tmpfsPath, "public")
		_ = os.MkdirAll(ramPublicDir, 0700)
		_ = secureCopy(profilePath, filepath.Join(ramPublicDir, "profile.json"))

	} else {
		return fmt.Errorf("could not locate profile.json on SSD. Identity corrupted")
	}

	return nil
}

// LockRAMToVault synchronizes the updated vault state back to the persistent SSD.
func LockRAMToVault(tmpfsPath string, privPath string) error {
	// Sync Double Ratchet DB
	dbPath := filepath.Join(tmpfsPath, "sessions.db")
	if _, err := os.Stat(dbPath); err == nil {
		_ = secureCopy(dbPath, filepath.Join(privPath, "sessions.db"))
	}

	// Sync Stateful Key Overwrites
	keyPath := filepath.Join(tmpfsPath, "private_key.asc")
	if _, err := os.Stat(keyPath); err == nil {
		_ = secureCopy(keyPath, filepath.Join(privPath, "private_key.asc"))
	}

	// Sync Anti-Rollback Canaries
	canaryPath := filepath.Join(tmpfsPath, "pqpg_system_canary.asc") // Adjust if you named your canary file differently
	if _, err := os.Stat(canaryPath); err == nil {
		_ = secureCopy(canaryPath, filepath.Join(privPath, "pqpg_system_canary.asc"))
	}

	return nil
}

// secureCopy handles the bit-by-bit transfer between file systems.
func secureCopy(src, dst string) error {
	sourceFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer sourceFile.Close()

	destFile, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer destFile.Close()

	_, err = io.Copy(destFile, sourceFile)
	return err
}
