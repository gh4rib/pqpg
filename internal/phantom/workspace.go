package phantom

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
)

// Workspace represents the ephemeral RAM-disk mount.
type Workspace struct {
	MountPoint string
}

// NewWorkspace negotiates a strict, RAM-backed directory using Linux's native /dev/shm.
func NewWorkspace() (*Workspace, error) {
	// Check if the native OS RAM-disk is available
	ramDiskBase := "/dev/shm"
	if _, err := os.Stat(ramDiskBase); os.IsNotExist(err) {
		// Fallback to standard OS Temp if /dev/shm doesn't exist (e.g., macOS/Windows)
		// Note: This loses the hardware-level RAM guarantee on non-Linux systems.
		fmt.Println("[-] Warning: /dev/shm not found. Falling back to standard OS temp directory.")
		ramDiskBase = os.TempDir()
	}

	// Generate a collision-proof, randomized directory name
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	dirName := "pqpg_phantom_" + hex.EncodeToString(b)
	phantomDir := filepath.Join(ramDiskBase, dirName)

	// Create the directory with absolute 0700 permissions.
	// 0700 guarantees ONLY the user running PQPG can read, write, or execute inside it.
	if err := os.MkdirAll(phantomDir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create phantom RAM directory: %v", err)
	}

	return &Workspace{MountPoint: phantomDir}, nil
}

// Destroy shreds the RAM-disk contents and deletes the directory.
func (w *Workspace) Destroy() {
	// 1. Aggressively zero-out all files before deleting them
	files, err := os.ReadDir(w.MountPoint)
	if err == nil {
		for _, f := range files {
			path := filepath.Join(w.MountPoint, f.Name())
			info, err := os.Stat(path)
			if err == nil && !info.IsDir() {
				// Overwrite the file's exact size with zeros in RAM
				zeros := make([]byte, info.Size())
				_ = os.WriteFile(path, zeros, 0600)
			}
			// Delete the shredded file
			_ = os.RemoveAll(path)
		}
	}

	// 2. Purge the parent directory itself
	_ = os.RemoveAll(w.MountPoint)
}
