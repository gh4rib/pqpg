package crypto

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/gh4rib/pqpg/internal/xmssmt"
)

type xmssAdapter struct {
	algName string
}

func (a *xmssAdapter) Name() string { return a.algName }

// getSecureTempDir creates a collision-proof temporary directory.
// Routed to the OS Secure Temp Directory (tmpfs/RAM on Linux)
// to prevent local directory clutter if the program exits forcefully.
func getSecureTempDir() (string, error) {
	// os.MkdirTemp automatically enforces strict 0700 permissions
	return os.MkdirTemp("", "pqpg_virtual_xmss_*")
}

func packState(keyPath string) ([]byte, error) {
	keyData, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read xmss key file: %v", err)
	}
	cacheData, err := os.ReadFile(keyPath + ".cache")
	if err != nil {
		return nil, fmt.Errorf("failed to read xmss cache file: %v", err)
	}

	out := make([]byte, 8+len(keyData)+len(cacheData))
	binary.BigEndian.PutUint64(out[:8], uint64(len(keyData)))
	copy(out[8:], keyData)
	copy(out[8+len(keyData):], cacheData)
	return out, nil
}

func unpackState(privKey []byte, keyPath string) error {
	if len(privKey) < 8 {
		return errors.New("invalid xmss state length")
	}
	keyLen := binary.BigEndian.Uint64(privKey[:8])
	if uint64(len(privKey)) < 8+keyLen {
		return errors.New("corrupt xmss state payload")
	}

	keyData := privKey[8 : 8+keyLen]
	cacheData := privKey[8+keyLen:]

	if err := os.WriteFile(keyPath, keyData, 0600); err != nil {
		return err
	}
	if err := os.WriteFile(keyPath+".cache", cacheData, 0600); err != nil {
		return err
	}
	return nil
}

func (a *xmssAdapter) GenerateKeyPair() ([]byte, []byte, error) {
	tempDir, err := getSecureTempDir()
	if err != nil {
		return nil, nil, err
	}
	defer os.RemoveAll(tempDir) // Aggressive cleanup

	keyPath := filepath.Join(tempDir, "key")

	sk, pk, err := xmssmt.GenerateKeyPair(a.algName, keyPath)
	if err != nil {
		return nil, nil, fmt.Errorf("xmssmt generation failed: %w", err)
	}

	pubBytes, err := pk.MarshalBinary()
	if err != nil {
		sk.Close()
		return nil, nil, err
	}

	// Explicitly close the file descriptors BEFORE packing state.
	// This ensures OS file locks are released so defer RemoveAll succeeds.
	sk.Close()

	privPacked, err := packState(keyPath)
	if err != nil {
		return nil, nil, err
	}

	return pubBytes, privPacked, nil
}

func (a *xmssAdapter) Sign(privKey []byte, message []byte, privDir string) ([]byte, []byte, error) {
	tempDir, err := getSecureTempDir()
	if err != nil {
		return nil, nil, err
	}
	defer os.RemoveAll(tempDir)

	keyPath := filepath.Join(tempDir, "key")
	if err := unpackState(privKey, keyPath); err != nil {
		return nil, nil, err
	}

	sk, _, _, err := xmssmt.LoadPrivateKey(keyPath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to load XMSS private key container: %w", err)
	}

	sig, err := sk.Sign(message)
	if err != nil {
		sk.Close()
		return nil, nil, fmt.Errorf("XMSS signing failed (key exhausted?): %w", err)
	}

	sigBytes, err := sig.MarshalBinary()
	if err != nil {
		sk.Close()
		return nil, nil, err
	}

	// Explicit release to prevent OS lock blocking the defer RemoveAll
	sk.Close()

	newPrivBytes, err := packState(keyPath)
	if err != nil {
		return nil, nil, err
	}

	return sigBytes, newPrivBytes, nil
}

func (a *xmssAdapter) Verify(pubKey []byte, message []byte, signature []byte) bool {
	valid, err := xmssmt.Verify(pubKey, signature, message)
	return err == nil && valid
}

func (a *xmssAdapter) ExtractCounter(privKey []byte) (uint64, error) {
	tempDir, err := getSecureTempDir()
	if err != nil {
		return 0, err
	}
	defer os.RemoveAll(tempDir)

	keyPath := filepath.Join(tempDir, "key")
	if err := unpackState(privKey, keyPath); err != nil {
		return 0, err
	}

	sk, _, _, err := xmssmt.LoadPrivateKey(keyPath)
	if err != nil {
		return 0, fmt.Errorf("failed to load XMSS container for rollback check: %w", err)
	}

	seqNo := uint64(sk.SeqNo())

	// Explicitly close rather than deferring to guarantee file lock release
	// before defer os.RemoveAll triggers on exit.
	sk.Close()

	return seqNo, nil
}
