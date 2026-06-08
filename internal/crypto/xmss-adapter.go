package crypto

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/gh4rib/pqpg/internal/xmssmt"
)

// 1. Add the algName field to the struct
type xmssAdapter struct {
	algName string
}

// 2. Return the dynamic name
func (a *xmssAdapter) Name() string { return a.algName }

// getSecureTempDir creates a collision-proof temporary directory inside the
// LOCAL working directory to prevent /tmp shared-memory leakage.
func getSecureTempDir() (string, error) {
	b := make([]byte, 16)
	_, _ = rand.Read(b)

	// FIX: Use the local directory "." instead of os.TempDir()
	dir := filepath.Join(".", ".pqpg_virtual_xmss_"+hex.EncodeToString(b))

	// 0700 ensures ONLY the user running the CLI can access this folder
	return dir, os.MkdirAll(dir, 0700)
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
	defer os.RemoveAll(tempDir)

	keyPath := filepath.Join(tempDir, "key")

	// 3. Dynamically inject the algorithm name from the struct
	sk, pk, err := xmssmt.GenerateKeyPair(a.algName, keyPath)
	if err != nil {
		return nil, nil, fmt.Errorf("xmssmt generation failed: %w", err)
	}

	pubBytes, err := pk.MarshalBinary()
	if err != nil {
		return nil, nil, err
	}

	sk.Close()

	privPacked, err := packState(keyPath)
	if err != nil {
		return nil, nil, err
	}

	return pubBytes, privPacked, nil
}

// ... (Keep Sign and Verify exactly the same as the previous version) ...
func (a *xmssAdapter) Sign(privKey []byte, message []byte) ([]byte, []byte, error) {
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

// ExtractCounter safely unpacks the virtual filesystem, reads the sequence number, and shreds it.
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
	defer sk.Close()

	// sk.SeqNo() returns a SignatureSeqNo (uint64)
	return uint64(sk.SeqNo()), nil
}
