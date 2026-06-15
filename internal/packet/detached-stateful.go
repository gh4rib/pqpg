package packet

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gh4rib/pqpg/internal/crypto"
	"github.com/gh4rib/pqpg/internal/identity"
)

// SignStatefulCleartextStream synchronously flushes the updated private key to disk BEFORE returning the signature.
func SignStatefulCleartextStream(in io.Reader, senderKr *identity.Keyring, hashSuite string, passphrase string, privDir string) (string, error) {
	registry := crypto.NewRegistry()

	hasher, err := registry.GetXOF(hashSuite)
	if err != nil {
		return "", err
	}

	hasher.Write([]byte(DomainStatefulDetached))

	if _, err := io.Copy(hasher.NewWriter(), in); err != nil {
		return "", fmt.Errorf("file hashing interrupted: %w", err)
	}
	digest := hasher.Derive(nil, XOFDeriveSize)

	statefulDSA, err := registry.GetStatefulDSA(senderKr.Profile.DSASuite)
	if err != nil {
		return "", fmt.Errorf("identity does not use a stateful signature scheme: %w", err)
	}

	// Sign returns the NEW serialized private key with the incremented counter
	// (Note: To match our earlier interface upgrade, statefulDSA.Sign takes privDir as the 3rd argument)
	sigBytes, newPrivKeyBytes, err := statefulDSA.Sign(senderKr.DSAPrivKey, digest, privDir)
	if err != nil {
		return "", fmt.Errorf("stateful signing failed (exhausted?): %w", err)
	}

	// =========================================================================
	// GOLDEN RULE: SYNCHRONOUS STATE FLUSH
	// =========================================================================

	senderKr.DSAPrivKey = newPrivKeyBytes

	armoredPrivateBlock, err := identity.EncryptAndArmorKeys(senderKr.KEMPrivKey, senderKr.DSAPrivKey, passphrase, senderKr.Profile.AEADSuite)
	if err != nil {
		return "", fmt.Errorf("CRITICAL ERROR: Failed to re-encrypt private key state: %w", err)
	}

	keyPath := filepath.Join(privDir, "private_key.asc")
	tempPath := keyPath + ".tmp"

	// HARDWARE-SAFE ATOMIC WRITE
	f, err := os.OpenFile(tempPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return "", fmt.Errorf("CRITICAL ERROR: Failed to create temporary state file: %w", err)
	}

	if _, err := f.Write([]byte(armoredPrivateBlock)); err != nil {
		f.Close()
		os.Remove(tempPath)
		return "", fmt.Errorf("CRITICAL ERROR: Failed to write new state to disk: %w", err)
	}

	// Force fsync while the file descriptor is actively open for writing
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tempPath)
		return "", fmt.Errorf("CRITICAL ERROR: Failed to flush hardware cache: %w", err)
	}

	if err := f.Close(); err != nil {
		os.Remove(tempPath)
		return "", fmt.Errorf("CRITICAL ERROR: Failed to cleanly close state file: %w", err)
	}

	// Atomic OS swap
	if err := os.Rename(tempPath, keyPath); err != nil {
		os.Remove(tempPath)
		return "", fmt.Errorf("CRITICAL ERROR: Failed to finalize state commit: %w", err)
	}

	// =========================================================================
	// State is Safe. Release the Signature.
	// =========================================================================

	sigStruct := DetachedSignature{
		SenderName: senderKr.Profile.Name,
		Timestamp:  time.Now().Unix(),
		DSASuite:   senderKr.Profile.DSASuite,
		HashSuite:  hashSuite,
		Signature:  sigBytes,
	}

	rawJSON, _ := json.MarshalIndent(sigStruct, "", "  ")
	b64Str := base64.StdEncoding.EncodeToString(rawJSON)

	var sb strings.Builder
	sb.WriteString(DetachedHeader + "\n")
	for i := 0; i < len(b64Str); i += 64 {
		end := i + 64
		if end > len(b64Str) {
			end = len(b64Str)
		}
		sb.WriteString(b64Str[i:end] + "\n")
	}
	sb.WriteString(DetachedFooter + "\n")

	return sb.String(), nil
}

// VerifyStatefulCleartextStream checks a raw file against a stateful signature.
func VerifyStatefulCleartextStream(in io.Reader, armoredSig string, senderProf *identity.Profile) error {
	registry := crypto.NewRegistry()

	start := strings.Index(armoredSig, DetachedHeader) + len(DetachedHeader)
	end := strings.Index(armoredSig, DetachedFooter)
	b64Payload := strings.ReplaceAll(armoredSig[start:end], "\n", "")
	b64Payload = strings.ReplaceAll(b64Payload, "\r", "")

	rawJSON, err := base64.StdEncoding.DecodeString(b64Payload)
	if err != nil {
		return fmt.Errorf("base64 decoding failed: %w", err)
	}

	var sigStruct DetachedSignature
	if err := json.Unmarshal(rawJSON, &sigStruct); err != nil {
		return fmt.Errorf("signature json unmarshal failed: %w", err)
	}

	hasher, err := registry.GetXOF(sigStruct.HashSuite)
	if err != nil {
		return err
	}

	hasher.Write([]byte(DomainStatefulDetached))

	if _, err := io.Copy(hasher.NewWriter(), in); err != nil {
		return fmt.Errorf("file hashing interrupted: %w", err)
	}
	digest := hasher.Derive(nil, XOFDeriveSize)

	statefulDSA, err := registry.GetStatefulDSA(sigStruct.DSASuite)
	if err != nil {
		return err
	}

	if !statefulDSA.Verify(senderProf.DSAPubKey, digest, sigStruct.Signature) {
		return errors.New("CRITICAL: FILE TAMPERED OR CORRUPTED. SIGNATURE INVALID")
	}

	return nil
}
