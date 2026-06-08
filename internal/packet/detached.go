package packet

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/gh4rib/pqpg/internal/crypto"
	"github.com/gh4rib/pqpg/internal/identity"
)


type DetachedSignature struct {
	SenderName string `json:"sender_name"`
	Timestamp  int64  `json:"timestamp"`
	DSASuite   string `json:"dsa_suite"`
	HashSuite  string `json:"hash_suite"`
	Signature  []byte `json:"signature"`
}

// SignCleartextStream hashes an open file stream and signs the digest.
func SignCleartextStream(in io.Reader, senderKr *identity.Keyring, hashSuite string) (string, error) {
	registry := crypto.NewRegistry()

	hasher, err := registry.GetXOF(hashSuite)
	if err != nil {
		return "", err
	}

	// DOMAIN SEPARATION
	hasher.Write([]byte("PQPG-Detached-Signature-v1"))

	// io.Copy automatically handles the streaming chunk loop with a 32KB buffer
	if _, err := io.Copy(hasher.NewWriter(), in); err != nil {
		return "", fmt.Errorf("file hashing interrupted: %w", err)
	}

	// 64-byte digest standardizes the DSA signing block
	digest := hasher.Derive(nil, 64)

	dsa, _ := registry.GetDSA(senderKr.Profile.DSASuite)
	sigBytes, err := dsa.Sign(senderKr.DSAPrivKey, digest)
	if err != nil {
		return "", fmt.Errorf("post-quantum signing failed: %w", err)
	}

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

// VerifyCleartextStream checks a raw file against a detached signature block.
func VerifyCleartextStream(in io.Reader, armoredSig string, senderProf *identity.Profile) error {
	registry := crypto.NewRegistry()

	if !strings.Contains(armoredSig, DetachedHeader) || !strings.Contains(armoredSig, DetachedFooter) {
		return errors.New("invalid or missing detached signature armor headers")
	}

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

	// DOMAIN SEPARATION
	hasher.Write([]byte("PQPG-Detached-Signature-v1"))

	// Stream the raw file through the designated hash engine
	if _, err := io.Copy(hasher.NewWriter(), in); err != nil {
		return fmt.Errorf("file hashing interrupted: %w", err)
	}
	digest := hasher.Derive(nil, 64)

	dsa, err := registry.GetDSA(sigStruct.DSASuite)
	if err != nil {
		return err
	}

	if !dsa.Verify(senderProf.DSAPubKey, digest, sigStruct.Signature) {
		return errors.New("CRITICAL: FILE TAMPERED OR CORRUPTED. SIGNATURE INVALID")
	}

	return nil
}
