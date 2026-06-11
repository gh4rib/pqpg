package packet

import (
	"bufio"
	"compress/gzip"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/gh4rib/pqpg/internal/crypto"
	"github.com/gh4rib/pqpg/internal/identity"
	"github.com/klauspost/compress/zstd"
)

type VaultMetadata struct {
	AEADSuite   string `json:"aead_suite"`
	Compression string `json:"compression"`
	XOFSuite    string `json:"xof_suite"`
	Nonce       []byte `json:"nonce"`
	Salt        []byte `json:"salt"`
}

func VaultSeal(in io.Reader, out io.Writer, myKr *identity.Keyring, compression string) error {
	registry := crypto.NewRegistry()
	aead, err := registry.GetAEAD(myKr.Profile.AEADSuite)
	if err != nil {
		return err
	}

	salt := make([]byte, 32)
	_, _ = io.ReadFull(rand.Reader, salt)

	xof, _ := registry.GetXOF(myKr.Profile.XOFSuite)
	xof.Write(salt)
	xof.Write(myKr.KEMPrivKey)

	// DYNAMIC KEY SIZING
	vaultKey := xof.Derive(nil, aead.KeySize())
	defer crypto.Wipe(vaultKey) // HYGIENE

	baseNonce := make([]byte, aead.NonceSize())
	_, _ = io.ReadFull(rand.Reader, baseNonce)

	metadata := VaultMetadata{
		AEADSuite:   myKr.Profile.AEADSuite,
		XOFSuite:    myKr.Profile.XOFSuite,
		Compression: compression,
		Nonce:       baseNonce,
		Salt:        salt,
	}

	metaBytes, _ := json.Marshal(metadata)
	fmt.Fprintf(out, "%s\n%s\n%s\n", VaultHeaderBoundary, base64.StdEncoding.EncodeToString(metaBytes), VaultPayloadBoundary)

	compReader, compWriter := io.Pipe()
	defer compReader.Close()

	go func() {
		var pipeErr error
		defer func() { compWriter.CloseWithError(pipeErr) }()
		switch compression {
		case "Zstd":
			zw, _ := zstd.NewWriter(compWriter)
			_, pipeErr = io.Copy(zw, in)
			zw.Close()
		case "Gzip":
			gw := gzip.NewWriter(compWriter)
			_, pipeErr = io.Copy(gw, in)
			gw.Close()
		default:
			_, pipeErr = io.Copy(compWriter, in)
		}
	}()

	buf := make([]byte, ChunkSize)
	var chunkIndex uint64 = 0

	for {
		n, readErr := io.ReadFull(compReader, buf)
		if n > 0 {
			if readErr == io.EOF || readErr == io.ErrUnexpectedEOF {
				padLen := 4096 - (n % 4096)
				if padLen < 2 {
					padLen += 4096
				}

				padBuf := make([]byte, padLen)
				_, _ = io.ReadFull(rand.Reader, padBuf)
				binary.LittleEndian.PutUint16(padBuf[padLen-2:], uint16(padLen))

				finalPlaintext := append(buf[:n], padBuf...)
				chunkNonce := buildChunkNonce(baseNonce, chunkIndex)
				ciphertext, errSeal := aead.Seal(vaultKey, chunkNonce, finalPlaintext, nil)
				if errSeal != nil {
					return fmt.Errorf("chunk encryption failed: %w", errSeal)
				}

				fmt.Fprintf(out, "%s\n", base64.StdEncoding.EncodeToString(ciphertext))
				break
			} else {
				chunkNonce := buildChunkNonce(baseNonce, chunkIndex)
				ciphertext, errSeal := aead.Seal(vaultKey, chunkNonce, buf[:n], nil)
				if errSeal != nil {
					return fmt.Errorf("chunk encryption failed: %w", errSeal)
				}

				fmt.Fprintf(out, "%s\n", base64.StdEncoding.EncodeToString(ciphertext))
				chunkIndex++
			}
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil && readErr != io.ErrUnexpectedEOF {
			return readErr
		}
	}

	fmt.Fprintf(out, "%s\n", VaultEndBoundary)
	return nil
}

func VaultOpen(in io.Reader, out io.Writer, myKr *identity.Keyring) error {
	registry := crypto.NewRegistry()
	reader := bufio.NewReader(in)

	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return errors.New("invalid vault file")
		}
		if strings.TrimSpace(line) == VaultHeaderBoundary {
			break
		}
	}

	metaB64, _ := reader.ReadString('\n')
	metaBytes, _ := base64.StdEncoding.DecodeString(strings.TrimSpace(metaB64))
	var metadata VaultMetadata
	if err := json.Unmarshal(metaBytes, &metadata); err != nil {
		return err
	}

	payloadBoundary, _ := reader.ReadString('\n')
	if strings.TrimSpace(payloadBoundary) != VaultPayloadBoundary {
		return errors.New("invalid vault structure")
	}

	aead, err := registry.GetAEAD(metadata.AEADSuite)
	if err != nil {
		return err
	}

	xof, _ := registry.GetXOF(metadata.XOFSuite)
	xof.Write(metadata.Salt)
	xof.Write(myKr.KEMPrivKey)

	// DYNAMIC KEY SIZING
	vaultKey := xof.Derive(nil, aead.KeySize())
	defer crypto.Wipe(vaultKey) // HYGIENE

	tempFile, err := os.CreateTemp("", "pqpg-vault-buffer-*")
	if err != nil {
		return fmt.Errorf("failed to allocate secure buffer: %v", err)
	}

	tempFileName := tempFile.Name()
	defer func() {
		tempFile.Close()
		os.Remove(tempFileName)
	}()

	decReader, decWriter := io.Pipe()
	defer decReader.Close()

	go func() {
		var loopErr error
		defer func() { decWriter.CloseWithError(loopErr) }()

		var chunkIndex uint64 = 0
		var prevPlaintext []byte

		for {
			line, err := reader.ReadString('\n')
			line = strings.TrimSpace(line)

			if line == VaultEndBoundary {
				if len(prevPlaintext) < 2 {
					loopErr = errors.New("corrupt padding")
					return
				}
				padLen := binary.LittleEndian.Uint16(prevPlaintext[len(prevPlaintext)-2:])
				decWriter.Write(prevPlaintext[:len(prevPlaintext)-int(padLen)])
				break
			}
			if line == "" && err == nil {
				continue
			}
			if err != nil {
				loopErr = errors.New("unexpected EOF")
				return
			}

			ciphertext, _ := base64.StdEncoding.DecodeString(line)
			chunkNonce := buildChunkNonce(metadata.Nonce, chunkIndex)

			plaintext, err := aead.Open(vaultKey, chunkNonce, ciphertext, nil)
			if err != nil {
				loopErr = errors.New("CRITICAL: Decryption failed. Vault key invalid or chunk tampered")
				return
			}

			if prevPlaintext != nil {
				decWriter.Write(prevPlaintext)
			}
			prevPlaintext = plaintext
			chunkIndex++
		}
	}()

	var extractErr error
	switch metadata.Compression {
	case "Zstd":
		zr, _ := zstd.NewReader(decReader)
		defer zr.Close()
		_, extractErr = io.Copy(tempFile, zr)
	case "Gzip":
		gr, _ := gzip.NewReader(decReader)
		defer gr.Close()
		_, extractErr = io.Copy(tempFile, gr)
	default:
		_, extractErr = io.Copy(tempFile, decReader)
	}

	if extractErr != nil {
		return fmt.Errorf("extraction aborted: %v", extractErr)
	}

	_, err = tempFile.Seek(0, 0)
	if err != nil {
		return err
	}
	_, errOut := io.Copy(out, tempFile)
	return errOut
}
