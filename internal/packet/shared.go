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
	"strings"

	"github.com/gh4rib/pqpg-cloudflare-circl/internal/crypto"
	"github.com/hashicorp/vault/shamir"
	"github.com/klauspost/compress/zstd"
)

const (
	SharedHeaderBoundary = "-----BEGIN SHARED VAULT HEADER-----"
	SharedPayloadBoundary = "-----BEGIN SHARED VAULT PAYLOAD-----"
	SharedEndBoundary = "-----END SHARED VAULT-----"
)

type SharedMetadata struct {
	AEADSuite   string `json:"aead_suite"`
	Compression string `json:"compression"`
	Nonce       []byte `json:"nonce"`
}

// SharedVaultLock generates a random Master Key, encrypts the file, and returns the Shamir shares.
func SharedVaultLock(in io.Reader, out io.Writer, aeadSuite, compression string, parts, threshold int) ([]string, error) {
	if threshold > parts || threshold < 2 {
		return nil, errors.New("invalid Shamir parameters: threshold must be <= parts and >= 2")
	}

	registry := crypto.NewRegistry()
	aead, err := registry.GetAEAD(aeadSuite)
	if err != nil { return nil, err }

	// 1. Generate Master Encryption Key & Split it
	msgKey := make([]byte, aead.KeySize())
	_, _ = io.ReadFull(rand.Reader, msgKey)

	rawShares, err := shamir.Split(msgKey, parts, threshold)
	if err != nil { return nil, fmt.Errorf("failed to generate polynomial shares: %w", err) }

	var encodedShares []string
	for _, share := range rawShares {
		encodedShares = append(encodedShares, base64.StdEncoding.EncodeToString(share))
	}

	// 2. Initialize Streaming Metadata
	baseNonce := make([]byte, aead.NonceSize())
	_, _ = io.ReadFull(rand.Reader, baseNonce)

	metadata := SharedMetadata{
		AEADSuite:   aeadSuite,
		Compression: compression,
		Nonce:       baseNonce,
	}

	metaBytes, _ := json.Marshal(metadata)
	fmt.Fprintf(out, "%s\n%s\n%s\n", SharedHeaderBoundary, base64.StdEncoding.EncodeToString(metaBytes), SharedPayloadBoundary)

	// --- COMPRESSION PIPELINE ---
	compReader, compWriter := io.Pipe()
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

	// 3. Encrypt & Pad the Stream
	buf := make([]byte, ChunkSize)
	var chunkIndex uint64 = 0

	for {
		n, readErr := io.ReadFull(compReader, buf)
		if n > 0 {
			if readErr == io.EOF || readErr == io.ErrUnexpectedEOF {
				padLen := 4096 - (n % 4096)
				if padLen < 2 { padLen += 4096 }
				
				padBuf := make([]byte, padLen)
				_, _ = io.ReadFull(rand.Reader, padBuf)
				binary.LittleEndian.PutUint16(padBuf[padLen-2:], uint16(padLen))
				
				finalPlaintext := append(buf[:n], padBuf...)
				chunkNonce := buildChunkNonce(baseNonce, chunkIndex)
				ciphertext, _ := aead.Seal(msgKey, chunkNonce, finalPlaintext, nil)
				
				fmt.Fprintf(out, "%s\n", base64.StdEncoding.EncodeToString(ciphertext))
				break
			} else {
				chunkNonce := buildChunkNonce(baseNonce, chunkIndex)
				ciphertext, _ := aead.Seal(msgKey, chunkNonce, buf[:n], nil)
				fmt.Fprintf(out, "%s\n", base64.StdEncoding.EncodeToString(ciphertext))
				chunkIndex++
			}
		}

		if readErr == io.EOF {
			padLen := 4096
			padBuf := make([]byte, padLen)
			_, _ = io.ReadFull(rand.Reader, padBuf)
			binary.LittleEndian.PutUint16(padBuf[padLen-2:], uint16(padLen))
			
			chunkNonce := buildChunkNonce(baseNonce, chunkIndex)
			ciphertext, _ := aead.Seal(msgKey, chunkNonce, padBuf, nil)
			fmt.Fprintf(out, "%s\n", base64.StdEncoding.EncodeToString(ciphertext))
			break
		}
		if readErr != nil && readErr != io.ErrUnexpectedEOF { return nil, readErr }
	}

	fmt.Fprintf(out, "%s\n", SharedEndBoundary)
	return encodedShares, nil // Returns the keys to be distributed to the board members
}

// SharedVaultUnlock mathematically reconstructs the Master Key from the provided M-shares.
func SharedVaultUnlock(in io.Reader, out io.Writer, encodedShares []string) error {
	registry := crypto.NewRegistry()
	reader := bufio.NewReader(in)

	// 1. Reconstruct Master Secret using Lagrange Interpolation
	var rawShares [][]byte
	for _, b64Share := range encodedShares {
		raw, err := base64.StdEncoding.DecodeString(b64Share)
		if err != nil { return errors.New("corrupt share encoding") }
		rawShares = append(rawShares, raw)
	}

	msgKey, err := shamir.Combine(rawShares)
	if err != nil { return fmt.Errorf("CRITICAL: Failed to reconstruct Master Key. Shares invalid or insufficient: %w", err) }

	// 2. Parse Header
	for {
		line, err := reader.ReadString('\n')
		if err != nil { return errors.New("invalid file: missing outer boundary") }
		if strings.TrimSpace(line) == SharedHeaderBoundary { break }
	}

	metaB64, _ := reader.ReadString('\n')
	metaBytes, _ := base64.StdEncoding.DecodeString(strings.TrimSpace(metaB64))
	var metadata SharedMetadata
	if err := json.Unmarshal(metaBytes, &metadata); err != nil { return err }

	payloadBoundary, _ := reader.ReadString('\n')
	if strings.TrimSpace(payloadBoundary) != SharedPayloadBoundary { return errors.New("invalid file structure") }

	aead, _ := registry.GetAEAD(metadata.AEADSuite)

	// --- DECOMPRESSION PIPELINE ---
	decReader, decWriter := io.Pipe()
	go func() {
		var loopErr error
		defer func() { decWriter.CloseWithError(loopErr) }()

		var chunkIndex uint64 = 0
		var prevPlaintext []byte 

		for {
			line, err := reader.ReadString('\n')
			line = strings.TrimSpace(line)

			if line == SharedEndBoundary {
				if len(prevPlaintext) < 2 { loopErr = errors.New("corrupt padding"); return }
				padLen := binary.LittleEndian.Uint16(prevPlaintext[len(prevPlaintext)-2:])
				decWriter.Write(prevPlaintext[:len(prevPlaintext)-int(padLen)])
				break
			}
			if line == "" && err == nil { continue }
			if err != nil { loopErr = errors.New("unexpected EOF"); return }

			ciphertext, _ := base64.StdEncoding.DecodeString(line)
			chunkNonce := buildChunkNonce(metadata.Nonce, chunkIndex)
			
			plaintext, err := aead.Open(msgKey, chunkNonce, ciphertext, nil)
			if err != nil { loopErr = errors.New("CRITICAL: Decryption failed. Master Key reconstructed incorrectly"); return }

			if prevPlaintext != nil { decWriter.Write(prevPlaintext) }
			prevPlaintext = plaintext 
			chunkIndex++
		}
	}()

	// 3. Stream to Output
	var errOut error
	switch metadata.Compression {
	case "Zstd":
		zr, _ := zstd.NewReader(decReader)
		defer zr.Close()
		_, errOut = io.Copy(out, zr)
	case "Gzip":
		gr, _ := gzip.NewReader(decReader)
		defer gr.Close()
		_, errOut = io.Copy(out, gr)
	default:
		_, errOut = io.Copy(out, decReader)
	}

	return errOut
}