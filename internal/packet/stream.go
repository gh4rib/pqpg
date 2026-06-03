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
	"time"

	"github.com/gh4rib/pqpg-cloudflare-circl/internal/crypto"
	"github.com/gh4rib/pqpg-cloudflare-circl/internal/identity"
	"github.com/klauspost/compress/zstd"
)

const (
	OuterHeaderBoundary = "-----BEGIN PQC OUTER ENVELOPE-----"
	InnerHeaderBoundary = "-----BEGIN PQC INNER METADATA-----"
	PayloadBoundary     = "-----BEGIN PQC PAYLOAD-----"
	SignatureBoundary   = "-----BEGIN PQC SIGNATURE-----"
	EndBoundary         = "-----END PQC MESSAGE-----"
	ChunkSize           = 64 * 1024 
	InnerHeaderSize     = 1024 // Fixed 1KB Padding Boundary for Metadata
)

// OuterMetadata contains ONLY what is strictly necessary to unlock the math.
// No identities or timestamps are leaked here.
type OuterMetadata struct {
	MessageID      []byte `json:"message_id"`
	KEMSuite       string `json:"kem_suite"`
	KEMEncap       []byte `json:"kem_encap"`
	OuterAEADSuite string `json:"outer_aead"`
	OuterXOFSuite  string `json:"outer_xof"`
	OuterNonce     []byte `json:"outer_nonce"`
}

// InnerMetadata contains the sensitive routing, identity, and compression flags.
type InnerMetadata struct {
	SenderName  string `json:"sender_name"`
	Timestamp   int64  `json:"timestamp"`
	DSASuite    string `json:"dsa_suite"`
	Compression string `json:"compression"`
	InnerNonce  []byte `json:"inner_nonce"`
}

func buildChunkNonce(baseNonce []byte, counter uint64) []byte {
	nonce := make([]byte, len(baseNonce))
	copy(nonce, baseNonce)
	offset := len(nonce) - 8
	if offset < 0 { offset = 0 }
	for i := 0; i < 8 && offset+i < len(nonce); i++ {
		nonce[offset+i] ^= byte(counter >> (8 * (7 - i)))
	}
	return nonce
}

// padInnerHeader forces the JSON metadata to exactly 1024 bytes using random noise.
func padInnerHeader(data []byte) ([]byte, error) {
	if len(data) > InnerHeaderSize-2 {
		return nil, errors.New("CRITICAL: Inner metadata exceeds padding capacity")
	}
	padded := make([]byte, InnerHeaderSize)
	copy(padded, data)
	
	// Fill the remaining space with random white noise to destroy structural signatures
	_, _ = io.ReadFull(rand.Reader, padded[len(data):InnerHeaderSize-2])
	
	// Embed the true length of the JSON at the very end
	binary.LittleEndian.PutUint16(padded[InnerHeaderSize-2:], uint16(len(data)))
	return padded, nil
}

// unpadInnerHeader safely extracts the original JSON from the 1024-byte block.
func unpadInnerHeader(data []byte) ([]byte, error) {
	if len(data) != InnerHeaderSize {
		return nil, errors.New("CRITICAL: Inner header block is not exactly 1024 bytes")
	}
	trueLen := int(binary.LittleEndian.Uint16(data[InnerHeaderSize-2:]))
	if trueLen > InnerHeaderSize-2 {
		return nil, errors.New("CRITICAL: Inner header length marker corrupted")
	}
	return data[:trueLen], nil
}

// StreamSeal implements the Sealed Sender protocol, compressing, padding, and encrypting.
func StreamSeal(in io.Reader, out io.Writer, senderKr *identity.Keyring, receiverProf *identity.Profile, compression string) error {
	registry := crypto.NewRegistry()

	msgID := make([]byte, 32)
	_, _ = io.ReadFull(rand.Reader, msgID)

	kem, err := registry.GetKEM(receiverProf.KEMSuite)
	if err != nil { return err }
	ctKEM, sharedSecret, err := kem.Encapsulate(receiverProf.KEMPubKey)
	if err != nil { return err }

	ratchetXOF, err := registry.GetXOF(receiverProf.XOFSuite)
	if err != nil { return err }
	ratchet, err := crypto.NewRatchet(sharedSecret, ratchetXOF)
	if err != nil { return err }
	defer ratchet.Destroy()

	aead, err := registry.GetAEAD(receiverProf.AEADSuite)
	if err != nil { return err }
	
	// DUAL-RATCHET DERIVATION
	headerKey, _ := ratchet.Advance(aead.KeySize())   // Derives AES Key 1 (For Metadata)
	payloadKey, _ := ratchet.Advance(aead.KeySize())  // Derives AES Key 2 (For the File Stream)

	outerNonce := make([]byte, aead.NonceSize())
	innerNonce := make([]byte, aead.NonceSize())
	_, _ = io.ReadFull(rand.Reader, outerNonce)
	_, _ = io.ReadFull(rand.Reader, innerNonce)

	// 1. Construct Outer Envelope (Plaintext)
	outer := OuterMetadata{
		MessageID:      msgID,
		KEMSuite:       receiverProf.KEMSuite,
		KEMEncap:       ctKEM,
		OuterAEADSuite: receiverProf.AEADSuite,
		OuterXOFSuite:  receiverProf.XOFSuite,
		OuterNonce:     outerNonce,
	}
	outerBytes, _ := json.Marshal(outer)
	fmt.Fprintf(out, "%s\n%s\n", OuterHeaderBoundary, base64.StdEncoding.EncodeToString(outerBytes))

	// 2. Construct Inner Envelope (Padded & Encrypted)
	inner := InnerMetadata{
		SenderName:  senderKr.Profile.Name,
		Timestamp:   time.Now().Unix(),
		DSASuite:    senderKr.Profile.DSASuite,
		Compression: compression,
		InnerNonce:  innerNonce,
	}
	innerJSON, _ := json.Marshal(inner)
	
	innerPadded, err := padInnerHeader(innerJSON)
	if err != nil { return err }
	
	innerCiphertext, _ := aead.Seal(headerKey, outerNonce, innerPadded, nil)
	fmt.Fprintf(out, "%s\n%s\n%s\n", InnerHeaderBoundary, base64.StdEncoding.EncodeToString(innerCiphertext), PayloadBoundary)

	// 3. Initialize Fiat-Shamir Binding (Binds the Outer and Encrypted Inner together)
	fiatShamirXOF, _ := registry.GetXOF(outer.OuterXOFSuite)
	fiatShamirXOF.Write([]byte("PQPG-v1-FiatShamir-"))
	fiatShamirXOF.Write(outerBytes)
	fiatShamirXOF.Write(innerCiphertext)

	// --- COMPRESSION PIPELINE ---
	compReader, compWriter := io.Pipe()
	go func() {
		var err error
		defer func() { compWriter.CloseWithError(err) }()
		switch compression {
		case "Zstd":
			zw, _ := zstd.NewWriter(compWriter)
			_, err = io.Copy(zw, in)
			zw.Close()
		case "Gzip":
			gw := gzip.NewWriter(compWriter)
			_, err = io.Copy(gw, in)
			gw.Close()
		default:
			_, err = io.Copy(compWriter, in)
		}
	}()

	// 4. Stream and Encrypt Payload
	buf := make([]byte, ChunkSize)
	var chunkIndex uint64 = 0

	for {
		n, readErr := io.ReadFull(compReader, buf)
		if n > 0 {
			if readErr == io.EOF || readErr == io.ErrUnexpectedEOF {
				// FINAL CHUNK: Apply 4KB Padding
				padLen := 4096 - (n % 4096)
				if padLen < 2 { padLen += 4096 }
				
				padBuf := make([]byte, padLen)
				_, _ = io.ReadFull(rand.Reader, padBuf)
				binary.LittleEndian.PutUint16(padBuf[padLen-2:], uint16(padLen))
				
				finalPlaintext := append(buf[:n], padBuf...)
				chunkNonce := buildChunkNonce(innerNonce, chunkIndex)
				ciphertext, _ := aead.Seal(payloadKey, chunkNonce, finalPlaintext, nil)
				
				fiatShamirXOF.Write(ciphertext)
				fmt.Fprintf(out, "%s\n", base64.StdEncoding.EncodeToString(ciphertext))
				chunkIndex++
				break
			} else {
				chunkNonce := buildChunkNonce(innerNonce, chunkIndex)
				ciphertext, _ := aead.Seal(payloadKey, chunkNonce, buf[:n], nil)
				
				fiatShamirXOF.Write(ciphertext)
				fmt.Fprintf(out, "%s\n", base64.StdEncoding.EncodeToString(ciphertext))
				chunkIndex++
			}
		}

		if readErr == io.EOF {
			// EMPTY COMPRESSED OUTPUT: Generate solid 4KB block
			padLen := 4096
			padBuf := make([]byte, padLen)
			_, _ = io.ReadFull(rand.Reader, padBuf)
			binary.LittleEndian.PutUint16(padBuf[padLen-2:], uint16(padLen))
			
			chunkNonce := buildChunkNonce(innerNonce, chunkIndex)
			ciphertext, _ := aead.Seal(payloadKey, chunkNonce, padBuf, nil)
			
			fiatShamirXOF.Write(ciphertext)
			fmt.Fprintf(out, "%s\n", base64.StdEncoding.EncodeToString(ciphertext))
			chunkIndex++
			break
		}
		
		if readErr != nil && readErr != io.ErrUnexpectedEOF {
			return fmt.Errorf("compression stream interrupted: %v", readErr)
		}
	}

	// 5. Finalize Signature
	digest := fiatShamirXOF.Derive(nil, 64)
	dsa, _ := registry.GetDSA(senderKr.Profile.DSASuite)
	sig, err := dsa.Sign(senderKr.DSAPrivKey, digest)
	if err != nil { return err }

	fmt.Fprintf(out, "%s\n%s\n%s\n", SignatureBoundary, base64.StdEncoding.EncodeToString(sig), EndBoundary)
	return nil
}

// StreamOpen extracts the Sealed Sender envelope, decompresses, and strips padding.
func StreamOpen(in io.Reader, out io.Writer, receiverKr *identity.Keyring, senderProf *identity.Profile) error {
	registry := crypto.NewRegistry()
	reader := bufio.NewReader(in)

	// 1. Read Outer Envelope
	for {
		line, err := reader.ReadString('\n')
		if err != nil { return errors.New("invalid file: missing outer boundary") }
		if strings.TrimSpace(line) == OuterHeaderBoundary { break }
	}

	outerB64, _ := reader.ReadString('\n')
	outerBytes, err := base64.StdEncoding.DecodeString(strings.TrimSpace(outerB64))
	if err != nil { return errors.New("corrupt outer base64 encoding") }

	var outer OuterMetadata
	if err := json.Unmarshal(outerBytes, &outer); err != nil { return err }

	innerBoundary, _ := reader.ReadString('\n')
	if strings.TrimSpace(innerBoundary) != InnerHeaderBoundary {
		return errors.New("invalid file structure: expected inner metadata boundary")
	}

	innerCipherB64, _ := reader.ReadString('\n')
	innerCiphertext, err := base64.StdEncoding.DecodeString(strings.TrimSpace(innerCipherB64))
	if err != nil { return errors.New("corrupt inner base64 encoding") }

	// 2. Initialize Ratchet and Derive Dual Keys
	kem, _ := registry.GetKEM(outer.KEMSuite)
	sharedSecret, err := kem.Decapsulate(outer.KEMEncap, receiverKr.KEMPrivKey)
	if err != nil { return errors.New("kem decapsulation failed: unauthorized receiver") }

	ratchetXOF, _ := registry.GetXOF(outer.OuterXOFSuite)
	ratchet, _ := crypto.NewRatchet(sharedSecret, ratchetXOF)
	defer ratchet.Destroy()

	aead, _ := registry.GetAEAD(outer.OuterAEADSuite)
	headerKey, _ := ratchet.Advance(aead.KeySize())
	payloadKey, _ := ratchet.Advance(aead.KeySize())

	// 3. Decrypt and Unpad Inner Envelope
	innerPadded, err := aead.Open(headerKey, outer.OuterNonce, innerCiphertext, nil)
	if err != nil { return errors.New("CRITICAL: Sealed Sender Authentication Failed. Envelope tampered") }
	
	innerJSON, err := unpadInnerHeader(innerPadded)
	if err != nil { return err }

	var inner InnerMetadata
	if err := json.Unmarshal(innerJSON, &inner); err != nil { return err }

	// Context Validation
	if inner.SenderName != senderProf.Name {
		return fmt.Errorf("CRITICAL: Identity mismatch. Envelope sealed by '%s', but evaluated against '%s'", inner.SenderName, senderProf.Name)
	}
	if err := CheckAndCacheMessage(outer.MessageID, inner.Timestamp); err != nil {
		return err
	}

	payloadBoundary, _ := reader.ReadString('\n')
	if strings.TrimSpace(payloadBoundary) != PayloadBoundary {
		return errors.New("invalid file structure: expected payload boundary")
	}

	fiatShamirXOF, _ := registry.GetXOF(outer.OuterXOFSuite)
	fiatShamirXOF.Write([]byte("PQPG-v1-FiatShamir-"))
	fiatShamirXOF.Write(outerBytes)
	fiatShamirXOF.Write(innerCiphertext)

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

			if line == SignatureBoundary {
				if len(prevPlaintext) < 2 {
					loopErr = errors.New("corrupt padding structure: chunk too small")
					return
				}
				padLen := binary.LittleEndian.Uint16(prevPlaintext[len(prevPlaintext)-2:])
				if int(padLen) > len(prevPlaintext) {
					loopErr = errors.New("CRITICAL: padding length metric exceeds chunk boundaries")
					return
				}
				decWriter.Write(prevPlaintext[:len(prevPlaintext)-int(padLen)])
				break
			}
			
			if line == "" && err == nil { continue }
			if err != nil { loopErr = errors.New("unexpected EOF"); return }

			ciphertext, err := base64.StdEncoding.DecodeString(line)
			if err != nil { loopErr = errors.New("corrupt ciphertext"); return }

			fiatShamirXOF.Write(ciphertext)
			chunkNonce := buildChunkNonce(inner.InnerNonce, chunkIndex)
			plaintext, err := aead.Open(payloadKey, chunkNonce, ciphertext, nil)
			if err != nil {
				loopErr = fmt.Errorf("CRITICAL: Payload chunk %d tampered", chunkIndex)
				return
			}

			if prevPlaintext != nil { decWriter.Write(prevPlaintext) }
			prevPlaintext = plaintext 
			chunkIndex++
		}

		sigB64, _ := reader.ReadString('\n')
		signature, _ := base64.StdEncoding.DecodeString(strings.TrimSpace(sigB64))

		digest := fiatShamirXOF.Derive(nil, 64)
		dsa, _ := registry.GetDSA(inner.DSASuite)
		if !dsa.Verify(senderProf.DSAPubKey, digest, signature) {
			loopErr = errors.New("CRITICAL ALARM: FIAT-SHAMIR BINDING TAMPERED")
			return
		}
	}()

	var errOut error
	switch inner.Compression {
	case "Zstd":
		zr, zerr := zstd.NewReader(decReader)
		if zerr != nil { return zerr }
		defer zr.Close()
		_, errOut = io.Copy(out, zr)
	case "Gzip":
		gr, gerr := gzip.NewReader(decReader)
		if gerr != nil { return gerr }
		defer gr.Close()
		_, errOut = io.Copy(out, gr)
	default:
		_, errOut = io.Copy(out, decReader)
	}

	if errOut != nil {
		return fmt.Errorf("decryption interrupted: %w", errOut)
	}
	return nil
}