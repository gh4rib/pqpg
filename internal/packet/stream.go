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
	HeaderBoundary    = "-----BEGIN PQC HEADER-----"
	PayloadBoundary   = "-----BEGIN PQC PAYLOAD-----"
	SignatureBoundary = "-----BEGIN PQC SIGNATURE-----"
	EndBoundary       = "-----END PQC MESSAGE-----"
	ChunkSize         = 64 * 1024 // 64KB Streaming Chunks
)

type EnvelopeMetadata struct {
	MessageID   []byte `json:"message_id"`
	SenderName  string `json:"sender_name"`
	Timestamp   int64  `json:"timestamp"`
	KEMSuite    string `json:"kem_suite"`
	DSASuite    string `json:"dsa_suite"`
	AEADSuite   string `json:"aead_suite"`
	XOFSuite    string `json:"xof_suite"`
	Compression string `json:"compression"` // Tracks compression state natively
	KEMEncap    []byte `json:"kem_encap"`
	Nonce       []byte `json:"nonce"`
}

func buildChunkNonce(baseNonce []byte, counter uint64) []byte {
	nonce := make([]byte, len(baseNonce))
	copy(nonce, baseNonce)
	offset := len(nonce) - 8
	if offset < 0 {
		offset = 0
	}
	for i := 0; i < 8 && offset+i < len(nonce); i++ {
		nonce[offset+i] ^= byte(counter >> (8 * (7 - i)))
	}
	return nonce
}

// StreamSeal compresses, pads, and encrypts a file stream.
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
	msgKey, err := ratchet.Advance(aead.KeySize())
	if err != nil { return err }

	baseNonce := make([]byte, aead.NonceSize())
	_, _ = io.ReadFull(rand.Reader, baseNonce)

	metadata := EnvelopeMetadata{
		MessageID:   msgID,
		SenderName:  senderKr.Profile.Name,
		Timestamp:   time.Now().Unix(),
		KEMSuite:    receiverProf.KEMSuite,
		DSASuite:    senderKr.Profile.DSASuite,
		AEADSuite:   receiverProf.AEADSuite,
		XOFSuite:    receiverProf.XOFSuite,
		Compression: compression,
		KEMEncap:    ctKEM,
		Nonce:       baseNonce,
	}

	metadataBytes, _ := json.Marshal(metadata)
	fmt.Fprintf(out, "%s\n%s\n%s\n", HeaderBoundary, base64.StdEncoding.EncodeToString(metadataBytes), PayloadBoundary)

	fiatShamirXOF, _ := registry.GetXOF(metadata.XOFSuite)
	fiatShamirXOF.Write([]byte("PQPG-v1-FiatShamir-"))
	fiatShamirXOF.Write(metadataBytes)

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
	// ----------------------------

	buf := make([]byte, ChunkSize)
	var chunkIndex uint64 = 0

	for {
		// Read from the COMPRESSED stream
		n, readErr := io.ReadFull(compReader, buf)
		
		if n > 0 {
			if readErr == io.EOF || readErr == io.ErrUnexpectedEOF {
				// FINAL CHUNK: Apply 4KB Padding to obscure compressed size
				padLen := 4096 - (n % 4096)
				if padLen < 2 {
					padLen += 4096 
				}
				
				padBuf := make([]byte, padLen)
				_, _ = io.ReadFull(rand.Reader, padBuf)
				binary.LittleEndian.PutUint16(padBuf[padLen-2:], uint16(padLen))
				
				finalPlaintext := append(buf[:n], padBuf...)
				
				chunkNonce := buildChunkNonce(baseNonce, chunkIndex)
				ciphertext, _ := aead.Seal(msgKey, chunkNonce, finalPlaintext, nil)
				
				fiatShamirXOF.Write(ciphertext)
				fmt.Fprintf(out, "%s\n", base64.StdEncoding.EncodeToString(ciphertext))
				chunkIndex++
				break
			} else {
				chunkNonce := buildChunkNonce(baseNonce, chunkIndex)
				ciphertext, _ := aead.Seal(msgKey, chunkNonce, buf[:n], nil)
				
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
			
			chunkNonce := buildChunkNonce(baseNonce, chunkIndex)
			ciphertext, _ := aead.Seal(msgKey, chunkNonce, padBuf, nil)
			
			fiatShamirXOF.Write(ciphertext)
			fmt.Fprintf(out, "%s\n", base64.StdEncoding.EncodeToString(ciphertext))
			chunkIndex++
			break
		}
		
		if readErr != nil && readErr != io.ErrUnexpectedEOF {
			return fmt.Errorf("file compression stream interrupted: %v", readErr)
		}
	}

	digest := fiatShamirXOF.Derive(nil, 64)
	dsa, _ := registry.GetDSA(senderKr.Profile.DSASuite)
	sig, err := dsa.Sign(senderKr.DSAPrivKey, digest)
	if err != nil { return err }

	fmt.Fprintf(out, "%s\n%s\n%s\n", SignatureBoundary, base64.StdEncoding.EncodeToString(sig), EndBoundary)
	return nil
}

// StreamOpen decrypts chunks sequentially, strips padding, and decompresses.
func StreamOpen(in io.Reader, out io.Writer, receiverKr *identity.Keyring, senderProf *identity.Profile) error {
	registry := crypto.NewRegistry()
	reader := bufio.NewReader(in)

	for {
		line, err := reader.ReadString('\n')
		if err != nil { return errors.New("invalid file: missing header boundary") }
		if strings.TrimSpace(line) == HeaderBoundary { break }
	}

	headerB64, _ := reader.ReadString('\n')
	headerBytes, err := base64.StdEncoding.DecodeString(strings.TrimSpace(headerB64))
	if err != nil { return errors.New("corrupt header base64 encoding") }

	var metadata EnvelopeMetadata
	if err := json.Unmarshal(headerBytes, &metadata); err != nil { return err }

	if err := CheckAndCacheMessage(metadata.MessageID, metadata.Timestamp); err != nil {
		return err
	}

	payloadBoundary, _ := reader.ReadString('\n')
	if strings.TrimSpace(payloadBoundary) != PayloadBoundary {
		return errors.New("invalid file structure: expected payload boundary")
	}

	kem, _ := registry.GetKEM(metadata.KEMSuite)
	sharedSecret, err := kem.Decapsulate(metadata.KEMEncap, receiverKr.KEMPrivKey)
	if err != nil { return errors.New("kem decapsulation failed: unauthorized receiver") }

	ratchetXOF, _ := registry.GetXOF(metadata.XOFSuite)
	ratchet, _ := crypto.NewRatchet(sharedSecret, ratchetXOF)
	defer ratchet.Destroy()

	aead, _ := registry.GetAEAD(metadata.AEADSuite)
	msgKey, _ := ratchet.Advance(aead.KeySize())

	fiatShamirXOF, _ := registry.GetXOF(metadata.XOFSuite)
	fiatShamirXOF.Write([]byte("PQPG-v1-FiatShamir-"))
	fiatShamirXOF.Write(headerBytes)

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
				
				// Write stripped block to the decompressor pipe
				decWriter.Write(prevPlaintext[:len(prevPlaintext)-int(padLen)])
				break
			}
			
			if line == "" && err == nil { continue }
			if err != nil {
				loopErr = errors.New("unexpected end of file before signature block")
				return
			}

			ciphertext, err := base64.StdEncoding.DecodeString(line)
			if err != nil {
				loopErr = errors.New("corrupt ciphertext base64 chunk")
				return
			}

			fiatShamirXOF.Write(ciphertext)

			chunkNonce := buildChunkNonce(metadata.Nonce, chunkIndex)
			plaintext, err := aead.Open(msgKey, chunkNonce, ciphertext, nil)
			if err != nil {
				loopErr = fmt.Errorf("CRITICAL: Ciphertext chunk %d corrupted or tampered", chunkIndex)
				return
			}

			if prevPlaintext != nil {
				decWriter.Write(prevPlaintext) 
			}
			
			prevPlaintext = plaintext 
			chunkIndex++
		}

		sigB64, _ := reader.ReadString('\n')
		signature, _ := base64.StdEncoding.DecodeString(strings.TrimSpace(sigB64))

		digest := fiatShamirXOF.Derive(nil, 64)
		dsa, _ := registry.GetDSA(metadata.DSASuite)
		if !dsa.Verify(senderProf.DSAPubKey, digest, signature) {
			loopErr = errors.New("CRITICAL ALARM: FIAT-SHAMIR METADATA BINDING TAMPERED. PAYLOAD REJECTED")
			return
		}
	}()
	// ------------------------------

	// Stream verified, decompressed data to the hard drive
	var errOut error
	switch metadata.Compression {
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
		return fmt.Errorf("decryption/decompression interrupted: %w", errOut)
	}

	return nil
}